//! Vault database — encrypted storage using AES-256-GCM + Argon2id, with an
//! optional post-quantum hybrid layer (ML-KEM-768, see `pqc.rs`) at rest, and
//! an XChaCha20-Poly1305 at-rest container (v3; W3 #141/#142, P10-R06).
//!
//! File format: `.twv` (Tallow Vault)
//!
//! Three container versions share the `TWV1` magic and differ in the version
//! byte at offset 4, so legacy files open unchanged:
//!
//! ```text
//! v1 (classical only — written when settings.pqc_enabled == false; still readable):
//!   Header: b"TWV1" (4) + version = 1 (1) + salt (32) + nonce (12)
//!         + argon2_m_cost u32 LE (4) + argon2_t_cost u32 LE (4) + argon2_p_cost u32 LE (4)
//!   Body:   AES-256-GCM(Argon2id(password, salt), nonce, JSON payload)
//!
//! v2 (hybrid PQC — written when settings.pqc_enabled == true; the default for new vaults since A6.1.3):
//!   Header: b"TWV1" (4) + version = 2 (1)
//!         + dk_nonce (12) + wrapped_mlkem_dk (2416)
//!         -- ephemeral ML-KEM-768 decapsulation key, AES-256-GCM wrapped under
//!            Argon2id(password, BLAKE3(EK)) so the file is decryptable from
//!            the password alone and the DK never appears in the clear.
//!   Body:   JSON of pqc::PQCEncryptedBlob (v2), i.e. the payload is double
//!           encrypted: inner AES-256-GCM(Argon2id KEK) over the JSON payload,
//!           then an authenticated outer AES-256-GCM layer keyed by the
//!           ML-KEM-768 shared secret (see pqc.rs).
//!
//! v3 (XChaCha20-Poly1305 at-rest — written when settings.pqc_enabled == false
//!     and settings.cipher == "xchacha20-poly1305", the default for new
//!     non-hybrid vaults; W3 #141/#142, P10-R06):
//!   AAD/Header: b"TWV1" (4) + version = 3 (1) + cipher_id = 1 (1) + salt (32)
//!         + argon2_m_cost u32 LE (4) + argon2_t_cost u32 LE (4) + argon2_p_cost u32 LE (4)
//!   Then:   wrapped_dek (40)          -- AES-256-KW (RFC 3394) of a fresh
//!                                         random per-object DEK under the KEK
//!           payload_nonce (24)        -- fresh random 192-bit XChaCha nonce
//!           ciphertext                -- XChaCha20-Poly1305(DEK, nonce, JSON,
//!                                         aad = the 50-byte header above)
//!   Key schedule: KEK = Argon2id(password, salt, header m/t/p); DEK = random
//!   32 B per save; one ciphertext ↔ one DEK (no random-96-bit-nonce
//!   AES-GCM at rest, no cross-key ciphertexts). The KDF parameters are read
//!   from the header on open (reader precedence, same as v1).
//! ```
//!
//! # Compatibility and migration (honest notes)
//!
//! - Reading: `open` dispatches on the version byte and opens v1, v2 and v3.
//! - Writing: v3 requires the new code; a **pre-v3 reader rejects a v3 file**
//!   with the existing "unsupported version 3" error. Downgrading a v3 vault
//!   is explicit: `set_cipher("aes-256-gcm")` + save rewrites it as v1.
//! - Migration v1 → v3: `open` then `set_cipher("xchacha20-poly1305")` then
//!   `save` (fresh salt, fresh DEK, fresh nonces).
//! - v2 (hybrid) files are untouched by this change: their inner classical
//!   layer remains AES-256-GCM until the PQC blob gains its own XChaCha
//!   version (recorded as follow-up, not silently claimed here). The `cipher`
//!   setting is not consumed while `pqc_enabled` is true.

use super::entry::{EntryData, VaultEntry};
use serde::{Deserialize, Serialize};

// The crate's XChaCha20-Poly1305 at-rest object seal (W3 #141/#142 · P10-R06):
// one implementation of the pattern, consumed here for `.twv` v3.
use tallow_crypto::symmetric::xchacha20 as at_rest;

/// Magic bytes identifying a Tallow Vault file.
const TWV_MAGIC: &[u8; 4] = b"TWV1";
/// File format version: classical AES-256-GCM + Argon2id only.
const TWV_VERSION_CLASSIC: u8 = 1;
/// File format version: hybrid PQC — body is a v2 `PQCEncryptedBlob` whose
/// outer AEAD layer is keyed by the ML-KEM-768 shared secret.
const TWV_VERSION_HYBRID: u8 = 2;
/// File format version: XChaCha20-Poly1305 at-rest — 192-bit random nonce +
/// per-object DEK (AES-256-KW wrapped), KDF params in the header
/// (W3 #141/#142, P10-R06).
const TWV_VERSION_XCHACHA: u8 = 3;
/// Cipher id byte carried in the v3 header (extensible; only id 1 is defined).
const TWV_CIPHER_XCHACHA20_POLY1305: u8 = 1;
/// ML-KEM-768 decapsulation key size in bytes.
const MLKEM768_DK_LEN: usize = 2400;
/// AES-256-GCM authentication tag size in bytes.
const GCM_TAG_LEN: usize = 16;
/// v1 header size: magic(4) + version(1) + salt(32) + nonce(12) + m_cost(4) + t_cost(4) + p_cost(4) = 61
const TWV_HEADER_SIZE: usize = 4 + 1 + 32 + 12 + 4 + 4 + 4;
/// v2 fixed header size: magic(4) + version(1) + dk_nonce(12)
/// + wrapped_dk(MLKEM768_DK_LEN + GCM_TAG_LEN) = 2433
const TWV_HYBRID_HEADER_SIZE: usize = 4 + 1 + 12 + MLKEM768_DK_LEN + GCM_TAG_LEN;
/// v3 fixed header size (this region is the payload AEAD's AAD):
/// magic(4) + version(1) + cipher_id(1) + salt(32) + m_cost(4) + t_cost(4) + p_cost(4) = 50
const TWV_V3_HEADER_SIZE: usize = 4 + 1 + 1 + 32 + 4 + 4 + 4;
/// v3 offset of the AES-256-KW-wrapped per-object DEK (40 bytes).
const TWV_V3_WRAPPED_DEK_OFFSET: usize = TWV_V3_HEADER_SIZE;
/// v3 offset of the 192-bit payload nonce (24 bytes).
const TWV_V3_NONCE_OFFSET: usize = TWV_V3_WRAPPED_DEK_OFFSET + at_rest::WRAPPED_DEK_LEN;
/// v3 offset of the payload ciphertext (tag appended).
const TWV_V3_BODY_OFFSET: usize = TWV_V3_NONCE_OFFSET + at_rest::NONCE_LEN;

/// Cipher name (vault setting): AES-256-GCM + Argon2id. Selects the legacy v1
/// classical container when `pqc_enabled` is false.
pub const CIPHER_AES_256_GCM: &str = "aes-256-gcm";
/// Cipher name (vault setting): XChaCha20-Poly1305 + per-object DEK. Selects
/// the v3 at-rest container when `pqc_enabled` is false (W3 #141/#142).
pub const CIPHER_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

/// Default Argon2id parameters.
const DEFAULT_M_COST: u32 = 65536; // 64 MB
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 4;

/// Result of an integrity check.
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    pub valid: bool,
    pub hash: String,
    pub entry_count: usize,
    pub deleted_count: usize,
    pub orphan_links: bool,
}

/// Result of a compaction operation.
#[derive(Debug, Clone)]
pub struct CompactResult {
    pub deleted_removed: usize,
    pub history_trimmed: usize,
}

/// The encrypted vault database.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultDatabase {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub entries: Vec<VaultEntry>,
    pub folders: Vec<String>,
    pub settings: VaultSettings,
    /// Provenance: the path this handle was decrypted from via `open`.
    ///
    /// Never serialized — the on-disk payload format is unchanged. `save`
    /// uses it to fail closed (F-g1-7): a handle may only write the file it
    /// came from, or a file authored by an explicit fresh-vault init.
    #[serde(skip)]
    opened_from: Option<String>,
    /// Set only around the explicit init write in `create` — the one flow
    /// authorized to author a brand-new `.twv` file.
    #[serde(skip)]
    init_authorized: bool,
}

/// Vault-wide settings.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Seconds before clipboard is cleared after copy.
    pub clipboard_clear_seconds: u32,
    /// Seconds of inactivity before the vault auto-locks.
    pub auto_lock_seconds: u32,
    /// Default number of TOTP digits (usually 6).
    pub default_totp_digits: u8,
    /// Default TOTP period in seconds (usually 30).
    pub default_totp_period: u32,
    /// Whether PQC hybrid encryption is enabled.
    ///
    /// When true, `save` writes the v2 `.twv` format: the AES-256-GCM +
    /// Argon2id payload is wrapped in a second authenticated AEAD layer keyed
    /// by an ML-KEM-768 shared secret (`pqc.rs`). When false, the legacy v1
    /// format is written. `open` detects the format from the version byte on
    /// disk, so both formats load regardless of this flag.
    pub pqc_enabled: bool,
    /// Encryption cipher: "xchacha20-poly1305" (default for new non-hybrid
    /// vaults since W3 #141/#142) or "aes-256-gcm" (legacy v1 classical
    /// container, still writable on request).
    ///
    /// Consumed by `save` only when `pqc_enabled == false`: it selects the
    /// classical at-rest container (v3 XChaCha20-Poly1305 vs legacy v1
    /// AES-256-GCM). While `pqc_enabled == true` the hybrid v2 container is
    /// written and this preference is not consumed yet (the PQC blob's inner
    /// classical layer is AES-256-GCM; upgrading it is a follow-up format
    /// change, not silently claimed here).
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Anti-phishing token (set on creation, displayed on unlock for verification)
    #[serde(default)]
    pub anti_phishing_token: String,
}

fn default_cipher() -> String {
    // W3 #141/#142: new vaults default their classical at-rest layer to
    // XChaCha20-Poly1305 (192-bit random nonce + per-object DEK). Explicitly
    // setting CIPHER_AES_256_GCM retains the legacy v1 write path.
    CIPHER_XCHACHA20_POLY1305.to_string()
}

/// Vault lock state for runtime use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLockState {
    /// Whether the vault is currently locked.
    pub locked: bool,
    /// ISO-8601 timestamp when the vault was last unlocked.
    pub unlocked_at: Option<String>,
    /// Seconds of inactivity before auto-lock triggers.
    pub auto_lock_seconds: u32,
}

impl VaultLockState {
    /// Create a new locked state.
    pub fn new_locked(auto_lock_seconds: u32) -> Self {
        Self {
            locked: true,
            unlocked_at: None,
            auto_lock_seconds,
        }
    }

    /// Create a new unlocked state (records current time).
    pub fn new_unlocked(auto_lock_seconds: u32) -> Self {
        Self {
            locked: false,
            unlocked_at: Some(chrono::Utc::now().to_rfc3339()),
            auto_lock_seconds,
        }
    }

    /// Check if auto_lock_seconds have been exceeded since unlock.
    pub fn should_lock(&self) -> bool {
        if self.locked {
            return false; // already locked
        }
        if self.auto_lock_seconds == 0 {
            return false; // auto-lock disabled
        }
        match &self.unlocked_at {
            None => true, // no unlock time recorded — lock
            Some(ts) => {
                if let Ok(unlocked) = chrono::DateTime::parse_from_rfc3339(ts) {
                    let elapsed = chrono::Utc::now()
                        .signed_duration_since(unlocked)
                        .num_seconds();
                    elapsed >= self.auto_lock_seconds as i64
                } else {
                    true // can't parse timestamp — lock for safety
                }
            }
        }
    }

    /// Lock the vault.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the vault (resets the unlock timestamp).
    pub fn unlock(&mut self) {
        self.locked = false;
        self.unlocked_at = Some(chrono::Utc::now().to_rfc3339());
    }
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            clipboard_clear_seconds: 30,
            auto_lock_seconds: 300,
            default_totp_digits: 6,
            default_totp_period: 30,
            // A6.1.3: hybrid PQC (v2 writes) is the DEFAULT for new vaults.
            // v1 files still open, and callers can opt back down to v1 by
            // setting this false explicitly.
            pqc_enabled: true,
            cipher: default_cipher(),
            anti_phishing_token: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `password` + `salt` using Argon2id.
fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("vault: invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("vault: key derivation failed: {e}"))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt helpers
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM using the given `key` and `nonce`.
fn aes_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("vault: encryption failed: {e}"))
}

/// Decrypt `ciphertext` with AES-256-GCM using the given `key` and `nonce`.
fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("vault: decryption failed (wrong password?): {e}"))
}

// ---------------------------------------------------------------------------
// VaultDatabase implementation
// ---------------------------------------------------------------------------

impl VaultDatabase {
    /// Create a new, empty vault with the given name.
    pub fn new(name: &str) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let mut db = Self {
            name: name.to_string(),
            created_at: now.clone(),
            updated_at: now,
            entries: Vec::new(),
            folders: Vec::new(),
            settings: VaultSettings::default(),
            opened_from: None,
            init_authorized: false,
        };
        // Generate anti-phishing token on creation
        db.settings.anti_phishing_token = db.anti_phishing_token();
        db
    }

    /// Create a new vault and immediately save it to disk (encrypted).
    pub fn create(path: &str, password: &str, name: &str) -> Result<Self, String> {
        if password.is_empty() {
            return Err("vault: password must not be empty".into());
        }
        let mut db = Self::new(name);
        // Explicit fresh-vault init is the one flow authorized to author a
        // brand-new file (and to re-create over an existing path, preserving
        // `vault create` semantics). Cleared right after the write.
        db.init_authorized = true;
        let saved = db.save(path, password);
        db.init_authorized = false;
        saved?;
        Ok(db)
    }

    /// Open an existing `.twv` file, decrypt it, and return the database.
    ///
    /// The container version byte (offset 4) selects the format: v1 vaults
    /// (classical AES-256-GCM + Argon2id only) open through the legacy path,
    /// v2 vaults (hybrid PQC) are unwrapped through `pqc.rs` first, v3 vaults
    /// (XChaCha20-Poly1305 at-rest) unwrap the per-object DEK and open through
    /// the crate's xchacha20 seal. The `settings` inside the payload are
    /// read-only here — what is on disk decides how it is decrypted.
    pub fn open(path: &str, password: &str) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("vault: cannot read '{}': {e}", path))?;

        if data.len() < 5 {
            return Err("vault: file too small — not a valid .twv file".into());
        }

        // Validate magic.
        if &data[0..4] != TWV_MAGIC {
            return Err("vault: invalid file — expected TWV1 magic".into());
        }

        let mut db = match data[4] {
            TWV_VERSION_CLASSIC => Self::open_classic(&data, password),
            TWV_VERSION_HYBRID => Self::open_hybrid(&data, password),
            TWV_VERSION_XCHACHA => Self::open_xchacha(&data, password),
            other => Err(format!(
                "vault: unsupported version {other} (expected {TWV_VERSION_CLASSIC}, \
                 {TWV_VERSION_HYBRID} or {TWV_VERSION_XCHACHA})"
            )),
        }?;
        // Record provenance so matching `save` writes stay allowed while a
        // handle that failed to open can never fabricate/clobber a file.
        db.opened_from = Some(path.to_string());
        Ok(db)
    }

    /// Legacy v1 path: single AES-256-GCM layer under the Argon2id KEK.
    fn open_classic(data: &[u8], password: &str) -> Result<Self, String> {
        if data.len() < TWV_HEADER_SIZE {
            return Err("vault: file too small — not a valid .twv file".into());
        }

        // Parse header fields.
        let salt: [u8; 32] = data[5..37]
            .try_into()
            .map_err(|_| "vault: corrupt salt".to_string())?;
        let nonce: [u8; 12] = data[37..49]
            .try_into()
            .map_err(|_| "vault: corrupt nonce".to_string())?;

        let m_cost = u32::from_le_bytes(
            data[49..53]
                .try_into()
                .map_err(|_| "vault: corrupt m_cost".to_string())?,
        );
        let t_cost = u32::from_le_bytes(
            data[53..57]
                .try_into()
                .map_err(|_| "vault: corrupt t_cost".to_string())?,
        );
        let p_cost = u32::from_le_bytes(
            data[57..61]
                .try_into()
                .map_err(|_| "vault: corrupt p_cost".to_string())?,
        );

        let ciphertext = &data[TWV_HEADER_SIZE..];

        // Derive key and decrypt.
        let key = derive_key(password, &salt, m_cost, t_cost, p_cost)?;
        let plaintext = aes_decrypt(&key, &nonce, ciphertext)?;

        let db: VaultDatabase = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("vault: corrupt payload — JSON parse failed: {e}"))?;

        Ok(db)
    }

    /// v2 hybrid path: unwrap the stored ML-KEM-768 decapsulation key with the
    /// Argon2id KEK, then let `pqc.rs` peel the authenticated outer (ML-KEM
    /// keyed) AEAD layer and the inner (Argon2id keyed) classical layer.
    fn open_hybrid(data: &[u8], password: &str) -> Result<Self, String> {
        if data.len() < TWV_HYBRID_HEADER_SIZE {
            return Err("vault: file too small — not a valid hybrid .twv file".into());
        }

        let dk_nonce: [u8; 12] = data[5..17]
            .try_into()
            .map_err(|_| "vault: corrupt hybrid dk nonce".to_string())?;
        let wrapped_dk = &data[17..17 + MLKEM768_DK_LEN + GCM_TAG_LEN];
        let body = &data[TWV_HYBRID_HEADER_SIZE..];
        if body.is_empty() {
            return Err("vault: corrupt hybrid vault — empty payload body".into());
        }

        // The body is the JSON-serialized v2 PQCEncryptedBlob from pqc.rs.
        let blob: super::pqc::PQCEncryptedBlob = serde_json::from_slice(body)
            .map_err(|e| format!("vault: corrupt hybrid payload — PQC blob parse failed: {e}"))?;
        if blob.version != 2 {
            return Err(format!(
                "vault: unsupported PQC blob version {} (only v2 authenticated AEAD is supported)",
                blob.version
            ));
        }

        // Recover the ephemeral decapsulation key: it is wrapped under
        // Argon2id(password, BLAKE3(EK)) — the same derivation pqc.rs uses
        // for the inner classical layer — so the file stays self-contained.
        let dk_hex = super::pqc::pqc_unwrap_dk(password, &blob.pqc_encapsulation_key, &dk_nonce, wrapped_dk)
            .map_err(|e| format!("vault: cannot unwrap PQC key: {e}"))?;

        let plaintext = super::pqc::pqc_hybrid_decrypt(&blob, password, &dk_hex)
            .map_err(|e| format!("vault: PQC decryption failed: {e}"))?;

        let db: VaultDatabase = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("vault: corrupt payload — JSON parse failed: {e}"))?;

        Ok(db)
    }

    /// v3 path: XChaCha20-Poly1305 at-rest — the payload is sealed under a
    /// fresh per-object DEK (AES-256-KW wrapped by the Argon2id KEK) with a
    /// random 192-bit nonce; the fixed 50-byte header is the AAD.
    ///
    /// The KDF parameters are read from the header verbatim (reader
    /// precedence, same discipline as v1), so files written with other
    /// Argon2id costs still open.
    fn open_xchacha(data: &[u8], password: &str) -> Result<Self, String> {
        if data.len() < TWV_V3_BODY_OFFSET + at_rest::TAG_LEN {
            return Err("vault: file too small — not a valid v3 .twv file".into());
        }

        // Cipher id (extensible header byte; only one cipher is defined).
        let cipher_id = data[5];
        if cipher_id != TWV_CIPHER_XCHACHA20_POLY1305 {
            return Err(format!(
                "vault: unsupported v3 cipher id {cipher_id} \
                 (expected {TWV_CIPHER_XCHACHA20_POLY1305})"
            ));
        }

        // Parse header fields.
        let salt: [u8; 32] = data[6..38]
            .try_into()
            .map_err(|_| "vault: corrupt v3 salt".to_string())?;
        let m_cost = u32::from_le_bytes(
            data[38..42]
                .try_into()
                .map_err(|_| "vault: corrupt v3 m_cost".to_string())?,
        );
        let t_cost = u32::from_le_bytes(
            data[42..46]
                .try_into()
                .map_err(|_| "vault: corrupt v3 t_cost".to_string())?,
        );
        let p_cost = u32::from_le_bytes(
            data[46..50]
                .try_into()
                .map_err(|_| "vault: corrupt v3 p_cost".to_string())?,
        );

        // Sealed fields: wrapped DEK, 192-bit nonce, payload ciphertext.
        let wrapped_dek: [u8; at_rest::WRAPPED_DEK_LEN] =
            data[TWV_V3_WRAPPED_DEK_OFFSET..TWV_V3_NONCE_OFFSET]
                .try_into()
                .map_err(|_| "vault: corrupt v3 wrapped DEK".to_string())?;
        let nonce: [u8; at_rest::NONCE_LEN] = data[TWV_V3_NONCE_OFFSET..TWV_V3_BODY_OFFSET]
            .try_into()
            .map_err(|_| "vault: corrupt v3 payload nonce".to_string())?;

        // Derive the KEK from the header parameters, unwrap the DEK, decrypt.
        let key = derive_key(password, &salt, m_cost, t_cost, p_cost)?;
        let sealed = at_rest::SealedObject {
            nonce,
            wrapped_dek,
            ciphertext: data[TWV_V3_BODY_OFFSET..].to_vec(),
        };
        let plaintext = at_rest::open_object(&key, &sealed, &data[..TWV_V3_HEADER_SIZE])
            .map_err(|e| {
                format!(
                    "vault: XChaCha20-Poly1305 open failed (wrong password or tampered file): {e}"
                )
            })?;

        let mut db: VaultDatabase = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("vault: corrupt payload — JSON parse failed: {e}"))?;
        // The on-disk version is authoritative: a v3 file always means the
        // XChaCha classical layer, whatever the payload metadata claims.
        db.settings.cipher = CIPHER_XCHACHA20_POLY1305.to_string();
        Ok(db)
    }

    /// Encrypt the database and write it to disk as a `.twv` file.
    ///
    /// A fresh random salt and nonce are generated on every save. When
    /// `settings.pqc_enabled` is true the file is written in the v2 hybrid
    /// format: the JSON payload is first AES-256-GCM encrypted under the
    /// Argon2id key, then wrapped in a second authenticated AEAD layer keyed
    /// by an ML-KEM-768 shared secret (see `pqc.rs`). When it is false, the
    /// classical container is selected by `settings.cipher`: v3
    /// XChaCha20-Poly1305 (default; 192-bit nonce + per-object DEK) or the
    /// legacy v1 AES-256-GCM container.
    pub fn save(&self, path: &str, password: &str) -> Result<(), String> {
        self.save_gated(path, password, false)
    }

    /// Test-fixture writer: identical encryption to `save`, without the
    /// provenance gate, for tests that author a brand-new file from a bare
    /// in-memory handle (the shape production code reaches via `create`).
    #[cfg(test)]
    fn save_unchecked(&self, path: &str, password: &str) -> Result<(), String> {
        self.save_gated(path, password, true)
    }

    /// True when this handle is entitled to write `path` under the F-g1-7
    /// rule: it was opened from that exact file (string or canonical match).
    /// New vault files are authored only by an explicit `create` init.
    fn may_write(&self, path: &str) -> bool {
        let Some(opened) = self.opened_from.as_deref() else {
            return false;
        };
        if opened == path {
            return true;
        }
        match (std::fs::canonicalize(opened), std::fs::canonicalize(path)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }

    /// `save` core with the F-g1-7 provenance gate. `forced` is set only by
    /// the in-crate test writer.
    fn save_gated(&self, path: &str, password: &str, forced: bool) -> Result<(), String> {
        if password.is_empty() {
            return Err("vault: password must not be empty".into());
        }

        // F-g1-7: fail closed. A handle may write only the file it was opened
        // from, or a file authored by an explicit `create` init. A fresh,
        // unopened handle (e.g. the CLI import fall-through after a failed
        // `open`) must never silently create a vault file or overwrite the
        // target — otherwise a wrong password / corrupt file / wrong path
        // ends with imported secrets written into a brand-new vault while the
        // original file is destroyed.
        if !forced && !self.init_authorized && !self.may_write(path) {
            return Err(format!(
                "vault: refusing to write '{path}': vault was not opened from that path \
                 (wrong password, corrupt file, or wrong target?) — refusing to create or \
                 overwrite it. Open the existing vault first, or create a new one with `vault create`."
            ));
        }

        // Serialize payload to JSON.
        let json = serde_json::to_vec(self)
            .map_err(|e| format!("vault: serialization failed: {e}"))?;

        if self.settings.pqc_enabled {
            Self::save_hybrid(path, password, &json)
        } else {
            // Classical container selection (W3 #141/#142): the `cipher`
            // setting decides; unknown names fail closed rather than silently
            // falling back to a weaker format.
            match self.settings.cipher.as_str() {
                CIPHER_XCHACHA20_POLY1305 => Self::save_xchacha(path, password, &json),
                CIPHER_AES_256_GCM => Self::save_classic(path, password, &json),
                other => Err(format!(
                    "vault: unknown cipher '{other}' (expected '{CIPHER_XCHACHA20_POLY1305}' \
                     or '{CIPHER_AES_256_GCM}')"
                )),
            }
        }
    }

    /// Legacy v1 writer: single AES-256-GCM layer under the Argon2id KEK.
    fn save_classic(path: &str, password: &str, json: &[u8]) -> Result<(), String> {
        use rand::RngCore;

        // Generate random salt and nonce.
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);

        // Derive key and encrypt.
        let key = derive_key(password, &salt, DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST)?;
        let ciphertext = aes_encrypt(&key, &nonce, json)?;

        // Build file: header + ciphertext.
        let mut out = Vec::with_capacity(TWV_HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(TWV_MAGIC);
        out.push(TWV_VERSION_CLASSIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&DEFAULT_M_COST.to_le_bytes());
        out.extend_from_slice(&DEFAULT_T_COST.to_le_bytes());
        out.extend_from_slice(&DEFAULT_P_COST.to_le_bytes());
        out.extend_from_slice(&ciphertext);

        std::fs::write(path, &out)
            .map_err(|e| format!("vault: cannot write '{}': {e}", path))?;

        Ok(())
    }

    /// v2 hybrid writer: double-encrypts `json` via `pqc.rs` (inner classical
    /// AES-256-GCM under the Argon2id KEK, outer authenticated AEAD keyed by
    /// the ML-KEM-768 shared secret) and stores the ephemeral decapsulation
    /// key in the header, AES-256-GCM wrapped under the Argon2id KEK, so the
    /// file remains decryptable from the password alone.
    fn save_hybrid(path: &str, password: &str, json: &[u8]) -> Result<(), String> {
        // pqc.rs does the actual hybrid double-encryption (v2 blob format).
        let (blob, dk_hex) = super::pqc::pqc_hybrid_encrypt(json, password)
            .map_err(|e| format!("vault: PQC hybrid encryption failed: {e}"))?;
        assert_eq!(blob.version, 2, "pqc.rs must produce v2 blobs");

        // Wrap the ephemeral decapsulation key under the password-derived key.
        let (dk_nonce, wrapped_dk) =
            super::pqc::pqc_wrap_dk(password, &blob.pqc_encapsulation_key, &dk_hex)
                .map_err(|e| format!("vault: cannot wrap PQC key: {e}"))?;
        debug_assert_eq!(wrapped_dk.len(), MLKEM768_DK_LEN + GCM_TAG_LEN);

        // Body: JSON-serialized v2 blob.
        let body = serde_json::to_vec(&blob)
            .map_err(|e| format!("vault: PQC blob serialization failed: {e}"))?;

        let mut out = Vec::with_capacity(TWV_HYBRID_HEADER_SIZE + body.len());
        out.extend_from_slice(TWV_MAGIC);
        out.push(TWV_VERSION_HYBRID);
        out.extend_from_slice(&dk_nonce);
        out.extend_from_slice(&wrapped_dk);
        out.extend_from_slice(&body);

        std::fs::write(path, &out)
            .map_err(|e| format!("vault: cannot write '{}': {e}", path))?;

        Ok(())
    }

    /// v3 writer: XChaCha20-Poly1305 at-rest (W3 #141/#142 · P10-R06).
    ///
    /// Fresh random Argon2id salt (KEK unique per file), fresh random
    /// per-object DEK wrapped under the KEK (AES-256-KW, RFC 3394), fresh
    /// random 192-bit payload nonce, payload under the DEK with the fixed
    /// 50-byte header bound as AAD. One file = one object = one DEK, so the
    /// RFC 8446 §5.5-style usage-ceiling discipline is a property of the
    /// format (see `tallow_crypto::symmetric::xchacha20`).
    fn save_xchacha(path: &str, password: &str, json: &[u8]) -> Result<(), String> {
        use rand::RngCore;
        use zeroize::Zeroizing;

        // Fresh salt per save — the KEK never repeats across files.
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);

        // Derive the KEK (KEK = wrapped-DEK key + wrap integrity root). It is
        // wiped on drop.
        let key = Zeroizing::new(derive_key(
            password,
            &salt,
            DEFAULT_M_COST,
            DEFAULT_T_COST,
            DEFAULT_P_COST,
        )?);

        // Build the fixed header first: it is the payload AEAD's AAD.
        let mut out = Vec::with_capacity(TWV_V3_BODY_OFFSET + json.len() + at_rest::TAG_LEN);
        out.extend_from_slice(TWV_MAGIC);
        out.push(TWV_VERSION_XCHACHA);
        out.push(TWV_CIPHER_XCHACHA20_POLY1305);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&DEFAULT_M_COST.to_le_bytes());
        out.extend_from_slice(&DEFAULT_T_COST.to_le_bytes());
        out.extend_from_slice(&DEFAULT_P_COST.to_le_bytes());
        debug_assert_eq!(out.len(), TWV_V3_HEADER_SIZE);

        // Seal: per-object DEK (AES-KW-wrapped) + 192-bit nonce + ciphertext.
        let sealed = at_rest::seal_object(&key, json, &out)
            .map_err(|e| format!("vault: XChaCha20-Poly1305 seal failed: {e}"))?;

        out.extend_from_slice(&sealed.wrapped_dek);
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.ciphertext);

        std::fs::write(path, &out)
            .map_err(|e| format!("vault: cannot write '{}': {e}", path))?;

        Ok(())
    }

    // ── Entry CRUD ──────────────────────────────────────────────────────

    /// Add an entry to the vault. Updates the vault timestamp.
    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.entries.push(entry);
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Remove an entry by ID. Returns the removed entry, or `None` if not found.
    pub fn remove_entry(&mut self, id: &str) -> Option<VaultEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            self.updated_at = chrono::Utc::now().to_rfc3339();
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }

    /// Get an entry by ID (immutable reference).
    pub fn get_entry(&self, id: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Get an entry by ID (mutable reference).
    pub fn get_entry_mut(&mut self, id: &str) -> Option<&mut VaultEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    // ── Queries ─────────────────────────────────────────────────────────

    /// Search entries by name, username, or URL (case-insensitive substring match).
    /// List soft-deleted entries (recycle bin).
    pub fn list_deleted(&self) -> Vec<&VaultEntry> {
        self.entries.iter().filter(|e| e.is_deleted()).collect()
    }

    /// Permanently remove all soft-deleted entries.
    pub fn empty_recycle_bin(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !e.is_deleted());
        let removed = before - self.entries.len();
        if removed > 0 {
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
        removed
    }

    /// Soft-delete an entry (move to recycle bin instead of permanent delete).
    pub fn soft_delete_entry(&mut self, id: &str) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.soft_delete();
            self.updated_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    /// Restore a soft-deleted entry from recycle bin.
    pub fn restore_entry(&mut self, id: &str) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id && e.is_deleted()) {
            entry.restore();
            self.updated_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    /// Verify vault integrity — recompute BLAKE3 hash of all entries and compare.
    pub fn integrity_check(&self) -> IntegrityResult {
        let json = serde_json::to_string(&self.entries).unwrap_or_default();
        let hash = blake3::hash(json.as_bytes()).to_hex().to_string();
        let entry_count = self.entries.len();
        let deleted_count = self.entries.iter().filter(|e| e.is_deleted()).count();
        let has_orphan_links = self.entries.iter().any(|e| {
            e.linked_entry_ids.iter().any(|link_id| {
                !self.entries.iter().any(|other| other.id == *link_id)
            })
        });
        IntegrityResult {
            valid: !has_orphan_links,
            hash,
            entry_count,
            deleted_count,
            orphan_links: has_orphan_links,
        }
    }

    /// Compact the vault — remove deleted entries, trim history, remove orphan links.
    pub fn compact(&mut self) -> CompactResult {
        let deleted = self.empty_recycle_bin();
        let mut history_trimmed = 0usize;
        let max_history = 20;
        // Collect valid IDs before mutable iteration
        let valid_ids: Vec<String> = self.entries.iter().map(|e| e.id.clone()).collect();
        for entry in &mut self.entries {
            if entry.history.len() > max_history {
                let excess = entry.history.len() - max_history;
                entry.history.drain(..excess);
                history_trimmed += excess;
            }
            entry.linked_entry_ids.retain(|id| valid_ids.contains(id));
        }
        if deleted > 0 || history_trimmed > 0 {
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
        CompactResult { deleted_removed: deleted, history_trimmed }
    }

    /// Get the anti-phishing token (derived from vault name + creation date).
    pub fn anti_phishing_token(&self) -> String {
        let input = format!("tallow-antiphish:{}:{}", self.name, self.created_at);
        let hash = blake3::hash(input.as_bytes());
        // Use first 4 bytes as a visual token (8 hex chars)
        hash.to_hex()[..8].to_string()
    }

    pub fn search(&self, query: &str) -> Vec<&VaultEntry> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| !e.is_deleted()) // Exclude recycle bin
            .filter(|e| {
                // Match against name.
                if e.name.to_lowercase().contains(&q) {
                    return true;
                }
                // Match against username / primary identifier.
                if let Some(u) = e.username() {
                    if u.to_lowercase().contains(&q) {
                        return true;
                    }
                }
                // Match against URLs (login entries).
                if let EntryData::Login(ref login) = e.data {
                    for url in &login.urls {
                        if url.to_lowercase().contains(&q) {
                            return true;
                        }
                    }
                }
                // Match against tags.
                for tag in &e.tags {
                    if tag.to_lowercase().contains(&q) {
                        return true;
                    }
                }
                // Match against notes.
                if let Some(ref notes) = e.notes {
                    if notes.to_lowercase().contains(&q) {
                        return true;
                    }
                }
                false
            })
            .collect()
    }

    /// List entries belonging to a specific folder (excludes deleted).
    pub fn list_by_folder(&self, folder: &str) -> Vec<&VaultEntry> {
        self.entries
            .iter()
            .filter(|e| !e.is_deleted() && e.folder.as_deref() == Some(folder))
            .collect()
    }

    /// List all favorited entries (excludes deleted).
    pub fn list_favorites(&self) -> Vec<&VaultEntry> {
        self.entries.iter().filter(|e| !e.is_deleted() && e.favorite).collect()
    }

    /// Add a folder to the vault (no-op if already exists).
    pub fn add_folder(&mut self, folder: &str) {
        let f = folder.to_string();
        if !self.folders.contains(&f) {
            self.folders.push(f);
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Change the master password — re-encrypt vault with a new password.
    ///
    /// Verifies the old password by attempting to open the vault, then saves
    /// with the new password (which generates a fresh random salt and nonce).
    pub fn change_password(path: &str, old_password: &str, new_password: &str) -> Result<(), String> {
        if new_password.is_empty() {
            return Err("vault: new password must not be empty".into());
        }
        let db = Self::open(path, old_password)?;
        db.save(path, new_password)?;
        Ok(())
    }

    /// Select the classical at-rest cipher used by subsequent `save` calls.
    ///
    /// `cipher` must be [`CIPHER_XCHACHA20_POLY1305`] (v3 — 192-bit random
    /// nonce + per-object DEK; the default for new non-hybrid vaults) or
    /// [`CIPHER_AES_256_GCM`] (legacy v1 container, kept writable on request).
    /// Unknown names are rejected so a typo can never silently downgrade the
    /// on-disk format.
    ///
    /// This is also the migration seam (W3 #141/#142): open a v1 vault,
    /// `set_cipher(CIPHER_XCHACHA20_POLY1305)`, `save` — the file is rewritten
    /// as v3 with a fresh salt, a fresh per-object DEK and fresh nonces.
    /// Nothing changes on disk until `save` runs. While `pqc_enabled` is true
    /// the preference is retained but not consumed (hybrid v2 saves; see the
    /// module docs for the compatibility matrix).
    pub fn set_cipher(&mut self, cipher: &str) -> Result<(), String> {
        match cipher {
            CIPHER_XCHACHA20_POLY1305 | CIPHER_AES_256_GCM => {
                self.settings.cipher = cipher.to_string();
                Ok(())
            }
            other => Err(format!(
                "vault: unknown cipher '{other}' (expected '{CIPHER_XCHACHA20_POLY1305}' \
                 or '{CIPHER_AES_256_GCM}')"
            )),
        }
    }

    /// Create a new unlocked `VaultLockState` using this vault's auto-lock setting.
    pub fn lock_state(&self) -> VaultLockState {
        VaultLockState::new_unlocked(self.settings.auto_lock_seconds)
    }

    /// Create a timestamped backup of the vault file.
    ///
    /// Copies `path` to `path.YYYYMMDD-HHMMSS.bak` and returns the backup path.
    pub fn backup(path: &str) -> Result<String, String> {
        if !std::path::Path::new(path).exists() {
            return Err(format!("vault: cannot backup '{}': file not found", path));
        }
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let backup_path = format!("{}.{}.bak", path, stamp);
        std::fs::copy(path, &backup_path)
            .map_err(|e| format!("vault: backup failed: {e}"))?;
        Ok(backup_path)
    }

    /// Total number of entries in the vault.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// One-line summary of vault contents.
    pub fn summary(&self) -> String {
        let mut logins = 0u32;
        let mut cards = 0u32;
        let mut notes = 0u32;
        let mut identities = 0u32;
        let mut ssh_keys = 0u32;
        let mut api_keys = 0u32;
        let mut totps = 0u32;

        for e in &self.entries {
            match &e.data {
                EntryData::Login(_) => logins += 1,
                EntryData::Card(_) => cards += 1,
                EntryData::SecureNote(_) => notes += 1,
                EntryData::Identity(_) => identities += 1,
                EntryData::SSHKey(_) => ssh_keys += 1,
                EntryData::APIKey(_) => api_keys += 1,
                EntryData::TOTP(_) => totps += 1,
            }
        }

        let mut parts = Vec::new();
        if logins > 0 {
            parts.push(format!("{logins} login{}", if logins == 1 { "" } else { "s" }));
        }
        if cards > 0 {
            parts.push(format!("{cards} card{}", if cards == 1 { "" } else { "s" }));
        }
        if notes > 0 {
            parts.push(format!("{notes} note{}", if notes == 1 { "" } else { "s" }));
        }
        if identities > 0 {
            parts.push(format!("{identities} identit{}", if identities == 1 { "y" } else { "ies" }));
        }
        if ssh_keys > 0 {
            parts.push(format!("{ssh_keys} SSH key{}", if ssh_keys == 1 { "" } else { "s" }));
        }
        if api_keys > 0 {
            parts.push(format!("{api_keys} API key{}", if api_keys == 1 { "" } else { "s" }));
        }
        if totps > 0 {
            parts.push(format!("{totps} TOTP{}", if totps == 1 { "" } else { "s" }));
        }

        let items = if parts.is_empty() {
            "empty".to_string()
        } else {
            parts.join(", ")
        };

        format!(
            "Vault '{}': {} entries ({}) in {} folders",
            self.name,
            self.entries.len(),
            items,
            self.folders.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    #[test]
    fn new_vault_is_empty() {
        let db = VaultDatabase::new("test");
        assert_eq!(db.name, "test");
        assert_eq!(db.entry_count(), 0);
        assert!(db.entries.is_empty());
        assert!(db.folders.is_empty());
    }

    #[test]
    fn add_and_search_entries() {
        let mut db = VaultDatabase::new("test");
        db.add_entry(VaultEntry::new_login(
            "GitHub",
            "user@example.com",
            "hunter2",
            vec!["https://github.com".into()],
        ));
        db.add_entry(VaultEntry::new_note("My Note", "secret stuff"));

        assert_eq!(db.entry_count(), 2);

        let results = db.search("github");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "GitHub");

        let results = db.search("example.com");
        assert_eq!(results.len(), 1);

        let results = db.search("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn remove_entry() {
        let mut db = VaultDatabase::new("test");
        let entry = VaultEntry::new_note("Note", "content");
        let id = entry.id.clone();
        db.add_entry(entry);
        assert_eq!(db.entry_count(), 1);

        let removed = db.remove_entry(&id);
        assert!(removed.is_some());
        assert_eq!(db.entry_count(), 0);

        assert!(db.remove_entry("nonexistent").is_none());
    }

    #[test]
    fn folders() {
        let mut db = VaultDatabase::new("test");
        db.add_folder("Social");
        db.add_folder("Work");
        db.add_folder("Social"); // duplicate — should be ignored
        assert_eq!(db.folders.len(), 2);
    }

    #[test]
    fn favorites() {
        let mut db = VaultDatabase::new("test");
        let mut entry = VaultEntry::new_login("Fav", "user", "pass", vec![]);
        entry.favorite = true;
        db.add_entry(entry);
        db.add_entry(VaultEntry::new_login("NotFav", "user", "pass", vec![]));

        let favs = db.list_favorites();
        assert_eq!(favs.len(), 1);
        assert_eq!(favs[0].name, "Fav");
    }

    #[test]
    fn list_by_folder() {
        let mut db = VaultDatabase::new("test");
        let mut e1 = VaultEntry::new_login("A", "u", "p", vec![]);
        e1.folder = Some("Work".into());
        let mut e2 = VaultEntry::new_login("B", "u", "p", vec![]);
        e2.folder = Some("Personal".into());
        let e3 = VaultEntry::new_login("C", "u", "p", vec![]);
        db.add_entry(e1);
        db.add_entry(e2);
        db.add_entry(e3);

        assert_eq!(db.list_by_folder("Work").len(), 1);
        assert_eq!(db.list_by_folder("Personal").len(), 1);
        assert_eq!(db.list_by_folder("Missing").len(), 0);
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let tmp = std::env::temp_dir().join("tallow_vault_test.twv");
        let path = tmp.to_str().unwrap();
        let password = "correct-horse-battery-staple";

        let mut db = VaultDatabase::new("roundtrip-test");
        db.add_entry(VaultEntry::new_login(
            "Example",
            "admin",
            "s3cret!",
            vec!["https://example.com".into()],
        ));
        db.add_folder("Servers");
        db.save_unchecked(path, password).expect("save failed");

        let loaded = VaultDatabase::open(path, password).expect("open failed");
        assert_eq!(loaded.name, "roundtrip-test");
        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(loaded.entries[0].name, "Example");
        assert_eq!(loaded.folders, vec!["Servers"]);

        // Wrong password should fail.
        let err = VaultDatabase::open(path, "wrong-password");
        assert!(err.is_err());

        // Clean up.
        let _ = std::fs::remove_file(path);
    }

    // ── PQC hybrid at-rest (.twv v2) ─────────────────────────────────────

    /// Unique temp file path per test so parallel vault tests don't collide.
    fn tmp_path(name: &str) -> String {
        std::env::temp_dir().join(name).to_str().unwrap().to_string()
    }

    /// Flip one hex digit of a named field in the JSON PQC blob body of a v2
    /// hybrid vault, keeping the file structurally valid (JSON still parses).
    /// `out_path` receives the tampered file; `path` is left untouched.
    fn tamper_body_field(path: &str, field: &str, out_path: &str) {
        let mut bytes = std::fs::read(path).expect("read hybrid vault");
        let mut body: serde_json::Value =
            serde_json::from_slice(&bytes[TWV_HYBRID_HEADER_SIZE..]).expect("parse PQC blob body");
        let val = body[field].as_str().expect("field must be a hex string").to_string();
        assert!(val.len() > 6, "field too short to tamper: {field}");
        let mut chars: Vec<char> = val.chars().collect();
        chars[5] = if chars[5] == '0' { '1' } else { '0' };
        body[field] = serde_json::Value::String(chars.into_iter().collect());
        let new_body = serde_json::to_vec(&body).expect("serialize tampered blob");
        bytes.truncate(TWV_HYBRID_HEADER_SIZE);
        bytes.extend_from_slice(&new_body);
        std::fs::write(out_path, &bytes).expect("write tampered vault");
    }

    fn make_pqc_db(name: &str) -> VaultDatabase {
        let mut db = VaultDatabase::new(name);
        db.settings.pqc_enabled = true;
        db.add_entry(VaultEntry::new_login(
            "PQCSite",
            "alice",
            "s3cret!",
            vec!["https://pqcsite.example".into()],
        ));
        db.add_entry(VaultEntry::new_note("PQC Note", "quantum-safe note body"));
        db.add_folder("PQC-Folder");
        db
    }

    #[test]
    fn pqc_hybrid_roundtrip() {
        let path = tmp_path("tallow_vault_pqc_roundtrip.twv");
        let db = make_pqc_db("pqc-rt");
        db.save_unchecked(&path, "master-pw").expect("hybrid save failed");

        // Header version marker: v2 hybrid format must be on disk.
        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(&bytes[0..4], TWV_MAGIC);
        assert_eq!(
            bytes[4],
            TWV_VERSION_HYBRID,
            "pqc_enabled save must write the v2 hybrid header marker"
        );
        assert!(bytes.len() > TWV_HYBRID_HEADER_SIZE);

        // No plaintext payload may appear anywhere in the file (both AEAD
        // layers are live on the stored bytes).
        for needle in [b"PQCSite".as_slice(), b"s3cret!".as_slice()] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "plaintext leaked into the .twv file"
            );
        }

        // Save-with-pqc -> load-with-pqc roundtrip.
        let loaded = VaultDatabase::open(&path, "master-pw").expect("hybrid open failed");
        assert!(loaded.settings.pqc_enabled);
        assert_eq!(loaded.name, "pqc-rt");
        assert_eq!(loaded.entry_count(), 2);
        assert_eq!(loaded.entries[0].name, "PQCSite");
        assert_eq!(loaded.folders, vec!["PQC-Folder"]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pqc_hybrid_wrong_password_is_honest_error() {
        let path = tmp_path("tallow_vault_pqc_wrongpw.twv");
        let db = make_pqc_db("pqc-wpw");
        db.save_unchecked(&path, "master-pw").expect("hybrid save failed");

        let err = VaultDatabase::open(&path, "wrong-password").expect_err("must fail");
        assert!(
            err.contains("wrong password") || err.contains("unwrap"),
            "wrong-password error should be explicit, got: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn classic_vault_still_roundtrips_when_pqc_disabled() {
        // Pre-existing non-PQC vault: pqc_enabled=false + explicit
        // "aes-256-gcm" writes v1 and v1 must open through the preserved
        // legacy path (backward compatibility). Since W3 #141/#142 the
        // implicit default cipher is "xchacha20-poly1305" (v3), so legacy v1
        // writing is pinned here explicitly.
        let path = tmp_path("tallow_vault_classic_bw.twv");
        let mut db = VaultDatabase::new("classic-bw");
        // A6.1.3: new vaults default to hybrid; this test pins the classic
        // path, so it opts out explicitly.
        db.settings.pqc_enabled = false;
        db.settings.cipher = CIPHER_AES_256_GCM.to_string();
        db.add_entry(VaultEntry::new_login(
            "LegacySite",
            "bob",
            "old-pass",
            vec![],
        ));
        db.save_unchecked(&path, "legacy-pw").expect("classic save failed");

        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(bytes[4], TWV_VERSION_CLASSIC, "disabled save must stay v1");

        let loaded = VaultDatabase::open(&path, "legacy-pw").expect("classic open failed");
        assert!(!loaded.settings.pqc_enabled);
        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(loaded.entries[0].name, "LegacySite");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn enabling_pqc_upgrades_vault_to_hybrid() {
        // The exact flow of `vault pqc-enable`: open -> set flag -> save.
        let path = tmp_path("tallow_vault_upgrade.twv");
        let mut db = VaultDatabase::new("upgrade");
        db.add_entry(VaultEntry::new_login("Site", "u", "p", vec![]));
        db.save_unchecked(&path, "pw").expect("v1 save");

        let mut db = VaultDatabase::open(&path, "pw").expect("open v1");
        db.settings.pqc_enabled = true;
        db.save(&path, "pw").expect("v2 save");

        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(bytes[4], TWV_VERSION_HYBRID, "pqc-enabled save must upgrade to v2");

        let loaded = VaultDatabase::open(&path, "pw").expect("open v2");
        assert!(loaded.settings.pqc_enabled);
        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(loaded.entries[0].name, "Site");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disabling_pqc_downgrades_to_classic_and_still_reads() {
        // Downgrading from the hybrid container writes the vault's currently
        // selected classical cipher. Since W3 #141/#142 that default is
        // XChaCha20-Poly1305 (v3); both downgrade targets are covered here.
        let path = tmp_path("tallow_vault_downgrade.twv");
        let db = make_pqc_db("downgrade");
        db.save_unchecked(&path, "pw").expect("v2 save");

        let mut db = VaultDatabase::open(&path, "pw").expect("open v2");
        db.settings.pqc_enabled = false;
        db.save(&path, "pw").expect("v3 save");

        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(
            bytes[4], TWV_VERSION_XCHACHA,
            "disabled save must downgrade to the selected classical cipher (v3 default)"
        );

        let loaded = VaultDatabase::open(&path, "pw").expect("open v3");
        assert!(!loaded.settings.pqc_enabled);
        assert_eq!(loaded.settings.cipher, CIPHER_XCHACHA20_POLY1305);
        assert_eq!(loaded.entry_count(), 2);

        // Explicit legacy downgrade: set the old cipher and the same vault
        // rewrites as v1 (still readable).
        let mut db = loaded;
        db.set_cipher(CIPHER_AES_256_GCM).expect("set legacy cipher");
        db.save(&path, "pw").expect("v1 save");
        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(bytes[4], TWV_VERSION_CLASSIC, "explicit legacy cipher must write v1");
        let loaded = VaultDatabase::open(&path, "pw").expect("open v1");
        assert_eq!(loaded.entry_count(), 2);

        let _ = std::fs::remove_file(&path);
    }

    // ── XChaCha20-Poly1305 at-rest (.twv v3, W3 #141/#142 · P10-R06) ─────
    //
    // Layer note: the crate-side seal/open pattern (per-object DEK, AES-KW,
    // 192-bit nonce, usage ceiling) is unit-tested in
    // `tallow_crypto::symmetric::xchacha20`; these tests cover the container
    // wiring: version/cipher byte, on-disk layout, wrong password/tamper
    // rejection, header-KDF precedence, default selection and migration.

    /// Non-PQC fixture with the default (XChaCha) classical cipher.
    fn make_xchacha_db(name: &str) -> VaultDatabase {
        let mut db = VaultDatabase::new(name);
        db.settings.pqc_enabled = false;
        db.add_entry(VaultEntry::new_login(
            "XSite",
            "carol",
            "s3cret!",
            vec!["https://x.example".into()],
        ));
        db.add_entry(VaultEntry::new_note("XNote", "xchacha note body"));
        db.add_folder("X-Folder");
        db
    }

    /// Flip one byte of a `.twv` file at `offset`, writing the result to `out`.
    fn flip_byte_at(path: &str, offset: usize, out: &str) {
        let mut bytes = std::fs::read(path).expect("read vault");
        bytes[offset] ^= 0x01;
        std::fs::write(out, &bytes).expect("write tampered vault");
    }

    #[test]
    fn non_pqc_vault_defaults_to_xchacha_v3() {
        // W3 #141/#142: new vaults default their classical at-rest layer to
        // XChaCha20-Poly1305 — a non-hybrid vault with no explicit cipher
        // writes the v3 container.
        assert_eq!(VaultSettings::default().cipher, CIPHER_XCHACHA20_POLY1305);
        assert_eq!(
            VaultDatabase::new("d").settings.cipher,
            CIPHER_XCHACHA20_POLY1305
        );

        let path = tmp_path("tallow_vault_xchacha_default.twv");
        let db = make_xchacha_db("xchacha-default");
        db.save_unchecked(&path, "master-pw").expect("v3 save");

        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(&bytes[0..4], TWV_MAGIC);
        assert_eq!(
            bytes[4], TWV_VERSION_XCHACHA,
            "non-PQC default save must write v3"
        );
        assert_eq!(bytes[5], TWV_CIPHER_XCHACHA20_POLY1305, "v3 cipher id");
        assert!(bytes.len() > TWV_V3_BODY_OFFSET, "v3 must carry sealed fields");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn xchacha_v3_roundtrip() {
        let path = tmp_path("tallow_vault_v3_roundtrip.twv");
        let db = make_xchacha_db("v3-rt");
        db.save_unchecked(&path, "master-pw").expect("save failed");

        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(bytes[4], TWV_VERSION_XCHACHA);
        for needle in [
            b"XSite".as_slice(),
            b"s3cret!".as_slice(),
            b"xchacha note body".as_slice(),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "plaintext leaked into the .twv file"
            );
        }

        let loaded = VaultDatabase::open(&path, "master-pw").expect("open failed");
        assert_eq!(loaded.name, "v3-rt");
        assert_eq!(loaded.entry_count(), 2);
        assert_eq!(loaded.entries[0].name, "XSite");
        assert_eq!(loaded.folders, vec!["X-Folder"]);
        assert!(!loaded.settings.pqc_enabled);
        assert_eq!(loaded.settings.cipher, CIPHER_XCHACHA20_POLY1305);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn xchacha_v3_wrong_password_is_honest_error() {
        let path = tmp_path("tallow_vault_v3_wrongpw.twv");
        let db = make_xchacha_db("v3-wpw");
        db.save_unchecked(&path, "master-pw").expect("save");

        let err = VaultDatabase::open(&path, "wrong-password").expect_err("must fail");
        assert!(
            err.contains("wrong password") || err.contains("XChaCha"),
            "wrong-password error should be explicit, got: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn xchacha_v3_save_is_randomized() {
        let path_a = tmp_path("tallow_vault_v3_rand_a.twv");
        let path_b = tmp_path("tallow_vault_v3_rand_b.twv");
        let db = make_xchacha_db("v3-rand");
        db.save_unchecked(&path_a, "pw").expect("save a");
        db.save_unchecked(&path_b, "pw").expect("save b");

        let a = std::fs::read(&path_a).expect("read a");
        let b = std::fs::read(&path_b).expect("read b");
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b, "fresh salt/nonce/DEK must differ on disk");
        assert_ne!(&a[6..38], &b[6..38], "fresh KDF salt per save");
        assert_ne!(
            &a[TWV_V3_WRAPPED_DEK_OFFSET..TWV_V3_NONCE_OFFSET],
            &b[TWV_V3_WRAPPED_DEK_OFFSET..TWV_V3_NONCE_OFFSET],
            "fresh per-object DEK per save"
        );
        assert_ne!(
            &a[TWV_V3_NONCE_OFFSET..TWV_V3_BODY_OFFSET],
            &b[TWV_V3_NONCE_OFFSET..TWV_V3_BODY_OFFSET],
            "fresh 192-bit nonce per save"
        );

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn xchacha_v3_tamper_matrix_rejected() {
        let path = tmp_path("tallow_vault_v3_tamper.twv");
        let out = tmp_path("tallow_vault_v3_tamper_out.twv");
        let db = make_xchacha_db("v3-tamper");
        db.save_unchecked(&path, "pw").expect("save");
        let len = std::fs::read(&path).expect("read").len();

        for (offset, label) in [
            (6, "KDF salt (wrong KEK)"),
            (TWV_V3_WRAPPED_DEK_OFFSET + 5, "wrapped DEK"),
            (TWV_V3_NONCE_OFFSET + 3, "payload nonce"),
            (TWV_V3_BODY_OFFSET, "payload start"),
            (len - 1, "payload tag"),
        ] {
            flip_byte_at(&path, offset, &out);
            let err = VaultDatabase::open(&out, "pw")
                .expect_err(&format!("tampered {label} must fail"));
            assert!(
                err.contains("wrong password") || err.contains("DEK") || err.contains("XChaCha"),
                "unexpected {label} error: {err}"
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn xchacha_v3_cipher_id_version_and_size_guards() {
        let path = tmp_path("tallow_vault_v3_guards.twv");
        let out = tmp_path("tallow_vault_v3_guards_out.twv");
        let db = make_xchacha_db("v3-guards");
        db.save_unchecked(&path, "pw").expect("save");

        // Unknown v3 cipher id is rejected by name.
        flip_byte_at(&path, 5, &out); // id 1 -> 0
        let err = VaultDatabase::open(&out, "pw").expect_err("unknown cipher id must fail");
        assert!(err.contains("cipher id"), "unexpected: {err}");

        // Unknown container version is rejected with an explicit message.
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[4] = 9;
        std::fs::write(&out, &bytes).expect("write");
        let err = VaultDatabase::open(&out, "pw").expect_err("unknown version must fail");
        assert!(err.contains("unsupported version"), "unexpected: {err}");

        // Truncated file is rejected as too small (re-read: the buffer above
        // carries the version-9 mutation).
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.truncate(TWV_V3_BODY_OFFSET);
        std::fs::write(&out, &bytes).expect("write");
        let err = VaultDatabase::open(&out, "pw").expect_err("truncated must fail");
        assert!(err.contains("too small"), "unexpected: {err}");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn xchacha_v3_kdf_params_are_read_from_the_header() {
        let path = tmp_path("tallow_vault_v3_params.twv");
        let password = "params-pw";
        let db = make_xchacha_db("v3-params");
        let json = serde_json::to_vec(&db).expect("serialize");

        // Non-default Argon2id costs, written into the header by hand: the
        // reader must use THEM (writer/reader cost-class agreement, W2-03 §D7).
        let (m, t, p) = (32768u32, 2u32, 2u32);
        let mut salt = [0u8; 32];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let mut header = Vec::new();
        header.extend_from_slice(TWV_MAGIC);
        header.push(TWV_VERSION_XCHACHA);
        header.push(TWV_CIPHER_XCHACHA20_POLY1305);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&m.to_le_bytes());
        header.extend_from_slice(&t.to_le_bytes());
        header.extend_from_slice(&p.to_le_bytes());
        assert_eq!(header.len(), TWV_V3_HEADER_SIZE);

        let key = derive_key(password, &salt, m, t, p).expect("derive");
        let sealed = at_rest::seal_object(&key, &json, &header).expect("seal");
        let mut out = header;
        out.extend_from_slice(&sealed.wrapped_dek);
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.ciphertext);
        std::fs::write(&path, &out).expect("write");

        // Opens only if the header m/t/p drive the KEK derivation.
        let loaded = VaultDatabase::open(&path, password).expect("open with header params");
        assert_eq!(loaded.entry_count(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn xchacha_v3_migration_from_v1() {
        let path = tmp_path("tallow_vault_v1_to_v3.twv");
        // v1 on disk (legacy writer, explicit AES cipher). The login entry is
        // deliberately present BEFORE the first save so the migration has a
        // secret to carry over.
        let mut db = VaultDatabase::new("migrate");
        db.settings.pqc_enabled = false;
        db.settings.cipher = CIPHER_AES_256_GCM.to_string();
        db.add_entry(VaultEntry::new_login("MigSite", "dave", "pw1", vec![]));
        db.save_unchecked(&path, "mig-pw").expect("v1 save");
        let before = std::fs::read(&path).expect("read v1");
        assert_eq!(before[4], TWV_VERSION_CLASSIC);
        let salt_before = before[6..38].to_vec();

        // Migration seam: open -> set_cipher -> save.
        let mut db = VaultDatabase::open(&path, "mig-pw").expect("open v1");
        db.set_cipher(CIPHER_XCHACHA20_POLY1305).expect("set cipher");
        db.save(&path, "mig-pw").expect("v3 save");

        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(bytes[4], TWV_VERSION_XCHACHA, "migration must rewrite as v3");
        assert_ne!(
            &bytes[6..38],
            salt_before.as_slice(),
            "migration must generate a fresh KDF salt"
        );

        let loaded = VaultDatabase::open(&path, "mig-pw").expect("open v3");
        assert_eq!(loaded.entries[0].name, "MigSite");
        assert_eq!(loaded.settings.cipher, CIPHER_XCHACHA20_POLY1305);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_cipher_rejects_unknown_names() {
        let mut db = VaultDatabase::new("set-cipher");
        db.set_cipher(CIPHER_XCHACHA20_POLY1305).expect("xchacha accepted");
        assert_eq!(db.settings.cipher, CIPHER_XCHACHA20_POLY1305);
        db.set_cipher(CIPHER_AES_256_GCM).expect("aes accepted");
        assert_eq!(db.settings.cipher, CIPHER_AES_256_GCM);

        let err = db.set_cipher("rot13").expect_err("unknown must be rejected");
        assert!(err.contains("unknown cipher"), "unexpected: {err}");
        // A rejected name must not change the selection.
        assert_eq!(db.settings.cipher, CIPHER_AES_256_GCM);
    }

    #[test]
    fn hybrid_save_keeps_v2_even_with_xchacha_preference() {
        // Documented interaction: while pqc_enabled is true, saves are the v2
        // hybrid container and the cipher preference is retained (payload
        // metadata) but not consumed.
        let path = tmp_path("tallow_vault_xchacha_hybrid.twv");
        let mut db = make_pqc_db("xchacha-hybrid");
        db.set_cipher(CIPHER_XCHACHA20_POLY1305).expect("set");
        db.save_unchecked(&path, "pw").expect("save");

        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes[4], TWV_VERSION_HYBRID, "hybrid save must stay v2");

        let loaded = VaultDatabase::open(&path, "pw").expect("open");
        assert_eq!(
            loaded.settings.cipher, CIPHER_XCHACHA20_POLY1305,
            "cipher preference must be retained"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hybrid_vault_outer_layer_tamper_rejected() {
        let path = tmp_path("tallow_vault_pqc_outer.twv");
        let out = tmp_path("tallow_vault_pqc_outer_tampered.twv");
        let db = make_pqc_db("pqc-outer");
        db.save_unchecked(&path, "pw").expect("save");

        // Flip one ciphertext bit of the *outer* (ML-KEM-keyed) AEAD layer.
        tamper_body_field(&path, "encrypted_data", &out);
        let err = VaultDatabase::open(&out, "pw").expect_err("tampered outer layer must fail");
        assert!(
            err.contains("decrypt") || err.contains("AEAD") || err.contains("PQC"),
            "unexpected outer-layer error: {err}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn hybrid_vault_inner_layer_tamper_rejected() {
        let path = tmp_path("tallow_vault_pqc_inner.twv");
        let out = tmp_path("tallow_vault_pqc_inner_tampered.twv");
        let db = make_pqc_db("pqc-inner");
        db.save_unchecked(&path, "pw").expect("save");

        // Flip a bit of the *inner* classical nonce. The outer ML-KEM layer is
        // untouched and still decrypts — only the inner Argon2id-keyed AEAD
        // layer catches the tampering, proving it is a real, independent layer.
        tamper_body_field(&path, "classical_nonce", &out);
        let err = VaultDatabase::open(&out, "pw").expect_err("tampered inner layer must fail");
        assert!(
            err.contains("decrypt") || err.contains("password"),
            "unexpected inner-layer error: {err}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn hybrid_vault_pqc_ciphertext_tamper_rejected() {
        let path = tmp_path("tallow_vault_pqc_ct.twv");
        let out = tmp_path("tallow_vault_pqc_ct_tampered.twv");
        let db = make_pqc_db("pqc-ct");
        db.save_unchecked(&path, "pw").expect("save");

        // Flip a bit of the ML-KEM-768 ciphertext: shared secret changes, the
        // authenticated outer layer must reject the decrypted blob.
        tamper_body_field(&path, "pqc_ciphertext", &out);
        let err = VaultDatabase::open(&out, "pw").expect_err("tampered ML-KEM ct must fail");
        assert!(
            err.contains("decrypt") || err.contains("PQC"),
            "unexpected ML-KEM tamper error: {err}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn hybrid_vault_header_tamper_rejected() {
        let path = tmp_path("tallow_vault_pqc_hdr.twv");
        let out = tmp_path("tallow_vault_pqc_hdr_tampered.twv");
        let db = make_pqc_db("pqc-hdr");
        db.save_unchecked(&path, "pw").expect("save");

        // Flip one byte inside the wrapped ML-KEM decapsulation key region of
        // the fixed header.
        let mut bytes = std::fs::read(&path).expect("read vault");
        bytes[100] ^= 0x01;
        std::fs::write(&out, &bytes).expect("write tampered vault");

        let err = VaultDatabase::open(&out, "pw").expect_err("tampered header must fail");
        assert!(
            err.contains("unwrap") || err.contains("wrong password"),
            "unexpected header-tamper error: {err}"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn change_password_works_on_hybrid_vault() {
        let path = tmp_path("tallow_vault_pqc_chpw.twv");
        let db = make_pqc_db("pqc-chpw");
        db.save_unchecked(&path, "old-pw").expect("v2 save");

        VaultDatabase::change_password(&path, "old-pw", "new-pw").expect("change password");

        assert!(VaultDatabase::open(&path, "old-pw").is_err());
        let loaded = VaultDatabase::open(&path, "new-pw").expect("open with new pw");
        assert!(loaded.settings.pqc_enabled);
        assert_eq!(loaded.entry_count(), 2);
        let bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(bytes[4], TWV_VERSION_HYBRID, "hybrid vault must stay v2");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn summary_format() {
        let mut db = VaultDatabase::new("demo");
        db.add_entry(VaultEntry::new_login("A", "u", "p", vec![]));
        db.add_entry(VaultEntry::new_login("B", "u", "p", vec![]));
        db.add_entry(VaultEntry::new_note("N", "text"));
        db.add_folder("F1");

        let s = db.summary();
        assert!(s.contains("3 entries"));
        assert!(s.contains("2 logins"));
        assert!(s.contains("1 note"));
        assert!(s.contains("1 folders"));
    }

    #[test]
    fn change_password() {
        let tmp = std::env::temp_dir().join("tallow_vault_chpw.twv");
        let path = tmp.to_str().unwrap();
        let old_pw = "old-password";
        let new_pw = "new-password";

        let mut db = VaultDatabase::new("chpw-test");
        db.add_entry(VaultEntry::new_login("X", "u", "p", vec![]));
        db.save_unchecked(path, old_pw).expect("save");

        VaultDatabase::change_password(path, old_pw, new_pw).expect("change password");

        // Old password should fail.
        assert!(VaultDatabase::open(path, old_pw).is_err());
        // New password should work.
        let loaded = VaultDatabase::open(path, new_pw).expect("open with new pw");
        assert_eq!(loaded.entry_count(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn change_password_wrong_old() {
        let tmp = std::env::temp_dir().join("tallow_vault_chpw_bad.twv");
        let path = tmp.to_str().unwrap();

        let db = VaultDatabase::new("test");
        db.save_unchecked(path, "real-pw").expect("save");

        let result = VaultDatabase::change_password(path, "wrong-pw", "new-pw");
        assert!(result.is_err());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn backup_creates_file() {
        let tmp = std::env::temp_dir().join("tallow_vault_backup.twv");
        let path = tmp.to_str().unwrap();

        let db = VaultDatabase::new("backup-test");
        db.save_unchecked(path, "pw").expect("save");

        let backup_path = VaultDatabase::backup(path).expect("backup");
        assert!(std::path::Path::new(&backup_path).exists());
        assert!(backup_path.ends_with(".bak"));

        // Backup should be openable with same password.
        let loaded = VaultDatabase::open(&backup_path, "pw").expect("open backup");
        assert_eq!(loaded.name, "backup-test");

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn lock_state_auto_lock() {
        let db = VaultDatabase::new("lock-test");
        let state = db.lock_state();
        assert!(!state.locked);
        assert!(state.unlocked_at.is_some());
        assert_eq!(state.auto_lock_seconds, 300);
        // Should not lock immediately.
        assert!(!state.should_lock());
    }

    #[test]
    fn lock_state_expired() {
        let mut state = VaultLockState {
            locked: false,
            unlocked_at: Some("2020-01-01T00:00:00Z".to_string()),
            auto_lock_seconds: 1,
        };
        // Way past the 1-second auto-lock window.
        assert!(state.should_lock());

        state.lock();
        assert!(state.locked);
        // Should not lock again when already locked.
        assert!(!state.should_lock());

        state.unlock();
        assert!(!state.locked);
        assert!(state.unlocked_at.is_some());
    }
}
