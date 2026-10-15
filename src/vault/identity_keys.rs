//! Vault identity-key custody (U-217; finding G-03 of `impl/U-201.md`).
//!
//! Stores the private halves of the **node** and **SVID-issuer** identity
//! keys (Ed25519) under the vault's state area. This is the identity-key
//! counterpart of [`super::key_custody`] (shred-key material): both wrap
//! their payload with the same password-bound hybrid construction from
//! [`super::pqc`], so a stolen file yields no usable key without the vault
//! password:
//!
//! * state directory mode `0700`, key files mode `0600` — enforced on write
//!   (and re-tightened best-effort on load); loads refuse symlinks and
//!   non-regular files;
//! * every read requires the vault password: inner AES-256-GCM keyed by
//!   `Argon2id(password, BLAKE3(EK))`, outer authenticated AEAD keyed by the
//!   ML-KEM-768 shared secret, plus an ML-KEM decapsulation key wrapped
//!   under `Argon2id(password, BLAKE3(EK))` via `pqc::pqc_wrap_dk`;
//! * wrong passphrase and a tampered file are indistinguishable (AEAD
//!   authentication) and surface as [`IdentityKeyError::Crypto`].
//!
//! Nothing auto-loads this module yet (additive, U-217). It is **consumed by
//! the SVID issuer wiring in a later wave** (checklist U-212 `tallow-svid`
//! `NodeIssuer` / daemon svid wiring): the issuer keeps its node key and its
//! ≤7 d intermediate-CA key here between runs, and the daemon refuses
//! identity operations while the vault is locked (U-201 finding G-03,
//! report §5.7.7).
//!
//! # Layout
//!
//! ```text
//! {state_dir}/node-identity.key.json      IdentityKeyRole::Node
//! {state_dir}/issuer-identity.key.json    IdentityKeyRole::Issuer
//! ```
//!
//! `{state_dir}` is caller-supplied; [`default_state_dir`] resolves the
//! daemon default. Sealed files are JSON, same envelope construction as
//! `key_custody`:
//!
//! ```text
//! { "version": 1,
//!   "role": "node",
//!   "blob": <pqc::PQCEncryptedBlob as JSON>,
//!   "dk_nonce": "<24 hex chars>",
//!   "wrapped_dk": "<hex>" }
//! ```
//!
//! # Material-handling rules
//!
//! * [`IdentityKeyPair`] implements neither `Clone` nor `Serialize` (both
//!   would mint or print an unwiped copy of the secret); its `Debug` redacts
//!   the private half and `Drop` zeroizes it — the
//!   [`super::pqc::PQCKeyPair`] pattern.
//! * No error variant carries key bytes: the on-disk envelope holds
//!   ciphertext only, and the decrypted payload is parsed with
//!   presence/length checks whose messages never echo content.
//! * Removal ([`remove_key`]) is deliberately *not* password-gated — it is a
//!   directory-write (policy) action, not a read of material — and it is not
//!   a secure erase: leftover blocks depend on the filesystem. The
//!   password-bound copy becomes unrecoverable once the password is lost,
//!   regardless of the file's presence.

use std::fmt;
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::pqc;

/// Sealed-file format version this module writes and reads.
pub const IDENTITY_KEY_VERSION: u32 = 1;

/// Algorithm tag for identity keys: Ed25519 — the vault's existing signing
/// primitive (`vault::ssh_agent`) and what the `rcgen`-based SVID issuer
/// signs with (U-201 D-1).
pub const KEY_ALGORITHM_ED25519: &str = "ed25519";

/// Environment override for [`default_state_dir`]: `TALLOW_VAULT_IDENTITY_DIR`.
pub const STATE_DIR_ENV: &str = "TALLOW_VAULT_IDENTITY_DIR";

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// Which identity key a file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKeyRole {
    /// This host's node identity key.
    Node,
    /// The local SVID-issuer (intermediate CA) key.
    Issuer,
}

impl IdentityKeyRole {
    /// File name used inside the state directory.
    pub fn file_name(self) -> &'static str {
        match self {
            IdentityKeyRole::Node => "node-identity.key.json",
            IdentityKeyRole::Issuer => "issuer-identity.key.json",
        }
    }

    /// Short tag used in the sealed envelope and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityKeyRole::Node => "node",
            IdentityKeyRole::Issuer => "issuer",
        }
    }
}

impl fmt::Display for IdentityKeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from identity-key custody operations.
///
/// No variant ever carries key material: the payload variants hold OS or
/// format diagnostics only, and the decrypted payload is parsed with fixed
/// messages that never echo content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityKeyError {
    /// Filesystem failure while creating the state area or reading/writing a
    /// key file.
    Io(String),
    /// Sealed-container or payload format problem (hex/JSON/version/role/
    /// algorithm/length mismatch).
    Codec(String),
    /// Crypto-layer refusal: wrong passphrase, tampered sealed file, or a
    /// seal-side failure. Wrong passphrase and tampering are intentionally
    /// indistinguishable (AEAD authentication).
    Crypto(String),
    /// No identity key is stored for the requested role.
    NotFound,
    /// A path failed a safety check: symlink, non-regular file, or a
    /// directory where a key file is expected.
    UnsafePath(String),
}

impl fmt::Display for IdentityKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityKeyError::Io(msg) => write!(f, "identity_keys: io error: {msg}"),
            IdentityKeyError::Codec(msg) => write!(f, "identity_keys: codec error: {msg}"),
            IdentityKeyError::Crypto(msg) => write!(
                f,
                "identity_keys: unlock refused (wrong passphrase or tampered seal): {msg}"
            ),
            IdentityKeyError::NotFound => {
                write!(f, "identity_keys: no stored identity key for this role")
            }
            IdentityKeyError::UnsafePath(msg) => write!(f, "identity_keys: unsafe path: {msg}"),
        }
    }
}

impl std::error::Error for IdentityKeyError {}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/// An Ed25519 identity key pair (public + private halves, hex-encoded).
///
/// Deliberately implements none of:
/// * `Clone` — a clone would be an independent, **unwiped** copy of the
///   private half (same rule as [`super::pqc::PQCKeyPair`]);
/// * `Serialize` / `Deserialize` — key material must not cross a
///   serialization boundary; the on-disk envelope carries ciphertext only.
///
/// `Debug` prints the public half and redacts the secret; `Drop` zeroizes
/// the secret. The private half is reachable only as borrowed hex via
/// [`IdentityKeyPair::secret_key_hex`].
pub struct IdentityKeyPair {
    algorithm: String,
    public_key: String,
    secret_key: String,
}

impl IdentityKeyPair {
    /// Generate a fresh Ed25519 identity key pair with the vault's existing
    /// keygen primitive (`ed25519-dalek`, identical construction to
    /// `vault::ssh_agent::generate_ed25519_key`).
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;

        let signing = SigningKey::generate(&mut rand_core_06::OsRng);
        let mut secret = signing.to_bytes();
        let secret_hex = hex_encode(&secret);
        secret.zeroize();
        Self {
            algorithm: KEY_ALGORITHM_ED25519.to_string(),
            public_key: hex_encode(signing.verifying_key().as_bytes()),
            secret_key: secret_hex,
        }
    }

    /// Algorithm tag of this key (always [`KEY_ALGORITHM_ED25519`] today).
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Hex-encoded public half — safe to log.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key
    }

    /// Hex-encoded private half. **Sensitive**: hand it only to the signer
    /// that needs it; never format it into logs or errors.
    pub fn secret_key_hex(&self) -> &str {
        &self.secret_key
    }

    /// Non-secret stable identifier for logs/audit: BLAKE3 of the public
    /// half, first 8 bytes as hex (16 chars).
    pub fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tallow-identity-key-fp-v1");
        hasher.update(self.public_key.as_bytes());
        hasher.finalize().to_hex()[..16].to_string()
    }

    /// Validate and adopt payload halves (used by `unseal_key` only).
    fn from_parts(
        algorithm: &str,
        public_key: &str,
        secret_key: &str,
    ) -> Result<Self, IdentityKeyError> {
        if algorithm != KEY_ALGORITHM_ED25519 {
            return Err(IdentityKeyError::Codec(
                "identity payload: unsupported key algorithm".to_string(),
            ));
        }
        let pk = hex_decode(public_key).map_err(|_| {
            IdentityKeyError::Codec("identity payload: public key is not hex".to_string())
        })?;
        let mut sk = hex_decode(secret_key).map_err(|_| {
            IdentityKeyError::Codec("identity payload: secret key is not hex".to_string())
        })?;
        if pk.len() != 32 || sk.len() != 32 {
            let msg = format!(
                "identity payload: ed25519 keys must be 32 bytes (public {}, secret {})",
                pk.len(),
                sk.len()
            );
            sk.zeroize();
            return Err(IdentityKeyError::Codec(msg));
        }
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk);
        sk.zeroize();
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        // Fail closed on a mismatched pair (cross-wired or corrupted halves).
        let derived = ed25519_dalek::SigningKey::from_bytes(&sk_arr)
            .verifying_key()
            .to_bytes();
        sk_arr.zeroize();
        if derived != pk_arr {
            return Err(IdentityKeyError::Codec(
                "identity payload: public and secret halves do not match".to_string(),
            ));
        }
        Ok(Self {
            algorithm: KEY_ALGORITHM_ED25519.to_string(),
            public_key: public_key.to_string(),
            secret_key: secret_key.to_string(),
        })
    }
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Sealed envelope
// ---------------------------------------------------------------------------

/// A sealed identity-key file (see module docs). Ciphertext + public wrap
/// metadata only — the secret exists in the clear only inside a seal/unseal
/// call.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedIdentityKey {
    /// Format version ([`IDENTITY_KEY_VERSION`]).
    pub version: u32,
    /// Role this file was sealed for (refused on mismatch).
    pub role: IdentityKeyRole,
    /// Sealed payload (hybrid double-encrypted).
    pub blob: pqc::PQCEncryptedBlob,
    /// Hex-encoded 12-byte nonce wrapping the ML-KEM decapsulation key.
    pub dk_nonce: String,
    /// Hex-encoded ML-KEM decapsulation key, wrapped under the password.
    pub wrapped_dk: String,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// The vault's default state area for identity keys:
/// `$TALLOW_VAULT_IDENTITY_DIR` when set and non-empty, else
/// `<home>/.tallow/vault/identity-keys`, else `./.tallow/vault/identity-keys`.
///
/// The leaf directory is created and tightened to `0700` on first store, as
/// is every parent directory this module creates below the deepest
/// pre-existing ancestor. Parent directories that already exist are left
/// alone — point the override at a directory you consider private.
pub fn default_state_dir() -> PathBuf {
    let env = std::env::var(STATE_DIR_ENV).ok();
    resolve_state_dir(env.as_deref(), dirs::home_dir().as_deref())
}

/// Pure resolution step of [`default_state_dir`] (unit-tested directly so
/// the env path needs no process-global mutation).
fn resolve_state_dir(env_override: Option<&str>, home: Option<&Path>) -> PathBuf {
    if let Some(value) = env_override {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    let base = match home {
        Some(home) => home.to_path_buf(),
        None => PathBuf::from("."),
    };
    base.join(".tallow").join("vault").join("identity-keys")
}

/// Path of the sealed key file for `role` inside `state_dir`.
pub fn key_path(state_dir: &Path, role: IdentityKeyRole) -> PathBuf {
    state_dir.join(role.file_name())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load the key for `role`, or provision it if none is stored yet.
///
/// * Key present → identical to [`load_key`] (a wrong passphrase is
///   [`IdentityKeyError::Crypto`]; the stored key is **never** overwritten or
///   regenerated by a failed unlock).
/// * No key → generates a fresh Ed25519 pair with
///   [`IdentityKeyPair::generate`], stores it with [`store_key`], and
///   returns it.
///
/// Callers must serialize concurrent first-time provisioning per role (two
/// racing `ensure` calls would both generate and the later write wins).
pub fn ensure_key(
    state_dir: &Path,
    role: IdentityKeyRole,
    password: &str,
) -> Result<IdentityKeyPair, IdentityKeyError> {
    match load_key(state_dir, role, password) {
        Ok(key) => Ok(key),
        Err(IdentityKeyError::NotFound) => {
            let key = IdentityKeyPair::generate();
            store_key(state_dir, role, &key, password)?;
            Ok(key)
        }
        Err(err) => Err(err),
    }
}

/// Store `key` for `role` under `password`, overwriting any existing file
/// (rotation semantics). Creates the state directory (`0700`) when missing;
/// writes the sealed file `0600`.
///
/// Callers must serialize writers per role.
pub fn store_key(
    state_dir: &Path,
    role: IdentityKeyRole,
    key: &IdentityKeyPair,
    password: &str,
) -> Result<(), IdentityKeyError> {
    let sealed = seal_key(role, key, password)?;
    write_sealed_file(state_dir, role, &sealed)
}

/// Load and unseal the key stored for `role`.
///
/// * No file → [`IdentityKeyError::NotFound`].
/// * Wrong passphrase or tampered file → [`IdentityKeyError::Crypto`].
/// * Symlink / non-regular file → [`IdentityKeyError::UnsafePath`].
pub fn load_key(
    state_dir: &Path,
    role: IdentityKeyRole,
    password: &str,
) -> Result<IdentityKeyPair, IdentityKeyError> {
    let sealed = read_sealed_file(state_dir, role)?;
    unseal_key(&sealed, password)
}

/// Remove the stored key for `role`.
///
/// Returns `Ok(true)` when a file was removed, `Ok(false)` when none existed
/// (idempotent). Not password-gated: removal is a directory-write (policy)
/// action, not a read of material — anyone who can write the state directory
/// can remove a key, so the later wiring layer gates identity mutations on
/// its own approval path. Not a secure erase: physical remnants depend on the
/// filesystem.
pub fn remove_key(state_dir: &Path, role: IdentityKeyRole) -> Result<bool, IdentityKeyError> {
    let path = key_path(state_dir, role);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => Err(IdentityKeyError::UnsafePath(format!(
            "'{}' is a directory; refusing to remove",
            path.display()
        ))),
        Ok(_) => std::fs::remove_file(&path)
            .map(|()| true)
            .map_err(|e| IdentityKeyError::Io(format!("remove '{}': {e}", path.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(IdentityKeyError::Io(format!(
            "stat '{}': {e}",
            path.display()
        ))),
    }
}

/// Node-role convenience wrapper for [`ensure_key`] — the entry point the
/// later SVID wiring calls.
pub fn ensure_node_key(state_dir: &Path, password: &str) -> Result<IdentityKeyPair, IdentityKeyError> {
    ensure_key(state_dir, IdentityKeyRole::Node, password)
}

/// Node-role convenience wrapper for [`store_key`].
pub fn store_node_key(
    state_dir: &Path,
    key: &IdentityKeyPair,
    password: &str,
) -> Result<(), IdentityKeyError> {
    store_key(state_dir, IdentityKeyRole::Node, key, password)
}

/// Node-role convenience wrapper for [`load_key`].
pub fn load_node_key(state_dir: &Path, password: &str) -> Result<IdentityKeyPair, IdentityKeyError> {
    load_key(state_dir, IdentityKeyRole::Node, password)
}

/// Node-role convenience wrapper for [`remove_key`].
pub fn remove_node_key(state_dir: &Path) -> Result<bool, IdentityKeyError> {
    remove_key(state_dir, IdentityKeyRole::Node)
}

/// Issuer-role convenience wrapper for [`ensure_key`].
pub fn ensure_issuer_key(
    state_dir: &Path,
    password: &str,
) -> Result<IdentityKeyPair, IdentityKeyError> {
    ensure_key(state_dir, IdentityKeyRole::Issuer, password)
}

/// Issuer-role convenience wrapper for [`store_key`].
pub fn store_issuer_key(
    state_dir: &Path,
    key: &IdentityKeyPair,
    password: &str,
) -> Result<(), IdentityKeyError> {
    store_key(state_dir, IdentityKeyRole::Issuer, key, password)
}

/// Issuer-role convenience wrapper for [`load_key`].
pub fn load_issuer_key(
    state_dir: &Path,
    password: &str,
) -> Result<IdentityKeyPair, IdentityKeyError> {
    load_key(state_dir, IdentityKeyRole::Issuer, password)
}

/// Issuer-role convenience wrapper for [`remove_key`].
pub fn remove_issuer_key(state_dir: &Path) -> Result<bool, IdentityKeyError> {
    remove_key(state_dir, IdentityKeyRole::Issuer)
}

// ---------------------------------------------------------------------------
// Sealing (same construction as `key_custody::seal`/`unseal`)
// ---------------------------------------------------------------------------

/// Seal `key` under `password` (hybrid PQC envelope; see module docs).
///
/// The plaintext payload exists only inside this call and is zeroized on
/// return; `Err` carries no key material.
fn seal_key(
    role: IdentityKeyRole,
    key: &IdentityKeyPair,
    password: &str,
) -> Result<SealedIdentityKey, IdentityKeyError> {
    // Serialize without materializing an extra un-zeroized copy of the
    // secret in a serde Value: the fields are fixed (algorithm tag + hex),
    // so a direct format! is safe and keeps a single owned copy of the
    // secret inside the Zeroizing buffer.
    let plaintext = Zeroizing::new(format!(
        "{{\"algorithm\":{},\"public_key\":{},\"secret_key\":{}}}",
        quote_json(key.algorithm()),
        quote_json(key.public_key_hex()),
        quote_json(key.secret_key_hex()),
    ));
    let (blob, dk_hex) =
        pqc::pqc_hybrid_encrypt(plaintext.as_bytes(), password).map_err(IdentityKeyError::Crypto)?;
    let (dk_nonce, wrapped_dk) =
        pqc::pqc_wrap_dk(password, &blob.pqc_encapsulation_key, &dk_hex)
            .map_err(IdentityKeyError::Crypto)?;
    Ok(SealedIdentityKey {
        version: IDENTITY_KEY_VERSION,
        role,
        blob,
        dk_nonce: hex_encode(&dk_nonce),
        wrapped_dk: hex_encode(&wrapped_dk),
    })
}

/// Unseal a [`SealedIdentityKey`], validating version, role-tag-independent
/// payload shape, key algorithm and pair consistency (fail-closed).
fn unseal_key(
    sealed: &SealedIdentityKey,
    password: &str,
) -> Result<IdentityKeyPair, IdentityKeyError> {
    if sealed.version != IDENTITY_KEY_VERSION {
        return Err(IdentityKeyError::Codec(format!(
            "unsupported version {} (expected {IDENTITY_KEY_VERSION})",
            sealed.version
        )));
    }
    let dk_nonce: [u8; 12] = hex_decode(&sealed.dk_nonce)
        .map_err(|_| IdentityKeyError::Codec("invalid dk nonce".to_string()))?
        .try_into()
        .map_err(|_| IdentityKeyError::Codec("invalid dk nonce length".to_string()))?;
    let wrapped_dk = hex_decode(&sealed.wrapped_dk)
        .map_err(|_| IdentityKeyError::Codec("invalid wrapped dk".to_string()))?;
    let dk_hex = pqc::pqc_unwrap_dk(
        password,
        &sealed.blob.pqc_encapsulation_key,
        &dk_nonce,
        &wrapped_dk,
    )
    .map_err(IdentityKeyError::Crypto)?;
    let plaintext = Zeroizing::new(
        pqc::pqc_hybrid_decrypt(&sealed.blob, password, &dk_hex)
            .map_err(IdentityKeyError::Crypto)?,
    );

    // Parse without echoing the decrypted text: serde error messages can
    // quote input, and the input here is key material. Fixed messages only.
    let payload: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|_| IdentityKeyError::Codec("identity payload is not valid JSON".to_string()))?;
    let field = |name: &str| -> Result<&str, IdentityKeyError> {
        payload
            .get(name)
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                IdentityKeyError::Codec(format!(
                    "identity payload: missing or non-string field '{name}'"
                ))
            })
    };
    let algorithm = field("algorithm")?;
    let public_key = field("public_key")?;
    let secret_key = field("secret_key")?;
    IdentityKeyPair::from_parts(algorithm, public_key, secret_key)
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/// Create the state directory if needed and tighten it (and every component
/// created by this call) to `0700` on unix.
fn ensure_state_dir(state_dir: &Path) -> Result<(), IdentityKeyError> {
    #[cfg(unix)]
    let mut created_below_existing: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    {
        // Walk up to the deepest pre-existing ancestor; everything below it
        // is created by us and gets tightened. (A dangling-symlink component
        // makes `exists()` false and surfaces as an Io error below.)
        let mut cur: Option<&Path> = Some(state_dir);
        while let Some(p) = cur {
            if p.exists() {
                break;
            }
            created_below_existing.push(p.to_path_buf());
            cur = p.parent().filter(|parent| !parent.as_os_str().is_empty());
        }
    }
    std::fs::create_dir_all(state_dir).map_err(|e| {
        IdentityKeyError::Io(format!("create state dir '{}': {e}", state_dir.display()))
    })?;
    #[cfg(unix)]
    {
        for created in &created_below_existing {
            set_mode(created, 0o700).map_err(|e| {
                IdentityKeyError::Io(format!("tighten '{}' to 0700: {e}", created.display()))
            })?;
        }
        // The leaf is the identity-key directory itself: tighten it even if
        // it pre-existed (e.g. 0755 from an older install).
        set_mode(state_dir, 0o700).map_err(|e| {
            IdentityKeyError::Io(format!("tighten '{}' to 0700: {e}", state_dir.display()))
        })?;
    }
    Ok(())
}

/// Write the sealed file for `role` (`0600`, `O_NOFOLLOW` where available).
fn write_sealed_file(
    state_dir: &Path,
    role: IdentityKeyRole,
    sealed: &SealedIdentityKey,
) -> Result<(), IdentityKeyError> {
    ensure_state_dir(state_dir)?;
    let path = key_path(state_dir, role);
    // Pre-check for a friendlier error; the O_NOFOLLOW open (unix) is the
    // authoritative race-free check.
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(IdentityKeyError::UnsafePath(format!(
                "'{}' is a symlink; refusing to write",
                path.display()
            )));
        }
        Ok(meta) if meta.is_dir() => {
            return Err(IdentityKeyError::UnsafePath(format!(
                "'{}' is a directory; refusing to write",
                path.display()
            )));
        }
        _ => {}
    }
    let json = serde_json::to_string_pretty(sealed)
        .map_err(|e| IdentityKeyError::Codec(format!("encode sealed identity key: {e}")))?;
    let mut file = match open_sealed_file(&path, true) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(IdentityKeyError::UnsafePath(format!(
                "'{}' is a symlink; refusing to write",
                path.display()
            )));
        }
        Err(e) => {
            return Err(IdentityKeyError::Io(format!(
                "write '{}': {e}",
                path.display()
            )));
        }
    };
    file.write_all(json.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| IdentityKeyError::Io(format!("write '{}': {e}", path.display())))?;
    #[cfg(unix)]
    set_mode(&path, 0o600).map_err(|e| {
        IdentityKeyError::Io(format!("tighten '{}' to 0600: {e}", path.display()))
    })?;
    Ok(())
}

/// Read and parse the sealed file for `role` (permission/type checks, no
/// unsealing).
fn read_sealed_file(
    state_dir: &Path,
    role: IdentityKeyRole,
) -> Result<SealedIdentityKey, IdentityKeyError> {
    let path = key_path(state_dir, role);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(IdentityKeyError::NotFound),
        Err(e) => {
            return Err(IdentityKeyError::Io(format!(
                "stat '{}': {e}",
                path.display()
            )));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(IdentityKeyError::UnsafePath(format!(
            "'{}' is a symlink; refusing",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(IdentityKeyError::UnsafePath(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    let mut file = match open_sealed_file(&path, false) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(IdentityKeyError::NotFound),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(IdentityKeyError::UnsafePath(format!(
                "'{}' is a symlink; refusing",
                path.display()
            )));
        }
        Err(e) => {
            return Err(IdentityKeyError::Io(format!(
                "read '{}': {e}",
                path.display()
            )));
        }
    };
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| IdentityKeyError::Io(format!("read '{}': {e}", path.display())))?;
    drop(file);
    // Defence in depth (T-110 tighten-on-load): best-effort 0600 re-tighten.
    #[cfg(unix)]
    {
        let _ = set_mode(&path, 0o600);
    }
    let sealed: SealedIdentityKey = serde_json::from_str(&text)
        .map_err(|e| IdentityKeyError::Codec(format!("parse '{}': {e}", path.display())))?;
    if sealed.role != role {
        return Err(IdentityKeyError::Codec(format!(
            "'{}' holds a {} key, expected {}",
            path.display(),
            sealed.role,
            role
        )));
    }
    Ok(sealed)
}

/// Open a sealed file. Reads use `read(true)`; writes use
/// create/truncate + `0600` + `O_NOFOLLOW` (unix).
#[cfg(unix)]
fn open_sealed_file(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    if write {
        opts.write(true).create(true).truncate(true).mode(0o600);
    } else {
        opts.read(true);
    }
    opts.custom_flags(libc::O_NOFOLLOW);
    opts.open(path)
}

#[cfg(not(unix))]
fn open_sealed_file(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    if write {
        opts.write(true).create(true).truncate(true);
    } else {
        opts.read(true);
    }
    opts.open(path)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// JSON-quote a string for the sealed payload (the module's own fields).
fn quote_json(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "identity-key-test-passphrase";

    fn temp_state() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn read_sealed_text(path: &Path) -> SealedIdentityKey {
        serde_json::from_str(&std::fs::read_to_string(path).expect("read sealed"))
            .expect("parse sealed")
    }

    /// Craft a sealed file with an arbitrary plaintext payload, using the
    /// same primitives the module seals with — exercises the *loader's*
    /// validation, not the module's own seal path.
    fn craft_sealed(role: IdentityKeyRole, payload: &str, password: &str) -> SealedIdentityKey {
        let (blob, dk_hex) = pqc::pqc_hybrid_encrypt(payload.as_bytes(), password).unwrap();
        let (nonce, wrapped) =
            pqc::pqc_wrap_dk(password, &blob.pqc_encapsulation_key, &dk_hex).unwrap();
        SealedIdentityKey {
            version: IDENTITY_KEY_VERSION,
            role,
            blob,
            dk_nonce: hex_encode(&nonce),
            wrapped_dk: hex_encode(&wrapped),
        }
    }

    fn write_crafted(path: &Path, role: IdentityKeyRole, payload: &str, password: &str) {
        let sealed = craft_sealed(role, payload, password);
        std::fs::write(path, serde_json::to_string_pretty(&sealed).unwrap()).unwrap();
    }

    #[test]
    fn round_trip_preserves_key_material() {
        let dir = temp_state();
        let key = ensure_node_key(dir.path(), PW).unwrap();
        assert_eq!(key.algorithm(), KEY_ALGORITHM_ED25519);

        // The secret half must be a real Ed25519 secret for the stored
        // public half.
        let mut sk_bytes = hex_decode(key.secret_key_hex()).unwrap();
        assert_eq!(sk_bytes.len(), 32);
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        sk_bytes.zeroize();
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk_arr);
        assert_eq!(
            hex_encode(signing.verifying_key().as_bytes()),
            key.public_key_hex()
        );

        let loaded = load_node_key(dir.path(), PW).unwrap();
        assert_eq!(loaded.algorithm(), key.algorithm());
        assert_eq!(loaded.public_key_hex(), key.public_key_hex());
        assert_eq!(loaded.secret_key_hex(), key.secret_key_hex());
        assert_eq!(loaded.fingerprint(), key.fingerprint());
        assert_eq!(loaded.fingerprint().len(), 16);
    }

    #[test]
    fn ensure_is_stable_once_provisioned() {
        let dir = temp_state();
        let first = ensure_issuer_key(dir.path(), PW).unwrap();
        assert!(key_path(dir.path(), IdentityKeyRole::Issuer).is_file());

        let second = ensure_issuer_key(dir.path(), PW).unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());
        assert_eq!(first.secret_key_hex(), second.secret_key_hex());
    }

    #[test]
    fn wrong_passphrase_is_refused_and_never_clobbers() {
        let dir = temp_state();
        let key = ensure_node_key(dir.path(), "right-passphrase").unwrap();

        let err = load_node_key(dir.path(), "wrong-passphrase").unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::Crypto(_)),
            "wrong passphrase must refuse: {err:?}"
        );

        // ensure() on an existing file must fail closed, not regenerate.
        let err = ensure_node_key(dir.path(), "wrong-passphrase").unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::Crypto(_)),
            "ensure must not clobber on failed unlock: {err:?}"
        );

        let again = load_node_key(dir.path(), "right-passphrase").unwrap();
        assert_eq!(again.public_key_hex(), key.public_key_hex());
    }

    #[test]
    fn missing_file_is_typed_not_found() {
        let dir = temp_state();
        assert_eq!(
            load_node_key(dir.path(), PW).unwrap_err(),
            IdentityKeyError::NotFound
        );
        assert_eq!(
            load_issuer_key(dir.path(), PW).unwrap_err(),
            IdentityKeyError::NotFound
        );
        // A nonexistent directory tree behaves the same way.
        let nested = dir.path().join("does/not/exist");
        assert_eq!(
            load_node_key(&nested, PW).unwrap_err(),
            IdentityKeyError::NotFound
        );
    }

    #[test]
    fn removal_semantics_are_idempotent_and_force_reprovisioning() {
        let dir = temp_state();
        assert!(!remove_node_key(dir.path()).unwrap(), "absent key → Ok(false)");

        let first = ensure_node_key(dir.path(), PW).unwrap();
        let path = key_path(dir.path(), IdentityKeyRole::Node);
        assert!(path.is_file());

        assert!(remove_node_key(dir.path()).unwrap(), "present key → Ok(true)");
        assert!(!path.exists());
        assert_eq!(
            load_node_key(dir.path(), PW).unwrap_err(),
            IdentityKeyError::NotFound
        );
        assert!(
            !remove_node_key(dir.path()).unwrap(),
            "second removal → Ok(false)"
        );

        let second = ensure_node_key(dir.path(), PW).unwrap();
        assert_ne!(
            first.public_key_hex(),
            second.public_key_hex(),
            "re-provisioning must mint a fresh key"
        );
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_is_0700_and_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_state();
        let nested = dir.path().join("vault-identity");
        ensure_node_key(&nested, PW).unwrap();

        let file = key_path(&nested, IdentityKeyRole::Node);
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700,
            "state dir must be 0700"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600,
            "key file must be 0600"
        );

        // Every intermediate directory this module creates is tightened too.
        let deep = dir.path().join("a/b/c");
        ensure_issuer_key(&deep, PW).unwrap();
        for created in [dir.path().join("a"), dir.path().join("a/b"), deep] {
            assert_eq!(
                std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
                0o700,
                "{} must be 0700",
                created.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn storing_tightens_pre_existing_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_state();
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = key_path(&state, IdentityKeyRole::Node);
        std::fs::write(&file, b"{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let key = IdentityKeyPair::generate();
        store_node_key(&state, &key, PW).unwrap();

        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_node_key(&state, PW).unwrap().public_key_hex(),
            key.public_key_hex()
        );
    }

    #[test]
    fn tampered_or_version_bumped_sealed_file_is_refused() {
        let dir = temp_state();
        let key = ensure_issuer_key(dir.path(), PW).unwrap();
        let path = key_path(dir.path(), IdentityKeyRole::Issuer);

        // Flip one hex digit of the ciphertext → AEAD refusal.
        let mut sealed = read_sealed_text(&path);
        let mut data = sealed.blob.encrypted_data.clone();
        let first = data.remove(0);
        data.insert(0, if first == '0' { '1' } else { '0' });
        sealed.blob.encrypted_data = data;
        std::fs::write(&path, serde_json::to_string_pretty(&sealed).unwrap()).unwrap();

        let err = load_issuer_key(dir.path(), PW).unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::Crypto(_)),
            "tampered ciphertext → Crypto: {err:?}"
        );

        // Version bump is a typed codec refusal (checked before any crypto).
        sealed.version = 99;
        std::fs::write(&path, serde_json::to_string_pretty(&sealed).unwrap()).unwrap();
        let err = load_issuer_key(dir.path(), PW).unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::Codec(_)),
            "version bump → Codec: {err:?}"
        );
        assert!(format!("{err}").contains("unsupported version"), "{err}");
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains(key.secret_key_hex()));
    }

    #[test]
    fn node_and_issuer_roles_are_independent_and_cross_use_is_refused() {
        let dir = temp_state();
        let node = ensure_node_key(dir.path(), PW).unwrap();
        let issuer = ensure_issuer_key(dir.path(), PW).unwrap();
        assert_ne!(node.public_key_hex(), issuer.public_key_hex());

        let node_path = key_path(dir.path(), IdentityKeyRole::Node);
        let issuer_path = key_path(dir.path(), IdentityKeyRole::Issuer);
        assert_ne!(node_path, issuer_path);

        // Swapping the files must be refused by the role tag, not silently
        // unlocked under the wrong role.
        let node_bytes = std::fs::read(&node_path).unwrap();
        let issuer_bytes = std::fs::read(&issuer_path).unwrap();
        std::fs::write(&issuer_path, &node_bytes).unwrap();
        let err = load_issuer_key(dir.path(), PW).unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::Codec(_)),
            "role swap → Codec: {err:?}"
        );
        assert!(format!("{err}").contains("holds a node key"), "{err}");

        std::fs::write(&issuer_path, &issuer_bytes).unwrap();
        assert_eq!(
            load_issuer_key(dir.path(), PW).unwrap().public_key_hex(),
            issuer.public_key_hex()
        );

        // Removing one role must not disturb the other.
        assert!(remove_node_key(dir.path()).unwrap());
        assert_eq!(
            load_node_key(dir.path(), PW).unwrap_err(),
            IdentityKeyError::NotFound
        );
        assert_eq!(
            load_issuer_key(dir.path(), PW).unwrap().public_key_hex(),
            issuer.public_key_hex()
        );
    }

    #[test]
    fn sealed_file_contains_no_plaintext_key_material() {
        let dir = temp_state();
        let key = ensure_node_key(dir.path(), PW).unwrap();
        let path = key_path(dir.path(), IdentityKeyRole::Node);
        let text = std::fs::read_to_string(&path).unwrap();

        assert!(
            !text.contains(key.secret_key_hex()),
            "secret must never appear in the sealed file"
        );
        assert!(
            !text.contains(key.public_key_hex()),
            "even the public half stays inside the seal"
        );
        assert!(
            !text.contains(PW),
            "passphrase must never appear in the sealed file"
        );

        let sealed = read_sealed_text(&path);
        assert_eq!(sealed.version, IDENTITY_KEY_VERSION);
        assert_eq!(sealed.role, IdentityKeyRole::Node);
        assert!(!sealed.blob.encrypted_data.is_empty());
        assert!(!sealed.wrapped_dk.is_empty());
    }

    #[test]
    fn debug_and_error_paths_never_leak_secret_material() {
        let dir = temp_state();
        let key = ensure_node_key(dir.path(), PW).unwrap();

        let dbg = format!("{key:?}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains(key.secret_key_hex()));

        let err = load_node_key(dir.path(), "not-the-passphrase").unwrap_err();
        let rendered = format!("{err} || {err:?}");
        assert!(!rendered.contains(key.secret_key_hex()));
        assert!(!rendered.contains(key.public_key_hex()));
        assert!(!rendered.contains(PW));
        assert!(!rendered.contains("not-the-passphrase"));
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_symlinks_and_non_regular_files() {
        let dir = temp_state();
        let key = IdentityKeyPair::generate();
        store_node_key(dir.path(), &key, PW).unwrap();
        let path = key_path(dir.path(), IdentityKeyRole::Node);

        let stash = dir.path().join("stash.json");
        std::fs::rename(&path, &stash).unwrap();
        std::os::unix::fs::symlink(&stash, &path).unwrap();
        let err = load_node_key(dir.path(), PW).unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::UnsafePath(_)),
            "symlink → UnsafePath: {err:?}"
        );

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = load_node_key(dir.path(), PW).unwrap_err();
        assert!(
            matches!(err, IdentityKeyError::UnsafePath(_)),
            "directory → UnsafePath: {err:?}"
        );
    }

    #[test]
    fn crafted_payloads_are_validated_fail_closed() {
        let dir = temp_state();
        let path = key_path(dir.path(), IdentityKeyRole::Node);

        // Positive control: a payload the module itself would seal loads.
        let key = IdentityKeyPair::generate();
        let good = format!(
            "{{\"algorithm\":\"ed25519\",\"public_key\":\"{}\",\"secret_key\":\"{}\"}}",
            key.public_key_hex(),
            key.secret_key_hex()
        );
        write_crafted(&path, IdentityKeyRole::Node, &good, PW);
        assert_eq!(
            load_node_key(dir.path(), PW).unwrap().public_key_hex(),
            key.public_key_hex()
        );

        // Unsupported algorithm tag.
        let other = IdentityKeyPair::generate();
        let rsa = format!(
            "{{\"algorithm\":\"rsa\",\"public_key\":\"{}\",\"secret_key\":\"{}\"}}",
            other.public_key_hex(),
            other.secret_key_hex()
        );
        write_crafted(&path, IdentityKeyRole::Node, &rsa, PW);
        let err = load_node_key(dir.path(), PW).unwrap_err();
        assert!(matches!(err, IdentityKeyError::Codec(_)), "{err:?}");
        assert!(format!("{err}").contains("unsupported key algorithm"), "{err}");

        // Cross-wired halves (public of A, secret of B).
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        let mismatched = format!(
            "{{\"algorithm\":\"ed25519\",\"public_key\":\"{}\",\"secret_key\":\"{}\"}}",
            a.public_key_hex(),
            b.secret_key_hex()
        );
        write_crafted(&path, IdentityKeyRole::Node, &mismatched, PW);
        let err = load_node_key(dir.path(), PW).unwrap_err();
        assert!(matches!(err, IdentityKeyError::Codec(_)), "{err:?}");
        assert!(format!("{err}").contains("do not match"), "{err}");

        // Truncated secret half.
        let truncated = format!(
            "{{\"algorithm\":\"ed25519\",\"public_key\":\"{}\",\"secret_key\":\"abcd\"}}",
            a.public_key_hex()
        );
        write_crafted(&path, IdentityKeyRole::Node, &truncated, PW);
        let err = load_node_key(dir.path(), PW).unwrap_err();
        assert!(matches!(err, IdentityKeyError::Codec(_)), "{err:?}");
        assert!(format!("{err}").contains("32 bytes"), "{err}");
    }

    #[test]
    fn default_state_dir_resolution_follows_env_then_home() {
        let with_env = resolve_state_dir(Some("/custom/state"), Some(Path::new("/home/u")));
        assert_eq!(with_env, PathBuf::from("/custom/state"));

        let blank_env = resolve_state_dir(Some("   "), Some(Path::new("/home/u")));
        assert_eq!(
            blank_env,
            PathBuf::from("/home/u/.tallow/vault/identity-keys")
        );

        let no_env_no_home = resolve_state_dir(None, None);
        assert!(no_env_no_home.is_relative());
        assert!(no_env_no_home.ends_with(".tallow/vault/identity-keys"));

        // The real helper must not panic (value env-dependent by design).
        let _ = default_state_dir();
    }
}
