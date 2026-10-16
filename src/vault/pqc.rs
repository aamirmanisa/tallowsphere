//! Post-Quantum Hybrid Encryption -- ML-KEM-768 + AES-256-GCM double encryption.
//! Even if AES is broken by quantum computers, ML-KEM protects the data.
//! Even if ML-KEM has an unknown flaw, AES still protects.
//!
//! The two encryption layers are each *authenticated* (AEAD):
//!   1. Classical layer: AES-256-GCM keyed by a password-derived key.
//!   2. Post-quantum layer: AES-256-GCM keyed by the ML-KEM-768 shared
//!      secret (via a BLAKE3 keyed KDF). This replaces the old
//!      unauthenticated BLAKE3-XOR stream cipher, so every layer now
//!      provides both confidentiality AND integrity.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The double-encrypted blob produced by PQC hybrid encryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct PQCEncryptedBlob {
    /// Hex-encoded 12-byte AES-256-GCM nonce (classical layer).
    pub classical_nonce: String,
    /// Hex-encoded 12-byte AES-256-GCM nonce (post-quantum layer).
    pub pqc_nonce: String,
    /// Hex-encoded ML-KEM-768 ciphertext (encapsulated key).
    pub pqc_ciphertext: String,
    /// Hex-encoded ML-KEM-768 encapsulation (public) key.
    pub pqc_encapsulation_key: String,
    /// Hex-encoded double-encrypted payload.
    pub encrypted_data: String,
    /// Format version.
    pub version: u8,
}

/// ML-KEM-768 key pair in hex-encoded form.
///
/// Carries private decapsulation-key material, so the type deliberately
/// implements none of:
/// - `Debug` — nothing can log or panic-print it;
/// - `Clone` — a clone would be an independent, **unwiped** copy of the
///   private key (removed 2026-09-11, zer. MEDIUM; no caller needed it — the
///   only production construction site is [`generate_pqc_keypair`] and
///   consumers read the hex fields by reference);
/// - `Serialize` / `Deserialize` — key material must never cross a
///   serialization boundary. Sealed flows move the DK as an explicit hex
///   `String` through [`pqc_wrap_dk`] / [`pqc_unwrap_dk`] (and the
///   [`PQCEncryptedBlob`] stored on disk carries only ciphertext, the public
///   EK and nonces), never through this type.
///
/// Both fields are wiped by the manual `Drop` below.
pub struct PQCKeyPair {
    /// Hex-encoded encapsulation (public) key.
    pub encapsulation_key: String,
    /// Hex-encoded decapsulation (private) key.
    pub decapsulation_key: String,
}

// Ensure the private key is wiped from the on-heap String when dropped.
impl Drop for PQCKeyPair {
    fn drop(&mut self) {
        self.decapsulation_key.zeroize();
        self.encapsulation_key.zeroize();
    }
}

/// Algorithm strength information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCInfo {
    pub classical_algo: String,
    pub classical_bits: u32,
    pub pqc_algo: String,
    pub pqc_level: u32,
    pub combined_security: String,
    pub nist_compliant: bool,
}

// ---------------------------------------------------------------------------
// Hex helpers (no external hex crate -- matches codebase convention)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("pqc: hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("pqc: invalid hex at offset {i}: {e}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Key derivation (mirrors db.rs)
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `password` + `salt` using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| format!("pqc: invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("pqc: key derivation failed: {e}"))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers
// ---------------------------------------------------------------------------

fn aes_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("pqc: AES encryption failed: {e}"))
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("pqc: AES decryption failed (wrong password?): {e}"))
}

// ---------------------------------------------------------------------------
// Second AEAD layer keyed by the ML-KEM shared secret
// ---------------------------------------------------------------------------

/// Derive a 32-byte AEAD key from the ML-KEM shared secret using a
/// BLAKE3-keyed KDF (domain-separated so the same secret can never be
/// confused with another purpose). Authenticated, unlike the old BLAKE3-XOR.
fn pqc_layer_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut kdf = blake3::Hasher::new();
    kdf.update(b"tallow-pqc-layer2-v1");
    kdf.update(shared_secret);
    let out = kdf.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(out.as_bytes());
    key
}

/// Second AEAD layer (AES-256-GCM) over the classical ciphertext, keyed by
/// the ML-KEM shared secret. Returns `(ciphertext, nonce)`.
fn pqc_layer_encrypt(shared_secret: &[u8], data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let key = pqc_layer_key(shared_secret);
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("pqc: post-quantum AEAD encrypt failed: {e}"))?;

    Zeroizing::new(key); // wipe the derived key
    Ok((ct, nonce_bytes))
}

/// Decrypt the second AEAD layer.
fn pqc_layer_decrypt(
    shared_secret: &[u8],
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let key = pqc_layer_key(shared_secret);
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "pqc: post-quantum AEAD decrypt failed (wrong key or tampered data)".to_string())?;

    Zeroizing::new(key); // wipe the derived key
    Ok(pt)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a new ML-KEM-768 key pair.
pub fn generate_pqc_keypair() -> Result<PQCKeyPair, String> {
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

    let (dk, ek) = MlKem768::generate(&mut rand_core_06::OsRng);
    let ek_bytes: Vec<u8> = EncodedSizeUser::as_bytes(&ek).to_vec();
    let dk_bytes: Vec<u8> = EncodedSizeUser::as_bytes(&dk).to_vec();

    Ok(PQCKeyPair {
        encapsulation_key: hex_encode(&ek_bytes),
        decapsulation_key: hex_encode(&dk_bytes),
    })
}

/// Encrypt plaintext with PQC hybrid encryption (AES-256-GCM + ML-KEM-768).
///
/// Returns `(blob, decapsulation_key_hex)`. The caller must store the
/// decapsulation key securely -- it is required for decryption alongside
/// the password.
///
/// Process:
/// 1. Generate ephemeral ML-KEM-768 keypair
/// 2. Derive AES key from password via Argon2id (salt = BLAKE3(EK))
/// 3. AES-256-GCM encrypt the plaintext -> classical_ciphertext
/// 4. Encapsulate with EK -> (shared_secret, ciphertext)
/// 5. AES-256-GCM encrypt classical_ciphertext with a key derived from
///    the ML-KEM shared secret -> authenticated second layer
pub fn pqc_hybrid_encrypt(
    plaintext: &[u8],
    password: &str,
) -> Result<(PQCEncryptedBlob, String), String> {
    use ml_kem::kem::Encapsulate;
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use rand::RngCore;

    // 1. Generate ephemeral ML-KEM-768 keypair
    let (dk, ek) = MlKem768::generate(&mut rand_core_06::OsRng);
    let ek_bytes: Vec<u8> = EncodedSizeUser::as_bytes(&ek).to_vec();
    let dk_bytes: Vec<u8> = EncodedSizeUser::as_bytes(&dk).to_vec();

    // 2. Derive AES key -- salt is deterministically derived from EK (unique per blob)
    let salt_hash = blake3::hash(&ek_bytes);
    let salt = salt_hash.as_bytes();
    let aes_key = derive_key(password, salt)?;

    // 3. AES-256-GCM encrypt (classical layer)
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let classical_ciphertext = aes_encrypt(&aes_key, &nonce_bytes, plaintext)?;

    // 4. Encapsulate
    let (ct, ss) = ek
        .encapsulate(&mut rand_core_06::OsRng)
        .map_err(|_| "pqc: ML-KEM-768 encapsulation failed".to_string())?;
    let ss_bytes: Vec<u8> = ss.into_iter().collect();
    let ct_bytes: Vec<u8> = ct.into_iter().collect();

    // 5. Authenticated second layer keyed by the ML-KEM shared secret
    let (double_encrypted, pqc_nonce) = pqc_layer_encrypt(&ss_bytes, &classical_ciphertext)?;

    let blob = PQCEncryptedBlob {
        classical_nonce: hex_encode(&nonce_bytes),
        pqc_nonce: hex_encode(&pqc_nonce),
        pqc_ciphertext: hex_encode(&ct_bytes),
        pqc_encapsulation_key: hex_encode(&ek_bytes),
        encrypted_data: hex_encode(&double_encrypted),
        version: 2,
    };

    // Wipe ephemeral secrets from the stack heap
    let dk_hex = hex_encode(&dk_bytes);
    Zeroizing::new(ss_bytes);
    Zeroizing::new(aes_key);
    Ok((blob, dk_hex))
}

/// Decrypt a PQC hybrid encrypted blob.
///
/// 1. Decapsulate ML-KEM ciphertext with decapsulation key -> shared_secret
/// 2. AES-256-GCM decrypt the second layer (ML-KEM-keyed) -> classical_ciphertext
/// 3. Derive AES key from password via Argon2id (salt = BLAKE3(EK))
/// 4. AES-256-GCM decrypt -> plaintext
pub fn pqc_hybrid_decrypt(
    blob: &PQCEncryptedBlob,
    password: &str,
    decapsulation_key: &str,
) -> Result<Vec<u8>, String> {
    use ml_kem::kem::{DecapsulationKey, Decapsulate};
    use ml_kem::{EncodedSizeUser, MlKem768Params};

    if blob.version != 2 {
        return Err(format!(
            "pqc: unsupported blob version {} (only v2 authenticated AEAD is supported)",
            blob.version
        ));
    }

    // 1. Decapsulate ML-KEM
    let dk_bytes = hex_decode(decapsulation_key)?;
    let ct_bytes = hex_decode(&blob.pqc_ciphertext)?;

    let dk_encoded = ml_kem::array::Array::try_from(dk_bytes.as_slice()).map_err(|_| {
        format!(
            "pqc: invalid ML-KEM-768 decapsulation key size (got {})",
            dk_bytes.len()
        )
    })?;
    let dk = <DecapsulationKey<MlKem768Params> as EncodedSizeUser>::from_bytes(&dk_encoded);

    let ct_encoded = ml_kem::array::Array::try_from(ct_bytes.as_slice()).map_err(|_| {
        format!(
            "pqc: invalid ML-KEM-768 ciphertext size (got {})",
            ct_bytes.len()
        )
    })?;
    let ss = dk
        .decapsulate(&ct_encoded)
        .map_err(|_| "pqc: ML-KEM-768 decapsulation failed".to_string())?;
    let ss_bytes: Vec<u8> = ss.into_iter().collect();

    // 2. Decrypt the second AEAD layer
    let double_encrypted = hex_decode(&blob.encrypted_data)?;
    let pqc_nonce: [u8; 12] = {
        let nb = hex_decode(&blob.pqc_nonce)?;
        nb.try_into()
            .map_err(|_| "pqc: invalid pqc nonce length".to_string())?
    };
    let classical_ciphertext = pqc_layer_decrypt(&ss_bytes, &double_encrypted, &pqc_nonce)?;

    // 3. Derive AES key -- salt from EK (same as encrypt)
    let ek_bytes = hex_decode(&blob.pqc_encapsulation_key)?;
    let salt_hash = blake3::hash(&ek_bytes);
    let salt = salt_hash.as_bytes();
    let aes_key = derive_key(password, salt)?;

    // 4. AES-256-GCM decrypt
    let nonce_bytes: [u8; 12] = {
        let nb = hex_decode(&blob.classical_nonce)?;
        nb.try_into()
            .map_err(|_| "pqc: invalid nonce length".to_string())?
    };

    let pt = aes_decrypt(&aes_key, &nonce_bytes, &classical_ciphertext)?;
    Zeroizing::new(ss_bytes);
    Zeroizing::new(aes_key);
    Ok(pt)
}

// ---------------------------------------------------------------------------
// Vault at-rest key wrapping (hybrid .twv v2)
// ---------------------------------------------------------------------------

/// ML-KEM-768 decapsulation key size in bytes.
const MLKEM768_DK_LEN: usize = 2400;

/// Wrap a hex-encoded ML-KEM-768 decapsulation key so a hybrid vault file can
/// store it without ever exposing it in the clear.
///
/// The key is AES-256-GCM encrypted under `Argon2id(password, BLAKE3(EK))` —
/// exactly the derivation used for the inner classical layer of
/// [`pqc_hybrid_encrypt`] — so the file remains decryptable from the password
/// alone and a stolen file yields no usable DK.
///
/// Returns `(nonce [12 bytes], wrapped_dk [MLKEM768_DK_LEN + 16 bytes])`.
pub fn pqc_wrap_dk(
    password: &str,
    ek_hex: &str,
    dk_hex: &str,
) -> Result<([u8; 12], Vec<u8>), String> {
    use rand::RngCore;

    let dk = hex_decode(dk_hex)?;
    if dk.len() != MLKEM768_DK_LEN {
        return Err(format!(
            "pqc: invalid ML-KEM-768 decapsulation key size (got {}, expected {MLKEM768_DK_LEN})",
            dk.len()
        ));
    }

    let ek = hex_decode(ek_hex)?;
    let salt = blake3::hash(&ek);
    let key = derive_key(password, salt.as_bytes())?;

    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let wrapped = aes_encrypt(&key, &nonce, &dk)?;

    Zeroizing::new(key);
    Zeroizing::new(dk);
    Ok((nonce, wrapped))
}

/// Unwrap a decapsulation key previously wrapped by [`pqc_wrap_dk`].
///
/// Fails (AEAD authentication) on the wrong password or a tampered header.
/// Returns the hex-encoded ML-KEM-768 decapsulation key.
pub fn pqc_unwrap_dk(
    password: &str,
    ek_hex: &str,
    nonce: &[u8; 12],
    wrapped_dk: &[u8],
) -> Result<String, String> {
    let ek = hex_decode(ek_hex)?;
    let salt = blake3::hash(&ek);
    let key = derive_key(password, salt.as_bytes())?;

    let dk = aes_decrypt(&key, nonce, wrapped_dk)
        .map_err(|e| format!("pqc: DK unwrap failed (wrong password or tampered header): {e}"))?;
    if dk.len() != MLKEM768_DK_LEN {
        return Err(format!(
            "pqc: unwrapped key has invalid size {} (expected {MLKEM768_DK_LEN})",
            dk.len()
        ));
    }

    Zeroizing::new(key);
    let dk_hex = hex_encode(&dk);
    Zeroizing::new(dk);
    Ok(dk_hex)
}

/// Serialize a `VaultEntry` to JSON and PQC-hybrid-encrypt it.
///
/// Returns `(blob, decapsulation_key_hex)`.
pub fn encrypt_entry_pqc(
    entry: &super::entry::VaultEntry,
    password: &str,
) -> Result<(PQCEncryptedBlob, String), String> {
    let json = serde_json::to_vec(entry)
        .map_err(|e| format!("pqc: entry serialization failed: {e}"))?;
    pqc_hybrid_encrypt(&json, password)
}

/// PQC-hybrid-decrypt a blob and deserialize the resulting JSON into a `VaultEntry`.
pub fn decrypt_entry_pqc(
    blob: &PQCEncryptedBlob,
    password: &str,
    dk: &str,
) -> Result<super::entry::VaultEntry, String> {
    let plaintext = pqc_hybrid_decrypt(blob, password, dk)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("pqc: entry deserialization failed: {e}"))
}

/// Return information about the PQC hybrid algorithms used.
pub fn pqc_strength_info() -> PQCInfo {
    PQCInfo {
        classical_algo: "AES-256-GCM".to_string(),
        classical_bits: 256,
        pqc_algo: "ML-KEM-768".to_string(),
        pqc_level: 3,
        combined_security: "Hybrid: AES-256 classical + NIST Level 3 post-quantum".to_string(),
        nist_compliant: true,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    #[test]
    fn keygen_produces_valid_keypair() {
        let kp = generate_pqc_keypair().expect("keygen failed");
        // ML-KEM-768 encapsulation key = 1184 bytes = 2368 hex chars
        assert_eq!(kp.encapsulation_key.len(), 1184 * 2);
        // ML-KEM-768 decapsulation key = 2400 bytes = 4800 hex chars
        assert_eq!(kp.decapsulation_key.len(), 2400 * 2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"The quick brown fox jumps over the lazy dog.";
        let password = "correct-horse-battery-staple";

        let (blob, dk) = pqc_hybrid_encrypt(plaintext, password).expect("encrypt failed");

        assert_eq!(blob.version, 2);
        assert!(!blob.encrypted_data.is_empty());
        assert!(!blob.pqc_ciphertext.is_empty());
        assert!(!blob.pqc_encapsulation_key.is_empty());
        assert!(!blob.pqc_nonce.is_empty());

        let recovered = pqc_hybrid_decrypt(&blob, password, &dk).expect("decrypt failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn entry_encrypt_decrypt_roundtrip() {
        let entry = VaultEntry::new_login(
            "GitHub",
            "octocat",
            "supersecret123!",
            vec!["https://github.com".into()],
        );
        let password = "vault-master-pw";

        let (blob, dk) = encrypt_entry_pqc(&entry, password).expect("encrypt entry failed");
        let recovered = decrypt_entry_pqc(&blob, password, &dk).expect("decrypt entry failed");

        assert_eq!(recovered.name, "GitHub");
        assert_eq!(recovered.id, entry.id);
        if let crate::vault::entry::EntryData::Login(ref d) = recovered.data {
            assert_eq!(d.username, "octocat");
            assert_eq!(d.password, "supersecret123!");
            assert_eq!(d.urls, vec!["https://github.com".to_string()]);
        } else {
            panic!("expected Login entry data");
        }
    }

    #[test]
    fn wrong_password_fails() {
        let plaintext = b"secret data";
        let (blob, dk) = pqc_hybrid_encrypt(plaintext, "right-password").expect("encrypt failed");

        let result = pqc_hybrid_decrypt(&blob, "wrong-password", &dk);
        assert!(result.is_err(), "decryption with wrong password should fail");
    }

    #[test]
    fn wrong_dk_fails() {
        let plaintext = b"secret data";
        let (blob, _dk) = pqc_hybrid_encrypt(plaintext, "password").expect("encrypt failed");

        // Generate a different keypair and use its DK
        let other_kp = generate_pqc_keypair().expect("keygen failed");
        let result = pqc_hybrid_decrypt(&blob, "password", &other_kp.decapsulation_key);
        // With wrong DK the ML-KEM shared secret differs -> second-layer AEAD
        // authentication fails
        assert!(result.is_err(), "decryption with wrong DK should fail");
    }

    #[test]
    fn strength_info_correct() {
        let info = pqc_strength_info();
        assert_eq!(info.classical_algo, "AES-256-GCM");
        assert_eq!(info.classical_bits, 256);
        assert_eq!(info.pqc_algo, "ML-KEM-768");
        assert_eq!(info.pqc_level, 3);
        assert!(info.nist_compliant);
        assert!(info.combined_security.contains("Hybrid"));
    }

    #[test]
    fn wrap_unwrap_dk_roundtrip() {
        let (blob, dk) = pqc_hybrid_encrypt(b"secret", "pw").expect("encrypt failed");

        let (nonce, wrapped) =
            pqc_wrap_dk("pw", &blob.pqc_encapsulation_key, &dk).expect("wrap failed");
        assert_eq!(wrapped.len(), 2400 + 16, "wrapped DK must be DK + GCM tag");

        // The DK must not be recoverable from the wrapped bytes alone.
        assert!(!wrapped
            .windows(dk.len())
            .any(|w| w == dk.as_bytes()));

        let unwrapped =
            pqc_unwrap_dk("pw", &blob.pqc_encapsulation_key, &nonce, &wrapped)
                .expect("unwrap failed");
        assert_eq!(unwrapped, dk);
    }

    #[test]
    fn wrap_dk_wrong_password_fails() {
        let (blob, dk) = pqc_hybrid_encrypt(b"secret", "pw").expect("encrypt failed");
        let (nonce, wrapped) =
            pqc_wrap_dk("pw", &blob.pqc_encapsulation_key, &dk).expect("wrap failed");

        let result = pqc_unwrap_dk("wrong", &blob.pqc_encapsulation_key, &nonce, &wrapped);
        assert!(result.is_err(), "unwrap with wrong password must fail");
    }

    #[test]
    fn wrap_dk_ek_tamper_fails() {
        let (blob, dk) = pqc_hybrid_encrypt(b"secret", "pw").expect("encrypt failed");
        let (nonce, wrapped) =
            pqc_wrap_dk("pw", &blob.pqc_encapsulation_key, &dk).expect("wrap failed");

        // Unwrap with a different EK -> different Argon2id salt -> auth failure.
        let other = generate_pqc_keypair().expect("keygen failed");
        let result = pqc_unwrap_dk("pw", &other.encapsulation_key, &nonce, &wrapped);
        assert!(
            result.is_err(),
            "unwrapping with a tampered EK must fail (header integrity)"
        );
    }

    #[test]
    fn dk_from_one_blob_cannot_decrypt_another() {
        let (blob_a, dk_a) = pqc_hybrid_encrypt(b"first", "pw").expect("encrypt a failed");
        let (blob_b, _dk_b) = pqc_hybrid_encrypt(b"second", "pw").expect("encrypt b failed");

        // dk_a belongs to blob_a only; using it on blob_b must fail at the
        // authenticated outer AEAD layer.
        let result = pqc_hybrid_decrypt(&blob_b, "pw", &dk_a);
        assert!(result.is_err(), "cross-blob DK use must fail");
        assert!(pqc_hybrid_decrypt(&blob_a, "pw", &dk_a).is_ok());
    }

    #[test]
    fn wrap_dk_rejects_bad_sizes() {
        let bad_dk = "abcd";
        let ek = generate_pqc_keypair().expect("keygen failed");
        assert!(
            pqc_wrap_dk("pw", &ek.encapsulation_key, bad_dk).is_err(),
            "DK of wrong size must be rejected"
        );

        let good = pqc_wrap_dk("pw", &ek.encapsulation_key, &ek.decapsulation_key)
            .expect("wrap failed");
        let bad_wrapped = good.1[..good.1.len() - 1].to_vec();
        let result = pqc_unwrap_dk("pw", &ek.encapsulation_key, &good.0, &bad_wrapped);
        assert!(result.is_err(), "truncated wrapped DK must fail");
    }

    #[test]
    fn large_payload_roundtrip() {
        // 64 KB of data to exercise multi-block AEAD second layer
        let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let password = "large-payload-test";

        let (blob, dk) = pqc_hybrid_encrypt(&plaintext, password).expect("encrypt failed");
        let recovered = pqc_hybrid_decrypt(&blob, password, &dk).expect("decrypt failed");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn sealed_blob_serializes_without_key_material_or_plaintext() {
        // The serialized blob is what lands on disk (vault .twv / custody
        // files). Format it and assert no secret material rides along.
        let plaintext = b"payload-marker-do-not-leak";
        let password = "password-marker-do-not-leak";
        let (blob, dk) = pqc_hybrid_encrypt(plaintext, password).expect("encrypt failed");

        let json = serde_json::to_string(&blob).expect("blob must serialize");
        assert!(!json.contains("payload-marker-do-not-leak"));
        assert!(!json.contains("password-marker-do-not-leak"));
        assert!(!json.contains(&dk));
    }

    #[test]
    fn keypair_material_is_only_reachable_as_borrowed_hex() {
        // PQCKeyPair intentionally implements none of `Clone`, `Debug`,
        // `Serialize` or `Deserialize` — each would mint (or print) an
        // unwiped copy of the hex decapsulation key. Trait-impl absence is
        // not assertable from a plain `#[test]` (it needs a compile-fail
        // harness); it is enforced by code review of this file. This test
        // pins what IS observable: the keypair is constructed only by
        // `generate_pqc_keypair`, and its material is read as borrowed hex.
        let kp = generate_pqc_keypair().expect("keygen failed");
        let dk: &str = &kp.decapsulation_key;
        let ek: &str = &kp.encapsulation_key;
        assert_eq!(dk.len(), 2400 * 2, "ML-KEM-768 DK is 2400 bytes of hex");
        assert_eq!(ek.len(), 1184 * 2, "ML-KEM-768 EK is 1184 bytes of hex");
        assert_ne!(dk, ek);
    }
}
