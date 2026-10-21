//! AES-256-GCM encryption
//!
//! # Backend
//!
//! RustCrypto's `aes-gcm` 0.10. The wire format — `ciphertext || tag`, empty AAD
//! allowed — is unchanged, and `tests/aes_gcm_differential.rs` pins it against a
//! fixed vector plus 2000 generated cases in both directions.
//!
//! # Why this replaced libcrux-aesgcm (item 6.4, reversed 2026-10-21)
//!
//! Item 6.4 swapped this implementation for `libcrux-aesgcm` 0.0.8 for raw speed
//! on aarch64. Two RustSec advisories against that exact version make it
//! untenable, and 0.0.8 is the newest published release:
//!
//! * RUSTSEC-2026-0209 — AES-GCM did not enforce limits on AAD length.
//! * RUSTSEC-2026-0211 — non-constant-time authentication-tag comparison.
//!
//! The upstream fixes (celabshq/libcrux PRs 1474 and 1528) are merged but
//! unreleased, so the choice is a vendored fork of a crypto primitive or the
//! maintained implementation it replaced. `aes-gcm` 0.10 verifies tags through
//! `subtle` and is the oracle this crate's differential test already trusts.
//!
//! The `+aes` target flags in `.cargo/config.toml` stay: `aes-gcm` dispatches to
//! AES-NI/ARMv8 intrinsics under them, which is why the throughput cliff those
//! flags guard against is still measured by `scripts/pgo_ab.sh`.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::error::{CryptoError, Result};

/// AES-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Encrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per message)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
///
/// # Returns
///
/// Ciphertext with authentication tag appended
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::Encryption("AES-GCM key setup failed".to_string()))?;

    // Wire format, unchanged: the AEAD returns ciphertext || tag.
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption("AES-GCM encryption failed".to_string()))
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must match encryption nonce)
/// * `ciphertext` - Data to decrypt (includes authentication tag)
/// * `aad` - Additional authenticated data (must match encryption AAD)
///
/// # Returns
///
/// Decrypted plaintext if authentication succeeds
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Decryption(
            "AES-GCM decryption failed: input is shorter than the authentication tag".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::Decryption("AES-GCM key setup failed".to_string()))?;

    // `aes-gcm` verifies the trailing tag in constant time and never returns
    // unauthenticated plaintext, so there is no partial buffer to wipe here.
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption("AES-GCM decryption failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"hello world";
        let aad = b"metadata";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"secret";

        let ciphertext = encrypt(&key1, &nonce, plaintext, &[]).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_aad() {
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"secret";
        let aad1 = b"metadata1";
        let aad2 = b"metadata2";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad1).unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, aad2);

        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_tag_is_not_truncated() {
        let ct = encrypt(&[0u8; 32], &[2u8; 12], b"abc", &[]).unwrap();
        assert_eq!(ct.len(), 3 + TAG_LEN);
    }

    /// One fixed vector produced by the backend that shipped before item 6.4
    /// (`aes-gcm` 0.10.3), pinned so a future swap cannot drift from the bytes
    /// peers already hold.
    #[test]
    fn test_shipped_vector_survives_the_backend_swap() {
        let key = [0x2bu8; 32];
        let nonce = [0x11u8; 12];
        let aad = b"tallow-transfer-scope-v1";
        let pt = b"TAllow wire-compat vector (pre-swap backend: aes-gcm 0.10.3)";
        let ct_tag = hex::decode(
            "ec070139e090c2fdd89a72d4adbf3835ca17d3409ed11fbba07af2edd9240fec9624ab8976755f036ce1aed11fb5e4c55d088a961c67086a49131afdbcf4f0459cc5357be08c61ddd09261c1",
        )
        .unwrap();

        assert_eq!(encrypt(&key, &nonce, pt, aad).unwrap(), ct_tag);
        assert_eq!(decrypt(&key, &nonce, &ct_tag, aad).unwrap(), pt);
    }
}
