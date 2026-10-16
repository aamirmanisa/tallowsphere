//! File decryption

use crate::error::{CryptoError, Result};
use crate::file::encrypt::{derive_transfer_subkey, transfer_bound_nonce, EncryptedChunk};
use crate::hash::blake3;
use crate::mem::constant_time;
use crate::symmetric::{aes_decrypt, chacha_decrypt, CipherSuite};
use zeroize::Zeroize;

/// File decryptor
pub struct FileDecryptor {
    key: [u8; 32],
    /// Cipher suite used for chunk decryption
    cipher: CipherSuite,
}

impl Drop for FileDecryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl FileDecryptor {
    /// Create a new file decryptor
    pub fn new(key: [u8; 32], cipher: CipherSuite) -> Self {
        Self { key, cipher }
    }

    /// Decrypt a chunk
    pub fn decrypt_chunk(&self, encrypted_chunk: &EncryptedChunk) -> Result<Vec<u8>> {
        decrypt_chunk(&self.key, encrypted_chunk, self.cipher)
    }
}

/// Decrypt a single file chunk
///
/// This is the low-level, caller-scoped entry point: the caller must supply the
/// same distinct per-file `key` used for encryption. Chunks produced with
/// `encrypt_chunk_scoped` MUST be decrypted with [`decrypt_chunk_scoped`]
/// (ATK-4-3).
///
/// # Arguments
///
/// * `key` - Decryption key
/// * `encrypted_chunk` - The encrypted chunk
/// * `cipher` - Cipher suite to use for decryption
///
/// # Returns
///
/// Decrypted chunk data
pub fn decrypt_chunk(
    key: &[u8; 32],
    encrypted_chunk: &EncryptedChunk,
    cipher: CipherSuite,
) -> Result<Vec<u8>> {
    decrypt_chunk_core(key, None, encrypted_chunk, cipher)
}

/// Decrypt a chunk produced by `encrypt_chunk_scoped`.
///
/// Re-derives the per-transfer subkey from `(session_key, transfer_id)` and the
/// transfer-bound nonce, then authenticates with AAD `transfer_id || chunk_index`.
/// A wrong or tampered `transfer_id` (or chunk index) derives different crypto
/// inputs and fails AEAD authentication.
pub fn decrypt_chunk_scoped(
    session_key: &[u8; 32],
    transfer_id: &[u8],
    encrypted_chunk: &EncryptedChunk,
    cipher: CipherSuite,
) -> Result<Vec<u8>> {
    if transfer_id.is_empty() {
        return Err(CryptoError::InvalidKey(
            "transfer_id must be non-empty (ATK-4-3: no unscoped key reuse)".to_string(),
        ));
    }

    let mut subkey = derive_transfer_subkey(session_key, transfer_id);
    let result = decrypt_chunk_core(&subkey, Some(transfer_id), encrypted_chunk, cipher);
    subkey.zeroize(); // Zeroize per-transfer subkey
    result
}

/// Shared chunk-decryption core for the caller-scoped ([`decrypt_chunk`]) and
/// transfer-scoped ([`decrypt_chunk_scoped`]) paths.
///
/// With `transfer_id = Some(..)` the nonce and AAD are transfer-bound; with
/// `None` the legacy index-only nonce/AAD construction is preserved
/// byte-for-byte for existing callers.
fn decrypt_chunk_core(
    key: &[u8; 32],
    transfer_id: Option<&[u8]>,
    encrypted_chunk: &EncryptedChunk,
    cipher: CipherSuite,
) -> Result<Vec<u8>> {
    // Verify hash using constant-time comparison
    let actual_hash = blake3::hash(&encrypted_chunk.ciphertext);
    if !constant_time::ct_eq(&actual_hash, &encrypted_chunk.hash) {
        return Err(CryptoError::HashMismatch {
            expected: String::from("[redacted]"),
            actual: String::from("[redacted]"),
        });
    }

    // Derive chunk-specific key
    let mut kdf_input = Vec::new();
    kdf_input.extend_from_slice(key);
    kdf_input.extend_from_slice(&encrypted_chunk.index.to_le_bytes());
    let mut chunk_key = blake3::derive_key("chunk_encryption", &kdf_input);
    kdf_input.zeroize(); // Zeroize KDF input containing master key

    // Nonce: transfer-bound when a transfer scope is supplied, index-only otherwise
    let nonce = match transfer_id {
        Some(tid) => transfer_bound_nonce(tid, encrypted_chunk.index),
        None => {
            let mut n = [0u8; 12];
            n[..8].copy_from_slice(&encrypted_chunk.index.to_le_bytes());
            n
        }
    };

    // AAD binds the transfer scope (when present) and the chunk index
    let aad: Vec<u8> = match transfer_id {
        Some(tid) => {
            let mut a = Vec::with_capacity(tid.len() + 8);
            a.extend_from_slice(tid);
            a.extend_from_slice(&encrypted_chunk.index.to_le_bytes());
            a
        }
        None => encrypted_chunk.index.to_le_bytes().to_vec(),
    };

    // Decrypt using the selected cipher suite
    let plaintext = match cipher {
        CipherSuite::Aes256Gcm => {
            aes_decrypt(&chunk_key, &nonce, &encrypted_chunk.ciphertext, &aad)?
        }
        CipherSuite::ChaCha20Poly1305 => {
            chacha_decrypt(&chunk_key, &nonce, &encrypted_chunk.ciphertext, &aad)?
        }
        #[cfg(feature = "aegis")]
        CipherSuite::Aegis256 => {
            let mut nonce32 = [0u8; 32];
            nonce32[..12].copy_from_slice(&nonce);
            crate::symmetric::aegis::decrypt(
                &chunk_key,
                &nonce32,
                &encrypted_chunk.ciphertext,
                &aad,
            )?
        }
    };

    chunk_key.zeroize(); // Zeroize derived chunk key

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::encrypt::{encrypt_chunk, encrypt_chunk_scoped};

    #[test]
    fn test_decrypt_chunk() {
        let key = [0u8; 32];
        let data = b"chunk data here";
        let index = 0;

        let encrypted = encrypt_chunk(&key, data, index, CipherSuite::Aes256Gcm).unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted, CipherSuite::Aes256Gcm).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_chunk_chacha() {
        let key = [0u8; 32];
        let data = b"chunk data here";
        let index = 0;

        let encrypted = encrypt_chunk(&key, data, index, CipherSuite::ChaCha20Poly1305).unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted, CipherSuite::ChaCha20Poly1305).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_tampered_chunk() {
        let key = [0u8; 32];
        let data = b"chunk data here";
        let index = 0;

        let mut encrypted = encrypt_chunk(&key, data, index, CipherSuite::Aes256Gcm).unwrap();
        encrypted.hash[0] ^= 1; // Tamper with hash

        let result = decrypt_chunk(&key, &encrypted, CipherSuite::Aes256Gcm);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_chunk_scoped_roundtrip() {
        let session_key = [0x33u8; 32];
        let tid = b"file:notes.txt|xfer:777";
        let data = b"scoped chunk data";

        for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let encrypted = encrypt_chunk_scoped(&session_key, tid, data, 3, cipher).unwrap();
            let decrypted = decrypt_chunk_scoped(&session_key, tid, &encrypted, cipher).unwrap();
            assert_eq!(data.as_slice(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_decrypt_chunk_scoped_wrong_transfer_id_fails() {
        let session_key = [0x44u8; 32];
        let data = b"bound to transfer a";
        let encrypted = encrypt_chunk_scoped(
            &session_key,
            b"file:a.bin|xfer:001",
            data,
            0,
            CipherSuite::Aes256Gcm,
        )
        .unwrap();

        // Tampered / wrong transfer id -> decryption failure
        assert!(decrypt_chunk_scoped(
            &session_key,
            b"file:a.bin|xfer:002",
            &encrypted,
            CipherSuite::Aes256Gcm
        )
        .is_err());
        assert!(decrypt_chunk_scoped(
            &session_key,
            b"file:b.bin|xfer:001",
            &encrypted,
            CipherSuite::Aes256Gcm
        )
        .is_err());

        // Tampered chunk index -> decryption failure (index feeds key, nonce and AAD)
        let mut tampered = encrypted.clone();
        tampered.index += 1;
        assert!(decrypt_chunk_scoped(
            &session_key,
            b"file:a.bin|xfer:001",
            &tampered,
            CipherSuite::Aes256Gcm
        )
        .is_err());

        // Correct scope still round-trips
        let ok = decrypt_chunk_scoped(
            &session_key,
            b"file:a.bin|xfer:001",
            &encrypted,
            CipherSuite::Aes256Gcm,
        )
        .unwrap();
        assert_eq!(data.as_slice(), ok.as_slice());
    }

    #[test]
    fn test_scoped_and_legacy_paths_are_separate() {
        let session_key = [0x55u8; 32];
        let data = b"separation check";
        let encrypted = encrypt_chunk_scoped(
            &session_key,
            b"file:s.bin|xfer:001",
            data,
            0,
            CipherSuite::Aes256Gcm,
        )
        .unwrap();

        // The legacy caller-scoped path uses different key/nonce/AAD inputs and
        // must not decrypt scoped ciphertext under the same session key
        assert!(decrypt_chunk(&session_key, &encrypted, CipherSuite::Aes256Gcm).is_err());
    }
}
