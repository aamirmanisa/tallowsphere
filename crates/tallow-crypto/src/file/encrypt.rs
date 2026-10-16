//! File encryption

use crate::error::Result;
use crate::hash::blake3;
use crate::symmetric::{aes_encrypt, chacha_encrypt, CipherSuite};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Domain separation context for per-transfer subkeys (ATK-4-3 / P10-R03).
///
/// Chunk crypto must not run under the raw session/master key across transfer
/// scopes; derive a per-transfer subkey with [`derive_transfer_subkey`] first.
pub const TRANSFER_SUBKEY_DOMAIN: &str = "tallow-transfer-subkey-v1";

/// Domain separation context for transfer-bound chunk nonce tags.
pub const TRANSFER_NONCE_DOMAIN: &str = "tallow-transfer-nonce-v1";

/// Encrypted file chunk
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// Zero-based sequential position of this chunk within the file
    pub index: u64,
    /// AES-256-GCM encrypted chunk data including authentication tag
    pub ciphertext: Vec<u8>,
    /// BLAKE3 hash of the ciphertext for integrity verification
    pub hash: [u8; 32],
}

/// File encryptor
pub struct FileEncryptor {
    key: [u8; 32],
    /// Cipher suite used for chunk encryption
    cipher: CipherSuite,
}

impl Drop for FileEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl FileEncryptor {
    /// Create a new file encryptor
    pub fn new(key: [u8; 32], cipher: CipherSuite) -> Self {
        Self { key, cipher }
    }

    /// Encrypt a chunk
    pub fn encrypt_chunk(&self, chunk_data: &[u8], chunk_index: u64) -> Result<EncryptedChunk> {
        encrypt_chunk(&self.key, chunk_data, chunk_index, self.cipher)
    }
}

/// Encrypt a single file chunk
///
/// This is the low-level, caller-scoped entry point: the caller must supply a
/// distinct `key` per file/stream. Callers that share a session/master key
/// across transfers MUST use [`encrypt_chunk_scoped`] instead (ATK-4-3).
///
/// # Arguments
///
/// * `key` - Encryption key
/// * `chunk_data` - Chunk data to encrypt
/// * `chunk_index` - Index of this chunk
/// * `cipher` - Cipher suite to use for encryption
///
/// # Returns
///
/// Encrypted chunk with metadata
pub fn encrypt_chunk(
    key: &[u8; 32],
    chunk_data: &[u8],
    chunk_index: u64,
    cipher: CipherSuite,
) -> Result<EncryptedChunk> {
    encrypt_chunk_core(key, None, chunk_data, chunk_index, cipher)
}

/// Encrypt a chunk under a per-transfer (per-file/per-stream) subkey with a
/// transfer-bound nonce and AAD.
///
/// 1. `subkey = derive_transfer_subkey(session_key, transfer_id)` — the session
///    key is never used directly as a chunk-crypto key.
/// 2. Chunk key = `BLAKE3("chunk_encryption", subkey || chunk_index)`.
/// 3. Nonce = [`transfer_bound_nonce`] (counter || transfer tag); AAD =
///    `transfer_id || chunk_index (LE)`.
///
/// This makes `(key, nonce)` reuse impossible across transfer scopes, and a
/// wrong or tampered `transfer_id` fails authenticated decryption.
///
/// # Arguments
///
/// * `session_key` - 32-byte session/master key; never passed to the AEAD directly
/// * `transfer_id` - Unambiguous non-empty per-transfer identifier; must not be
///   reused across transfers (for a re-transfer, use a fresh id)
/// * `chunk_data` - Chunk data to encrypt
/// * `chunk_index` - Index of this chunk within the transfer
/// * `cipher` - Cipher suite to use for encryption
pub fn encrypt_chunk_scoped(
    session_key: &[u8; 32],
    transfer_id: &[u8],
    chunk_data: &[u8],
    chunk_index: u64,
    cipher: CipherSuite,
) -> Result<EncryptedChunk> {
    if transfer_id.is_empty() {
        return Err(crate::error::CryptoError::InvalidKey(
            "transfer_id must be non-empty (ATK-4-3: no unscoped key reuse)".to_string(),
        ));
    }

    let mut subkey = derive_transfer_subkey(session_key, transfer_id);
    let result = encrypt_chunk_core(&subkey, Some(transfer_id), chunk_data, chunk_index, cipher);
    subkey.zeroize(); // Zeroize per-transfer subkey
    result
}

/// Derive a per-transfer (per-file/per-stream) subkey from a session/master key.
///
/// `subkey = BLAKE3(TRANSFER_SUBKEY_DOMAIN, session_key || transfer_id)`
///
/// Distinct `transfer_id` values (distinct files, distinct transfer sessions,
/// or a re-transfer of the same file name under a new transfer id) yield
/// independent subkeys, so the same `(key, nonce)` pair cannot be reused across
/// transfer scopes even when every file restarts chunk indices at 0.
///
/// # Arguments
///
/// * `session_key` - Session/master key (32 bytes)
/// * `transfer_id` - Unambiguous per-transfer identifier, e.g.
///   `file_id || transfer_sequence`
pub fn derive_transfer_subkey(session_key: &[u8; 32], transfer_id: &[u8]) -> [u8; 32] {
    debug_assert!(
        !transfer_id.is_empty(),
        "transfer_id must be non-empty (ATK-4-3)"
    );

    let mut input = Vec::with_capacity(32 + transfer_id.len());
    input.extend_from_slice(session_key);
    input.extend_from_slice(transfer_id);
    let subkey = blake3::derive_key(TRANSFER_SUBKEY_DOMAIN, &input);
    input.zeroize(); // Zeroize input containing the session key
    subkey
}

/// Deterministic transfer-bound chunk nonce: `chunk_index (u64 LE) || transfer_tag`.
///
/// `transfer_tag = BLAKE3(TRANSFER_NONCE_DOMAIN, transfer_id)[..4]`.
///
/// Uniqueness: for one transfer scope the tag is constant and the 8-byte
/// counter differs per chunk index, so nonces never repeat within the scope;
/// across scopes the subkey differs, so a `(key, nonce)` pair cannot repeat
/// even if a nonce were to coincide.
pub(crate) fn transfer_bound_nonce(transfer_id: &[u8], chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&chunk_index.to_le_bytes());
    let tag = blake3::derive_key(TRANSFER_NONCE_DOMAIN, transfer_id);
    nonce[8..].copy_from_slice(&tag[..4]);
    nonce
}

/// Shared chunk-encryption core for the caller-scoped ([`encrypt_chunk`]) and
/// transfer-scoped ([`encrypt_chunk_scoped`]) paths.
///
/// With `transfer_id = Some(..)` the nonce and AAD are transfer-bound; with
/// `None` the legacy index-only nonce/AAD construction is preserved
/// byte-for-byte for existing callers.
fn encrypt_chunk_core(
    key: &[u8; 32],
    transfer_id: Option<&[u8]>,
    chunk_data: &[u8],
    chunk_index: u64,
    cipher: CipherSuite,
) -> Result<EncryptedChunk> {
    // Derive chunk-specific key
    let mut kdf_input = Vec::new();
    kdf_input.extend_from_slice(key);
    kdf_input.extend_from_slice(&chunk_index.to_le_bytes());
    let mut chunk_key = blake3::derive_key("chunk_encryption", &kdf_input);
    kdf_input.zeroize(); // Zeroize KDF input containing master key

    // Nonce: transfer-bound when a transfer scope is supplied, index-only otherwise
    let nonce = match transfer_id {
        Some(tid) => transfer_bound_nonce(tid, chunk_index),
        None => {
            let mut n = [0u8; 12];
            n[..8].copy_from_slice(&chunk_index.to_le_bytes());
            n
        }
    };

    // AAD binds the transfer scope (when present) and the chunk index
    let aad: Vec<u8> = match transfer_id {
        Some(tid) => {
            let mut a = Vec::with_capacity(tid.len() + 8);
            a.extend_from_slice(tid);
            a.extend_from_slice(&chunk_index.to_le_bytes());
            a
        }
        None => chunk_index.to_le_bytes().to_vec(),
    };

    // Encrypt using the selected cipher suite
    let ciphertext = match cipher {
        CipherSuite::Aes256Gcm => aes_encrypt(&chunk_key, &nonce, chunk_data, &aad)?,
        CipherSuite::ChaCha20Poly1305 => chacha_encrypt(&chunk_key, &nonce, chunk_data, &aad)?,
        #[cfg(feature = "aegis")]
        CipherSuite::Aegis256 => {
            let mut nonce32 = [0u8; 32];
            nonce32[..12].copy_from_slice(&nonce);
            crate::symmetric::aegis::encrypt(&chunk_key, &nonce32, chunk_data, &aad)?
        }
    };

    chunk_key.zeroize(); // Zeroize derived chunk key

    // Hash for integrity
    let hash = blake3::hash(&ciphertext);

    Ok(EncryptedChunk {
        index: chunk_index,
        ciphertext,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_chunk() {
        let key = [0u8; 32];
        let data = b"chunk data here";
        let index = 0;

        let encrypted = encrypt_chunk(&key, data, index, CipherSuite::Aes256Gcm).unwrap();
        assert_eq!(encrypted.index, index);
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_encrypt_chunk_chacha() {
        let key = [0u8; 32];
        let data = b"chunk data here";
        let index = 0;

        let encrypted = encrypt_chunk(&key, data, index, CipherSuite::ChaCha20Poly1305).unwrap();
        assert_eq!(encrypted.index, index);
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_transfer_subkey_domain_separation() {
        use std::collections::HashSet;

        let session_key = [7u8; 32];

        // Different transfers (including re-transfers of the same file) -> different subkeys
        let mut subkeys = HashSet::new();
        for t in 0..16u32 {
            let tid = format!("file:report.pdf|xfer:{t:04}").into_bytes();
            subkeys.insert(derive_transfer_subkey(&session_key, &tid));
        }
        assert_eq!(
            subkeys.len(),
            16,
            "distinct transfers must derive distinct subkeys"
        );

        // Deterministic: same inputs -> same subkey
        let a = derive_transfer_subkey(&session_key, b"file:report.pdf|xfer:0001");
        let b = derive_transfer_subkey(&session_key, b"file:report.pdf|xfer:0001");
        assert_eq!(a, b);

        // The subkey is never the raw session key
        assert_ne!(a, session_key);
    }

    #[test]
    fn test_transfer_bound_nonce_uniqueness() {
        use std::collections::HashSet;

        // Within one transfer scope: distinct chunk indices -> distinct nonces
        let tid = b"file:data.bin|xfer:0001";
        let mut within_scope = HashSet::new();
        for i in 0..1024u64 {
            assert!(
                within_scope.insert(transfer_bound_nonce(tid, i)),
                "nonce reuse within transfer scope at index {i}"
            );
        }

        // Across scopes: (subkey, nonce) pairs never repeat, including a
        // re-transfer of the same file name under a different transfer id
        let session_key = [0x11u8; 32];
        let mut pairs = HashSet::new();
        for t in 0..16u32 {
            let tid = format!("file:report.pdf|xfer:{t:04}").into_bytes();
            let subkey = derive_transfer_subkey(&session_key, &tid);
            for i in 0..16u64 {
                assert!(
                    pairs.insert((subkey, transfer_bound_nonce(&tid, i))),
                    "key/nonce pair reuse across transfer scopes"
                );
            }
        }
        assert_eq!(pairs.len(), 16 * 16);
    }

    #[test]
    fn test_encrypt_chunk_scoped_freshness() {
        let session_key = [0x22u8; 32];
        let data = b"identical plaintext at index 0";

        for cipher in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            // Same file re-transferred under a new transfer id -> fresh key + nonce
            let first =
                encrypt_chunk_scoped(&session_key, b"file:x.bin|xfer:0001", data, 0, cipher)
                    .unwrap();
            let retransfer =
                encrypt_chunk_scoped(&session_key, b"file:x.bin|xfer:0002", data, 0, cipher)
                    .unwrap();
            assert_ne!(
                first.ciphertext, retransfer.ciphertext,
                "re-transfer must not reuse (key, nonce)"
            );

            // Deterministic construction: identical scope + plaintext -> identical chunk
            let repeat =
                encrypt_chunk_scoped(&session_key, b"file:x.bin|xfer:0001", data, 0, cipher)
                    .unwrap();
            assert_eq!(first.ciphertext, repeat.ciphertext);
            assert_eq!(first.hash, repeat.hash);
        }
    }
}
