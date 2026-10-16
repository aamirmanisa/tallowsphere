//! File chunk signing for integrity verification

use crate::error::{CryptoError, Result};
use crate::hash::blake3;
use crate::mem::constant_time;
use crate::sig::Ed25519Signer;
use serde::{Deserialize, Serialize};

/// Signature for a file chunk
#[derive(Clone, Serialize, Deserialize)]
pub struct ChunkSignature {
    /// Chunk index
    pub index: u64,
    /// Hash of the chunk data
    pub chunk_hash: [u8; 32],
    /// Ed25519 signature over (index || chunk_hash)
    #[serde(with = "serde_signature")]
    pub signature: [u8; 64],
}

// Custom serde for [u8; 64] signature
mod serde_signature {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("Expected 64 bytes"))
    }
}

/// Sign a file chunk
///
/// # Arguments
///
/// * `signer` - The signer to use
/// * `chunk_data` - The chunk data to sign
/// * `chunk_index` - Index of this chunk in the file
///
/// # Returns
///
/// A chunk signature
pub fn sign_chunk(signer: &Ed25519Signer, chunk_data: &[u8], chunk_index: u64) -> ChunkSignature {
    let chunk_hash = blake3::hash(chunk_data);

    // Create message: index || chunk_hash
    let mut message = Vec::with_capacity(8 + 32);
    message.extend_from_slice(&chunk_index.to_le_bytes());
    message.extend_from_slice(&chunk_hash);

    let signature = signer.sign(&message);

    ChunkSignature {
        index: chunk_index,
        chunk_hash,
        signature,
    }
}

/// Verify a chunk signature
///
/// # Arguments
///
/// * `public_key` - The signer's public key
/// * `chunk_data` - The chunk data
/// * `sig` - The chunk signature
///
/// # Returns
///
/// Ok(()) if valid, Err otherwise
pub fn verify_chunk(public_key: &[u8; 32], chunk_data: &[u8], sig: &ChunkSignature) -> Result<()> {
    // Verify chunk hash using constant-time comparison
    let actual_hash = blake3::hash(chunk_data);
    if !constant_time::ct_eq(&actual_hash, &sig.chunk_hash) {
        return Err(CryptoError::HashMismatch {
            expected: String::from("[redacted]"),
            actual: String::from("[redacted]"),
        });
    }

    // Verify signature
    let mut message = Vec::with_capacity(8 + 32);
    message.extend_from_slice(&sig.index.to_le_bytes());
    message.extend_from_slice(&sig.chunk_hash);

    crate::sig::ed25519::verify(public_key, &message, &sig.signature)
}

/// File manifest with all chunk signatures
#[derive(Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Total file size
    pub file_size: u64,
    /// Chunk size
    pub chunk_size: usize,
    /// Chunk signatures in order
    pub chunks: Vec<ChunkSignature>,
    /// Public key used for signing
    pub public_key: [u8; 32],
}

impl FileManifest {
    /// Verify all chunks in the manifest
    pub fn verify_all(&self, file_data: &[u8]) -> Result<()> {
        if file_data.len() != self.file_size as usize {
            return Err(CryptoError::Verification(format!(
                "File size mismatch: expected {}, got {}",
                self.file_size,
                file_data.len()
            )));
        }

        for (i, chunk_sig) in self.chunks.iter().enumerate() {
            let start = i * self.chunk_size;
            let end = (start + self.chunk_size).min(file_data.len());
            let chunk = &file_data[start..end];

            verify_chunk(&self.public_key, chunk, chunk_sig)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_signing() {
        let signer = Ed25519Signer::keygen();
        let chunk = b"chunk data here";
        let index = 0;

        let sig = sign_chunk(&signer, chunk, index);
        let result = verify_chunk(&signer.verifying_key_bytes(), chunk, &sig);

        assert!(result.is_ok());
    }

    #[test]
    fn test_chunk_tampering() {
        let signer = Ed25519Signer::keygen();
        let chunk = b"chunk data here";
        let tampered = b"tampered chunk!";
        let index = 0;

        let sig = sign_chunk(&signer, chunk, index);
        let result = verify_chunk(&signer.verifying_key_bytes(), tampered, &sig);

        assert!(result.is_err());
    }
}
