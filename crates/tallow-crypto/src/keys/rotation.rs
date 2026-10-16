//! Key rotation records with signed transitions

use crate::error::Result;
use crate::sig::hybrid::{self, HybridSignature, HybridSigner};
use serde::{Deserialize, Serialize};

/// Record of a key rotation event
///
/// Uses hybrid ML-DSA-87 + Ed25519 signatures to ensure post-quantum
/// security for identity key transitions ("NEVER Ed25519 alone for identity").
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRotationRecord {
    /// Ed25519 verifying key bytes identifying the key being replaced
    pub old_key_id: [u8; 32],
    /// Ed25519 verifying key bytes identifying the replacement key
    pub new_key_id: [u8; 32],
    /// Unix timestamp (seconds) when this rotation was recorded
    pub timestamp: u64,
    /// Hybrid signature (ML-DSA-87 + Ed25519) over old_key_id, new_key_id,
    /// and timestamp, made by the old key
    pub signature: HybridSignature,
}

impl KeyRotationRecord {
    /// Create a new rotation record signed with hybrid ML-DSA + Ed25519
    pub fn new(old_identity: &HybridSigner, new_identity: &HybridSigner) -> Result<Self> {
        let old_key_id = old_identity.public_key().ed25519;
        let new_key_id = new_identity.public_key().ed25519;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                crate::error::CryptoError::KeyGeneration(format!("system clock error: {}", e))
            })?
            .as_secs();

        // Domain-separated message to prevent cross-context signature reuse
        let mut message = Vec::new();
        message.extend_from_slice(b"tallow-key-rotation-v1:");
        message.extend_from_slice(&old_key_id);
        message.extend_from_slice(&new_key_id);
        message.extend_from_slice(&timestamp.to_le_bytes());

        let signature = old_identity.sign(&message)?;

        Ok(Self {
            old_key_id,
            new_key_id,
            timestamp,
            signature,
        })
    }

    /// Verify the rotation record using only the Ed25519 component
    ///
    /// # Security Warning
    ///
    /// This method only verifies the Ed25519 component of the hybrid signature.
    /// It does NOT verify the ML-DSA-87 component because only the Ed25519 key ID
    /// is stored in the record. For full post-quantum security, use
    /// [`verify_with_key()`](Self::verify_with_key) which verifies both components.
    ///
    /// Use this method ONLY when the full hybrid public key is unavailable.
    #[deprecated(note = "Use verify_with_key() for full hybrid (Ed25519 + ML-DSA-87) verification")]
    pub fn verify(&self) -> Result<()> {
        let mut message = Vec::new();
        message.extend_from_slice(b"tallow-key-rotation-v1:");
        message.extend_from_slice(&self.old_key_id);
        message.extend_from_slice(&self.new_key_id);
        message.extend_from_slice(&self.timestamp.to_le_bytes());

        crate::sig::ed25519::verify(&self.old_key_id, &message, &self.signature.ed25519)
    }

    /// Verify the rotation record with a full hybrid public key
    ///
    /// This performs complete hybrid verification (both ML-DSA and Ed25519).
    pub fn verify_with_key(&self, old_public_key: &crate::sig::HybridPublicKey) -> Result<()> {
        let mut message = Vec::new();
        message.extend_from_slice(b"tallow-key-rotation-v1:");
        message.extend_from_slice(&self.old_key_id);
        message.extend_from_slice(&self.new_key_id);
        message.extend_from_slice(&self.timestamp.to_le_bytes());

        hybrid::verify(old_public_key, &message, &self.signature)
    }
}
