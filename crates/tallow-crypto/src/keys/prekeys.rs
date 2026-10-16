//! Pre-keys for asynchronous key agreement

use crate::error::{CryptoError, Result};
use crate::kem::hybrid::{HybridKem, PublicKey};
use crate::sig::hybrid::{HybridPublicKey, HybridSignature, HybridSigner};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Signed pre-key
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    /// Unique identifier for this pre-key
    pub id: u32,
    /// Hybrid public key used for key agreement
    pub public_key: PublicKey,
    /// Hybrid (ML-DSA-87 + Ed25519) signature over the pre-key id, public key, and timestamp
    pub signature: HybridSignature,
    /// Unix timestamp (seconds) when this pre-key was generated
    pub timestamp: u64,
}

/// One-time pre-key
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    /// Unique identifier for this one-time pre-key
    pub id: u32,
    /// Hybrid public key used for a single key agreement exchange
    pub public_key: PublicKey,
}

impl Zeroize for OneTimePreKey {
    fn zeroize(&mut self) {
        self.id.zeroize();
        // PublicKey doesn't need zeroization (it's public)
    }
}

impl Drop for OneTimePreKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Pre-key bundle for key agreement
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Hybrid identity public key (ML-DSA-87 + Ed25519) of the bundle owner
    pub identity_key: HybridPublicKey,
    /// Medium-term signed pre-key for initiating key agreement
    pub signed_prekey: SignedPreKey,
    /// Optional one-time pre-key for forward secrecy; absent when exhausted
    pub onetime_prekey: Option<OneTimePreKey>,
}

impl SignedPreKey {
    /// Generate a new signed pre-key using hybrid identity (ML-DSA-87 + Ed25519)
    ///
    /// Pre-keys MUST be signed with the hybrid identity key per security policy:
    /// "NEVER Ed25519 alone for identity"
    pub fn generate(id: u32, identity: &HybridSigner) -> Result<Self> {
        let (pk, _sk) = HybridKem::keygen()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::KeyGeneration(format!("system clock error: {}", e)))?
            .as_secs();

        let pk_bytes = bincode::serialize(&pk).map_err(|e| {
            CryptoError::Serialization(format!("Failed to serialize pre-key: {}", e))
        })?;

        let mut message = Vec::new();
        message.extend_from_slice(&id.to_le_bytes());
        message.extend_from_slice(&pk_bytes);
        message.extend_from_slice(&timestamp.to_le_bytes());

        let signature = identity.sign(&message)?;

        Ok(Self {
            id,
            public_key: pk,
            signature,
            timestamp,
        })
    }

    /// Verify the hybrid signature on this pre-key
    ///
    /// Both ML-DSA-87 and Ed25519 signatures must verify.
    pub fn verify(&self, identity_key: &HybridPublicKey) -> Result<()> {
        let pk_bytes = bincode::serialize(&self.public_key).map_err(|e| {
            CryptoError::Serialization(format!(
                "Failed to serialize pre-key for verification: {}",
                e
            ))
        })?;

        let mut message = Vec::new();
        message.extend_from_slice(&self.id.to_le_bytes());
        message.extend_from_slice(&pk_bytes);
        message.extend_from_slice(&self.timestamp.to_le_bytes());

        crate::sig::hybrid::verify(identity_key, &message, &self.signature)
    }
}

impl OneTimePreKey {
    /// Generate a new one-time pre-key
    pub fn generate(id: u32) -> Result<Self> {
        let (pk, _sk) = HybridKem::keygen()?;
        Ok(Self { id, public_key: pk })
    }
}
