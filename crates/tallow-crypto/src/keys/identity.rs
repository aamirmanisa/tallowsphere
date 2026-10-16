//! Long-term identity key pairs

use crate::error::{CryptoError, Result};
use crate::sig::{HybridPublicKey, HybridSigner};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Identity key pair (hybrid signature)
#[derive(Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct IdentityKeyPair {
    signer: HybridSigner,
    id: [u8; 32],
}

/// Derive the identity fingerprint for a hybrid public key.
///
/// Single source of the id derivation used by [`IdentityKeyPair::generate`]:
/// BLAKE3 over the bincode serialization of the key. A verifier that has been
/// presented a public key (e.g. in a `HandshakeSigned` frame) computes the
/// peer's id with this function for pin comparisons.
pub fn id_for_public_key(pk: &HybridPublicKey) -> Result<[u8; 32]> {
    let pk_bytes = bincode::serialize(pk).map_err(|e| {
        CryptoError::Serialization(format!("Failed to serialize public key: {}", e))
    })?;
    Ok(crate::hash::blake3::hash(&pk_bytes))
}

impl IdentityKeyPair {
    /// Generate a new identity keypair
    pub fn generate() -> Result<Self> {
        let signer = HybridSigner::keygen()?;
        let pk = signer.public_key();
        let id = id_for_public_key(&pk)?;
        Ok(Self { signer, id })
    }

    /// Get the signer
    pub fn signer(&self) -> &HybridSigner {
        &self.signer
    }

    /// Get the identity (fingerprint)
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_id_matches_public_key_derivation() {
        let kp = IdentityKeyPair::generate().unwrap();
        let pk = kp.signer().public_key();
        // The id stored at generation equals the one a verifier computes from
        // a presented public key (this is what pins compare against).
        assert_eq!(id_for_public_key(&pk).unwrap(), *kp.id());
    }

    #[test]
    fn test_identity_roundtrip_preserves_id() {
        let kp = IdentityKeyPair::generate().unwrap();
        let bytes = kp.to_bytes().unwrap();
        let back = IdentityKeyPair::from_bytes(&bytes).unwrap();
        assert_eq!(back.id(), kp.id());
    }
}
