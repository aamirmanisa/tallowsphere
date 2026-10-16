//! Hybrid signature combining ML-DSA and Ed25519

use crate::error::Result;
use crate::sig::{ed25519, mldsa};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Hybrid signature (ML-DSA + Ed25519)
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// ML-DSA-87 signature bytes for post-quantum authentication
    pub mldsa: Vec<u8>,
    #[serde(with = "serde_arrays")]
    /// Ed25519 signature bytes for classical authentication
    pub ed25519: [u8; 64],
}

// Custom serde for [u8; 64]
mod serde_arrays {
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

/// Hybrid signer
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct HybridSigner {
    mldsa: mldsa::MlDsaSigner,
    ed25519: ed25519::Ed25519Signer,
}

impl HybridSigner {
    /// Generate a new hybrid keypair
    pub fn keygen() -> Result<Self> {
        Ok(Self {
            mldsa: mldsa::MlDsaSigner::keygen()?,
            ed25519: ed25519::Ed25519Signer::keygen(),
        })
    }

    /// Sign a message with both algorithms
    ///
    /// Both ML-DSA-87 and Ed25519 signatures are produced.
    /// Both must be valid for verification to succeed.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let mldsa_sig = self.mldsa.sign(message)?;
        let ed25519_sig = self.ed25519.sign(message);

        Ok(HybridSignature {
            mldsa: mldsa_sig,
            ed25519: ed25519_sig,
        })
    }

    /// Get the hybrid public key
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            mldsa: self.mldsa.public_key_bytes().to_vec(),
            ed25519: self.ed25519.verifying_key_bytes(),
        }
    }
}

/// Hybrid public key
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// ML-DSA-87 public key bytes for post-quantum signature verification
    pub mldsa: Vec<u8>,
    /// Ed25519 verifying key bytes for classical signature verification
    pub ed25519: [u8; 32],
}

/// Verify a hybrid signature
///
/// Both signatures are verified unconditionally to prevent timing side-channels.
/// A failure in one algorithm must not short-circuit the other.
pub fn verify(
    public_key: &HybridPublicKey,
    message: &[u8],
    signature: &HybridSignature,
) -> Result<()> {
    // Verify both unconditionally — no short-circuit
    let mldsa_result = mldsa::verify(&public_key.mldsa, message, &signature.mldsa);
    let ed25519_result = ed25519::verify(&public_key.ed25519, message, &signature.ed25519);

    // Both must succeed
    mldsa_result?;
    ed25519_result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() {
        let signer = HybridSigner::keygen().unwrap();
        let message = b"test message";

        let signature = signer.sign(message).unwrap();
        let public_key = signer.public_key();

        let result = verify(&public_key, message, &signature);
        assert!(result.is_ok());
    }
}
