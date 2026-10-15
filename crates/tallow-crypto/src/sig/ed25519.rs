//! Ed25519 signature scheme

use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Ed25519 signer
#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519Signer {
    #[serde(with = "signing_key_serde")]
    signing_key: SigningKey,
    #[serde(with = "verifying_key_serde")]
    verifying_key: VerifyingKey,
}

impl Zeroize for Ed25519Signer {
    fn zeroize(&mut self) {
        // ed25519-dalek's SigningKey doesn't expose Zeroize directly.
        // Overwrite with a deterministic zero-seed key. Because SigningKey
        // is stored inline (not behind a pointer), this overwrites the
        // 32-byte secret seed at its memory location.
        self.signing_key = SigningKey::from_bytes(&[0u8; 32]);
        self.verifying_key = self.signing_key.verifying_key();
    }
}

impl Drop for Ed25519Signer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Ed25519Signer {
    /// Generate a new Ed25519 keypair
    pub fn keygen() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// 64-byte signature
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the verifying key as bytes
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Create a signer from a seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }
}

/// Verify an Ed25519 signature
///
/// # Arguments
///
/// * `public_key` - The signer's public key
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// Ok(()) if the signature is valid, Err otherwise
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::Verification(format!("Invalid public key: {}", e)))?;

    let sig = Signature::from_bytes(signature);

    // Use verify_strict to additionally reject low-order (weak) public keys and
    // low-order R components in the signature. The non-strict verify() already
    // uses non-cofactored verification and enforces canonical scalar encoding
    // (s < ℓ), but does not check is_small_order() on R or the verifying key.
    // verify_strict() adds those checks, closing the small-subgroup / weak-key
    // attack surface referenced in CVE-2025-69277.
    vk.verify_strict(message, &sig)
        .map_err(|e| CryptoError::Verification(format!("Signature verification failed: {}", e)))
}

// Custom serde for SigningKey
mod signing_key_serde {
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(key: &SigningKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

// Custom serde for VerifyingKey
mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519Signer::keygen();
        let message = b"test message";

        let signature = signer.sign(message);
        let result = verify(&signer.verifying_key_bytes(), message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_rejects_weak_public_key() {
        // The Ed25519 curve has cofactor 8, meaning 8 small-order (torsion)
        // points exist. A weak/low-order verifying key could be used in a
        // small-subgroup attack. verify_strict() must reject such keys.
        //
        // The identity point on Ed25519 compresses to 01 || 00 * 31.
        // It is a low-order point (order 1), so is_small_order() returns true.
        let weak_key_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0x01;
            b
        };

        let signer = Ed25519Signer::keygen();
        let message = b"test message";
        let signature = signer.sign(message);

        // Signature is valid for the real key but verification against the
        // weak (identity) key must fail.
        let result = verify(&weak_key_bytes, message, &signature);
        assert!(
            result.is_err(),
            "verify() must reject low-order (weak) public keys"
        );
    }

    #[test]
    fn test_ed25519_wrong_message() {
        let signer = Ed25519Signer::keygen();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = signer.sign(message);
        let result = verify(&signer.verifying_key_bytes(), wrong_message, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_serialization() {
        let signer = Ed25519Signer::keygen();
        let serialized = bincode::serialize(&signer).unwrap();
        let deserialized: Ed25519Signer = bincode::deserialize(&serialized).unwrap();

        let message = b"test";
        let sig1 = signer.sign(message);
        let sig2 = deserialized.sign(message);

        assert_eq!(sig1, sig2);
    }
}
