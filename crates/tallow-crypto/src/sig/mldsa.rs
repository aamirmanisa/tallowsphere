//! ML-DSA-87 (FIPS 204) digital signature scheme

use crate::error::{CryptoError, Result};
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// ML-DSA-87 signing key byte length
pub const SK_LEN: usize = 4896;

/// ML-DSA-87 verifying key byte length
pub const VK_LEN: usize = 2592;

/// ML-DSA-87 signer
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct MlDsaSigner {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl MlDsaSigner {
    /// Generate a new ML-DSA-87 keypair
    pub fn keygen() -> Result<Self> {
        let (vk, sk) = ml_dsa_87::KG::try_keygen().map_err(|_| {
            CryptoError::KeyGeneration("ML-DSA-87 keygen failed: OS RNG unavailable".to_string())
        })?;

        Ok(Self {
            public_key: vk.into_bytes().to_vec(),
            secret_key: sk.into_bytes().to_vec(),
        })
    }

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature bytes, or an error if signing fails
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk_bytes: [u8; SK_LEN] = self.secret_key.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidKey("Invalid ML-DSA-87 signing key length".to_string())
        })?;

        let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|_| CryptoError::Signing("Invalid ML-DSA-87 signing key".to_string()))?;

        let sig = sk
            .try_sign(message, &[])
            .map_err(|_| CryptoError::Signing("ML-DSA-87 signing failed".to_string()))?;

        Ok(sig.to_vec())
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

/// Verify an ML-DSA-87 signature
///
/// # Arguments
///
/// * `public_key` - The signer's public key bytes
/// * `message` - The original message
/// * `signature` - The signature bytes to verify
///
/// # Returns
///
/// Ok(()) if valid, Err otherwise
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let vk_bytes: [u8; VK_LEN] = public_key.try_into().map_err(|_| {
        CryptoError::Verification("Invalid ML-DSA-87 public key length".to_string())
    })?;

    let vk = ml_dsa_87::PublicKey::try_from_bytes(vk_bytes)
        .map_err(|_| CryptoError::Verification("Invalid ML-DSA-87 public key".to_string()))?;

    // Convert signature bytes to fixed-size array
    let sig_bytes: [u8; 4627] = signature
        .try_into()
        .map_err(|_| CryptoError::Verification("Invalid ML-DSA-87 signature length".to_string()))?;

    if !vk.verify(message, &sig_bytes, &[]) {
        return Err(CryptoError::Verification(
            "ML-DSA-87 signature verification failed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_sign_verify() {
        let signer = MlDsaSigner::keygen().unwrap();
        let message = b"test message";

        let sig = signer.sign(message).unwrap();
        let result = verify(signer.public_key_bytes(), message, &sig);

        assert!(result.is_ok());
    }

    #[test]
    fn test_mldsa_wrong_message() {
        let signer = MlDsaSigner::keygen().unwrap();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let sig = signer.sign(message).unwrap();
        let result = verify(signer.public_key_bytes(), wrong_message, &sig);

        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa_key_sizes() {
        let signer = MlDsaSigner::keygen().unwrap();
        assert_eq!(signer.public_key_bytes().len(), VK_LEN);
        assert_eq!(signer.secret_key.len(), SK_LEN);
    }
}
