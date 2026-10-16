//! SLH-DSA-SHA2-256f (FIPS 205) stateless hash-based signature scheme

use crate::error::{CryptoError, Result};
use fips205::slh_dsa_sha2_256f;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// SLH-DSA-SHA2-256f signing key byte length
pub const SK_LEN: usize = 128;

/// SLH-DSA-SHA2-256f verifying key byte length
pub const VK_LEN: usize = 64;

/// SLH-DSA signer (SHA2-256f, fast variant)
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct SlhDsaSigner {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl SlhDsaSigner {
    /// Generate a new SLH-DSA keypair
    pub fn keygen() -> Result<Self> {
        let (vk, sk) = slh_dsa_sha2_256f::KG::try_keygen().map_err(|_| {
            CryptoError::KeyGeneration("SLH-DSA keygen failed: OS RNG unavailable".to_string())
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
            CryptoError::InvalidKey("Invalid SLH-DSA signing key length".to_string())
        })?;

        let sk = slh_dsa_sha2_256f::PrivateKey::try_from_bytes(&sk_bytes)
            .map_err(|_| CryptoError::Signing("Invalid SLH-DSA signing key".to_string()))?;

        let sig = sk
            .try_sign(message, &[], true)
            .map_err(|_| CryptoError::Signing("SLH-DSA signing failed".to_string()))?;

        Ok(sig.to_vec())
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

/// Verify an SLH-DSA signature
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
    let vk_bytes: [u8; VK_LEN] = public_key
        .try_into()
        .map_err(|_| CryptoError::Verification("Invalid SLH-DSA public key length".to_string()))?;

    let vk = slh_dsa_sha2_256f::PublicKey::try_from_bytes(&vk_bytes)
        .map_err(|_| CryptoError::Verification("Invalid SLH-DSA public key".to_string()))?;

    // SLH-DSA-SHA2-256f signature size is 49856 bytes
    let sig_bytes: [u8; 49856] = signature
        .try_into()
        .map_err(|_| CryptoError::Verification("Invalid SLH-DSA signature length".to_string()))?;

    if !vk.verify(message, &sig_bytes, &[]) {
        return Err(CryptoError::Verification(
            "SLH-DSA signature verification failed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slhdsa_sign_verify() {
        let signer = SlhDsaSigner::keygen().unwrap();
        let message = b"test message";

        let sig = signer.sign(message).unwrap();
        let result = verify(signer.public_key_bytes(), message, &sig);

        assert!(result.is_ok());
    }

    #[test]
    fn test_slhdsa_wrong_message() {
        let signer = SlhDsaSigner::keygen().unwrap();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let sig = signer.sign(message).unwrap();
        let result = verify(signer.public_key_bytes(), wrong_message, &sig);

        assert!(result.is_err());
    }
}
