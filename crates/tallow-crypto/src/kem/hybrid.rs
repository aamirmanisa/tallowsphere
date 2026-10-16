//! Hybrid KEM combining ML-KEM and X25519

use crate::error::Result;
use crate::hash::{blake3, domain};
use crate::kem::{mlkem, x25519};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Hybrid public key (ML-KEM + X25519)
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// ML-KEM-1024 public key component for post-quantum encapsulation
    pub mlkem: mlkem::PublicKey,
    #[serde(with = "x25519_pubkey_serde")]
    /// X25519 public key component for classical Diffie-Hellman
    pub x25519: x25519::X25519PublicKey,
}

// Custom serde for X25519 PublicKey
mod x25519_pubkey_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        pk.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(PublicKey::from(bytes))
    }
}

/// Hybrid secret key (ML-KEM + X25519)
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct SecretKey {
    /// ML-KEM-1024 secret key component for post-quantum decapsulation
    pub mlkem: mlkem::SecretKey,
    /// X25519 key pair component for classical Diffie-Hellman
    pub x25519: x25519::X25519KeyPair,
}

/// Hybrid ciphertext
#[derive(Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// ML-KEM-1024 ciphertext encapsulating the post-quantum shared secret
    pub mlkem: mlkem::Ciphertext,
    #[serde(with = "x25519_pubkey_serde")]
    /// Ephemeral X25519 public key for the classical DH component
    pub x25519_public: x25519::X25519PublicKey,
}

/// Hybrid shared secret
///
/// Not `Clone` — shared secrets must never be duplicated. Duplication risks
/// the secret surviving in memory longer than necessary and undermines
/// zeroization guarantees. Use `expose_secret()` to access the raw bytes.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub(crate) [u8; 32]);

impl SharedSecret {
    /// Access the raw secret bytes
    ///
    /// Callers are responsible for zeroizing any copies they make.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hybrid KEM operations
pub struct HybridKem;

impl HybridKem {
    /// Generate a new hybrid keypair
    ///
    /// # Returns
    ///
    /// A tuple of (public_key, secret_key), or an error if key generation fails
    pub fn keygen() -> Result<(PublicKey, SecretKey)> {
        let (mlkem_pk, mlkem_sk) = mlkem::MlKem::keygen()?;
        let x25519_kp = x25519::X25519KeyPair::generate();

        let pk = PublicKey {
            mlkem: mlkem_pk,
            x25519: *x25519_kp.public_key(),
        };

        let sk = SecretKey {
            mlkem: mlkem_sk,
            x25519: x25519_kp,
        };

        Ok((pk, sk))
    }

    /// Encapsulate a shared secret to a hybrid public key
    ///
    /// # Arguments
    ///
    /// * `pk` - The recipient's public key
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret)
    pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
        // Encapsulate with ML-KEM
        let (mlkem_ct, mlkem_ss) = mlkem::MlKem::encapsulate(&pk.mlkem)?;

        // Generate ephemeral X25519 keypair and compute DH
        let ephemeral_kp = x25519::X25519KeyPair::generate();
        let x25519_ss = ephemeral_kp.diffie_hellman(&pk.x25519)?;

        // Combine both shared secrets using BLAKE3
        let combined = Self::combine_secrets(&mlkem_ss.0, &x25519_ss.0)?;

        let ct = Ciphertext {
            mlkem: mlkem_ct,
            x25519_public: *ephemeral_kp.public_key(),
        };

        Ok((ct, SharedSecret(combined)))
    }

    /// Decapsulate a shared secret from a hybrid ciphertext
    ///
    /// # Arguments
    ///
    /// * `sk` - The recipient's secret key
    /// * `ct` - The ciphertext
    ///
    /// # Returns
    ///
    /// The shared secret
    pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret> {
        // Decapsulate ML-KEM
        let mlkem_ss = mlkem::MlKem::decapsulate(&sk.mlkem, &ct.mlkem)?;

        // Compute X25519 DH
        let x25519_ss = sk.x25519.diffie_hellman(&ct.x25519_public)?;

        // Combine both shared secrets
        let combined = Self::combine_secrets(&mlkem_ss.0, &x25519_ss.0)?;

        Ok(SharedSecret(combined))
    }

    /// Combine two shared secrets using BLAKE3 KDF
    ///
    /// Parameter order is significant: ML-KEM occupies the first 32 bytes,
    /// X25519 occupies the second 32 bytes. Do NOT swap the parameter order.
    fn combine_secrets(mlkem_ss: &[u8; 32], x25519_ss: &[u8; 32]) -> Result<[u8; 32]> {
        use zeroize::Zeroize;

        let mut combined_input = [0u8; 64];
        combined_input[..32].copy_from_slice(mlkem_ss);
        combined_input[32..].copy_from_slice(x25519_ss);

        // Use BLAKE3 with domain separation to combine
        let result = blake3::derive_key(domain::DOMAIN_HYBRID_COMBINE, &combined_input);

        // Zeroize temporary that held both shared secrets
        combined_input.zeroize();

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_roundtrip() {
        let (pk, sk) = HybridKem::keygen().unwrap();
        let (ct, ss1) = HybridKem::encapsulate(&pk).unwrap();
        let ss2 = HybridKem::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss1.0, ss2.0);
    }

    #[test]
    fn test_hybrid_serialization() {
        let (pk, sk) = HybridKem::keygen().unwrap();

        let pk_serialized = bincode::serialize(&pk).unwrap();
        let sk_serialized = bincode::serialize(&sk).unwrap();

        let pk2: PublicKey = bincode::deserialize(&pk_serialized).unwrap();
        let sk2: SecretKey = bincode::deserialize(&sk_serialized).unwrap();

        let (ct, ss1) = HybridKem::encapsulate(&pk2).unwrap();
        let ss2 = HybridKem::decapsulate(&sk2, &ct).unwrap();

        assert_eq!(ss1.0, ss2.0);
    }
}
