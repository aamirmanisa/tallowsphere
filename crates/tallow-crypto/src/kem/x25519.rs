//! X25519 key exchange

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

// Re-export PublicKey for use in other modules
pub use x25519_dalek::PublicKey as X25519PublicKey;

/// X25519 shared secret
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

/// X25519 keypair
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct X25519KeyPair {
    #[serde(with = "secret_serde")]
    secret: StaticSecret,
    #[serde(with = "public_serde")]
    public: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new X25519 keypair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self { secret, public }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get the public key as bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Perform Diffie-Hellman key exchange
    ///
    /// Rejects low-order points that produce an all-zero shared secret,
    /// which would indicate the peer sent a malicious public key.
    ///
    /// # Arguments
    ///
    /// * `their_public` - The other party's public key
    ///
    /// # Returns
    ///
    /// The shared secret, or an error if the peer's key is a low-order point
    pub fn diffie_hellman(
        &self,
        their_public: &PublicKey,
    ) -> std::result::Result<SharedSecret, crate::error::CryptoError> {
        let shared = self.secret.diffie_hellman(their_public);
        let bytes = *shared.as_bytes();

        // Reject all-zero shared secret (indicates low-order point attack)
        // Uses constant-time comparison to prevent timing side-channel leakage
        if crate::mem::constant_time::ct_eq(&bytes, &[0u8; 32]) {
            return Err(crate::error::CryptoError::InvalidKey(
                "X25519 DH produced all-zero output (low-order point)".into(),
            ));
        }

        Ok(SharedSecret(bytes))
    }

    /// Create a keypair from a secret key
    pub fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create a keypair from secret bytes
    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

// Custom serde for StaticSecret
mod secret_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::StaticSecret;

    pub fn serialize<S>(secret: &StaticSecret, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        secret.to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<StaticSecret, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(StaticSecret::from(bytes))
    }
}

// Custom serde for PublicKey
mod public_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S>(public: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        public.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Ok(PublicKey::from(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_exchange() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.diffie_hellman(bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(alice.public_key()).unwrap();

        assert_eq!(alice_shared.0, bob_shared.0);
    }

    #[test]
    fn test_x25519_serialization() {
        let keypair = X25519KeyPair::generate();
        let serialized = bincode::serialize(&keypair).unwrap();
        let deserialized: X25519KeyPair = bincode::deserialize(&serialized).unwrap();

        assert_eq!(keypair.public_bytes(), deserialized.public_bytes());
    }

    #[test]
    fn test_x25519_from_bytes() {
        let secret_bytes = [42u8; 32];
        let kp1 = X25519KeyPair::from_bytes(secret_bytes);
        let kp2 = X25519KeyPair::from_bytes(secret_bytes);

        assert_eq!(kp1.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_x25519_low_order_point_rejected() {
        // The all-zero public key is a low-order point on Curve25519
        // DH with it produces an all-zero shared secret, which we reject
        let kp = X25519KeyPair::generate();
        let zero_pk = PublicKey::from([0u8; 32]);
        let result = kp.diffie_hellman(&zero_pk);
        assert!(result.is_err(), "DH with all-zero public key should fail");
    }
}
