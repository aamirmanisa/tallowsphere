//! Ephemeral key pairs for single-use operations

use crate::kem::x25519::X25519KeyPair;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Ephemeral key pair (X25519)
#[derive(Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct EphemeralKeyPair {
    inner: X25519KeyPair,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        Self {
            inner: X25519KeyPair::generate(),
        }
    }

    /// Get the underlying X25519 keypair
    pub fn inner(&self) -> &X25519KeyPair {
        &self.inner
    }

    /// Get the public key bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        self.inner.public_bytes()
    }
}
