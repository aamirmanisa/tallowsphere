//! Symmetric encryption primitives
//!
//! Provides AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 (at-rest objects,
//! see [`xchacha20`]), and optionally AEGIS-256 with automatic cipher suite
//! selection based on hardware capabilities.
//!
//! [`CipherSuite`] models the transport/chunk negotiation surface (96-bit
//! nonces, counter-managed). At-rest encryption deliberately rides the
//! dedicated [`xchacha20`] module instead: 192-bit random nonces plus a
//! per-object DEK are properties a negotiated suite does not carry (W3
//! #141/#142 · P10-R06).

pub mod aes_gcm;
pub mod chacha20;
pub mod negotiation;
pub mod nonce;
pub mod xchacha20;

#[cfg(feature = "aegis")]
pub mod aegis;

pub use aes_gcm::{decrypt as aes_decrypt, encrypt as aes_encrypt};
pub use chacha20::{decrypt as chacha_decrypt, encrypt as chacha_encrypt};
pub use negotiation::{detect_aes_ni, select_cipher};
pub use nonce::NonceGenerator;

#[cfg(feature = "aegis")]
pub use self::aegis::{decrypt as aegis_decrypt, encrypt as aegis_encrypt};

use serde::{Deserialize, Serialize};

/// Supported cipher suites for symmetric encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256-GCM (hardware accelerated when available)
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// AEGIS-256 (experimental, requires feature flag)
    #[cfg(feature = "aegis")]
    Aegis256,
}

impl Default for CipherSuite {
    fn default() -> Self {
        select_cipher()
    }
}

impl CipherSuite {
    /// Get the key size for this cipher suite in bytes
    pub fn key_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
            #[cfg(feature = "aegis")]
            CipherSuite::Aegis256 => 32,
        }
    }

    /// Get the nonce size for this cipher suite in bytes
    pub fn nonce_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 12,
            CipherSuite::ChaCha20Poly1305 => 12,
            #[cfg(feature = "aegis")]
            CipherSuite::Aegis256 => 32,
        }
    }

    /// Get the authentication tag size in bytes
    pub fn tag_size(&self) -> usize {
        match self {
            CipherSuite::Aes256Gcm => 16,
            CipherSuite::ChaCha20Poly1305 => 16,
            #[cfg(feature = "aegis")]
            CipherSuite::Aegis256 => 32,
        }
    }
}
