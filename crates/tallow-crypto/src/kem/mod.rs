//! Key Encapsulation Mechanisms (KEM)
//!
//! Provides ML-KEM (Kyber), X25519, and hybrid KEM constructions.

pub mod hybrid;
pub mod mlkem;
pub mod negotiation;
pub mod provider;
pub mod x25519;

pub use hybrid::HybridKem;
pub use mlkem::MlKem;
pub use negotiation::{
    negotiate, negotiate_with_downgrade_guard, DowngradeAlarm, DowngradePolicy, KemCapabilities,
    NegotiationOutcome,
};
pub use provider::{backing_for, kex_provider, provider_for, Provider, PROVIDER_TABLE};
pub use x25519::X25519KeyPair;

use serde::{Deserialize, Serialize};

/// Supported KEM algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum KemAlgorithm {
    /// ML-KEM-1024 (post-quantum)
    MlKem1024,
    /// X25519 (classical ECDH)
    X25519,
    /// Hybrid: ML-KEM-1024 + X25519
    #[default]
    Hybrid,
}
