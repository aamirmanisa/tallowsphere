//! Digital signature schemes
//!
//! Provides Ed25519, ML-DSA (Dilithium), SLH-DSA (SPHINCS+), and hybrid signatures.

pub mod ed25519;
pub mod file_signing;
pub mod hybrid;
pub mod mldsa;
pub mod slhdsa;

pub use ed25519::Ed25519Signer;
pub use file_signing::{sign_chunk, verify_chunk, ChunkSignature};
pub use hybrid::{HybridPublicKey, HybridSignature, HybridSigner};
pub use mldsa::MlDsaSigner;
pub use slhdsa::SlhDsaSigner;

use serde::{Deserialize, Serialize};

/// Supported signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SignatureAlgorithm {
    /// Ed25519 (classical)
    Ed25519,
    /// ML-DSA-87 (post-quantum Dilithium)
    MlDsa87,
    /// SLH-DSA (post-quantum SPHINCS+)
    SlhDsa,
    /// Hybrid: ML-DSA-87 + Ed25519
    #[default]
    Hybrid,
}
