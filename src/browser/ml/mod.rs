//! Machine learning foundation for HackTheCart.
//!
//! Provides text embeddings, vector search, and ML-based product matching.
//! By default uses a deterministic mock embedding engine so tests are stable
//! and no model weights need to be committed. Real Candle/BGE integration is
//! gated behind the `real-ml` cargo feature (not yet wired).

pub mod embeddings;
pub mod ml_matcher;
pub mod vector_store;

/// Common error type for ML operations.
#[derive(Debug, Clone)]
pub enum MlError {
    ModelLoad(String),
    Tokenize(String),
    Inference(String),
    DimensionMismatch { expected: usize, got: usize },
    Io(String),
}

impl std::fmt::Display for MlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlError::ModelLoad(s) => write!(f, "model load error: {}", s),
            MlError::Tokenize(s) => write!(f, "tokenize error: {}", s),
            MlError::Inference(s) => write!(f, "inference error: {}", s),
            MlError::DimensionMismatch { expected, got } => {
                write!(f, "dimension mismatch: expected {}, got {}", expected, got)
            }
            MlError::Io(s) => write!(f, "io error: {}", s),
        }
    }
}

impl std::error::Error for MlError {}
