//! Error types for cryptographic operations

use thiserror::Error;

/// Result type alias using CryptoError
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Error during key generation
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Error during encryption
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Error during decryption
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Error during signing
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Error during signature verification
    #[error("Verification failed: {0}")]
    Verification(String),

    /// Hash mismatch detected
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash value
        expected: String,
        /// Actual hash value
        actual: String,
    },

    /// PAKE protocol failure
    #[error("PAKE protocol failed: {0}")]
    PakeFailure(String),

    /// Invalid key material
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid nonce value
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Buffer size too small for operation
    #[error("Buffer too small: need {needed} bytes, got {actual}")]
    BufferTooSmall {
        /// Required buffer size
        needed: usize,
        /// Actual buffer size
        actual: usize,
    },

    /// Unsupported operation or algorithm
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// I/O error during cryptographic operation
    #[error("I/O error: {0}")]
    Io(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::Io(e.to_string())
    }
}

impl From<bincode::Error> for CryptoError {
    fn from(e: bincode::Error) -> Self {
        CryptoError::Serialization(e.to_string())
    }
}
