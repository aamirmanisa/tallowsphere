//! Protocol error types

use std::fmt;

/// Protocol-layer errors
#[derive(Debug)]
pub enum ProtocolError {
    /// Invalid message format
    InvalidMessage(String),
    /// Version mismatch
    VersionMismatch { local: u32, remote: u32 },
    /// Encoding error
    EncodingError(String),
    /// Decoding error
    DecodingError(String),
    /// Transfer failed
    TransferFailed(String),
    /// Compression error
    CompressionError(String),
    /// Invalid state transition
    InvalidStateTransition { from: String, to: String },
    /// IO error
    Io(std::io::Error),
    /// Handshake failed (generic -- MUST NOT leak whether PAKE or KEM caused it)
    HandshakeFailed(String),
    /// Key confirmation mismatch
    KeyConfirmationFailed,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            Self::VersionMismatch { local, remote } => {
                write!(f, "Version mismatch: local={}, remote={}", local, remote)
            }
            Self::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            Self::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            Self::TransferFailed(msg) => write!(f, "Transfer failed: {}", msg),
            Self::CompressionError(msg) => write!(f, "Compression error: {}", msg),
            Self::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition: {} -> {}", from, to)
            }
            Self::Io(err) => write!(f, "IO error: {}", err),
            Self::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            Self::KeyConfirmationFailed => {
                write!(f, "Handshake failed: key confirmation mismatch")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<std::io::Error> for ProtocolError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
