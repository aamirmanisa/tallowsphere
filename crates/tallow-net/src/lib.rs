//! Network layer for Tallow secure file transfer
//!
//! Provides transport abstractions, NAT traversal, discovery, privacy-preserving
//! networking, relay support, and signaling protocols.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod error;
pub mod nat;
pub mod privacy;
pub mod relay;
pub mod signaling;
pub mod transport;

// Re-exports
pub use error::NetworkError;
pub use transport::PeerChannel;
pub use transport::Transport;

/// Result type for network operations
pub type Result<T> = std::result::Result<T, NetworkError>;
