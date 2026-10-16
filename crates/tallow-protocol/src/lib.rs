//! Tallow wire protocol and transfer logic
//!
//! Defines message formats, transfer pipelines, compression, file manifests,
//! chat protocol, room management, and metadata handling.
//!
//! # Feature flags
//!
//! - **`full`** (default): All modules, native dependencies (tokio, zstd, etc.)
//! - **`wasm`**: Browser-compatible subset for WASM bindings (wire messages + KEX)

#![forbid(unsafe_code)]

#[cfg(feature = "full")]
pub mod chat;
#[cfg(feature = "full")]
pub mod compression;
pub mod error;
#[cfg(any(feature = "full", feature = "wasm"))]
pub mod kex;
#[cfg(feature = "full")]
pub mod metadata;
#[cfg(any(feature = "full", feature = "wasm"))]
pub mod mode_auth;
#[cfg(feature = "full")]
pub mod multi;
#[cfg(feature = "full")]
pub mod pq_handshake;
#[cfg(any(feature = "full", feature = "wasm"))]
pub mod room;
pub mod transfer;
pub mod wire;

pub use error::ProtocolError;

/// Result type for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;
