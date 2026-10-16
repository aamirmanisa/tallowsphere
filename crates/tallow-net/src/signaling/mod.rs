//! Signaling protocol for peer coordination

pub mod client;
pub mod protocol;

pub use client::SignalingClient;
pub use protocol::SignalingMessage;
