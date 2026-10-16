//! MCP (Model Context Protocol) **client** support — see [`client`] for the wire format.
//!
//! Tallow is export-only by design; this module is the other direction, where Tallow consumes a
//! third-party MCP server's tools (sheet item U-G03).

pub mod client;

pub use client::{McpClient, Tool, DEFAULT_TIMEOUT};
