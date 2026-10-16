//! Room/lobby system for multi-party transfers.
//!
//! Only [`code`] (code phrases, passcodes, room-id derivation) is available to
//! wasm builds — the browser needs the derivation shared with the CLI, nothing
//! else from this module. `manager`/`roles` are full-only (relay-facing).

pub mod code;
#[cfg(feature = "full")]
pub mod manager;
#[cfg(feature = "full")]
pub mod roles;

pub use code::generate_code_phrase;
#[cfg(feature = "full")]
pub use manager::RoomManager;
#[cfg(feature = "full")]
pub use roles::RoomRole;
