//! Memory safety utilities for cryptographic operations
//!
//! This module provides secure memory handling, constant-time operations,
//! and protection against memory dumps.

pub mod constant_time;
pub mod secure_buf;
pub mod wipe;

pub use constant_time::{ct_eq, ct_select};
pub use secure_buf::SecureBuf;
pub use wipe::{lock_memory, prevent_core_dumps, wipe_on_drop};
