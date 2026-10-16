//! Key derivation functions
//!
//! This module provides KDF primitives including HKDF, Argon2, and password utilities.

pub mod argon2;
pub mod eff_wordlist;
pub mod hkdf;
pub mod password;

pub use self::argon2::{hash_password, verify_password};
pub use self::hkdf::derive;
pub use password::{estimate_entropy, generate_diceware};
