//! Cryptographic hash functions and utilities
//!
//! This module provides hash functions including BLAKE3 and SHA3,
//! domain separation constants, and Merkle tree implementations.

pub mod blake3;
pub mod domain;
pub mod merkle;
pub mod sha3;

pub use self::blake3::{derive_key, hash, keyed_hash};
pub use self::sha3::sha3_256;
pub use domain::*;
pub use merkle::{MerkleProof, MerkleTree};
