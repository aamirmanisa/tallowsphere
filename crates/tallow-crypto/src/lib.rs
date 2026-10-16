//! # Tallow Cryptography Library
//!
//! This crate provides all cryptographic primitives for the Tallow secure file transfer system,
//! including post-quantum cryptography, symmetric encryption, key derivation, and ratcheting protocols.
//!
//! ## Features
//!
//! - **Post-Quantum Security**: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
//! - **Hybrid Cryptography**: Combines classical and PQ algorithms for defense-in-depth
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **Constant-Time Operations**: Protection against timing side-channels
//! - **Domain Separation**: Cryptographic domain separation for all use cases

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod error;
pub mod file;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod mem;
pub mod pake;
pub mod ratchet;
pub mod sig;
pub mod symmetric;
mod rng;

// Re-export commonly used types
pub use error::{CryptoError, Result};
pub use hash::{blake3, domain};
pub use symmetric::CipherSuite;

/// Library version constant
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Published suite identifier for the cryptographic construction this build implements.
///
/// The suite is **named and versioned rather than implied**: its construction, the points where it
/// deliberately deviates from the CPace draft, and its published vectors are recorded in the TCS-1
/// specification, and this name is what a reader can check a served build against.
///
/// **This constant is the source of truth for that name.** The site reads it at build time to fill
/// `suite` in `version.json` (see `website/src/integrations/release-identity.mjs`), and
/// `scripts/wire-version-claim-check.py` fails when a published page states a different one — so the
/// name a visitor sees and the name in the code cannot drift apart. Renaming it is a suite-defining
/// event: a new id, new vectors and a changelog row (TCS-1 §2.2), never a quiet edit.
pub const SUITE_ID: &str = "TCS-1";

/// Wire code for [`SUITE_ID`] — the one-byte form the handshake declares, bound into the transcript
/// by protocol v8 (checklist 5.2).
///
/// A *name* is not something a wire can carry, so the handshake declares this code instead and
/// absorbs it into the transcript beside the protocol version and mode. That is what makes an
/// unknown-suite attempt and a rewrite of the declared code fail loudly, and why there is no default
/// to fall back to: one code per suite id, a new suite gets a new code, and codes are never reused.
pub const SUITE_CODE_TCS1: u8 = 0x01;

/// The suite code this build implements — what it declares, and what it requires of a peer.
pub const fn suite_code() -> u8 {
    SUITE_CODE_TCS1
}

/// Whether `code` names a suite this build can actually run.
///
/// Unknown codes are refused, never defaulted: a peer declaring a suite outside this set is telling
/// us it will derive different keys, and proceeding on a guess is exactly the silent downgrade the
/// transcript binding exists to prevent.
pub const fn is_known_suite_code(code: u8) -> bool {
    code == SUITE_CODE_TCS1
}

/// Initialize the cryptography library (e.g., prevent core dumps, lock memory)
///
/// This should be called once at application startup for maximum security.
pub fn init() -> Result<()> {
    mem::wipe::prevent_core_dumps()?;
    Ok(())
}
