//! Password-Authenticated Key Exchange (PAKE) protocols
//!
//! **TCS-PAKE-1** — Tallow's own PAKE over Ristretto255 (CPace-*shaped*; no
//! `draft-irtf-cfrg-cpace` conformance is claimed). Construction, vectors and the deviation
//! record: `docs/security/pake-vectors-2026-10-13.md`.
//!
//! Code identifiers keep the historical `cpace` name (`cpace.rs`, `CpaceInitiator`,
//! `start_cpace_*`): they are wire-adjacent and renaming one is a suite change, not a rename
//! (TCS-1 spec §2.4 rule 1). OPAQUE is deferred to v2.

pub mod cpace;
pub mod sas;

#[cfg(test)]
mod adversarial;
#[cfg(test)]
mod cpace_draft_vectors;
#[cfg(test)]
mod tcs_pake_1_vectors;
#[cfg(test)]
mod vectors;

pub use cpace::{CpaceInitiator, CpaceResponder};
pub use sas::{SasCode, SAS_FINGERPRINT_BYTES, SAS_WORDS};
