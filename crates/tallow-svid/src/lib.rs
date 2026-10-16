//! `tallow-svid` — SPIFFE-style SVID workload identity (W3 identity wave, U-201 blueprint).
//!
//! Skeleton created by parent 2026-09-12; module files are filled by the W3
//! execution batch (U-211..U-213). Do not reorder the `mod` declarations:
//! each file has exactly one writer per batch.

pub mod issuer;
pub mod join;
pub mod model;
pub mod policy;
pub mod relay_auth;
pub mod revocation;
pub mod rotation;
pub mod verify;
pub mod wire;
pub mod workload;
