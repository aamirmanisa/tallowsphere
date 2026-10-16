//! # tallow-advisory — advisory v1 (checklist 3.6)
//!
//! Read-only anomaly detection over the local ledgers (jobs receipts) and the
//! mesh snapshot, producing **advisory findings for a human**.
//!
//! ## Red lines (binding — see `advisory/ADVISORY-V1.md` for the full list)
//!
//! - **No write path.** This crate never opens a file for writing, never
//!   mutates the mesh, ledger, or any system state. It reads files and prints.
//! - **No network.** No provider calls, no telemetry, no model calls.
//! - **No automated action.** Findings are *suggestions*; acting is a human
//!   decision, always (human-gated by construction — there is nothing to gate
//!   because nothing here acts).
//! - **No secrets in output.** Fingerprints only; never key material.
//! - **Deterministic and explainable.** v1 has no ML: fixed detectors with
//!   evidence attached; same input ⇒ same findings. (Hermes / local-model
//!   layers are a follow-up and remain advisory-only.)
//!
//! Exit codes (CLI): `0` clean or info-only · `4` warn findings · `5` critical ·
//! `2` usage · `1` error.

#![forbid(unsafe_code)]

pub mod advise;
pub mod cli;
pub mod detectors;
pub mod findings;
pub mod ledger;
