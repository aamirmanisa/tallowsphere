//! # tallow-registry — fleet registry skeleton + receipt format v1
//!
//! Local-only skeleton of the Tallow spine's identity + receipts layers
//! (SPEC-v2 §10): a file-backed **device registry** and an **append-only,
//! hash-chained, Ed25519-signed receipts ledger**.
//!
//! - [`store`] — device registry (`registry.json`): id, role, status,
//!   Ed25519 public key, timestamps. Atomic writes (tmp + rename).
//! - [`receipt`] — receipt format v1: canonical-JSON body, sha256 digest,
//!   Ed25519 signature, `prev` hash chain. Full rules:
//!   `artifacts/tallow-mega-mesh-2026-09-27/registry/RECEIPT-FORMAT-v1.md`.
//! - [`ledger`] — append-only JSONL ledger (`receipts.jsonl`): chain and
//!   sequence linkage are enforced on append and re-verified on demand.
//! - [`bridge`] — registry rows → [`tallow_admission::server::DeviceEntry`]
//!   (the mint → door path preview; checklist item 2.4).
//! - [`pins`] — peer **pin registry** (`pins.json`): out-of-band identity /
//!   SPKI pins with fail-closed resolution (pin + registry-verify arc; never
//!   trust-on-first-use).
//!
//! Everything is local by design: the CLI (`tallow-registry`) is the v1
//! "registry service" shape. It runs on deterministic DEV key material by
//! default with a loud warning; `--key` loads real material.
//!
//! Known v1 limits (documented in the format spec): single actor key per
//! ledger, no key rotation, no external anchoring (RFC 3161 / SCITT later).

#![forbid(unsafe_code)]

pub mod bridge;
pub mod canonical;
pub mod ledger;
pub mod pins;
pub mod receipt;
pub mod store;

pub use canonical::{canonical_digest_hex, canonical_json};
pub use ledger::{Ledger, LedgerError, LedgerVerdict, Query};
pub use pins::{PinChange, PinError, PinRow, PinVerdict, PinsStore};
pub use receipt::{key_fp16, Receipt, ReceiptError, Signed, RECEIPT_V};
pub use store::{DeviceRow, RegistryStore, StoreError};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}
