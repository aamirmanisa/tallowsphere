//! # tallow-locator — lawful egress broker (v1, local)
//!
//! SPEC-v2 §11: *sources = official provider APIs; pipeline = poll → normalize
//! → snapshot → score (latency · cost · jurisdiction · capability) → selector
//! → provisioner → receipts; compliance = own keys, robots/ToS, never
//! third-party endpoints, fail-close refusals.*
//!
//! This crate implements the **local, testable leg** of that pipeline:
//!
//! - [`watchers`] — provider watchers (Hetzner · Vultr · DigitalOcean · OVH).
//!   Every watcher has a **fixture** source (deterministic JSON, used by tests
//!   and rehearsals) and an **HTTP** source (official API, own key from env).
//!   Live polling requires provider keys — the operator leg.
//! - [`score`] — deterministic scoring model: cost · latency · jurisdiction ·
//!   capability, with class-dependent jurisdiction policy (ruling 6.5:
//!   privacy workloads exclude US; unknown jurisdictions fail closed).
//! - [`select`] — selector with **fail-close semantics**: zero compliant
//!   offers ⇒ explicit [`select::Refusal`] (no fallback, no "best effort").
//! - [`receipts`] — `locator.scorecard` / `locator.refusal` receipts on the
//!   registry's v1 ledger (Ed25519, hash-chained).
//!
//! **What v1 does not do (honest limits):** no provisioning (that is 3.3 and
//! is spend-gated), no live latency probes (static baselines table, marked),
//! no Onionoo/RDAP/Atlas sources yet (follow-ups), no operator keys wired in.
//! The CLI never calls a network unless `--live` is passed explicitly.

#![forbid(unsafe_code)]

pub mod cli;
pub mod model;
pub mod receipts;
pub mod score;
pub mod select;
pub mod watchers;

pub use model::{JobClass, Offer};
pub use select::{DecisionRecord, Refusal, SelectorError};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}
