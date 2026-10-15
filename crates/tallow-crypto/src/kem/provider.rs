//! Crypto provider selection for the KEX stack — one provider path, one gate
//!
//! ## Why this module exists (P10-R01 / P4-6, ATK-4-6)
//!
//! The audit flagged a crypto-provider split (`ring` vs `aws-lc-rs`) and the
//! absence of any selection gate: which implementation served a group was an
//! accident of feature flags, not a decision. This module codifies the split
//! that actually exists and makes it single-valued.
//!
//! ## The split, codified
//!
//! - **KEX plane — [`Provider::PureRust`] (this crate).** Every KEM algorithm
//!   is served by exactly one backing implementation:
//!   - [`KemAlgorithm::Hybrid`] → the in-crate `HybridKem` combiner over the
//!     two backings below (ML-KEM + X25519),
//!   - [`KemAlgorithm::MlKem1024`] → `fips203` (FIPS 203),
//!   - [`KemAlgorithm::X25519`] → `x25519-dalek` / `curve25519-dalek`.
//!
//!   `tallow-crypto` does not depend on `ring` or `aws-lc-rs`; a test below
//!   enforces that this stays true, so there is no second provider for the
//!   KEX plane to silently fall back to.
//!
//! - **TLS plane — rustls + `aws-lc-rs` (owned by `tallow-net`).** The
//!   `quinn`/`rustls` configs in `crates/tallow-net/src/transport/tls_config.rs`
//!   build the provider explicitly with
//!   `rustls::crypto::aws_lc_rs::default_provider()`, and the workspace has no
//!   `ring` dependency at all (`crates/tallow-net/Cargo.toml`: "TLS (aws-lc-rs
//!   backend — ring has compile-time assertion bug on macOS ARM)"; the same
//!   choice is carried through `quinn`, `rcgen` and `hickory-resolver`). That
//!   plane is out of scope for enforcement here — the negotiated TLS group is
//!   asserted and alarmed at that layer (P4-6 landed 2026-09-16:
//!   `tallow-net::transport::tls_cohort::{assert_pq_hybrid_kex_group,
//!   alarm_on_classical_kex}`, wired at TCP+TLS handshake completion in
//!   `tcp_tls` / `proxied`, with a classical-only handshake failing the
//!   fail-loud assert as a silent PQ downgrade).
//!
//! ## Enforcement
//!
//! [`provider_for`] is the single selection function: *total* (every
//! [`KemAlgorithm`] has a provider) and *single-valued* (exactly one provider
//! per algorithm). The tests fail if an algorithm maps to zero or two
//! providers, or if a second provider enters this crate's dependency path.

use super::KemAlgorithm;
use serde::{Deserialize, Serialize};

/// Identifies which provider serves an algorithm on the KEX plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provider {
    /// Pure-Rust implementations (`fips203`, `x25519-dalek`). The only
    /// provider for the KEX plane.
    PureRust,
}

impl Provider {
    /// Stable identifier for logs, alarms and `doctor` output.
    pub fn id(&self) -> &'static str {
        match self {
            Provider::PureRust => "pure-rust",
        }
    }
}

/// One row of the KEX provider table: an algorithm and its single backing.
#[derive(Debug, Clone, Copy)]
pub struct ProviderEntry {
    /// The KEM algorithm
    pub algorithm: KemAlgorithm,
    /// The provider that serves it
    pub provider: Provider,
    /// The crate that backs the provider for this algorithm
    pub backing: &'static str,
}

/// The KEX-plane provider table — exactly one entry per [`KemAlgorithm`].
pub const PROVIDER_TABLE: &[ProviderEntry] = &[
    ProviderEntry {
        algorithm: KemAlgorithm::Hybrid,
        provider: Provider::PureRust,
        backing: "fips203 (ML-KEM-1024) + x25519-dalek, combined by kem::hybrid",
    },
    ProviderEntry {
        algorithm: KemAlgorithm::MlKem1024,
        provider: Provider::PureRust,
        backing: "fips203 (FIPS 203)",
    },
    ProviderEntry {
        algorithm: KemAlgorithm::X25519,
        provider: Provider::PureRust,
        backing: "x25519-dalek",
    },
];

/// The one crypto provider path for the KEX stack.
pub fn kex_provider() -> Provider {
    Provider::PureRust
}

/// Single selection function: the provider serving `algorithm`.
///
/// Contract (enforced by tests):
/// - *total* — every [`KemAlgorithm`] has an entry in [`PROVIDER_TABLE`];
/// - *single-valued* — no algorithm has two providers.
///
/// # Panics
///
/// Panics if the table is not total or not single-valued. That state is a
/// programming error caught by tests; failing loudly is strictly better than
/// a silent fallback to "some other provider".
pub fn provider_for(algorithm: KemAlgorithm) -> Provider {
    let mut found: Option<Provider> = None;
    for entry in PROVIDER_TABLE {
        if entry.algorithm == algorithm {
            if found.is_some() {
                panic!("provider table is not single-valued for {algorithm:?}");
            }
            found = Some(entry.provider);
        }
    }
    found.unwrap_or_else(|| panic!("no provider registered for {algorithm:?} (table not total)"))
}

/// The crate backing `algorithm`'s provider (for alarms and `doctor` output).
///
/// # Panics
///
/// Panics if the table has no entry for `algorithm` — see [`provider_for`].
pub fn backing_for(algorithm: KemAlgorithm) -> &'static str {
    PROVIDER_TABLE
        .iter()
        .find(|e| e.algorithm == algorithm)
        .map(|e| e.backing)
        .unwrap_or_else(|| panic!("no provider registered for {algorithm:?} (table not total)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full set of KEM algorithms — update when `KemAlgorithm` grows.
    fn all_algorithms() -> [KemAlgorithm; 3] {
        [
            KemAlgorithm::Hybrid,
            KemAlgorithm::MlKem1024,
            KemAlgorithm::X25519,
        ]
    }

    #[test]
    fn test_provider_selection_is_total_and_single_valued() {
        let all = all_algorithms();

        // Totality: exactly one row per algorithm.
        assert_eq!(PROVIDER_TABLE.len(), all.len());
        for algorithm in all {
            assert_eq!(
                PROVIDER_TABLE
                    .iter()
                    .filter(|e| e.algorithm == algorithm)
                    .count(),
                1,
                "{algorithm:?} must map to exactly one provider entry"
            );
        }

        // Single-valuedness + the selection function agrees with the table.
        for entry in PROVIDER_TABLE {
            assert_eq!(provider_for(entry.algorithm), entry.provider);
        }
        for algorithm in all {
            assert_eq!(provider_for(algorithm), Provider::PureRust);
        }
        assert_eq!(kex_provider(), Provider::PureRust);
        assert_eq!(Provider::PureRust.id(), "pure-rust");
    }

    #[test]
    fn test_backings_are_documented_for_every_algorithm() {
        for algorithm in all_algorithms() {
            assert!(!backing_for(algorithm).is_empty());
        }
    }

    /// Enforce "one provider path" for the KEX plane: `tallow-crypto` must not
    /// pick up a second provider (`ring` / `aws-lc-rs`). The TLS plane in
    /// `tallow-net` uses `aws-lc-rs` via rustls; the KEX plane does not.
    #[test]
    fn test_no_second_provider_in_crate_dependency_path() {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        for banned in ["ring", "aws-lc-rs", "aws_lc_rs"] {
            for line in manifest.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with(banned) {
                    panic!(
                        "second crypto provider `{banned}` found in tallow-crypto/Cargo.toml: \
                         `{trimmed}` — the KEX plane must have exactly one provider path"
                    );
                }
            }
        }
    }
}
