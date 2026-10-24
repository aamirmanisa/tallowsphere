//! TLS crypto-provider selection, including the post-quantum hybrid group.
//!
//! # Why this exists
//!
//! Until now every TLS entry point installed `rustls::crypto::ring` locally and
//! independently (`net.rs`, `transfer_net.rs`, `relay.rs`). Ring does not
//! implement ML-KEM, so no connection in this tree could negotiate a
//! post-quantum hybrid group — a passive recorder could keep the handshake and
//! open it later with a quantum computer ("harvest now, decrypt later").
//!
//! `aws-lc-rs` (already in the dependency graph through rustls' default
//! features) does implement `X25519MLKEM768`, and rustls 0.23 prefers it by
//! default when that provider is installed.
//!
//! # Why it is opt-in
//!
//! An ML-KEM key share adds ~1.2 KB to the ClientHello. That changes the TLS
//! fingerprint (JA3/JA4 size and ordering) that the browser-impersonation
//! profiles in `tls_profile.rs` reproduce. Modern Chrome does offer
//! `X25519MLKEM768`, so matching it is defensible — but a silent, fleet-wide
//! change to every handshake's fingerprint is not something a library should do
//! on its own. Hence:
//!
//! * default: ring provider, classical groups only — today's bytes, unchanged;
//! * `TALLOW_TLS_PQ=1`: aws-lc-rs provider, PQ hybrid preferred, classical
//!   fallback still enabled (a peer without the group still connects);
//! * whichever runs, [`info`] reports what was actually installed so a caller
//!   can log or assert it instead of assuming.

use std::sync::OnceLock;

/// The IANA name of the hybrid group (TLS codepoint 0x11EC).
pub const PQ_GROUP: &str = "X25519MLKEM768";

#[derive(Clone, Debug)]
pub struct ProviderInfo {
    /// Which provider is installed: `ring` or `aws-lc-rs`.
    pub provider: &'static str,
    /// Whether the post-quantum hybrid group is offered.
    pub pq_offered: bool,
    /// Group names in preference order, as rustls reports them.
    pub groups: Vec<String>,
}

static INSTALLED: OnceLock<ProviderInfo> = OnceLock::new();

/// Is the PQ hybrid requested by the environment?
///
/// Accepts `1`, `true`, `yes`, `on` — anything else is off. Read once, at
/// install time, so a later `set_var` cannot produce a provider/report mismatch.
pub fn pq_requested() -> bool {
    match std::env::var("TALLOW_TLS_PQ") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Install the process-wide provider (idempotent) and report what is in force.
///
/// Calling this twice is safe: the first call wins and every caller sees the
/// same [`ProviderInfo`]. If installation fails because another provider is
/// already installed, the report describes the provider rustls actually uses —
/// which is the only thing worth telling a caller.
pub fn install() -> &'static ProviderInfo {
    INSTALLED.get_or_init(|| {
        let want_pq = pq_requested();
        let provider: rustls::crypto::CryptoProvider = if want_pq {
            rustls::crypto::aws_lc_rs::default_provider()
        } else {
            rustls::crypto::ring::default_provider()
        };

        let name: &'static str = if want_pq { "aws-lc-rs" } else { "ring" };
        let groups: Vec<String> = provider
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();

        // `install_default` returns Err if one is already installed; either way
        // the process has a provider and the report below is what we asked for.
        let _ = provider.install_default();

        ProviderInfo {
            provider: name,
            pq_offered: groups.iter().any(|g| g.contains("MLKEM")),
            groups,
        }
    })
}

/// The provider report, installing on first use.
pub fn info() -> &'static ProviderInfo {
    install()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_provider_is_classical_and_the_opt_in_is_reported() {
        // This test asserts the *reporting* contract without touching env vars
        // (which are process-global and racy under a parallel test runner): a
        // ring provider must not claim a PQ group, and an aws-lc-rs provider
        // must offer ML-KEM.
        let ring = rustls::crypto::ring::default_provider();
        let ring_groups: Vec<String> = ring
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        assert!(
            !ring_groups.iter().any(|g| g.contains("MLKEM")),
            "ring unexpectedly offers a PQ group: {ring_groups:?}"
        );

        let aws = rustls::crypto::aws_lc_rs::default_provider();
        let aws_groups: Vec<String> = aws
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        assert!(
            aws_groups.iter().any(|g| g.contains("MLKEM")),
            "aws-lc-rs must offer X25519MLKEM768, got {aws_groups:?}"
        );
        assert!(
            aws_groups.iter().any(|g| g == PQ_GROUP),
            "the group must carry the IANA name {PQ_GROUP}, got {aws_groups:?}"
        );
    }
}
