//! KEM capability negotiation
//!
//! Plain preference negotiation between peer [`KemCapabilities`], plus the
//! P10-R01 / P4-6 downgrade guard: when the negotiated group is not the
//! expected hybrid (ML-KEM + X25519), the exchange either fails closed
//! ([`DowngradePolicy::Strict`]) or proceeds carrying a loud, structured
//! [`DowngradeAlarm`] ([`DowngradePolicy::Alarm`]). There is no silent
//! classical-only fallback lane.

use super::KemAlgorithm;
use serde::{Deserialize, Serialize};
use std::fmt;

/// KEM capabilities for negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemCapabilities {
    /// Supported algorithms in preference order
    pub supported: Vec<KemAlgorithm>,
}

impl KemCapabilities {
    /// Create capabilities with all algorithms supported
    pub fn all() -> Self {
        Self {
            supported: vec![
                KemAlgorithm::Hybrid,
                KemAlgorithm::MlKem1024,
                KemAlgorithm::X25519,
            ],
        }
    }

    /// Create capabilities with only post-quantum algorithms
    pub fn pq_only() -> Self {
        Self {
            supported: vec![KemAlgorithm::MlKem1024],
        }
    }

    /// Create capabilities with only classical algorithms
    pub fn classical_only() -> Self {
        Self {
            supported: vec![KemAlgorithm::X25519],
        }
    }

    /// Check if an algorithm is supported
    pub fn supports(&self, algorithm: KemAlgorithm) -> bool {
        self.supported.contains(&algorithm)
    }
}

impl Default for KemCapabilities {
    fn default() -> Self {
        Self::all()
    }
}

/// Negotiate a KEM algorithm between two peers
///
/// # Arguments
///
/// * `ours` - Our KEM capabilities
/// * `theirs` - Their KEM capabilities
///
/// # Returns
///
/// The first mutually supported algorithm, or None if no match
pub fn negotiate(ours: &KemCapabilities, theirs: &KemCapabilities) -> Option<KemAlgorithm> {
    for algorithm in &ours.supported {
        if theirs.supports(*algorithm) {
            return Some(*algorithm);
        }
    }
    None
}

/// How the handshake reacts when the negotiated group deviates from the
/// P10-R01 expectation (hybrid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DowngradePolicy {
    /// Fail closed: [`negotiate_with_downgrade_guard`] returns `Err(alarm)`.
    /// Use on transports where "PQ in transit" is a claimed property.
    Strict,
    /// Proceed, but hand the caller a loud [`DowngradeAlarm`] that must be
    /// surfaced (logs / `doctor` / transfer metadata). Never ignore it.
    Alarm,
}

/// A loud, structured PQ-downgrade alarm (P10-R01 / P4-6).
///
/// `Display` renders the canonical, greppable one-line alarm
/// (`PQ-DOWNGRADE ALARM: ...`). Callers in [`DowngradePolicy::Alarm`] mode
/// must surface this line (log at error level, include it in `doctor` output)
/// — the type is `Serialize` so it can travel in handshake/transfer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DowngradeAlarm {
    /// The group required by the P10-R01 policy (always `Hybrid`).
    pub expected: KemAlgorithm,
    /// The group actually negotiated; `None` = no mutually supported group.
    pub negotiated: Option<KemAlgorithm>,
    /// `true` when the PQ leg is absent (classical-only fallback — HNDL exposure).
    pub pq_leg_missing: bool,
}

impl fmt::Display for DowngradeAlarm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negotiated = match self.negotiated {
            Some(a) => format!("{a:?}"),
            None => "none".to_string(),
        };
        let leg = if self.pq_leg_missing {
            "PQ leg missing (classical-only fallback, HNDL exposure)"
        } else {
            "hybrid not selected"
        };
        write!(
            f,
            "PQ-DOWNGRADE ALARM: negotiated group {negotiated}, expected {:?} — {leg}",
            self.expected
        )
    }
}

impl std::error::Error for DowngradeAlarm {}

/// Outcome of a guarded negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationOutcome {
    /// The negotiated group.
    pub algorithm: KemAlgorithm,
    /// Present iff the negotiated group deviates from the expected hybrid.
    pub alarm: Option<DowngradeAlarm>,
}

/// Negotiate with the P10-R01 downgrade guard.
///
/// The expected group is [`KemAlgorithm::Hybrid`]: whenever both peers can do
/// it, it is selected (`KemCapabilities::all()` orders it first), and a
/// session that does not carry it is a deviation.
///
/// Semantics:
/// - negotiated == Hybrid → `Ok`, `alarm: None` (both legs present);
/// - negotiated == anything else → alarm: `Strict` returns `Err(alarm)`
///   (fail closed — the exchange must not proceed); `Alarm` returns `Ok`
///   with `alarm: Some(..)` for the caller to surface loudly;
/// - no mutually supported group → `Err(alarm)` with `negotiated: None` in
///   every policy (there is nothing to proceed with).
pub fn negotiate_with_downgrade_guard(
    ours: &KemCapabilities,
    theirs: &KemCapabilities,
    policy: DowngradePolicy,
) -> std::result::Result<NegotiationOutcome, DowngradeAlarm> {
    let negotiated = negotiate(ours, theirs);
    let expected = KemAlgorithm::Hybrid;

    match negotiated {
        Some(KemAlgorithm::Hybrid) => Ok(NegotiationOutcome {
            algorithm: KemAlgorithm::Hybrid,
            alarm: None,
        }),
        Some(other) => {
            let alarm = DowngradeAlarm {
                expected,
                negotiated: Some(other),
                pq_leg_missing: other == KemAlgorithm::X25519,
            };
            match policy {
                DowngradePolicy::Strict => Err(alarm),
                DowngradePolicy::Alarm => Ok(NegotiationOutcome {
                    algorithm: other,
                    alarm: Some(alarm),
                }),
            }
        }
        None => Err(DowngradeAlarm {
            expected,
            negotiated: None,
            pq_leg_missing: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::hybrid::{self, HybridKem};
    use crate::kem::{mlkem, x25519};

    #[test]
    fn test_negotiate_hybrid() {
        let ours = KemCapabilities::all();
        let theirs = KemCapabilities::all();

        let result = negotiate(&ours, &theirs);
        assert_eq!(result, Some(KemAlgorithm::Hybrid));
    }

    #[test]
    fn test_negotiate_pq_only() {
        let ours = KemCapabilities::pq_only();
        let theirs = KemCapabilities::all();

        let result = negotiate(&ours, &theirs);
        assert_eq!(result, Some(KemAlgorithm::MlKem1024));
    }

    #[test]
    fn test_negotiate_no_match() {
        let ours = KemCapabilities::pq_only();
        let theirs = KemCapabilities::classical_only();

        let result = negotiate(&ours, &theirs);
        assert_eq!(result, None);
    }

    #[test]
    fn test_supports() {
        let caps = KemCapabilities::all();
        assert!(caps.supports(KemAlgorithm::Hybrid));
        assert!(caps.supports(KemAlgorithm::MlKem1024));
        assert!(caps.supports(KemAlgorithm::X25519));

        let pq_caps = KemCapabilities::pq_only();
        assert!(!pq_caps.supports(KemAlgorithm::X25519));
    }

    /// Negotiated-group test (P10-R01 / P4-6): both peers offer the hybrid
    /// group → hybrid must win over available classical-only fallback, and
    /// neither leg may be decorative — tampering either leg must change (or
    /// extinguish) the derived secret.
    #[test]
    fn test_negotiated_group_is_hybrid_and_both_legs_contribute() {
        // 1. Negotiation: hybrid wins even though classical X25519 is available.
        let ours = KemCapabilities::all();
        let theirs = KemCapabilities::all();
        assert_eq!(
            negotiate(&ours, &theirs),
            Some(KemAlgorithm::Hybrid),
            "hybrid group must win when both peers support it (no silent classical-only fallback)"
        );

        // 2. KEX with the negotiated hybrid group: both sides agree on the secret.
        let (pk, sk) = HybridKem::keygen().expect("hybrid keygen");
        let (ct, ss_sender) = HybridKem::encapsulate(&pk).expect("hybrid encaps");
        let ss_receiver = HybridKem::decapsulate(&sk, &ct).expect("hybrid decaps");
        assert_eq!(
            ss_sender.expose_secret(),
            ss_receiver.expose_secret(),
            "hybrid roundtrip must agree"
        );

        // 3. Both legs structurally present in the ciphertext.
        assert_eq!(
            ct.mlkem.as_bytes().len(),
            mlkem::CT_LEN,
            "ML-KEM leg must be a full FIPS 203 ciphertext"
        );
        assert_eq!(
            ct.x25519_public.as_bytes().len(),
            32,
            "X25519 leg must be present"
        );

        // 4. Tamper the ML-KEM leg → the combined secret must change (or
        //    decaps must fail). If it did not, the PQ leg would be decorative.
        let mut mlkem_bytes = ct.mlkem.as_bytes().to_vec();
        mlkem_bytes[0] ^= 0x01;
        let tampered_mlkem_ct = hybrid::Ciphertext {
            mlkem: mlkem::Ciphertext::from_bytes(mlkem_bytes).expect("1568-byte ct"),
            x25519_public: ct.x25519_public,
        };
        let pq_leg_differs = match HybridKem::decapsulate(&sk, &tampered_mlkem_ct) {
            Ok(ss) => ss.expose_secret() != ss_sender.expose_secret(),
            Err(_) => true,
        };
        assert!(
            pq_leg_differs,
            "tampering the ML-KEM ciphertext must change/extinguish the hybrid secret — PQ leg is not contributing"
        );

        // 5. Tamper the classical leg → the combined secret must change. If it
        //    did not, the X25519 leg would be decorative (PQ-only, not hybrid).
        let fresh = x25519::X25519KeyPair::generate();
        let tampered_classical_ct = hybrid::Ciphertext {
            mlkem: ct.mlkem.clone(),
            x25519_public: *fresh.public_key(),
        };
        let classical_leg_differs = match HybridKem::decapsulate(&sk, &tampered_classical_ct) {
            Ok(ss) => ss.expose_secret() != ss_sender.expose_secret(),
            Err(_) => true,
        };
        assert!(
            classical_leg_differs,
            "tampering the X25519 leg must change the hybrid secret — classical leg is not contributing"
        );
    }

    #[test]
    fn test_strict_refuses_classical_only_fallback() {
        let ours = KemCapabilities::all();
        let theirs = KemCapabilities::classical_only();

        let err = negotiate_with_downgrade_guard(&ours, &theirs, DowngradePolicy::Strict)
            .expect_err("strict mode must fail closed on a classical-only negotiated group");
        assert_eq!(err.expected, KemAlgorithm::Hybrid);
        assert_eq!(err.negotiated, Some(KemAlgorithm::X25519));
        assert!(
            err.pq_leg_missing,
            "classical-only fallback must be flagged as PQ-leg-missing"
        );
        assert!(
            err.to_string().starts_with("PQ-DOWNGRADE ALARM:"),
            "alarm must be loud and greppable: {err}"
        );
    }

    #[test]
    fn test_alarm_path_reports_classical_only_fallback() {
        let ours = KemCapabilities::all();
        let theirs = KemCapabilities::classical_only();

        let outcome = negotiate_with_downgrade_guard(&ours, &theirs, DowngradePolicy::Alarm)
            .expect("alarm mode proceeds");
        assert_eq!(outcome.algorithm, KemAlgorithm::X25519);
        let alarm = outcome
            .alarm
            .expect("alarm must be attached on the downgrade path");
        assert_eq!(alarm.negotiated, Some(KemAlgorithm::X25519));
        assert!(alarm.pq_leg_missing);
        assert!(alarm.to_string().contains("PQ-DOWNGRADE ALARM"));
    }

    #[test]
    fn test_no_alarm_when_hybrid_negotiated() {
        let ours = KemCapabilities::all();
        let theirs = KemCapabilities::all();

        let outcome = negotiate_with_downgrade_guard(&ours, &theirs, DowngradePolicy::Strict)
            .expect("hybrid negotiated, strict mode may proceed");
        assert_eq!(outcome.algorithm, KemAlgorithm::Hybrid);
        assert!(outcome.alarm.is_none());
    }

    #[test]
    fn test_deviation_without_pq_leg_missing_still_alarms() {
        // Peer only does ML-KEM (no classical leg): still not the expected
        // hybrid group, so the deviation is surfaced; the PQ leg itself is present.
        let ours = KemCapabilities::all();
        let theirs = KemCapabilities::pq_only();

        let err = negotiate_with_downgrade_guard(&ours, &theirs, DowngradePolicy::Strict)
            .expect_err("strict mode must refuse a non-hybrid group");
        assert_eq!(err.negotiated, Some(KemAlgorithm::MlKem1024));
        assert!(!err.pq_leg_missing);
    }

    #[test]
    fn test_no_mutual_group_is_hard_error() {
        let ours = KemCapabilities::pq_only();
        let theirs = KemCapabilities::classical_only();

        for policy in [DowngradePolicy::Strict, DowngradePolicy::Alarm] {
            let err = negotiate_with_downgrade_guard(&ours, &theirs, policy)
                .expect_err("no mutually supported group must never proceed");
            assert_eq!(err.negotiated, None);
        }
    }
}
