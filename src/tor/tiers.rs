//! Egress tiering (P1 W1-E3) — target-class → egress-class mapping.
//!
//! The 5-layer design maps a *target class* to an *egress class*; this module
//! is the **design + gate stub**, not a provisioning layer:
//!
//! | target class | requested egress | state                       |
//! |--------------|------------------|-----------------------------|
//! | `Public`     | `PublicTor`      | live (the box default)      |
//! | `Sensitive`  | `Bridge`         | operator-gated — not provisioned in R0 |
//! | `Hostile`    | `Commercial`     | operator-gated — budget/contract decision |
//!
//! **Operator gate:** `Bridge` and `Commercial` are *requested* classes only.
//! [`effective_egress_class`] returns `PublicTor` for them unless the matching
//! approval is recorded in an [`OperatorGate`] — so a run can never silently
//! start spending commercial egress or dial a bridge transport that was never
//! provisioned. Both approvals default to `false` (R0: local-only, no spend).
//!
//! See `docs/operations/egress-tiers.md` for the operator decision notes and
//! the "one task = one exit" hygiene rule (W1-E4).

use serde::{Deserialize, Serialize};

/// What kind of target a task is aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetClass {
    /// Public-friendly surfaces: our own pages, demo targets, co-op corpora.
    Public,
    /// Targets where attribution risk needs a non-public transport.
    Sensitive,
    /// Adversarial targets (fraud/infra investigation under legal process).
    Hostile,
}

/// How a run's traffic leaves the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EgressClass {
    /// The public Tor network (the fail-closed default).
    PublicTor,
    /// A private bridge transport (obfs4/webtunnel) — operator-gated.
    Bridge,
    /// Commercial residential/mobile egress — operator-gated, budget-bound.
    Commercial,
}

impl EgressClass {
    /// Stable wire/log name.
    pub fn as_str(&self) -> &'static str {
        match self {
            EgressClass::PublicTor => "public-tor",
            EgressClass::Bridge => "bridge",
            EgressClass::Commercial => "commercial",
        }
    }
}

/// The mapping's *requested* class, before the operator gate.
pub fn requested_egress_class(target: TargetClass) -> EgressClass {
    match target {
        TargetClass::Public => EgressClass::PublicTor,
        TargetClass::Sensitive => EgressClass::Bridge,
        TargetClass::Hostile => EgressClass::Commercial,
    }
}

/// Recorded operator approvals. Defaults are all-`false` (R0).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorGate {
    /// Bridges provisioned + approved for use (infra operator).
    pub bridges_approved: bool,
    /// Commercial egress spend approved (budget holder).
    pub commercial_budget_approved: bool,
}

/// Resolve the *effective* egress class for a target under the operator gate.
///
/// Returns the class to use plus, when the requested class was downgraded, a
/// reason string suitable for evidence (the downgrade must be visible, never
/// silent).
pub fn effective_egress_class(
    target: TargetClass,
    gate: &OperatorGate,
) -> (EgressClass, Option<&'static str>) {
    match requested_egress_class(target) {
        EgressClass::PublicTor => (EgressClass::PublicTor, None),
        EgressClass::Bridge if gate.bridges_approved => (EgressClass::Bridge, None),
        EgressClass::Bridge => (
            EgressClass::PublicTor,
            Some("bridge egress requested but not approved (operator gate) — using public-tor"),
        ),
        EgressClass::Commercial if gate.commercial_budget_approved => {
            (EgressClass::Commercial, None)
        }
        EgressClass::Commercial => (
            EgressClass::PublicTor,
            Some("commercial egress requested but budget not approved (operator gate) — using public-tor"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gate_keeps_everything_on_public_tor() {
        let gate = OperatorGate::default();
        for target in [TargetClass::Public, TargetClass::Sensitive, TargetClass::Hostile] {
            let (class, reason) = effective_egress_class(target, &gate);
            assert_eq!(class, EgressClass::PublicTor, "{target:?} must default to public-tor");
            if target != TargetClass::Public {
                assert!(
                    reason.is_some(),
                    "{target:?} downgrade must be visible in evidence"
                );
            }
        }
    }

    #[test]
    fn approvals_enable_the_requested_class() {
        let gate = OperatorGate {
            bridges_approved: true,
            commercial_budget_approved: true,
        };
        assert_eq!(
            effective_egress_class(TargetClass::Sensitive, &gate).0,
            EgressClass::Bridge
        );
        assert_eq!(
            effective_egress_class(TargetClass::Hostile, &gate).0,
            EgressClass::Commercial
        );
        // Public stays public even with approvals.
        assert_eq!(
            effective_egress_class(TargetClass::Public, &gate).0,
            EgressClass::PublicTor
        );
    }

    #[test]
    fn gates_are_independent() {
        let bridge_only = OperatorGate {
            bridges_approved: true,
            commercial_budget_approved: false,
        };
        assert_eq!(
            effective_egress_class(TargetClass::Sensitive, &bridge_only).0,
            EgressClass::Bridge
        );
        assert_eq!(
            effective_egress_class(TargetClass::Hostile, &bridge_only).0,
            EgressClass::PublicTor,
            "commercial must still be gated off"
        );
    }
}
