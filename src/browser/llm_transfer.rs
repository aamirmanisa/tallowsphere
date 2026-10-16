//! Whether the schema-first tier may send page content to a **third-party
//! vendor**.
//!
//! The tier sends a sample of third-party page content and a prompt to whatever
//! engine is configured. For a loopback engine nothing leaves the box, so there
//! is nothing to authorise. For a remote engine the content leaves the box to a
//! vendor, and that transfer is exactly the kind the request plan already
//! governs through its per-request `compliance` block — so it is governed here
//! too, instead of being the one path that bypasses its own governance.
//!
//! **Fail-closed.** With no policy, a remote transfer is refused. The default is
//! not "allow because nothing said otherwise": nothing saying otherwise is the
//! condition this module exists to refuse.

/// The plan's `compliance` fields this gate reads.
///
/// Names match `schemas/tallow/request-plan-execution-contract.v1.json` and the
/// committed specimens (`pii_policy`, `requires_approval`), so a plan can be fed
/// in without translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPolicy {
    /// The plan's `pii_policy`, when a plan supplied one.
    pub pii_policy: Option<String>,
    /// The plan's `requires_approval`.
    pub requires_approval: bool,
    /// Where the policy came from, for the refusal message and the record.
    pub source: String,
}

impl TransferPolicy {
    /// No policy — nothing was supplied, so a remote transfer is refused.
    pub fn none() -> Self {
        Self {
            pii_policy: None,
            requires_approval: false,
            source: "none".to_string(),
        }
    }

    /// Build from a plan's `compliance` object.
    pub fn from_compliance(compliance: &serde_json::Value) -> Self {
        Self {
            pii_policy: compliance
                .get("pii_policy")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            requires_approval: compliance
                .get("requires_approval")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            source: "plan compliance block".to_string(),
        }
    }

    /// Build from the environment, for a run with no plan.
    ///
    /// Read explicitly rather than defaulting: an operator who wants the tier to
    /// send content to a vendor states the policy, exactly as a plan would.
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Self {
        let policy = getenv("TALLOW_LLM_PII_POLICY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let requires_approval = getenv("TALLOW_LLM_REQUIRES_APPROVAL")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
        // The source describes where the policy ACTUALLY came from. Reporting
        // "environment" when nothing was declared would be the module
        // misreporting its own provenance — the one thing a gate about
        // authorisation must not do.
        let source = if policy.is_some() || requires_approval {
            "environment (TALLOW_LLM_PII_POLICY)".to_string()
        } else {
            "none".to_string()
        };
        Self {
            pii_policy: policy,
            requires_approval,
            source,
        }
    }

    /// Does this policy permit sending an unredacted sample to a vendor?
    ///
    /// A redact-class policy is refused rather than honoured by redaction: the
    /// tier sends the sample it was given, and quietly transforming it would
    /// make the extraction's own provenance a description of something other
    /// than what was sent. Refusing keeps "what the plan said" and "what left the
    /// box" the same claim.
    pub fn permits_third_party(&self) -> Result<(), String> {
        let Some(policy) = self.pii_policy.as_deref() else {
            return Err(format!(
                "no pii_policy is declared ({}) — a remote engine would send third-party page \
                 content to a vendor, and nothing has authorised that",
                self.source
            ));
        };
        if self.requires_approval {
            return Err(format!(
                "the compliance block sets requires_approval with pii_policy={policy:?} — a \
                 third-party transfer needs that approval, and the tier cannot grant it"
            ));
        }
        if policy.to_ascii_lowercase().contains("redact") {
            return Err(format!(
                "pii_policy={policy:?} requires redaction, and the tier sends the sample it was \
                 given — refusing rather than silently sending unredacted content"
            ));
        }
        Ok(())
    }
}

/// The gate, for a transfer whose destination is or is not third-party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferDecision {
    Allow,
    Refuse(String),
}

impl TransferDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, TransferDecision::Allow)
    }
}

/// Decide whether the tier may send.
///
/// `third_party` is false when the engine is in-zone (a loopback engine): the
/// content never leaves the box, so no authorisation is required and none is
/// invented.
pub fn decide(third_party: bool, policy: &TransferPolicy) -> TransferDecision {
    if !third_party {
        return TransferDecision::Allow;
    }
    match policy.permits_third_party() {
        Ok(()) => TransferDecision::Allow,
        Err(reason) => TransferDecision::Refuse(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(pii_policy: &str, requires_approval: bool) -> TransferPolicy {
        TransferPolicy::from_compliance(&serde_json::json!({
            "source_authority": "public_web",
            "purpose": "fixture",
            "legal_basis": "legitimate_interest",
            "pii_policy": pii_policy,
            "retention_days": 1,
            "robots_mode": "strict",
            "requires_approval": requires_approval,
        }))
    }

    #[test]
    fn a_loopback_engine_needs_no_authorisation() {
        // Nothing leaves the box, so there is nothing to authorise — and the gate
        // must not invent a requirement that would disable the offline path.
        assert!(decide(false, &TransferPolicy::none()).is_allowed());
    }

    #[test]
    fn a_third_party_transfer_with_no_policy_is_refused() {
        match decide(true, &TransferPolicy::none()) {
            TransferDecision::Refuse(reason) => {
                assert!(reason.contains("no pii_policy"), "{reason}");
            }
            d => panic!("expected a refusal, got {d:?}"),
        }
    }

    #[test]
    fn a_redact_class_policy_is_refused_not_silently_obeyed() {
        for policy in ["redact", "pii_redact_before_transfer", "REDACT"] {
            let d = decide(true, &plan(policy, false));
            assert!(
                !d.is_allowed(),
                "{policy} must not permit an unredacted send: {d:?}"
            );
        }
    }

    #[test]
    fn requires_approval_refuses_even_with_a_permitting_policy() {
        let d = decide(true, &plan("no_pii_expected", true));
        match d {
            TransferDecision::Refuse(reason) => assert!(reason.contains("approval"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_declared_no_pii_policy_permits_the_transfer() {
        assert!(decide(true, &plan("no_pii_expected", false)).is_allowed());
    }

    #[test]
    fn the_env_path_declares_its_own_source() {
        let none = |_: &str| None;
        let p = TransferPolicy::from_env(&none);
        assert_eq!(p.pii_policy, None);
        assert_eq!(p.source, "none");

        let env = |k: &str| match k {
            "TALLOW_LLM_PII_POLICY" => Some("no_pii_expected".to_string()),
            _ => None,
        };
        let p = TransferPolicy::from_env(&env);
        assert_eq!(p.pii_policy.as_deref(), Some("no_pii_expected"));
        assert!(p.source.contains("TALLOW_LLM_PII_POLICY"), "{}", p.source);
        assert!(decide(true, &p).is_allowed());
    }

    #[test]
    fn the_specimens_block_parses_as_the_gate_expects() {
        // The shape taken verbatim from examples/request_plan_get_only.
        let block = serde_json::json!({
            "source_authority": "local_fixture_public_web",
            "purpose": "release_example_request_plan_get_only",
            "legal_basis": "legitimate_interest",
            "pii_policy": "no_pii_expected",
            "retention_days": 1,
            "robots_mode": "strict",
            "requires_approval": false
        });
        let p = TransferPolicy::from_compliance(&block);
        assert_eq!(p.pii_policy.as_deref(), Some("no_pii_expected"));
        assert!(!p.requires_approval);
        assert!(decide(true, &p).is_allowed());
    }
}
