//! Op-class gate — irreversible-op blocking, reviewer override, and declined
//! telemetry (tasks A7.1.2 + A7.1.3); confirm/decline verdict recording goes
//! through the telemetry choke point (R-6.9, [`crate::observability`]).
//!
//! [`crate::degraded_gate`] answers *"is the run degraded?"* — it classifies
//! attempt outcomes into [`DegradedReason`]s (failure streak, retry spiral,
//! error storm, anomalous tool feedback). This module answers the follow-up:
//! *"given those reasons, may THIS operation proceed?"* — and records what was
//! turned away at the gate.
//!
//! * [`OpClass`] names the operation class; [`OpClass::is_irreversible`] marks
//!   the classes whose blast radius cannot be undone (`Publish`, `Delete`,
//!   `CredentialChange`).
//! * [`decide`] applies the gate policy, producing a [`GateDecision`].
//! * [`ReviewerConfirmation`] is the explicit human override — a degraded
//!   irreversible op may proceed *only* with a valid confirmation attached.
//! * [`record_declined`] / [`summary`] are the A7.1.3 telemetry: what got
//!   blocked, per op class, deterministically summarized.
//! * [`decide_and_record`] / [`emit_verdict`] record the confirm/decline
//!   verdict on the telemetry choke point as an
//!   [`EventClass::PolicyVerdict`] event — best-effort, never blocking the
//!   decision (R-6.9).
//!
//! # Decision rules (precedence, top to bottom — first match wins)
//!
//! ```text
//! 1. reasons empty                        → Allowed { Healthy }
//! 2. reasons present + op reversible      → Allowed { LowRiskOnly }
//! 3. reasons present + op irreversible
//!     3a. confirmation present + valid    → Allowed { ReviewerOverride }
//!     3b. no confirmation / invalid       → Blocked { reasons }
//! ```
//!
//! Consequences of the precedence, documented deliberately:
//! * A confirmation is **irrelevant when healthy** (rule 1 wins): an
//!   unconditional op does not need a reviewer, so `decide` reports `Healthy`.
//! * A confirmation is **irrelevant for low-risk ops** (rule 2 wins): the
//!   gate never demands a reviewer for work that is safe to retry.
//! * "Invalid" means [`ReviewerConfirmation::is_valid`] is false — the
//!   `reviewer` field is empty after trimming. An invalid confirmation is
//!   treated exactly like no confirmation: the op stays blocked.
//!
//! # Purity contract
//! [`decide`], [`record_declined`], [`summary`], and [`verdict_event`] are
//! pure and deterministic: no clock, no IO, no randomness, and they never
//! panic. `at_ms` values are caller-supplied wall-clock milliseconds for
//! audit. Recording ([`emit_verdict`], [`decide_and_record`]) is the module's
//! only IO, kept at the edge and best-effort.
//!
//! # Wiring
//! No external call site is wired here yet; the parent integrates (A7.1.2/
//! A7.1.3). The intended pipeline, with verdict recording folded in (R-6.9):
//!
//! ```text
//! let reasons = degraded_gate::detect(&attempts, &Thresholds::default());
//! let decision = ops_gate::decide_and_record(OpClass::Publish, &reasons, confirmation.as_ref(), now_ms);
//! if let Some(event) = ops_gate::record_declined(&decision, OpClass::Publish, &reasons, now_ms) {
//!     // append to the declined log; summarize with ops_gate::summary(&events)
//! }
//! ```
//!
//! [`decide_and_record`] = [`decide`] + best-effort [`emit_verdict_to_journal`]:
//! the confirm/decline verdict lands on the security-events journal as a
//! `policy_verdict` record. The decision is computed first and returned
//! unchanged regardless of emission; embedders that own a sink use
//! [`decide_and_record_to`] / [`emit_verdict`].

use serde::{Deserialize, Serialize};

use crate::degraded_gate::DegradedReason;
use crate::observability::{
    self, EmitError, EventClass, RedactedSecurityEvent, SecurityEvent, SecurityEventSink,
};

// ── OpClass ─────────────────────────────────────────────────────────────────

/// The class of an operation the agent loop wants to perform.
///
/// Irreversibility is a property of the *class*, not of intent: an op whose
/// effect cannot be walked back from inside the loop must pass the degraded
/// gate even when the loop feels fine (see [`OpClass::is_irreversible`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpClass {
    /// Reconnaissance: probing, scanning, enumerating — observes the outside
    /// world, changes nothing. Reversible (always allowed by the gate).
    Recon,
    /// Read: fetching/reading data and state. Changes nothing. Reversible.
    Read,
    /// Publish: sending/posting/spending outward — once out, it cannot be
    /// recalled. Irreversible.
    Publish,
    /// Delete: destroying data or state — deletion has no inverse without a
    /// backup. Irreversible.
    Delete,
    /// CredentialChange: rotating/issuing/revoking credentials — can lock the
    /// operator out and invalidates audit trails keyed to the old secret.
    /// Irreversible.
    CredentialChange,
}

impl OpClass {
    /// All classes in canonical order (declaration order — also the count
    /// order used by [`summary`]).
    pub const ALL: [OpClass; 5] = [
        OpClass::Recon,
        OpClass::Read,
        OpClass::Publish,
        OpClass::Delete,
        OpClass::CredentialChange,
    ];

    /// Canonical lowercase class name (also the wire form).
    pub fn as_str(&self) -> &'static str {
        match self {
            OpClass::Recon => "recon",
            OpClass::Read => "read",
            OpClass::Publish => "publish",
            OpClass::Delete => "delete",
            OpClass::CredentialChange => "credential_change",
        }
    }

    /// Whether an operation of this class is irreversible — i.e. the loop
    /// cannot undo it after the fact.
    ///
    /// `true` for [`Publish`](OpClass::Publish), [`Delete`](OpClass::Delete),
    /// and [`CredentialChange`](OpClass::CredentialChange): output that has
    /// left, data that is gone, and authentication state that has moved are
    /// each unrecoverable from inside the run. `false` for
    /// [`Recon`](OpClass::Recon) and [`Read`](OpClass::Read): observation
    /// leaves no state change behind.
    pub fn is_irreversible(&self) -> bool {
        matches!(
            self,
            OpClass::Publish | OpClass::Delete | OpClass::CredentialChange
        )
    }
}

impl std::fmt::Display for OpClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ReviewerConfirmation ────────────────────────────────────────────────────

/// Explicit human reviewer confirmation — the only way a degraded,
/// irreversible op may proceed.
///
/// Validity is deliberately cheap and mechanical:
/// [`ReviewerConfirmation::is_valid`] requires a non-empty **trimmed**
/// `reviewer` name. `at_ms` and `note` are audit fields (who allowed it, when,
/// and why) and are not gated on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerConfirmation {
    /// Who reviewed — must be non-empty after trimming to be valid.
    pub reviewer: String,
    /// When the confirmation was given (caller's clock, ms).
    pub at_ms: i64,
    /// Free-form note (context, ticket, rationale).
    pub note: String,
}

impl ReviewerConfirmation {
    /// Convenience constructor; does not validate (see [`Self::is_valid`]).
    pub fn new(reviewer: impl Into<String>, at_ms: i64, note: impl Into<String>) -> Self {
        Self { reviewer: reviewer.into(), at_ms, note: note.into() }
    }

    /// A confirmation is valid iff `reviewer` is non-empty after trimming
    /// whitespace. An empty (or whitespace-only) reviewer is treated as no
    /// confirmation at all by [`decide`].
    pub fn is_valid(&self) -> bool {
        !self.reviewer.trim().is_empty()
    }
}

// ── AllowReason / GateDecision ──────────────────────────────────────────────

/// Why the gate allowed an op (echoed for observability and audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowReason {
    /// No degraded reasons: the run is healthy.
    Healthy,
    /// Degraded, but the op class is reversible — low-risk work only.
    LowRiskOnly,
    /// Degraded and irreversible, but a valid reviewer confirmation allowed it.
    ReviewerOverride,
}

impl AllowReason {
    /// Canonical lowercase reason name (also the wire form).
    pub fn as_str(&self) -> &'static str {
        match self {
            AllowReason::Healthy => "healthy",
            AllowReason::LowRiskOnly => "low_risk_only",
            AllowReason::ReviewerOverride => "reviewer_override",
        }
    }
}

impl std::fmt::Display for AllowReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The gate's verdict for one operation. See the module docs for the exact
/// precedence rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// The operation may proceed; `reason` records why.
    Allowed { reason: AllowReason },
    /// The operation must not proceed; `reasons` is the degraded state that
    /// blocked it (echoed verbatim, in the order supplied).
    Blocked { reasons: Vec<DegradedReason> },
}

impl GateDecision {
    /// Whether this decision is an `Allowed`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateDecision::Allowed { .. })
    }

    /// Whether this decision is a `Blocked`.
    pub fn is_blocked(&self) -> bool {
        matches!(self, GateDecision::Blocked { .. })
    }

    /// The allow reason, if allowed.
    pub fn allow_reason(&self) -> Option<AllowReason> {
        match self {
            GateDecision::Allowed { reason } => Some(*reason),
            GateDecision::Blocked { .. } => None,
        }
    }

    /// The blocking reasons, if blocked.
    pub fn block_reasons(&self) -> Option<&[DegradedReason]> {
        match self {
            GateDecision::Allowed { .. } => None,
            GateDecision::Blocked { reasons } => Some(reasons),
        }
    }
}

// ── decide ──────────────────────────────────────────────────────────────────

/// Pure gate policy: decide whether `op` may proceed given the degraded
/// `reasons` and an optional reviewer `confirmation`.
///
/// Rules (precedence documented in the module docs, first match wins):
/// 1. no reasons → `Allowed { Healthy }` (confirmation ignored);
/// 2. reasons + reversible op → `Allowed { LowRiskOnly }`;
/// 3. reasons + irreversible op → `Allowed { ReviewerOverride }` with a valid
///    confirmation, else `Blocked { reasons }` (invalid treated as absent).
///
/// Never panics. Deterministic for identical input.
pub fn decide(
    op: OpClass,
    reasons: &[DegradedReason],
    confirmation: Option<&ReviewerConfirmation>,
) -> GateDecision {
    if reasons.is_empty() {
        return GateDecision::Allowed { reason: AllowReason::Healthy };
    }
    if !op.is_irreversible() {
        return GateDecision::Allowed { reason: AllowReason::LowRiskOnly };
    }
    match confirmation {
        Some(c) if c.is_valid() => GateDecision::Allowed { reason: AllowReason::ReviewerOverride },
        _ => GateDecision::Blocked { reasons: reasons.to_vec() },
    }
}

// ── Declined telemetry (A7.1.3) ─────────────────────────────────────────────

/// One recorded decline at the gate — the audit shape for A7.1.3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeclinedAtGate {
    /// The op class that was turned away.
    pub op: OpClass,
    /// The degraded reasons that caused the block.
    pub reasons: Vec<DegradedReason>,
    /// When the decline was recorded (caller's clock, ms).
    pub at_ms: i64,
}

/// Turn a [`GateDecision`] into a decline record — `Some` only when the
/// decision is [`GateDecision::Blocked`], `None` for any `Allowed`.
///
/// The recorded `reasons` are the caller-supplied slice, verbatim: pass the
/// same slice you handed to [`decide`] so the record mirrors the blocking
/// decision. Purely a projection — no clock, no IO, never panics.
pub fn record_declined(
    decision: &GateDecision,
    op: OpClass,
    reasons: &[DegradedReason],
    at_ms: i64,
) -> Option<DeclinedAtGate> {
    match decision {
        GateDecision::Blocked { .. } => {
            Some(DeclinedAtGate { op, reasons: reasons.to_vec(), at_ms })
        }
        GateDecision::Allowed { .. } => None,
    }
}

/// Deterministic one-line summary of decline counts, per op class.
///
/// Format: `declined-at-gate: <op>=<count>[, <op>=<count>]*` with ops in
/// canonical [`OpClass::ALL`] order and zero-count classes omitted. Empty
/// input → `declined-at-gate: none`. Input order does not affect the output.
pub fn summary(events: &[DeclinedAtGate]) -> String {
    if events.is_empty() {
        return "declined-at-gate: none".to_string();
    }
    let parts: Vec<String> = OpClass::ALL
        .iter()
        .filter_map(|op| {
            let n = events.iter().filter(|e| e.op == *op).count();
            (n > 0).then(|| format!("{}={}", op.as_str(), n))
        })
        .collect();
    format!("declined-at-gate: {}", parts.join(", "))
}

// ── Verdict recording via the telemetry choke point (R-6.9) ────────────────

/// Actor name recorded for every gate verdict — hashed by the choke point
/// before any sink sees it (the literal never reaches the journal).
const VERDICT_ACTOR: &str = "ops_gate";

/// Build the telemetry event for a confirm/decline verdict — `None` when
/// there is nothing to record.
///
/// The recorded verdicts (R-6.9):
/// * **confirm** — `Allowed { ReviewerOverride }`: a reviewer explicitly
///   confirmed a degraded irreversible op;
/// * **decline** — `Blocked`: the op was turned away at the gate.
///
/// `Allowed { Healthy }` and `Allowed { LowRiskOnly }` carry no
/// confirm/decline and produce `None`. The event carries only the verdict
/// and the op class (`"confirm:delete"` / `"decline:delete"` as the
/// [`SecurityEvent::target`]); the reviewer name and the degraded reasons
/// are deliberately not recorded. Purely a projection — no clock, no IO,
/// never panics.
pub fn verdict_event(decision: &GateDecision, op: OpClass, at_ms: i64) -> Option<SecurityEvent> {
    let token = match decision {
        GateDecision::Allowed { reason: AllowReason::ReviewerOverride } => "confirm",
        GateDecision::Blocked { .. } => "decline",
        GateDecision::Allowed { reason: AllowReason::Healthy | AllowReason::LowRiskOnly } => {
            return None;
        }
    };
    Some(SecurityEvent {
        class: EventClass::PolicyVerdict,
        actor: VERDICT_ACTOR.to_string(),
        target: Some(format!("{token}:{op}")),
        size: 0,
        at_ms,
    })
}

/// Record a gate verdict on `sink` through the telemetry choke point
/// ([`crate::observability::emit_security_event`]).
///
/// * `Ok(Some(record))` — a confirm/decline verdict was minimized and
///   recorded; `record` is what the sink received.
/// * `Ok(None)` — the decision is `Allowed { Healthy | LowRiskOnly }`:
///   nothing to record.
/// * `Err` — the choke point refused the event or the sink failed
///   (marker-record semantics per [`crate::observability`]). Recording is
///   best-effort: the decision never depends on it, and live call sites
///   drop the result (`let _ =`).
pub fn emit_verdict(
    sink: &mut dyn SecurityEventSink,
    decision: &GateDecision,
    op: OpClass,
    at_ms: i64,
) -> Result<Option<RedactedSecurityEvent>, EmitError> {
    match verdict_event(decision, op, at_ms) {
        Some(ev) => observability::emit_security_event(sink, &ev).map(Some),
        None => Ok(None),
    }
}

/// [`emit_verdict`] to the default security-events journal — the live
/// call-site convenience, best-effort like
/// [`crate::observability::emit_to_default_journal`].
pub fn emit_verdict_to_journal(
    decision: &GateDecision,
    op: OpClass,
    at_ms: i64,
) -> Result<Option<RedactedSecurityEvent>, EmitError> {
    match verdict_event(decision, op, at_ms) {
        Some(ev) => observability::emit_to_default_journal(&ev).map(Some),
        None => Ok(None),
    }
}

/// [`decide`] + best-effort verdict recording — the library-level entry
/// point (R-6.9): the decision is computed first, then its confirm/decline
/// verdict is recorded on the telemetry choke point
/// ([`emit_verdict_to_journal`]). Emission failures are dropped (`let _ =`)
/// and can never change the returned decision.
pub fn decide_and_record(
    op: OpClass,
    reasons: &[DegradedReason],
    confirmation: Option<&ReviewerConfirmation>,
    at_ms: i64,
) -> GateDecision {
    let decision = decide(op, reasons, confirmation);
    let _ = emit_verdict_to_journal(&decision, op, at_ms);
    decision
}

/// [`decide_and_record`] with a caller-owned sink — for embedders and tests
/// ([`crate::observability::MemorySink`]); same best-effort contract.
pub fn decide_and_record_to(
    sink: &mut dyn SecurityEventSink,
    op: OpClass,
    reasons: &[DegradedReason],
    confirmation: Option<&ReviewerConfirmation>,
    at_ms: i64,
) -> GateDecision {
    let decision = decide(op, reasons, confirmation);
    let _ = emit_verdict(sink, &decision, op, at_ms);
    decision
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn spiral() -> DegradedReason {
        DegradedReason::RetrySpiral { op: "publish.run".to_string(), len: 5 }
    }

    fn storm() -> DegradedReason {
        DegradedReason::ErrorStorm { rate: 0.75 }
    }

    fn degraded() -> Vec<DegradedReason> {
        vec![DegradedReason::FailureStreak { len: 5 }, spiral(), storm()]
    }

    fn conf(reviewer: &str) -> ReviewerConfirmation {
        ReviewerConfirmation::new(reviewer, 1_700_000_000_000, "manual review complete")
    }

    // ── OpClass ─────────────────────────────────────────────────────────────

    #[test]
    fn is_irreversible_truth_table() {
        assert!(!OpClass::Recon.is_irreversible(), "recon observes, never mutates");
        assert!(!OpClass::Read.is_irreversible(), "read observes, never mutates");
        assert!(OpClass::Publish.is_irreversible(), "published output cannot be recalled");
        assert!(OpClass::Delete.is_irreversible(), "deletion has no inverse without a backup");
        assert!(
            OpClass::CredentialChange.is_irreversible(),
            "a rotated credential cannot be un-rotated without an operator"
        );
    }

    #[test]
    fn op_class_names_and_display_match_wire_form() {
        assert_eq!(OpClass::Recon.as_str(), "recon");
        assert_eq!(OpClass::Read.as_str(), "read");
        assert_eq!(OpClass::Publish.as_str(), "publish");
        assert_eq!(OpClass::Delete.as_str(), "delete");
        assert_eq!(OpClass::CredentialChange.as_str(), "credential_change");
        for op in OpClass::ALL {
            assert_eq!(op.to_string(), op.as_str(), "Display mirrors as_str");
            let wire = serde_json::to_string(&op).unwrap();
            assert_eq!(wire.trim_matches('"'), op.as_str(), "serde wire matches as_str");
        }
        assert_eq!(OpClass::ALL.len(), 5);
    }

    // ── decide: the rule table ──────────────────────────────────────────────

    #[test]
    fn healthy_allows_every_op_class() {
        for op in OpClass::ALL {
            assert_eq!(
                decide(op, &[], None),
                GateDecision::Allowed { reason: AllowReason::Healthy },
                "{op}: healthy run allows everything"
            );
        }
    }

    #[test]
    fn healthy_ignores_a_confirmation() {
        // Rule 1 precedes everything: a confirmation cannot change a healthy
        // verdict, and is not required for one.
        let c = conf("ops-lead");
        for op in OpClass::ALL {
            assert_eq!(
                decide(op, &[], Some(&c)),
                GateDecision::Allowed { reason: AllowReason::Healthy },
                "{op}: healthy wins over confirmation handling"
            );
        }
    }

    #[test]
    fn degraded_reversible_ops_pass_as_low_risk_only() {
        let reasons = degraded();
        for op in [OpClass::Recon, OpClass::Read] {
            assert_eq!(
                decide(op, &reasons, None),
                GateDecision::Allowed { reason: AllowReason::LowRiskOnly },
                "{op}: low-risk work proceeds while degraded"
            );
        }
    }

    #[test]
    fn degraded_irreversible_ops_are_blocked_with_reasons_echoed() {
        let reasons = degraded();
        for op in [OpClass::Publish, OpClass::Delete, OpClass::CredentialChange] {
            let d = decide(op, &reasons, None);
            assert_eq!(
                d,
                GateDecision::Blocked { reasons: reasons.clone() },
                "{op}: irreversible op must be blocked while degraded"
            );
            assert!(d.is_blocked());
            assert_eq!(d.block_reasons(), Some(reasons.as_slice()));
            assert!(d.allow_reason().is_none());
        }
    }

    #[test]
    fn valid_confirmation_flips_blocked_to_reviewer_override() {
        let reasons = degraded();
        let c = conf("ops-lead");
        for op in [OpClass::Publish, OpClass::Delete, OpClass::CredentialChange] {
            let d = decide(op, &reasons, Some(&c));
            assert_eq!(
                d,
                GateDecision::Allowed { reason: AllowReason::ReviewerOverride },
                "{op}: explicit reviewer confirmation unlocks the op"
            );
            assert!(d.is_allowed());
            assert_eq!(d.allow_reason(), Some(AllowReason::ReviewerOverride));
        }
    }

    #[test]
    fn invalid_confirmation_does_not_unlock() {
        let reasons = degraded();
        let empty = conf("");
        let whitespace = conf("   \t ");
        for c in [&empty, &whitespace] {
            assert!(!c.is_valid());
            assert_eq!(
                decide(OpClass::Delete, &reasons, Some(c)),
                GateDecision::Blocked { reasons: reasons.clone() },
                "an empty/whitespace reviewer must be treated as no confirmation"
            );
        }
        // A merely padded name is valid — trimming is the only normalization.
        let padded = conf("  ops-lead  ");
        assert!(padded.is_valid());
        assert_eq!(
            decide(OpClass::Delete, &reasons, Some(&padded)),
            GateDecision::Allowed { reason: AllowReason::ReviewerOverride }
        );
    }

    #[test]
    fn confirmation_is_irrelevant_for_low_risk_ops() {
        // Rule 2 wins over rule 3: reversible ops ignore the confirmation —
        // they were already allowed, and never as a "reviewer override".
        let reasons = degraded();
        let c = conf("ops-lead");
        assert_eq!(
            decide(OpClass::Recon, &reasons, Some(&c)),
            GateDecision::Allowed { reason: AllowReason::LowRiskOnly }
        );
    }

    #[test]
    fn decide_is_deterministic_and_never_panics() {
        let reasons = degraded();
        let c = conf("ops-lead");
        let cases: Vec<(OpClass, Vec<DegradedReason>, Option<ReviewerConfirmation>)> = vec![
            (OpClass::Recon, vec![], None),
            (OpClass::Read, reasons.clone(), None),
            (OpClass::Publish, reasons.clone(), None),
            (OpClass::Delete, reasons.clone(), Some(c.clone())),
            (OpClass::CredentialChange, vec![spiral()], None),
        ];
        for (op, rs, cf) in &cases {
            // Determinism: identical input → identical output.
            assert_eq!(decide(*op, rs, cf.as_ref()), decide(*op, rs, cf.as_ref()));
            // Exhaustiveness: exactly one arm, and it matches the predicates.
            let d = decide(*op, rs, cf.as_ref());
            assert_eq!(d.is_allowed(), !d.is_blocked());
            assert_eq!(d.is_allowed(), d.block_reasons().is_none());
            assert_eq!(d.is_blocked(), d.block_reasons().is_some());
        }
    }

    // ── The A7.1.3 failure-spiral drill ─────────────────────────────────────

    #[test]
    fn failure_spiral_drill_blocks_irreversible_low_risk_passes_and_records_declines() {
        use crate::degraded_gate::{detect, AttemptOutcome, Thresholds};

        // A retrying loop: five straight failures of the same op class.
        let t = Thresholds {
            failure_streak: 5,
            retry_spiral: 5,
            error_rate_window_ms: 60_000,
            error_rate: 0.5,
        };
        let attempts: Vec<AttemptOutcome> = (0..5)
            .map(|i| AttemptOutcome {
                ok: false,
                kind: "publish.run".to_string(),
                ts_ms: 1_700_000_000_000 + i as i64 * 200,
            })
            .collect();
        let reasons = detect(&attempts, &t);

        // The drill must actually be a spiral (plus its fellow reasons).
        assert!(!reasons.is_empty(), "five failures must trip the detectors");
        assert!(
            reasons.iter().any(|r| matches!(r, DegradedReason::RetrySpiral { .. })),
            "the retry spiral must be among the reasons: {reasons:?}"
        );

        let now_ms = 1_700_000_001_200;

        // Irreversible ops: all blocked, all recorded as declines.
        let mut declined = Vec::new();
        for op in [OpClass::Publish, OpClass::Delete, OpClass::CredentialChange] {
            let d = decide(op, &reasons, None);
            assert!(d.is_blocked(), "{op} must be blocked mid-spiral");
            let ev = record_declined(&d, op, &reasons, now_ms)
                .expect("a blocked decision must produce a decline record");
            assert_eq!(ev.op, op);
            assert_eq!(ev.reasons, reasons);
            assert_eq!(ev.at_ms, now_ms);
            declined.push(ev);
        }
        assert_eq!(
            summary(&declined),
            "declined-at-gate: publish=1, delete=1, credential_change=1"
        );

        // Low-risk ops: still pass, and leave no decline records.
        for op in [OpClass::Recon, OpClass::Read] {
            let d = decide(op, &reasons, None);
            assert_eq!(d, GateDecision::Allowed { reason: AllowReason::LowRiskOnly });
            assert!(record_declined(&d, op, &reasons, now_ms).is_none());
        }

        // Reviewer override closes the loop: blocked → confirmed → allowed.
        let c = conf("ops-lead");
        let override_decision = decide(OpClass::Publish, &reasons, Some(&c));
        assert_eq!(
            override_decision,
            GateDecision::Allowed { reason: AllowReason::ReviewerOverride }
        );
        assert!(record_declined(&override_decision, OpClass::Publish, &reasons, now_ms).is_none());
    }

    #[test]
    fn storm_reasons_block_irreversible_and_spare_low_risk() {
        // A narrower probe than the drill: storm-only reasons, exact arms.
        let reasons = vec![storm()];
        assert_eq!(
            decide(OpClass::Delete, &reasons, None),
            GateDecision::Blocked { reasons: reasons.clone() }
        );
        assert_eq!(
            decide(OpClass::Read, &reasons, None),
            GateDecision::Allowed { reason: AllowReason::LowRiskOnly }
        );
    }

    // ── record_declined ─────────────────────────────────────────────────────

    #[test]
    fn record_declined_some_only_for_blocked() {
        let reasons = degraded();

        let blocked = decide(OpClass::Publish, &reasons, None);
        let ev = record_declined(&blocked, OpClass::Publish, &reasons, 42)
            .expect("Blocked must yield Some");
        assert_eq!(ev, DeclinedAtGate { op: OpClass::Publish, reasons: reasons.clone(), at_ms: 42 });

        let healthy = decide(OpClass::Delete, &[], None);
        assert!(record_declined(&healthy, OpClass::Delete, &[], 42).is_none());

        let low_risk = decide(OpClass::Recon, &reasons, None);
        assert!(record_declined(&low_risk, OpClass::Recon, &reasons, 42).is_none());

        let override_ok = decide(OpClass::Publish, &reasons, Some(&conf("ops-lead")));
        assert!(record_declined(&override_ok, OpClass::Publish, &reasons, 42).is_none());
    }

    // ── summary ─────────────────────────────────────────────────────────────

    #[test]
    fn summary_counts_per_op_in_canonical_order() {
        let reasons = degraded();
        let mk = |op: OpClass, at_ms: i64| DeclinedAtGate { op, reasons: reasons.clone(), at_ms };
        let events = [
            mk(OpClass::Delete, 1),
            mk(OpClass::Publish, 2),
            mk(OpClass::Delete, 3),
            mk(OpClass::CredentialChange, 4),
            mk(OpClass::Publish, 5),
        ];
        assert_eq!(
            summary(&events),
            "declined-at-gate: publish=2, delete=2, credential_change=1"
        );

        // Recon/Read declines are counted too (the gate allows them, but the
        // telemetry tolerates any record — counts must stay truthful).
        let with_low_risk = [mk(OpClass::Recon, 6), mk(OpClass::Delete, 7)];
        assert_eq!(summary(&with_low_risk), "declined-at-gate: recon=1, delete=1");
    }

    #[test]
    fn summary_empty_is_none() {
        assert_eq!(summary(&[]), "declined-at-gate: none");
    }

    #[test]
    fn summary_is_order_independent() {
        let reasons = degraded();
        let a = DeclinedAtGate { op: OpClass::Publish, reasons: reasons.clone(), at_ms: 1 };
        let b = DeclinedAtGate { op: OpClass::Delete, reasons: reasons.clone(), at_ms: 2 };
        let c = DeclinedAtGate { op: OpClass::Publish, reasons: reasons.clone(), at_ms: 3 };
        let s = summary(&[a.clone(), b.clone(), c.clone()]);
        assert_eq!(s, summary(&[c.clone(), a.clone(), b.clone()]));
        assert_eq!(s, summary(&[b.clone(), c.clone(), a.clone()]));
        assert_eq!(s, "declined-at-gate: publish=2, delete=1");
    }

    // ── serde ───────────────────────────────────────────────────────────────

    #[test]
    fn serde_round_trips_all_types() {
        for op in OpClass::ALL {
            let json = serde_json::to_string(&op).unwrap();
            let back: OpClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, op);
        }

        let c = conf("ops-lead");
        let back: ReviewerConfirmation =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);

        for reason in [AllowReason::Healthy, AllowReason::LowRiskOnly, AllowReason::ReviewerOverride] {
            let back: AllowReason =
                serde_json::from_str(&serde_json::to_string(&reason).unwrap()).unwrap();
            assert_eq!(back, reason);
        }

        let reasons = degraded();
        for d in [
            GateDecision::Allowed { reason: AllowReason::LowRiskOnly },
            GateDecision::Blocked { reasons: reasons.clone() },
        ] {
            let back: GateDecision =
                serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
            assert_eq!(back, d);
        }

        let ev = DeclinedAtGate { op: OpClass::Delete, reasons: reasons.clone(), at_ms: 99 };
        let back: DeclinedAtGate =
            serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn serde_pins_the_wire_shapes() {
        assert_eq!(serde_json::to_string(&OpClass::CredentialChange).unwrap(), r#""credential_change""#);
        assert_eq!(serde_json::to_string(&AllowReason::LowRiskOnly).unwrap(), r#""low_risk_only""#);
        assert_eq!(
            serde_json::to_string(&GateDecision::Allowed { reason: AllowReason::Healthy }).unwrap(),
            r#"{"allowed":{"reason":"healthy"}}"#
        );
        assert_eq!(
            serde_json::to_string(&GateDecision::Blocked {
                reasons: vec![DegradedReason::FailureStreak { len: 3 }]
            })
            .unwrap(),
            r#"{"blocked":{"reasons":[{"FailureStreak":{"len":3}}]}}"#
        );
        // Decline records reconstruct from an audit log.
        let ev: DeclinedAtGate = serde_json::from_str(
            r#"{"op":"publish","reasons":[{"ErrorStorm":{"rate":0.75}}],"at_ms":1700000000}"#,
        )
        .unwrap();
        assert_eq!(ev.op, OpClass::Publish);
        assert_eq!(ev.reasons, vec![DegradedReason::ErrorStorm { rate: 0.75 }]);
        assert_eq!(ev.at_ms, 1_700_000_000);
    }

    #[test]
    fn allow_reason_names_and_display() {
        assert_eq!(AllowReason::Healthy.as_str(), "healthy");
        assert_eq!(AllowReason::LowRiskOnly.as_str(), "low_risk_only");
        assert_eq!(AllowReason::ReviewerOverride.as_str(), "reviewer_override");
        for r in [AllowReason::Healthy, AllowReason::LowRiskOnly, AllowReason::ReviewerOverride] {
            assert_eq!(r.to_string(), r.as_str());
        }
    }

    // ── Verdict recording via the telemetry choke point (R-6.9) ─────────────

    // Externally computed (printf ops_gate | sha256sum) so the hashing
    // convention is grounded outside this module's own code path.
    const SHA256_OPS_GATE: &str = "72710d754fbb1c90d2a9da6f53f9e4964790af76b3a942127ef24d1d8bd502ee";

    /// SMOKE (R-6.9): a confirm and a decline each land exactly one
    /// `policy_verdict` record on a MemorySink — verdict token, op class,
    /// hashed actor, plane, and coarsened timestamp all pinned; the reviewer
    /// name never reaches the wire form.
    #[test]
    fn smoke_confirm_and_decline_land_policy_verdict_records() {
        use crate::observability::{MemorySink, Plane};

        let reasons = degraded();
        let at_ms = 1_700_000_123_456;
        let mut sink = MemorySink::new();

        // Decline: degraded irreversible op, no confirmation.
        let declined = decide_and_record_to(&mut sink, OpClass::Delete, &reasons, None, at_ms);
        assert!(declined.is_blocked(), "unconfirmed irreversible op must stay blocked");

        // Confirm: same degraded op, valid reviewer confirmation.
        let confirmed =
            decide_and_record_to(&mut sink, OpClass::Delete, &reasons, Some(&conf("ops-lead")), at_ms);
        assert_eq!(
            confirmed,
            GateDecision::Allowed { reason: AllowReason::ReviewerOverride },
            "the confirmation must flip the verdict to reviewer override"
        );

        let events = sink.events();
        assert_eq!(events.len(), 2, "confirm and decline must each record exactly one event");

        let decline_ev = &events[0];
        assert_eq!(decline_ev.class, EventClass::PolicyVerdict);
        assert_eq!(decline_ev.plane, Plane::Ops, "policy verdicts classify to the ops plane");
        assert_eq!(decline_ev.target.as_deref(), Some("decline:delete"));
        assert_eq!(decline_ev.actor_hash, format!("n-{SHA256_OPS_GATE}"), "actor must be hashed");
        assert_eq!(decline_ev.at_ms, 1_699_999_200_000, "timestamp must be hour-floored");
        assert_eq!(decline_ev.id, "policy_verdict-1699999200000");
        assert_eq!(decline_ev.size, 0, "a verdict carries no byte payload");
        assert_eq!(decline_ev.note, None);

        let confirm_ev = &events[1];
        assert_eq!(confirm_ev.class, EventClass::PolicyVerdict);
        assert_eq!(confirm_ev.plane, Plane::Ops);
        assert_eq!(confirm_ev.target.as_deref(), Some("confirm:delete"));
        assert_eq!(confirm_ev.actor_hash, format!("n-{SHA256_OPS_GATE}"));
        assert_eq!(confirm_ev.at_ms, 1_699_999_200_000);
        assert_eq!(confirm_ev.id, "policy_verdict-1699999200000");

        // The reviewer name is audit context, never telemetry: it must not
        // appear anywhere on the wire form of either record.
        for ev in events {
            let wire = serde_json::to_string(ev).unwrap();
            assert!(wire.contains(r#""class":"policy_verdict""#), "wire: {wire}");
            assert!(wire.contains(r#""plane":"ops""#), "wire: {wire}");
            assert!(!wire.contains("ops-lead"), "reviewer name leaked into {wire}");
        }
    }

    /// Verdicts with nothing to confirm/decline record nothing; a failing
    /// sink surfaces an error but never changes the decision (best-effort
    /// contract).
    #[test]
    fn verdict_recording_is_absent_for_healthy_low_risk_and_never_blocks_the_decision() {
        use crate::observability::MemorySink;

        /// A sink that always fails — proves emission errors are ignored.
        struct FailingSink;
        impl crate::observability::SecurityEventSink for FailingSink {
            fn record(&mut self, _ev: &RedactedSecurityEvent) -> Result<(), String> {
                Err("disk full".to_string())
            }
        }

        let reasons = degraded();
        let c = conf("ops-lead");

        // Pure builder: only confirm/decline produce an event.
        assert!(verdict_event(&decide(OpClass::Recon, &reasons, None), OpClass::Recon, 0).is_none());
        assert!(verdict_event(&decide(OpClass::Recon, &[], None), OpClass::Recon, 0).is_none());
        // Healthy verdict ignores the confirmation — nothing to record.
        assert!(verdict_event(&decide(OpClass::Recon, &[], Some(&c)), OpClass::Recon, 0).is_none());
        assert!(verdict_event(&decide(OpClass::Delete, &reasons, None), OpClass::Delete, 0).is_some());
        assert!(verdict_event(&decide(OpClass::Delete, &reasons, Some(&c)), OpClass::Delete, 0).is_some());

        // Healthy and low-risk decisions record nothing on a real sink.
        let mut sink = MemorySink::new();
        let healthy = decide_and_record_to(&mut sink, OpClass::Publish, &[], None, 1);
        assert_eq!(healthy, GateDecision::Allowed { reason: AllowReason::Healthy });
        let low_risk = decide_and_record_to(&mut sink, OpClass::Read, &reasons, None, 2);
        assert_eq!(low_risk, GateDecision::Allowed { reason: AllowReason::LowRiskOnly });
        assert!(sink.events().is_empty(), "no confirm/decline -> no policy_verdict record");

        // A failing sink surfaces Err, but the decision is returned intact —
        // recording can never block or alter the verdict.
        let mut fail = FailingSink;
        let blocked = decide_and_record_to(&mut fail, OpClass::Publish, &reasons, None, 42);
        assert_eq!(blocked, GateDecision::Blocked { reasons: reasons.clone() });
        let override_ok = decide_and_record_to(&mut fail, OpClass::Publish, &reasons, Some(&c), 42);
        assert_eq!(override_ok, GateDecision::Allowed { reason: AllowReason::ReviewerOverride });
        assert!(matches!(
            emit_verdict(&mut fail, &override_ok, OpClass::Publish, 42),
            Err(EmitError::Sink(_))
        ));
        assert!(matches!(
            emit_verdict(&mut fail, &blocked, OpClass::Publish, 42),
            Err(EmitError::Sink(_))
        ));
    }
}

