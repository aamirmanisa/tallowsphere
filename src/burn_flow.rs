//! Burn(persona) orchestration — task A5.1.3 (dossier E13, ruleset A5.2.1).
//!
//! The [`crate::persona`] registry (A5.1.2) owns the *state* half of persona
//! disposal: `burn` moves a persona `Active → Burned` and taints its id, and
//! `assert_reusable` hard-fails for that id forever after. This module owns
//! the *orchestration* half: a [`BurnPlan`] states how a persona is disposed
//! of (method, circuit close-out, artifact quarantine, taint note) and
//! [`execute`] drives the registry, verifies the never-reuse invariant, and
//! returns a serializable [`BurnReceipt`] — the burn report that doubles as
//! the audit trail (ruleset A5.2.1 `@burn_plan(persona, after,
//! method: .revoke_and_quarantine, artifacts: .quarantine)`).
//!
//! # Fail-closed rules
//! 1. An empty (or blank) [`BurnPlan::taint_note`] is refused
//!    ([`BurnFlowError::EmptyTaint`]): a burn that cannot state what it
//!    taints must not happen.
//! 2. A second `execute` for the same id is refused
//!    ([`BurnFlowError::AlreadyBurned`]): burn is terminal (E13 never-reuse)
//!    and the registry's burned set is consulted *before* anything mutates.
//! 3. After `burn`, `assert_reusable(id)` MUST hard-fail; `execute` verifies
//!    this post-condition and refuses to issue a receipt otherwise (see
//!    [`execute`] for the panic semantics).
//!
//! The vault-side effects (credential revocation, moving artifacts into
//! quarantine) are A5.1.2 runtime work and are not present here; `execute`
//! records the *requested* disposition verbatim in the receipt and never
//! claims an effect it did not observe.
//!
//! Deviations vs `B08_INTERFACES.md` §2 (argued in batch report AGT-82.md):
//! `BurnPlan` additionally derives serde (mirrors `BurnReceipt`; additive,
//! cannot break integration); negative `now_ms` clamps to `0` (the registry
//! clock is `u64` and a negative wall clock is not a burn time); blank-but-
//! not-empty taint notes count as empty (trim-based check); the fail-closed
//! post-check panics rather than growing a fourth `BurnFlowError` variant,
//! keeping the frozen enum byte-exact.


use std::fmt;

use serde::{Deserialize, Serialize};

use crate::persona::{BurnMethod, PersonaError, PersonaRegistry, QuarantineMode};

/// What to do when burning a persona: the executable form of the corpus
/// burn plan (`@burn_plan(persona, after, method: ..., artifacts: ...)`).
///
/// `close_circuits` is the revoke half of the disposal. [`crate::persona`]
/// models *whether* revocation happened (`BurnMethod::Revoke*`); this plan
/// carries the operator's request as a boolean so [`execute`] can record it
/// in the receipt (the actual circuit store is vault work, A5.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnPlan {
    /// Persona id to dispose of (single-use; never reused after a burn).
    pub persona_id: String,
    /// Disposal method (revoke / quarantine split — corpus literal set).
    pub method: BurnMethod,
    /// Whether credential/circuit revocation is requested for this burn.
    pub close_circuits: bool,
    /// What happens to the persona's artifacts (corpus `artifacts:` arg).
    pub quarantine: QuarantineMode,
    /// Why the burn is happening / what it taints. MUST be non-empty
    /// (fail-closed): the burn report is the audit trail.
    pub taint_note: String,
}

/// Audit receipt of an executed burn — the burn report of E13.
///
/// Serde round-trippable so it can be persisted alongside the run ledger;
/// a reloaded receipt keeps the taint list intact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnReceipt {
    /// The burned persona's id.
    pub persona_id: String,
    /// Burn timestamp as handed to the registry (ms since epoch).
    pub burned_at_ms: i64,
    /// The method word exactly as the corpus spells it
    /// (`revoke_and_quarantine`, `revoke_only`, `quarantine_only`).
    pub method_word: String,
    /// Whether circuit revocation was requested (`BurnPlan::close_circuits`,
    /// recorded verbatim).
    pub circuits_closed: bool,
    /// Artifact disposition word (`quarantine` or `none`).
    pub quarantine: String,
    /// What the burn taints — the plan's taint note, verbatim.
    pub taint: Vec<String>,
}

/// Why the burn flow refused. Fail-closed: every variant refuses the burn or
/// withholds the receipt; none of them "repairs" state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurnFlowError {
    /// Registry refusal passed through (unknown persona, fingerprint reuse,
    /// …). Never swallowed: the registry is the reuse authority (E5003).
    Persona(PersonaError),
    /// The plan's taint note was empty — a burn without an audit trail is
    /// refused.
    EmptyTaint,
    /// The id was already burned: burn is terminal, so a second one is a
    /// caller bug surfaced, not silently idempotent.
    AlreadyBurned,
}

impl fmt::Display for BurnFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BurnFlowError::Persona(e) => write!(f, "burn refused by persona registry: {e}"),
            BurnFlowError::EmptyTaint => write!(
                f,
                "burn plan taint note must not be empty (a burn without an audit trail is refused)"
            ),
            BurnFlowError::AlreadyBurned => write!(
                f,
                "persona is already burned (never-reuse: a burn is terminal and cannot repeat)"
            ),
        }
    }
}

impl std::error::Error for BurnFlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BurnFlowError::Persona(e) => Some(e),
            BurnFlowError::EmptyTaint | BurnFlowError::AlreadyBurned => None,
        }
    }
}

/// Artifact-disposition word recorded in the receipt. `persona`'s
/// [`QuarantineMode`] has no `as_str`; this pins the spelling.
fn quarantine_word(mode: QuarantineMode) -> &'static str {
    match mode {
        QuarantineMode::Quarantine => "quarantine",
        QuarantineMode::None => "none",
    }
}

/// Execute a burn: validate, drive the registry, verify never-reuse, return
/// the receipt.
///
/// Order of operations (all fail-closed):
/// 1. blank `plan.taint_note` → [`BurnFlowError::EmptyTaint`] — nothing is
///    touched;
/// 2. `reg.is_burned(&plan.persona_id)` → [`BurnFlowError::AlreadyBurned`] —
///    nothing is touched (the reuse gate runs *before* any mutation);
/// 3. `reg.burn(id, at_ms, method, quarantine)` — registry errors pass
///    through as [`BurnFlowError::Persona`]; the registry's own
///    `AlreadyBurned` is folded into [`BurnFlowError::AlreadyBurned`];
/// 4. post-condition: `reg.assert_reusable(id)` MUST be `Err`. If it is
///    `Ok`, the burn failed to taint and `execute` **panics** rather than
///    issue a receipt that lies about never-reuse. (Unreachable via the
///    public registry API — `burn` always taints — so this guards future
///    registry changes; fail-closed means abort, never "carry on".)
///
/// # Clock adaptation
/// The flow boundary takes `now_ms: i64` (caller-supplied, no clock here)
/// while the registry stores `at_ms: u64`; negative values clamp to `0` so
/// the receipt and the registry always agree on the recorded time.
pub fn execute(
    reg: &mut PersonaRegistry,
    plan: &BurnPlan,
    now_ms: i64,
) -> Result<BurnReceipt, BurnFlowError> {
    // 1. Fail-closed: a burn must state what it taints.
    if plan.taint_note.trim().is_empty() {
        return Err(BurnFlowError::EmptyTaint);
    }

    // 2. Fail-closed reuse gate: the registry's tainted set is the authority
    // (E5003: reuse across runs is decided at the persona boundary, not
    // statically).
    if reg.is_burned(&plan.persona_id) {
        return Err(BurnFlowError::AlreadyBurned);
    }

    // 3. Drive the registry. v1 boundary is i64 → registry u64 (clamped).
    let at_ms: u64 = now_ms.max(0) as u64;
    reg.burn(&plan.persona_id, at_ms, plan.method, plan.quarantine)
        .map_err(|e| match e {
            PersonaError::AlreadyBurned { .. } => BurnFlowError::AlreadyBurned,
            other => BurnFlowError::Persona(other),
        })?;

    // 4. Post-condition, fail-closed: the burn must have tainted the id. If
    // the registry still reports it reusable, abort rather than hand back a
    // receipt that lies about the never-reuse invariant.
    if reg.assert_reusable(&plan.persona_id).is_ok() {
        panic!(
            "burn_flow fail-closed: `{}` was burned but assert_reusable still \
             succeeds; refusing to issue a receipt",
            plan.persona_id
        );
    }

    Ok(BurnReceipt {
        persona_id: plan.persona_id.clone(),
        burned_at_ms: at_ms as i64,
        method_word: plan.method.as_str().to_string(),
        circuits_closed: plan.close_circuits,
        quarantine: quarantine_word(plan.quarantine).to_string(),
        taint: vec![plan.taint_note.clone()],
    })
}

/// The taint list recorded by a burn receipt (borrow helper for callers that
/// want the tainted-material view without owning the receipt).
pub fn taint_of(receipt: &BurnReceipt) -> &[String] {
    &receipt.taint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persona::{CoverClass, Legend, Lifecycle, Persona};

    const NOW: i64 = 1_800_000_000_000;

    fn persona(id: &str, seed: &str) -> Persona {
        Persona::new(
            id,
            CoverClass::new("researcher"),
            "ctrl-1",
            Legend::new("grad student", "cover@example.invalid", "run-1"),
            seed,
            1_700_000_000_000,
        )
    }

    fn plan_for(id: &str) -> BurnPlan {
        BurnPlan {
            persona_id: id.to_string(),
            method: BurnMethod::RevokeAndQuarantine,
            close_circuits: true,
            quarantine: QuarantineMode::Quarantine,
            taint_note: "taint: run-1 notes derived from cover legend".to_string(),
        }
    }

    #[test]
    fn happy_burn_receipt_and_reuse_hard_fails() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        let plan = plan_for("p-1");

        let receipt = execute(&mut reg, &plan, NOW).expect("first burn must succeed");
        assert_eq!(receipt.persona_id, "p-1");
        assert_eq!(receipt.burned_at_ms, NOW);
        assert_eq!(receipt.method_word, "revoke_and_quarantine");
        assert!(receipt.circuits_closed);
        assert_eq!(receipt.quarantine, "quarantine");
        assert_eq!(receipt.taint, vec![plan.taint_note.clone()]);

        // The registry state is burned, and the never-reuse invariant now
        // hard-fails for the id (post-condition of execute).
        assert!(reg.is_burned("p-1"));
        assert!(reg.burned_ids().contains("p-1"));
        match reg.assert_reusable("p-1") {
            Err(PersonaError::BurnedReuse { id, at_ms, method }) => {
                assert_eq!(id, "p-1");
                assert_eq!(at_ms, NOW as u64);
                assert_eq!(method, BurnMethod::RevokeAndQuarantine);
            }
            other => panic!("burned id must hard-fail: {other:?}"),
        }
        assert_eq!(
            reg.get("p-1").unwrap().lifecycle,
            Lifecycle::Burned {
                at_ms: NOW as u64,
                method: BurnMethod::RevokeAndQuarantine,
                quarantine: QuarantineMode::Quarantine,
            }
        );
    }

    #[test]
    fn second_execute_is_already_burned() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        execute(&mut reg, &plan_for("p-1"), NOW).expect("first burn");

        let err = execute(&mut reg, &plan_for("p-1"), NOW + 1).expect_err("second burn must fail");
        assert_eq!(err, BurnFlowError::AlreadyBurned);
        // Terminal state: exactly one burn happened, at the original time.
        assert_eq!(reg.burned_ids().len(), 1);
        match reg.assert_reusable("p-1") {
            Err(PersonaError::BurnedReuse { at_ms, .. }) => assert_eq!(at_ms, NOW as u64),
            other => panic!("expected BurnedReuse: {other:?}"),
        }
    }

    #[test]
    fn empty_or_blank_taint_is_refused() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();

        let mut plan = plan_for("p-1");
        plan.taint_note = String::new();
        assert_eq!(execute(&mut reg, &plan, NOW).unwrap_err(), BurnFlowError::EmptyTaint);

        plan.taint_note = "   \n\t".to_string();
        assert_eq!(execute(&mut reg, &plan, NOW).unwrap_err(), BurnFlowError::EmptyTaint);

        // Fail-closed: nothing was burned and nothing was tainted.
        assert!(!reg.is_burned("p-1"));
        assert!(reg.assert_reusable("p-1").is_ok());
        assert!(reg.burned_ids().is_empty());
    }

    #[test]
    fn unknown_persona_passes_registry_error_through() {
        let mut reg = PersonaRegistry::new();
        let err = execute(&mut reg, &plan_for("ghost"), NOW).unwrap_err();
        match err {
            BurnFlowError::Persona(PersonaError::UnknownPersona { id }) => assert_eq!(id, "ghost"),
            other => panic!("expected UnknownPersona passthrough: {other:?}"),
        }
        assert!(reg.burned_ids().is_empty());
    }

    #[test]
    fn method_and_quarantine_words_are_pinned() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-a", "seed-a")).unwrap();
        reg.register(persona("p-b", "seed-b")).unwrap();

        let mut revoke_only = plan_for("p-a");
        revoke_only.method = BurnMethod::RevokeOnly;
        let r = execute(&mut reg, &revoke_only, NOW).unwrap();
        assert_eq!(r.method_word, "revoke_only");
        assert_eq!(r.quarantine, "quarantine");
        assert!(r.circuits_closed);

        let mut quarantine_only = plan_for("p-b");
        quarantine_only.method = BurnMethod::QuarantineOnly;
        quarantine_only.quarantine = QuarantineMode::None;
        quarantine_only.close_circuits = false;
        let r = execute(&mut reg, &quarantine_only, NOW).unwrap();
        assert_eq!(r.method_word, "quarantine_only");
        assert_eq!(r.quarantine, "none");
        assert!(!r.circuits_closed);
    }

    #[test]
    fn negative_now_clamps_to_zero_and_agrees_with_registry() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        let receipt = execute(&mut reg, &plan_for("p-1"), -5).unwrap();
        assert_eq!(receipt.burned_at_ms, 0);
        assert_eq!(
            reg.get("p-1").unwrap().lifecycle,
            Lifecycle::Burned {
                at_ms: 0,
                method: BurnMethod::RevokeAndQuarantine,
                quarantine: QuarantineMode::Quarantine,
            }
        );
        match reg.assert_reusable("p-1") {
            Err(PersonaError::BurnedReuse { at_ms, .. }) => assert_eq!(at_ms, 0),
            other => panic!("expected BurnedReuse: {other:?}"),
        }
    }

    #[test]
    fn receipt_serde_round_trip() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        let receipt = execute(&mut reg, &plan_for("p-1"), NOW).unwrap();

        let json = serde_json::to_string(&receipt).expect("receipt serializes");
        let back: BurnReceipt = serde_json::from_str(&json).expect("receipt deserializes");
        assert_eq!(back, receipt);
        assert!(json.contains("\"method_word\":\"revoke_and_quarantine\""), "json: {json}");
        assert!(json.contains("\"quarantine\":\"quarantine\""), "json: {json}");
    }

    #[test]
    fn determinism_independent_runs_identical_receipts() {
        let mut a = PersonaRegistry::new();
        let mut b = PersonaRegistry::new();
        a.register(persona("p-1", "seed-1")).unwrap();
        b.register(persona("p-1", "seed-1")).unwrap();
        let plan = plan_for("p-1");

        let ra = execute(&mut a, &plan, NOW).unwrap();
        let rb = execute(&mut b, &plan, NOW).unwrap();
        assert_eq!(ra, rb);
        assert_eq!(
            serde_json::to_string(&ra).unwrap(),
            serde_json::to_string(&rb).unwrap()
        );
    }

    #[test]
    fn taint_of_exposes_the_note() {
        let mut reg = PersonaRegistry::new();
        reg.register(persona("p-1", "seed-1")).unwrap();
        let plan = plan_for("p-1");
        let receipt = execute(&mut reg, &plan, NOW).unwrap();
        assert_eq!(taint_of(&receipt), std::slice::from_ref(&plan.taint_note));
        assert_eq!(taint_of(&receipt).len(), 1);
    }

    #[test]
    fn error_display_and_source() {
        use std::error::Error;

        let blank = BurnFlowError::EmptyTaint;
        assert!(blank.to_string().contains("taint"), "msg: {blank}");
        assert!(blank.source().is_none());

        let again = BurnFlowError::AlreadyBurned;
        assert!(again.to_string().contains("already burned"), "msg: {again}");
        assert!(again.source().is_none());

        let passthrough = BurnFlowError::Persona(PersonaError::UnknownPersona {
            id: "ghost".into(),
        });
        let msg = passthrough.to_string();
        assert!(msg.contains("ghost"), "msg: {msg}");
        assert!(passthrough.source().is_some());
    }
}
