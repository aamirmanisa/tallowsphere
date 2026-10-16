//! Nepsis consent — the propose→consent pipeline with a separation rule and a
//! fail-closed clear gate (tasks B2.2.1–B2.2.3, frozen interface §1).
//!
//! *Nepsis* (νῆψις) is sober watchfulness: no consequential action proceeds on
//! its own proposer's say-so. This module is the consent ledger for that rule.
//! Every action enters as a [`Proposal`] carrying who proposed it, why, and
//! when. It leaves as a [`ConsentCase`] holding either nothing (pending) or a
//! single write-once [`Decision`], recorded by someone *other than* the
//! proposer. [`ConsentGate::is_clear`] is the query surface a consent hook
//! asks before acting; [`ConsentGate::declined_telemetry`] is the audit trail
//! of everything that was refused.
//!
//! # The separation rule (B2.2.2)
//!
//! [`ConsentGate::decide`] refuses any attempt by the proposer to decide their
//! own proposal ([`NepsisError::SelfConsent`]). Self-consent is *never*
//! allowed — not for approvals and not for declines (a proposer declining
//! their own proposal is still a proposer writing to their own case).
//! Identity comparison is **trim-normalised and ASCII case-insensitive**; see
//! the documented-rules section for why this is deliberately stricter than a
//! raw `==`.
//!
//! # Fail-closed clear gate (B2.2.3)
//!
//! [`ConsentGate::is_clear`] answers `Ok(true)` **iff** the case holds an
//! approval. Pending ⇒ `false`; declined ⇒ `false`; a proposal id that does
//! not exist ⇒ `Err(`[`NepsisError::UnknownProposal`]`)`. Callers wiring this
//! as a required action gate must treat *any* `Err`, and any inability to run
//! the check at all, as denial — a gate that cannot be shown open is closed.
//! There is no override, no implicit consent, and no expiry that turns silence
//! into approval.
//!
//! # Declined telemetry (B2.2.3)
//!
//! [`ConsentGate::declined_telemetry`] returns one [`DeclinedRecord`] per
//! declined case — id, action, decliner, reason, timestamp — sorted by
//! `(at_ms, id)`. Nothing else ever appears there: approvals and pending cases
//! are not telemetry.
//!
//! # Documented rules (spec silent where noted; conservative reading)
//!
//! * **`propose` check order**: `action`, `rationale`, `proposed_by` — the
//!   first empty-or-whitespace-only argument is refused as
//!   [`NepsisError::BadInput`] with the *argument name*. A refused call
//!   records nothing and consumes no id.
//! * **Stored text**: free prose (`action`, `rationale`, decline `reason`) is
//!   validated on its trimmed form but stored **verbatim**; identity names
//!   (`proposed_by`, `by`) are trim-normalised on the way in, because they
//!   participate in the separation rule (see next bullet).
//! * **Identity comparison (argued deviation)**: the frozen spec writes the
//!   separation rule as `by == proposed_by`. Comparing raw strings would let
//!   `" alice "` or `"ALICE"` approve alice's proposal — a trivial escape from
//!   a rule whose stated intent is that self-consent is *never* allowed. This
//!   module therefore compares trim-normalised forms with
//!   [`str::eq_ignore_ascii_case`] (ASCII folding only; non-ASCII characters
//!   compare case-sensitively). Case is preserved as given for display.
//! * **`decide` check order**: unknown id ([`NepsisError::UnknownProposal`]),
//!   then already decided ([`NepsisError::AlreadyDecided`] — decisions are
//!   write-once and the first decision survives every later attempt), then
//!   empty `by` ([`NepsisError::BadInput`]`("by")` — *argued extension*, see
//!   next bullet), then the separation rule ([`NepsisError::SelfConsent`]),
//!   then declined-with-empty-reason ([`NepsisError::BadInput`]`("reason")`).
//!   A refused call records nothing.
//! * **Empty decider refusal (argued deviation)**: the spec's `decide` bullet
//!   lists four refusals and does not mention an empty `by`. This module adds
//!   `BadInput("by")` for an empty-or-whitespace-only decider, in the spirit
//!   of `propose`'s empty-field validation: an approval attributed to nobody
//!   is an unauditable consent act, and an empty name can never equal a
//!   non-empty `proposed_by`, so accepting it would be a hole *inside* the
//!   separation rule's domain. Fail-closed reading: refuse.
//! * **`reason` on approval**: ignored. [`Decision::Approved`] has no reason
//!   field; the argument is only consulted (and then required non-empty) for
//!   declines.
//! * **Ids**: `pr-<seq:04>`, seq = 1-based position of the case in the ledger
//!   (`pr-0001`, …, `pr-0012`, …). There is no removal API, so ids are stable,
//!   unique, and deterministic across replays. Lookups are exact-string
//!   (`pr-0001` matches; `" pr-0001"` does not — an unknown id is refused,
//!   which is fail-closed).
//! * **Telemetry sort**: `(at_ms, id)` ascending. Ids are zero-padded, so a
//!   lexicographic id tie-break is also chronological among same-time declines.
//! * **No clocks inside**: every timestamp is caller-supplied (`now_ms` and
//!   the `at_ms` fields). The module is a pure function of the call sequence,
//!   which is what makes replays bit-identical.
//! * [`ConsentGate`] is **not** `serde` — the frozen spec annotates only
//!   [`Proposal`], [`Decision`], [`ConsentCase`] and [`DeclinedRecord`]; the
//!   gate is live runtime state. [`NepsisError`] derives `Serialize` but not
//!   `Deserialize`: its `BadInput(&'static str)` payload cannot be
//!   deserialized into a `'static` lifetime. This mirrors the in-repo
//!   precedent (`clearness_gate`, `vouching::VouchError`, `gap_register`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A proposed action awaiting consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Stable id: `pr-<seq:04>`, seq = 1-based position in the ledger.
    pub id: String,
    /// What is being proposed.
    pub action: String,
    /// Why it should be done.
    pub rationale: String,
    /// Who proposed it (trim-normalised; identity field).
    pub proposed_by: String,
    /// Caller-supplied proposal time.
    pub proposed_ms: i64,
}

/// The recorded outcome of a consent review — write-once, never revised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Consent granted.
    Approved { by: String, at_ms: i64 },
    /// Consent refused; the reason is mandatory and stored verbatim.
    Declined {
        by: String,
        reason: String,
        at_ms: i64,
    },
}

/// One proposal together with its decision state (`None` = pending).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentCase {
    pub proposal: Proposal,
    pub decision: Option<Decision>,
}

/// Audit record for one declined proposal (declined telemetry only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclinedRecord {
    /// The declined proposal's id.
    pub id: String,
    /// The declined proposal's action.
    pub action: String,
    /// Who declined it (trim-normalised).
    pub declined_by: String,
    /// The decliner's reason, verbatim.
    pub reason: String,
    /// Caller-supplied decision time.
    pub at_ms: i64,
}

/// Identity comparison for the separation rule: surrounding whitespace
/// ignored, ASCII case-insensitive, non-ASCII compared as-is.
fn names_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The propose→consent ledger: proposals in, decisions out, declines on the
/// record. See the module docs for the separation rule and the fail-closed
/// clear-gate contract.
#[derive(Debug, Clone, Default)]
pub struct ConsentGate {
    cases: Vec<ConsentCase>,
}

impl ConsentGate {
    /// Propose an action for consent and return the recorded proposal.
    ///
    /// # Errors
    ///
    /// * [`NepsisError::BadInput`]`("action")` / `("rationale")` /
    ///   `("proposed_by")` — the first of those that is empty after trimming.
    ///   A refused call records nothing and consumes no id.
    pub fn propose(
        &mut self,
        action: &str,
        rationale: &str,
        proposed_by: &str,
        now_ms: i64,
    ) -> Result<&Proposal, NepsisError> {
        if action.trim().is_empty() {
            return Err(NepsisError::BadInput("action"));
        }
        if rationale.trim().is_empty() {
            return Err(NepsisError::BadInput("rationale"));
        }
        if proposed_by.trim().is_empty() {
            return Err(NepsisError::BadInput("proposed_by"));
        }
        let id = format!("pr-{:04}", self.cases.len() + 1);
        let idx = self.cases.len();
        self.cases.push(ConsentCase {
            proposal: Proposal {
                id,
                action: action.to_string(),
                rationale: rationale.to_string(),
                proposed_by: proposed_by.trim().to_string(),
                proposed_ms: now_ms,
            },
            decision: None,
        });
        Ok(&self.cases[idx].proposal)
    }

    /// Record a decision on a pending proposal. Write-once: the first decision
    /// recorded is final, and later attempts are refused.
    ///
    /// # Errors
    ///
    /// Check order: [`NepsisError::UnknownProposal`] (no such id) →
    /// [`NepsisError::AlreadyDecided`] (decision already recorded) →
    /// [`NepsisError::BadInput`]`("by")` (empty decider — argued extension) →
    /// [`NepsisError::SelfConsent`] (the separation rule: `by` is the
    /// proposer) → [`NepsisError::BadInput`]`("reason")` (decline with an
    /// empty reason). A refused call records nothing.
    pub fn decide(
        &mut self,
        id: &str,
        approved: bool,
        by: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<(), NepsisError> {
        let case = self
            .cases
            .iter_mut()
            .find(|c| c.proposal.id == id)
            .ok_or(NepsisError::UnknownProposal)?;
        if case.decision.is_some() {
            return Err(NepsisError::AlreadyDecided);
        }
        if by.trim().is_empty() {
            return Err(NepsisError::BadInput("by"));
        }
        if names_eq(by, &case.proposal.proposed_by) {
            return Err(NepsisError::SelfConsent);
        }
        if !approved && reason.trim().is_empty() {
            return Err(NepsisError::BadInput("reason"));
        }
        let by = by.trim().to_string();
        case.decision = Some(if approved {
            Decision::Approved { by, at_ms: now_ms }
        } else {
            Decision::Declined {
                by,
                reason: reason.to_string(),
                at_ms: now_ms,
            }
        });
        Ok(())
    }

    /// Fail-closed consent check: `Ok(true)` **iff** the case holds an
    /// approval; pending and declined are `Ok(false)`; an unknown id is
    /// [`NepsisError::UnknownProposal`]. Callers must treat any `Err` — any
    /// inability to obtain a `true` — as denial.
    pub fn is_clear(&self, id: &str) -> Result<bool, NepsisError> {
        let case = self
            .cases
            .iter()
            .find(|c| c.proposal.id == id)
            .ok_or(NepsisError::UnknownProposal)?;
        Ok(matches!(case.decision, Some(Decision::Approved { .. })))
    }

    /// One record per declined case, sorted by `(at_ms, id)` ascending.
    /// Approvals and pending cases do not appear.
    pub fn declined_telemetry(&self) -> Vec<DeclinedRecord> {
        let mut out: Vec<DeclinedRecord> = self
            .cases
            .iter()
            .filter_map(|c| match &c.decision {
                Some(Decision::Declined { by, reason, at_ms }) => Some(DeclinedRecord {
                    id: c.proposal.id.clone(),
                    action: c.proposal.action.clone(),
                    declined_by: by.clone(),
                    reason: reason.clone(),
                    at_ms: *at_ms,
                }),
                _ => None,
            })
            .collect();
        out.sort_by(|a, b| (a.at_ms, &a.id).cmp(&(b.at_ms, &b.id)));
        out
    }

    /// Number of cases still awaiting a decision.
    pub fn pending_count(&self) -> usize {
        self.cases.iter().filter(|c| c.decision.is_none()).count()
    }

    /// Total number of cases (pending + decided) ever proposed.
    pub fn count(&self) -> usize {
        self.cases.len()
    }
}

/// Refusals raised by the consent pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NepsisError {
    /// A required field is empty (the payload names it); also raised for an
    /// empty decider (`"by"`, argued extension).
    BadInput(&'static str),
    /// No proposal with the given id exists.
    UnknownProposal,
    /// The proposal already carries a decision; decisions are write-once.
    AlreadyDecided,
    /// The decider is the proposer — self-consent is never allowed.
    SelfConsent,
}

impl fmt::Display for NepsisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NepsisError::BadInput(reason) => write!(f, "invalid input: {reason}"),
            NepsisError::UnknownProposal => write!(f, "unknown proposal id"),
            NepsisError::AlreadyDecided => write!(f, "proposal already decided"),
            NepsisError::SelfConsent => {
                write!(f, "self-consent refused: proposer cannot decide their own proposal")
            }
        }
    }
}

impl std::error::Error for NepsisError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate_with_two() -> ConsentGate {
        let mut g = ConsentGate::default();
        g.propose("Deploy sensor", "Field test.", "alice", 100).unwrap();
        g.propose("Rotate key", "Scheduled.", "bob", 200).unwrap();
        g
    }

    // --- propose -------------------------------------------------------------

    #[test]
    fn propose_assigns_sequential_zero_padded_ids_and_records_fields() {
        let mut g = ConsentGate::default();
        assert_eq!(g.count(), 0);
        assert_eq!(g.pending_count(), 0);

        let first_id = g.propose("Deploy sensor", "Field test.", "alice", 100).unwrap().id.clone();
        assert_eq!(first_id, "pr-0001");
        {
            let p = &g.cases[0].proposal;
            assert_eq!(p.action, "Deploy sensor");
            assert_eq!(p.rationale, "Field test.");
            assert_eq!(p.proposed_by, "alice");
            assert_eq!(p.proposed_ms, 100);
        }
        let second_id = g.propose("Rotate key", "Scheduled.", "bob", 200).unwrap().id.clone();
        assert_eq!(second_id, "pr-0002");
        assert_eq!(g.count(), 2);
        assert_eq!(g.pending_count(), 2);
    }

    #[test]
    fn propose_refuses_empty_fields_and_records_nothing() {
        let mut g = ConsentGate::default();
        assert_eq!(
            g.propose("", "r", "alice", 1),
            Err(NepsisError::BadInput("action"))
        );
        assert_eq!(
            g.propose("   ", "r", "alice", 1),
            Err(NepsisError::BadInput("action"))
        );
        assert_eq!(
            g.propose("a", "", "alice", 1),
            Err(NepsisError::BadInput("rationale"))
        );
        assert_eq!(
            g.propose("a", "r", " \t ", 1),
            Err(NepsisError::BadInput("proposed_by"))
        );
        assert_eq!(g.count(), 0);
        // check order: wholly empty input names the first argument
        assert_eq!(g.propose("", "", "", 1), Err(NepsisError::BadInput("action")));
        assert_eq!(g.propose("a", "", "", 1), Err(NepsisError::BadInput("rationale")));
        assert_eq!(g.count(), 0);
    }

    #[test]
    fn propose_normalises_identity_but_stores_prose_verbatim() {
        let mut g = ConsentGate::default();
        let p = g
            .propose("  Deploy sensor  ", "  Field test.  ", "  alice  ", 100)
            .unwrap();
        // identity field: trim-normalised (case preserved for display)
        assert_eq!(p.proposed_by, "alice");
        // prose fields: exact text kept (validated on the trimmed form only)
        assert_eq!(p.action, "  Deploy sensor  ");
        assert_eq!(p.rationale, "  Field test.  ");
    }

    // --- decide: happy path --------------------------------------------------

    #[test]
    fn happy_path_propose_then_approve_clears() {
        let mut g = gate_with_two();
        assert_eq!(g.is_clear("pr-0001"), Ok(false));
        g.decide("pr-0001", true, "carol", "", 500).unwrap();
        assert_eq!(g.is_clear("pr-0001"), Ok(true));
        assert_eq!(g.pending_count(), 1);
        assert_eq!(g.count(), 2);
        // decision recorded on the case, attributed and time-stamped
        match &g.cases[0].decision {
            Some(Decision::Approved { by, at_ms }) => {
                assert_eq!(by, "carol");
                assert_eq!(*at_ms, 500);
            }
            other => panic!("expected approved, got {other:?}"),
        }
        // the other case is untouched
        assert_eq!(g.cases[1].decision, None);
    }

    #[test]
    fn decline_records_reason_and_stays_unclear() {
        let mut g = gate_with_two();
        g.decide("pr-0002", false, "carol", "Risk too high.", 600).unwrap();
        assert_eq!(g.is_clear("pr-0002"), Ok(false));
        assert_eq!(g.pending_count(), 1);
        assert_eq!(
            g.cases[1].decision,
            Some(Decision::Declined {
                by: "carol".to_string(),
                reason: "Risk too high.".to_string(),
                at_ms: 600,
            })
        );
    }

    // --- fail-closed clear gate ---------------------------------------------

    #[test]
    fn is_clear_fail_closed_for_pending_and_declined() {
        let mut g = gate_with_two();
        // pending ⇒ closed
        assert_eq!(g.is_clear("pr-0001"), Ok(false));
        assert_eq!(g.is_clear("pr-0002"), Ok(false));
        // declined ⇒ closed
        g.decide("pr-0002", false, "carol", "Not yet.", 600).unwrap();
        assert_eq!(g.is_clear("pr-0002"), Ok(false));
        // approved ⇒ the only true
        g.decide("pr-0001", true, "dave", "", 700).unwrap();
        assert_eq!(g.is_clear("pr-0001"), Ok(true));
        // unknown ⇒ error, never an accidental true (callers treat Err as denial)
        assert_eq!(g.is_clear("pr-9999"), Err(NepsisError::UnknownProposal));
        assert_eq!(g.is_clear(""), Err(NepsisError::UnknownProposal));
        assert_eq!(g.is_clear(" pr-0001"), Err(NepsisError::UnknownProposal));
    }

    // --- separation rule -----------------------------------------------------

    #[test]
    fn self_consent_refused_even_with_variant_spellings() {
        let mut g = gate_with_two();
        assert_eq!(
            g.decide("pr-0001", true, "alice", "", 700),
            Err(NepsisError::SelfConsent)
        );
        assert_eq!(
            g.decide("pr-0001", true, "  alice ", "", 700),
            Err(NepsisError::SelfConsent)
        );
        assert_eq!(
            g.decide("pr-0001", true, "ALICE", "", 700),
            Err(NepsisError::SelfConsent)
        );
        assert_eq!(
            g.decide("pr-0001", false, "Alice", "No.", 700),
            Err(NepsisError::SelfConsent)
        );
        // every refusal leaves the proposal pending
        assert_eq!(g.is_clear("pr-0001"), Ok(false));
        assert_eq!(g.pending_count(), 2);
        assert!(g.declined_telemetry().is_empty());
        // a different decider is fine
        g.decide("pr-0001", true, "carol", "", 700).unwrap();
        assert_eq!(g.is_clear("pr-0001"), Ok(true));
    }

    // --- decide: refusals ----------------------------------------------------

    #[test]
    fn double_decide_refused_and_first_decision_survives() {
        let mut g = gate_with_two();
        g.decide("pr-0001", true, "carol", "", 500).unwrap();
        let dl = g.decide("pr-0001", false, "dave", "changed mind", 600);
        assert_eq!(dl, Err(NepsisError::AlreadyDecided));
        // the approval stands, and the refused decline is not telemetry
        assert_eq!(g.is_clear("pr-0001"), Ok(true));
        assert!(g.declined_telemetry().is_empty());
    }

    #[test]
    fn decide_refuses_unknown_ids() {
        let mut g = gate_with_two();
        assert_eq!(
            g.decide("pr-0042", true, "carol", "", 1),
            Err(NepsisError::UnknownProposal)
        );
        assert_eq!(
            g.decide("", false, "carol", "why not", 1),
            Err(NepsisError::UnknownProposal)
        );
        assert_eq!(g.count(), 2);
        assert_eq!(g.pending_count(), 2);
        assert!(g.declined_telemetry().is_empty());
    }

    #[test]
    fn decline_requires_a_reason() {
        let mut g = gate_with_two();
        assert_eq!(
            g.decide("pr-0001", false, "carol", "", 500),
            Err(NepsisError::BadInput("reason"))
        );
        assert_eq!(
            g.decide("pr-0001", false, "carol", "   ", 500),
            Err(NepsisError::BadInput("reason"))
        );
        assert_eq!(g.pending_count(), 2);
        assert!(g.declined_telemetry().is_empty());
        // a reason (validated on the trimmed form) is stored verbatim
        g.decide("pr-0001", false, "carol", "  Risk too high.  ", 500).unwrap();
        assert_eq!(g.declined_telemetry()[0].reason, "  Risk too high.  ");
    }

    #[test]
    fn empty_decider_refused_argued_extension() {
        let mut g = gate_with_two();
        assert_eq!(
            g.decide("pr-0001", true, "", "", 500),
            Err(NepsisError::BadInput("by"))
        );
        assert_eq!(
            g.decide("pr-0001", false, "   ", "reason", 500),
            Err(NepsisError::BadInput("by"))
        );
        assert_eq!(g.pending_count(), 2);
    }

    #[test]
    fn decide_error_precedence_pinned() {
        let mut g = gate_with_two();
        // ① unknown id dominates everything
        assert_eq!(
            g.decide("pr-0042", true, "alice", "", 1),
            Err(NepsisError::UnknownProposal)
        );
        // ② already-decided dominates empty decider / self-consent
        g.decide("pr-0001", true, "carol", "", 500).unwrap();
        assert_eq!(
            g.decide("pr-0001", true, "", "", 600),
            Err(NepsisError::AlreadyDecided)
        );
        assert_eq!(
            g.decide("pr-0001", true, "alice", "", 600),
            Err(NepsisError::AlreadyDecided)
        );
        // ③ empty decider dominates self-consent
        assert_eq!(
            g.decide("pr-0002", true, "", "", 1),
            Err(NepsisError::BadInput("by"))
        );
        // ④ self-consent dominates the declined-reason check
        assert_eq!(
            g.decide("pr-0002", false, " bob ", "", 1),
            Err(NepsisError::SelfConsent)
        );
        // ⑤ declined-without-reason is the last refusal
        assert_eq!(
            g.decide("pr-0002", false, "carol", " ", 1),
            Err(NepsisError::BadInput("reason"))
        );
        assert_eq!(g.pending_count(), 1);
        assert!(g.declined_telemetry().is_empty());
    }

    #[test]
    fn approval_ignores_reason_argument() {
        let mut g = gate_with_two();
        g.decide("pr-0001", true, "carol", "looks good", 500).unwrap();
        match &g.cases[0].decision {
            Some(Decision::Approved { by, at_ms }) => {
                assert_eq!(by, "carol");
                assert_eq!(*at_ms, 500);
            }
            other => panic!("expected approved, got {other:?}"),
        }
        assert!(g.declined_telemetry().is_empty());
        // exact JSON pin: an approval stores no reason even if one was passed
        assert_eq!(
            serde_json::to_string(&g.cases[0].decision).unwrap(),
            r#"{"approved":{"by":"carol","at_ms":500}}"#
        );
    }

    // --- declined telemetry --------------------------------------------------

    #[test]
    fn declined_telemetry_sorted_by_at_then_id() {
        let mut g = ConsentGate::default();
        for i in 0..4 {
            g.propose(&format!("act {i}"), "why", "alice", 10).unwrap();
        }
        // declines recorded out of id and time order; two share at_ms = 300
        g.decide("pr-0004", false, "zoe", "no d", 400).unwrap();
        g.decide("pr-0002", false, "yan", "no b", 300).unwrap();
        g.decide("pr-0001", false, "xen", "no a", 300).unwrap();
        g.decide("pr-0003", true, "wes", "", 350).unwrap();

        let t = g.declined_telemetry();
        let ids: Vec<&str> = t.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["pr-0001", "pr-0002", "pr-0004"]);
        assert_eq!(
            t[0],
            DeclinedRecord {
                id: "pr-0001".to_string(),
                action: "act 0".to_string(),
                declined_by: "xen".to_string(),
                reason: "no a".to_string(),
                at_ms: 300,
            }
        );
        assert_eq!((t[1].id.as_str(), t[1].at_ms), ("pr-0002", 300));
        assert_eq!((t[2].id.as_str(), t[2].at_ms), ("pr-0004", 400));
        // approvals never appear in declined telemetry
        assert!(t.iter().all(|r| r.id != "pr-0003"));
        // repeated queries are stable
        assert_eq!(g.declined_telemetry(), t);
    }

    // --- ids -----------------------------------------------------------------

    #[test]
    fn ids_zero_pad_past_single_digits_and_never_shift() {
        let mut g = ConsentGate::default();
        for i in 1..=12 {
            let id = g.propose("act", "why", "alice", i).unwrap().id.clone();
            assert_eq!(id, format!("pr-{i:04}"));
        }
        assert_eq!(g.count(), 12);
        assert_eq!(g.cases[11].proposal.id, "pr-0012");
        // deciding does not renumber anything
        g.decide("pr-0001", true, "carol", "", 99).unwrap();
        assert_eq!(g.cases[0].proposal.id, "pr-0001");
        assert_eq!(g.cases[11].proposal.id, "pr-0012");
    }

    // --- determinism ---------------------------------------------------------

    #[test]
    fn gate_is_deterministic_across_replays() {
        let run = || {
            let mut g = ConsentGate::default();
            g.propose("Deploy sensor", "Field test.", "alice", 100).unwrap();
            g.propose("Rotate key", "Scheduled.", "bob", 200).unwrap();
            g.propose("Retire node", "EOL.", "carol", 300).unwrap();
            g.decide("pr-0002", true, "dave", "", 400).unwrap();
            g.decide("pr-0003", false, "erin", "not yet", 450).unwrap();
            (
                g.cases.clone(),
                g.declined_telemetry(),
                g.pending_count(),
                g.count(),
            )
        };
        let a = run();
        let b = run();
        assert_eq!(a, b);
        // and the replay's telemetry matches the pinned shape
        assert_eq!(a.1.len(), 1);
        assert_eq!(
            (a.1[0].id.as_str(), a.1[0].declined_by.as_str(), a.1[0].at_ms),
            ("pr-0003", "erin", 450)
        );
        assert_eq!((a.2, a.3), (1, 3));
    }

    // --- serde ---------------------------------------------------------------

    #[test]
    fn consent_case_serde_roundtrip_and_exact_json() {
        let pending = ConsentCase {
            proposal: Proposal {
                id: "pr-0001".to_string(),
                action: "Deploy sensor".to_string(),
                rationale: "Field test.".to_string(),
                proposed_by: "alice".to_string(),
                proposed_ms: 100,
            },
            decision: None,
        };
        let pj = serde_json::to_string(&pending).unwrap();
        assert_eq!(
            pj,
            r#"{"proposal":{"id":"pr-0001","action":"Deploy sensor","rationale":"Field test.","proposed_by":"alice","proposed_ms":100},"decision":null}"#
        );
        assert_eq!(serde_json::from_str::<ConsentCase>(&pj).unwrap(), pending);

        let approved = ConsentCase {
            proposal: pending.proposal.clone(),
            decision: Some(Decision::Approved {
                by: "carol".to_string(),
                at_ms: 500,
            }),
        };
        let aj = serde_json::to_string(&approved).unwrap();
        assert_eq!(
            aj,
            r#"{"proposal":{"id":"pr-0001","action":"Deploy sensor","rationale":"Field test.","proposed_by":"alice","proposed_ms":100},"decision":{"approved":{"by":"carol","at_ms":500}}}"#
        );
        assert_eq!(serde_json::from_str::<ConsentCase>(&aj).unwrap(), approved);

        // a gate-built case serializes identically
        let mut g = gate_with_two();
        g.decide("pr-0001", true, "carol", "", 500).unwrap();
        assert_eq!(serde_json::to_string(&g.cases[0]).unwrap(), aj);
    }

    #[test]
    fn decision_and_record_serde_exact_json_and_roundtrip() {
        let ap = Decision::Approved {
            by: "carol".to_string(),
            at_ms: 500,
        };
        let apj = serde_json::to_string(&ap).unwrap();
        assert_eq!(apj, r#"{"approved":{"by":"carol","at_ms":500}}"#);
        assert_eq!(serde_json::from_str::<Decision>(&apj).unwrap(), ap);

        let de = Decision::Declined {
            by: "dave".to_string(),
            reason: "Cost.".to_string(),
            at_ms: 600,
        };
        let dej = serde_json::to_string(&de).unwrap();
        assert_eq!(dej, r#"{"declined":{"by":"dave","reason":"Cost.","at_ms":600}}"#);
        assert_eq!(serde_json::from_str::<Decision>(&dej).unwrap(), de);

        let record = DeclinedRecord {
            id: "pr-0002".to_string(),
            action: "Rotate key".to_string(),
            declined_by: "dave".to_string(),
            reason: "Cost.".to_string(),
            at_ms: 600,
        };
        let rj = serde_json::to_string(&record).unwrap();
        assert_eq!(
            rj,
            r#"{"id":"pr-0002","action":"Rotate key","declined_by":"dave","reason":"Cost.","at_ms":600}"#
        );
        assert_eq!(serde_json::from_str::<DeclinedRecord>(&rj).unwrap(), record);
    }

    #[test]
    fn nepsis_error_serde_and_display_pins() {
        assert_eq!(
            serde_json::to_string(&NepsisError::BadInput("action")).unwrap(),
            r#"{"bad_input":"action"}"#
        );
        assert_eq!(
            serde_json::to_string(&NepsisError::UnknownProposal).unwrap(),
            "\"unknown_proposal\""
        );
        assert_eq!(
            serde_json::to_string(&NepsisError::AlreadyDecided).unwrap(),
            "\"already_decided\""
        );
        assert_eq!(
            serde_json::to_string(&NepsisError::SelfConsent).unwrap(),
            "\"self_consent\""
        );

        assert_eq!(NepsisError::BadInput("action").to_string(), "invalid input: action");
        assert_eq!(NepsisError::UnknownProposal.to_string(), "unknown proposal id");
        assert_eq!(
            NepsisError::AlreadyDecided.to_string(),
            "proposal already decided"
        );
        assert_eq!(
            NepsisError::SelfConsent.to_string(),
            "self-consent refused: proposer cannot decide their own proposal"
        );

        // usable as a std::error::Error
        let e: Box<dyn std::error::Error> = Box::new(NepsisError::SelfConsent);
        assert_eq!(
            e.to_string(),
            "self-consent refused: proposer cannot decide their own proposal"
        );
    }
}
