//! Indicator registry — I&W (indications & warning) watch loops.
//!
//! Frozen interface §7, tasks B5.1.1–B5.1.3. An *indicator* is an observable
//! condition whose observed motion would betray an adversary's preparation or
//! intent; a registry of them is the raw material of indications & warning.
//!
//! # B5.1.1 — Pherson criteria gate ([`Criteria`], [`IndicatorRegistry::register`])
//! An indicator may only be watched if it passes **all five** Pherson
//! criteria — [`observable`](Criteria::observable),
//! [`valid`](Criteria::valid), [`reliable`](Criteria::reliable),
//! [`stable`](Criteria::stable), [`unique`](Criteria::unique) (an indicator
//! that is not unique, for example, fires on ambient noise and drowns the
//! signal). [`register`](IndicatorRegistry::register) refuses any candidate
//! that fails the gate with [`IndicatorError::CriteriaUnmet`] carrying the
//! comma-joined (`", "`) names of the false criteria in struct-declaration
//! order — a warning system must not watch indicators it cannot stand behind.
//! Lifecycle: an accepted indicator starts [`Draft`](IndicatorStatus::Draft);
//! [`activate`](IndicatorRegistry::activate) moves it to
//! [`Active`](IndicatorStatus::Active); [`retire`](IndicatorRegistry::retire)
//! moves any non-retired indicator to the terminal
//! [`Retired`](IndicatorStatus::Retired) state. `Retired` is terminal —
//! re-retiring, or activating/checking a retired indicator, is a
//! [`BadTransition`](IndicatorError::BadTransition).
//!
//! # B5.1.2 — check counting & false-positive tracking ([`IndicatorRegistry::record_check`], [`IndicatorRegistry::fp_rate`])
//! Only `Active` indicators are checked. Each recorded check increments
//! [`checks`](Indicator::checks) and, when `hit`, [`hits`](Indicator::hits),
//! and when `false_positive`, [`false_positives`](Indicator::false_positives).
//! A single check cannot be *both* a hit and a false positive — that
//! contradiction is refused ([`IndicatorError::BadInput`]`("false_positive")`)
//! and nothing is counted. [`fp_rate`](IndicatorRegistry::fp_rate) reports
//! `false_positives / checks`, defined as `0.0` when no check has been
//! recorded (0/0 is a contract, not a crash); it is a plain read that works
//! on any live indicator, checked or not.
//!
//! # B5.1.3 — escalation ([`IndicatorRegistry::escalations`])
//! [`escalations`](IndicatorRegistry::escalations) is the watch-loop pull
//! surface: the `Active` indicators whose `hits` reach a caller-set threshold
//! (`hits >= threshold`, equality included — a threshold is a floor, not an
//! exclusive bar), sorted most-hits-first, ties by id ascending, so an
//! operator consumes them in a stable order.
//!
//! # Pinned decisions (interface silent; chosen and tested here)
//! - "Empty text" means `text.trim().is_empty()` — whitespace-only text is
//!   empty (batch-10 house style, e.g. `unknowns`/`liaison`).
//! - `register` validates text before the criteria gate (interface order):
//!   empty text + unmet criteria yields `BadInput("text")`.
//! - `record_check` validates state before flags: a non-`Active` indicator
//!   with `hit && false_positive` yields `BadTransition`, not `BadInput`.
//! - Ids are `ind-<seq:03>` with `seq = len + 1`; nothing is ever removed, so
//!   ids are monotonic for the life of a registry.
//! - Wire names are serde's verbatim variant names (`"Draft"`, `"Active"`,
//!   `"Retired"`, `"BadInput"`, …) — the interface pins `snake_case` renames
//!   only where it says so (§1's `Decision`), and §7 does not.
//! - [`IndicatorError`] derives `Serialize` but not `Deserialize`: its
//!   `BadInput(&'static str)` payload cannot be deserialized into `'static`
//!   (in-repo precedent: `clearness_gate`, `unknowns`, `vouching`).
//!
//! # Scope / integration
//! Pure in-memory bookkeeping: no I/O, no clock, no globals. Not wired into
//! `lib.rs` yet (the parent does that). Intended consumers: the watch loop
//! (`escalations` after each collection cycle), the warning desk
//! (`fp_rate` to retire noisy indicators), and the ledger (serde forms of
//! [`Indicator`] travel as stable records).

use serde::{Deserialize, Serialize};

/// The five Pherson criteria an indicator must pass to be watchable.
///
/// Every field must be `true` for [`passes`](Criteria::passes); a false field
/// is named by [`missing`](Criteria::missing) in struct-declaration order
/// (`observable`, `valid`, `reliable`, `stable`, `unique`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Criteria {
    /// The condition can actually be observed with available collection.
    pub observable: bool,
    /// The condition logically bears on the hypothesis it is meant to warn of.
    pub valid: bool,
    /// Collection on the condition produces trustworthy data.
    pub reliable: bool,
    /// The condition's baseline is steady enough that deviation is signal.
    pub stable: bool,
    /// The condition is not duplicated by cheaper or more general indicators.
    pub unique: bool,
}

impl Criteria {
    /// All five criteria met.
    pub fn passes(&self) -> bool {
        self.observable && self.valid && self.reliable && self.stable && self.unique
    }

    /// Names of the criteria that are `false`, in struct-declaration order.
    ///
    /// The returned names are the field names exactly (`"observable"`,
    /// `"valid"`, `"reliable"`, `"stable"`, `"unique"`); empty iff
    /// [`passes`](Criteria::passes).
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.observable {
            missing.push("observable");
        }
        if !self.valid {
            missing.push("valid");
        }
        if !self.reliable {
            missing.push("reliable");
        }
        if !self.stable {
            missing.push("stable");
        }
        if !self.unique {
            missing.push("unique");
        }
        missing
    }
}

/// Where an indicator sits in its lifecycle (B5.1.1).
///
/// `Draft` — admitted, not yet watched. `Active` — being checked. `Retired` —
/// terminal; kept for the record, never re-activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorStatus {
    /// Admitted by the criteria gate, not yet watched.
    Draft,
    /// Watched: `record_check` accepts it, `escalations` can return it.
    Active,
    /// Terminal: no further checks or transitions.
    Retired,
}

/// One registered indicator with its lifetime check accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    /// Registry-assigned id, `ind-<seq:03>` (`ind-001`, `ind-002`, …).
    pub id: String,
    /// The observable condition being watched (verbatim as registered).
    pub text: String,
    /// The Pherson criteria this indicator was admitted under.
    pub criteria: Criteria,
    /// Total checks recorded while `Active`.
    pub checks: u32,
    /// Checks that counted as hits.
    pub hits: u32,
    /// Checks that counted as false positives.
    pub false_positives: u32,
    /// Lifecycle state.
    pub status: IndicatorStatus,
}

/// Errors from registry operations.
///
/// `Serialize` is derived; `Deserialize` is not — `BadInput(&'static str)`
/// cannot be deserialized into a `'static` lifetime (in-repo precedent:
/// `clearness_gate`, `unknowns`, `vouching`). Diagnostic strings here are
/// serialized verbatim (`"BadInput"`, `"CriteriaUnmet"`, …).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IndicatorError {
    /// A required input was empty or otherwise malformed; carries the
    /// field/reason name (`"text"`, `"false_positive"`).
    BadInput(&'static str),
    /// The Pherson gate refused the candidate; carries the comma-joined
    /// (`", "`) names of the unmet criteria in declaration order.
    CriteriaUnmet(String),
    /// No indicator with the given id exists in this registry.
    UnknownIndicator,
    /// The operation is not legal from the indicator's current status.
    BadTransition,
}

impl std::fmt::Display for IndicatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndicatorError::BadInput(reason) => write!(f, "invalid input: {reason}"),
            IndicatorError::CriteriaUnmet(missing) => {
                write!(f, "criteria unmet: {missing}")
            }
            IndicatorError::UnknownIndicator => write!(f, "unknown indicator id"),
            IndicatorError::BadTransition => write!(f, "invalid indicator status transition"),
        }
    }
}

impl std::error::Error for IndicatorError {}

/// The registry: an ordered set of [`Indicator`]s, ids `ind-001` upward.
///
/// Private field — construct with [`IndicatorRegistry::new`] (or `Default`),
/// add via [`register`](IndicatorRegistry::register). No removal: retiral is
/// a status change, so ids stay monotonic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndicatorRegistry {
    indicators: Vec<Indicator>,
}

impl IndicatorRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of indicators registered (all statuses).
    pub fn count(&self) -> usize {
        self.indicators.len()
    }

    /// Look up an indicator by id.
    pub fn get(&self, id: &str) -> Option<&Indicator> {
        self.indicators.iter().find(|i| i.id == id)
    }

    /// Admit an indicator candidate (B5.1.1, Pherson gate).
    ///
    /// Empty (`trim()`) `text` ⇒ [`IndicatorError::BadInput`]`("text")`;
    /// otherwise a candidate failing any Pherson criterion is refused with
    /// [`IndicatorError::CriteriaUnmet`] carrying the comma-joined missing
    /// names. Admitted indicators get the next id (`ind-<seq:03>`, `seq =
    /// len + 1`), zeroed counters, and [`IndicatorStatus::Draft`].
    pub fn register(
        &mut self,
        text: &str,
        criteria: Criteria,
    ) -> Result<&Indicator, IndicatorError> {
        if text.trim().is_empty() {
            return Err(IndicatorError::BadInput("text"));
        }
        if !criteria.passes() {
            return Err(IndicatorError::CriteriaUnmet(criteria.missing().join(", ")));
        }
        let id = format!("ind-{:03}", self.indicators.len() + 1);
        self.indicators.push(Indicator {
            id,
            text: text.to_string(),
            criteria,
            checks: 0,
            hits: 0,
            false_positives: 0,
            status: IndicatorStatus::Draft,
        });
        Ok(self.indicators.last().expect("just pushed"))
    }

    /// Begin watching a `Draft` indicator: `Draft` ⇒ `Active`.
    ///
    /// Any other current status (`Active`, `Retired`) ⇒
    /// [`IndicatorError::BadTransition`]; unknown id ⇒
    /// [`IndicatorError::UnknownIndicator`].
    pub fn activate(&mut self, id: &str) -> Result<(), IndicatorError> {
        let indicator = self.find_mut(id)?;
        if indicator.status != IndicatorStatus::Draft {
            return Err(IndicatorError::BadTransition);
        }
        indicator.status = IndicatorStatus::Active;
        Ok(())
    }

    /// Record one check result on an `Active` indicator (B5.1.2).
    ///
    /// `Active` only — any other status ⇒ [`IndicatorError::BadTransition`]
    /// (state is validated before the flags). `hit && false_positive` is a
    /// contradiction and is refused with [`IndicatorError::BadInput`]
    /// (`"false_positive"`), counting nothing; otherwise `checks` is always
    /// incremented and `hits` / `false_positives` follow their flags.
    pub fn record_check(
        &mut self,
        id: &str,
        hit: bool,
        false_positive: bool,
    ) -> Result<(), IndicatorError> {
        let indicator = self.find_mut(id)?;
        if indicator.status != IndicatorStatus::Active {
            return Err(IndicatorError::BadTransition);
        }
        if hit && false_positive {
            return Err(IndicatorError::BadInput("false_positive"));
        }
        indicator.checks += 1;
        if hit {
            indicator.hits += 1;
        }
        if false_positive {
            indicator.false_positives += 1;
        }
        Ok(())
    }

    /// False-positive rate of an indicator: `false_positives / checks`.
    ///
    /// `0.0` when no check has been recorded (0/0 is a contract, not an
    /// error). A plain read — works on any status; unknown id ⇒
    /// [`IndicatorError::UnknownIndicator`].
    pub fn fp_rate(&self, id: &str) -> Result<f64, IndicatorError> {
        let indicator = self
            .indicators
            .iter()
            .find(|i| i.id == id)
            .ok_or(IndicatorError::UnknownIndicator)?;
        if indicator.checks == 0 {
            return Ok(0.0);
        }
        Ok(f64::from(indicator.false_positives) / f64::from(indicator.checks))
    }

    /// The escalated set (B5.1.3): `Active` indicators with `hits >=
    /// threshold` (equality included), sorted hits descending, ties by id
    /// ascending.
    pub fn escalations(&self, threshold: u32) -> Vec<&Indicator> {
        let mut escalated: Vec<&Indicator> = self
            .indicators
            .iter()
            .filter(|i| i.status == IndicatorStatus::Active && i.hits >= threshold)
            .collect();
        escalated.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.id.cmp(&b.id)));
        escalated
    }

    /// Retire an indicator: any non-`Retired` status ⇒ `Retired` (terminal).
    ///
    /// Already `Retired` ⇒ [`IndicatorError::BadTransition`]; unknown id ⇒
    /// [`IndicatorError::UnknownIndicator`].
    pub fn retire(&mut self, id: &str) -> Result<(), IndicatorError> {
        let indicator = self.find_mut(id)?;
        if indicator.status == IndicatorStatus::Retired {
            return Err(IndicatorError::BadTransition);
        }
        indicator.status = IndicatorStatus::Retired;
        Ok(())
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut Indicator, IndicatorError> {
        self.indicators
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(IndicatorError::UnknownIndicator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Criteria that pass all five gates.
    fn all_pass() -> Criteria {
        Criteria {
            observable: true,
            valid: true,
            reliable: true,
            stable: true,
            unique: true,
        }
    }

    /// Criteria with the named fields (by field name) set false.
    fn failing(names: &[&str]) -> Criteria {
        let mut c = all_pass();
        for name in names {
            match *name {
                "observable" => c.observable = false,
                "valid" => c.valid = false,
                "reliable" => c.reliable = false,
                "stable" => c.stable = false,
                "unique" => c.unique = false,
                other => panic!("unknown criteria name in test: {other}"),
            }
        }
        c
    }

    /// A registry with `n` active indicators, checks mottling hits/fps.
    fn active(n: usize) -> IndicatorRegistry {
        let mut r = IndicatorRegistry::new();
        for i in 0..n {
            let id = r
                .register(&format!("indicator {i}"), all_pass())
                .unwrap()
                .id
                .clone();
            r.activate(&id).unwrap();
        }
        r
    }

    // ---------- B5.1.1: criteria gate ----------------------------------

    #[test]
    fn criteria_passes_requires_all_five() {
        assert!(all_pass().passes());
        for name in ["observable", "valid", "reliable", "stable", "unique"] {
            assert!(
                !failing(&[name]).passes(),
                "single false criterion {name} must fail the gate"
            );
        }
        assert!(!Criteria {
            observable: false,
            valid: false,
            reliable: false,
            stable: false,
            unique: false,
        }
        .passes());
    }

    #[test]
    fn criteria_missing_names_false_fields_in_declaration_order() {
        assert_eq!(all_pass().missing(), Vec::<&'static str>::new());
        // Given out of order, reported in struct-declaration order.
        assert_eq!(failing(&["stable", "observable"]).missing(), vec!["observable", "stable"]);
        assert_eq!(failing(&["unique"]).missing(), vec!["unique"]);
        assert_eq!(
            failing(&["unique", "valid", "reliable", "observable", "stable"]).missing(),
            vec!["observable", "valid", "reliable", "stable", "unique"]
        );
    }

    #[test]
    fn register_admits_and_assigns_sequential_ids_draft() {
        let mut r = IndicatorRegistry::new();
        let first = r.register("first signal", all_pass()).unwrap();
        assert_eq!(first.id, "ind-001");
        assert_eq!(first.text, "first signal");
        assert_eq!(first.criteria, all_pass());
        assert_eq!(first.checks, 0);
        assert_eq!(first.hits, 0);
        assert_eq!(first.false_positives, 0);
        assert_eq!(first.status, IndicatorStatus::Draft);

        let second = r.register("second signal", all_pass()).unwrap();
        assert_eq!(second.id, "ind-002");
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn register_rejects_empty_and_whitespace_only_text() {
        let mut r = IndicatorRegistry::new();
        assert_eq!(r.register("", all_pass()), Err(IndicatorError::BadInput("text")));
        assert_eq!(
            r.register("   \t\n", all_pass()),
            Err(IndicatorError::BadInput("text"))
        );
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn register_refuses_unmet_criteria_with_comma_joined_missing() {
        let mut r = IndicatorRegistry::new();
        let err = r.register("noise", failing(&["observable", "stable"])).unwrap_err();
        assert_eq!(err, IndicatorError::CriteriaUnmet("observable, stable".to_string()));
        assert_eq!(err.to_string(), "criteria unmet: observable, stable");

        // Single missing criterion: no dangling separator.
        let err = r.register("noise", failing(&["unique"])).unwrap_err();
        assert_eq!(err, IndicatorError::CriteriaUnmet("unique".to_string()));

        assert_eq!(r.count(), 0, "refused candidates must not be registered");
    }

    #[test]
    fn register_validates_text_before_the_criteria_gate() {
        let mut r = IndicatorRegistry::new();
        // Both invalid: text wins (interface order).
        assert_eq!(
            r.register("", failing(&["stable"])),
            Err(IndicatorError::BadInput("text"))
        );
    }

    // ---------- B5.1.1: lifecycle transitions --------------------------

    #[test]
    fn activate_draft_and_retire_from_active() {
        let mut r = active(1);
        assert_eq!(r.get("ind-001").unwrap().status, IndicatorStatus::Active);
        r.retire("ind-001").unwrap();
        assert_eq!(r.get("ind-001").unwrap().status, IndicatorStatus::Retired);
    }

    #[test]
    fn activate_refuses_active_and_retired() {
        let mut r = active(1);
        assert_eq!(r.activate("ind-001"), Err(IndicatorError::BadTransition));
        r.register("second", all_pass()).unwrap();
        r.retire("ind-002").unwrap();
        assert_eq!(r.activate("ind-002"), Err(IndicatorError::BadTransition));
    }

    #[test]
    fn retire_from_draft_allowed_and_retired_is_terminal() {
        let mut r = IndicatorRegistry::new();
        r.register("stillborn", all_pass()).unwrap();
        r.retire("ind-001").unwrap(); // Draft ⇒ Retired allowed
        assert_eq!(r.get("ind-001").unwrap().status, IndicatorStatus::Retired);
        // Retired is terminal: retire again, activate, check — all refused.
        assert_eq!(r.retire("ind-001"), Err(IndicatorError::BadTransition));
        assert_eq!(r.activate("ind-001"), Err(IndicatorError::BadTransition));
        assert_eq!(
            r.record_check("ind-001", false, false),
            Err(IndicatorError::BadTransition)
        );
    }

    #[test]
    fn by_id_operations_reject_unknown_ids() {
        let mut r = active(1);
        assert_eq!(r.activate("ind-999"), Err(IndicatorError::UnknownIndicator));
        assert_eq!(r.retire("ind-999"), Err(IndicatorError::UnknownIndicator));
        assert_eq!(
            r.record_check("ind-999", true, false),
            Err(IndicatorError::UnknownIndicator)
        );
        assert_eq!(r.fp_rate("ind-999"), Err(IndicatorError::UnknownIndicator));
        assert!(r.get("ind-999").is_none());
    }

    // ---------- B5.1.2: check counting & false positives ----------------

    #[test]
    fn record_check_counts_checks_hits_and_false_positives() {
        let mut r = active(1);
        r.record_check("ind-001", true, false).unwrap();
        r.record_check("ind-001", false, true).unwrap();
        r.record_check("ind-001", false, false).unwrap();
        let i = r.get("ind-001").unwrap();
        assert_eq!((i.checks, i.hits, i.false_positives), (3, 1, 1));
    }

    #[test]
    fn record_check_rejects_hit_and_false_positive_together() {
        let mut r = active(1);
        r.record_check("ind-001", true, false).unwrap();
        assert_eq!(
            r.record_check("ind-001", true, true),
            Err(IndicatorError::BadInput("false_positive"))
        );
        let i = r.get("ind-001").unwrap();
        assert_eq!((i.checks, i.hits, i.false_positives), (1, 1, 0), "rejected check must not count");
    }

    #[test]
    fn record_check_requires_active_state_first() {
        let mut r = IndicatorRegistry::new();
        r.register("draft", all_pass()).unwrap();
        assert_eq!(
            r.record_check("ind-001", false, false),
            Err(IndicatorError::BadTransition)
        );
        // State is validated before flags: Draft + contradictory flags ⇒
        // BadTransition, not BadInput.
        assert_eq!(
            r.record_check("ind-001", true, true),
            Err(IndicatorError::BadTransition)
        );
        r.activate("ind-001").unwrap();
        r.record_check("ind-001", true, false).unwrap();
        r.retire("ind-001").unwrap();
        assert_eq!(
            r.record_check("ind-001", true, false),
            Err(IndicatorError::BadTransition)
        );
    }

    #[test]
    fn fp_rate_zero_checks_is_zero() {
        let mut r = IndicatorRegistry::new();
        r.register("never checked", all_pass()).unwrap();
        assert_eq!(r.fp_rate("ind-001"), Ok(0.0)); // Draft, 0 checks
        r.activate("ind-001").unwrap();
        assert_eq!(r.fp_rate("ind-001"), Ok(0.0)); // Active, 0 checks
        r.record_check("ind-001", true, false).unwrap();
        assert_eq!(r.fp_rate("ind-001"), Ok(0.0)); // checked, no fps
    }

    #[test]
    fn fp_rate_pins() {
        let mut r = active(1);
        // 4 checks, 1 fp ⇒ exactly 0.25.
        r.record_check("ind-001", true, false).unwrap();
        r.record_check("ind-001", false, true).unwrap();
        r.record_check("ind-001", false, false).unwrap();
        r.record_check("ind-001", true, false).unwrap();
        assert_eq!(r.fp_rate("ind-001"), Ok(0.25));

        // 3 checks, 1 fp ⇒ 1/3 within epsilon.
        let mut r2 = active(1);
        r2.record_check("ind-001", false, true).unwrap();
        r2.record_check("ind-001", true, false).unwrap();
        r2.record_check("ind-001", false, false).unwrap();
        let rate = r2.fp_rate("ind-001").unwrap();
        assert!((rate - 1.0 / 3.0).abs() < 1e-12, "got {rate}");

        // All false positives ⇒ 1.0 (≤ 1 by construction).
        let mut r3 = active(1);
        r3.record_check("ind-001", false, true).unwrap();
        r3.record_check("ind-001", false, true).unwrap();
        assert_eq!(r3.fp_rate("ind-001"), Ok(1.0));
    }

    // ---------- B5.1.3: escalation --------------------------------------

    #[test]
    fn escalations_threshold_equality_and_hits_desc_id_asc() {
        let mut r = active(3);
        for _ in 0..3 {
            r.record_check("ind-001", true, false).unwrap();
        }
        for _ in 0..5 {
            r.record_check("ind-002", true, false).unwrap();
        }
        for _ in 0..5 {
            r.record_check("ind-003", true, false).unwrap();
        }
        // Equality included: hits 5 == threshold 5.
        let top = r.escalations(5);
        assert_eq!(
            top.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["ind-002", "ind-003"]
        );
        // Full order: hits desc, ties by id asc.
        let all = r.escalations(3);
        assert_eq!(
            all.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["ind-002", "ind-003", "ind-001"]
        );
        // Above everything: empty.
        assert!(r.escalations(6).is_empty());
    }

    #[test]
    fn escalations_excludes_draft_and_retired() {
        let mut r = active(2);
        for _ in 0..4 {
            r.record_check("ind-001", true, false).unwrap();
        }
        for _ in 0..4 {
            r.record_check("ind-002", true, false).unwrap();
        }
        // Draft with no checks, retired with hits: neither escalates.
        r.register("draft", all_pass()).unwrap();
        r.retire("ind-001").unwrap();
        let escalated = r.escalations(4);
        assert_eq!(
            escalated.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["ind-002"]
        );
        // Retired keeps its recorded hits even though it never escalates.
        assert_eq!(r.get("ind-001").unwrap().hits, 4);
    }

    #[test]
    fn escalations_threshold_zero_lists_all_active_by_id() {
        let mut r = active(2);
        r.record_check("ind-002", true, false).unwrap();
        let all = r.escalations(0);
        assert_eq!(
            all.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["ind-002", "ind-001"] // 1 hit before 0 hits
        );
        assert_eq!(all.len(), 2);
    }

    // ---------- cross-cutting: errors, determinism, serde ----------------

    #[test]
    fn error_display_and_std_error() {
        assert_eq!(
            IndicatorError::BadInput("text").to_string(),
            "invalid input: text"
        );
        assert_eq!(
            IndicatorError::CriteriaUnmet("stable".to_string()).to_string(),
            "criteria unmet: stable"
        );
        assert_eq!(
            IndicatorError::UnknownIndicator.to_string(),
            "unknown indicator id"
        );
        assert_eq!(
            IndicatorError::BadTransition.to_string(),
            "invalid indicator status transition"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(IndicatorError::UnknownIndicator);
        assert!(boxed.source().is_none());
    }

    #[test]
    fn operations_are_deterministic_across_runs() {
        fn run() -> IndicatorRegistry {
            let mut r = IndicatorRegistry::new();
            r.register("alpha", all_pass()).unwrap();
            assert!(r.register("beta", failing(&["stable"])).is_err()); // refused — must not affect ids
            r.register("gamma", all_pass()).unwrap();
            r.activate("ind-001").unwrap();
            r.record_check("ind-001", true, false).unwrap();
            r.record_check("ind-001", false, true).unwrap();
            r.retire("ind-002").unwrap();
            r
        }
        let (a, b) = (run(), run());
        assert_eq!(a, b);
        assert_eq!(a.count(), 2);
        assert_eq!(a.get("ind-002").unwrap().id, "ind-002");
        assert_eq!(b.fp_rate("ind-001"), a.fp_rate("ind-001"));
    }

    #[test]
    fn serde_json_shapes_of_indicator_status_and_criteria() {
        // Verbatim variant names (no rename_all in §7).
        assert_eq!(serde_json::to_value(IndicatorStatus::Draft).unwrap(), serde_json::json!("Draft"));
        assert_eq!(
            serde_json::to_value(IndicatorStatus::Active).unwrap(),
            serde_json::json!("Active")
        );
        assert_eq!(
            serde_json::to_value(IndicatorStatus::Retired).unwrap(),
            serde_json::json!("Retired")
        );
        // Criteria: five boolean fields under their own names.
        assert_eq!(
            serde_json::to_value(all_pass()).unwrap(),
            serde_json::json!({
                "observable": true, "valid": true, "reliable": true,
                "stable": true, "unique": true
            })
        );
        // Roundtrip both ways.
        let c: Criteria =
            serde_json::from_value(serde_json::json!({"observable": true, "valid": false, "reliable": true, "stable": true, "unique": false})).unwrap();
        assert_eq!(c.missing(), vec!["valid", "unique"]);
        let s: IndicatorStatus = serde_json::from_value(serde_json::json!("Retired")).unwrap();
        assert_eq!(s, IndicatorStatus::Retired);
    }

    #[test]
    fn indicator_serde_roundtrip_and_wire_field_names() {
        let mut r = active(1);
        r.record_check("ind-001", true, false).unwrap();
        r.record_check("ind-001", false, true).unwrap();
        let indicator = r.get("ind-001").unwrap().clone();

        let value = serde_json::to_value(&indicator).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "id": "ind-001", "text": "indicator 0",
                "criteria": {"observable": true, "valid": true, "reliable": true,
                             "stable": true, "unique": true},
                "checks": 2, "hits": 1, "false_positives": 1, "status": "Active"
            })
        );
        let back: Indicator = serde_json::from_value(value).unwrap();
        assert_eq!(back, indicator);
    }

    #[test]
    fn indicator_error_serializes_verbatim_variants() {
        assert_eq!(
            serde_json::to_value(IndicatorError::BadInput("text")).unwrap(),
            serde_json::json!({"BadInput": "text"})
        );
        assert_eq!(
            serde_json::to_value(IndicatorError::CriteriaUnmet("observable, stable".to_string()))
                .unwrap(),
            serde_json::json!({"CriteriaUnmet": "observable, stable"})
        );
        assert_eq!(
            serde_json::to_value(IndicatorError::UnknownIndicator).unwrap(),
            serde_json::json!("UnknownIndicator")
        );
        assert_eq!(
            serde_json::to_value(IndicatorError::BadTransition).unwrap(),
            serde_json::json!("BadTransition")
        );
    }
}
