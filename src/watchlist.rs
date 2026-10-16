//! Horizon-scan watchlist (tasks B4.2.1–B4.2.3, frozen interface §6).
//!
//! A [`Watchlist`] holds *targets* — horizon-scanning sources scanned on a
//! cadence — plus *event triggers* recorded against them. Three semantics are
//! pinned here:
//!
//! 1. **Cadence scheduling.** Adding a target schedules it immediately
//!    (`next_due_ms = now`). [`Watchlist::mark_checked`] is the only way the
//!    scan clock advances: it stamps `last_checked_ms = now` and
//!    `next_due_ms = now + cadence_ms` (*saturating* — a cadence can never
//!    wrap the clock). [`Watchlist::due`] returns every scheduled target with
//!    `next_due ≤ now`; the comparison is inclusive, so a target exactly at
//!    its due instant *is* due.
//! 2. **Triggers are annotations, not schedules.** [`Watchlist::trigger`]
//!    records an observed event against a live target and deliberately does
//!    *not* touch the cadence — an event never silently resets the scan
//!    clock. The operator decides what an event means; the schedule keeps
//!    running.
//! 3. **PQC seeds are hints only.** [`seed_pqc_milestones`] returns
//!    `(name, source_hint)` template pairs for post-quantum-migration
//!    milestones (B4.2.3). Every hint carries the explicit
//!    [`VERIFY_BEFORE_ADDING`] marker, and nothing is ever auto-added: the
//!    caller reviews a hint and decides.
//!
//! Everything here is a **pure** function of its arguments — no clock reads,
//! no randomness — so a replay with the same `now_ms` values reproduces
//! identical scheduling, ordering and seeds.
//!
//! # Pinned interpretations
//!
//! Frozen §6 says "exactly"; these are the readings where the text was
//! ambiguous (argued in the AGT-116 batch-11 report):
//!
//! - "Empty" means empty **or whitespace-only**, matching in-repo precedent
//!   (`liaison`, `unknowns`). Stored strings are kept verbatim (never
//!   trimmed).
//! - A target with **no schedule** (`next_due_ms == None`) is never due — it
//!   has no due instant to compare. The public API always schedules targets,
//!   so `None` only appears on hand-built values; treating it as "due now"
//!   would fire scans that were never asked for.
//! - Tag matching ([`Watchlist::by_tag`]) is exact and case-sensitive.
//! - [`Watchlist::trigger`] validates the event first, then the target
//!   (`BadInput("event")` precedes `UnknownTarget`), and a failed call
//!   records nothing.
//! - Ids come from the live sequence (`wl-<seq:03>`, sequence from 1);
//!   rejected calls never consume an id (matching `unknowns` precedent).

use serde::{Deserialize, Serialize};

/// The marker every [`seed_pqc_milestones`] hint must carry (B4.2.3 pin).
///
/// Additive to the frozen §6 surface: it makes the "seeds are hints, not
/// facts to trust blindly" contract machine-checkable instead of a string
/// convention buried in tests.
pub const VERIFY_BEFORE_ADDING: &str = "verify before adding";

/// One horizon-scan target: where to look, how often, and when it is next
/// due.
///
/// `cadence_ms` is the scan interval in milliseconds and is always positive.
/// `last_checked_ms` is `None` until the first [`Watchlist::mark_checked`];
/// `next_due_ms` is set at [`Watchlist::add`] time (`now`) and advanced only
/// by [`Watchlist::mark_checked`] — triggers never move it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchTarget {
    /// Stable id, `wl-<seq:03>` (sequence from 1, rejected adds consume
    /// nothing).
    pub id: String,
    /// Human-readable target name (stored verbatim).
    pub name: String,
    /// Source hint: where this target is scanned (stored verbatim).
    pub source: String,
    /// Scan cadence in ms; validated `> 0` on add.
    pub cadence_ms: i64,
    /// When the target was last checked, or `None` if never.
    pub last_checked_ms: Option<i64>,
    /// The next due instant; `None` only on hand-built values ("no
    /// schedule" — such targets are never due).
    pub next_due_ms: Option<i64>,
    /// Free-form tags for grouping ([`Watchlist::by_tag`]); stored in the
    /// given order, exact case.
    pub tags: Vec<String>,
}

/// One observed event, recorded against a target via
/// [`Watchlist::trigger`].
///
/// `target` is the target's id. Triggers are append-only annotations:
/// recording one never mutates the target's cadence or schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trigger {
    /// Id of the target this event was observed for.
    pub target: String,
    /// What happened (stored verbatim; must be non-empty on record).
    pub event: String,
    /// When the event was observed (ms, caller's clock).
    pub at_ms: i64,
}

/// An append-only horizon-scan watchlist: scheduled targets plus the event
/// log of triggers observed against them.
///
/// Construct with [`Watchlist::new`] (or [`Default`]). Fields are private —
/// all mutation goes through the methods below, which is what keeps ids,
/// schedules and orderings deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watchlist {
    targets: Vec<WatchTarget>,
    triggers: Vec<Trigger>,
}

impl Watchlist {
    /// Empty watchlist.
    pub fn new() -> Self {
        Watchlist {
            targets: Vec::new(),
            triggers: Vec::new(),
        }
    }

    /// Add a target and schedule it immediately (`next_due_ms = now`).
    ///
    /// `name` and `source` must be non-empty (empty **or whitespace-only**);
    /// `cadence_ms` must be `> 0`. The returned id is `wl-<seq:03>` with the
    /// sequence taken from the live target count — a rejected add never
    /// consumes a number.
    ///
    /// Errors: `BadInput("name")`, `BadInput("source")`,
    /// `BadInput("cadence_ms")`.
    pub fn add(
        &mut self,
        name: &str,
        source: &str,
        cadence_ms: i64,
        tags: &[String],
        now_ms: i64,
    ) -> Result<&WatchTarget, WatchlistError> {
        if name.trim().is_empty() {
            return Err(WatchlistError::BadInput("name"));
        }
        if source.trim().is_empty() {
            return Err(WatchlistError::BadInput("source"));
        }
        if cadence_ms <= 0 {
            return Err(WatchlistError::BadInput("cadence_ms"));
        }
        let seq = self.targets.len() + 1;
        self.targets.push(WatchTarget {
            id: format!("wl-{seq:03}"),
            name: name.to_string(),
            source: source.to_string(),
            cadence_ms,
            last_checked_ms: None,
            next_due_ms: Some(now_ms),
            tags: tags.to_vec(),
        });
        Ok(self.targets.last().expect("target was just pushed"))
    }

    /// Every scheduled target whose `next_due_ms ≤ now_ms`, sorted by
    /// `(next_due_ms, id)`.
    ///
    /// The boundary is inclusive: a target exactly due at `now_ms` is due.
    /// Targets with no schedule (`next_due_ms == None`) are never returned.
    pub fn due(&self, now_ms: i64) -> Vec<&WatchTarget> {
        let mut due: Vec<&WatchTarget> = self
            .targets
            .iter()
            .filter(|t| matches!(t.next_due_ms, Some(d) if d <= now_ms))
            .collect();
        due.sort_by(|a, b| {
            a.next_due_ms
                .cmp(&b.next_due_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        due
    }

    /// Stamp a check: `last_checked_ms = now_ms`, `next_due_ms = now_ms +
    /// cadence_ms` (saturating).
    ///
    /// The next due instant is computed from *this call's* `now_ms`, not
    /// from the previous schedule — a late check does not shift the cadence
    /// grid. Errors: [`WatchlistError::UnknownTarget`]; a failed call leaves
    /// the target untouched.
    pub fn mark_checked(
        &mut self,
        id: &str,
        now_ms: i64,
    ) -> Result<(), WatchlistError> {
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(WatchlistError::UnknownTarget)?;
        target.last_checked_ms = Some(now_ms);
        target.next_due_ms = Some(now_ms.saturating_add(target.cadence_ms));
        Ok(())
    }

    /// Record an observed event against a target.
    ///
    /// The event must be non-empty (empty or whitespace-only ⇒
    /// `BadInput("event")`; validated before the target lookup), and the
    /// target must exist (⇒ [`WatchlistError::UnknownTarget`]). The
    /// trigger is appended and returned; the target's cadence and schedule
    /// are untouched. A failed call records nothing.
    pub fn trigger(
        &mut self,
        id: &str,
        event: &str,
        now_ms: i64,
    ) -> Result<&Trigger, WatchlistError> {
        if event.trim().is_empty() {
            return Err(WatchlistError::BadInput("event"));
        }
        if !self.targets.iter().any(|t| t.id == id) {
            return Err(WatchlistError::UnknownTarget);
        }
        self.triggers.push(Trigger {
            target: id.to_string(),
            event: event.to_string(),
            at_ms: now_ms,
        });
        Ok(self.triggers.last().expect("trigger was just pushed"))
    }

    /// Targets carrying `tag` (exact, case-sensitive match), sorted by id.
    ///
    /// An absent tag (or empty string) yields an empty list — this function
    /// has no error channel, so there is nothing to refuse.
    pub fn by_tag(&self, tag: &str) -> Vec<&WatchTarget> {
        let mut hits: Vec<&WatchTarget> = self
            .targets
            .iter()
            .filter(|t| t.tags.iter().any(|tagged| tagged == tag))
            .collect();
        hits.sort_by(|a, b| a.id.cmp(&b.id));
        hits
    }

    /// Triggers recorded for target `id`, sorted by `(at_ms, insertion)` —
    /// ties on the instant keep insertion order (stable sort). Unknown ids
    /// yield an empty list (no error channel).
    pub fn triggers_for(&self, id: &str) -> Vec<&Trigger> {
        let mut hits: Vec<&Trigger> = self
            .triggers
            .iter()
            .filter(|tr| tr.target == id)
            .collect();
        hits.sort_by_key(|tr| tr.at_ms);
        hits
    }
}

/// Post-quantum-migration milestone seeds (B4.2.3), as `(name,
/// source_hint)` pairs in a pinned, deterministic order.
///
/// These are **template hints only**: every `source_hint` carries the
/// explicit [`VERIFY_BEFORE_ADDING`] marker because a milestone name alone
/// is not evidence that the milestone is real, current, or relevant to this
/// deployment — the operator verifies against the named source before adding
/// a [`WatchTarget`]. Nothing here is ever auto-added, and the returned
/// pairs are owned copies (mutating them cannot mutate the template).
///
/// Hints carry the concrete sources probe-verified for B4.2.3 (2026-09-11);
/// `docs/ops/watchlist_pqc_seed.md` is the operator runbook (exact
/// `Watchlist::add` shape, cadence/tag defaults, the NSA Tor caveat, and a
/// ready-to-run seeding snippet).
pub fn seed_pqc_milestones() -> Vec<(String, String)> {
    PQC_MILESTONE_SEEDS
        .iter()
        .map(|(name, hint)| ((*name).to_string(), (*hint).to_string()))
        .collect()
}

/// The pinned seed template behind [`seed_pqc_milestones`]: six
/// post-quantum-migration milestones, each with a source hint carrying the
/// verify marker.
///
/// The web-verifiable hints carry the concrete sources probe-verified for
/// B4.2.3 through the box Tor stack (2026-09-11 — see
/// `artifacts/tallow_intel_uplift_2026-09-11/impl/B4.2.3_verified_targets.md`
/// and the seeding runbook `docs/ops/watchlist_pqc_seed.md`). The
/// [`VERIFY_BEFORE_ADDING`] marker stays on every hint: a verified *URL* is
/// not a verified *milestone status* — the operator still confirms currency
/// and relevance before adding.
const PQC_MILESTONE_SEEDS: &[(&str, &str)] = &[
    (
        "ML-KEM (FIPS 203) deployment in TLS hybrid key exchange",
        "https://csrc.nist.gov/projects/post-quantum-cryptography + https://datatracker.ietf.org/wg/tls/ — verify before adding",
    ),
    (
        "ML-DSA (FIPS 204) signing migration for firmware and release artifacts",
        "https://csrc.nist.gov/ — verify before adding",
    ),
    (
        "SLH-DSA (FIPS 205) availability in HSM and code-signing stacks",
        "https://csrc.nist.gov/ — verify before adding",
    ),
    // B4.2.3 caveat: nsa.gov 403s Tor exits (reputation-gated). The URL is
    // real but only reachable from a non-Tor vantage — scanning this target
    // through the box Tor stack will see the 403, not the page.
    (
        "CNSA 2.0 transition deadlines for national-security systems",
        "https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity/ (403 via Tor — use a non-Tor vantage) — verify before adding",
    ),
    (
        "Legacy algorithm retirement (RSA / ECDSA / ECDH deprecation dates)",
        "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final — verify before adding",
    ),
    (
        "Harvest-now-decrypt-later (HNDL) re-assessment for long-lived secrets",
        "operator key-inventory review (internal — no URL) — verify before adding",
    ),
];

/// Errors from watchlist operations.
///
/// `Serialize` is derived (wire form = snake_case). `Deserialize` is not —
/// the `BadInput(&'static str)` payload cannot be deserialized into a
/// `'static` lifetime; this mirrors the in-repo precedent
/// (`clearness_gate::ClearnessError`, `unknowns::UnknownsError`).
///
/// `BadInput` payloads are the offending field names: `"name"`, `"source"`,
/// `"cadence_ms"`, `"event"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchlistError {
    /// A required field was empty (or whitespace-only), or `cadence_ms` was
    /// `≤ 0`; carries the field name.
    BadInput(&'static str),
    /// No target with the given id exists.
    UnknownTarget,
}

impl std::fmt::Display for WatchlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchlistError::BadInput(field) => {
                write!(f, "invalid watchlist input: {field}")
            }
            WatchlistError::UnknownTarget => {
                write!(f, "unknown target: no watchlist target with that id")
            }
        }
    }
}

impl std::error::Error for WatchlistError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(wl: &'a Watchlist, id: &str) -> &'a WatchTarget {
        wl.targets.iter().find(|t| t.id == id).expect("target exists")
    }

    fn due_ids(wl: &Watchlist, now_ms: i64) -> Vec<String> {
        wl.due(now_ms).iter().map(|t| t.id.clone()).collect()
    }

    // ------------------------------------------------------------------- add

    #[test]
    fn add_assigns_sequential_ids_and_schedules_now() {
        let mut wl = Watchlist::new();
        let tags = vec!["b".to_string(), "a".to_string()];
        let first = wl.add("  padded  ", "src", 1_000, &tags, 42).unwrap();
        assert_eq!(first.id, "wl-001");
        assert_eq!(first.name, "  padded  ", "stored verbatim, never trimmed");
        assert_eq!(first.source, "src");
        assert_eq!(first.cadence_ms, 1_000);
        assert_eq!(first.last_checked_ms, None, "never checked yet");
        assert_eq!(first.next_due_ms, Some(42), "scheduled at add time");
        assert_eq!(
            first.tags,
            vec!["b".to_string(), "a".to_string()],
            "tag order preserved, not sorted"
        );

        let second = wl.add("second", "src", 5, &[], 42).unwrap();
        assert_eq!(second.id, "wl-002");
    }

    #[test]
    fn add_rejects_bad_input_and_never_consumes_ids() {
        let mut wl = Watchlist::new();
        assert!(matches!(
            wl.add("", "src", 10, &[], 0),
            Err(WatchlistError::BadInput("name"))
        ));
        assert!(matches!(
            wl.add("   ", "src", 10, &[], 0),
            Err(WatchlistError::BadInput("name"))
        ));
        assert!(matches!(
            wl.add("n", "", 10, &[], 0),
            Err(WatchlistError::BadInput("source"))
        ));
        assert!(matches!(
            wl.add("n", " \t ", 10, &[], 0),
            Err(WatchlistError::BadInput("source"))
        ));
        assert!(matches!(
            wl.add("n", "s", 0, &[], 0),
            Err(WatchlistError::BadInput("cadence_ms"))
        ));
        assert!(matches!(
            wl.add("n", "s", -5, &[], 0),
            Err(WatchlistError::BadInput("cadence_ms"))
        ));
        let t = wl.add("ok", "s", 1, &[], 0).unwrap();
        assert_eq!(t.id, "wl-001", "rejected adds must not consume the id sequence");
    }

    // ------------------------------------------------------------------- due

    #[test]
    fn due_boundary_is_inclusive() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 100, &[], 1_000).unwrap();
        assert!(wl.due(999).is_empty(), "one ms early ⇒ not due");
        assert_eq!(due_ids(&wl, 1_000), vec!["wl-001"], "exactly due ⇒ due");
        assert_eq!(due_ids(&wl, 10_000), vec!["wl-001"]);
    }

    #[test]
    fn due_sorted_by_next_due_then_id() {
        let mut wl = Watchlist::new();
        wl.add("first-added", "s", 1_000, &[], 0).unwrap(); // wl-001, due 0
        wl.add("second-added", "s", 1_000, &[], 0).unwrap(); // wl-002, due 0
        // Tie on next_due ⇒ id order.
        assert_eq!(due_ids(&wl, 0), vec!["wl-001", "wl-002"]);
        // Advance schedules so wl-002 is due sooner than wl-001.
        wl.mark_checked("wl-002", 100).unwrap(); // due 1100
        wl.mark_checked("wl-001", 500).unwrap(); // due 1500
        assert_eq!(due_ids(&wl, 2_000), vec!["wl-002", "wl-001"]);
    }

    #[test]
    fn due_excludes_targets_without_a_schedule() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 10, &[], 0).unwrap();
        // Hand-built value with no schedule: never due (pinned reading).
        wl.targets.push(WatchTarget {
            id: "wl-000".to_string(),
            name: "ghost".to_string(),
            source: "s".to_string(),
            cadence_ms: 10,
            last_checked_ms: None,
            next_due_ms: None,
            tags: Vec::new(),
        });
        assert_eq!(due_ids(&wl, i64::MAX), vec!["wl-001"]);
    }

    // ---------------------------------------------------------- mark_checked

    #[test]
    fn mark_checked_advances_cadence_exactly() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 1_000, &[], 0).unwrap();
        wl.mark_checked("wl-001", 400).unwrap();
        assert_eq!(find(&wl, "wl-001").last_checked_ms, Some(400));
        assert_eq!(find(&wl, "wl-001").next_due_ms, Some(1_400));
        assert!(wl.due(1_399).is_empty());
        assert_eq!(due_ids(&wl, 1_400), vec!["wl-001"]);
        // A later check computes from its own now, not from the old grid.
        wl.mark_checked("wl-001", 2_000).unwrap();
        assert_eq!(find(&wl, "wl-001").next_due_ms, Some(3_000));
        assert!(wl.due(2_999).is_empty());
        assert_eq!(due_ids(&wl, 3_000), vec!["wl-001"]);
    }

    #[test]
    fn mark_checked_unknown_target_errors_and_leaves_state() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 100, &[], 0).unwrap();
        assert_eq!(
            wl.mark_checked("wl-999", 5),
            Err(WatchlistError::UnknownTarget)
        );
        assert_eq!(find(&wl, "wl-001").next_due_ms, Some(0), "untouched");
    }

    #[test]
    fn mark_checked_saturates_never_wraps() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 100, &[], 0).unwrap();
        wl.mark_checked("wl-001", i64::MAX - 5).unwrap();
        assert_eq!(
            find(&wl, "wl-001").next_due_ms,
            Some(i64::MAX),
            "saturating add, not wrap-around"
        );
    }

    // -------------------------------------------------------------- triggers

    #[test]
    fn trigger_records_event_without_touching_cadence() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 1_000, &[], 0).unwrap();
        wl.mark_checked("wl-001", 100).unwrap(); // due 1100

        let (target, event, at) = {
            let tr = wl.trigger("wl-001", "draft-published", 555).unwrap();
            (tr.target.clone(), tr.event.clone(), tr.at_ms)
        };
        assert_eq!(target, "wl-001");
        assert_eq!(event, "draft-published");
        assert_eq!(at, 555);
        assert_eq!(find(&wl, "wl-001").last_checked_ms, Some(100), "check stamp untouched");
        assert_eq!(find(&wl, "wl-001").next_due_ms, Some(1_100), "cadence unchanged");

        // Trigger and mark_checked are independent: at the same instant both
        // are recorded, and only mark_checked moves the schedule.
        wl.mark_checked("wl-001", 555).unwrap();
        assert_eq!(find(&wl, "wl-001").next_due_ms, Some(1_555));
        assert_eq!(wl.triggers_for("wl-001").len(), 1);
    }

    #[test]
    fn trigger_rejects_bad_input_and_unknown_target() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 10, &[], 0).unwrap();
        assert!(matches!(
            wl.trigger("wl-001", "", 0),
            Err(WatchlistError::BadInput("event"))
        ));
        assert!(matches!(
            wl.trigger("wl-001", "  ", 0),
            Err(WatchlistError::BadInput("event"))
        ));
        assert!(matches!(
            wl.trigger("wl-404", "x", 0),
            Err(WatchlistError::UnknownTarget)
        ));
        // Validation precedes lookup (pinned): unknown target + empty event
        // reports the event problem first.
        assert!(matches!(
            wl.trigger("wl-404", " ", 0),
            Err(WatchlistError::BadInput("event"))
        ));
        assert!(wl.triggers.is_empty(), "failed triggers record nothing");
    }

    #[test]
    fn triggers_for_sorted_by_at_then_insertion() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 10, &[], 0).unwrap(); // wl-001
        wl.add("B", "s", 10, &[], 0).unwrap(); // wl-002
        wl.trigger("wl-001", "third-inserted", 30).unwrap();
        wl.trigger("wl-001", "first", 10).unwrap();
        wl.trigger("wl-001", "fourth-inserted", 30).unwrap();
        wl.trigger("wl-002", "other-target", 5).unwrap();

        let events: Vec<(String, i64)> = wl
            .triggers_for("wl-001")
            .iter()
            .map(|t| (t.event.clone(), t.at_ms))
            .collect();
        assert_eq!(
            events,
            vec![
                ("first".to_string(), 10),
                ("third-inserted".to_string(), 30),
                ("fourth-inserted".to_string(), 30),
            ],
            "sorted by at_ms; equal instants keep insertion order (stable)"
        );
        assert_eq!(wl.triggers_for("wl-002").len(), 1, "per-target scoping");
        assert!(wl.triggers_for("wl-999").is_empty(), "unknown id ⇒ empty");
    }

    // ---------------------------------------------------------------- by_tag

    #[test]
    fn by_tag_exact_case_sensitive_sorted_by_id() {
        let mut wl = Watchlist::new();
        wl.add("A", "s", 10, &["pqc".to_string(), "crypto".to_string()], 0)
            .unwrap(); // wl-001
        wl.add("B", "s", 10, &["pqc".to_string()], 0).unwrap(); // wl-002
        wl.add("C", "s", 10, &["PQC".to_string()], 0).unwrap(); // wl-003

        let ids = |tag: &str| -> Vec<String> {
            wl.by_tag(tag).iter().map(|t| t.id.clone()).collect()
        };
        assert_eq!(ids("pqc"), vec!["wl-001", "wl-002"]);
        assert_eq!(ids("PQC"), vec!["wl-003"], "match is exact and case-sensitive");
        assert!(ids("missing").is_empty());
        assert!(ids("").is_empty());
    }

    // ----------------------------------------------------------------- seeds

    #[test]
    fn seed_pqc_milestones_shape_and_marker() {
        let seeds = seed_pqc_milestones();
        assert!(seeds.len() >= 3, "B4.2.3 requires at least three seeds");
        assert_eq!(seeds.len(), PQC_MILESTONE_SEEDS.len());
        for (name, hint) in &seeds {
            assert!(!name.trim().is_empty(), "seed name must be non-empty");
            assert!(!hint.trim().is_empty(), "seed source hint must be non-empty");
            assert!(
                hint.contains(VERIFY_BEFORE_ADDING),
                "hint must carry the verify marker: {hint:?}"
            );
            assert!(
                !name.contains(VERIFY_BEFORE_ADDING),
                "the marker belongs to the hint, not the name"
            );
        }
        let mut names: Vec<&str> = seeds.iter().map(|(n, _)| n.as_str()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "seed names must be unique");
    }

    #[test]
    fn seed_pqc_milestones_deterministic_and_first_pinned() {
        assert_eq!(seed_pqc_milestones(), seed_pqc_milestones());
        let seeds = seed_pqc_milestones();
        assert_eq!(
            seeds[0].0,
            "ML-KEM (FIPS 203) deployment in TLS hybrid key exchange"
        );
        assert!(seeds[0].1.contains(VERIFY_BEFORE_ADDING));
    }

    #[test]
    fn seed_pqc_milestones_carry_verified_sources() {
        let seeds = seed_pqc_milestones();
        assert_eq!(seeds.len(), 6, "B4.2.3 keeps the six-seed structure");
        let hint = |name: &str| -> String {
            seeds
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("seed missing: {name:?}"))
                .1
                .clone()
        };

        // B4.2.3 probe-verified reachable (HTTP 200 via the box Tor stack,
        // 2026-09-11). These concrete URLs are what make seeding
        // ready-to-run; dropping one re-opens the "vague hint" gap.
        let ml_kem = hint("ML-KEM (FIPS 203) deployment in TLS hybrid key exchange");
        assert!(ml_kem.contains("https://csrc.nist.gov/projects/post-quantum-cryptography"));
        assert!(ml_kem.contains("https://datatracker.ietf.org/wg/tls/"));
        assert!(
            hint("ML-DSA (FIPS 204) signing migration for firmware and release artifacts")
                .contains("https://csrc.nist.gov/")
        );
        assert!(
            hint("SLH-DSA (FIPS 205) availability in HSM and code-signing stacks")
                .contains("https://csrc.nist.gov/")
        );
        assert!(
            hint("Legacy algorithm retirement (RSA / ECDSA / ECDH deprecation dates)")
                .contains("https://csrc.nist.gov/pubs/sp/800/131/a/r2/final")
        );

        // NSA/CNSA-2.0 row: the concrete URL rides the hint together with the
        // Tor-reachability caveat (nsa.gov 403s Tor exits; non-Tor vantage
        // untested). The caveat must not be dropped as noise.
        let cnsa = hint("CNSA 2.0 transition deadlines for national-security systems");
        assert!(cnsa.contains("https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity/"));
        assert!(
            cnsa.contains("403"),
            "the NSA row must carry its Tor-reachability caveat: {cnsa:?}"
        );

        // HNDL row stays an internal key-inventory review — no fabricated URL.
        let hndl = hint("Harvest-now-decrypt-later (HNDL) re-assessment for long-lived secrets");
        assert!(
            !hndl.contains("http"),
            "the HNDL row is an internal review, not a URL: {hndl:?}"
        );
    }

    #[test]
    fn runbook_snippet_rows_add_and_land_due_with_cadence_and_tag() {
        // Mirrors the ready-to-run snippet in
        // `docs/ops/watchlist_pqc_seed.md` — keep the two in sync. The
        // snippet is the operator's copy/paste path, so its exact rows must
        // add cleanly, schedule immediately, and be queryable by the `pqc`
        // tag.
        const CADENCE_30D_MS: i64 = 30 * 24 * 60 * 60 * 1_000; // 2_592_000_000
        let now_ms = 1_760_000_000_000;
        let tags = vec!["pqc".to_string()];
        let mut wl = Watchlist::new();
        let rows: [(&str, &str); 5] = [
            (
                "ML-KEM (FIPS 203) deployment in TLS hybrid key exchange",
                "https://csrc.nist.gov/projects/post-quantum-cryptography + https://datatracker.ietf.org/wg/tls/",
            ),
            (
                "ML-DSA (FIPS 204) signing migration for firmware and release artifacts",
                "https://csrc.nist.gov/",
            ),
            (
                "SLH-DSA (FIPS 205) availability in HSM and code-signing stacks",
                "https://csrc.nist.gov/",
            ),
            (
                "CNSA 2.0 transition deadlines for national-security systems",
                "https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity/ (403 via Tor — use a non-Tor vantage)",
            ),
            (
                "Legacy algorithm retirement (RSA / ECDSA / ECDH deprecation dates)",
                "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
            ),
        ];
        for (name, source) in rows {
            wl.add(name, source, CADENCE_30D_MS, &tags, now_ms).unwrap();
        }
        assert_eq!(wl.due(now_ms).len(), 5, "all seeded rows are due at add time");

        // Row 6 (HNDL): internal review, no URL — schedulable all the same.
        wl.add(
            "Harvest-now-decrypt-later (HNDL) re-assessment for long-lived secrets",
            "operator key-inventory review (internal — no URL)",
            CADENCE_30D_MS,
            &tags,
            now_ms,
        )
        .unwrap();

        let pqc_rows = wl.by_tag("pqc");
        assert_eq!(pqc_rows.len(), 6);
        for t in pqc_rows {
            assert_eq!(t.cadence_ms, CADENCE_30D_MS);
            assert_eq!(t.next_due_ms, Some(now_ms), "add schedules immediately");
        }
    }

    #[test]
    fn seeds_are_hints_only_never_auto_added() {
        let wl = Watchlist::new();
        let seeds = seed_pqc_milestones();
        assert!(!seeds.is_empty());
        // The seed template cannot have added anything: there is no such
        // path, and a fresh watchlist stays empty.
        assert!(wl.due(i64::MAX).is_empty());
        assert!(wl.by_tag("pqc").is_empty());
        // Returned pairs are owned copies — mutating them cannot mutate the
        // template.
        let mut copy = seed_pqc_milestones();
        copy[0].0 = "mutated".to_string();
        assert_eq!(seed_pqc_milestones()[0].0, seeds[0].0);
    }

    // ----------------------------------------------------------------- serde

    #[test]
    fn serde_watch_target_and_trigger_roundtrip() {
        let target = WatchTarget {
            id: "wl-007".to_string(),
            name: "n".to_string(),
            source: "s".to_string(),
            cadence_ms: 86_400_000,
            last_checked_ms: None,
            next_due_ms: Some(5),
            tags: vec!["pqc".to_string()],
        };
        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("\"cadence_ms\":86400000"));
        assert!(json.contains("\"last_checked_ms\":null"));
        assert_eq!(serde_json::from_str::<WatchTarget>(&json).unwrap(), target);

        let tr = Trigger {
            target: "wl-007".to_string(),
            event: "e".to_string(),
            at_ms: 9,
        };
        let json = serde_json::to_string(&tr).unwrap();
        assert_eq!(serde_json::from_str::<Trigger>(&json).unwrap(), tr);
    }

    #[test]
    fn serde_error_wire_tokens() {
        assert_eq!(
            serde_json::to_string(&WatchlistError::UnknownTarget).unwrap(),
            "\"unknown_target\""
        );
        assert_eq!(
            serde_json::to_string(&WatchlistError::BadInput("name")).unwrap(),
            "{\"bad_input\":\"name\"}"
        );
    }

    #[test]
    fn display_and_std_error_impls() {
        assert!(
            WatchlistError::BadInput("name")
                .to_string()
                .contains("name")
        );
        assert!(
            WatchlistError::UnknownTarget
                .to_string()
                .contains("unknown target")
        );
        let boxed: Box<dyn std::error::Error> = Box::new(WatchlistError::UnknownTarget);
        assert!(boxed.source().is_none());
    }

    // ----------------------------------------------------------- determinism

    #[test]
    fn replay_is_deterministic() {
        let run = || {
            let mut wl = Watchlist::new();
            wl.add("A", "s", 100, &["x".to_string()], 10).unwrap();
            wl.add("B", "s", 50, &["x".to_string()], 10).unwrap();
            wl.mark_checked("wl-002", 40).unwrap();
            wl.trigger("wl-001", "evt", 30).unwrap();
            wl.trigger("wl-001", "evt2", 30).unwrap();
            (
                due_ids(&wl, 1_000),
                wl.by_tag("x").iter().map(|t| t.id.clone()).collect::<Vec<_>>(),
                wl.triggers_for("wl-001")
                    .iter()
                    .map(|t| (t.event.clone(), t.at_ms))
                    .collect::<Vec<_>>(),
                seed_pqc_milestones(),
            )
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn new_and_default_are_empty() {
        let wl = Watchlist::new();
        assert_eq!(wl, Watchlist::default());
        assert!(wl.due(i64::MAX).is_empty());
        assert!(wl.by_tag("any").is_empty());
        assert!(wl.triggers_for("wl-001").is_empty());
    }
}
