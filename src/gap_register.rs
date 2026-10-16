//! Collection-gap register feeding direction — task A3.2.3 (dossier E7),
//! batch 07 §5.
//!
//! A *collection gap* is an unmet requirement: the question is still
//! chartered (not retired) and nothing in the link chain answers it. The
//! register is the bridge from "requirements + coverage" to *direction*:
//! it converts uncovered requirements into ranked, actionable gap entries
//! and hands back ordered requirement ids ready for tasking.
//!
//! # Frozen interface (batch 07, §5)
//! - [`GapReason`] `{ NoCoverage, ExpiredOpen }`;
//! - [`GapEntry`] `{ requirement_id, reason, priority: u8, raised_ms }`;
//! - [`derive_gaps`] — derive entries from a [`RequirementStore`] plus a
//!   per-requirement finding-count map;
//! - [`GapRegister`] — `add` (dedupe while unresolved) / `pending` /
//!   `resolve` / `feeds_direction` / `len` / `is_empty`;
//! - [`GapError`] `{ Duplicate, EmptyField }`.
//!
//! # Semantics pinned here
//! - **Derivation rules** (per requirement, in this order):
//!   1. `Retired` requirements are skipped — withdrawal is terminal for
//!      collection, so a retired requirement is never a gap;
//!   2. `covered_findings > 0` → no gap (a covered requirement is answered,
//!      whatever its status);
//!   3. deadline passed and still uncovered → [`GapReason::ExpiredOpen`].
//!      "Deadline passed" means the record was already transitioned to
//!      `Expired`, **or** it is still `Open` but `is_expired_at(now_ms)`
//!      (due time reached, `expire_due` not yet run — inclusive boundary).
//!      The overdue-but-open case is precisely what the reason name says;
//!      a transitioned `Expired` record with zero findings is the same
//!      unmet need and is included (it must not silently vanish from the
//!      register);
//!   4. otherwise (still `Open`, not yet due, zero findings) →
//!      [`GapReason::NoCoverage`].
//!   Uncovered entries therefore always carry exactly one reason;
//!   `ExpiredOpen` takes precedence over `NoCoverage`.
//! - **Ordering.** [`derive_gaps`] output is deterministic: most urgent
//!   requirement first, then ascending id. This is the contract's
//!   "(priority DESC, then id ASC)" read against this codebase's rank
//!   semantics — [`ReqKind`]/[`Requirement`] pin `1` = highest urgency
//!   (see `requirements.rs`), so *descending urgency* = numerically
//!   ascending priority. The register exists to feed direction (tasking),
//!   so the most urgent gaps must surface first. (If a raw
//!   numerically-descending sort were intended, flip the comparator in
//!   [`derive_gaps`]; noted in the batch-07 report.)
//! - **`raised_ms` for derived entries** is `now_ms` — the instant the gap
//!   is derived/observed. Registers merged across repeated derivation
//!   batches keep older gaps "older", which is what
//!   [`GapRegister::feeds_direction`]'s oldest-first tiebreak orders by.
//! - **[`GapRegister`] state.** `pending()` returns entries in insertion
//!   order (no re-sorting; ranking is `feeds_direction`'s job). `add`
//!   rejects a second entry for a requirement id **while it is unresolved**
//!   ([`GapError::Duplicate`]); once resolved, the id may re-enter (a
//!   requirement can fall back out of coverage). `resolve` removes the
//!   pending entry and records `(requirement_id -> at_ms)`, returning
//!   `true` iff something was actually resolved (idempotent after that).
//!   `len`/`is_empty` count pending (unresolved) entries.
//! - **`feeds_direction` ordering**: same primary key as [`derive_gaps`]
//!   (most urgent first), then oldest-first (`raised_ms` ascending), then
//!   ascending id as the deterministic final tiebreak. This is the
//!   contract's "same priority/oldest-first ordering".
//! - Serde: [`GapReason`] uses `snake_case` wire names
//!   (`"no_coverage"` / `"expired_open"`). [`GapEntry`] and
//!   [`GapRegister`] round-trip; the register's resolution state (id →
//!   `at_ms`) persists across a round-trip. (Serde on `GapRegister` is an
//!   additive convenience beyond the frozen `(+ serde)` markers, so
//!   resolution state is persistable; the markers themselves are on
//!   `GapReason`/`GapEntry`.)


use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::requirements::{ReqStatus, RequirementStore};

/// Why a requirement is in the collection-gap register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// Still open, not yet due, zero linked findings — the standing
    /// shortfall.
    NoCoverage,
    /// Deadline passed (`Expired`, or `Open` past its due time) and still
    /// zero linked findings — the escalated shortfall.
    ExpiredOpen,
}

impl GapReason {
    /// Lowercase wire/display name (`"no_coverage"` / `"expired_open"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            GapReason::NoCoverage => "no_coverage",
            GapReason::ExpiredOpen => "expired_open",
        }
    }
}

impl fmt::Display for GapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One collection-gap entry: a requirement that needs direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapEntry {
    /// The uncovered requirement's id.
    pub requirement_id: String,
    /// Why it is a gap (see [`GapReason`]).
    pub reason: GapReason,
    /// Copied from the requirement (`1` = highest urgency … `3` = lowest).
    pub priority: u8,
    /// When the gap was raised, ms since the Unix epoch. For
    /// [`derive_gaps`] entries this is the derivation instant `now_ms`.
    pub raised_ms: i64,
}

/// Derive the current gap entries from a requirement store and a
/// per-requirement count of linked findings.
///
/// Rules and ordering are documented on the module (skip retired; covered →
/// no gap; deadline passed + uncovered → [`GapReason::ExpiredOpen`];
/// otherwise open + uncovered → [`GapReason::NoCoverage`]; output ordered
/// most-urgent-first, then ascending id). `covered_findings` keys that are
/// not in the store are ignored; a count of `0` is equivalent to absence.
/// Never panics; deterministic for identical inputs.
pub fn derive_gaps(
    store: &RequirementStore,
    covered_findings: &BTreeMap<String, usize>,
    now_ms: i64,
) -> Vec<GapEntry> {
    let mut gaps = Vec::new();
    for r in store.iter() {
        if r.status == ReqStatus::Retired {
            continue;
        }
        if covered_findings.get(&r.id).copied().unwrap_or(0) > 0 {
            continue;
        }
        let deadline_passed = r.status == ReqStatus::Expired || r.is_expired_at(now_ms);
        let reason = if deadline_passed {
            GapReason::ExpiredOpen
        } else {
            GapReason::NoCoverage
        };
        gaps.push(GapEntry {
            requirement_id: r.id.clone(),
            reason,
            priority: r.priority,
            raised_ms: now_ms,
        });
    }
    // Most urgent first (priority 1 = highest urgency → numeric ascending),
    // then ascending id. See module docs for the contract reading.
    gaps.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.requirement_id.cmp(&b.requirement_id))
    });
    gaps
}

/// Errors from gap-register operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapError {
    /// The requirement id already has an unresolved entry in the register.
    Duplicate { requirement_id: String },
    /// A required text field was empty / whitespace-only (field name).
    EmptyField(&'static str),
}

impl fmt::Display for GapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GapError::Duplicate { requirement_id } => {
                write!(f, "gap for requirement already pending: {requirement_id}")
            }
            GapError::EmptyField(field) => write!(f, "empty required field: {field}"),
        }
    }
}

impl std::error::Error for GapError {}

/// The gap register: unresolved entries plus the resolution record.
///
/// Insertion goes through [`GapRegister::add`] only (empty-id rejection,
/// dedupe by requirement id while unresolved). `pending()` exposes entries
/// in insertion order; [`GapRegister::feeds_direction`] applies the
/// urgency/oldest ordering. The register serde-round-trips (resolution
/// state included).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapRegister {
    entries: Vec<GapEntry>,
    resolved: BTreeMap<String, i64>,
}

impl GapRegister {
    /// Empty register.
    pub fn new() -> Self {
        GapRegister {
            entries: Vec::new(),
            resolved: BTreeMap::new(),
        }
    }

    /// Add a gap entry. Returns:
    /// - [`GapError::EmptyField`] if `requirement_id` is empty or
    ///   whitespace-only;
    /// - [`GapError::Duplicate`] if the id already has an unresolved entry
    ///   (dedupe is strictly "while unresolved" — re-adding a resolved id
    ///   is allowed).
    ///
    /// On any error the register is left unchanged.
    pub fn add(&mut self, e: GapEntry) -> Result<(), GapError> {
        if e.requirement_id.trim().is_empty() {
            return Err(GapError::EmptyField("requirement_id"));
        }
        if self.is_pending(&e.requirement_id) {
            return Err(GapError::Duplicate {
                requirement_id: e.requirement_id,
            });
        }
        self.entries.push(e);
        Ok(())
    }

    /// Unresolved entries, in insertion order.
    pub fn pending(&self) -> &[GapEntry] {
        &self.entries
    }

    /// Resolve the pending gap for `requirement_id`, recording `at_ms`.
    /// Returns `true` iff a pending entry was actually removed; `false` if
    /// the id is not pending (already resolved or never registered) —
    /// idempotent, never panics.
    pub fn resolve(&mut self, requirement_id: &str, at_ms: i64) -> bool {
        match self
            .entries
            .iter()
            .position(|e| e.requirement_id == requirement_id)
        {
            Some(pos) => {
                self.entries.remove(pos);
                self.resolved.insert(requirement_id.to_string(), at_ms);
                true
            }
            None => false,
        }
    }

    /// Requirement ids ready for tasking, most urgent first, then
    /// oldest-raised first, then ascending id (documented ordering).
    pub fn feeds_direction(&self) -> Vec<String> {
        let mut pending: Vec<&GapEntry> = self.entries.iter().collect();
        pending.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.raised_ms.cmp(&b.raised_ms))
                .then_with(|| a.requirement_id.cmp(&b.requirement_id))
        });
        pending
            .into_iter()
            .map(|e| e.requirement_id.clone())
            .collect()
    }

    /// Number of pending (unresolved) entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no pending entries remain.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn is_pending(&self, requirement_id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.requirement_id == requirement_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requirements::{ReqKind, Requirement};

    fn req(id: &str, priority: u8, expires_ms: Option<i64>, status: ReqStatus) -> Requirement {
        Requirement {
            id: id.to_string(),
            kind: ReqKind::Pir,
            question: format!("question {id}"),
            owner: "owner".to_string(),
            priority,
            created_ms: 1_000,
            expires_ms,
            status,
        }
    }

    fn entry(requirement_id: &str, reason: GapReason, priority: u8, raised_ms: i64) -> GapEntry {
        GapEntry {
            requirement_id: requirement_id.to_string(),
            reason,
            priority,
            raised_ms,
        }
    }

    fn ids(gaps: &[GapEntry]) -> Vec<&str> {
        gaps.iter().map(|g| g.requirement_id.as_str()).collect()
    }

    #[test]
    fn derive_matrix_open_expired_retired_covered() {
        let mut store = RequirementStore::new();
        // a: open, no deadline, uncovered -> NoCoverage.
        store.append(req("a", 1, None, ReqStatus::Open)).unwrap();
        // b: open but due already reached at now (inclusive) -> ExpiredOpen.
        store.append(req("b", 2, Some(200), ReqStatus::Open)).unwrap();
        // c: already transitioned to Expired, uncovered -> still a gap.
        store.append(req("c", 2, Some(50), ReqStatus::Expired)).unwrap();
        // d: covered -> no gap.
        store.append(req("d", 1, None, ReqStatus::Open)).unwrap();
        // e: retired -> skipped even though uncovered.
        store.append(req("e", 1, None, ReqStatus::Retired)).unwrap();
        // f: expired but covered -> no gap.
        store.append(req("f", 3, Some(10), ReqStatus::Expired)).unwrap();

        let mut covered = BTreeMap::new();
        covered.insert("d".to_string(), 2usize);
        covered.insert("f".to_string(), 1usize);
        covered.insert("stranger".to_string(), 9usize); // not in store: ignored

        let gaps = derive_gaps(&store, &covered, 200);
        assert_eq!(ids(&gaps), vec!["a", "b", "c"]);
        assert_eq!(gaps[0].reason, GapReason::NoCoverage);
        assert_eq!(gaps[0].priority, 1);
        assert_eq!(gaps[1].reason, GapReason::ExpiredOpen);
        assert_eq!(gaps[2].reason, GapReason::ExpiredOpen);
        // Derived raised_ms is the derivation instant.
        assert!(gaps.iter().all(|g| g.raised_ms == 200));
    }

    #[test]
    fn deadline_boundary_is_inclusive() {
        let mut store = RequirementStore::new();
        store
            .append(req("due", 1, Some(500), ReqStatus::Open))
            .unwrap();
        let none = BTreeMap::new();

        let before = derive_gaps(&store, &none, 499);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].reason, GapReason::NoCoverage);

        let at = derive_gaps(&store, &none, 500);
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].reason, GapReason::ExpiredOpen);
    }

    #[test]
    fn derive_order_is_most_urgent_first_then_id_asc() {
        let mut store = RequirementStore::new();
        for (id, p) in [("z3", 3u8), ("b1", 1), ("a1", 1), ("m2", 2)] {
            store.append(req(id, p, None, ReqStatus::Open)).unwrap();
        }
        let gaps = derive_gaps(&store, &BTreeMap::new(), 10);
        // priority 1 first (id asc), then 2, then 3.
        assert_eq!(ids(&gaps), vec!["a1", "b1", "m2", "z3"]);
    }

    #[test]
    fn derive_empty_and_deterministic() {
        let empty = RequirementStore::new();
        assert!(derive_gaps(&empty, &BTreeMap::new(), 0).is_empty());

        let mut store = RequirementStore::new();
        store.append(req("p", 2, Some(9), ReqStatus::Open)).unwrap();
        store.append(req("q", 1, Some(9), ReqStatus::Open)).unwrap();
        store.append(req("r", 3, Some(9), ReqStatus::Retired)).unwrap();
        let covered = BTreeMap::new();
        let a = derive_gaps(&store, &covered, 9);
        let b = derive_gaps(&store, &covered, 9);
        assert_eq!(a, b);
        assert_eq!(ids(&a), vec!["q", "p"]);
    }

    #[test]
    fn add_rejects_duplicate_while_unresolved_and_empty_id() {
        let mut reg = GapRegister::new();
        assert!(reg.is_empty());
        reg.add(entry("r1", GapReason::NoCoverage, 1, 10)).unwrap();
        assert_eq!(reg.len(), 1);

        assert_eq!(
            reg.add(entry("r1", GapReason::ExpiredOpen, 2, 20)),
            Err(GapError::Duplicate {
                requirement_id: "r1".to_string()
            })
        );
        assert_eq!(reg.len(), 1, "rejected add left the register unchanged");

        assert_eq!(
            reg.add(entry("   ", GapReason::NoCoverage, 1, 0)),
            Err(GapError::EmptyField("requirement_id"))
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn resolve_then_readd() {
        let mut reg = GapRegister::new();
        reg.add(entry("r1", GapReason::NoCoverage, 1, 10)).unwrap();

        assert!(reg.resolve("r1", 99));
        assert!(reg.is_empty());
        assert!(reg.pending().is_empty());

        // Idempotent: nothing pending for that id anymore.
        assert!(!reg.resolve("r1", 100));
        assert!(!reg.resolve("never-registered", 100));

        // Dedupe is strictly "while unresolved": re-add after resolve is ok.
        reg.add(entry("r1", GapReason::ExpiredOpen, 1, 150)).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.pending()[0].raised_ms, 150);
    }

    #[test]
    fn feeds_direction_priority_then_oldest_first() {
        let mut reg = GapRegister::new();
        reg.add(entry("e1", GapReason::NoCoverage, 2, 100)).unwrap();
        reg.add(entry("b2", GapReason::NoCoverage, 2, 50)).unwrap();
        reg.add(entry("a2", GapReason::ExpiredOpen, 2, 50)).unwrap();
        reg.add(entry("e3", GapReason::ExpiredOpen, 1, 900)).unwrap();

        // priority 1 first, then priority 2 by raised_ms asc, id asc on ties.
        assert_eq!(
            reg.feeds_direction(),
            vec![
                "e3".to_string(),
                "a2".to_string(),
                "b2".to_string(),
                "e1".to_string()
            ]
        );

        reg.resolve("e3", 1_000);
        assert_eq!(
            reg.feeds_direction(),
            vec!["a2".to_string(), "b2".to_string(), "e1".to_string()]
        );

        assert!(GapRegister::new().feeds_direction().is_empty());
    }

    #[test]
    fn pending_preserves_insertion_order() {
        let mut reg = GapRegister::new();
        reg.add(entry("z", GapReason::NoCoverage, 1, 1)).unwrap();
        reg.add(entry("a", GapReason::NoCoverage, 3, 2)).unwrap();
        let pending_ids: Vec<&str> = reg
            .pending()
            .iter()
            .map(|e| e.requirement_id.as_str())
            .collect();
        assert_eq!(pending_ids, vec!["z", "a"], "insertion order, no re-sort");
    }

    #[test]
    fn derived_gaps_feed_register_in_priority_order() {
        let mut store = RequirementStore::new();
        store.append(req("low", 3, None, ReqStatus::Open)).unwrap();
        store.append(req("high", 1, None, ReqStatus::Open)).unwrap();

        let mut reg = GapRegister::new();
        for g in derive_gaps(&store, &BTreeMap::new(), 5) {
            reg.add(g).unwrap();
        }
        assert_eq!(
            reg.feeds_direction(),
            vec!["high".to_string(), "low".to_string()]
        );
    }

    #[test]
    fn serde_round_trips_and_wire_names() {
        assert_eq!(
            serde_json::to_string(&GapReason::NoCoverage).unwrap(),
            "\"no_coverage\""
        );
        assert_eq!(
            serde_json::to_string(&GapReason::ExpiredOpen).unwrap(),
            "\"expired_open\""
        );

        let e = entry("r1", GapReason::ExpiredOpen, 2, 42);
        let j = serde_json::to_string(&e).unwrap();
        let back: GapEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);

        // Register round-trip preserves pending entries AND resolution state.
        let mut reg = GapRegister::new();
        reg.add(entry("r1", GapReason::NoCoverage, 1, 10)).unwrap();
        reg.add(entry("r2", GapReason::ExpiredOpen, 2, 20)).unwrap();
        reg.resolve("r2", 30);
        let rj = serde_json::to_string(&reg).unwrap();
        let mut loaded: GapRegister = serde_json::from_str(&rj).unwrap();
        assert_eq!(loaded, reg);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.pending()[0].requirement_id, "r1");
        // Resolution persisted: resolving r2 again reports false.
        assert!(!loaded.resolve("r2", 40));
    }

    #[test]
    fn display_and_error_messages() {
        assert_eq!(GapReason::NoCoverage.to_string(), "no_coverage");
        assert_eq!(GapReason::ExpiredOpen.to_string(), "expired_open");
        assert!(GapError::Duplicate {
            requirement_id: "r9".into()
        }
        .to_string()
        .contains("r9"));
        assert!(GapError::EmptyField("requirement_id")
            .to_string()
            .contains("requirement_id"));
    }
}
