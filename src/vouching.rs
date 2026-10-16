//! Vouched-by edges model (task B1.2.1 · frozen interface §9).
//!
//! A [`VouchGraph`] is a set of directed vouching edges `voucher → subject`,
//! each stamped with the caller's clock (`at_ms`, stored unchanged; this
//! module never reads the clock itself).
//!
//! # Documented edge rules (spec silent where noted; conservative reading)
//!
//! * **Emptiness**: a `voucher` or `subject` that is empty *after trimming*
//!   is refused with [`VouchError::EmptyField`], carrying the offending field
//!   name. `voucher` is checked before `subject`, so an all-empty call reports
//!   `"voucher"` first. Stored values are kept **exactly as passed** (no
//!   rewriting) — edge identity is the exact string.
//! * **Self-vouch**: `voucher == subject` (exact string equality) is refused
//!   with [`VouchError::SelfVouch`] — a vouch graph is evidence that *another*
//!   party attests to a claim, so a self-edge is structurally invalid.
//! * **Duplicates**: the same `(voucher, subject)` pair is refused with
//!   [`VouchError::Duplicate`], *regardless of `at_ms`* — edges are idempotent;
//!   re-vouching later does not deepen the edge and the first record is kept.
//!   The reversed pair `(subject, voucher)` is a *distinct* edge (mutual
//!   vouching is allowed).
//! * **Ordering**: [`VouchGraph::vouchers_of`] / [`VouchGraph::subjects_of`]
//!   return **sorted, deduplicated** names, so query output is independent of
//!   insertion order (determinism is a security property: verdicts are cached
//!   and compared between runs).
//! * **Threshold**: [`meets_threshold`] counts *distinct* vouchers. `n == 0`
//!   is vacuously met by every subject, **including unknown ones** — needing
//!   zero endorsements is no requirement at all. Documented because a caller
//!   might expect unknown subjects to fail. For `n >= 1`, an unknown subject
//!   has count 0 and fails.
//! * The graph is `serde` (de)serializable. Data loaded from an external
//!   source could in principle carry duplicate edges, so the query methods
//!   deduplicate defensively rather than trusting `add` invariants.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// One vouching edge: `voucher` attests for `subject` at `at_ms` (caller
/// clock, stored unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vouch {
    /// The vouching party (exact string, checked non-blank at [`VouchGraph::add`]).
    pub voucher: String,
    /// The vouched-for subject.
    pub subject: String,
    /// Caller-supplied timestamp (ms); never rewritten.
    pub at_ms: i64,
}

/// Errors refusing an edge.
///
/// `Serialize` is derived; `Deserialize` is not — the `&'static str` payload
/// of [`VouchError::EmptyField`] cannot be deserialized into a `'static`
/// lifetime. This mirrors the in-repo precedent of sibling modules
/// (`gap_register` / `link_chain` / `decoy_flags` / `requirements`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VouchError {
    /// `voucher == subject`: a party cannot vouch for itself.
    SelfVouch,
    /// The `(voucher, subject)` edge is already present (`at_ms` ignored).
    Duplicate,
    /// A required field was empty after trimming; carries the field name.
    EmptyField(&'static str),
}

impl fmt::Display for VouchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VouchError::SelfVouch => {
                write!(f, "self-vouch refused: voucher and subject are the same")
            }
            VouchError::Duplicate => write!(f, "duplicate vouch refused: edge already present"),
            VouchError::EmptyField(field) => write!(f, "empty required field: {field}"),
        }
    }
}

impl std::error::Error for VouchError {}

/// Directed vouching graph. See the module docs for edge rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchGraph {
    edges: Vec<Vouch>,
}

impl VouchGraph {
    /// Empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the edge `voucher → subject` at `at_ms`.
    ///
    /// Refusals (checked in order): blank `voucher` / blank `subject`
    /// ([`VouchError::EmptyField`]); `voucher == subject`
    /// ([`VouchError::SelfVouch`]); pair already present
    /// ([`VouchError::Duplicate`]).
    pub fn add(&mut self, voucher: &str, subject: &str, at_ms: i64) -> Result<(), VouchError> {
        if voucher.trim().is_empty() {
            return Err(VouchError::EmptyField("voucher"));
        }
        if subject.trim().is_empty() {
            return Err(VouchError::EmptyField("subject"));
        }
        if voucher == subject {
            return Err(VouchError::SelfVouch);
        }
        if self
            .edges
            .iter()
            .any(|e| e.voucher == voucher && e.subject == subject)
        {
            return Err(VouchError::Duplicate);
        }
        self.edges.push(Vouch {
            voucher: voucher.to_string(),
            subject: subject.to_string(),
            at_ms,
        });
        Ok(())
    }

    /// Distinct vouchers of `subject`, sorted ascending (deterministic).
    pub fn vouchers_of(&self, subject: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| e.subject == subject)
            .map(|e| e.voucher.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Distinct subjects vouched for by `voucher`, sorted ascending.
    pub fn subjects_of(&self, voucher: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| e.voucher == voucher)
            .map(|e| e.subject.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Number of edges held.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// True when no edges are held.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

/// Distinct-voucher count of `subject` (see [`VouchGraph::vouchers_of`]).
pub fn vouch_count(g: &VouchGraph, subject: &str) -> usize {
    g.vouchers_of(subject).len()
}

/// True when `subject` has at least `n` distinct vouchers.
///
/// `n == 0` is vacuously true for every subject, including unknown ones
/// (documented in the module docs). For `n >= 1`, unknown subjects fail.
pub fn meets_threshold(g: &VouchGraph, subject: &str, n: usize) -> bool {
    vouch_count(g, subject) >= n
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Three distinct vouchers for `claim-1`.
    fn sample() -> VouchGraph {
        let mut g = VouchGraph::new();
        g.add("alice", "claim-1", 10).unwrap();
        g.add("bob", "claim-1", 20).unwrap();
        g.add("carol", "claim-1", 30).unwrap();
        g
    }

    #[test]
    fn add_and_list_roundtrip() {
        let g = sample();
        assert_eq!(g.len(), 3);
        assert!(!g.is_empty());
        assert_eq!(g.vouchers_of("claim-1"), vec!["alice", "bob", "carol"]);
        assert_eq!(g.subjects_of("bob"), vec!["claim-1"]);
        // Unknown names: empty results, never a panic.
        assert_eq!(g.vouchers_of("unknown"), Vec::<&str>::new());
        assert_eq!(g.subjects_of("unknown"), Vec::<&str>::new());
    }

    #[test]
    fn empty_graph_is_empty() {
        let g = VouchGraph::default();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        assert_eq!(vouch_count(&g, "claim-1"), 0);
    }

    #[test]
    fn self_vouch_refused() {
        let mut g = VouchGraph::new();
        assert_eq!(g.add("alice", "alice", 1), Err(VouchError::SelfVouch));
        assert!(g.is_empty(), "refused edge must not be stored");
    }

    #[test]
    fn duplicate_refused_regardless_of_clock() {
        let mut g = VouchGraph::new();
        g.add("alice", "claim-1", 1).unwrap();
        assert_eq!(g.add("alice", "claim-1", 2), Err(VouchError::Duplicate));
        assert_eq!(g.len(), 1, "duplicate must not grow the graph");
        // Reversed pair is a distinct edge: mutual vouching is allowed.
        g.add("claim-1", "alice", 3).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g.vouchers_of("alice"), vec!["claim-1"]);
    }

    #[test]
    fn empty_fields_refused() {
        let mut g = VouchGraph::new();
        assert_eq!(g.add("", "s", 0), Err(VouchError::EmptyField("voucher")));
        assert_eq!(g.add("   ", "s", 0), Err(VouchError::EmptyField("voucher")));
        assert_eq!(g.add("v", "", 0), Err(VouchError::EmptyField("subject")));
        assert_eq!(g.add("v", "\t", 0), Err(VouchError::EmptyField("subject")));
        // `voucher` is checked before `subject` when both are blank.
        assert_eq!(g.add("", "", 0), Err(VouchError::EmptyField("voucher")));
        assert!(g.is_empty());
    }

    #[test]
    fn vouch_count_counts_distinct_vouchers() {
        let g = sample();
        assert_eq!(vouch_count(&g, "claim-1"), 3);
        assert_eq!(vouch_count(&g, "unknown"), 0);
    }

    #[test]
    fn threshold_semantics() {
        let g = sample();
        assert!(meets_threshold(&g, "claim-1", 0)); // vacuous truth
        assert!(meets_threshold(&g, "claim-1", 1));
        assert!(meets_threshold(&g, "claim-1", 3));
        assert!(!meets_threshold(&g, "claim-1", 4));
        // n == 0 is met even by an unknown subject (documented).
        assert!(meets_threshold(&g, "unknown", 0));
        assert!(!meets_threshold(&g, "unknown", 1));
    }

    #[test]
    fn outputs_sorted_and_insertion_order_independent() {
        let mut a = VouchGraph::new();
        a.add("carol", "s", 1).unwrap();
        a.add("alice", "s", 2).unwrap();
        a.add("bob", "s", 3).unwrap();
        assert_eq!(a.vouchers_of("s"), vec!["alice", "bob", "carol"]);

        let mut b = VouchGraph::new();
        b.add("bob", "s", 3).unwrap();
        b.add("carol", "s", 1).unwrap();
        b.add("alice", "s", 2).unwrap();
        assert_eq!(b.vouchers_of("s"), vec!["alice", "bob", "carol"]);
        assert_eq!(a.vouchers_of("s"), b.vouchers_of("s"));

        let mut c = VouchGraph::new();
        c.add("v", "zeta", 1).unwrap();
        c.add("v", "alpha", 2).unwrap();
        assert_eq!(c.subjects_of("v"), vec!["alpha", "zeta"]);
    }

    #[test]
    fn serde_roundtrip() {
        let v = Vouch {
            voucher: "alice".into(),
            subject: "claim-1".into(),
            at_ms: 42,
        };
        let j = serde_json::to_string(&v).unwrap();
        let back: Vouch = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);

        let g = sample();
        let j = serde_json::to_string(&g).unwrap();
        let mut back: VouchGraph = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
        assert_eq!(back.vouchers_of("claim-1"), vec!["alice", "bob", "carol"]);
        // `add` invariants still enforced after a load.
        assert_eq!(back.add("alice", "claim-1", 99), Err(VouchError::Duplicate));
    }

    #[test]
    fn at_ms_stored_unchanged() {
        let mut g = VouchGraph::new();
        g.add("alice", "claim-1", -5).unwrap();
        let j = serde_json::to_string(&g).unwrap();
        assert!(j.contains("\"at_ms\":-5"), "clock value must survive: {j}");
    }

    #[test]
    fn error_display_and_serde() {
        assert_eq!(
            VouchError::SelfVouch.to_string(),
            "self-vouch refused: voucher and subject are the same"
        );
        assert_eq!(
            VouchError::Duplicate.to_string(),
            "duplicate vouch refused: edge already present"
        );
        assert_eq!(
            VouchError::EmptyField("subject").to_string(),
            "empty required field: subject"
        );

        assert_eq!(
            serde_json::to_string(&VouchError::SelfVouch).unwrap(),
            "\"SelfVouch\""
        );
        assert_eq!(
            serde_json::to_string(&VouchError::Duplicate).unwrap(),
            "\"Duplicate\""
        );
        assert_eq!(
            serde_json::to_string(&VouchError::EmptyField("voucher")).unwrap(),
            "{\"EmptyField\":\"voucher\"}"
        );
    }

    #[test]
    fn determinism_repeated_queries_identical() {
        let g = sample();
        for _ in 0..5 {
            assert_eq!(g.vouchers_of("claim-1"), vec!["alice", "bob", "carol"]);
            assert_eq!(vouch_count(&g, "claim-1"), 3);
            assert!(meets_threshold(&g, "claim-1", 3));
        }
    }
}
