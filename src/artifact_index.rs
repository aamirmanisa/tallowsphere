//! Universal artifact & memory index — a **rebuildable view, never the source
//! of truth** (frozen interface B12 §7, B6.3.1–B6.3.3).
//!
//! Design premise: canonical artifact records live in their owning subsystems
//! (vault, derived store, ingest runs, …). [`ArtifactIndex`] adds nothing to
//! them and owns nothing durable — it is a *derived, disposable view* that can
//! be deleted and rebuilt at any moment from those sources. Nothing may treat
//! the index as authoritative: losing it must cost a rebuild, never data. That
//! is why the only constructor is [`ArtifactIndex::rebuild`] — a validated,
//! deterministic fold over a snapshot of the underlying records — and why the
//! `entries` vec is private and the struct deliberately derives no `serde`
//! (a serialized index could be deserialized around validation; rebuild from
//! the owning sources instead of persisting the view).
//!
//! Provenance typing (B6.3.1): every entry carries a [`ProvenanceKind`] —
//!
//! - [`ProvenanceKind::Original`] — primary artifact, no upstream (`source`
//!   must be `None` in practice, but the index records what it is told);
//! - [`ProvenanceKind::Derived`] — produced by processing upstream
//!   artifact(s); `source` names the immediate upstream;
//! - [`ProvenanceKind::Imported`] — brought in from outside this system;
//! - [`ProvenanceKind::Generated`] — synthesized (renders, charts, summaries).
//!
//! Lineage (B6.3.3, [`ArtifactIndex::lineage`]) follows the single `source`
//! pointer upward from an artifact to its root, returning the walked chain in
//! **leaf→root order including the queried artifact itself**: for
//! `report-q3 ← analysis-q3 ← raw-scan`, `lineage("report-q3")` is
//! `["report-q3", "analysis-q3", "raw-scan"]`. The walk is cycle-safe: any
//! revisit of a name already on the chain is [`IndexError::CycleDetected`],
//! and a `source` that names no entry is [`IndexError::Unknown`] — a dangling
//! provenance link is an integrity failure, never silently truncated.
//!
//! Wire forms: default serde naming for [`ProvenanceKind`] (`"Original"`, …)
//! as the frozen §7 leaves naming unpinned. [`IndexError`] derives `Serialize`
//! only — its `BadInput(&'static str)` payload cannot be derive-`Deserialize`d
//! into a `'static` lifetime (repo precedent: `sentinel_lifecycle`,
//! `clearness_gate`, `unknowns`).
//!
//! Input ordering: [`ArtifactIndex::rebuild`] preserves the caller's entry
//! order; every read-side method ([`ArtifactIndex::by_kind`],
//! [`ArtifactIndex::search`]) sorts by `artifact` before returning, so result
//! order is a function of content alone, not of insertion sequence.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Provenance class of an indexed artifact (frozen B6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvenanceKind {
    /// Primary artifact; it is its own root.
    Original,
    /// Produced by processing another indexed artifact.
    Derived,
    /// Brought in from outside the system.
    Imported,
    /// Synthesized from other material (render, chart, summary).
    Generated,
}

/// One row of the artifact index (frozen §7).
///
/// `source` is the single immediate upstream artifact name (`None` for a
/// root). Lookups are exact-string: `"Report"` and `"report"` are distinct
/// artifacts, and a `source` naming nothing in the index is a dangling
/// reference that any lineage walk through it refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Unique artifact name within the index (exact string).
    pub artifact: String,
    /// Provenance class of this artifact.
    pub kind: ProvenanceKind,
    /// Immediate upstream artifact, if any.
    pub source: Option<String>,
    /// Actor (tool/run/operator) that produced this artifact.
    pub produced_by: String,
    /// Production time, milliseconds since the epoch.
    pub produced_ms: i64,
}

/// A rebuildable, validated view over a snapshot of artifact records.
///
/// "Rebuildable view, never source of truth": see the module docs. Invariants
/// enforced by [`ArtifactIndex::rebuild`] (unrepresentable from outside the
/// module, since `entries` is private): every `artifact` and `produced_by` is
/// non-empty, every `Some(source)` is non-empty, and `artifact` names are
/// unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIndex {
    entries: Vec<IndexEntry>,
}

impl ArtifactIndex {
    /// Build the view from a snapshot of artifact records.
    ///
    /// Validation runs per entry in **input order**; for each entry the checks
    /// are: non-empty `artifact` ⇒ non-empty `produced_by` ⇒ non-empty
    /// `source` (when `Some`) ⇒ artifact-uniqueness against earlier entries.
    /// The first failure wins, so a duplicate earlier in the list is reported
    /// as [`IndexError::DupId`] even if a later entry would have failed field
    /// validation, and an entry that is both empty-named and duplicate is
    /// reported as [`IndexError::BadInput`].
    pub fn rebuild(entries: Vec<IndexEntry>) -> Result<ArtifactIndex, IndexError> {
        let mut seen: HashSet<&str> = HashSet::with_capacity(entries.len());
        for e in &entries {
            if e.artifact.is_empty() {
                return Err(IndexError::BadInput("artifact"));
            }
            if e.produced_by.is_empty() {
                return Err(IndexError::BadInput("produced_by"));
            }
            if let Some(src) = &e.source {
                if src.is_empty() {
                    return Err(IndexError::BadInput("source"));
                }
            }
            if !seen.insert(e.artifact.as_str()) {
                return Err(IndexError::DupId);
            }
        }
        drop(seen);
        Ok(ArtifactIndex { entries })
    }

    /// Exact-string lookup of one artifact; unknown name ⇒
    /// [`IndexError::Unknown`] (fail-closed: no fuzzy fallback).
    pub fn query(&self, artifact: &str) -> Result<&IndexEntry, IndexError> {
        self.find(artifact).ok_or(IndexError::Unknown)
    }

    /// All entries of one provenance kind, sorted by `artifact`.
    pub fn by_kind(&self, kind: ProvenanceKind) -> Vec<&IndexEntry> {
        let mut out: Vec<&IndexEntry> =
            self.entries.iter().filter(|e| e.kind == kind).collect();
        out.sort_by(|a, b| a.artifact.cmp(&b.artifact));
        out
    }

    /// Walk `source` upward from `artifact` to its root.
    ///
    /// Returns the chain in **leaf→root order, starting with the queried
    /// artifact itself**; a root artifact yields a one-element chain. A
    /// `source` that names no entry ⇒ [`IndexError::Unknown`]; a chain that
    /// revisits a name (self-loop or longer cycle) ⇒
    /// [`IndexError::CycleDetected`]. The walk is bounded by the index size,
    /// so cyclic data can never hang it.
    pub fn lineage(&self, artifact: &str) -> Result<Vec<String>, IndexError> {
        let start = self.find(artifact).ok_or(IndexError::Unknown)?;
        let mut chain = vec![start.artifact.clone()];
        let mut visited: HashSet<&str> = HashSet::new();
        visited.insert(start.artifact.as_str());
        let mut current = start;
        while let Some(src) = current.source.as_deref() {
            if visited.contains(src) {
                return Err(IndexError::CycleDetected);
            }
            let next = self.find(src).ok_or(IndexError::Unknown)?;
            visited.insert(next.artifact.as_str());
            chain.push(next.artifact.clone());
            current = next;
        }
        Ok(chain)
    }

    /// Case-insensitive substring search **on the `artifact` field only**,
    /// sorted by `artifact`. Empty needle ⇒ [`IndexError::BadInput`]
    /// (refuse, don't match everything); no match ⇒ `Ok(vec![])`.
    pub fn search(&self, needle: &str) -> Result<Vec<&IndexEntry>, IndexError> {
        if needle.is_empty() {
            return Err(IndexError::BadInput("needle"));
        }
        let needle_lc = needle.to_lowercase();
        let mut out: Vec<&IndexEntry> = self
            .entries
            .iter()
            .filter(|e| e.artifact.to_lowercase().contains(&needle_lc))
            .collect();
        out.sort_by(|a, b| a.artifact.cmp(&b.artifact));
        Ok(out)
    }

    /// Private exact-string lookup shared by `query`/`lineage`.
    fn find(&self, artifact: &str) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.artifact == artifact)
    }
}

/// Errors from building or querying the artifact index (frozen §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IndexError {
    /// Malformed input; payload names the offending field.
    BadInput(&'static str),
    /// Two entries share the same artifact name.
    DupId,
    /// No entry (or no `source` target) with that exact name.
    Unknown,
    /// The provenance chain revisits a name (self-loop or longer cycle).
    CycleDetected,
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexError::BadInput(what) => {
                write!(f, "artifact index: bad input: {what}")
            }
            IndexError::DupId => write!(f, "artifact index: duplicate artifact id"),
            IndexError::Unknown => write!(f, "artifact index: unknown artifact"),
            IndexError::CycleDetected => {
                write!(f, "artifact index: provenance cycle detected")
            }
        }
    }
}

impl std::error::Error for IndexError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(
        artifact: &str,
        kind: ProvenanceKind,
        source: Option<&str>,
        produced_by: &str,
        produced_ms: i64,
    ) -> IndexEntry {
        IndexEntry {
            artifact: artifact.to_string(),
            kind,
            source: source.map(str::to_string),
            produced_by: produced_by.to_string(),
            produced_ms,
        }
    }

    /// The canonical fixture: two chains plus a root imported artifact.
    ///
    /// `report-q3 ← analysis-q3 ← raw-scan` (Derived/Derived/Original) and
    /// `chart-q3 ← analysis-q3` (Generated), `import-q3` (Imported root),
    /// `archive-2024` (Original root). Input order is deliberately unsorted.
    fn sample() -> ArtifactIndex {
        ArtifactIndex::rebuild(vec![
            entry(
                "report-q3",
                ProvenanceKind::Derived,
                Some("analysis-q3"),
                "compiler",
                300,
            ),
            entry(
                "analysis-q3",
                ProvenanceKind::Derived,
                Some("raw-scan"),
                "pipeline",
                200,
            ),
            entry("raw-scan", ProvenanceKind::Original, None, "collector", 100),
            entry(
                "chart-q3",
                ProvenanceKind::Generated,
                Some("analysis-q3"),
                "renderer",
                350,
            ),
            entry("import-q3", ProvenanceKind::Imported, None, "ingest", 50),
            entry(
                "archive-2024",
                ProvenanceKind::Original,
                None,
                "collector",
                10,
            ),
        ])
        .expect("sample fixture must build")
    }

    fn names<'a>(rows: &[&'a IndexEntry]) -> Vec<&'a str> {
        rows.iter().map(|e| e.artifact.as_str()).collect()
    }

    // ---- rebuild / dup -------------------------------------------------

    #[test]
    fn rebuild_accepts_valid_chain_and_preserves_input_order() {
        let ix = sample();
        assert_eq!(ix.entries.len(), 6);
        // input order preserved internally
        assert_eq!(ix.entries[0].artifact, "report-q3");
        assert_eq!(ix.entries[5].artifact, "archive-2024");
        // fields survive intact
        let e = ix.query("report-q3").unwrap();
        assert_eq!(e.kind, ProvenanceKind::Derived);
        assert_eq!(e.source.as_deref(), Some("analysis-q3"));
        assert_eq!(e.produced_by, "compiler");
        assert_eq!(e.produced_ms, 300);
        let root = ix.query("raw-scan").unwrap();
        assert_eq!(root.source, None);
        assert_eq!(root.kind, ProvenanceKind::Original);
    }

    #[test]
    fn rebuild_rejects_empty_artifact() {
        let err = ArtifactIndex::rebuild(vec![entry(
            "",
            ProvenanceKind::Original,
            None,
            "collector",
            1,
        )])
        .unwrap_err();
        assert_eq!(err, IndexError::BadInput("artifact"));
    }

    #[test]
    fn rebuild_rejects_empty_produced_by() {
        let err = ArtifactIndex::rebuild(vec![entry(
            "a",
            ProvenanceKind::Derived,
            Some("b"),
            "",
            1,
        )])
        .unwrap_err();
        assert_eq!(err, IndexError::BadInput("produced_by"));
    }

    #[test]
    fn rebuild_rejects_empty_source() {
        let err = ArtifactIndex::rebuild(vec![entry(
            "a",
            ProvenanceKind::Derived,
            Some(""),
            "pipeline",
            1,
        )])
        .unwrap_err();
        assert_eq!(err, IndexError::BadInput("source"));
    }

    #[test]
    fn rebuild_rejects_duplicate_artifact() {
        let err = ArtifactIndex::rebuild(vec![
            entry("dup", ProvenanceKind::Original, None, "a", 1),
            entry("other", ProvenanceKind::Original, None, "a", 2),
            entry("dup", ProvenanceKind::Derived, Some("other"), "b", 3),
        ])
        .unwrap_err();
        assert_eq!(err, IndexError::DupId);
    }

    #[test]
    fn rebuild_rejects_duplicate_with_different_fields() {
        // Same name, different kind/source/by/ms — still a duplicate.
        let err = ArtifactIndex::rebuild(vec![
            entry("x", ProvenanceKind::Original, None, "a", 1),
            entry("x", ProvenanceKind::Generated, Some("a"), "b", 999),
        ])
        .unwrap_err();
        assert_eq!(err, IndexError::DupId);
    }

    #[test]
    fn rebuild_empty_input_is_empty_index() {
        let ix = ArtifactIndex::rebuild(vec![]).unwrap();
        assert!(ix.entries.is_empty());
        assert!(ix.by_kind(ProvenanceKind::Original).is_empty());
        assert!(ix.search("anything").unwrap().is_empty());
        assert_eq!(ix.query("anything"), Err(IndexError::Unknown));
        assert_eq!(ix.lineage("anything"), Err(IndexError::Unknown));
    }

    #[test]
    fn rebuild_is_exact_string_case_sensitive() {
        // "A" and "a" are distinct artifacts (exact-string identity).
        let ix = ArtifactIndex::rebuild(vec![
            entry("A", ProvenanceKind::Original, None, "a", 1),
            entry("a", ProvenanceKind::Original, None, "a", 2),
        ])
        .unwrap();
        assert_eq!(ix.query("A").unwrap().produced_ms, 1);
        assert_eq!(ix.query("a").unwrap().produced_ms, 2);
    }

    #[test]
    fn rebuild_check_order_is_input_order_first_failure_wins() {
        // Entry 1 is fine, entry 2 is a duplicate, entry 3 would fail field
        // validation — the duplicate (earlier) is reported.
        let err = ArtifactIndex::rebuild(vec![
            entry("ok", ProvenanceKind::Original, None, "a", 1),
            entry("ok", ProvenanceKind::Original, None, "a", 2),
            entry("", ProvenanceKind::Original, None, "a", 3),
        ])
        .unwrap_err();
        assert_eq!(err, IndexError::DupId);
        // Within one entry, empty-field checks precede the dup check.
        let err = ArtifactIndex::rebuild(vec![
            entry("ok", ProvenanceKind::Original, None, "a", 1),
            entry("", ProvenanceKind::Original, None, "a", 2),
        ])
        .unwrap_err();
        assert_eq!(err, IndexError::BadInput("artifact"));
    }

    // ---- query ---------------------------------------------------------

    #[test]
    fn query_exact_hit_and_miss() {
        let ix = sample();
        assert_eq!(ix.query("import-q3").unwrap().produced_by, "ingest");
        assert_eq!(ix.query("chart-q3").unwrap().produced_ms, 350);
        assert_eq!(ix.query("no-such"), Err(IndexError::Unknown));
        assert_eq!(ix.query(""), Err(IndexError::Unknown));
        // case-variant is a miss — exact strings only
        assert_eq!(ix.query("REPORT-Q3"), Err(IndexError::Unknown));
    }

    // ---- by_kind -------------------------------------------------------

    #[test]
    fn by_kind_sorted_and_filtered() {
        let ix = sample();
        assert_eq!(
            names(&ix.by_kind(ProvenanceKind::Derived)),
            vec!["analysis-q3", "report-q3"]
        );
        assert_eq!(
            names(&ix.by_kind(ProvenanceKind::Original)),
            vec!["archive-2024", "raw-scan"]
        );
        assert_eq!(
            names(&ix.by_kind(ProvenanceKind::Generated)),
            vec!["chart-q3"]
        );
        assert_eq!(names(&ix.by_kind(ProvenanceKind::Imported)), vec!["import-q3"]);
    }

    #[test]
    fn by_kind_empty_kind_returns_empty() {
        let ix = ArtifactIndex::rebuild(vec![entry(
            "only",
            ProvenanceKind::Imported,
            None,
            "ingest",
            1,
        )])
        .unwrap();
        assert!(ix.by_kind(ProvenanceKind::Original).is_empty());
        assert!(ix.by_kind(ProvenanceKind::Derived).is_empty());
        assert!(ix.by_kind(ProvenanceKind::Generated).is_empty());
    }

    // ---- lineage -------------------------------------------------------

    #[test]
    fn lineage_full_chain_leaf_to_root() {
        let ix = sample();
        // includes the queried artifact itself, then source upward to root
        assert_eq!(
            ix.lineage("report-q3").unwrap(),
            vec!["report-q3", "analysis-q3", "raw-scan"]
        );
        // branch shares the same tail
        assert_eq!(
            ix.lineage("chart-q3").unwrap(),
            vec!["chart-q3", "analysis-q3", "raw-scan"]
        );
        // mid-chain start
        assert_eq!(
            ix.lineage("analysis-q3").unwrap(),
            vec!["analysis-q3", "raw-scan"]
        );
    }

    #[test]
    fn lineage_root_is_singleton() {
        let ix = sample();
        assert_eq!(ix.lineage("raw-scan").unwrap(), vec!["raw-scan"]);
        assert_eq!(ix.lineage("import-q3").unwrap(), vec!["import-q3"]);
        assert_eq!(ix.lineage("archive-2024").unwrap(), vec!["archive-2024"]);
    }

    #[test]
    fn lineage_unknown_artifact_is_unknown() {
        let ix = sample();
        assert_eq!(ix.lineage("no-such"), Err(IndexError::Unknown));
        assert_eq!(ix.lineage(""), Err(IndexError::Unknown));
        assert_eq!(ix.lineage("REPORT-Q3"), Err(IndexError::Unknown));
    }

    #[test]
    fn lineage_dangling_source_is_unknown() {
        let ix = ArtifactIndex::rebuild(vec![
            entry("a", ProvenanceKind::Derived, Some("ghost"), "p", 1),
            entry("b", ProvenanceKind::Original, None, "p", 2),
        ])
        .unwrap();
        assert_eq!(ix.lineage("a"), Err(IndexError::Unknown));
        // a dangling link deeper in the chain is refused too
        let deep = ArtifactIndex::rebuild(vec![
            entry("top", ProvenanceKind::Derived, Some("mid"), "p", 1),
            entry("mid", ProvenanceKind::Derived, Some("nowhere"), "p", 2),
        ])
        .unwrap();
        assert_eq!(deep.lineage("top"), Err(IndexError::Unknown));
        assert_eq!(deep.lineage("mid"), Err(IndexError::Unknown));
        // untouched entries remain queryable
        assert_eq!(ix.query("b").unwrap().produced_ms, 2);
    }

    #[test]
    fn lineage_cycle_detected() {
        // 3-cycle: a → b → c → a; refused from every member.
        let ix = ArtifactIndex::rebuild(vec![
            entry("a", ProvenanceKind::Derived, Some("b"), "p", 1),
            entry("b", ProvenanceKind::Derived, Some("c"), "p", 2),
            entry("c", ProvenanceKind::Derived, Some("a"), "p", 3),
            entry("d", ProvenanceKind::Derived, Some("e"), "p", 4),
            entry("e", ProvenanceKind::Original, None, "p", 5),
        ])
        .unwrap();
        assert_eq!(ix.lineage("a"), Err(IndexError::CycleDetected));
        assert_eq!(ix.lineage("b"), Err(IndexError::CycleDetected));
        assert_eq!(ix.lineage("c"), Err(IndexError::CycleDetected));
        // the clean chain still walks
        assert_eq!(ix.lineage("d").unwrap(), vec!["d", "e"]);
    }

    #[test]
    fn lineage_self_cycle_detected() {
        let ix = ArtifactIndex::rebuild(vec![entry(
            "self",
            ProvenanceKind::Derived,
            Some("self"),
            "p",
            1,
        )])
        .unwrap();
        assert_eq!(ix.lineage("self"), Err(IndexError::CycleDetected));
    }

    #[test]
    fn lineage_cycle_shorter_than_full_walk_detected() {
        // a → b → c → b: cycle reachable only after stepping past c.
        let ix = ArtifactIndex::rebuild(vec![
            entry("a", ProvenanceKind::Derived, Some("b"), "p", 1),
            entry("b", ProvenanceKind::Derived, Some("c"), "p", 2),
            entry("c", ProvenanceKind::Derived, Some("b"), "p", 3),
        ])
        .unwrap();
        assert_eq!(ix.lineage("a"), Err(IndexError::CycleDetected));
        assert_eq!(ix.lineage("b"), Err(IndexError::CycleDetected));
        // cycle never hangs: repeated calls return the same verdict
        assert_eq!(ix.lineage("a"), Err(IndexError::CycleDetected));
    }

    // ---- search --------------------------------------------------------

    #[test]
    fn search_case_insensitive_sorted() {
        let ix = sample();
        assert_eq!(
            names(&ix.search("q3").unwrap()),
            vec!["analysis-q3", "chart-q3", "import-q3", "report-q3"]
        );
        assert_eq!(
            names(&ix.search("Q3").unwrap()),
            vec!["analysis-q3", "chart-q3", "import-q3", "report-q3"]
        );
        assert_eq!(
            names(&ix.search("ANAlySIS").unwrap()),
            vec!["analysis-q3"]
        );
        assert_eq!(
            names(&ix.search("raw").unwrap()),
            vec!["raw-scan"]
        );
        assert_eq!(
            names(&ix.search("2024").unwrap()),
            vec!["archive-2024"]
        );
    }

    #[test]
    fn search_empty_needle_refused() {
        let ix = sample();
        assert_eq!(ix.search(""), Err(IndexError::BadInput("needle")));
    }

    #[test]
    fn search_scope_is_artifact_field_only_and_miss_is_empty() {
        let ix = sample();
        // "collector" appears only as produced_by, "analysis-q3" only as source
        assert!(ix.search("collector").unwrap().is_empty());
        assert!(ix.search("zzz").unwrap().is_empty());
        // full-name match works
        assert_eq!(names(&ix.search("analysis-q3").unwrap()), vec!["analysis-q3"]);
    }

    // ---- determinism ---------------------------------------------------

    #[test]
    fn determinism_rebuild_twice_is_identical() {
        let one = sample();
        let two = sample();
        assert_eq!(one.entries, two.entries);
        assert_eq!(
            names(&one.by_kind(ProvenanceKind::Derived)),
            names(&two.by_kind(ProvenanceKind::Derived))
        );
        assert_eq!(
            names(&one.search("q3").unwrap()),
            names(&two.search("q3").unwrap())
        );
        assert_eq!(one.lineage("report-q3").unwrap(), two.lineage("report-q3").unwrap());
        // repeated reads on one index are stable too
        assert_eq!(
            names(&one.search("q3").unwrap()),
            names(&one.search("q3").unwrap())
        );
        // and serde of entries is stable across builds
        let j1 = serde_json::to_value(&one.entries).unwrap();
        let j2 = serde_json::to_value(&two.entries).unwrap();
        assert_eq!(j1, j2);
    }

    // ---- serde ---------------------------------------------------------

    #[test]
    fn serde_index_entry_wire_form() {
        let with_source = entry("a", ProvenanceKind::Derived, Some("b"), "p", 42);
        assert_eq!(
            serde_json::to_value(&with_source).unwrap(),
            json!({
                "artifact": "a",
                "kind": "Derived",
                "source": "b",
                "produced_by": "p",
                "produced_ms": 42
            })
        );
        let root = entry("a", ProvenanceKind::Original, None, "p", 0);
        assert_eq!(
            serde_json::to_value(&root).unwrap(),
            json!({
                "artifact": "a",
                "kind": "Original",
                "source": null,
                "produced_by": "p",
                "produced_ms": 0
            })
        );
        // round-trip
        for e in [with_source, root] {
            let back: IndexEntry =
                serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
            assert_eq!(back, e);
        }
    }

    #[test]
    fn serde_provenance_kind_wire_forms() {
        assert_eq!(
            serde_json::to_value(ProvenanceKind::Original).unwrap(),
            json!("Original")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceKind::Derived).unwrap(),
            json!("Derived")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceKind::Imported).unwrap(),
            json!("Imported")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceKind::Generated).unwrap(),
            json!("Generated")
        );
        // declaration order matches provenance-class order
        let all = [
            ProvenanceKind::Original,
            ProvenanceKind::Derived,
            ProvenanceKind::Imported,
            ProvenanceKind::Generated,
        ];
        for k in all {
            let back: ProvenanceKind =
                serde_json::from_value(serde_json::to_value(k).unwrap()).unwrap();
            assert_eq!(back, k);
        }
    }

    #[test]
    fn serde_error_wire_forms() {
        assert_eq!(
            serde_json::to_value(IndexError::BadInput("artifact")).unwrap(),
            json!({"BadInput": "artifact"})
        );
        assert_eq!(serde_json::to_value(IndexError::DupId).unwrap(), json!("DupId"));
        assert_eq!(
            serde_json::to_value(IndexError::Unknown).unwrap(),
            json!("Unknown")
        );
        assert_eq!(
            serde_json::to_value(IndexError::CycleDetected).unwrap(),
            json!("CycleDetected")
        );
        // Display is implemented for every variant
        for err in [
            IndexError::BadInput("artifact"),
            IndexError::BadInput("produced_by"),
            IndexError::BadInput("source"),
            IndexError::BadInput("needle"),
            IndexError::DupId,
            IndexError::Unknown,
            IndexError::CycleDetected,
        ] {
            assert!(err.to_string().contains("artifact index:"));
        }
    }
}
