//! Requirement → task → source → finding chain + coverage — task A3.2.2
//! (batch 07, §4).
//!
//! A collection run produces findings; a finding only *counts* once it can be
//! traced back to the requirement it answers. This module is the deterministic
//! bookkeeping half of that trace:
//!
//! * [`ChainLink`] — one recorded edge of the chain: a `finding` (the product
//!   of a `task`, drawn from a `source`) answers a `requirement`.
//! * [`LinkGraph`] — the append-only set of links, queried per requirement:
//!   [`LinkGraph::findings_for`] (the links themselves),
//!   [`LinkGraph::sources_for`] / [`LinkGraph::tasks_for`] (deduped ids), and
//!   [`LinkGraph::coverage`] (findings count + distinct sources + flag).
//! * [`coverage_summary`] — one [`CoverageRow`] per requirement held by a
//!   [`RequirementStore`](crate::requirements::RequirementStore), so a run can
//!   report “which requirements did we actually answer?” without the caller
//!   hand-rolling the join.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * **Field validation first, then duplicates.** [`LinkGraph::add`] rejects
//!   any link whose `requirement` / `task` / `source` / `finding` is empty or
//!   whitespace-only ([`LinkError::EmptyField`], checked in that field order),
//!   and only then rejects an *exact* duplicate — all four fields equal — as
//!   [`LinkError::Duplicate`]. A link that differs in any one field is a
//!   distinct edge and is accepted (the same source re-collected by another
//!   task, or answering another finding, is legitimate).
//! * **Order is insertion order everywhere.** Links are held in the order they
//!   were added; [`LinkGraph::findings_for`] returns the matching links in
//!   that order, and [`LinkGraph::sources_for`] / [`LinkGraph::tasks_for`]
//!   return each distinct id at its *first* occurrence (“deduped, stable
//!   order” — first-seen, not sorted). Nothing here sorts by name.
//! * **`findings_for` is not deduplicated** — exact-duplicate links cannot
//!   exist (rejected at [`LinkGraph::add`]), so every returned link is a
//!   distinct (task, source, finding) edge for that requirement. The
//!   deduplication in `sources_for` / `tasks_for` collapses repeats of the
//!   *same id* across different links.
//! * **Coverage math.** `covered = findings >= 1`; `distinct_sources` counts
//!   unique `source` ids among that requirement’s links; `findings` counts
//!   links, not unique findings (two findings from the same source still
//!   count twice). All zero / `false` for an unknown requirement — a miss is
//!   not an error.
//! * **`coverage_summary` is one row per requirement in the store, ascending
//!   by requirement id.** Requirements with zero links get a zeroed,
//!   `covered: false` row; links referencing a requirement that is *not* in
//!   the store contribute to nothing (the store is the authority on which
//!   requirements exist). Deliberately **not** re-sorted so uncovered rows
//!   come first — need-based ordering (priority / age / gap reason) is
//!   [`crate::gap_register`]’s job (§5), this function stays a pure
//!   id-ordered report.
//! * **Complexity is linear by design.** `add` scans for exact duplicates and
//!   the query methods scan the link list; a run’s chain volume is modest
//!   (number of tasked findings), so a single flat `Vec` keeps insertion
//!   order, one source of truth, and trivial serde rather than maintaining a
//!   parallel index.
//!
//! No clock, filesystem, or global state: identical inputs always produce
//! identical outputs.


use std::fmt;

use serde::{Deserialize, Serialize};

use crate::requirements::RequirementStore;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One edge of the requirement → task → source → finding chain.
///
/// All four fields are ids / references held as strings; the graph does not
/// interpret them beyond equality and (non-)emptiness. A link asserts: the
/// `finding` produced by `task` from `source` answers `requirement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    /// Requirement id this evidence answers (see
    /// [`RequirementStore`](crate::requirements::RequirementStore)).
    pub requirement: String,
    /// Task id that produced the finding.
    pub task: String,
    /// Source id the finding was drawn from.
    pub source: String,
    /// Finding id itself.
    pub finding: String,
}

/// Per-requirement coverage snapshot returned by [`LinkGraph::coverage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Number of links (findings) recorded for the requirement.
    pub findings: usize,
    /// Number of distinct `source` ids among those links.
    pub distinct_sources: usize,
    /// `true` iff at least one finding is linked (`findings >= 1`).
    pub covered: bool,
}

/// One row of [`coverage_summary`]: coverage for a requirement that exists in
/// the [`RequirementStore`](crate::requirements::RequirementStore).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRow {
    /// Requirement id the row reports on.
    pub requirement_id: String,
    /// `true` iff the graph links ≥ 1 finding to this requirement.
    pub covered: bool,
    /// Number of linked findings (0 when uncovered).
    pub findings: usize,
    /// Number of distinct sources behind those findings.
    pub distinct_sources: usize,
}

/// Errors from [`LinkGraph::add`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// An exact duplicate (all four fields equal) is already in the graph.
    Duplicate {
        /// Requirement id of the rejected link.
        requirement: String,
        /// Task id of the rejected link.
        task: String,
        /// Source id of the rejected link.
        source: String,
        /// Finding id of the rejected link.
        finding: String,
    },
    /// A required field was empty / whitespace-only (field name carried).
    EmptyField(&'static str),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Duplicate {
                requirement,
                task,
                source,
                finding,
            } => write!(
                f,
                "duplicate chain link: requirement={requirement} task={task} source={source} finding={finding}"
            ),
            LinkError::EmptyField(field) => write!(f, "empty required field: {field}"),
        }
    }
}

impl std::error::Error for LinkError {}

// ---------------------------------------------------------------------------
// LinkGraph
// ---------------------------------------------------------------------------

/// Append-only set of [`ChainLink`]s, queried per requirement.
///
/// Dedup rule and ordering: see the module docs. Serde-round-trips as a
/// transparent sequence of links (insertion order preserved).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LinkGraph {
    links: Vec<ChainLink>,
}

impl LinkGraph {
    /// Empty graph.
    pub fn new() -> Self {
        LinkGraph { links: Vec::new() }
    }

    /// Validate and record `l`.
    ///
    /// Validation order (documented): empty-field checks in field order
    /// `requirement` → `task` → `source` → `finding` ([`LinkError::EmptyField`]),
    /// then exact-duplicate rejection ([`LinkError::Duplicate`]; all four
    /// fields equal). On any error the graph is unchanged.
    pub fn add(&mut self, l: ChainLink) -> Result<(), LinkError> {
        if l.requirement.trim().is_empty() {
            return Err(LinkError::EmptyField("requirement"));
        }
        if l.task.trim().is_empty() {
            return Err(LinkError::EmptyField("task"));
        }
        if l.source.trim().is_empty() {
            return Err(LinkError::EmptyField("source"));
        }
        if l.finding.trim().is_empty() {
            return Err(LinkError::EmptyField("finding"));
        }
        if self.links.iter().any(|x| *x == l) {
            return Err(LinkError::Duplicate {
                requirement: l.requirement,
                task: l.task,
                source: l.source,
                finding: l.finding,
            });
        }
        self.links.push(l);
        Ok(())
    }

    /// All links recorded for `req`, in insertion order.
    ///
    /// Not deduplicated (exact duplicates cannot exist — see module docs);
    /// returns an empty vec for an unknown requirement.
    pub fn findings_for(&self, req: &str) -> Vec<&ChainLink> {
        self.links.iter().filter(|l| l.requirement == req).collect()
    }

    /// Distinct `source` ids among the links for `req`, each at its
    /// **first** occurrence (insertion order, no sorting).
    pub fn sources_for(&self, req: &str) -> Vec<String> {
        distinct_ids_for(&self.links, req, |l| &l.source)
    }

    /// Distinct `task` ids among the links for `req`, each at its
    /// **first** occurrence (insertion order, no sorting).
    pub fn tasks_for(&self, req: &str) -> Vec<String> {
        distinct_ids_for(&self.links, req, |l| &l.task)
    }

    /// Coverage snapshot for `req`: findings count, distinct sources, and the
    /// `covered` flag (`findings >= 1`). Zero / `false` for unknown ids.
    pub fn coverage(&self, req: &str) -> Coverage {
        let findings = self.findings_for(req).len();
        Coverage {
            findings,
            distinct_sources: self.sources_for(req).len(),
            covered: findings >= 1,
        }
    }

    /// Number of links held.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// `true` if no links are held.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// Shared first-seen dedupe used by `sources_for` / `tasks_for`.
fn distinct_ids_for<'a, F>(links: &'a [ChainLink], req: &str, pick: F) -> Vec<String>
where
    F: Fn(&'a ChainLink) -> &'a String,
{
    let mut out: Vec<String> = Vec::new();
    for l in links {
        if l.requirement == req {
            let id = pick(l);
            if !out.iter().any(|s| s == id) {
                out.push(id.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// coverage_summary
// ---------------------------------------------------------------------------

/// One [`CoverageRow`] per requirement in `store`, **ascending by
/// requirement id** (the store iterates ascending; the explicit sort keeps the
/// contract true even if iteration order ever changes).
///
/// Requirements with zero links yield a zeroed, `covered: false` row. Links in
/// `graph` whose requirement id is not held by `store` are not represented.
/// No need-based re-ordering happens here (deliberately — see module docs).
pub fn coverage_summary(graph: &LinkGraph, store: &RequirementStore) -> Vec<CoverageRow> {
    let mut rows: Vec<CoverageRow> = store
        .iter()
        .map(|r| {
            let c = graph.coverage(&r.id);
            CoverageRow {
                requirement_id: r.id.clone(),
                covered: c.covered,
                findings: c.findings,
                distinct_sources: c.distinct_sources,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));
    rows
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requirements::{ReqKind, ReqStatus, Requirement};

    /// Test link constructor.
    fn link(req: &str, task: &str, source: &str, finding: &str) -> ChainLink {
        ChainLink {
            requirement: req.to_string(),
            task: task.to_string(),
            source: source.to_string(),
            finding: finding.to_string(),
        }
    }

    /// Test requirement constructor (store validates on append).
    fn req(id: &str, priority: u8) -> Requirement {
        Requirement {
            id: id.to_string(),
            kind: ReqKind::Pir,
            question: format!("question {id}"),
            owner: "owner".to_string(),
            priority,
            created_ms: 1_000,
            expires_ms: None,
            status: ReqStatus::Open,
        }
    }

    #[test]
    fn add_accumulates_links() {
        let mut g = LinkGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);

        g.add(link("r1", "t1", "s1", "f1")).unwrap();
        g.add(link("r1", "t1", "s1", "f2")).unwrap();
        g.add(link("r2", "t2", "s2", "f3")).unwrap();
        assert_eq!(g.len(), 3);
        assert!(!g.is_empty());
        assert_eq!(g.findings_for("r1").len(), 2);
        assert_eq!(g.findings_for("r2").len(), 1);
        assert!(g.findings_for("r3").is_empty());
    }

    #[test]
    fn add_rejects_exact_duplicate_but_allows_near_duplicates() {
        let mut g = LinkGraph::new();
        let l = link("r1", "t1", "s1", "f1");
        g.add(l.clone()).unwrap();

        assert_eq!(
            g.add(l.clone()),
            Err(LinkError::Duplicate {
                requirement: "r1".to_string(),
                task: "t1".to_string(),
                source: "s1".to_string(),
                finding: "f1".to_string(),
            })
        );
        assert_eq!(g.len(), 1, "rejected duplicate left graph unchanged");

        // Differing in any one field is a distinct edge.
        g.add(link("r1", "t1", "s1", "f2")).unwrap(); // other finding
        g.add(link("r1", "t1", "s2", "f1")).unwrap(); // other source
        g.add(link("r1", "t2", "s1", "f1")).unwrap(); // other task
        g.add(link("r2", "t1", "s1", "f1")).unwrap(); // other requirement
        assert_eq!(g.len(), 5);
    }

    #[test]
    fn add_rejects_each_empty_field_with_its_name() {
        let mut g = LinkGraph::new();

        let mut cases: Vec<(ChainLink, &'static str)> = Vec::new();
        let mut c = link("r1", "t1", "s1", "f1");
        c.requirement = "   ".to_string();
        cases.push((c, "requirement"));
        let mut c = link("r1", "t1", "s1", "f1");
        c.task = String::new();
        cases.push((c, "task"));
        let mut c = link("r1", "t1", "s1", "f1");
        c.source = " \t ".to_string();
        cases.push((c, "source"));
        let mut c = link("r1", "t1", "s1", "f1");
        c.finding = String::new();
        cases.push((c, "finding"));

        for (bad, field) in cases {
            assert_eq!(g.add(bad), Err(LinkError::EmptyField(field)));
        }
        assert!(g.is_empty(), "rejected links never landed");
    }

    #[test]
    fn findings_for_filters_and_keeps_insertion_order() {
        let mut g = LinkGraph::new();
        g.add(link("r1", "t1", "s1", "f1")).unwrap();
        g.add(link("r2", "t9", "s9", "f9")).unwrap();
        g.add(link("r1", "t2", "s1", "f2")).unwrap();
        g.add(link("r1", "t1", "s2", "f3")).unwrap();

        let got: Vec<&str> = g
            .findings_for("r1")
            .iter()
            .map(|l| l.finding.as_str())
            .collect();
        assert_eq!(got, vec!["f1", "f2", "f3"], "insertion order, r2 excluded");

        let all: Vec<&str> = g.findings_for("r2").iter().map(|l| l.finding.as_str()).collect();
        assert_eq!(all, vec!["f9"]);
    }

    #[test]
    fn sources_for_dedupes_first_seen_order() {
        let mut g = LinkGraph::new();
        g.add(link("r1", "t1", "sZ", "f1")).unwrap();
        g.add(link("r1", "t2", "sA", "f2")).unwrap();
        g.add(link("r1", "t3", "sZ", "f3")).unwrap(); // sZ repeats
        g.add(link("r1", "t4", "sM", "f4")).unwrap();
        g.add(link("r2", "t5", "sOTHER", "f5")).unwrap();

        assert_eq!(
            g.sources_for("r1"),
            vec!["sZ".to_string(), "sA".to_string(), "sM".to_string()],
            "deduped, first-seen order (NOT sorted), other requirements excluded"
        );
        assert_eq!(g.sources_for("r2"), vec!["sOTHER".to_string()]);
        assert!(g.sources_for("nope").is_empty());
    }

    #[test]
    fn tasks_for_dedupes_first_seen_order() {
        let mut g = LinkGraph::new();
        g.add(link("r1", "tz", "s1", "f1")).unwrap();
        g.add(link("r1", "ta", "s1", "f2")).unwrap();
        g.add(link("r1", "tz", "s2", "f3")).unwrap(); // tz repeats
        g.add(link("r2", "tx", "s1", "f4")).unwrap();

        assert_eq!(
            g.tasks_for("r1"),
            vec!["tz".to_string(), "ta".to_string()],
            "deduped, first-seen order"
        );
        assert!(g.tasks_for("nope").is_empty());
    }

    #[test]
    fn coverage_math_including_multi_source() {
        let mut g = LinkGraph::new();
        g.add(link("r1", "t1", "s1", "f1")).unwrap();
        g.add(link("r1", "t1", "s1", "f2")).unwrap(); // same source, new finding
        g.add(link("r1", "t2", "s2", "f3")).unwrap();

        let c = g.coverage("r1");
        assert_eq!(c.findings, 3, "findings count links, not unique sources");
        assert_eq!(c.distinct_sources, 2);
        assert!(c.covered);

        // Single link: one finding, one source.
        let c1 = g.coverage("r2");
        assert_eq!(
            c1,
            Coverage {
                findings: 0,
                distinct_sources: 0,
                covered: false
            },
            "unknown requirement -> zeroed snapshot, not an error"
        );

        let mut single = LinkGraph::new();
        single.add(link("rX", "t", "s", "f")).unwrap();
        assert_eq!(
            single.coverage("rX"),
            Coverage {
                findings: 1,
                distinct_sources: 1,
                covered: true
            }
        );
    }

    #[test]
    fn coverage_summary_one_row_per_requirement_ascending_id() {
        let mut store = RequirementStore::new();
        // Append out of id order; store iterates ascending.
        store.append(req("r-b", 1)).unwrap();
        store.append(req("r-a", 2)).unwrap();
        store.append(req("r-c", 3)).unwrap(); // uncovered

        let mut g = LinkGraph::new();
        g.add(link("r-b", "t1", "s1", "f1")).unwrap();
        g.add(link("r-b", "t2", "s2", "f2")).unwrap();
        g.add(link("r-a", "t3", "s1", "f3")).unwrap();

        let rows = coverage_summary(&g, &store);
        assert_eq!(rows.len(), 3, "one row per requirement");
        assert_eq!(
            rows.iter().map(|r| r.requirement_id.as_str()).collect::<Vec<_>>(),
            vec!["r-a", "r-b", "r-c"],
            "ascending by id — NOT uncovered-first"
        );
        assert_eq!(
            rows[0],
            CoverageRow {
                requirement_id: "r-a".to_string(),
                covered: true,
                findings: 1,
                distinct_sources: 1
            }
        );
        assert_eq!(
            rows[1],
            CoverageRow {
                requirement_id: "r-b".to_string(),
                covered: true,
                findings: 2,
                distinct_sources: 2
            }
        );
        assert_eq!(
            rows[2],
            CoverageRow {
                requirement_id: "r-c".to_string(),
                covered: false,
                findings: 0,
                distinct_sources: 0
            },
            "requirement with zero links still gets a zeroed row"
        );
    }

    #[test]
    fn coverage_summary_ignores_links_for_requirements_outside_store() {
        let mut store = RequirementStore::new();
        store.append(req("r1", 1)).unwrap();

        let mut g = LinkGraph::new();
        g.add(link("r1", "t1", "s1", "f1")).unwrap();
        g.add(link("ghost", "t2", "s2", "f2")).unwrap(); // not in store

        let rows = coverage_summary(&g, &store);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requirement_id, "r1");
        assert_eq!(rows[0].findings, 1);
        // The ghost link still informs that requirement's own coverage…
        assert_eq!(g.coverage("ghost").findings, 1);
        // …but is not represented in the store-derived summary.
    }

    #[test]
    fn empty_graph_and_store_edges() {
        let g = LinkGraph::new();
        let store = RequirementStore::new();

        assert!(g.findings_for("r").is_empty());
        assert!(g.sources_for("r").is_empty());
        assert!(g.tasks_for("r").is_empty());
        assert_eq!(
            g.coverage("r"),
            Coverage {
                findings: 0,
                distinct_sources: 0,
                covered: false
            }
        );
        assert!(coverage_summary(&g, &store).is_empty());

        // Non-empty store, empty graph: all rows uncovered.
        let mut s = RequirementStore::new();
        s.append(req("only", 1)).unwrap();
        let rows = coverage_summary(&g, &s);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].covered);
        assert_eq!(rows[0].findings, 0);
    }

    #[test]
    fn deterministic_across_identical_rebuilds() {
        fn build() -> (LinkGraph, RequirementStore) {
            let mut g = LinkGraph::new();
            g.add(link("r1", "t1", "s1", "f1")).unwrap();
            g.add(link("r1", "t2", "s1", "f2")).unwrap();
            g.add(link("r2", "t1", "s2", "f3")).unwrap();
            let mut s = RequirementStore::new();
            s.append(req("r1", 1)).unwrap();
            s.append(req("r2", 2)).unwrap();
            (g, s)
        }
        let (g1, s1) = build();
        let (g2, s2) = build();
        assert_eq!(g1, g2);
        assert_eq!(coverage_summary(&g1, &s1), coverage_summary(&g2, &s2));
        assert_eq!(g1.sources_for("r1"), g2.sources_for("r1"));
        assert_eq!(g1.coverage("r1"), g2.coverage("r1"));
    }

    #[test]
    fn serde_chain_link_round_trip_and_wire_names() {
        let l = link("r1", "t1", "s1", "f1");
        let j = serde_json::to_string(&l).unwrap();
        assert!(j.contains("\"requirement\":\"r1\""));
        assert!(j.contains("\"task\":\"t1\""));
        assert!(j.contains("\"source\":\"s1\""));
        assert!(j.contains("\"finding\":\"f1\""));
        let back: ChainLink = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn serde_graph_and_coverage_row_round_trip_preserves_behavior() {
        let mut g = LinkGraph::new();
        g.add(link("r1", "t1", "s1", "f1")).unwrap();
        g.add(link("r1", "t2", "s2", "f2")).unwrap();
        g.add(link("r2", "t1", "s1", "f3")).unwrap();

        // Transparent: serializes as a plain array of links.
        let j = serde_json::to_string(&g).unwrap();
        assert!(j.starts_with('[') && j.ends_with(']'), "wire form was {j}");
        let mut back: LinkGraph = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
        assert_eq!(back.coverage("r1"), g.coverage("r1"));
        // Still append-only after the round-trip.
        assert!(back.add(link("r1", "t1", "s1", "f1")).is_err());
        back.add(link("r3", "t3", "s3", "f4")).unwrap();

        let row = CoverageRow {
            requirement_id: "r1".to_string(),
            covered: true,
            findings: 2,
            distinct_sources: 2,
        };
        let rj = serde_json::to_string(&row).unwrap();
        let rback: CoverageRow = serde_json::from_str(&rj).unwrap();
        assert_eq!(row, rback);

        let c = g.coverage("r1");
        let cj = serde_json::to_string(&c).unwrap();
        let cback: Coverage = serde_json::from_str(&cj).unwrap();
        assert_eq!(c, cback);
    }

    #[test]
    fn error_display_mentions_offending_values() {
        let d = LinkError::Duplicate {
            requirement: "rq".to_string(),
            task: "tk".to_string(),
            source: "sr".to_string(),
            finding: "fd".to_string(),
        };
        let s = d.to_string();
        for part in ["rq", "tk", "sr", "fd"] {
            assert!(s.contains(part), "display `{s}` missing `{part}`");
        }
        assert!(LinkError::EmptyField("source").to_string().contains("source"));
    }
}
