//! Dataset-reuse advisories (task A3.4.3 · frozen interface §7).
//!
//! When several nominally independent intel datasets share copied or
//! template-derived content, the apparent corroboration between them is
//! illusory: the copies are one source wearing several names. This module
//! turns the pairwise template-reuse detector
//! ([`crate::corroboration::template_reuse_detect`]) into a per-dataset
//! advisory report: for every dataset that shares material with at least one
//! other dataset in the corpus, one [`ReuseAdvisory`] is emitted naming the
//! overlapping datasets, the strongest similarity observed, and a severity
//! word.
//!
//! # Contract (as frozen in §7)
//!
//! * [`advisories`] takes the corpus and a similarity `threshold`.
//! * A pair of datasets whose normalized token-set Jaccard similarity is
//!   `>= threshold` (inclusive, per `template_reuse_detect`) is a *reuse
//!   hit*; every dataset involved in at least one hit gets an advisory.
//! * `severity` is `2` for any overlap (`SEVERITY_OVERLAP`); there is no
//!   lower-severity advisory because an advisory is only emitted when an
//!   overlap exists at all.
//! * Output is ascending by dataset name; within an advisory, `overlapping`
//!   is ascending. Both orders are deterministic.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * **Threshold domain `(0, 1]`**: a threshold outside that open-closed
//!   interval — including `0.0`, negatives, values `> 1.0`, and `NaN` —
//!   yields an empty report. `0.0` is excluded deliberately: an advisory
//!   under a degenerate threshold would flag every pair with any token in
//!   common, which is not an actionable reuse signal. Note this is stricter
//!   than `template_reuse_detect` itself, which admits all pairs at `0.0`.
//! * **Zero-token bodies are never flagged**: pairs involving an empty or
//!   punctuation-only body are skipped by the underlying detector (no
//!   template content to reuse), so such datasets never appear in a report —
//!   not even as the *subject* of one.
//! * **Name identity is the advisory key**: advisories are keyed by dataset
//!   `name`, not by input position. If two corpus entries share a name their
//!   hits are merged into a single advisory (the max similarity and the union
//!   of overlapping names). A hit between two same-named entries records that
//!   name as overlapping itself; the advisory still states the fact that
//!   same-named inputs reuse a template.
//! * **Sort order is lexicographic byte order** of the name (`String`'s
//!   `Ord`), which for ASCII names is the expected dictionary order;
//!   `"Zeta" < "alpha"` by byte order (documented, pinned in tests).
//! * `max_similarity` is the maximum hit similarity over all pairs involving
//!   the dataset, narrowed to `f32` only at report time (the detector computes
//!   in `f64`; the narrowing is the report's storage precision, documented and
//!   pinned by tests).
//! * The advisory report is purely a function of `(datasets, threshold)`: it
//!   touches no clock, filesystem, or global state, so identical inputs
//!   produce identical output (determinism is a security property here —
//!   reports are compared between runs).

use crate::corroboration::template_reuse_detect;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One intake dataset: a named body of material to check for reuse.
///
/// The `name` is the report identity (advisories key on it); `body` is the
/// raw text, normalized by the reused token-set machinery in
/// [`crate::corroboration`]. No validation is imposed here: an empty `body`
/// simply never produces a hit (documented edge rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    /// Dataset identity as recorded at intake (report key).
    pub name: String,
    /// Raw body text. Normalization (case-folding, token splitting) happens
    /// inside the reused detector, so callers pass raw values.
    pub body: String,
}

/// Advisory that one dataset shares material with other datasets in the
/// corpus, i.e. its independence from them is compromised.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReuseAdvisory {
    /// Name of the dataset this advisory is about.
    pub dataset: String,
    /// Names of the datasets it overlaps with, ascending. At least one entry
    /// (an advisory is only emitted when an overlap exists).
    pub overlapping: Vec<String>,
    /// Strongest hit similarity observed between this dataset and any of the
    /// `overlapping` datasets, in `[threshold, 1.0]`.
    pub max_similarity: f32,
    /// Severity of the finding. Pinned to `2` (`SEVERITY_OVERLAP`) for any
    /// overlap; future revisions may add higher severities.
    pub severity: u8,
}

/// Severity emitted for any detected overlap (pinned by §7).
const SEVERITY_OVERLAP: u8 = 2;

// ---------------------------------------------------------------------------
// Advisory builder
// ---------------------------------------------------------------------------

/// Build the reuse-advisory report for `datasets` at `threshold`.
///
/// Every dataset involved in at least one pairwise template-reuse hit (see
/// [`template_reuse_detect`]; inclusive `>=` threshold test) yields one
/// advisory naming its overlapping peers. Output is ascending by dataset
/// name; each `overlapping` list is ascending. An empty corpus, a corpus with
/// no hits, or a threshold outside `(0, 1]` yields an empty report.
///
/// Deterministic: identical `(datasets, threshold)` inputs always produce
/// identical output.
pub fn advisories(datasets: &[Dataset], threshold: f32) -> Vec<ReuseAdvisory> {
    // Degenerate thresholds produce no actionable advisory (documented rule).
    // NaN fails both comparisons, so it lands here too.
    if !(threshold > 0.0 && threshold <= 1.0) {
        return Vec::new();
    }

    let texts: Vec<(String, String)> = datasets
        .iter()
        .map(|d| (d.name.clone(), d.body.clone()))
        .collect();
    let hits = template_reuse_detect(&texts, threshold as f64);

    // Key advisories by dataset name so output ordering is ascending by name
    // and same-named entries merge deterministically (documented edge rule).
    let mut by_name: BTreeMap<String, (BTreeSet<String>, f64)> = BTreeMap::new();
    for hit in &hits {
        let a = by_name.entry(hit.a.clone()).or_insert_with(|| (BTreeSet::new(), 0.0));
        a.0.insert(hit.b.clone());
        if hit.similarity > a.1 {
            a.1 = hit.similarity;
        }
        let b = by_name.entry(hit.b.clone()).or_insert_with(|| (BTreeSet::new(), 0.0));
        b.0.insert(hit.a.clone());
        if hit.similarity > b.1 {
            b.1 = hit.similarity;
        }
    }

    by_name
        .into_iter()
        .map(|(dataset, (overlapping, max_similarity))| ReuseAdvisory {
            dataset,
            overlapping: overlapping.into_iter().collect(),
            max_similarity: max_similarity as f32,
            severity: SEVERITY_OVERLAP,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ds(name: &str, body: &str) -> Dataset {
        Dataset {
            name: name.to_string(),
            body: body.to_string(),
        }
    }

    /// A body deliberately long enough to carry real template content.
    fn base_body() -> &'static str {
        "officials confirm the incident occurred early tuesday in the northern district"
    }

    // ----- core detection ---------------------------------------------------

    #[test]
    fn cloned_corpus_is_flagged_both_ways() {
        let corpus = [ds("alpha", base_body()), ds("beta", base_body())];
        let report = advisories(&corpus, 0.9);

        assert_eq!(report.len(), 2, "both datasets must be advised: {report:?}");

        let alpha = &report[0];
        assert_eq!(alpha.dataset, "alpha");
        assert_eq!(alpha.overlapping, vec!["beta".to_string()]);
        assert_eq!(alpha.max_similarity, 1.0);
        assert_eq!(alpha.severity, 2);

        let beta = &report[1];
        assert_eq!(beta.dataset, "beta");
        assert_eq!(beta.overlapping, vec!["alpha".to_string()]);
        assert_eq!(beta.max_similarity, 1.0);
        assert_eq!(beta.severity, 2);
    }

    #[test]
    fn distinct_corpus_yields_no_advisories() {
        let corpus = [
            ds("one", "crop yields rose across the northern districts"),
            ds("two", "harbour traffic slowed after the storm"),
            ds("three", "the committee will publish its findings in march"),
        ];
        assert!(advisories(&corpus, 0.3).is_empty());
    }

    #[test]
    fn partial_template_reuse_still_flags_at_severity_two() {
        // {alpha,bravo,charlie} vs {alpha,bravo,charlie,delta} -> 3/4 = 0.75.
        let corpus = [
            ds("orig", "alpha bravo charlie"),
            ds("derived", "alpha bravo charlie delta"),
        ];
        let report = advisories(&corpus, 0.75);
        assert_eq!(report.len(), 2);
        assert!(report.iter().all(|a| a.severity == 2));
        assert!(report.iter().all(|a| a.max_similarity == 0.75));
    }

    // ----- threshold rules --------------------------------------------------

    #[test]
    fn threshold_boundary_is_inclusive() {
        let corpus = [
            ds("orig", "alpha bravo charlie"),
            ds("derived", "alpha bravo charlie delta"),
        ];
        // Exactly at 0.75 -> advised (inclusive test).
        let at = advisories(&corpus, 0.75);
        assert_eq!(at.len(), 2);
        assert_eq!(at[0].max_similarity, 0.75);
        // Just above -> clean.
        assert!(advisories(&corpus, 0.750_000_1).is_empty());

        // Identical bodies at the top of the interval (1.0) -> advised.
        let clones = [ds("a", base_body()), ds("b", base_body())];
        assert_eq!(advisories(&clones, 1.0).len(), 2);
    }

    #[test]
    fn threshold_outside_unit_interval_yields_empty_report() {
        let clones = [ds("a", base_body()), ds("b", base_body())];
        // 0.0 is deliberately outside the advisory domain (documented rule),
        // even though the underlying detector would admit every pair at 0.0.
        for bad in [0.0_f32, -0.5, 1.5, f32::NAN, f32::INFINITY] {
            assert!(
                advisories(&clones, bad).is_empty(),
                "threshold {bad} must yield an empty report"
            );
        }
    }

    // ----- ordering / shape -------------------------------------------------

    #[test]
    fn output_and_overlap_lists_are_sorted() {
        // Input order deliberately not alphabetical; all three share one body.
        let corpus = [
            ds("zeta", base_body()),
            ds("alpha", base_body()),
            ds("mid", base_body()),
        ];
        let report = advisories(&corpus, 0.5);
        let names: Vec<&str> = report.iter().map(|a| a.dataset.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);

        for adv in &report {
            let mut sorted = adv.overlapping.clone();
            sorted.sort();
            assert_eq!(adv.overlapping, sorted, "overlapping must be sorted");
            let mut expected: Vec<String> = vec!["alpha", "mid", "zeta"]
                .into_iter()
                .filter(|n| *n != adv.dataset)
                .map(str::to_string)
                .collect();
            expected.sort();
            assert_eq!(adv.overlapping, expected);
            assert_eq!(adv.max_similarity, 1.0);
            assert_eq!(adv.severity, 2);
        }
    }

    #[test]
    fn empty_and_single_inputs_yield_no_advisories() {
        assert!(advisories(&[], 0.5).is_empty());
        assert!(advisories(&[ds("only", base_body())], 0.5).is_empty());
    }

    #[test]
    fn zero_token_bodies_are_never_flagged() {
        // Pairs involving a zero-token body carry no template content and are
        // skipped by the reused detector (documented edge rule).
        let corpus = [
            ds("empty", ""),
            ds("blank", "   \n "),
            ds("punct", "!!! ---"),
            ds("real", "alpha bravo charlie"),
        ];
        assert!(advisories(&corpus, 0.01).is_empty());
    }

    #[test]
    fn deterministic_same_input_twice() {
        let corpus = [
            ds("w1", "the ministry said the project remains on schedule for 2027"),
            ds("w2", "the ministry said the project remains on schedule for 2027"),
            ds("w3", "completely unrelated statement about rainfall"),
        ];
        let first = advisories(&corpus, 0.7);
        let second = advisories(&corpus, 0.7);
        assert_eq!(first, second, "same input must produce identical output");
        // Only w1/w2 overlap; w3 stays clean.
        let names: Vec<&str> = first.iter().map(|a| a.dataset.as_str()).collect();
        assert_eq!(names, vec!["w1", "w2"]);
        assert!(first.iter().all(|a| a.overlapping.len() == 1));
    }

    #[test]
    fn same_named_entries_merge_and_name_order_is_byte_order() {
        // Two distinct entries share the name "dup" (and a body): their hits
        // merge into one advisory keyed by the name, recorded as overlapping
        // itself (documented edge rule for same-named inputs).
        let corpus = [ds("dup", base_body()), ds("dup", base_body())];
        let report = advisories(&corpus, 0.9);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].dataset, "dup");
        assert_eq!(report[0].overlapping, vec!["dup".to_string()]);
        assert_eq!(report[0].max_similarity, 1.0);
        assert_eq!(report[0].severity, 2);

        // Name ordering is lexicographic byte order: uppercase sorts first.
        let corpus = [ds("alpha", base_body()), ds("Zeta", base_body())];
        let report = advisories(&corpus, 0.9);
        let names: Vec<&str> = report.iter().map(|a| a.dataset.as_str()).collect();
        assert_eq!(names, vec!["Zeta", "alpha"]);
    }

    // ----- serde ------------------------------------------------------------

    #[test]
    fn serde_round_trip_and_wire_form() {
        let adv = ReuseAdvisory {
            dataset: "alpha".to_string(),
            overlapping: vec!["beta".to_string()],
            max_similarity: 1.0,
            severity: 2,
        };
        let json = serde_json::to_string(&adv).unwrap();
        assert_eq!(
            json,
            r#"{"dataset":"alpha","overlapping":["beta"],"max_similarity":1.0,"severity":2}"#
        );
        assert_eq!(serde_json::from_str::<ReuseAdvisory>(&json).unwrap(), adv);

        // A report serializes as an array of advisories (wire shape).
        let corpus = [ds("a", base_body()), ds("b", base_body())];
        let report = advisories(&corpus, 0.9);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.starts_with(r#"[{"dataset":"a""#), "unexpected: {json}");
    }
}
