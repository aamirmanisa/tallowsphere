//! Intake corroboration counters + boilerplate/template-reuse detector
//! (task A3.4.1 · E11 · frozen interface §10).
//!
//! Two pure, deterministic intake helpers:
//!
//! * [`independent_domain_count`] — the corroboration counter. An item is
//!   corroborated only by *independent* sources, and independence is judged
//!   at the domain level: five pages of one site are one source, not five.
//!   The independence key is the **trimmed, lower-cased domain**
//!   ([`normalize_domain`]); same-domain repeats count once.
//!
//! * [`template_reuse_detect`] — the boilerplate/template detector. Each
//!   text is normalized to a token set (lower-cased, split on every
//!   non-alphanumeric character) and every pair of inputs whose Jaccard
//!   similarity is `>= threshold` is reported. Copied boilerplate across
//!   nominally independent sources is itself a corroboration red flag: the
//!   "multiple sources" may be one press release.
//!
//! Neither function touches the clock, the filesystem, or any global state:
//! identical inputs always produce identical outputs (determinism is a
//! security property — verdicts are cached and compared between runs).
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * Instances whose domain is empty/blank after normalization are **not**
//!   counted: a missing domain is no evidence of independence. They are
//!   likewise absent from [`distinct_domain_keys`].
//! * `texts` entries are `(label, text)` pairs; the label is echoed into
//!   [`ReuseHit::a`] / [`ReuseHit::b`] and is the only identifier — duplicate
//!   labels are not deduplicated (pairs are enumerated by position).
//! * Tokens are split on `!char::is_alphanumeric()`; no stop-word list and no
//!   token-length cutoff (kept deliberately simple and stable). `"don't"`
//!   therefore tokenizes as `{don, t}` and `a_b` as `{a, b}`.
//! * A pair involving a zero-token text (empty or punctuation-only input) is
//!   never reported by [`template_reuse_detect`] — there is no template
//!   content to reuse. [`similarity`] alone follows the set-equality
//!   convention: `similarity("", "") == 1.0` (both token sets are vacuously
//!   equal).
//! * The threshold test is inclusive (`>=`): a pair exactly at the threshold
//!   is a hit. A `NaN` threshold matches nothing (all comparisons false).
//! * Hits are emitted in input position order — `(0,1), (0,2), … (n-2,n-1)` —
//!   and are not re-sorted by similarity, so ordering is input-stable.
//! * Pair enumeration is `O(n²)`; intake batches are small by nature. A caller
//!   holding a large corpus should pre-filter before calling.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

// ---------------------------------------------------------------------------
// Corroboration counter
// ---------------------------------------------------------------------------

/// One intake instance of a claim/observation: where it was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    /// Human-readable source label (site, feed, account). Informational only:
    /// the independence key is the domain, never this label.
    pub source: String,
    /// Domain as recorded at intake. Normalization ([`normalize_domain`]) is
    /// applied inside the counters, so callers may pass raw values.
    pub domain: String,
}

/// The independence key: `domain` trimmed of surrounding whitespace, then
/// lower-cased (Unicode-aware). `" Reuters.COM "` → `"reuters.com"`.
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().to_lowercase()
}

/// Distinct normalized domains, sorted (deterministic order).
///
/// Instances whose normalized domain is empty are skipped — a missing domain
/// is no evidence of independence (documented deviation; the spec is silent).
pub fn distinct_domain_keys(instances: &[Instance]) -> Vec<String> {
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for inst in instances {
        let key = normalize_domain(&inst.domain);
        if !key.is_empty() {
            keys.insert(key);
        }
    }
    keys.into_iter().collect()
}

/// Number of INDEPENDENT domains behind `instances`: the count of distinct
/// normalized domains. Same-domain repeats count once no matter how many
/// different `source` labels they carry (`source` is informational only).
pub fn independent_domain_count(instances: &[Instance]) -> usize {
    distinct_domain_keys(instances).len()
}

// ---------------------------------------------------------------------------
// Boilerplate / template-reuse detector
// ---------------------------------------------------------------------------

/// A pair of inputs whose normalized token-set similarity reached the
/// threshold. `a`/`b` are the input labels of the pair (in input order).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReuseHit {
    /// Label of the earlier input in the pair (input position order).
    pub a: String,
    /// Label of the later input in the pair.
    pub b: String,
    /// Jaccard similarity of the normalized token sets, in `[0.0, 1.0]`
    /// (or exactly `1.0` for two zero-token texts — see [`similarity`]).
    pub similarity: f64,
}

/// Normalize one text to its token set: lower-case (Unicode-aware), split on
/// every non-alphanumeric character, drop empty tokens.
fn token_set(text: &str) -> HashSet<String> {
    let lower = text.to_lowercase();
    lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Jaccard index `|A ∩ B| / |A ∪ B|` over two token sets.
///
/// Convention for the degenerate case: two empty sets are equal, so their
/// similarity is `1.0` (`0/0` has no analytic value; the equality convention
/// is documented and pinned by tests).
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let inter = small.iter().filter(|t| large.contains(*t)).count();
    let union = a.len() + b.len() - inter;
    inter as f64 / union as f64
}

/// Jaccard similarity of two raw texts under [`token_set`] normalization.
///
/// Deterministic: case and punctuation differences do not affect the result;
/// token order does not matter (set semantics). `similarity("", "") == 1.0`
/// by the set-equality convention (documented edge rule).
pub fn similarity(a: &str, b: &str) -> f64 {
    jaccard(&token_set(a), &token_set(b))
}

/// Every unordered pair of `texts` whose normalized token-set Jaccard
/// similarity is `>= threshold`.
///
/// `texts` entries are `(label, text)`; hits carry the labels. Pairs are
/// enumerated by input position `(0,1), (0,2), … (n-2,n-1)` and returned in
/// that order (not sorted by similarity). Pairs involving a zero-token text
/// are never reported (no template content to reuse).
pub fn template_reuse_detect(texts: &[(String, String)], threshold: f64) -> Vec<ReuseHit> {
    let sets: Vec<(&str, HashSet<String>)> = texts
        .iter()
        .map(|(label, text)| (label.as_str(), token_set(text)))
        .collect();

    let mut hits = Vec::new();
    for i in 0..sets.len() {
        for j in (i + 1)..sets.len() {
            let (label_a, set_a) = &sets[i];
            let (label_b, set_b) = &sets[j];
            if set_a.is_empty() || set_b.is_empty() {
                continue; // degenerate input: no template content
            }
            let sim = jaccard(set_a, set_b);
            if sim >= threshold {
                hits.push(ReuseHit {
                    a: (*label_a).to_owned(),
                    b: (*label_b).to_owned(),
                    similarity: sim,
                });
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(source: &str, domain: &str) -> Instance {
        Instance {
            source: source.to_string(),
            domain: domain.to_string(),
        }
    }

    fn pair(label: &str, text: &str) -> (String, String) {
        (label.to_string(), text.to_string())
    }

    // ----- independent_domain_count ----------------------------------------

    #[test]
    fn count_empty_input_is_zero() {
        assert_eq!(independent_domain_count(&[]), 0);
        assert!(distinct_domain_keys(&[]).is_empty());
    }

    #[test]
    fn count_dedupes_same_domain_variants() {
        let instances = [
            inst("Reuters", "reuters.com"),
            inst("Reuters (syndicated copy)", "Reuters.COM "),
            inst("AP", "  apnews.com"),
        ];
        // reuters.com twice (case/whitespace variants) + apnews.com once.
        assert_eq!(independent_domain_count(&instances), 2);
        assert_eq!(
            distinct_domain_keys(&instances),
            vec!["apnews.com".to_string(), "reuters.com".to_string()]
        );
    }

    #[test]
    fn count_never_splits_by_source_label_on_same_domain() {
        // Three different labels, one domain: one independent source.
        let instances = [
            inst("homepage", "example.com"),
            inst("press page", "Example.com"),
            inst("mirror", "EXAMPLE.COM"),
        ];
        assert_eq!(independent_domain_count(&instances), 1);
    }

    #[test]
    fn count_treats_different_domains_as_independent() {
        let instances = [
            inst("same label", "one.example"),
            inst("same label", "two.example"),
            inst("same label", "three.example"),
        ];
        assert_eq!(independent_domain_count(&instances), 3);
        assert_eq!(independent_domain_count(&instances[..2]), 2);
    }

    #[test]
    fn count_blank_domain_not_counted_documented_deviation() {
        // Missing domain provides no independence evidence (module docs).
        let instances = [
            inst("anonymous tip", ""),
            inst("another anonymous tip", "   "),
            inst("Reuters", "reuters.com"),
            inst("Reuters again", "reuters.com"),
        ];
        assert_eq!(independent_domain_count(&instances), 1);
        assert_eq!(distinct_domain_keys(&instances), vec!["reuters.com".to_string()]);
    }

    // ----- similarity -------------------------------------------------------

    #[test]
    fn similarity_ignores_case_and_punctuation() {
        assert_eq!(similarity("The Quick, brown Fox!!", "the quick brown fox"), 1.0);
        assert_eq!(similarity("a_b-c", "a b c"), 1.0);
        assert_eq!(similarity("ÁÉÍ ÓÚ", "áéí óú"), 1.0); // Unicode-aware lowering
        assert_eq!(similarity("naïve—café", "naive cafe"), 0.0); // ï/í are alphanumeric, ≠ i/e
    }

    #[test]
    fn similarity_is_symmetric_and_bounded() {
        let a = "officials confirm the incident occurred early tuesday";
        let b = "officials confirm the incident occurred early tuesday in the region";
        assert_eq!(similarity(a, b), similarity(b, a));
        for (x, y) in [("alpha beta", "gamma delta"), (a, a), (a, b), ("", "alpha")] {
            let s = similarity(x, y);
            assert!((0.0..=1.0).contains(&s), "similarity out of range: {s}");
        }
    }

    #[test]
    fn similarity_empty_sets_follow_equality_convention() {
        assert_eq!(similarity("", ""), 1.0);
        assert_eq!(similarity("!!! ...", "   "), 1.0); // both normalize to {}
        assert_eq!(similarity("", "alpha beta"), 0.0);
    }

    // ----- template_reuse_detect -------------------------------------------

    #[test]
    fn near_duplicate_template_is_detected() {
        let texts = [
            pair("wire-a", "BREAKING: officials confirm the incident occurred early tuesday"),
            pair("wire-b", "Officials confirm the incident occurred early Tuesday in the region"),
        ];
        // token sets: 8 and 9 tokens, intersection 7 -> 7/10.
        assert!((similarity(&texts[0].1, &texts[1].1) - 0.7).abs() < 1e-12);

        let hits = template_reuse_detect(&texts, 0.6);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].a, "wire-a");
        assert_eq!(hits[0].b, "wire-b");
        assert!((hits[0].similarity - 0.7).abs() < 1e-12);

        // ... and not reported when the threshold sits just above the value.
        assert!(template_reuse_detect(&texts, 0.700_000_1).is_empty());
    }

    #[test]
    fn distinct_texts_produce_no_hits() {
        let texts = [
            pair("one", "crop yields rose across the northern districts"),
            pair("two", "harbour traffic slowed after the storm"),
            pair("three", "the committee will publish its findings in march"),
        ];
        let hits = template_reuse_detect(&texts, 0.3);
        assert!(hits.is_empty(), "unexpected hits: {hits:?}");
    }

    #[test]
    fn threshold_boundary_is_inclusive() {
        // {a,b,c} vs {a,b,c,d} -> 3/4 = 0.75 exactly (binary-exact).
        let texts = [pair("x", "alpha bravo charlie"), pair("y", "alpha bravo charlie delta")];
        let at = template_reuse_detect(&texts, 0.75);
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].similarity, 0.75);
        assert!(template_reuse_detect(&texts, 0.750_000_1).is_empty());
        // Threshold at 0 admits every non-degenerate pair.
        assert_eq!(template_reuse_detect(&texts, 0.0).len(), 1);
        // NaN threshold matches nothing (no panic).
        assert!(template_reuse_detect(&texts, f64::NAN).is_empty());
    }

    #[test]
    fn zero_token_texts_are_never_flagged() {
        let texts = [
            pair("empty", ""),
            pair("blank", "   \n "),
            pair("punct", "!!! ---"),
            pair("real", "alpha bravo charlie"),
        ];
        // Every pair here involves at least one zero-token text.
        assert!(template_reuse_detect(&texts, 0.0).is_empty());
    }

    #[test]
    fn all_pairs_enumerated_once_in_input_order() {
        let texts = [
            pair("t0", "alpha bravo charlie"),
            pair("t1", "alpha bravo charlie"),
            pair("t2", "alpha bravo charlie"),
            pair("t3", "alpha bravo charlie"),
        ];
        let hits = template_reuse_detect(&texts, 0.5);
        assert_eq!(hits.len(), 6); // C(4,2)
        let ordered: Vec<(&str, &str)> = hits
            .iter()
            .map(|h| (h.a.as_str(), h.b.as_str()))
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("t0", "t1"),
                ("t0", "t2"),
                ("t0", "t3"),
                ("t1", "t2"),
                ("t1", "t3"),
                ("t2", "t3"),
            ]
        );
        assert!(hits.iter().all(|h| h.similarity == 1.0));
    }

    #[test]
    fn hits_report_only_the_similar_pair() {
        let texts = [
            pair("a", "officials confirm the incident occurred early tuesday"),
            pair("b", "harbour traffic slowed after the storm"),
            pair("c", "officials confirm the incident occurred early Tuesday"),
        ];
        let hits = template_reuse_detect(&texts, 0.8);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].a, "a");
        assert_eq!(hits[0].b, "c");
        assert_eq!(hits[0].similarity, 1.0); // case-only difference
    }

    #[test]
    fn single_or_no_texts_yield_no_pairs() {
        assert!(template_reuse_detect(&[], 0.0).is_empty());
        assert!(template_reuse_detect(&[pair("only", "alpha bravo")], 0.0).is_empty());
    }

    #[test]
    fn deterministic_same_input_twice() {
        let texts = [
            pair("w1", "the ministry said the project remains on schedule for 2027"),
            pair("w2", "the ministry said the project remains on schedule for 2027 also"),
            pair("w3", "completely unrelated statement about rainfall"),
            pair("w4", "the Ministry said the project remains on  schedule for 2027"),
        ];
        let first = template_reuse_detect(&texts, 0.7);
        let second = template_reuse_detect(&texts, 0.7);
        assert_eq!(first, second, "same input must produce identical output");
        // w1/w2: 9-token sets, intersection 9 -> 9/10; w1/w4: 1.0; w2/w4: 9/10.
        // Pairs in input position order: (w1,w2), (w1,w4), (w2,w4).
        let ordered: Vec<(&str, &str, f64)> = first
            .iter()
            .map(|h| (h.a.as_str(), h.b.as_str(), h.similarity))
            .collect();
        assert_eq!(
            ordered,
            vec![("w1", "w2", 0.9), ("w1", "w4", 1.0), ("w2", "w4", 0.9)]
        );
    }

    // ----- serde ------------------------------------------------------------

    #[test]
    fn serde_round_trip_and_wire_form() {
        let i = inst("Reuters", "reuters.com");
        let json = serde_json::to_string(&i).unwrap();
        assert_eq!(json, r#"{"source":"Reuters","domain":"reuters.com"}"#);
        assert_eq!(serde_json::from_str::<Instance>(&json).unwrap(), i);

        let h = ReuseHit {
            a: "w1".to_string(),
            b: "w2".to_string(),
            similarity: 0.75,
        };
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, r#"{"a":"w1","b":"w2","similarity":0.75}"#);
        assert_eq!(serde_json::from_str::<ReuseHit>(&json).unwrap(), h);
    }
}
