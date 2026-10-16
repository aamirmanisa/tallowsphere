//! Collection-mode diversity lint — single-mode detection + corroboration-route
//! suggestions (tasks B8.1.1–B8.1.3, frozen interface §9).
//!
//! A finding is only as robust as the *variety of collection channels* behind
//! it. Five pages scraped from five different domains are still five products
//! of one collection mode ([`CollectionMode::OpenWeb`]): one sensor framing,
//! one set of blind spots, one failure mode. "Multiple sources" is not the
//! same claim as "independent observation", and this lint exists to keep the
//! two apart:
//!
//! * [`validate`] — intake gate: a finding with no sources, or with blank
//!   id/claim/source-id fields, is refused outright.
//! * [`mode_counts`] / [`is_single_mode`] — describe the mode coverage of a
//!   finding. A single-mode finding is a corroboration *monoculture*.
//! * [`suggest_routes`] — the corroboration-route suggestions: which modes are
//!   *absent* and could be added to cross-check the claim through a different
//!   class of channel. A mode gap is a route, not a virtue: the empty list
//!   returned when all five modes are present means "no route suggested by
//!   mode coverage alone", never "this claim is true".
//! * [`lint`] — the batch pass: every valid single-mode finding becomes a
//!   [`LintHit`] carrying the canonical reason line and its suggested routes.
//!   Invalid findings are skipped (documented below) — a malformed record is
//!   an intake problem, not a diversity verdict, and must not drown the lint
//!   output.
//!
//! # Relationship to `crate::corroboration` (independence vocabulary)
//!
//! `src/corroboration.rs` judges corroboration at the **domain** level: five
//! labels on one domain are one source, and [`distinct_domain_keys`] /
//! [`independent_domain_count`] count independent domains. This module judges
//! **collection mode**, and the two axes are orthogonal — which is the whole
//! point:
//!
//! * ten sources, ten distinct domains, all `OpenWeb` ⇒ domain-independent,
//!   mode-monoculture ⇒ **this lint flags it**;
//! * one source each from OpenWeb + Archive + Registry + Sensor + Human on
//!   overlapping domains ⇒ mode-diverse by this lint, possibly weak on the
//!   domain axis ⇒ `corroboration`'s counters still apply.
//!
//! Neither check subsumes the other, so no code is shared: `validate` reuses
//! the vocabulary (a source is identified by id and carries an informational
//! `domain`) but the lint never inspects `domain` values, so nothing from
//! `corroboration` is directly applicable and no `crate::` import is taken
//! (documented decision; §9 says reuse only if directly applicable).
//!
//! # Documented rules (spec silent where noted; conservative reading)
//!
//! * **Emptiness is tested on the trimmed form**: an id/claim/source-id of
//!   whitespace only is empty for validation purposes (and stored text is
//!   never mutated — like the other intake lints, verbatim storage, trimmed
//!   validation). `domain` is deliberately *not* validated: it is ledger
//!   metadata for this lint, and a missing domain is no diversity evidence
//!   either way.
//! * **`validate` check order**: sources emptiness first
//!   ([`ModeLintError::EmptySources`] — a finding with no sources cannot be
//!   linted at all), then finding id, then claim, then source ids in vector
//!   order (first offender reported). All field refusals are
//!   [`ModeLintError::BadInput`] naming the field (`"id"`, `"claim"`,
//!   `"source id"`).
//! * **`is_single_mode` is vacuous-true for zero sources** (`≤ 1 source`).
//!   That state is unreachable through [`lint`] (which validates first), but
//!   the predicate stays a total, deterministic function of the struct —
//!   pinned by test.
//! * **`mode_counts` counts every source**, including same-mode repeats on the
//!   same domain: the counter answers "how much of this finding came through
//!   mode M", not "how many independent items". Only non-zero entries are
//!   returned, in [`CollectionMode::ALL`] (declaration) order.
//! * **`suggest_routes` returns an empty vector iff all five modes are
//!   present** (documented in the function doc): absence of suggestions is
//!   not an endorsement.
//! * **Reason line** is exactly
//!   `all sources share mode <word> over <n> source(s)` where `<word>` is
//!   [`CollectionMode::as_str`] ("open_web", "archive", "registry", "sensor",
//!   "human") and `<n>` = `sources.len()`. No singular special-case: a
//!   one-source finding reads `over 1 source(s)` — the format is fixed and
//!   ledger-stable (pinned by test).
//! * **`lint` sorts by finding id** (ascending, `String` byte order) with a
//!   *stable* sort, so duplicate ids keep input order. Invalid findings are
//!   skipped, never reported: the lint's verdict is about mode diversity of
//!   well-formed records only.
//! * **Serde wire forms**: enums/structs use the default (variant-name)
//!   representation — `CollectionMode` serialises as `"OpenWeb"`/`"Archive"`/
//!   …, unlike `as_str`'s lowercase audit token. The spec marks snake_case
//!   explicitly where wanted (cf. §1 `Decision`); §9 does not, so the default
//!   derive is used and pinned. [`ModeLintError`] derives `Serialize` but not
//!   `Deserialize` (`BadInput(&'static str)` cannot deserialise into
//!   `'static`), mirroring `clearness_gate`, `gap_register`, `decoy_flags`.
//! * **No clocks, no I/O, no global state**: every function is a pure
//!   function of its argument; identical inputs produce identical outputs
//!   (determinism is pinned by test — verdicts are cached and compared
//!   between runs).
//!
//! Example (text fence: not compiled as a doctest before `lib.rs` wiring):
//!
//! ```text
//! let f = SourcedFinding {
//!     id: "f-1".into(),
//!     claim: "port capacity was expanded in 2025".into(),
//!     sources: vec![
//!         SourceRef { id: "s-1".into(), mode: CollectionMode::OpenWeb, domain: "a.example".into() },
//!         SourceRef { id: "s-2".into(), mode: CollectionMode::OpenWeb, domain: "b.example".into() },
//!     ],
//! };
//! assert!(is_single_mode(&f));
//! let hits = lint(std::slice::from_ref(&f));
//! assert_eq!(hits[0].reason, "all sources share mode open_web over 2 source(s)");
//! assert_eq!(hits[0].suggested_route, vec![Archive, Registry, Sensor, Human]);
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Collection modes
// ---------------------------------------------------------------------------

/// How a source was collected. Declaration order is the canonical output
/// order used by [`mode_counts`] and [`suggest_routes`] (and [`ALL`]).
///
/// [`ALL`]: CollectionMode::ALL
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollectionMode {
    /// Open web: crawls, site scrapes, public feeds. The default mode, and
    /// the one most exposed to shared framing and shared tooling.
    OpenWeb,
    /// Archive: historical captures (web archives, filings, print scans).
    Archive,
    /// Registry: authoritative structured registries (corporate, cadastral,
    /// licensing, standards bodies).
    Registry,
    /// Sensor: direct instrumentation (telemetry, network vantage points,
    /// calibrated measurement).
    Sensor,
    /// Human: HUMINT — interviews, liaison, direct observation by people.
    Human,
}

impl CollectionMode {
    /// Every mode, in declaration order (also the output order of
    /// [`mode_counts`] and [`suggest_routes`]).
    pub const ALL: [CollectionMode; 5] = [
        CollectionMode::OpenWeb,
        CollectionMode::Archive,
        CollectionMode::Registry,
        CollectionMode::Sensor,
        CollectionMode::Human,
    ];

    /// Canonical lowercase word for audit/lint lines ("open_web", "archive",
    /// "registry", "sensor", "human"). This is the `<word>` in the [`lint`]
    /// reason line; serde uses the variant name (documented spec-silent
    /// convention).
    pub fn as_str(&self) -> &'static str {
        match self {
            CollectionMode::OpenWeb => "open_web",
            CollectionMode::Archive => "archive",
            CollectionMode::Registry => "registry",
            CollectionMode::Sensor => "sensor",
            CollectionMode::Human => "human",
        }
    }
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One collected source behind a finding: which mode produced it, from which
/// domain. `domain` is informational ledger metadata for this lint (the mode
/// axis, not the domain axis, is judged here — see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Source id (intake-stable).
    pub id: String,
    /// The collection mode that produced this source.
    pub mode: CollectionMode,
    /// Domain as recorded at intake. Not inspected by this lint.
    pub domain: String,
}

/// A claim with the sources that stand behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcedFinding {
    /// Finding id (the lint's sort key and ledger handle).
    pub id: String,
    /// The claim under test.
    pub claim: String,
    /// Everything offered as support, in intake order.
    pub sources: Vec<SourceRef>,
}

/// One lint hit: a valid finding whose sources all share a single mode, the
/// canonical reason line, and the modes absent from its coverage — the
/// corroboration routes worth adding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LintHit {
    /// Id of the flagged finding.
    pub finding: String,
    /// Canonical reason: `all sources share mode <word> over <n> source(s)`.
    pub reason: String,
    /// Modes not present among the finding's sources, declaration order.
    /// Empty iff all five modes are present (routes, not verdicts).
    pub suggested_route: Vec<CollectionMode>,
}

/// Refusal causes for the mode-diversity lint. `Serialize` only — the
/// `BadInput(&'static str)` payload cannot deserialise into `'static`
/// (repo precedent: `clearness_gate`, `gap_register`, `decoy_flags`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ModeLintError {
    /// A field is empty on its trimmed form; the reason names the field.
    BadInput(&'static str),
    /// The finding carries no sources at all.
    EmptySources,
}

impl fmt::Display for ModeLintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModeLintError::BadInput(reason) => write!(f, "invalid input: {reason}"),
            ModeLintError::EmptySources => write!(f, "finding has no sources"),
        }
    }
}

impl std::error::Error for ModeLintError {}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Intake gate for one finding.
///
/// Refuses [`ModeLintError::EmptySources`] first (no sources ⇒ nothing to
/// judge), then blank fields on their trimmed form: finding id
/// (`BadInput("id")`), claim (`BadInput("claim")`), then each source id in
/// vector order (`BadInput("source id")`, first offender). `domain` is not
/// validated — see module docs. Stored text is never mutated.
pub fn validate(f: &SourcedFinding) -> Result<(), ModeLintError> {
    if f.sources.is_empty() {
        return Err(ModeLintError::EmptySources);
    }
    if f.id.trim().is_empty() {
        return Err(ModeLintError::BadInput("id"));
    }
    if f.claim.trim().is_empty() {
        return Err(ModeLintError::BadInput("claim"));
    }
    for s in &f.sources {
        if s.id.trim().is_empty() {
            return Err(ModeLintError::BadInput("source id"));
        }
    }
    Ok(())
}

/// Per-mode source counts, in [`CollectionMode::ALL`] (declaration) order,
/// only non-zero entries. Counts every source, including same-mode repeats.
pub fn mode_counts(f: &SourcedFinding) -> Vec<(CollectionMode, usize)> {
    let mut out = Vec::new();
    for mode in CollectionMode::ALL {
        let n = f.sources.iter().filter(|s| s.mode == mode).count();
        if n > 0 {
            out.push((mode, n));
        }
    }
    out
}

/// `true` iff the finding has at most one source, or every source shares one
/// mode — i.e. the finding rests on a single collection channel type.
///
/// Vacuous for zero sources (`≤ 1 source`); [`lint`] validates before
/// consulting it, so that state never reaches a verdict through the batch
/// pass.
pub fn is_single_mode(f: &SourcedFinding) -> bool {
    match f.sources.first() {
        None => true,
        Some(first) => f.sources.iter().all(|s| s.mode == first.mode),
    }
}

/// The corroboration routes: modes **not** present among the finding's
/// sources, in declaration order. Empty iff all five modes are present
/// (documented) — no mode-level suggestion remains, which is not an
/// endorsement of the claim.
pub fn suggest_routes(f: &SourcedFinding) -> Vec<CollectionMode> {
    CollectionMode::ALL
        .iter()
        .filter(|mode| !f.sources.iter().any(|s| s.mode == **mode))
        .copied()
        .collect()
}

/// Batch pass: a [`LintHit`] for every **valid** single-mode finding, sorted
/// by finding id (stable, so duplicate ids keep input order).
///
/// Invalid findings (per [`validate`]) are skipped, not reported: the lint
/// judges mode diversity of well-formed records only. Reason line is exactly
/// `all sources share mode <word> over <n> source(s)` with `<word>` =
/// [`CollectionMode::as_str`] of the shared mode and `<n>` = `sources.len()`.
pub fn lint(findings: &[SourcedFinding]) -> Vec<LintHit> {
    let mut hits = Vec::new();
    for f in findings {
        if validate(f).is_err() {
            continue;
        }
        if !is_single_mode(f) {
            continue;
        }
        // validate() guarantees at least one source.
        let mode = f.sources[0].mode;
        let n = f.sources.len();
        hits.push(LintHit {
            finding: f.id.clone(),
            reason: format!("all sources share mode {} over {} source(s)", mode.as_str(), n),
            suggested_route: suggest_routes(f),
        });
    }
    hits.sort_by(|a, b| a.finding.cmp(&b.finding));
    hits
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn src(id: &str, mode: CollectionMode, domain: &str) -> SourceRef {
        SourceRef {
            id: id.to_string(),
            mode,
            domain: domain.to_string(),
        }
    }

    fn finding(id: &str, sources: Vec<SourceRef>) -> SourcedFinding {
        SourcedFinding {
            id: id.to_string(),
            claim: format!("claim for {id}"),
            sources,
        }
    }

    // ----- ALL / as_str -----------------------------------------------------

    #[test]
    fn all_const_pins_declaration_order_and_words() {
        assert_eq!(CollectionMode::ALL.len(), 5);
        assert_eq!(
            CollectionMode::ALL,
            [
                CollectionMode::OpenWeb,
                CollectionMode::Archive,
                CollectionMode::Registry,
                CollectionMode::Sensor,
                CollectionMode::Human,
            ]
        );
        let words: Vec<&str> = CollectionMode::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(words, vec!["open_web", "archive", "registry", "sensor", "human"]);
    }

    // ----- validate ---------------------------------------------------------

    #[test]
    fn validate_accepts_well_formed_finding() {
        let f = finding("f-1", vec![src("s-1", CollectionMode::OpenWeb, "a.example")]);
        assert_eq!(validate(&f), Ok(()));
        // domain is not validated: blank domain is still fine here.
        let f = finding("f-1", vec![src("s-1", CollectionMode::Sensor, "")]);
        assert_eq!(validate(&f), Ok(()));
    }

    #[test]
    fn validate_empty_sources_wins_over_empty_fields() {
        // Check order pinned: EmptySources before any field emptiness.
        let f = SourcedFinding {
            id: String::new(),
            claim: String::new(),
            sources: Vec::new(),
        };
        assert_eq!(validate(&f), Err(ModeLintError::EmptySources));
    }

    #[test]
    fn validate_refuses_blank_fields_trimmed_form() {
        let good = src("s-1", CollectionMode::OpenWeb, "a.example");

        let f = SourcedFinding {
            id: "   ".to_string(), // whitespace-only == empty
            claim: "c".to_string(),
            sources: vec![good.clone()],
        };
        assert_eq!(validate(&f), Err(ModeLintError::BadInput("id")));

        let f = SourcedFinding {
            id: "f-1".to_string(),
            claim: "\t\n ".to_string(),
            sources: vec![good.clone()],
        };
        assert_eq!(validate(&f), Err(ModeLintError::BadInput("claim")));

        let f = finding("f-1", vec![good.clone(), src("  ", CollectionMode::Archive, "b.example")]);
        assert_eq!(validate(&f), Err(ModeLintError::BadInput("source id")));
    }

    // ----- mode_counts ------------------------------------------------------

    #[test]
    fn mode_counts_declaration_order_non_zero_only() {
        // Sources deliberately in non-canonical insertion order.
        let f = finding(
            "f-1",
            vec![
                src("s-1", CollectionMode::Archive, "nara.example"),
                src("s-2", CollectionMode::OpenWeb, "news.example"),
                src("s-3", CollectionMode::Archive, "records.example"),
            ],
        );
        assert_eq!(
            mode_counts(&f),
            vec![(CollectionMode::OpenWeb, 1), (CollectionMode::Archive, 2)]
        );

        // All five present ⇒ five entries, declaration order, counts pinned.
        let f = finding(
            "f-2",
            vec![
                src("h", CollectionMode::Human, "h.example"),
                src("s", CollectionMode::Sensor, "s.example"),
                src("r", CollectionMode::Registry, "r.example"),
                src("a", CollectionMode::Archive, "a.example"),
                src("a2", CollectionMode::Archive, "a.example"),
                src("w", CollectionMode::OpenWeb, "w.example"),
            ],
        );
        assert_eq!(
            mode_counts(&f),
            vec![
                (CollectionMode::OpenWeb, 1),
                (CollectionMode::Archive, 2),
                (CollectionMode::Registry, 1),
                (CollectionMode::Sensor, 1),
                (CollectionMode::Human, 1),
            ]
        );

        // No sources ⇒ no counts.
        assert!(mode_counts(&finding("f-3", vec![])).is_empty());
    }

    // ----- is_single_mode ---------------------------------------------------

    #[test]
    fn single_mode_detection_matrix() {
        // Several sources, one mode ⇒ true.
        let f = finding(
            "f-1",
            vec![
                src("s-1", CollectionMode::OpenWeb, "a.example"),
                src("s-2", CollectionMode::OpenWeb, "b.example"),
                src("s-3", CollectionMode::OpenWeb, "c.example"),
            ],
        );
        assert!(is_single_mode(&f));

        // Exactly one source (any mode) ⇒ true.
        assert!(is_single_mode(&finding(
            "f-2",
            vec![src("s-1", CollectionMode::Registry, "r.example")]
        )));

        // Duplicates of one mode ⇒ true.
        assert!(is_single_mode(&finding(
            "f-3",
            vec![
                src("s-1", CollectionMode::Sensor, "x.example"),
                src("s-2", CollectionMode::Sensor, "x.example"),
            ]
        )));

        // Two modes ⇒ false.
        let f = finding(
            "f-4",
            vec![
                src("s-1", CollectionMode::OpenWeb, "a.example"),
                src("s-2", CollectionMode::Human, "b.example"),
            ],
        );
        assert!(!is_single_mode(&f));

        // Any mixture ⇒ false, regardless of count dominance.
        let f = finding(
            "f-5",
            vec![
                src("s-1", CollectionMode::OpenWeb, "a.example"),
                src("s-2", CollectionMode::OpenWeb, "b.example"),
                src("s-3", CollectionMode::OpenWeb, "c.example"),
                src("s-4", CollectionMode::Archive, "d.example"),
            ],
        );
        assert!(!is_single_mode(&f));

        // Zero sources: vacuous true (documented; unreachable via lint).
        assert!(is_single_mode(&finding("f-6", vec![])));
    }

    // ----- suggest_routes ---------------------------------------------------

    #[test]
    fn suggest_routes_excludes_present_in_declaration_order() {
        let f = finding(
            "f-1",
            vec![
                src("s-1", CollectionMode::Human, "h.example"),
                src("s-2", CollectionMode::OpenWeb, "w.example"),
                src("s-3", CollectionMode::Human, "h2.example"),
            ],
        );
        assert_eq!(
            suggest_routes(&f),
            vec![
                CollectionMode::Archive,
                CollectionMode::Registry,
                CollectionMode::Sensor
            ]
        );

        // No sources ⇒ every mode is a route.
        assert_eq!(suggest_routes(&finding("f-2", vec![])), CollectionMode::ALL.to_vec());
    }

    #[test]
    fn suggest_routes_empty_iff_all_five_present() {
        let all = finding(
            "f-1",
            CollectionMode::ALL
                .iter()
                .enumerate()
                .map(|(i, m)| src(&format!("s-{i}"), *m, "d.example"))
                .collect(),
        );
        assert!(suggest_routes(&all).is_empty());

        // Dropping any single mode makes exactly that mode the route.
        for (i, missing) in CollectionMode::ALL.iter().enumerate() {
            let partial = finding(
                &format!("f-{i}"),
                all.sources
                    .iter()
                    .filter(|s| s.mode != *missing)
                    .cloned()
                    .collect(),
            );
            assert_eq!(suggest_routes(&partial), vec![*missing]);
        }
    }

    // ----- lint -------------------------------------------------------------

    #[test]
    fn single_mode_multi_source_is_flagged_with_exact_reason() {
        let f = finding(
            "f-1",
            vec![
                src("s-1", CollectionMode::OpenWeb, "a.example"),
                src("s-2", CollectionMode::OpenWeb, "b.example"),
                src("s-3", CollectionMode::OpenWeb, "c.example"),
            ],
        );
        let hits = lint(std::slice::from_ref(&f));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].finding, "f-1");
        assert_eq!(hits[0].reason, "all sources share mode open_web over 3 source(s)");
        assert_eq!(
            hits[0].suggested_route,
            vec![
                CollectionMode::Archive,
                CollectionMode::Registry,
                CollectionMode::Sensor,
                CollectionMode::Human
            ]
        );
    }

    #[test]
    fn single_source_is_flagged() {
        let f = finding("f-1", vec![src("s-1", CollectionMode::Sensor, "probe.example")]);
        let hits = lint(std::slice::from_ref(&f));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reason, "all sources share mode sensor over 1 source(s)");
    }

    #[test]
    fn reason_word_pins_every_mode() {
        for mode in CollectionMode::ALL {
            let f = finding("f-1", vec![src("s-1", mode, "d.example")]);
            let hits = lint(std::slice::from_ref(&f));
            assert_eq!(
                hits[0].reason,
                format!("all sources share mode {} over 1 source(s)", mode.as_str())
            );
        }
    }

    #[test]
    fn multi_mode_findings_are_not_flagged() {
        let f = finding(
            "f-1",
            vec![
                src("s-1", CollectionMode::OpenWeb, "a.example"),
                src("s-2", CollectionMode::Archive, "b.example"),
            ],
        );
        assert!(lint(std::slice::from_ref(&f)).is_empty());

        let all = finding(
            "f-2",
            CollectionMode::ALL
                .iter()
                .enumerate()
                .map(|(i, m)| src(&format!("s-{i}"), *m, "d.example"))
                .collect(),
        );
        assert!(lint(std::slice::from_ref(&all)).is_empty());
    }

    #[test]
    fn lint_ordering_by_finding_id_and_invalid_skipped() {
        let zeta = finding("zeta", vec![src("s-1", CollectionMode::Archive, "z.example")]);
        let alpha = finding(
            "alpha",
            vec![
                src("s-1", CollectionMode::OpenWeb, "a.example"),
                src("s-2", CollectionMode::OpenWeb, "b.example"),
            ],
        );
        let mid = finding("mid", vec![src("s-1", CollectionMode::Human, "m.example")]);

        // Invalid entries: empty sources, blank id, blank claim, blank source id.
        let empty = finding("invalid-empty", vec![]);
        let blank_id = SourcedFinding {
            id: "  ".to_string(),
            claim: "c".to_string(),
            sources: vec![src("s-1", CollectionMode::OpenWeb, "d.example")],
        };
        let blank_claim = SourcedFinding {
            id: "invalid-claim".to_string(),
            claim: " ".to_string(),
            sources: vec![src("s-1", CollectionMode::OpenWeb, "d.example")],
        };
        let blank_source = finding("invalid-source", vec![src("", CollectionMode::OpenWeb, "d.example")]);

        // Input deliberately out of order; invalid entries interleaved.
        let input = vec![
            zeta.clone(),
            empty,
            alpha.clone(),
            blank_id,
            mid.clone(),
            blank_claim,
            blank_source,
        ];
        let hits = lint(&input);
        let ids: Vec<&str> = hits.iter().map(|h| h.finding.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "mid", "zeta"]);
        // Sort is stable (ids are unique here); suggestions intact per hit.
        assert_eq!(hits[0].suggested_route, suggest_routes(&alpha));
        assert_eq!(hits[2].suggested_route, suggest_routes(&zeta));
    }

    #[test]
    fn lint_empty_input_and_all_invalid_yield_nothing() {
        assert!(lint(&[]).is_empty());
        let bad = SourcedFinding {
            id: "f-1".to_string(),
            claim: "c".to_string(),
            sources: vec![],
        };
        assert!(lint(std::slice::from_ref(&bad)).is_empty());
    }

    #[test]
    fn determinism_same_input_twice() {
        let input = vec![
            finding(
                "f-3",
                vec![
                    src("s-1", CollectionMode::Registry, "r.example"),
                    src("s-2", CollectionMode::Registry, "r2.example"),
                ],
            ),
            finding(
                "f-1",
                vec![
                    src("s-1", CollectionMode::OpenWeb, "a.example"),
                    src("s-2", CollectionMode::Human, "b.example"),
                ],
            ),
            finding("f-2", vec![src("s-1", CollectionMode::Sensor, "s.example")]),
            SourcedFinding {
                id: "bad".to_string(),
                claim: String::new(),
                sources: vec![src("s-1", CollectionMode::OpenWeb, "x.example")],
            },
        ];
        let first = lint(&input);
        let second = lint(&input);
        assert_eq!(first, second, "same input must produce identical output");
        let ids: Vec<&str> = first.iter().map(|h| h.finding.as_str()).collect();
        assert_eq!(ids, vec!["f-2", "f-3"]);
    }

    // ----- serde ------------------------------------------------------------

    #[test]
    fn serde_wire_forms_round_trip() {
        // CollectionMode wire form = variant name (default derive, spec-silent
        // convention pinned here).
        for (mode, wire) in [
            (CollectionMode::OpenWeb, "\"OpenWeb\""),
            (CollectionMode::Archive, "\"Archive\""),
            (CollectionMode::Registry, "\"Registry\""),
            (CollectionMode::Sensor, "\"Sensor\""),
            (CollectionMode::Human, "\"Human\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), wire);
            assert_eq!(serde_json::from_str::<CollectionMode>(wire).unwrap(), mode);
        }

        let f = finding(
            "f-1",
            vec![src("s-1", CollectionMode::OpenWeb, "a.example")],
        );
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            json,
            r#"{"id":"f-1","claim":"claim for f-1","sources":[{"id":"s-1","mode":"OpenWeb","domain":"a.example"}]}"#
        );
        assert_eq!(serde_json::from_str::<SourcedFinding>(&json).unwrap(), f);

        let hit = LintHit {
            finding: "f-1".to_string(),
            reason: "all sources share mode open_web over 1 source(s)".to_string(),
            suggested_route: vec![CollectionMode::Archive, CollectionMode::Registry],
        };
        let json = serde_json::to_string(&hit).unwrap();
        assert_eq!(serde_json::from_str::<LintHit>(&json).unwrap(), hit);
    }

    #[test]
    fn error_display_serialize_and_boxed() {
        let err = ModeLintError::BadInput("claim");
        assert_eq!(err.to_string(), "invalid input: claim");
        assert_eq!(serde_json::to_string(&err).unwrap(), r#"{"BadInput":"claim"}"#);

        let err = ModeLintError::EmptySources;
        assert_eq!(err.to_string(), "finding has no sources");
        assert_eq!(serde_json::to_string(&err).unwrap(), r#""EmptySources""#);

        let boxed: Box<dyn std::error::Error> = Box::new(ModeLintError::EmptySources);
        assert_eq!(boxed.to_string(), "finding has no sources");
    }
}
