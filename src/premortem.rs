//! Pre-mortem gate — prospective hindsight before commitment (task A4.2.1;
//! dossier E9; interface §6).
//!
//! Wave A4 ("judgment quality") makes Tallow's analytic judgments auditable.
//! A4.2.1 is the **pre-mortem**: before a high-credibility commitment, the
//! analyst must (a) state the assumption under test, (b) enumerate at least
//! [`MIN_FAILURE_MODES`] distinct ways it could fail ("assume it failed —
//! why?"), (c) name the strongest competing hypothesis, and (d) register a
//! falsifier ("what would change my mind"). The method lineage is the
//! prospective-hindsight pre-mortem (Kahneman/Klein) plus Heuer's competing
//! hypotheses (dossier E9, `raw/06`, `raw/07`, `raw/10`).
//!
//! This module is the record + policy-gate layer only:
//!
//! * [`Premortem`] — one pre-mortem record (assumption, failure modes,
//!   strongest competing hypothesis, falsifier, `created_ms`).
//! * [`validate`] — structural validation: trimmed-non-empty assumption /
//!   competing / falsifier, and at least [`MIN_FAILURE_MODES`] failure modes
//!   counted **after** trim + case-insensitive dedupe (so padding the list
//!   with `"access control"` / `"Access Control"` / `" access control "`
//!   does not satisfy the gate — three distinct reasons are required).
//! * [`gate`] — the commitment gate: at credibility digit ≤ 2 (the
//!   "high credibility" class, see `crate::source_registry::ItemCredibility`
//!   digits 1..=6) a valid `Some(premortem)` is **required**; at digit ≥ 3
//!   the gate passes regardless. Digits `0` and `> 6` pass through: this is
//!   a policy gate, not a digit validator (that role belongs to
//!   `crate::claim_typing::promotion_guard` / `source_registry`), so an
//!   invalid digit is documented as out of scope and does not block here.
//! * [`template_markdown`] — the four-heading review template used to drive
//!   the pre-mortem conversation.
//!
//! # Error ordering
//! [`validate`] reports the **first** failure in declaration/enum order:
//! assumption → failure modes → competing → falsifier. Empty/whitespace-only
//! entries in `failure_modes` are not failure modes; they are skipped before
//! counting (documented, so an empty bullet can neither pad nor invalidate).
//!
//! # Serde
//! Serde derive is a plain wire decoder and does not validate. Call
//! [`validate`] / [`gate`] after ingesting untrusted JSON. The wire form is
//! pinned by the serde round-trip test.


use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Minimum number of **distinct** failure modes a pre-mortem must enumerate
/// (frozen by interface §6). "Distinct" = compared trim-first,
/// case-insensitively; empty entries are skipped.
pub const MIN_FAILURE_MODES: usize = 3;

/// One pre-mortem record. Fields are frozen by interface §6; serde derive is
/// provided, but structs deserialized from untrusted JSON must still be run
/// through [`validate`] / [`gate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Premortem {
    /// The assumption under test — what the product leans on. Non-empty
    /// (trimmed), enforced by [`validate`].
    pub assumption: String,
    /// Ways the assumption could fail — "assume it already failed,
    /// enumerate why". At least [`MIN_FAILURE_MODES`] distinct entries
    /// (trim + case-insensitive dedupe), enforced by [`validate`].
    pub failure_modes: Vec<String>,
    /// Strongest competing hypothesis / alternative account that would also
    /// explain the evidence. Non-empty (trimmed), enforced by [`validate`].
    pub strongest_competing: String,
    /// "What would change my mind": the observation that would refute the
    /// assumption. Non-empty (trimmed), enforced by [`validate`].
    pub falsifier: String,
    /// Creation time, Unix epoch milliseconds. Not validated here
    /// (clock provenance is the caller's concern).
    pub created_ms: i64,
}

/// Validation / gate errors for the pre-mortem protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum PremortemError {
    /// `assumption` was empty or whitespace-only. Also returned by [`gate`]
    /// when the commitment is high-credibility and **no** pre-mortem was
    /// supplied at all: a missing pre-mortem is a missing assumption.
    #[error("pre-mortem assumption must not be empty")]
    MissingAssumption,
    /// Fewer than `need` distinct failure modes after trim + case-insensitive
    /// dedupe; `have` is the deduped count.
    #[error("pre-mortem needs at least {need} distinct failure modes, found {have}")]
    TooFewFailureModes { have: usize, need: usize },
    /// `strongest_competing` was empty or whitespace-only.
    #[error("pre-mortem strongest competing hypothesis must not be empty")]
    MissingCompeting,
    /// `falsifier` was empty or whitespace-only.
    #[error("pre-mortem falsifier ('what would change my mind') must not be empty")]
    MissingFalsifier,
}

/// Distinct failure modes after trim + case-insensitive (Unicode-lowercase)
/// dedupe, in first-appearance order. Empty/whitespace-only entries are
/// skipped — they are not failure modes.
fn deduped_failure_modes(modes: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for m in modes {
        let trimmed = m.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_lowercase()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Validate a pre-mortem: trimmed-non-empty `assumption`,
/// `strongest_competing` and `falsifier`; at least [`MIN_FAILURE_MODES`]
/// failure modes counted after trim + case-insensitive dedupe.
///
/// # Errors
/// First failure in declaration/enum order:
/// [`PremortemError::MissingAssumption`] →
/// [`PremortemError::TooFewFailureModes`] (with the **deduped** count in
/// `have`) → [`PremortemError::MissingCompeting`] →
/// [`PremortemError::MissingFalsifier`]. Never panics.
pub fn validate(p: &Premortem) -> Result<(), PremortemError> {
    if p.assumption.trim().is_empty() {
        return Err(PremortemError::MissingAssumption);
    }
    let have = deduped_failure_modes(&p.failure_modes).len();
    if have < MIN_FAILURE_MODES {
        return Err(PremortemError::TooFewFailureModes {
            have,
            need: MIN_FAILURE_MODES,
        });
    }
    if p.strongest_competing.trim().is_empty() {
        return Err(PremortemError::MissingCompeting);
    }
    if p.falsifier.trim().is_empty() {
        return Err(PremortemError::MissingFalsifier);
    }
    Ok(())
}

/// The commitment gate (frozen interface §6).
///
/// * Credibility digit `1 | 2` ("high credibility" commitments) **requires**
///   `Some(valid)`; `None` is rejected as
///   [`PremortemError::MissingAssumption`] (no pre-mortem on record means no
///   assumption on record), and `Some(invalid)` propagates [`validate`]'s
///   error.
/// * Digit `3..=6` → `Ok` regardless of `p` (lower-credibility commitments
///   do not require a pre-mortem).
/// * Digit `0` and `> 6` → `Ok`, documented: this is a **policy gate, not a
///   validator** — invalid digits are another guard's concern
///   (`claim_typing::promotion_guard`, `source_registry` digits 1..=6), so
///   they neither block nor require a pre-mortem here.
///
/// Never panics. Deterministic.
pub fn gate(credibility_digit: u8, p: Option<&Premortem>) -> Result<(), PremortemError> {
    match credibility_digit {
        1 | 2 => match p {
            Some(pm) => validate(pm),
            None => Err(PremortemError::MissingAssumption),
        },
        3..=6 => Ok(()),
        // 0 and >6: invalid digits — out of scope for this policy gate.
        _ => Ok(()),
    }
}

/// Review template with the four required headings (frozen interface §6):
/// Assumption / Failure modes (>= 3 — assume it failed, enumerate why) /
/// Strongest competing hypothesis / What would change my mind.
///
/// Deterministic: contains no timestamps or variant data, so two calls are
/// byte-identical (pinned by test).
pub fn template_markdown() -> String {
    concat!(
        "# Pre-mortem\n",
        "\n",
        "## Assumption\n",
        "\n",
        "<!-- The assumption under test: what does this commitment lean on? -->\n",
        "\n",
        "## Failure modes (>= 3 — assume it failed, enumerate why)\n",
        "\n",
        "- <!-- reason 1 -->\n",
        "- <!-- reason 2 -->\n",
        "- <!-- reason 3 -->\n",
        "\n",
        "## Strongest competing hypothesis\n",
        "\n",
        "<!-- The alternative account that would also explain the evidence. -->\n",
        "\n",
        "## What would change my mind\n",
        "\n",
        "<!-- The observation that would refute the assumption. -->\n",
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(assumption: &str, modes: &[&str], competing: &str, falsifier: &str) -> Premortem {
        Premortem {
            assumption: assumption.to_string(),
            failure_modes: modes.iter().map(|s| s.to_string()).collect(),
            strongest_competing: competing.to_string(),
            falsifier: falsifier.to_string(),
            created_ms: 1_700_000_000_000,
        }
    }

    fn valid() -> Premortem {
        pm(
            "the pipeline holds under load",
            &["queue saturates", "upstream rate-limits us", "shard rebalance stalls"],
            "the observed pattern is a scrape artifact",
            "a controlled replay shows the same pattern",
        )
    }

    // ---- validate -------------------------------------------------------

    #[test]
    fn validate_happy_path() {
        assert_eq!(validate(&valid()), Ok(()));
        // Determinism.
        assert_eq!(validate(&valid()), validate(&valid()));
    }

    #[test]
    fn validate_missing_assumption() {
        let mut p = valid();
        p.assumption = "   \t ".to_string();
        assert_eq!(validate(&p), Err(PremortemError::MissingAssumption));
    }

    #[test]
    fn validate_missing_competing() {
        let mut p = valid();
        p.strongest_competing = "  ".to_string();
        assert_eq!(validate(&p), Err(PremortemError::MissingCompeting));
    }

    #[test]
    fn validate_missing_falsifier() {
        let mut p = valid();
        p.falsifier = "\n".to_string();
        assert_eq!(validate(&p), Err(PremortemError::MissingFalsifier));
    }

    #[test]
    fn validate_too_few_failure_modes() {
        let p = pm("a", &["one", "two"], "c", "f");
        assert_eq!(
            validate(&p),
            Err(PremortemError::TooFewFailureModes { have: 2, need: 3 })
        );
        let empty = pm("a", &[], "c", "f");
        assert_eq!(
            validate(&empty),
            Err(PremortemError::TooFewFailureModes { have: 0, need: 3 })
        );
    }

    #[test]
    fn validate_dedupes_case_insensitively_after_trim() {
        // Three spellings of one mode + one other = 2 distinct → still short.
        let p = pm(
            "a",
            &["access control", " Access Control ", "ACCESS CONTROL", "clock skew"],
            "c",
            "f",
        );
        assert_eq!(
            validate(&p),
            Err(PremortemError::TooFewFailureModes { have: 2, need: 3 })
        );
    }

    #[test]
    fn validate_distinct_after_dedupe_passes() {
        // 6 raw entries, 3 distinct after trim+casefold → passes.
        let p = pm(
            "a",
            &["skew", "Skew", " SKEW ", "bias", "Bias", "drift"],
            "c",
            "f",
        );
        assert_eq!(validate(&p), Ok(()));
    }

    #[test]
    fn validate_skips_empty_failure_modes() {
        // Empty bullets neither count nor invalidate.
        let p = pm("a", &["", "  ", "x", "y", "z"], "c", "f");
        assert_eq!(validate(&p), Ok(()));
        let padded = pm("a", &["x", "y"], "c", "f");
        assert_eq!(
            validate(&padded),
            Err(PremortemError::TooFewFailureModes { have: 2, need: 3 })
        );
    }

    #[test]
    fn validate_error_precedence_is_declaration_order() {
        // Everything wrong at once → assumption first.
        let p = pm(" ", &[], "", "");
        assert_eq!(validate(&p), Err(PremortemError::MissingAssumption));
        // Assumption ok, modes short, competing missing → modes error first.
        let p = pm("ok", &["one"], "", "f");
        assert_eq!(
            validate(&p),
            Err(PremortemError::TooFewFailureModes { have: 1, need: 3 })
        );
        // Assumption + modes ok, competing missing, falsifier missing →
        // competing first.
        let p = pm("ok", &["a", "b", "c"], " ", "");
        assert_eq!(validate(&p), Err(PremortemError::MissingCompeting));
    }

    #[test]
    fn validate_display_text() {
        let e = PremortemError::TooFewFailureModes { have: 1, need: 3 };
        let s = e.to_string();
        assert!(s.contains('1') && s.contains('3'), "display was: {s}");
        assert!(PremortemError::MissingFalsifier
            .to_string()
            .contains("change my mind"));
    }

    // ---- gate -----------------------------------------------------------

    #[test]
    fn gate_high_credibility_requires_valid_premortem() {
        // digit 1 and 2: None refused…
        for d in [1u8, 2] {
            assert_eq!(gate(d, None), Err(PremortemError::MissingAssumption));
            // …invalid refused with the validation error…
            let mut bad = valid();
            bad.failure_modes.truncate(1);
            assert_eq!(
                gate(d, Some(&bad)),
                Err(PremortemError::TooFewFailureModes { have: 1, need: 3 })
            );
            // …valid passes.
            assert_eq!(gate(d, Some(&valid())), Ok(()));
        }
    }

    #[test]
    fn gate_low_credibility_passes_regardless() {
        for d in [3u8, 4, 5, 6] {
            assert_eq!(gate(d, None), Ok(()));
            assert_eq!(gate(d, Some(&valid())), Ok(()));
            let mut bad = valid();
            bad.assumption.clear();
            assert_eq!(gate(d, Some(&bad)), Ok(())); // invalid premortem is ignored
        }
    }

    #[test]
    fn gate_invalid_digits_pass_through_documented() {
        // 0 and >6: policy gate, not a validator — documented as Ok.
        assert_eq!(gate(0, None), Ok(()));
        assert_eq!(gate(0, Some(&valid())), Ok(()));
        assert_eq!(gate(7, None), Ok(()));
        assert_eq!(gate(255, None), Ok(()));
    }

    // ---- template -------------------------------------------------------

    #[test]
    fn template_has_four_headings() {
        let t = template_markdown();
        for heading in [
            "## Assumption",
            "## Failure modes (>= 3 — assume it failed, enumerate why)",
            "## Strongest competing hypothesis",
            "## What would change my mind",
        ] {
            assert!(t.contains(heading), "template missing heading: {heading}");
        }
    }

    #[test]
    fn template_is_deterministic() {
        assert_eq!(template_markdown(), template_markdown());
    }

    // ---- serde ----------------------------------------------------------

    #[test]
    fn serde_round_trips() {
        let p = valid();
        let json = serde_json::to_string(&p).expect("serialize");
        let back: Premortem = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, p);

        let errs = [
            PremortemError::MissingAssumption,
            PremortemError::TooFewFailureModes { have: 1, need: 3 },
            PremortemError::MissingCompeting,
            PremortemError::MissingFalsifier,
        ];
        for e in errs {
            let j = serde_json::to_string(&e).expect("serialize err");
            let back: PremortemError = serde_json::from_str(&j).expect("deserialize err");
            assert_eq!(back, e);
        }
    }
}
