//! Grades → caveated-wording renderer (task A3.1.4 · batch 08 §6).
//!
//! Analyst-facing wording for the two Admiralty axes owned by
//! [`crate::source_registry`]: SOURCE reliability `A`–`F` and ITEM credibility
//! `1`–`6`. The registry stays the single source of truth — the word tables
//! here are thin passthroughs ([`reliability_word`], [`credibility_word`]),
//! so rendered wording can never drift from the registry definitions.
//!
//! * [`caveated_phrase`] — compact `"{credibility_word} ({letter}{digit})"`
//!   rendering, e.g. `"probably true (B2)"`.
//! * [`hedged_sentence`] — deterministic hedge templates keyed on the SOURCE
//!   reliability grade class, so a graded statement cannot be rendered
//!   stronger than its sourcing supports.
//!
//! # Grade classes (documented, ≥ 3)
//!
//! [`hedged_sentence`] selects its template by the SOURCE grade `g`:
//!
//! | class | source grade `g` | scaffold appended before `: {statement}` |
//! |-------|------------------|------------------------------------------|
//! | High  | `A`, `B`         | `high-confidence sourcing supports`      |
//! | Medium| `C`, `D`         | `treat with caution`                     |
//! | Low   | `E`, `F`         | `low-confidence sourcing, do not rely on it` |
//!
//! Every template starts with [`caveated_phrase`], so both axes remain
//! visible in every rendered sentence. Blank statements (empty or
//! whitespace-only) are rejected with [`WordingError::EmptyStatement`].

use crate::source_registry::{ItemCredibility, ReliabilityGrade};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Source-reliability class selecting the [`hedged_sentence`] template.
enum GradeClass {
    /// Grades `A`/`B` — high-confidence sourcing.
    High,
    /// Grades `C`/`D` — treat with caution.
    Medium,
    /// Grades `E`/`F` — low-confidence sourcing.
    Low,
}

/// Classify a SOURCE reliability grade into its wording class.
fn grade_class(g: ReliabilityGrade) -> GradeClass {
    match g {
        ReliabilityGrade::A | ReliabilityGrade::B => GradeClass::High,
        ReliabilityGrade::C | ReliabilityGrade::D => GradeClass::Medium,
        ReliabilityGrade::E | ReliabilityGrade::F => GradeClass::Low,
    }
}

/// Canonical NATO wording for a SOURCE reliability grade — passthrough to
/// [`ReliabilityGrade::word`].
pub fn reliability_word(g: ReliabilityGrade) -> &'static str {
    g.word()
}

/// Canonical NATO wording for an ITEM credibility digit — passthrough to
/// [`ItemCredibility::word`].
pub fn credibility_word(c: ItemCredibility) -> &'static str {
    c.word()
}

/// Compact caveated rendering of a grade pair:
/// `"{credibility_word} ({letter}{digit})"` — e.g. `"doubtful (C4)"`.
pub fn caveated_phrase(g: ReliabilityGrade, c: ItemCredibility) -> String {
    format!("{} ({}{})", credibility_word(c), g.as_letter(), c.as_digit())
}

/// Hedge `statement` with the caveats implied by the grade pair `(g, c)`.
///
/// Deterministic: identical `(g, c, statement)` always renders byte-identical
/// output. The template class comes from `g` (see module docs); both axes are
/// always visible via [`caveated_phrase`], which prefixes the sentence.
///
/// Blank statements — empty or whitespace-only — are rejected
/// ([`WordingError::EmptyStatement`]): a deviation cannot be caveated into
/// existence. The statement itself is rendered verbatim (never trimmed).
pub fn hedged_sentence(
    g: ReliabilityGrade,
    c: ItemCredibility,
    statement: &str,
) -> Result<String, WordingError> {
    if statement.trim().is_empty() {
        return Err(WordingError::EmptyStatement);
    }
    let caveat = caveated_phrase(g, c);
    Ok(match grade_class(g) {
        GradeClass::High => format!("{caveat}; high-confidence sourcing supports: {statement}"),
        GradeClass::Medium => format!("{caveat}; treat with caution: {statement}"),
        GradeClass::Low => {
            format!("{caveat}; low-confidence sourcing, do not rely on it: {statement}")
        }
    })
}

/// Errors from grade-wording rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WordingError {
    /// The statement to hedge was empty (or whitespace-only).
    EmptyStatement,
}

impl fmt::Display for WordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStatement => write!(f, "statement must not be empty"),
        }
    }
}

impl std::error::Error for WordingError {}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_registry::{ItemCredibility, ReliabilityGrade};

    const ALL_GRADES: [ReliabilityGrade; 6] = [
        ReliabilityGrade::A,
        ReliabilityGrade::B,
        ReliabilityGrade::C,
        ReliabilityGrade::D,
        ReliabilityGrade::E,
        ReliabilityGrade::F,
    ];
    const ALL_CRED: [ItemCredibility; 6] = [
        ItemCredibility::Confirmed,
        ItemCredibility::ProbablyTrue,
        ItemCredibility::PossiblyTrue,
        ItemCredibility::Doubtful,
        ItemCredibility::Improbable,
        ItemCredibility::CannotBeJudged,
    ];

    #[test]
    fn passthrough_words_match_registry() {
        let grade_words = [
            (ReliabilityGrade::A, "completely reliable"),
            (ReliabilityGrade::B, "usually reliable"),
            (ReliabilityGrade::C, "fairly reliable"),
            (ReliabilityGrade::D, "not usually reliable"),
            (ReliabilityGrade::E, "unreliable"),
            (ReliabilityGrade::F, "cannot be judged"),
        ];
        for (g, w) in grade_words {
            assert_eq!(reliability_word(g), w);
            assert_eq!(reliability_word(g), g.word(), "registry is the source of truth");
        }
        let cred_words = [
            (ItemCredibility::Confirmed, "confirmed by independent sources"),
            (ItemCredibility::ProbablyTrue, "probably true"),
            (ItemCredibility::PossiblyTrue, "possibly true"),
            (ItemCredibility::Doubtful, "doubtful"),
            (ItemCredibility::Improbable, "improbable"),
            (ItemCredibility::CannotBeJudged, "cannot be judged"),
        ];
        for (c, w) in cred_words {
            assert_eq!(credibility_word(c), w);
            assert_eq!(credibility_word(c), c.word());
        }
    }

    #[test]
    fn caveated_phrase_format_pinned() {
        // Representative pairs, exact strings.
        assert_eq!(
            caveated_phrase(ReliabilityGrade::A, ItemCredibility::Confirmed),
            "confirmed by independent sources (A1)"
        );
        assert_eq!(
            caveated_phrase(ReliabilityGrade::B, ItemCredibility::ProbablyTrue),
            "probably true (B2)"
        );
        assert_eq!(
            caveated_phrase(ReliabilityGrade::D, ItemCredibility::Doubtful),
            "doubtful (D4)"
        );
        assert_eq!(
            caveated_phrase(ReliabilityGrade::F, ItemCredibility::CannotBeJudged),
            "cannot be judged (F6)"
        );
        // Exhaustive shape pin: all 36 pairs equal "{word} ({letter}{digit})".
        for g in ALL_GRADES {
            for c in ALL_CRED {
                assert_eq!(
                    caveated_phrase(g, c),
                    format!("{} ({}{})", credibility_word(c), g.as_letter(), c.as_digit())
                );
            }
        }
    }

    #[test]
    fn hedged_templates_pinned_per_class() {
        let s = "the convoy sails at dawn";
        assert_eq!(
            hedged_sentence(ReliabilityGrade::A, ItemCredibility::Confirmed, s).unwrap(),
            "confirmed by independent sources (A1); high-confidence sourcing supports: \
             the convoy sails at dawn"
        );
        assert_eq!(
            hedged_sentence(ReliabilityGrade::B, ItemCredibility::ProbablyTrue, s).unwrap(),
            "probably true (B2); high-confidence sourcing supports: the convoy sails at dawn"
        );
        assert_eq!(
            hedged_sentence(ReliabilityGrade::C, ItemCredibility::PossiblyTrue, s).unwrap(),
            "possibly true (C3); treat with caution: the convoy sails at dawn"
        );
        assert_eq!(
            hedged_sentence(ReliabilityGrade::D, ItemCredibility::Doubtful, s).unwrap(),
            "doubtful (D4); treat with caution: the convoy sails at dawn"
        );
        assert_eq!(
            hedged_sentence(ReliabilityGrade::E, ItemCredibility::Improbable, s).unwrap(),
            "improbable (E5); low-confidence sourcing, do not rely on it: \
             the convoy sails at dawn"
        );
        assert_eq!(
            hedged_sentence(ReliabilityGrade::F, ItemCredibility::CannotBeJudged, s).unwrap(),
            "cannot be judged (F6); low-confidence sourcing, do not rely on it: \
             the convoy sails at dawn"
        );
    }

    #[test]
    fn grade_classes_share_scaffolds_and_differ() {
        let stmt = "stmt";
        // Both members of a class share the exact same scaffold suffix.
        for g in [ReliabilityGrade::A, ReliabilityGrade::B] {
            let out = hedged_sentence(g, ItemCredibility::Confirmed, stmt).unwrap();
            assert!(
                out.ends_with("; high-confidence sourcing supports: stmt"),
                "{out}"
            );
        }
        for g in [ReliabilityGrade::C, ReliabilityGrade::D] {
            let out = hedged_sentence(g, ItemCredibility::Confirmed, stmt).unwrap();
            assert!(out.ends_with("; treat with caution: stmt"), "{out}");
        }
        for g in [ReliabilityGrade::E, ReliabilityGrade::F] {
            let out = hedged_sentence(g, ItemCredibility::Confirmed, stmt).unwrap();
            assert!(
                out.ends_with("; low-confidence sourcing, do not rely on it: stmt"),
                "{out}"
            );
        }
        // The three classes are pairwise distinct for a fixed pair of axes.
        let c = ItemCredibility::ProbablyTrue;
        let high = hedged_sentence(ReliabilityGrade::A, c, stmt).unwrap();
        let med = hedged_sentence(ReliabilityGrade::C, c, stmt).unwrap();
        let low = hedged_sentence(ReliabilityGrade::F, c, stmt).unwrap();
        assert_ne!(high, med);
        assert_ne!(med, low);
        assert_ne!(high, low);
    }

    #[test]
    fn sentence_carries_both_axes() {
        for g in ALL_GRADES {
            for c in ALL_CRED {
                let out = hedged_sentence(g, c, "stmt").unwrap();
                let caveat = caveated_phrase(g, c);
                assert!(out.starts_with(&caveat), "{out}");
                assert!(out.contains(credibility_word(c)), "{out}");
                assert!(
                    out.contains(&format!("({}{})", g.as_letter(), c.as_digit())),
                    "{out}"
                );
                assert!(out.ends_with(": stmt"), "{out}");
            }
        }
    }

    #[test]
    fn empty_statement_rejected() {
        assert_eq!(
            hedged_sentence(ReliabilityGrade::A, ItemCredibility::Confirmed, ""),
            Err(WordingError::EmptyStatement)
        );
        // Documented strictness: whitespace-only counts as empty.
        assert_eq!(
            hedged_sentence(ReliabilityGrade::B, ItemCredibility::Doubtful, " \t\n "),
            Err(WordingError::EmptyStatement)
        );
        assert_eq!(
            WordingError::EmptyStatement.to_string(),
            "statement must not be empty"
        );
        let json = serde_json::to_string(&WordingError::EmptyStatement).unwrap();
        assert_eq!(json, "\"EmptyStatement\"");
        assert_eq!(
            serde_json::from_str::<WordingError>(&json).unwrap(),
            WordingError::EmptyStatement
        );
    }

    #[test]
    fn statement_rendered_verbatim() {
        let raw = "  padded statement  ";
        let out = hedged_sentence(ReliabilityGrade::C, ItemCredibility::PossiblyTrue, raw).unwrap();
        assert!(out.ends_with(raw), "{out}");
        assert!(out.contains(raw), "{out}");
    }

    #[test]
    fn deterministic_renders() {
        for g in ALL_GRADES {
            for c in ALL_CRED {
                assert_eq!(caveated_phrase(g, c), caveated_phrase(g, c));
                assert_eq!(
                    hedged_sentence(g, c, "same input").unwrap(),
                    hedged_sentence(g, c, "same input").unwrap()
                );
            }
        }
        // Error path is deterministic too.
        assert_eq!(
            hedged_sentence(ReliabilityGrade::B, ItemCredibility::Doubtful, ""),
            hedged_sentence(ReliabilityGrade::B, ItemCredibility::Doubtful, "")
        );
    }
}
