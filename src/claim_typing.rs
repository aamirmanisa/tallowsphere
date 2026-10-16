//! Claim typing + promotion guard — task A3.1.3 (E6; interface §4).
//!
//! Two halves of the same discipline, both from the E6 graded-collection
//! pipeline (dossier: "no derived claim may be promoted above its source
//! grade without explicit provenance — origin-inflation guard"; `raw/03`:
//! legend systematically drifts into record unless it has a typed slot):
//!
//! 1. **Claim typing.** [`ClaimType`] gives graph nodes/edges an explicit
//!    `claim_class ∈ {documented, disputed, legend, debunked, attributed}`
//!    typed slot, and [`type_claim`] cheaply infers it from free text via
//!    the [`TYPE_MARKERS`] table. The whole point is that *myth, legend,
//!    dispute, and debunking must not silently read as record* — the
//!    Rosicrucian "first real Rosicrucians 1763" / Simmel "claiming origins
//!    older than can be reliably documented" failure mode (`raw/03`).
//!
//! 2. **Promotion guard.** [`may_promote`] / [`promotion_guard`] implement
//!    the origin-inflation guard: a derived claim must not be graded *more
//!    credible* than its source unless explicit provenance is on record.
//!
//! # Digit convention
//! Digits follow the workspace Admiralty convention already used by
//! [`crate::source_registry`] (`ItemCredibility::as_digit`, `1` = best …
//! `6` = worst) and by the E6 sibling regrade logic (§3: corroboration
//! "flips up" `3/4 → 2/1`, i.e. **up the ladder means a numerically smaller
//! digit**). "Above its source grade" therefore means a *numerically
//! smaller* digit than the source's: `derived = 2` from `source = 4` is an
//! upgrade (inflation) and is refused without `explicit_provenance`; a
//! derived claim at or weaker than its source (`derived >= source`) is
//! always allowed.
//!
//! # Marker precedence (documented)
//! [`type_claim`] performs a case-insensitive `contains` scan over
//! [`TYPE_MARKERS`], **first match wins**, in this class order:
//! `Debunked` → `Legend` → `Disputed` → `Attributed` → `Documented`
//! (default). A text carrying several signals resolves to the strongest
//! class present: "myth later disproven" → `Debunked`, "contested myth" →
//! `Legend`. The scan is substring-based, so "mythology"/"mythical" also
//! trip `myth`; this is deliberate (a lineage claim wearing mythological
//! language should still read as legend, not record) and is pinned by test.
//!
//! # Failure behaviour
//! [`type_claim`] never panics — the default class is `Documented`.
//! [`may_promote`] returns `false` on invalid digits (`0` or `> 6`).
//! [`promotion_guard`] reports [`PromotionError::InvalidDigit`] before
//! [`PromotionError::AboveSource`] (invalid input is diagnosed first;
//! provenance does not excuse invalid digits).
//!
//! # Serde
//! Wire form is the lowercase class name (`"debunked"`, …), pinned by test,
//! matching the `claim_class` value space named in the dossier. Derives are
//! plain decoders and do not validate — callers ingest untrusted JSON at
//! their own verification boundary.


use serde::{Deserialize, Serialize};

// ── Claim typing ────────────────────────────────────────────────────────────

/// The typed claim class of an IntelGraph node/edge (E6/A3.1.3).
///
/// `Documented` is the default when no marker matches; the other four
/// classes exist so legend/dispute/debunking cannot silently read as record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    /// Record: supported by documents/sources as stated.
    Documented,
    /// Contested: sources disagree or the claim is unverified.
    Disputed,
    /// Legend/folklore/myth: traditional material, not a documentary record.
    Legend,
    /// Debunked: shown false (disproven, hoax).
    Debunked,
    /// Attributed: hedged sourcing ("attributed to X", "reportedly").
    Attributed,
}

impl ClaimType {
    /// Canonical lowercase class name (also the wire form).
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimType::Documented => "documented",
            ClaimType::Disputed => "disputed",
            ClaimType::Legend => "legend",
            ClaimType::Debunked => "debunked",
            ClaimType::Attributed => "attributed",
        }
    }
}

impl std::fmt::Display for ClaimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lowercase marker → claim type, in **precedence order** (first match wins).
///
/// Markers are grouped by class in the documented order
/// `Debunked → Legend → Disputed → Attributed → Documented`. The literal
/// `"documented"` marker is placed last so it can never shadow a stronger
/// class; `Documented` is additionally the default for unmatched text.
pub const TYPE_MARKERS: &[(&str, ClaimType)] = &[
    // Debunked
    ("debunked", ClaimType::Debunked),
    ("disproven", ClaimType::Debunked),
    ("hoax", ClaimType::Debunked),
    // Legend
    ("legend", ClaimType::Legend),
    ("folklore", ClaimType::Legend),
    ("myth", ClaimType::Legend),
    // Disputed
    ("disputed", ClaimType::Disputed),
    ("contested", ClaimType::Disputed),
    ("unverified", ClaimType::Disputed),
    // Attributed
    ("attributed to", ClaimType::Attributed),
    ("reportedly", ClaimType::Attributed),
    ("sources say", ClaimType::Attributed),
    // Documented (default; literal marker last so it cannot shadow others)
    ("documented", ClaimType::Documented),
];

/// Infer the claim class of `text` by case-insensitive `contains` scan.
///
/// First marker hit in [`TYPE_MARKERS`] order wins; unmatched text (including
/// empty text) is [`ClaimType::Documented`]. Never panics.
pub fn type_claim(text: &str) -> ClaimType {
    let lower = text.to_lowercase();
    for (marker, claim_type) in TYPE_MARKERS {
        if lower.contains(marker) {
            return *claim_type;
        }
    }
    ClaimType::Documented
}

// ── Promotion guard (origin-inflation guard) ────────────────────────────────

/// The inputs of one promotion decision: the grade the derived claim would
/// carry, the grade of its origin source, and whether explicit provenance
/// (a recorded derivation chain justifying the upgrade) exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionCheck {
    /// Desired Admiralty item-credibility digit of the derived claim (1–6).
    pub derived_digit: u8,
    /// Admiralty digit of the origin source (1–6).
    pub source_digit: u8,
    /// Is an explicit provenance record on file for an upgrade above source?
    pub explicit_provenance: bool,
}

/// Refusal from the origin-inflation guard.
///
/// `Display`/`Error` are hand-rolled rather than `thiserror`-derived: the
/// frozen field name `source` collides with thiserror's implicit
/// "a field named `source` is `Error::source()`" convention, which would
/// (wrongly) demand `u8: std::error::Error` (verified: rustc E0599). The
/// public surface is identical to the sibling modules' error enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionError {
    /// The derived claim would be graded above its source grade (more
    /// credible, i.e. a numerically smaller digit) without explicit
    /// provenance.
    AboveSource { derived: u8, source: u8 },
    /// A digit outside the valid range `1..=6`.
    InvalidDigit(u8),
}

impl std::fmt::Display for PromotionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromotionError::AboveSource { derived, source } => write!(
                f,
                "derived claim graded {derived} is above source grade {source} without explicit provenance"
            ),
            PromotionError::InvalidDigit(d) => {
                write!(f, "invalid credibility digit {d}; valid range is 1..=6")
            }
        }
    }
}

impl std::error::Error for PromotionError {}

/// `true` iff `d` is a valid Admiralty digit (`1..=6`).
fn in_range(d: u8) -> bool {
    (1..=6).contains(&d)
}

/// Origin-inflation guard (E6), predicate form.
///
/// * Invalid digit (`0` or `> 6`) anywhere → `false`.
/// * Derived at or below the source grade (`derived >= source`, i.e. equal
///   or weaker credibility) → allowed.
/// * Derived **above** the source grade (more credible: `derived < source`)
///   → allowed only with `explicit_provenance`.
pub fn may_promote(derived: u8, source: u8, explicit_provenance: bool) -> bool {
    if !in_range(derived) || !in_range(source) {
        return false;
    }
    if derived >= source {
        return true;
    }
    explicit_provenance
}

/// Origin-inflation guard, hard-fail form.
///
/// Precedence: [`PromotionError::InvalidDigit`] first (`derived` then
/// `source`), then [`PromotionError::AboveSource`] when the claim would sit
/// above its source grade without explicit provenance. Otherwise `Ok(())`.
pub fn promotion_guard(c: &PromotionCheck) -> Result<(), PromotionError> {
    if !in_range(c.derived_digit) {
        return Err(PromotionError::InvalidDigit(c.derived_digit));
    }
    if !in_range(c.source_digit) {
        return Err(PromotionError::InvalidDigit(c.source_digit));
    }
    if c.derived_digit < c.source_digit && !c.explicit_provenance {
        return Err(PromotionError::AboveSource {
            derived: c.derived_digit,
            source: c.source_digit,
        });
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── typing: each marker class ───────────────────────────────────────────

    #[test]
    fn each_debunked_marker_types_debunked() {
        for text in [
            "the hoax was exposed",
            "this was debunked in 1994",
            "the lineage was disproven by the archive",
        ] {
            assert_eq!(type_claim(text), ClaimType::Debunked, "{text}");
        }
    }

    #[test]
    fn each_legend_marker_types_legend() {
        for text in [
            "the legend of the first master",
            "local folklore holds that…",
            "an origin myth repeated by later authors",
        ] {
            assert_eq!(type_claim(text), ClaimType::Legend, "{text}");
        }
    }

    #[test]
    fn each_disputed_marker_types_disputed() {
        for text in [
            "the date is disputed among historians",
            "the founder's role is contested",
            "an unverified charter",
        ] {
            assert_eq!(type_claim(text), ClaimType::Disputed, "{text}");
        }
    }

    #[test]
    fn each_attributed_marker_types_attributed() {
        for text in [
            "the charter attributed to the 1763 assembly",
            "reportedly founded in Paris",
            "sources say the lodge burned",
        ] {
            assert_eq!(type_claim(text), ClaimType::Attributed, "{text}");
        }
    }

    #[test]
    fn matching_documented_marker_or_default_types_documented() {
        assert_eq!(type_claim("a documented lineage"), ClaimType::Documented);
        assert_eq!(type_claim("plain archival statement"), ClaimType::Documented);
        assert_eq!(type_claim(""), ClaimType::Documented);
    }

    // ── typing: precedence + case + determinism + table sanity ─────────────

    #[test]
    fn class_precedence_first_match_wins() {
        // Debunked beats Legend.
        assert_eq!(type_claim("the myth was disproven"), ClaimType::Debunked);
        // Legend beats Disputed.
        assert_eq!(type_claim("a contested legend"), ClaimType::Legend);
        // Disputed beats Attributed.
        assert_eq!(type_claim("reportedly disputed"), ClaimType::Disputed);
        // Attributed beats Documented.
        assert_eq!(
            type_claim("a documented claim, reportedly older"),
            ClaimType::Attributed
        );
        // Full ladder in one string.
        assert_eq!(
            type_claim("undocumented folklore, reportedly disputed, later debunked"),
            ClaimType::Debunked
        );
    }

    #[test]
    fn scan_is_case_insensitive() {
        assert_eq!(type_claim("DEBUNKED"), ClaimType::Debunked);
        assert_eq!(type_claim("A HOAX"), ClaimType::Debunked);
        assert_eq!(type_claim("Legend"), ClaimType::Legend);
        assert_eq!(type_claim("RePoRtEdLy"), ClaimType::Attributed);
        assert_eq!(type_claim("UnVeRiFiEd"), ClaimType::Disputed);
    }

    #[test]
    fn substring_scan_trips_on_mythological_words() {
        // Substring scan is deliberate: mythological language reads as legend.
        assert_eq!(type_claim("mythical origins"), ClaimType::Legend);
        assert_eq!(type_claim("the mythology around the founder"), ClaimType::Legend);
    }

    #[test]
    fn type_claim_is_deterministic() {
        let t = "reportedly debunked folklore";
        let a = type_claim(t);
        let b = type_claim(t);
        assert_eq!(a, b);
        assert_eq!(a, ClaimType::Debunked);
    }

    #[test]
    fn marker_table_is_lowercase_and_in_class_order() {
        for (marker, _) in TYPE_MARKERS {
            assert_eq!(*marker, marker.to_lowercase(), "marker not lowercase: {marker}");
            assert!(!marker.is_empty());
        }
        let first_index_of = |want: ClaimType| {
            TYPE_MARKERS
                .iter()
                .position(|(_, t)| *t == want)
                .expect("class present in table")
        };
        let d = first_index_of(ClaimType::Debunked);
        let l = first_index_of(ClaimType::Legend);
        let p = first_index_of(ClaimType::Disputed);
        let a = first_index_of(ClaimType::Attributed);
        let doc = first_index_of(ClaimType::Documented);
        assert!(d < l && l < p && p < a && a < doc, "class precedence order");
    }

    // ── guard: predicate form ───────────────────────────────────────────────

    #[test]
    fn may_promote_allows_at_or_below_source() {
        assert!(may_promote(3, 3, false)); // same grade
        assert!(may_promote(4, 3, false)); // weaker than source
        assert!(may_promote(6, 1, false)); // far weaker than source
    }

    #[test]
    fn may_promote_denies_above_source_without_provenance() {
        assert!(!may_promote(2, 4, false));
        assert!(!may_promote(1, 6, false));
        assert!(!may_promote(2, 3, false));
    }

    #[test]
    fn may_promote_allows_above_source_with_provenance() {
        assert!(may_promote(2, 4, true));
        assert!(may_promote(1, 6, true));
        assert!(may_promote(2, 3, true));
    }

    #[test]
    fn may_promote_rejects_invalid_digits_even_with_provenance() {
        for bad in [0u8, 7, 42, 255] {
            assert!(!may_promote(bad, 3, true), "derived={bad}");
            assert!(!may_promote(3, bad, true), "source={bad}");
            assert!(!may_promote(bad, bad, true), "both={bad}");
        }
    }

    // ── guard: hard-fail form ───────────────────────────────────────────────

    #[test]
    fn guard_ok_paths() {
        let ok = |d, s, p| promotion_guard(&PromotionCheck {
            derived_digit: d,
            source_digit: s,
            explicit_provenance: p,
        });
        assert_eq!(ok(3, 3, false), Ok(()));
        assert_eq!(ok(5, 2, false), Ok(()));
        assert_eq!(ok(2, 4, true), Ok(()));
    }

    #[test]
    fn guard_invalid_digit_precedes_above_source() {
        let err = promotion_guard(&PromotionCheck {
            derived_digit: 0,
            source_digit: 6,
            explicit_provenance: false,
        });
        assert_eq!(err, Err(PromotionError::InvalidDigit(0)));
        let err = promotion_guard(&PromotionCheck {
            derived_digit: 5,
            source_digit: 7,
            explicit_provenance: false,
        });
        assert_eq!(err, Err(PromotionError::InvalidDigit(7)));
        // Derived checked before source.
        let err = promotion_guard(&PromotionCheck {
            derived_digit: 9,
            source_digit: 0,
            explicit_provenance: false,
        });
        assert_eq!(err, Err(PromotionError::InvalidDigit(9)));
    }

    #[test]
    fn guard_reports_above_source_without_provenance() {
        let err = promotion_guard(&PromotionCheck {
            derived_digit: 2,
            source_digit: 4,
            explicit_provenance: false,
        });
        assert_eq!(err, Err(PromotionError::AboveSource { derived: 2, source: 4 }));
        // Provenance clears the same check.
        assert_eq!(
            promotion_guard(&PromotionCheck {
                derived_digit: 2,
                source_digit: 4,
                explicit_provenance: true,
            }),
            Ok(())
        );
    }

    #[test]
    fn guard_is_deterministic_and_agrees_with_predicate() {
        for derived in 0u8..=7 {
            for source in 0u8..=7 {
                for prov in [false, true] {
                    let c = PromotionCheck {
                        derived_digit: derived,
                        source_digit: source,
                        explicit_provenance: prov,
                    };
                    let gated = promotion_guard(&c).is_ok();
                    assert_eq!(gated, may_promote(derived, source, prov));
                    assert_eq!(gated, promotion_guard(&c).is_ok());
                }
            }
        }
    }

    // ── display + serde ─────────────────────────────────────────────────────

    #[test]
    fn display_strings() {
        assert_eq!(ClaimType::Debunked.to_string(), "debunked");
        assert_eq!(ClaimType::Legend.to_string(), "legend");
        assert_eq!(ClaimType::Attributed.to_string(), "attributed");
        let e = PromotionError::AboveSource { derived: 2, source: 4 };
        let s = e.to_string();
        assert!(s.contains("2") && s.contains("4") && s.contains("provenance"), "{s}");
        assert!(PromotionError::InvalidDigit(7).to_string().contains("7"));
    }

    #[test]
    fn serde_round_trips_and_pins_wire_form() {
        for (ct, wire) in [
            (ClaimType::Documented, "\"documented\""),
            (ClaimType::Disputed, "\"disputed\""),
            (ClaimType::Legend, "\"legend\""),
            (ClaimType::Debunked, "\"debunked\""),
            (ClaimType::Attributed, "\"attributed\""),
        ] {
            let j = serde_json::to_string(&ct).unwrap();
            assert_eq!(j, wire);
            let back: ClaimType = serde_json::from_str(&j).unwrap();
            assert_eq!(back, ct);
            assert_eq!(ct.as_str(), wire.trim_matches('"'));
        }

        let c = PromotionCheck {
            derived_digit: 2,
            source_digit: 4,
            explicit_provenance: true,
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: PromotionCheck = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);
        assert!(j.contains("\"derived_digit\":2"));
        assert!(j.contains("\"explicit_provenance\":true"));
    }
}
