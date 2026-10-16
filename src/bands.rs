//! Numeric probability bands → estimative wording — task A4.1.3 (interface §5).
//!
//! Intelligence-reporting convention (ODNI-style estimative language): a
//! numeric likelihood should never be quoted naked — it is rendered as a
//! canonical estimative term, optionally with the rounded percentage in
//! parentheses. This module is the single place where the numeric → verbal
//! mapping and its inverse bounds are defined, so every surface (UI, report,
//! prompt) renders probability bands identically.
//!
//! # Pinned bands (contract §5, pinned by test)
//!
//! | probability `p`       | estimative       |
//! |-----------------------|------------------|
//! | `p < 0.05`            | `AlmostNoChance` |
//! | `p < 0.20`            | `VeryUnlikely`   |
//! | `p < 0.45`            | `Unlikely`       |
//! | `p <= 0.55`           | `RoughlyEven`    |
//! | `p <= 0.80`           | `Likely`         |
//! | `p <= 0.95`           | `VeryLikely`     |
//! | otherwise (`p <= 1`)  | `AlmostCertain`  |
//!
//! [`band_to_estimative`] returns `None` for `NaN` and for any value outside
//! `[0.0, 1.0]` — invalid input is refused, never silently rounded into a band.
//!
//! # Boundary ownership
//! The first three bands are half-open `[lo, hi)`; the last four are
//! `(lo, hi]` (the shared edge belongs to the current band). Concretely:
//! `0.05`, `0.20`, `0.45` open the *next* band (`VeryUnlikely`, `Unlikely`,
//! `RoughlyEven` respectively), while `0.55`, `0.80`, `0.95` close the
//! *current* band (`RoughlyEven`, `Likely`, `VeryLikely` respectively).
//! [`band_range`] returns the nominal bounds; the conventions are pinned by
//! `boundary_ownership_documented` and `band_range_consistency`.
//!
//! # Render format
//! [`render_likelihood`] → `"{word} (≈{pct}%)"` where `pct = round(p * 100)`
//! (round half away from zero), e.g. `0.61` → `"likely (≈61%)"`. The `≈`
//! (U+2248) flags the rounding to the reader. Invalid input → `None`.
//!
//! # Serde
//! Wire form is the snake_case variant name (`"almost_no_chance"`, …),
//! pinned by test.


use serde::{Deserialize, Serialize};

/// Canonical estimative likelihood terms, ascending probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Estimative {
    /// `[0.00, 0.05)` — almost no chance.
    AlmostNoChance,
    /// `[0.05, 0.20)` — very unlikely.
    VeryUnlikely,
    /// `[0.20, 0.45)` — unlikely.
    Unlikely,
    /// `[0.45, 0.55]` — roughly even chance.
    RoughlyEven,
    /// `(0.55, 0.80]` — likely.
    Likely,
    /// `(0.80, 0.95]` — very likely.
    VeryLikely,
    /// `(0.95, 1.00]` — almost certain.
    AlmostCertain,
}

impl Estimative {
    /// All variants in ascending probability order (added convenience; not
    /// part of the §5 contract API — see report).
    pub const ALL: [Estimative; 7] = [
        Estimative::AlmostNoChance,
        Estimative::VeryUnlikely,
        Estimative::Unlikely,
        Estimative::RoughlyEven,
        Estimative::Likely,
        Estimative::VeryLikely,
        Estimative::AlmostCertain,
    ];

    /// Canonical display word (also used by [`render_likelihood`]).
    pub const fn word(self) -> &'static str {
        match self {
            Estimative::AlmostNoChance => "almost no chance",
            Estimative::VeryUnlikely => "very unlikely",
            Estimative::Unlikely => "unlikely",
            Estimative::RoughlyEven => "roughly even chance",
            Estimative::Likely => "likely",
            Estimative::VeryLikely => "very likely",
            Estimative::AlmostCertain => "almost certain",
        }
    }
}

impl std::fmt::Display for Estimative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.word())
    }
}

/// Map a probability to its estimative band.
///
/// Returns `None` for `NaN` or any value outside `[0.0, 1.0]` (both
/// infinities included). Boundaries exactly as pinned in the contract:
/// `< 0.05` → `AlmostNoChance`, `< 0.20` → `VeryUnlikely`, `< 0.45` →
/// `Unlikely`, `<= 0.55` → `RoughlyEven`, `<= 0.80` → `Likely`,
/// `<= 0.95` → `VeryLikely`, else → `AlmostCertain`.
pub fn band_to_estimative(prob: f64) -> Option<Estimative> {
    if prob.is_nan() || !(0.0..=1.0).contains(&prob) {
        return None;
    }
    Some(if prob < 0.05 {
        Estimative::AlmostNoChance
    } else if prob < 0.20 {
        Estimative::VeryUnlikely
    } else if prob < 0.45 {
        Estimative::Unlikely
    } else if prob <= 0.55 {
        Estimative::RoughlyEven
    } else if prob <= 0.80 {
        Estimative::Likely
    } else if prob <= 0.95 {
        Estimative::VeryLikely
    } else {
        Estimative::AlmostCertain
    })
}

/// Render a probability as `"{word} (≈{pct}%)"` with `pct = round(p * 100)`.
///
/// Returns `None` on the same invalid inputs as [`band_to_estimative`].
/// Format is pinned by test (`render_format_pinned`), including the `≈`
/// (U+2248) and the parentheses.
pub fn render_likelihood(prob: f64) -> Option<String> {
    band_to_estimative(prob).map(|e| {
        let pct = (prob * 100.0).round() as i64;
        format!("{} (≈{}%)", e, pct)
    })
}

/// Nominal inverse bounds `(lo, hi)` of an estimative band.
///
/// Edge ownership follows [`band_to_estimative`]: the first three bands are
/// half-open `[lo, hi)` while the last four are `(lo, hi]`, so consecutive
/// bands share an edge exactly (`hi_i == lo_{i+1}`) and every shared edge
/// value maps to the band it opens (`0.05` → `VeryUnlikely`, `0.45` →
/// `RoughlyEven`) except the closing edges `0.55`/`0.80`/`0.95`, which stay
/// with `RoughlyEven`/`Likely`/`VeryLikely`. `AlmostNoChance` starts at
/// `0.0`, `AlmostCertain` ends at `1.0`; together the ranges cover
/// `[0.0, 1.0]` exactly (pinned by `band_range_consistency`).
pub fn band_range(e: Estimative) -> (f64, f64) {
    match e {
        Estimative::AlmostNoChance => (0.0, 0.05),
        Estimative::VeryUnlikely => (0.05, 0.20),
        Estimative::Unlikely => (0.20, 0.45),
        Estimative::RoughlyEven => (0.45, 0.55),
        Estimative::Likely => (0.55, 0.80),
        Estimative::VeryLikely => (0.80, 0.95),
        Estimative::AlmostCertain => (0.95, 1.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 0.000 … 1.000 inclusive, step 0.001 — hits every band and every edge.
    fn grid() -> Vec<f64> {
        (0..=1000).map(|i| i as f64 / 1000.0).collect()
    }

    #[test]
    fn boundaries_pinned() {
        // Below each edge.
        assert_eq!(band_to_estimative(0.0), Some(Estimative::AlmostNoChance));
        assert_eq!(band_to_estimative(0.049), Some(Estimative::AlmostNoChance));
        assert_eq!(band_to_estimative(0.199), Some(Estimative::VeryUnlikely));
        assert_eq!(band_to_estimative(0.449), Some(Estimative::Unlikely));
        assert_eq!(band_to_estimative(0.5500001), Some(Estimative::Likely));
        assert_eq!(band_to_estimative(0.7999999), Some(Estimative::Likely));
        assert_eq!(band_to_estimative(0.8000001), Some(Estimative::VeryLikely));
        assert_eq!(band_to_estimative(0.9500001), Some(Estimative::AlmostCertain));
        // Exactly on each pinned edge.
        assert_eq!(band_to_estimative(0.05), Some(Estimative::VeryUnlikely));
        assert_eq!(band_to_estimative(0.20), Some(Estimative::Unlikely));
        assert_eq!(band_to_estimative(0.45), Some(Estimative::RoughlyEven));
        assert_eq!(band_to_estimative(0.55), Some(Estimative::RoughlyEven));
        assert_eq!(band_to_estimative(0.80), Some(Estimative::Likely));
        assert_eq!(band_to_estimative(0.95), Some(Estimative::VeryLikely));
        // Endpoints of [0, 1].
        assert_eq!(band_to_estimative(1.0), Some(Estimative::AlmostCertain));
    }

    #[test]
    fn boundary_ownership_documented() {
        // Shared lower edges belong to the next band…
        assert_eq!(band_to_estimative(0.05), Some(Estimative::VeryUnlikely));
        assert_eq!(band_to_estimative(0.20), Some(Estimative::Unlikely));
        assert_eq!(band_to_estimative(0.45), Some(Estimative::RoughlyEven));
        // …and shared upper edges stay with the current band.
        assert_eq!(band_to_estimative(0.55), Some(Estimative::RoughlyEven));
        assert_eq!(band_to_estimative(0.80), Some(Estimative::Likely));
        assert_eq!(band_to_estimative(0.95), Some(Estimative::VeryLikely));
    }

    #[test]
    fn none_for_invalid_input() {
        for p in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.001,
            -1.0,
            1.001,
            2.0,
            100.0,
        ] {
            assert_eq!(band_to_estimative(p), None, "band_to_estimative({p})");
            assert_eq!(render_likelihood(p), None, "render_likelihood({p})");
        }
    }

    #[test]
    fn render_format_pinned() {
        assert_eq!(
            render_likelihood(0.0).as_deref(),
            Some("almost no chance (≈0%)")
        );
        assert_eq!(
            render_likelihood(0.12).as_deref(),
            Some("very unlikely (≈12%)")
        );
        assert_eq!(
            render_likelihood(0.5).as_deref(),
            Some("roughly even chance (≈50%)")
        );
        assert_eq!(render_likelihood(0.61).as_deref(), Some("likely (≈61%)"));
        assert_eq!(
            render_likelihood(0.876).as_deref(),
            Some("very likely (≈88%)")
        );
        // Rounds up across the last band edge.
        assert_eq!(
            render_likelihood(0.999999).as_deref(),
            Some("almost certain (≈100%)")
        );
        assert_eq!(
            render_likelihood(1.0).as_deref(),
            Some("almost certain (≈100%)")
        );
    }

    #[test]
    fn display_words_canonical() {
        assert_eq!(Estimative::AlmostNoChance.to_string(), "almost no chance");
        assert_eq!(Estimative::VeryUnlikely.to_string(), "very unlikely");
        assert_eq!(Estimative::Unlikely.to_string(), "unlikely");
        assert_eq!(Estimative::RoughlyEven.to_string(), "roughly even chance");
        assert_eq!(Estimative::Likely.to_string(), "likely");
        assert_eq!(Estimative::VeryLikely.to_string(), "very likely");
        assert_eq!(Estimative::AlmostCertain.to_string(), "almost certain");
    }

    #[test]
    fn band_range_documented_bounds() {
        assert_eq!(band_range(Estimative::AlmostNoChance), (0.0, 0.05));
        assert_eq!(band_range(Estimative::VeryUnlikely), (0.05, 0.20));
        assert_eq!(band_range(Estimative::Unlikely), (0.20, 0.45));
        assert_eq!(band_range(Estimative::RoughlyEven), (0.45, 0.55));
        assert_eq!(band_range(Estimative::Likely), (0.55, 0.80));
        assert_eq!(band_range(Estimative::VeryLikely), (0.80, 0.95));
        assert_eq!(band_range(Estimative::AlmostCertain), (0.95, 1.0));
    }

    #[test]
    fn band_range_consistency() {
        // Consecutive bands share their edge exactly: hi_i == lo_{i+1}.
        for pair in Estimative::ALL.windows(2) {
            let (_, hi) = band_range(pair[0]);
            let (lo, _) = band_range(pair[1]);
            assert_eq!(hi, lo, "{:?} → {:?}", pair[0], pair[1]);
        }
        // Full coverage of [0.0, 1.0], anchored at both ends.
        assert_eq!(band_range(Estimative::AlmostNoChance).0, 0.0);
        assert_eq!(band_range(Estimative::AlmostCertain).1, 1.0);
        // The midpoint of every band maps back to that band.
        for e in Estimative::ALL {
            let (lo, hi) = band_range(e);
            assert!(lo <= hi, "inverted range for {e}");
            let mid = (lo + hi) / 2.0;
            assert_eq!(band_to_estimative(mid), Some(e), "midpoint of {e}");
        }
    }

    #[test]
    fn every_variant_reachable_and_deterministic() {
        let first: Vec<Option<Estimative>> =
            grid().iter().map(|&p| band_to_estimative(p)).collect();
        let second: Vec<Option<Estimative>> =
            grid().iter().map(|&p| band_to_estimative(p)).collect();
        assert_eq!(first, second, "grid mapping must be deterministic");
        for e in Estimative::ALL {
            assert!(
                first.contains(&Some(e)),
                "variant {e} never produced on the 0.000–1.000 grid"
            );
        }
        // Rendering is deterministic too, including rounding.
        for &p in &[0.0, 0.05, 0.45, 0.55, 0.95, 1.0, 0.333, 0.777] {
            assert_eq!(render_likelihood(p), render_likelihood(p), "p = {p}");
        }
    }

    #[test]
    fn serde_wire_form_snake_case() {
        assert_eq!(
            serde_json::to_string(&Estimative::AlmostNoChance).unwrap(),
            "\"almost_no_chance\""
        );
        assert_eq!(
            serde_json::to_string(&Estimative::RoughlyEven).unwrap(),
            "\"roughly_even\""
        );
        for e in Estimative::ALL {
            let wire = serde_json::to_string(&e).unwrap();
            let back: Estimative = serde_json::from_str(&wire).unwrap();
            assert_eq!(back, e, "roundtrip failed for {wire}");
        }
    }
}
