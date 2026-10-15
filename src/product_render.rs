//! Product rendering suite (tasks B5.3.1–B5.3.3, frozen interface §1).
//!
//! Analytic products need a *pinned* lexicon and a *deterministic* renderer:
//! two analysts given the same numbers must produce the same words and the
//! same markdown. This module provides three layers, bottom-up:
//!
//! 1. **Likelihood lexicon (B5.3.1).** [`band_for`] maps a probability
//!    `p ∈ [0.0, 1.0]` onto one of seven [`LikelihoodBand`]s; [`word_for`]
//!    returns the house phrase for a band; [`estimate_line`] renders the
//!    canonical `"<word> (<lo>–<hi>%)"` line with the band's integer bounds
//!    (`0.6 → "likely (55–80%)"`). Bands are half-open intervals with the
//!    PINNED edges below; declaration order of the enum *is* band order
//!    (`Ord` is derived, so `AlmostNoChance < … < AlmostCertain`).
//! 2. **Source annex (B5.3.2).** [`render_annex`] renders a deterministic
//!    markdown table from [`SourceDescriptor`] rows, sorted by `id`, so the
//!    same source set always renders byte-identically regardless of input
//!    order.
//! 3. **Product templates (B5.3.3).** [`render_product`] assembles a
//!    [`ProductDoc`] into a markdown product with the fixed section order
//!    `# <title>` → `## BLUF` → `## Key judgments` → `## Gaps` →
//!    `## Sources` → `## Caveats`. Key judgments and gaps keep input order
//!    (narrative sequence is meaningful); caveats are sorted and deduped
//!    (they are a set); optional sections are omitted when empty.
//!
//! Everything here is a pure function of its arguments — no clock, no I/O,
//! no state — so repeated renders are byte-identical.
//!
//! # Pinned band edges (B5.3.1)
//!
//! | band            | interval          | word                  |
//! |-----------------|-------------------|-----------------------|
//! | `AlmostNoChance`| `[0.00, 0.05)`    | `almost no chance`    |
//! | `VeryUnlikely`  | `[0.05, 0.20)`    | `very unlikely`       |
//! | `Unlikely`      | `[0.20, 0.45)`    | `unlikely`            |
//! | `RoughlyEven`   | `[0.45, 0.55)`    | `roughly even chance` |
//! | `Likely`        | `[0.55, 0.80)`    | `likely`              |
//! | `VeryLikely`    | `[0.80, 0.95)`    | `very likely`         |
//! | `AlmostCertain` | `[0.95, 1.00]`    | `almost certain`      |
//!
//! `p` outside `[0.0, 1.0]`, `NaN`, and infinities are refused with
//! [`RenderError::BadInput`]`("p")`.
//!
//! # Pinned output formats
//!
//! * `estimate_line` uses an EN DASH `–` (U+2013) between the bounds and no
//!   space inside the parentheses: `likely (55–80%)`.
//! * The annex is generated from the two-line skeleton `| id | descriptor |
//!   reliability | credibility |` plus `| --- | --- | --- | --- |` (the
//!   delimiter row is what makes a header row a valid Markdown table), with
//!   one data row per source. Empty input yields exactly the skeleton — no
//!   data rows. Sorting is by `id` (byte order); the sort is stable, so rows
//!   with equal ids keep input order.
//! * `render_product` joins sections with a blank line and emits NO trailing
//!   newline. A missing/empty `title` or `bluf` is refused
//!   (`BadInput("title")` / `BadInput("bluf")`); every other section is
//!   omitted entirely when its vector is empty.
//!
//! # Serde
//!
//! [`LikelihoodBand`], [`SourceDescriptor`], and [`ProductDoc`] derive
//! `Serialize + Deserialize` (default representation — variant names
//! verbatim, e.g. `"VeryLikely"`; §1 specifies no `rename_all`). Error
//! enums that carry `&'static str` payloads derive `Serialize` only (repo
//! precedent: the payload cannot deserialise into `'static`);
//! [`RenderError`] serialises as `{"BadInput":"p"}`.

use serde::{Deserialize, Serialize};

/// The seven-band likelihood lexicon (B5.3.1). Declaration order is band
/// order, and `Ord` is derived so comparisons follow the declaration
/// (`AlmostNoChance < VeryUnlikely < … < AlmostCertain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LikelihoodBand {
    /// `[0.00, 0.05)`.
    AlmostNoChance,
    /// `[0.05, 0.20)`.
    VeryUnlikely,
    /// `[0.20, 0.45)`.
    Unlikely,
    /// `[0.45, 0.55)`.
    RoughlyEven,
    /// `[0.55, 0.80)`.
    Likely,
    /// `[0.80, 0.95)`.
    VeryLikely,
    /// `[0.95, 1.00]`.
    AlmostCertain,
}

/// Errors from product-render operations.
///
/// `Serialize` only (carries `&'static str`; repo precedent): `BadInput`
/// serialises as `{"BadInput":"…"}`. The payload names the offending field
/// (`"p"`, `"title"`, `"bluf"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RenderError {
    /// A named input was malformed (out-of-range probability, `NaN`/`inf`,
    /// or an empty required field).
    BadInput(&'static str),
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::BadInput(name) => write!(f, "invalid product-render input: {name}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// Map a probability onto its [`LikelihoodBand`] (pinned half-open edges).
///
/// `p ∈ [0.0, 1.0]`; anything else — including `NaN` and the infinities —
/// is `BadInput("p")`.
pub fn band_for(p: f64) -> Result<LikelihoodBand, RenderError> {
    // The range `contains` check is false for NaN (all comparisons with NaN
    // are false) and for ±inf, so one guard covers every invalid class.
    if !(0.0..=1.0).contains(&p) {
        return Err(RenderError::BadInput("p"));
    }
    Ok(if p < 0.05 {
        LikelihoodBand::AlmostNoChance
    } else if p < 0.20 {
        LikelihoodBand::VeryUnlikely
    } else if p < 0.45 {
        LikelihoodBand::Unlikely
    } else if p < 0.55 {
        LikelihoodBand::RoughlyEven
    } else if p < 0.80 {
        LikelihoodBand::Likely
    } else if p < 0.95 {
        LikelihoodBand::VeryLikely
    } else {
        LikelihoodBand::AlmostCertain
    })
}

/// The house phrase for a band (pinned strings).
pub fn word_for(b: LikelihoodBand) -> &'static str {
    match b {
        LikelihoodBand::AlmostNoChance => "almost no chance",
        LikelihoodBand::VeryUnlikely => "very unlikely",
        LikelihoodBand::Unlikely => "unlikely",
        LikelihoodBand::RoughlyEven => "roughly even chance",
        LikelihoodBand::Likely => "likely",
        LikelihoodBand::VeryLikely => "very likely",
        LikelihoodBand::AlmostCertain => "almost certain",
    }
}

/// The integer percent bounds of a band, `(lo, hi)`: the lower edge is
/// inclusive, the upper edge is the band's exclusive upper bound (100 for
/// `AlmostCertain`, whose interval is closed at 1.0).
fn band_bounds(b: LikelihoodBand) -> (u32, u32) {
    match b {
        LikelihoodBand::AlmostNoChance => (0, 5),
        LikelihoodBand::VeryUnlikely => (5, 20),
        LikelihoodBand::Unlikely => (20, 45),
        LikelihoodBand::RoughlyEven => (45, 55),
        LikelihoodBand::Likely => (55, 80),
        LikelihoodBand::VeryLikely => (80, 95),
        LikelihoodBand::AlmostCertain => (95, 100),
    }
}

/// Render the canonical estimate line `"<word> (<lo>–<hi>%)"` for `p`
/// (EN DASH U+2013 between the bounds; format pinned in tests), e.g.
/// `0.6 → "likely (55–80%)"`, `1.0 → "almost certain (95–100%)"`.
pub fn estimate_line(p: f64) -> Result<String, RenderError> {
    let band = band_for(p)?;
    let (lo, hi) = band_bounds(band);
    Ok(format!("{} ({}–{}%)", word_for(band), lo, hi))
}

/// One annex row: the source `id`, a short `descriptor`, and the two
/// standard evaluation columns (typically reliability of the source and
/// credibility of the information).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescriptor {
    /// Stable source identifier; annex rows are sorted by this.
    pub id: String,
    /// Short human description of the source.
    pub descriptor: String,
    /// Reliability rating text (e.g. `high`, `moderate`).
    pub reliability: String,
    /// Credibility rating text (e.g. `confirmed`, `probable`).
    pub credibility: String,
}

/// Render the source annex as a deterministic markdown table.
///
/// Layout: the two-line skeleton `| id | descriptor | reliability |
/// credibility |` + `| --- | --- | --- | --- |`, then one
/// `| <id> | <descriptor> | <reliability> | <credibility> |` data row per
/// source, sorted by `id` (stable, so equal ids keep input order). Empty
/// input yields exactly the two-line skeleton. No trailing newline; the
/// same row set always renders byte-identically.
pub fn render_annex(rows: &[SourceDescriptor]) -> String {
    let mut ordered: Vec<&SourceDescriptor> = rows.iter().collect();
    ordered.sort_by(|a, b| a.id.cmp(&b.id));

    let mut out = String::from(
        "| id | descriptor | reliability | credibility |\n| --- | --- | --- | --- |",
    );
    for row in ordered {
        out.push_str("\n| ");
        out.push_str(&row.id);
        out.push_str(" | ");
        out.push_str(&row.descriptor);
        out.push_str(" | ");
        out.push_str(&row.reliability);
        out.push_str(" | ");
        out.push_str(&row.credibility);
        out.push_str(" |");
    }
    out
}

/// An analytic product to render: a title, the bottom-line-up-front
/// paragraph, and (optionally) key judgments, gaps, a source annex, and
/// caveats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductDoc {
    /// Product title (line rendered as `# <title>`).
    pub title: String,
    /// Bottom line up front; required.
    pub bluf: String,
    /// Key judgments in narrative (input) order.
    pub key_judgments: Vec<String>,
    /// Intelligence gaps in narrative (input) order.
    pub gaps: Vec<String>,
    /// Source annex rows (sorted by `id` at render time).
    pub annex: Vec<SourceDescriptor>,
    /// Caveats; rendered sorted and deduplicated (they are a set).
    pub caveats: Vec<String>,
}

/// Render `- ` bullets, one per line, preserving iteration order.
fn bullets<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    let mut out = String::new();
    let mut first = true;
    for item in items {
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str("- ");
        out.push_str(item);
    }
    out
}

/// Render a [`ProductDoc`] as markdown.
///
/// Fixed section order: `# <title>` → `## BLUF` → `## Key judgments` →
/// `## Gaps` → `## Sources` (via [`render_annex`]) → `## Caveats` (sorted +
/// deduped). Optional sections are omitted entirely when empty. Empty
/// `title` / `bluf` → `BadInput("title")` / `BadInput("bluf")`. Sections are
/// separated by a blank line; there is no trailing newline. Deterministic:
/// the same document always renders byte-identically.
pub fn render_product(doc: &ProductDoc) -> Result<String, RenderError> {
    if doc.title.is_empty() {
        return Err(RenderError::BadInput("title"));
    }
    if doc.bluf.is_empty() {
        return Err(RenderError::BadInput("bluf"));
    }

    let mut sections: Vec<String> = Vec::with_capacity(6);
    sections.push(format!("# {}", doc.title));
    sections.push(format!("## BLUF\n\n{}", doc.bluf));

    if !doc.key_judgments.is_empty() {
        sections.push(format!("## Key judgments\n\n{}", bullets(&doc.key_judgments)));
    }
    if !doc.gaps.is_empty() {
        sections.push(format!("## Gaps\n\n{}", bullets(&doc.gaps)));
    }
    if !doc.annex.is_empty() {
        sections.push(format!("## Sources\n\n{}", render_annex(&doc.annex)));
    }
    if !doc.caveats.is_empty() {
        let mut caveats: Vec<&String> = doc.caveats.iter().collect();
        caveats.sort();
        caveats.dedup();
        sections.push(format!("## Caveats\n\n{}", bullets(caveats)));
    }

    Ok(sections.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------- bands (B5.3.1)

    #[test]
    fn band_edges_pinned() {
        // The ten edges named in §1, plus the remaining internal edge
        // (0.45) for completeness.
        let pins = [
            (0.0, LikelihoodBand::AlmostNoChance),
            (0.0499, LikelihoodBand::AlmostNoChance),
            (0.05, LikelihoodBand::VeryUnlikely),
            (0.1999, LikelihoodBand::VeryUnlikely),
            (0.2, LikelihoodBand::Unlikely),
            (0.4499, LikelihoodBand::Unlikely),
            (0.45, LikelihoodBand::RoughlyEven),
            (0.5499, LikelihoodBand::RoughlyEven),
            (0.55, LikelihoodBand::Likely),
            (0.8, LikelihoodBand::VeryLikely),
            (0.95, LikelihoodBand::AlmostCertain),
            (1.0, LikelihoodBand::AlmostCertain),
        ];
        for (p, expected) in pins {
            assert_eq!(band_for(p).unwrap(), expected, "p = {p}");
        }
    }

    #[test]
    fn band_for_rejects_invalid_inputs() {
        for p in [
            -0.0001,
            -1.0,
            1.0001,
            2.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            assert_eq!(band_for(p), Err(RenderError::BadInput("p")), "p = {p}");
        }
    }

    #[test]
    fn declaration_order_is_band_order() {
        // Windows-method ordering across the whole enum via strict increase
        // of band_for over strictly increasing probabilities.
        let increasing = [0.0, 0.05, 0.2, 0.45, 0.55, 0.8, 0.95];
        let bands: Vec<LikelihoodBand> =
            increasing.iter().map(|&p| band_for(p).unwrap()).collect();
        let ordered = {
            let mut sorted = bands.clone();
            sorted.sort(); // Ord = declaration order
            sorted
        };
        assert_eq!(bands, ordered);
        // And the raw comparison chain, literally.
        assert!(LikelihoodBand::AlmostNoChance < LikelihoodBand::VeryUnlikely);
        assert!(LikelihoodBand::VeryUnlikely < LikelihoodBand::Unlikely);
        assert!(LikelihoodBand::Unlikely < LikelihoodBand::RoughlyEven);
        assert!(LikelihoodBand::RoughlyEven < LikelihoodBand::Likely);
        assert!(LikelihoodBand::Likely < LikelihoodBand::VeryLikely);
        assert!(LikelihoodBand::VeryLikely < LikelihoodBand::AlmostCertain);
    }

    #[test]
    fn words_pinned() {
        assert_eq!(word_for(LikelihoodBand::AlmostNoChance), "almost no chance");
        assert_eq!(word_for(LikelihoodBand::VeryUnlikely), "very unlikely");
        assert_eq!(word_for(LikelihoodBand::Unlikely), "unlikely");
        assert_eq!(word_for(LikelihoodBand::RoughlyEven), "roughly even chance");
        assert_eq!(word_for(LikelihoodBand::Likely), "likely");
        assert_eq!(word_for(LikelihoodBand::VeryLikely), "very likely");
        assert_eq!(word_for(LikelihoodBand::AlmostCertain), "almost certain");
    }

    #[test]
    fn estimate_line_format_pinned() {
        // §1's two literal examples first.
        assert_eq!(estimate_line(0.6).unwrap(), "likely (55–80%)");
        assert_eq!(estimate_line(1.0).unwrap(), "almost certain (95–100%)");
        // Remaining bands, both edges of the lexicon.
        assert_eq!(estimate_line(0.0).unwrap(), "almost no chance (0–5%)");
        assert_eq!(estimate_line(0.0499).unwrap(), "almost no chance (0–5%)");
        assert_eq!(estimate_line(0.05).unwrap(), "very unlikely (5–20%)");
        assert_eq!(estimate_line(0.2).unwrap(), "unlikely (20–45%)");
        assert_eq!(estimate_line(0.5).unwrap(), "roughly even chance (45–55%)");
        assert_eq!(estimate_line(0.8).unwrap(), "very likely (80–95%)");
        assert_eq!(estimate_line(0.95).unwrap(), "almost certain (95–100%)");
        // The dash is an EN DASH (U+2013), not a hyphen.
        assert!(estimate_line(0.6).unwrap().contains('\u{2013}'));
        assert!(!estimate_line(0.6).unwrap().contains('-'));
    }

    #[test]
    fn estimate_line_propagates_invalid() {
        assert_eq!(estimate_line(f64::NAN), Err(RenderError::BadInput("p")));
        assert_eq!(estimate_line(-0.5), Err(RenderError::BadInput("p")));
        assert_eq!(estimate_line(1.5), Err(RenderError::BadInput("p")));
    }

    // -------------------------------------------------------------- annex (B5.3.2)

    fn src(id: &str, descriptor: &str) -> SourceDescriptor {
        SourceDescriptor {
            id: id.to_string(),
            descriptor: descriptor.to_string(),
            reliability: "high".to_string(),
            credibility: "confirmed".to_string(),
        }
    }

    #[test]
    fn render_annex_sorts_rows_by_id() {
        let rows = vec![
            src("C-3", "third"),
            src("A-1", "first"),
            src("B-2", "second"),
        ];
        let expected = concat!(
            "| id | descriptor | reliability | credibility |\n",
            "| --- | --- | --- | --- |\n",
            "| A-1 | first | high | confirmed |\n",
            "| B-2 | second | high | confirmed |\n",
            "| C-3 | third | high | confirmed |",
        );
        assert_eq!(render_annex(&rows), expected);
        // Input order does not matter.
        let reordered = vec![rows[1].clone(), rows[2].clone(), rows[0].clone()];
        assert_eq!(render_annex(&reordered), expected);
    }

    #[test]
    fn render_annex_empty_is_header_only() {
        let expected =
            "| id | descriptor | reliability | credibility |\n| --- | --- | --- | --- |";
        assert_eq!(render_annex(&[]), expected);
        // No trailing newline (byte-exact tail check).
        assert!(!render_annex(&[]).ends_with('\n'));
    }

    #[test]
    fn render_annex_deterministic() {
        let rows = vec![src("Z-9", "z"), src("A-1", "a"), src("M-5", "m")];
        let a = render_annex(&rows);
        let b = render_annex(&rows);
        assert_eq!(a, b);
        assert_eq!(a, render_annex(&rows.clone()));
    }

    // ------------------------------------------------------------ product (B5.3.3)

    #[test]
    fn render_product_full_format_pinned() {
        let doc = ProductDoc {
            title: "Weekly assessment".to_string(),
            bluf: "Adversary activity increased.".to_string(),
            key_judgments: vec!["KJ one".to_string(), "KJ two".to_string()],
            gaps: vec!["Gap one".to_string()],
            annex: vec![
                SourceDescriptor {
                    id: "B-2".to_string(),
                    descriptor: "OSINT".to_string(),
                    reliability: "moderate".to_string(),
                    credibility: "probable".to_string(),
                },
                SourceDescriptor {
                    id: "A-1".to_string(),
                    descriptor: "SIGINT feed".to_string(),
                    reliability: "high".to_string(),
                    credibility: "confirmed".to_string(),
                },
            ],
            caveats: vec![
                "Sorted second".to_string(),
                "Sorted first".to_string(),
            ],
        };
        let expected = concat!(
            "# Weekly assessment\n",
            "\n",
            "## BLUF\n",
            "\n",
            "Adversary activity increased.\n",
            "\n",
            "## Key judgments\n",
            "\n",
            "- KJ one\n",
            "- KJ two\n",
            "\n",
            "## Gaps\n",
            "\n",
            "- Gap one\n",
            "\n",
            "## Sources\n",
            "\n",
            "| id | descriptor | reliability | credibility |\n",
            "| --- | --- | --- | --- |\n",
            "| A-1 | SIGINT feed | high | confirmed |\n",
            "| B-2 | OSINT | moderate | probable |\n",
            "\n",
            "## Caveats\n",
            "\n",
            "- Sorted first\n",
            "- Sorted second",
        );
        assert_eq!(render_product(&doc).unwrap(), expected);
    }

    #[test]
    fn render_product_omits_empty_sections() {
        // Only title + bluf: exactly two sections.
        let minimal = ProductDoc {
            title: "T".to_string(),
            bluf: "B".to_string(),
            key_judgments: vec![],
            gaps: vec![],
            annex: vec![],
            caveats: vec![],
        };
        assert_eq!(render_product(&minimal).unwrap(), "# T\n\n## BLUF\n\nB");

        // Add just gaps: `## Gaps` appears, others stay absent.
        let with_gaps = ProductDoc {
            gaps: vec!["g".to_string()],
            ..minimal.clone()
        };
        let out = render_product(&with_gaps).unwrap();
        assert_eq!(out, "# T\n\n## BLUF\n\nB\n\n## Gaps\n\n- g");
        assert!(!out.contains("## Key judgments"));
        assert!(!out.contains("## Sources"));
        assert!(!out.contains("## Caveats"));

        // Empty annex rows must not emit `## Sources`.
        let empty_annex = ProductDoc {
            key_judgments: vec!["k".to_string()],
            ..minimal.clone()
        };
        let out2 = render_product(&empty_annex).unwrap();
        assert!(out2.contains("## Key judgments\n\n- k"));
        assert!(!out2.contains("## Sources"));
    }

    #[test]
    fn render_product_caveats_sorted_deduped() {
        let doc = ProductDoc {
            title: "T".to_string(),
            bluf: "B".to_string(),
            key_judgments: vec![],
            gaps: vec![],
            annex: vec![],
            caveats: vec![
                "z".to_string(),
                "a".to_string(),
                "z".to_string(),
                "b".to_string(),
                "a".to_string(),
            ],
        };
        let out = render_product(&doc).unwrap();
        assert!(out.ends_with("## Caveats\n\n- a\n- b\n- z"));
    }

    #[test]
    fn render_product_judgments_and_gaps_keep_input_order() {
        let doc = ProductDoc {
            title: "T".to_string(),
            bluf: "B".to_string(),
            key_judgments: vec!["z".to_string(), "a".to_string()],
            gaps: vec!["q".to_string(), "p".to_string()],
            annex: vec![],
            caveats: vec![],
        };
        let out = render_product(&doc).unwrap();
        let kj = out.find("## Key judgments").unwrap();
        let gaps = out.find("## Gaps").unwrap();
        assert!(kj < gaps, "section order: judgments before gaps");
        assert!(out.contains("## Key judgments\n\n- z\n- a"));
        assert!(out.contains("## Gaps\n\n- q\n- p"));
    }

    #[test]
    fn render_product_rejects_empty_title_and_bluf() {
        let no_title = ProductDoc {
            title: String::new(),
            bluf: "B".to_string(),
            key_judgments: vec![],
            gaps: vec![],
            annex: vec![],
            caveats: vec![],
        };
        assert_eq!(
            render_product(&no_title),
            Err(RenderError::BadInput("title"))
        );

        let no_bluf = ProductDoc {
            title: "T".to_string(),
            bluf: String::new(),
            ..no_title
        };
        assert_eq!(render_product(&no_bluf), Err(RenderError::BadInput("bluf")));
    }

    #[test]
    fn render_product_deterministic() {
        let doc = ProductDoc {
            title: "T".to_string(),
            bluf: "B".to_string(),
            key_judgments: vec!["k2".to_string(), "k1".to_string()],
            gaps: vec!["g".to_string()],
            annex: vec![src("B", "b"), src("A", "a")],
            caveats: vec!["c2".to_string(), "c1".to_string(), "c1".to_string()],
        };
        let a = render_product(&doc).unwrap();
        let b = render_product(&doc.clone()).unwrap();
        assert_eq!(a, b);
        // No trailing newline.
        assert!(!a.ends_with('\n'));
    }

    // ------------------------------------------------------------------ serde

    #[test]
    fn serde_likelihood_band_roundtrip() {
        // Default representation: variant names verbatim.
        let json = serde_json::to_string(&LikelihoodBand::VeryLikely).unwrap();
        assert_eq!(json, "\"VeryLikely\"");
        let back: LikelihoodBand = serde_json::from_str(&json).unwrap();
        assert_eq!(back, LikelihoodBand::VeryLikely);
        // All seven round-trip.
        for b in [
            LikelihoodBand::AlmostNoChance,
            LikelihoodBand::VeryUnlikely,
            LikelihoodBand::Unlikely,
            LikelihoodBand::RoughlyEven,
            LikelihoodBand::Likely,
            LikelihoodBand::VeryLikely,
            LikelihoodBand::AlmostCertain,
        ] {
            let s = serde_json::to_string(&b).unwrap();
            assert_eq!(serde_json::from_str::<LikelihoodBand>(&s).unwrap(), b);
        }
    }

    #[test]
    fn serde_product_doc_and_source_descriptor_roundtrip() {
        let doc = ProductDoc {
            title: "T".to_string(),
            bluf: "B".to_string(),
            key_judgments: vec!["k".to_string()],
            gaps: vec!["g".to_string()],
            annex: vec![src("A-1", "a")],
            caveats: vec!["c".to_string()],
        };
        let json = serde_json::to_string(&doc).unwrap();
        let back: ProductDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);

        let row = src("A-1", "a");
        let rjson = serde_json::to_string(&row).unwrap();
        assert_eq!(
            serde_json::from_str::<SourceDescriptor>(&rjson).unwrap(),
            row
        );
    }

    #[test]
    fn serde_render_error_serializes_and_displays() {
        assert_eq!(
            serde_json::to_string(&RenderError::BadInput("p")).unwrap(),
            "{\"BadInput\":\"p\"}"
        );
        assert_eq!(
            RenderError::BadInput("bluf").to_string(),
            "invalid product-render input: bluf"
        );
        // Usable as a std error trait object.
        let e: &dyn std::error::Error = &RenderError::BadInput("title");
        assert!(e.to_string().contains("title"));
    }
}
