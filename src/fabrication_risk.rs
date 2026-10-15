//! Fabrication-risk scoring + the wilderness-of-mirrors formalism
//! (task B5.4 · batch-12 frozen interface §2 · B5.4.1–B5.4.3).
//!
//! Deception-aware doctrine in two pure, deterministic pieces:
//!
//! * [`fabrication_risk`] — scores one intake [`ChannelAssessment`] on the
//!   pinned additive model below. A channel that is adversary-controlled
//!   starts high; genuine corroboration lowers the score (independent
//!   retelling is evidence *against* fabrication); a prior fabrication
//!   finding raises it. [`RiskScore::factors`] lists every applied term, in
//!   application order, with pinned string forms, so any score can be
//!   explained line by line.
//! * [`apparent_sources`] / [`real_independence`] (B5.4.1) — the wilderness
//!   of mirrors. A [`MirrorChain`] is a handful of channels that *look* like
//!   a crowd. [`apparent_sources`] counts what the chain appears to be
//!   (distinct channel names); [`real_independence`] counts how many
//!   genuinely independent origins remain once adversary control is
//!   accounted for. Three front pages that all trace back to one
//!   adversary-run outlet are three apparent sources and zero real
//!   independence — a doctrine that counts appearances has already been
//!   laundered.
//!
//! # Pinned scoring arithmetic (frozen; exact)
//!
//! Terms are applied to a running total, in this fixed order:
//!
//! 1. base: `50` if `adversary_controlled`, else `10`;
//! 2. corroboration: `+25` if there is **no** corroboration (zero distinct
//!    corroborators); otherwise `−10` per distinct corroborating channel —
//!    and at this step the running total **floors at 0** (it never rests
//!    negative);
//! 3. history: `+25` if `previously_fabricated`;
//! 4. final `clamp 0..=100`.
//!
//! The floor binds at step 2, so the history surcharge (step 3) can lift a
//! floored total back above 0 — a channel that fabricated before stays in
//! consideration no matter how thoroughly it is mirrored (pinned by
//! `history_after_floor_keeps_source_in_play`; this is the conservative
//! reading of the frozen parenthetical “total floors at 0”). Bands are at
//! frozen edges: ≤24 `Low` · 25–59 `Moderate` · 60–84 `High` · ≥85 `Severe`.
//!
//! # Factor strings (pinned in tests)
//!
//! [`RiskScore::factors`] lists the applied terms in application order,
//! using exactly these forms: `"base: adversary-controlled (+50)"`,
//! `"base: open (+10)"`, `"no corroboration (+25)"`,
//! `"corroboration: -10 x <n>"` (n = distinct corroborators), `"floored at 0"`
//! (present only when step 2 actually floored a negative total), and
//! `"previously fabricated (+25)"`.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * `channel` empty **or blank** (whitespace-only) ⇒ `Err(BadInput("channel"))`
//!   — a blank name is no channel (repository precedent: blank counts as
//!   empty). The stored channel is echoed back verbatim; nothing is trimmed
//!   in outputs.
//! * Corroborator names are compared **verbatim** (exact strings) when
//!   sorting and deduplicating; names that are blank after trimming are
//!   skipped — an unnamed corroborator is no corroborator, so skipping keeps
//!   the score on the fail-closed side. Duplicates and input order can never
//!   move a score.
//! * [`MirrorChain`] channel names are compared verbatim as well; blank
//!   names are skipped in both counters — a nameless link is no source.
//! * [`real_independence`] is the frozen rule applied literally: **any**
//!   `adversary_controlled` link anywhere in the chain ⇒ `0`; otherwise the
//!   distinct non-adversary channel names are counted. `relays_via` is
//!   carried structurally (it models re-publication and makes the laundering
//!   case legible) but the frozen rule does not walk it — a clean chain that
//!   merely relays through a channel *outside* the chain is not collapsed by
//!   that alone (pinned by `relay_chains_are_not_walked_literal_rule`).
//!
//! Nothing here touches the clock, the filesystem, or global state:
//! identical inputs always produce identical outputs.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Risk model (B5.4.2–B5.4.3) ───────────────────────────────────────────────

/// Coarse consequence band of a [`RiskScore`]; declaration order is ascending
/// severity. Wire form is the variant name (`"Low"`, … `"Severe"`), pinned by
/// test. Edges are frozen: ≤24 `Low` · 25–59 `Moderate` · 60–84 `High` ·
/// ≥85 `Severe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskBand {
    /// `score <= 24`.
    Low,
    /// `25 <= score <= 59`.
    Moderate,
    /// `60 <= score <= 84`.
    High,
    /// `score >= 85`.
    Severe,
}

/// One intake channel under deception scrutiny.
///
/// `corroborating_channels` is consumed only as a *distinct count*: the
/// names are sorted and deduplicated internally, and blank names are skipped
/// (documented edge rules in the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAssessment {
    /// Channel name as recorded at intake. Required non-blank.
    pub channel: String,
    /// Is this channel run or controlled by the adversary (plant, front,
    /// captured outlet)?
    pub adversary_controlled: bool,
    /// Channels that independently carry (or appear to carry) the same
    /// claim. Only the distinct, non-blank count enters the score.
    pub corroborating_channels: Vec<String>,
    /// Has this channel been caught fabricating before?
    pub previously_fabricated: bool,
}

/// Scored verdict for one channel: the score, its band, and the applied
/// terms in application order (see module docs for the pinned strings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScore {
    /// The channel this verdict is about, echoed verbatim.
    pub channel: String,
    /// Pinned additive score, clamped to `0..=100`.
    pub score: u8,
    /// Band for `score` at the frozen edges.
    pub band: RiskBand,
    /// Applied scoring terms, in application order, pinned string forms.
    pub factors: Vec<String>,
}

/// Band for a clamped score (`0..=100`, frozen edges). Private helper: the
/// public surface scores channels via [`fabrication_risk`] only; in-module
/// tests pin the edges through this function directly.
fn band_of(score: u8) -> RiskBand {
    match score {
        0..=24 => RiskBand::Low,
        25..=59 => RiskBand::Moderate,
        60..=84 => RiskBand::High,
        _ => RiskBand::Severe, // 85..=100
    }
}

/// Score one channel assessment on the pinned arithmetic (module docs).
///
/// * blank `channel` ⇒ [`FabricationError::BadInput`]`("channel")`;
/// * corroborators are sorted + deduplicated (verbatim names, blanks
///   skipped) and enter the score as their distinct count;
/// * terms applied in fixed order — base (50 adversary / 10 open), then
///   `+25` no-corroboration **or** `−10` per distinct corroborator (total
///   floors at 0 at this step), then `+25` previously-fabricated — with the
///   final score clamped to `0..=100`;
/// * `factors` lists the applied terms in the same order, using the pinned
///   string forms.
///
/// Pure and deterministic: identical inputs ⇒ identical [`RiskScore`].
pub fn fabrication_risk(a: &ChannelAssessment) -> Result<RiskScore, FabricationError> {
    if a.channel.trim().is_empty() {
        return Err(FabricationError::BadInput("channel"));
    }

    // Distinct corroborators: verbatim names, blank-after-trim skipped.
    let corroborators: BTreeSet<&str> = a
        .corroborating_channels
        .iter()
        .map(String::as_str)
        .filter(|name| !name.trim().is_empty())
        .collect();
    let n_corroborators = corroborators.len();

    let mut factors: Vec<String> = Vec::with_capacity(4);
    let mut total: i64 = if a.adversary_controlled {
        factors.push("base: adversary-controlled (+50)".to_string());
        50
    } else {
        factors.push("base: open (+10)".to_string());
        10
    };

    if n_corroborators == 0 {
        total += 25;
        factors.push("no corroboration (+25)".to_string());
    } else {
        total -= 10 * n_corroborators as i64;
        factors.push(format!("corroboration: -10 x {n_corroborators}"));
        if total < 0 {
            total = 0; // frozen: the total floors at 0 at this step
            factors.push("floored at 0".to_string());
        }
    }

    if a.previously_fabricated {
        total += 25;
        factors.push("previously fabricated (+25)".to_string());
    }

    let score = total.clamp(0, 100) as u8;
    Ok(RiskScore {
        channel: a.channel.clone(),
        score,
        band: band_of(score),
        factors,
    })
}

// ── Wilderness-of-mirrors formalism (B5.4.1) ─────────────────────────────────

/// One apparent source in a mirror chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorLink {
    /// Channel name as it appears.
    pub channel: String,
    /// The channel this one re-publishes from, when it is a relay rather
    /// than an origin. Structural: the frozen [`real_independence`] rule
    /// does not walk it (see module docs).
    pub relays_via: Option<String>,
    /// Is this channel run or controlled by the adversary?
    pub adversary_controlled: bool,
}

/// A set of channels that appear to corroborate one another — the input to
/// the apparent-vs-real independence counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorChain {
    /// The links, in intake order (counters are order-insensitive).
    pub links: Vec<MirrorLink>,
}

/// Distinct non-blank channel names in the chain (verbatim comparison),
/// sorted for determinism.
fn distinct_channels(c: &MirrorChain) -> BTreeSet<&str> {
    c.links
        .iter()
        .map(|l| l.channel.as_str())
        .filter(|name| !name.trim().is_empty())
        .collect()
}

/// Apparent source count: the number of distinct channel names in the chain —
/// what the chain looks like from outside. Empty (or all-blank) chain ⇒ `0`.
pub fn apparent_sources(c: &MirrorChain) -> usize {
    distinct_channels(c).len()
}

/// Real independence count (frozen rule, applied literally): `0` if **any**
/// link in the chain is adversary-controlled — whatever the apparent count,
/// one captured link means the chain can be steered, so no independence
/// survives. Otherwise the number of distinct non-adversary channel names.
/// Empty (or all-blank) chain ⇒ `0`.
pub fn real_independence(c: &MirrorChain) -> usize {
    if c.links.iter().any(|l| l.adversary_controlled) {
        return 0;
    }
    c.links
        .iter()
        .filter(|l| !l.adversary_controlled)
        .map(|l| l.channel.as_str())
        .filter(|name| !name.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .len()
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Refusals raised by this module.
///
/// `Serialize` is derived; `Deserialize` is not — the `BadInput(&'static str)`
/// payload cannot be deserialized into a `'static` lifetime (same documented
/// choice as the sibling gate modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum FabricationError {
    /// A named input was missing or outside its valid domain.
    BadInput(&'static str),
}

impl fmt::Display for FabricationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FabricationError::BadInput(reason) => write!(f, "invalid input: {reason}"),
        }
    }
}

impl std::error::Error for FabricationError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn assess(channel: &str, adv: bool, corrob: &[&str], hist: bool) -> ChannelAssessment {
        ChannelAssessment {
            channel: channel.to_string(),
            adversary_controlled: adv,
            corroborating_channels: corrob.iter().map(|s| s.to_string()).collect(),
            previously_fabricated: hist,
        }
    }

    fn link(channel: &str, via: Option<&str>, adv: bool) -> MirrorLink {
        MirrorLink {
            channel: channel.to_string(),
            relays_via: via.map(str::to_string),
            adversary_controlled: adv,
        }
    }

    // ── fabrication_risk: pinned worked examples ─────────────────────────

    #[test]
    fn worked_example_pins() {
        let cases: Vec<(ChannelAssessment, RiskScore)> = vec![
            (
                assess("adv-0", true, &[], false),
                RiskScore {
                    channel: "adv-0".to_string(),
                    score: 75,
                    band: RiskBand::High,
                    factors: vec![
                        "base: adversary-controlled (+50)".to_string(),
                        "no corroboration (+25)".to_string(),
                    ],
                },
            ),
            (
                assess("adv-0-hist", true, &[], true),
                RiskScore {
                    channel: "adv-0-hist".to_string(),
                    score: 100,
                    band: RiskBand::Severe,
                    factors: vec![
                        "base: adversary-controlled (+50)".to_string(),
                        "no corroboration (+25)".to_string(),
                        "previously fabricated (+25)".to_string(),
                    ],
                },
            ),
            (
                assess("adv-2", true, &["front-a", "front-b"], false),
                RiskScore {
                    channel: "adv-2".to_string(),
                    score: 30,
                    band: RiskBand::Moderate,
                    factors: vec![
                        "base: adversary-controlled (+50)".to_string(),
                        "corroboration: -10 x 2".to_string(),
                    ],
                },
            ),
            (
                assess("adv-5", true, &["a", "b", "c", "d", "e"], false),
                RiskScore {
                    channel: "adv-5".to_string(),
                    score: 0,
                    band: RiskBand::Low,
                    factors: vec![
                        "base: adversary-controlled (+50)".to_string(),
                        "corroboration: -10 x 5".to_string(),
                    ],
                },
            ),
            (
                assess("open-0", false, &[], false),
                RiskScore {
                    channel: "open-0".to_string(),
                    score: 35,
                    band: RiskBand::Moderate,
                    factors: vec![
                        "base: open (+10)".to_string(),
                        "no corroboration (+25)".to_string(),
                    ],
                },
            ),
            (
                assess("open-1", false, &["front-a"], false),
                RiskScore {
                    channel: "open-1".to_string(),
                    score: 0,
                    band: RiskBand::Low,
                    factors: vec![
                        "base: open (+10)".to_string(),
                        "corroboration: -10 x 1".to_string(),
                    ],
                },
            ),
        ];
        for (input, expected) in &cases {
            assert_eq!(&fabrication_risk(input).unwrap(), expected);
        }
    }

    #[test]
    fn band_edges_pinned() {
        assert_eq!(band_of(0), RiskBand::Low);
        assert_eq!(band_of(24), RiskBand::Low);
        assert_eq!(band_of(25), RiskBand::Moderate);
        assert_eq!(band_of(59), RiskBand::Moderate);
        assert_eq!(band_of(60), RiskBand::High);
        assert_eq!(band_of(84), RiskBand::High);
        assert_eq!(band_of(85), RiskBand::Severe);
        assert_eq!(band_of(100), RiskBand::Severe);
    }

    #[test]
    fn band_edges_reachable_from_scoring() {
        // 75 → High (adversary, no corroboration)
        assert_eq!(
            fabrication_risk(&assess("a", true, &[], false)).unwrap().band,
            RiskBand::High
        );
        // 100 → Severe (adversary, no corroboration, history)
        assert_eq!(
            fabrication_risk(&assess("a", true, &[], true)).unwrap().band,
            RiskBand::Severe
        );
        // 35 → Moderate (open, no corroboration)
        assert_eq!(
            fabrication_risk(&assess("a", false, &[], false)).unwrap().band,
            RiskBand::Moderate
        );
        // 0 → Low
        assert_eq!(
            fabrication_risk(&assess("a", false, &["x"], false)).unwrap().band,
            RiskBand::Low
        );
        // 60 → High (open, no corroboration, history)
        assert_eq!(
            fabrication_risk(&assess("a", false, &[], true)).unwrap().band,
            RiskBand::High
        );
        // 25 → Moderate (floored, then history keeps it in play)
        assert_eq!(
            fabrication_risk(&assess("a", true, &["1", "2", "3", "4", "5", "6", "7", "8"], true))
                .unwrap()
                .band,
            RiskBand::Moderate
        );
    }

    // ── fabrication_risk: corroborator handling ──────────────────────────

    #[test]
    fn corroborators_dedup_and_order_insensitive() {
        let ugly = assess("c", true, &["front-b", "front-a", "front-b"], false);
        let tidy = assess("c", true, &["front-a", "front-b"], false);
        assert_eq!(fabrication_risk(&ugly).unwrap(), fabrication_risk(&tidy).unwrap());
        assert_eq!(fabrication_risk(&tidy).unwrap().score, 30);
    }

    #[test]
    fn corroborator_names_compare_verbatim() {
        // Padded variants are distinct names (nothing is trimmed/merged).
        let a = assess("c", true, &[" x", "x "], false);
        let r = fabrication_risk(&a).unwrap();
        assert_eq!(r.score, 30); // 50 − 20
        assert_eq!(r.factors[1], "corroboration: -10 x 2");
    }

    #[test]
    fn blank_corroborators_skipped() {
        let a = assess("c", true, &["", "   ", "\t"], false);
        let r = fabrication_risk(&a).unwrap();
        // Blank names are no corroborators: the no-corroboration term applies.
        assert_eq!(r.score, 75);
        assert_eq!(
            r.factors,
            vec![
                "base: adversary-controlled (+50)".to_string(),
                "no corroboration (+25)".to_string(),
            ]
        );
    }

    #[test]
    fn corroboration_term_replaces_the_bonus() {
        // With at least one corroborator the +25 bonus must NOT apply.
        let r = fabrication_risk(&assess("c", true, &["x"], false)).unwrap();
        assert_eq!(r.score, 40); // 50 − 10, no +25
        assert!(!r.factors.iter().any(|f| f.contains("no corroboration")));
    }

    #[test]
    fn open_base_is_ten() {
        let r = fabrication_risk(&assess("o", false, &[], false)).unwrap();
        assert_eq!(r.factors[0], "base: open (+10)");
        assert_eq!(r.score, 35);
    }

    // ── fabrication_risk: floor semantics ────────────────────────────────

    #[test]
    fn floor_binds_only_on_negative_total() {
        // 50 − 50 = 0 exactly: reached the floor value, nothing floored.
        let five = fabrication_risk(&assess("c", true, &["a", "b", "c", "d", "e"], false)).unwrap();
        assert_eq!(five.score, 0);
        assert_eq!(
            five.factors,
            vec![
                "base: adversary-controlled (+50)".to_string(),
                "corroboration: -10 x 5".to_string(),
            ]
        );
        assert!(!five.factors.iter().any(|f| f == "floored at 0"));

        // 50 − 60 = −10: the floor actually binds and is recorded.
        let six = fabrication_risk(&assess("c", true, &["a", "b", "c", "d", "e", "f"], false)).unwrap();
        assert_eq!(six.score, 0);
        assert_eq!(six.factors.last().unwrap(), "floored at 0");

        // 10 − 20 = −10 for an open channel: same floor.
        let open_two = fabrication_risk(&assess("o", false, &["a", "b"], false)).unwrap();
        assert_eq!(open_two.score, 0);
        assert_eq!(open_two.factors.last().unwrap(), "floored at 0");
    }

    #[test]
    fn history_after_floor_keeps_source_in_play() {
        // Conservative reading of "total floors at 0": the floor binds at the
        // corroboration step, then the history surcharge still applies.
        let a = assess("c", true, &["1", "2", "3", "4", "5", "6", "7", "8"], true);
        let r = fabrication_risk(&a).unwrap();
        assert_eq!(r.score, 25); // 0 (floored) + 25
        assert_eq!(r.band, RiskBand::Moderate);
        assert_eq!(
            r.factors,
            vec![
                "base: adversary-controlled (+50)".to_string(),
                "corroboration: -10 x 8".to_string(),
                "floored at 0".to_string(),
                "previously fabricated (+25)".to_string(),
            ]
        );
    }

    #[test]
    fn history_surcharge_alone_reaches_high() {
        let r = fabrication_risk(&assess("o", false, &[], true)).unwrap();
        assert_eq!(r.score, 60); // 10 + 25 + 25
        assert_eq!(r.band, RiskBand::High);
    }

    #[test]
    fn huge_corroboration_still_floors_at_zero() {
        let many: Vec<String> = (0..30).map(|i| format!("ch-{i}")).collect();
        let a = ChannelAssessment {
            channel: "c".to_string(),
            adversary_controlled: true,
            corroborating_channels: many,
            previously_fabricated: false,
        };
        let r = fabrication_risk(&a).unwrap();
        assert_eq!(r.score, 0);
        assert_eq!(r.factors[1], "corroboration: -10 x 30");
        assert_eq!(r.factors[2], "floored at 0");
    }

    // ── fabrication_risk: refusals + verbatim echo ───────────────────────

    #[test]
    fn empty_channel_refused() {
        assert_eq!(
            fabrication_risk(&assess("", false, &[], false)),
            Err(FabricationError::BadInput("channel"))
        );
        assert_eq!(
            fabrication_risk(&assess("   ", true, &[], false)),
            Err(FabricationError::BadInput("channel"))
        );
    }

    #[test]
    fn channel_echoed_verbatim() {
        let r = fabrication_risk(&assess(" feed.x/source-7 ", true, &[], false)).unwrap();
        assert_eq!(r.channel, " feed.x/source-7 ");
    }

    // ── wilderness of mirrors ────────────────────────────────────────────

    #[test]
    fn laundering_case_three_apparent_zero_real() {
        // Three apparent links, all tracing back to one adversary-run
        // channel: apparent 3, real 0.
        let c = MirrorChain {
            links: vec![
                link("mirror-central", None, true),
                link("front-a", Some("mirror-central"), false),
                link("front-b", Some("mirror-central"), false),
            ],
        };
        assert_eq!(apparent_sources(&c), 3);
        assert_eq!(real_independence(&c), 0);
    }

    #[test]
    fn mixed_chain_any_adversary_collapses() {
        let c = MirrorChain {
            links: vec![
                link("clean-a", None, false),
                link("bad-b", None, true),
                link("front-c", Some("bad-b"), false),
                link("clean-d", None, false),
            ],
        };
        assert_eq!(apparent_sources(&c), 4);
        assert_eq!(real_independence(&c), 0); // ANY adversary-controlled link
    }

    #[test]
    fn clean_chain_real_equals_apparent() {
        let c = MirrorChain {
            links: vec![
                link("a", None, false),
                link("b", None, false),
                link("c", Some("a"), false),
            ],
        };
        assert_eq!(apparent_sources(&c), 3);
        assert_eq!(real_independence(&c), 3);
    }

    #[test]
    fn relay_chains_are_not_walked_literal_rule() {
        // Frozen rule, literal: a fully clean chain is NOT collapsed just
        // because links relay through one another (relays_via is structural).
        let c = MirrorChain {
            links: vec![
                link("a", None, false),
                link("b", Some("a"), false),
                link("c", Some("b"), false),
            ],
        };
        assert_eq!(real_independence(&c), 3);
        // And a relay target outside the chain carries no flag of its own.
        let outside = MirrorChain {
            links: vec![link("x", Some("evil"), false), link("y", Some("evil"), false)],
        };
        assert_eq!(apparent_sources(&outside), 2);
        assert_eq!(real_independence(&outside), 2);
    }

    #[test]
    fn duplicate_channel_names_count_once() {
        let c = MirrorChain {
            links: vec![link("same", None, false), link("same", Some("other"), false)],
        };
        assert_eq!(apparent_sources(&c), 1);
        assert_eq!(real_independence(&c), 1);
    }

    #[test]
    fn empty_chain_and_blank_channels_zero() {
        let empty = MirrorChain { links: vec![] };
        assert_eq!(apparent_sources(&empty), 0);
        assert_eq!(real_independence(&empty), 0);

        let blank = MirrorChain {
            links: vec![link("", None, false), link("  ", None, false)],
        };
        assert_eq!(apparent_sources(&blank), 0);
        assert_eq!(real_independence(&blank), 0);
    }

    // ── determinism + serde ──────────────────────────────────────────────

    #[test]
    fn determinism_repeated_calls() {
        let a = assess("feed-d", true, &["b", "a", "b"], true);
        let r1 = fabrication_risk(&a).unwrap();
        let r2 = fabrication_risk(&a).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(
            serde_json::to_string(&r1).unwrap(),
            serde_json::to_string(&r2).unwrap()
        );

        let chain = MirrorChain {
            links: vec![link("s1", None, false), link("s2", Some("s1"), false)],
        };
        assert_eq!(apparent_sources(&chain), apparent_sources(&chain));
        assert_eq!(real_independence(&chain), 2);
        assert_eq!(real_independence(&chain), real_independence(&chain));
    }

    #[test]
    fn serde_roundtrips_and_wire_pins() {
        let a = assess("feed-x", true, &["front-a"], false);
        let ja = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<ChannelAssessment>(&ja).unwrap(), a);

        let s = fabrication_risk(&a).unwrap(); // 50 − 10 = 40 → Moderate
        let js = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<RiskScore>(&js).unwrap(), s);
        assert!(js.contains(r#""band":"Moderate""#));

        let band = serde_json::to_string(&RiskBand::Severe).unwrap();
        assert_eq!(band, r#""Severe""#);
        assert_eq!(
            serde_json::from_str::<RiskBand>(&band).unwrap(),
            RiskBand::Severe
        );

        let chain = MirrorChain {
            links: vec![link("a", Some("x"), false), link("x", None, true)],
        };
        let jc = serde_json::to_string(&chain).unwrap();
        assert_eq!(serde_json::from_str::<MirrorChain>(&jc).unwrap(), chain);
        assert!(jc.contains(r#""relays_via":"x""#));
        let none_via = serde_json::to_string(&link("a", None, false)).unwrap();
        assert!(none_via.contains(r#""relays_via":null"#));
    }

    #[test]
    fn error_traits_and_wire_form() {
        let e = FabricationError::BadInput("channel");
        assert_eq!(e.to_string(), "invalid input: channel");
        let dyn_err: &dyn std::error::Error = &e;
        assert_eq!(dyn_err.to_string(), "invalid input: channel");
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!({"BadInput": "channel"})
        );
    }
}
