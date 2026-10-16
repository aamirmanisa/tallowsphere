//! ACH — Analysis of Competing Hypotheses matrix (tasks B5.2.1–B5.2.3,
//! frozen interface §8).
//!
//! ACH is Heuer's structured-analysis discipline: enumerate the competing
//! hypotheses first, score every item of evidence against *all* of them, and
//! rank by how much the evidence *refutes* each hypothesis rather than by how
//! much it confirms it ("seek to refute, not confirm"). This module is the
//! pure matrix engine — no clock, no I/O, no state beyond the matrix itself.
//!
//! # Diagnosticity (B5.2.1)
//! Each [`EvidenceItem`] carries a `diagnosticity` in `1..=5`: how sharply the
//! item distinguishes between the hypotheses. It multiplies every cell
//! contribution, so a high-diagnosticity item dominates the arithmetic. `0`
//! and `6+` are rejected on construction ([`AchError::BadInput`]).
//!
//! # Scoring arithmetic (B5.2.2) — disconfirmation double-weighted
//! [`Consistency`] carries the pinned symmetric weights
//! (`StronglyConsistent = +2` … `StronglyInconsistent = −2`). Per cell the
//! contribution to a hypothesis is `|weight| × diagnosticity`, and the totals
//! are:
//!
//! * `consistent` = Σ `weight × diagnosticity` over positive-weight cells;
//! * `inconsistent` = Σ `|weight| × diagnosticity` over negative-weight cells;
//! * **`net = consistent − 2 × inconsistent`**.
//!
//! The literal `2×` on the refutation side is the frozen pin: it is an
//! *additional* asymmetric penalty on top of the magnitude that
//! `Inconsistent`/`StronglyInconsistent` already carry, so disconfirming
//! evidence counts double against a hypothesis. Worked asymmetry: one
//! `StronglyConsistent` cell with diagnosticity 5 yields `net = +10`, while
//! its mirror `StronglyInconsistent` cell yields `net = −20`. A hypothesis
//! whose evidence is "balanced" in raw magnitude therefore ranks negative — by
//! design (anti-confirmation-bias: one refutation outweighs one corroboration
//! of the same strength). Tests pin the arithmetic literally as specified,
//! including both extremes.
//!
//! # Missing cells and neutrality
//! A hypothesis × evidence pair with no stored cell is **Neutral** (weight 0):
//! absent and explicit `Consistency::Neutral` are indistinguishable in every
//! score (pinned by test). Cells are stored sparsely — the matrix starts with
//! none and never materialises the full grid.
//!
//! # SACH split (B5.2.3)
//! [`AchMatrix::split`] decomposes one coarse hypothesis into `≥ 2` finer
//! sub-hypotheses: the original id and *all* of its cells are removed (its
//! evidential record is deliberately dropped — finer hypotheses must be
//! re-scored from scratch, so no coarse-grain cell can silently leak into a
//! finer claim), and the replacements are appended in the given order with no
//! cells. Refused if the id is unknown ([`AchError::Unknown`]),
//! `into.len() < 2` ([`AchError::BadInput`]), or any replacement id collides
//! with a surviving hypothesis, with the id being split, or duplicates within
//! `into` ([`AchError::DupId`]).
//!
//! # Validation order
//! [`AchMatrix::new`] validates in §8 listing order: empty `hypotheses`, empty
//! `evidence`, duplicate hypothesis ids, duplicate evidence ids, then the
//! `diagnosticity` range. Ids and texts are *not* checked for emptiness (§8
//! pins only the two vector-emptiness errors); pass non-empty text from
//! callers.
//!
//! # Determinism
//! Every consumer of iteration order uses insertion order: cells keep their
//! (evidence, hypothesis) key order with upserts replacing in place;
//! [`AchMatrix::ranking`] sorts `net` descending then hypothesis id ascending,
//! a total order over unique ids. Repeated runs on equal inputs produce equal
//! outputs (pinned).
//!
//! # Serde conventions
//! All wire structs derive `Serialize + Deserialize` with default variant
//! naming (`"StronglyConsistent"` …, pinned by test). [`AchError`] is
//! `Serialize`-only (it carries `&'static str`; repo precedent) — `BadInput`
//! serialises as `{"BadInput":"hypotheses"}`. Serde is a plain wire decoder
//! and does not validate; call [`AchMatrix::new`] after ingesting untrusted
//! JSON.
//!
//! # Integration
//! Not wired into `lib.rs` yet — the parent integrates. Intended consumers:
//! the structured-analysis op surface (build matrix → score → rank → record
//! the refutation-ranked outcome) and the SACH decomposition path. Read-only
//! accessors ([`AchMatrix::hypotheses`], [`AchMatrix::evidence`],
//! [`AchMatrix::cells`], [`AchMatrix::cell`]) exist so consumers can render or
//! audit the matrix without reaching into private fields; they are additive to
//! §8 and change no semantics.


use std::fmt;

use serde::{Deserialize, Serialize};

/// Consistency of one evidence item with one hypothesis (B5.2.1).
///
/// Wire form is the variant name (`"StronglyConsistent"` …
/// `"StronglyInconsistent"`). [`Consistency::weight`] returns the pinned
/// signed weight `2, 1, 0, −1, −2` in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Consistency {
    /// Directly supports the hypothesis (weight `+2`).
    StronglyConsistent,
    /// Somewhat supports the hypothesis (weight `+1`).
    Consistent,
    /// Neither supports nor refutes (weight `0`); also the implicit value of
    /// a missing cell.
    Neutral,
    /// Somewhat refutes the hypothesis (weight `−1`).
    Inconsistent,
    /// Directly refutes the hypothesis (weight `−2`).
    StronglyInconsistent,
}

impl Consistency {
    /// Pinned signed weight: `2, 1, 0, −1, −2` (§8, declaration order).
    pub fn weight(&self) -> i8 {
        match self {
            Consistency::StronglyConsistent => 2,
            Consistency::Consistent => 1,
            Consistency::Neutral => 0,
            Consistency::Inconsistent => -1,
            Consistency::StronglyInconsistent => -2,
        }
    }
}

/// One competing hypothesis under test (its rationale lives in `text`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Stable, caller-chosen id, unique per side of the matrix.
    pub id: String,
    /// What the hypothesis claims.
    pub text: String,
}

/// One item of evidence scored against every hypothesis (B5.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Stable, caller-chosen id, unique per side of the matrix.
    pub id: String,
    /// What the evidence is.
    pub text: String,
    /// How sharply the item distinguishes between hypotheses: `1..=5`
    /// (out-of-range is [`AchError::BadInput`] on [`AchMatrix::new`]).
    pub diagnosticity: u8,
}

/// Refutation-ranked score of one hypothesis (B5.2.2).
///
/// `consistent` sums `weight × diagnosticity` over supporting cells,
/// `inconsistent` sums `|weight| × diagnosticity` over refuting cells, and
/// `net = consistent − 2 × inconsistent` (disconfirmation double-weighted —
/// see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypothesisScore {
    /// The hypothesis id this score belongs to.
    pub hyp: String,
    /// Σ `weight × diagnosticity` over cells with positive weight.
    pub consistent: i32,
    /// Σ `|weight| × diagnosticity` over cells with negative weight.
    pub inconsistent: i32,
    /// `consistent − 2 × inconsistent`.
    pub net: i32,
}

/// The ACH matrix: hypotheses × evidence, with sparse consistency cells
/// keyed `(evidence_id, hypothesis_id)` (upsert semantics).
///
/// Construct with [`AchMatrix::new`], fill cells with
/// [`AchMatrix::set_cell`], read scores with [`AchMatrix::score`] /
/// [`AchMatrix::ranking`], and decompose a coarse hypothesis with
/// [`AchMatrix::split`].
#[derive(Debug, Clone, PartialEq)]
pub struct AchMatrix {
    hypotheses: Vec<Hypothesis>,
    evidence: Vec<EvidenceItem>,
    /// Sparse cells in insertion order; upserts replace in place.
    /// Key is `(evidence_id, hypothesis_id)`.
    cells: Vec<(String, String, Consistency)>,
}

impl AchMatrix {
    /// Build an empty matrix over the given hypotheses and evidence.
    ///
    /// Validation, in §8 listing order:
    /// 1. empty `hypotheses` ⇒ [`AchError::BadInput`]`("hypotheses")`;
    /// 2. empty `evidence` ⇒ [`AchError::BadInput`]`("evidence")`;
    /// 3. duplicate hypothesis ids ⇒ [`AchError::DupId`];
    /// 4. duplicate evidence ids ⇒ [`AchError::DupId`];
    /// 5. any `diagnosticity` outside `1..=5` ⇒
    ///    [`AchError::BadInput`]`("diagnosticity")`.
    pub fn new(
        hypotheses: Vec<Hypothesis>,
        evidence: Vec<EvidenceItem>,
    ) -> Result<AchMatrix, AchError> {
        if hypotheses.is_empty() {
            return Err(AchError::BadInput("hypotheses"));
        }
        if evidence.is_empty() {
            return Err(AchError::BadInput("evidence"));
        }
        for (i, h) in hypotheses.iter().enumerate() {
            if hypotheses[..i].iter().any(|prev| prev.id == h.id) {
                return Err(AchError::DupId);
            }
        }
        for (i, e) in evidence.iter().enumerate() {
            if evidence[..i].iter().any(|prev| prev.id == e.id) {
                return Err(AchError::DupId);
            }
        }
        if evidence
            .iter()
            .any(|e| !(1..=5).contains(&e.diagnosticity))
        {
            return Err(AchError::BadInput("diagnosticity"));
        }
        Ok(AchMatrix {
            hypotheses,
            evidence,
            cells: Vec::new(),
        })
    }

    /// The hypotheses, in insertion order (read-only; additive to §8).
    pub fn hypotheses(&self) -> &[Hypothesis] {
        &self.hypotheses
    }

    /// The evidence, in insertion order (read-only; additive to §8).
    pub fn evidence(&self) -> &[EvidenceItem] {
        &self.evidence
    }

    /// The sparse cells, `(evidence_id, hypothesis_id, consistency)` in
    /// insertion order (read-only; additive to §8).
    pub fn cells(&self) -> &[(String, String, Consistency)] {
        &self.cells
    }

    /// Look up one hypothesis by id (read-only; additive to §8).
    pub fn hypothesis(&self, id: &str) -> Option<&Hypothesis> {
        self.hypotheses.iter().find(|h| h.id == id)
    }

    /// Look up one cell by key; `None` means the pair is **Neutral**
    /// (missing) rather than an error (read-only; additive to §8).
    pub fn cell(&self, evidence_id: &str, hypothesis_id: &str) -> Option<Consistency> {
        self.cell_of(evidence_id, hypothesis_id)
    }

    /// Private sparse-cell lookup shared by [`AchMatrix::cell`] and
    /// [`AchMatrix::score`].
    fn cell_of(&self, evidence_id: &str, hypothesis_id: &str) -> Option<Consistency> {
        self.cells
            .iter()
            .find(|(e, h, _)| e.as_str() == evidence_id && h.as_str() == hypothesis_id)
            .map(|(_, _, c)| *c)
    }

    /// Set (upsert) the consistency of `evidence_id` × `hypothesis_id`.
    ///
    /// Unknown ids on either side ⇒ [`AchError::Unknown`] (evidence checked
    /// first, then hypothesis; both unknown is the same error). An existing
    /// cell is replaced **in place** — the key order of [`AchMatrix::cells`]
    /// is stable across upserts; a new key is appended.
    pub fn set_cell(
        &mut self,
        evidence_id: &str,
        hypothesis_id: &str,
        c: Consistency,
    ) -> Result<(), AchError> {
        if !self.evidence.iter().any(|e| e.id == evidence_id) {
            return Err(AchError::Unknown);
        }
        if !self.hypotheses.iter().any(|h| h.id == hypothesis_id) {
            return Err(AchError::Unknown);
        }
        if let Some(cell) = self
            .cells
            .iter_mut()
            .find(|(e, h, _)| e.as_str() == evidence_id && h.as_str() == hypothesis_id)
        {
            cell.2 = c;
        } else {
            self.cells
                .push((evidence_id.to_string(), hypothesis_id.to_string(), c));
        }
        Ok(())
    }

    /// Score one hypothesis (B5.2.2).
    ///
    /// `consistent` = Σ `weight × diagnosticity` over positive-weight cells;
    /// `inconsistent` = Σ `|weight| × diagnosticity` over negative-weight
    /// cells; `net = consistent − 2 × inconsistent` (disconfirmation
    /// double-weighted). Missing cells count Neutral. Unknown hypothesis id ⇒
    /// [`AchError::Unknown`].
    pub fn score(&self, hyp: &str) -> Result<HypothesisScore, AchError> {
        if self.hypothesis(hyp).is_none() {
            return Err(AchError::Unknown);
        }
        let mut consistent: i32 = 0;
        let mut inconsistent: i32 = 0;
        for ev in &self.evidence {
            let weight = match self.cell_of(&ev.id, hyp) {
                Some(c) => c.weight() as i32,
                None => 0, // missing cell ⇒ Neutral
            };
            let diagnosticity = ev.diagnosticity as i32;
            if weight > 0 {
                consistent += weight * diagnosticity;
            } else if weight < 0 {
                inconsistent += -weight * diagnosticity;
            }
        }
        Ok(HypothesisScore {
            hyp: hyp.to_string(),
            consistent,
            inconsistent,
            net: consistent - 2 * inconsistent,
        })
    }

    /// All hypotheses scored and ranked: `net` descending, then hypothesis id
    /// ascending (total order over unique ids).
    pub fn ranking(&self) -> Vec<HypothesisScore> {
        let mut ranked: Vec<HypothesisScore> = self
            .hypotheses
            .iter()
            .map(|h| {
                self.score(&h.id)
                    .expect("every hypothesis in the matrix is scorable")
            })
            .collect();
        ranked.sort_by(|a, b| b.net.cmp(&a.net).then_with(|| a.hyp.cmp(&b.hyp)));
        ranked
    }

    /// SACH split (B5.2.3): decompose `hyp_id` into `into` = `(id, text)`
    /// replacement hypotheses.
    ///
    /// * unknown `hyp_id` ⇒ [`AchError::Unknown`];
    /// * `into.len() < 2` ⇒ [`AchError::BadInput`]`("into")`;
    /// * any replacement id already in the matrix, equal to `hyp_id`, or
    ///   duplicated within `into` ⇒ [`AchError::DupId`].
    ///
    /// On success the original hypothesis **and all of its cells** are
    /// removed (the finer hypotheses start unscored), and the replacements are
    /// appended in the given order with no cells. Refusals leave the matrix
    /// untouched. Replacement texts are not checked for emptiness (mirrors
    /// [`AchMatrix::new`]).
    pub fn split(&mut self, hyp_id: &str, into: &[(String, String)]) -> Result<(), AchError> {
        if self.hypothesis(hyp_id).is_none() {
            return Err(AchError::Unknown);
        }
        if into.len() < 2 {
            return Err(AchError::BadInput("into"));
        }
        for (id, _) in into {
            // `hyp_id` is still stored here, so reusing its own id is also a
            // collision: a replacement must not alias the dropped record.
            if id.as_str() == hyp_id || self.hypothesis(id).is_some() {
                return Err(AchError::DupId);
            }
        }
        for (i, (id, _)) in into.iter().enumerate() {
            if into[..i].iter().any(|(prev, _)| prev == id) {
                return Err(AchError::DupId);
            }
        }
        self.hypotheses.retain(|h| h.id != hyp_id);
        self.cells.retain(|(_, h, _)| h != hyp_id);
        for (id, text) in into {
            self.hypotheses.push(Hypothesis {
                id: id.clone(),
                text: text.clone(),
            });
        }
        Ok(())
    }
}

/// Errors from ACH construction, scoring, and splitting.
///
/// `Serialize`-only (carries `&'static str`; repo precedent): `BadInput`
/// serialises as `{"BadInput":"…"}`, unit variants as `"DupId"` / `"Unknown"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AchError {
    /// A malformed argument: the named field/vector is empty or (for
    /// `"diagnosticity"` / `"into"`) out of range/short.
    BadInput(&'static str),
    /// A duplicate id on one side of the matrix (construction) or in a SACH
    /// split's replacements.
    DupId,
    /// An id that is not present in the matrix.
    Unknown,
}

impl fmt::Display for AchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AchError::BadInput(name) => write!(f, "invalid ACH input: {name}"),
            AchError::DupId => f.write_str("duplicate ACH id"),
            AchError::Unknown => f.write_str("unknown ACH id"),
        }
    }
}

impl std::error::Error for AchError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned worked example: 3 hypotheses × 4 evidence.
    ///
    /// Cell grid (`+2/+1/0/−1/−2`; `·` = missing ⇒ Neutral), evidence
    /// diagnosticity in the header row:
    ///
    /// ```text
    ///            e1(d4)  e2(d3)  e3(d5)  e4(d2)
    /// h1           +2      +2      −1      +1
    /// h2           +2      −1      −1      −2
    /// h3           −1       0      +2       ·
    /// ```
    ///
    /// Hand-computed scores (consistent, inconsistent, net):
    ///
    /// * h1: (2×4 + 2×3 + 1×2, |−1|×5) = (16, 5, 16 − 10 = **6**)
    /// * h2: (2×4, 1×3 + 1×5 + 2×2)   = (8, 12, 8 − 24 = **−16**)
    /// * h3: (2×5, |−1|×4)            = (10, 4, 10 − 8 = **2**)
    fn worked_example() -> AchMatrix {
        let mut m = AchMatrix::new(
            vec![
                Hypothesis {
                    id: "h1".into(),
                    text: "insider exfiltration".into(),
                },
                Hypothesis {
                    id: "h2".into(),
                    text: "external compromise".into(),
                },
                Hypothesis {
                    id: "h3".into(),
                    text: "benign transfer (false alarm)".into(),
                },
            ],
            vec![
                EvidenceItem {
                    id: "e1".into(),
                    text: "large outbound transfer at 03:12".into(),
                    diagnosticity: 4,
                },
                EvidenceItem {
                    id: "e2".into(),
                    text: "no brute force in auth logs; valid credentials".into(),
                    diagnosticity: 3,
                },
                EvidenceItem {
                    id: "e3".into(),
                    text: "destination resolves to a known CDN range".into(),
                    diagnosticity: 5,
                },
                EvidenceItem {
                    id: "e4".into(),
                    text: "no interactive session in endpoint telemetry".into(),
                    diagnosticity: 2,
                },
            ],
        )
        .unwrap();
        m.set_cell("e1", "h1", Consistency::StronglyConsistent).unwrap();
        m.set_cell("e1", "h2", Consistency::StronglyConsistent).unwrap();
        m.set_cell("e1", "h3", Consistency::Inconsistent).unwrap();
        m.set_cell("e2", "h1", Consistency::StronglyConsistent).unwrap();
        m.set_cell("e2", "h2", Consistency::Inconsistent).unwrap();
        m.set_cell("e2", "h3", Consistency::Neutral).unwrap();
        m.set_cell("e3", "h1", Consistency::Inconsistent).unwrap();
        m.set_cell("e3", "h2", Consistency::Inconsistent).unwrap();
        m.set_cell("e3", "h3", Consistency::StronglyConsistent).unwrap();
        m.set_cell("e4", "h1", Consistency::Consistent).unwrap();
        m.set_cell("e4", "h2", Consistency::StronglyInconsistent).unwrap();
        // (e4, h3) deliberately left missing — a missing cell is Neutral.
        m
    }

    #[test]
    fn worked_example_scores_pinned() {
        let m = worked_example();
        let h1 = m.score("h1").unwrap();
        assert_eq!((h1.consistent, h1.inconsistent, h1.net), (16, 5, 6));
        let h2 = m.score("h2").unwrap();
        assert_eq!((h2.consistent, h2.inconsistent, h2.net), (8, 12, -16));
        let h3 = m.score("h3").unwrap();
        assert_eq!((h3.consistent, h3.inconsistent, h3.net), (10, 4, 2));
        assert_eq!(h1.hyp, "h1");
    }

    #[test]
    fn ranking_worked_example_pinned() {
        let r = worked_example().ranking();
        assert_eq!(
            r.iter().map(|s| s.hyp.as_str()).collect::<Vec<_>>(),
            vec!["h1", "h3", "h2"]
        );
        assert_eq!(r.iter().map(|s| s.net).collect::<Vec<_>>(), vec![6, 2, -16]);
    }

    #[test]
    fn ranking_ties_break_by_hypothesis_id_ascending() {
        let mut m = AchMatrix::new(
            vec![
                Hypothesis {
                    id: "hb".into(),
                    text: "b".into(),
                },
                Hypothesis {
                    id: "ha".into(),
                    text: "a".into(),
                },
            ],
            vec![EvidenceItem {
                id: "e1".into(),
                text: "x".into(),
                diagnosticity: 3,
            }],
        )
        .unwrap();
        m.set_cell("e1", "ha", Consistency::Consistent).unwrap();
        m.set_cell("e1", "hb", Consistency::Consistent).unwrap();
        let r = m.ranking();
        assert_eq!(r[0].net, r[1].net, "fixture must actually tie");
        assert_eq!(r[0].net, 3);
        assert_eq!(
            r.iter().map(|s| s.hyp.as_str()).collect::<Vec<_>>(),
            vec!["ha", "hb"]
        );
    }

    #[test]
    fn set_cell_upserts_in_place() {
        let mut m = worked_example();
        let keys_before = m.cells().len();
        m.set_cell("e1", "h3", Consistency::StronglyInconsistent)
            .unwrap();
        assert_eq!(m.cells().len(), keys_before, "upsert must not add a key");
        assert_eq!(m.cell("e1", "h3"), Some(Consistency::StronglyInconsistent));
        // h3: e1 flips −1×4 → −2×4; consistent stays 10.
        let h3 = m.score("h3").unwrap();
        assert_eq!((h3.consistent, h3.inconsistent, h3.net), (10, 8, -6));
        // position preserved: (e1,h3) still the third inserted key
        let idx = m
            .cells()
            .iter()
            .position(|(e, h, _)| e == "e1" && h == "h3")
            .unwrap();
        assert_eq!(idx, 2);
    }

    #[test]
    fn neutral_or_missing_cells_contribute_zero() {
        let mut m = AchMatrix::new(
            vec![Hypothesis {
                id: "h".into(),
                text: "h".into(),
            }],
            vec![
                EvidenceItem {
                    id: "e1".into(),
                    text: "a".into(),
                    diagnosticity: 5,
                },
                EvidenceItem {
                    id: "e2".into(),
                    text: "b".into(),
                    diagnosticity: 4,
                },
            ],
        )
        .unwrap();
        let missing = m.score("h").unwrap();
        assert_eq!(
            (missing.consistent, missing.inconsistent, missing.net),
            (0, 0, 0)
        );
        m.set_cell("e1", "h", Consistency::Neutral).unwrap();
        let explicit = m.score("h").unwrap();
        assert_eq!(explicit, missing, "absent and explicit Neutral must agree");
    }

    #[test]
    fn disconfirmation_is_double_weighted() {
        fn one(d: u8, c: Consistency) -> HypothesisScore {
            let mut m = AchMatrix::new(
                vec![Hypothesis {
                    id: "h".into(),
                    text: "h".into(),
                }],
                vec![EvidenceItem {
                    id: "e".into(),
                    text: "e".into(),
                    diagnosticity: d,
                }],
            )
            .unwrap();
            m.set_cell("e", "h", c).unwrap();
            m.score("h").unwrap()
        }
        // net = weight × d for positive cells; net = −2 × |weight| × d for
        // negative cells. d = 5 pins: +10 / −10 / −20 boundaries.
        assert_eq!(one(5, Consistency::StronglyConsistent).net, 10);
        assert_eq!(one(5, Consistency::Consistent).net, 5);
        assert_eq!(one(5, Consistency::Inconsistent).net, -10);
        assert_eq!(one(5, Consistency::StronglyInconsistent).net, -20);
        // Same raw magnitude, opposite direction: the refutation side is
        // penalised exactly twice on top of its own weight.
        let sc = one(5, Consistency::StronglyConsistent);
        let si = one(5, Consistency::StronglyInconsistent);
        assert_eq!((sc.consistent, sc.inconsistent), (10, 0));
        assert_eq!((si.consistent, si.inconsistent), (0, 10));
        assert_eq!(si.net, -2 * si.inconsistent);
        assert_eq!(si.net, -2 * sc.net);
        // Balanced raw magnitudes net negative — the anti-confirmation slant.
        let mut both = AchMatrix::new(
            vec![Hypothesis {
                id: "h".into(),
                text: "h".into(),
            }],
            vec![
                EvidenceItem {
                    id: "for".into(),
                    text: "supports".into(),
                    diagnosticity: 5,
                },
                EvidenceItem {
                    id: "against".into(),
                    text: "refutes".into(),
                    diagnosticity: 5,
                },
            ],
        )
        .unwrap();
        both.set_cell("for", "h", Consistency::StronglyConsistent).unwrap();
        both.set_cell("against", "h", Consistency::StronglyInconsistent)
            .unwrap();
        let s = both.score("h").unwrap();
        assert_eq!((s.consistent, s.inconsistent, s.net), (10, 10, -10));
    }

    #[test]
    fn consistency_weights_pinned() {
        assert_eq!(Consistency::StronglyConsistent.weight(), 2);
        assert_eq!(Consistency::Consistent.weight(), 1);
        assert_eq!(Consistency::Neutral.weight(), 0);
        assert_eq!(Consistency::Inconsistent.weight(), -1);
        assert_eq!(Consistency::StronglyInconsistent.weight(), -2);
    }

    #[test]
    fn new_validation_errors() {
        let h = || Hypothesis {
            id: "h".into(),
            text: "h".into(),
        };
        let e = |d: u8| EvidenceItem {
            id: "e".into(),
            text: "e".into(),
            diagnosticity: d,
        };
        assert_eq!(
            AchMatrix::new(vec![], vec![e(3)]).unwrap_err(),
            AchError::BadInput("hypotheses")
        );
        assert_eq!(
            AchMatrix::new(vec![h()], vec![]).unwrap_err(),
            AchError::BadInput("evidence")
        );
        assert_eq!(
            AchMatrix::new(vec![h(), h()], vec![e(3)]).unwrap_err(),
            AchError::DupId
        );
        assert_eq!(
            AchMatrix::new(vec![h()], vec![e(3), e(3)]).unwrap_err(),
            AchError::DupId
        );
        assert_eq!(
            AchMatrix::new(vec![h()], vec![e(0)]).unwrap_err(),
            AchError::BadInput("diagnosticity")
        );
        assert_eq!(
            AchMatrix::new(vec![h()], vec![e(6)]).unwrap_err(),
            AchError::BadInput("diagnosticity")
        );
        // boundaries accepted
        assert!(AchMatrix::new(vec![h()], vec![e(1)]).is_ok());
        assert!(AchMatrix::new(vec![h()], vec![e(5)]).is_ok());
    }

    #[test]
    fn set_cell_unknown_ids() {
        let mut m = worked_example();
        let before = m.cells().len();
        assert_eq!(
            m.set_cell("nope", "h1", Consistency::Consistent)
                .unwrap_err(),
            AchError::Unknown
        );
        assert_eq!(
            m.set_cell("e1", "nope", Consistency::Consistent)
                .unwrap_err(),
            AchError::Unknown
        );
        assert_eq!(
            m.set_cell("nope", "nope", Consistency::Consistent)
                .unwrap_err(),
            AchError::Unknown
        );
        assert_eq!(m.cells().len(), before, "refused writes must not touch cells");
    }

    #[test]
    fn score_unknown_hypothesis() {
        assert_eq!(
            worked_example().score("nope").unwrap_err(),
            AchError::Unknown
        );
        assert_eq!(worked_example().cell("e1", "nope"), None);
    }

    #[test]
    fn split_drops_original_and_cells_and_appends_replacements() {
        let mut m = worked_example();
        m.split(
            "h2",
            &[
                ("h2a".into(), "compromise via stolen session token".into()),
                ("h2b".into(), "compromise via supply-chain implant".into()),
            ],
        )
        .unwrap();
        assert!(m.hypothesis("h2").is_none(), "original hypothesis removed");
        assert!(
            m.cells().iter().all(|(_, h, _)| h != "h2"),
            "all original cells dropped"
        );
        assert_eq!(m.cells().len(), 11 - 4, "h2 had four cells");
        assert_eq!(m.hypotheses().len(), 4);
        // replacements appended in given order, no cells yet
        let ids: Vec<&str> = m.hypotheses().iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, vec!["h1", "h3", "h2a", "h2b"]);
        let fresh = m.score("h2a").unwrap();
        assert_eq!((fresh.consistent, fresh.inconsistent, fresh.net), (0, 0, 0));
        assert_eq!(m.cell("e1", "h2a"), None);
        // survivors' scores unchanged
        assert_eq!(m.score("h1").unwrap().net, 6);
        assert_eq!(m.score("h3").unwrap().net, 2);
        // ranking now ranks the unscored replacements last, id ascending
        let r = m.ranking();
        assert_eq!(
            r.iter().map(|s| s.hyp.as_str()).collect::<Vec<_>>(),
            vec!["h1", "h3", "h2a", "h2b"]
        );
    }

    #[test]
    fn split_refusals_leave_matrix_untouched() {
        let mut m = worked_example();
        let two = [
            ("x".to_string(), "x".to_string()),
            ("y".to_string(), "y".to_string()),
        ];
        assert_eq!(m.split("nope", &two).unwrap_err(), AchError::Unknown);
        assert_eq!(
            m.split("h2", &[]).unwrap_err(),
            AchError::BadInput("into")
        );
        assert_eq!(
            m.split("h2", &[("only".into(), "only".into())]).unwrap_err(),
            AchError::BadInput("into")
        );
        // collision with a surviving hypothesis
        assert_eq!(
            m.split(
                "h2",
                &[("h1".into(), "a".into()), ("h2a".into(), "a".into())]
            )
            .unwrap_err(),
            AchError::DupId
        );
        // collision with the id being split
        assert_eq!(
            m.split(
                "h2",
                &[("h2".into(), "a".into()), ("h2a".into(), "a".into())]
            )
            .unwrap_err(),
            AchError::DupId
        );
        // duplicate within `into`
        assert_eq!(
            m.split(
                "h2",
                &[("h2a".into(), "a".into()), ("h2a".into(), "b".into())]
            )
            .unwrap_err(),
            AchError::DupId
        );
        assert_eq!(m.hypotheses().len(), 3, "refusals are atomic");
        assert_eq!(m.cells().len(), 11);
    }

    #[test]
    fn replacement_hypotheses_accept_new_cells() {
        let mut m = worked_example();
        m.split(
            "h2",
            &[
                ("h2a".into(), "a".into()),
                ("h2b".into(), "b".into()),
            ],
        )
        .unwrap();
        m.set_cell("e1", "h2a", Consistency::Consistent).unwrap();
        let s = m.score("h2a").unwrap();
        assert_eq!((s.consistent, s.inconsistent, s.net), (4, 0, 4));
    }

    #[test]
    fn accessors_preserve_input_order() {
        let m = worked_example();
        let hids: Vec<&str> = m.hypotheses().iter().map(|h| h.id.as_str()).collect();
        assert_eq!(hids, vec!["h1", "h2", "h3"]);
        let eids: Vec<&str> = m.evidence().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(eids, vec!["e1", "e2", "e3", "e4"]);
        assert_eq!(m.hypothesis("h2").map(|h| h.id.as_str()), Some("h2"));
        assert_eq!(m.hypothesis("nope"), None);
    }

    #[test]
    fn determinism_repeated_construction() {
        let a = worked_example();
        let b = worked_example();
        assert_eq!(a.cells(), b.cells());
        assert_eq!(a.ranking(), b.ranking());
        let mut c = worked_example();
        c.split("h2", &[("h2a".into(), "a".into()), ("h2b".into(), "b".into())])
            .unwrap();
        let mut d = worked_example();
        d.split("h2", &[("h2a".into(), "a".into()), ("h2b".into(), "b".into())])
            .unwrap();
        assert_eq!(c.hypotheses(), d.hypotheses());
        assert_eq!(c.cells(), d.cells());
        assert_eq!(c.ranking(), d.ranking());
    }

    #[test]
    fn serde_wire_pins() {
        assert_eq!(
            serde_json::to_string(&Consistency::StronglyConsistent).unwrap(),
            "\"StronglyConsistent\""
        );
        assert_eq!(
            serde_json::to_string(&Consistency::Neutral).unwrap(),
            "\"Neutral\""
        );
        assert_eq!(
            serde_json::to_string(&Consistency::StronglyInconsistent).unwrap(),
            "\"StronglyInconsistent\""
        );
        let h = Hypothesis {
            id: "h1".into(),
            text: "t".into(),
        };
        let back: Hypothesis = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(back, h);
        let e = EvidenceItem {
            id: "e1".into(),
            text: "x".into(),
            diagnosticity: 3,
        };
        let back: EvidenceItem = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        let s = HypothesisScore {
            hyp: "h1".into(),
            consistent: 16,
            inconsistent: 5,
            net: 6,
        };
        let back: HypothesisScore =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        // AchError is Serialize-only (repo precedent)
        assert_eq!(
            serde_json::to_string(&AchError::BadInput("hypotheses")).unwrap(),
            "{\"BadInput\":\"hypotheses\"}"
        );
        assert_eq!(serde_json::to_string(&AchError::DupId).unwrap(), "\"DupId\"");
        assert_eq!(
            serde_json::to_string(&AchError::Unknown).unwrap(),
            "\"Unknown\""
        );
    }
}
