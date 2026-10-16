//! Source registry with append-only reliability history (task A3.1.1 · E6).
//!
//! Collection sources (domains, accounts, feeds, …) are first-class records
//! whose *reliability* is a maintained, **append-only history** of
//! assessments — never a single mutable label. Grades follow the
//! NATO/Admiralty source-reliability scale `A`–`F` (`A` = completely
//! reliable … `F` = cannot be judged), the same scale already used by the
//! `tallow.sourcegrade` stdlib module (which derives a *static, registry
//! based* grade; this module maintains the *live* history on top).
//!
//! # Source vs item separation (the point of this module)
//!
//! Admiralty doctrine assesses two axes **in isolation**:
//!
//! * SOURCE reliability — `A`–`F`, a property of the source's capability and
//!   track record ([`ReliabilityGrade`]).
//! * ITEM credibility — `1`–`6`, a property of one collected item, based on
//!   its own corroboration ([`ItemCredibility`]).
//!
//! The separation exists so that a trusted source cannot whitewash a doubtful
//! item, and a dubious source cannot sink a well-corroborated one. It is
//! enforced *structurally* here:
//!
//! * [`SourceRegistry`] owns sources and is the only way to append to a
//!   reliability history ([`SourceRegistry::record_assessment`] /
//!   [`SourceRegistry::assess_source`] — SOURCE-side entry point).
//! * [`ItemAssessmentLog`] owns item assessments. Its entry point
//!   [`ItemAssessmentLog::assess_item`] takes `&SourceRegistry` — a shared,
//!   read-only borrow — to snapshot the source's current grade. It
//!   structurally *cannot* rewrite source history (the borrow checker
//!   enforces it), and the snapshot it records never feeds back into the
//!   registry.
//!
//! Promotion guards (“no derived claim promoted above its source grade”) and
//! automatic re-grading on corroboration are later checklist items
//! (A3.1.2 / A3.1.3) and are intentionally **not** implemented here.
//!
//! # Append-only rules
//!
//! * Assessments are only ever appended; there is no API to edit or remove
//!   one.
//! * [`SourceRegistry::record_assessment`] rejects a timestamp older than the
//!   last entry ([`RegistryError::AssessmentOutOfOrder`]); equal timestamps
//!   are allowed (tie order = insertion order).
//! * [`SourceRegistry::upsert`] may *extend* a stored history but never
//!   shrink, rewrite, or reorder it ([`RegistryError::HistoryDiverged`]).
//!
//! # Example
//!
//! ```
//! use tallow::source_registry::{
//!     Assessment, ItemAssessmentLog, ItemCredibility, ReliabilityGrade, SourceKind, SourceRecord,
//!     SourceRegistry,
//! };
//!
//! let mut reg = SourceRegistry::new();
//! reg.upsert(SourceRecord::new("example.com", SourceKind::Domain, 0)).unwrap();
//! reg.assess_source("example.com", Assessment::new(1_000, ReliabilityGrade::B, "ok so far", "analyst"))
//!     .unwrap();
//! assert_eq!(reg.current_grade("example.com").unwrap(), ReliabilityGrade::B);
//!
//! // Item credibility is assessed independently, snapshotting the source axis.
//! let mut items = ItemAssessmentLog::new();
//! let entry = items
//!     .assess_item(&reg, "report-1", "example.com", ItemCredibility::Doubtful, "single anonymous string", "analyst", 1_100)
//!     .unwrap();
//! assert_eq!(entry.source_grade, Some(ReliabilityGrade::B));
//! ```

use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;

// ── Grades ──────────────────────────────────────────────────────────────────

/// NATO/Admiralty **source reliability** grade, `A`–`F`.
///
/// * `A` — completely reliable
/// * `B` — usually reliable
/// * `C` — fairly reliable
/// * `D` — not usually reliable
/// * `E` — unreliable
/// * `F` — cannot be judged
///
/// Derived `Ord` is **best-first**: `A < B < … < F` (the strongest grade is
/// the smallest), so “keep the strongest grade” is `min()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReliabilityGrade {
    /// Completely reliable.
    A,
    /// Usually reliable.
    B,
    /// Fairly reliable.
    C,
    /// Not usually reliable.
    D,
    /// Unreliable.
    E,
    /// Cannot be judged.
    F,
}

impl ReliabilityGrade {
    /// The bare letter (`"A"`–`"F"`); also the serde form.
    pub fn as_letter(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::E => "E",
            Self::F => "F",
        }
    }

    /// Rank `1`–`6` (`A` = 1 … `F` = 6).
    pub fn rank(&self) -> u8 {
        match self {
            Self::A => 1,
            Self::B => 2,
            Self::C => 3,
            Self::D => 4,
            Self::E => 5,
            Self::F => 6,
        }
    }

    /// NATO wording of the grade (for caveated output later).
    pub fn word(&self) -> &'static str {
        match self {
            Self::A => "completely reliable",
            Self::B => "usually reliable",
            Self::C => "fairly reliable",
            Self::D => "not usually reliable",
            Self::E => "unreliable",
            Self::F => "cannot be judged",
        }
    }

    /// Parse a letter `A`–`F` (case-insensitive, surrounding whitespace
    /// trimmed). Anything else is [`RegistryError::UnknownGrade`].
    pub fn from_letter(raw: &str) -> Result<Self, RegistryError> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "B" => Ok(Self::B),
            "C" => Ok(Self::C),
            "D" => Ok(Self::D),
            "E" => Ok(Self::E),
            "F" => Ok(Self::F),
            other => Err(RegistryError::UnknownGrade {
                raw: other.to_string(),
            }),
        }
    }

    /// Parse a rank `1`–`6` (`1` → `A` … `6` → `F`).
    pub fn from_rank(rank: u8) -> Result<Self, RegistryError> {
        match rank {
            1 => Ok(Self::A),
            2 => Ok(Self::B),
            3 => Ok(Self::C),
            4 => Ok(Self::D),
            5 => Ok(Self::E),
            6 => Ok(Self::F),
            other => Err(RegistryError::UnknownGrade {
                raw: other.to_string(),
            }),
        }
    }
}

impl std::str::FromStr for ReliabilityGrade {
    type Err = RegistryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_letter(s)
    }
}

/// Admiralty **item credibility** digit, `1`–`6` — the *second* axis,
/// assessed per collected item, never per source.
///
/// * `1` — confirmed by other independent sources
/// * `2` — probably true
/// * `3` — possibly true
/// * `4` — doubtful
/// * `5` — improbable
/// * `6` — cannot be judged
///
/// Derived `Ord` is best-first (`1 < … < 6`, declared order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ItemCredibility {
    /// Confirmed by other independent sources.
    Confirmed,
    /// Probably true.
    ProbablyTrue,
    /// Possibly true.
    PossiblyTrue,
    /// Doubtful.
    Doubtful,
    /// Improbable.
    Improbable,
    /// Cannot be judged.
    CannotBeJudged,
}

impl ItemCredibility {
    /// The Admiralty digit, `1`–`6`.
    pub fn as_digit(&self) -> u8 {
        match self {
            Self::Confirmed => 1,
            Self::ProbablyTrue => 2,
            Self::PossiblyTrue => 3,
            Self::Doubtful => 4,
            Self::Improbable => 5,
            Self::CannotBeJudged => 6,
        }
    }

    /// NATO wording of the credibility digit.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed by independent sources",
            Self::ProbablyTrue => "probably true",
            Self::PossiblyTrue => "possibly true",
            Self::Doubtful => "doubtful",
            Self::Improbable => "improbable",
            Self::CannotBeJudged => "cannot be judged",
        }
    }

    /// Parse a digit `1`–`6`. Anything else is
    /// [`RegistryError::UnknownCredibility`].
    pub fn from_digit(digit: u8) -> Result<Self, RegistryError> {
        match digit {
            1 => Ok(Self::Confirmed),
            2 => Ok(Self::ProbablyTrue),
            3 => Ok(Self::PossiblyTrue),
            4 => Ok(Self::Doubtful),
            5 => Ok(Self::Improbable),
            6 => Ok(Self::CannotBeJudged),
            other => Err(RegistryError::UnknownCredibility {
                raw: other.to_string(),
            }),
        }
    }
}

// ── Records ─────────────────────────────────────────────────────────────────

/// One reliability assessment of a SOURCE at a point in time.
///
/// An assessment is immutable once appended: histories are append-only and
/// there is no remove/rewrite API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    /// Epoch milliseconds when the assessment was made.
    pub ts_ms: i64,
    /// The graded reliability of the source.
    pub grade: ReliabilityGrade,
    /// Free-text rationale (what was observed, why this grade).
    pub note: String,
    /// Who/what made the assessment (analyst id, job name, …).
    pub by: String,
}

impl Assessment {
    /// Convenience constructor.
    pub fn new(
        ts_ms: i64,
        grade: ReliabilityGrade,
        note: impl Into<String>,
        by: impl Into<String>,
    ) -> Self {
        Self {
            ts_ms,
            grade,
            note: note.into(),
            by: by.into(),
        }
    }
}

/// What kind of thing a source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// A domain / site.
    Domain,
    /// An account on some platform.
    Account,
    /// A feed (RSS/Atom/JSON feed, streaming endpoint).
    Feed,
    /// Anything else.
    Other,
}

/// A registered SOURCE with its append-only reliability history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    /// Stable registry id (e.g. `example.com`, `acct:example@platform`).
    pub id: String,
    /// What kind of source this is.
    pub kind: SourceKind,
    /// Epoch ms the source was first registered (first-seen; kept across
    /// `upsert` updates).
    pub created_ms: i64,
    /// Reliability assessments, time-ordered (non-decreasing `ts_ms`),
    /// append-only.
    pub history: Vec<Assessment>,
}

impl SourceRecord {
    /// New record with an empty history.
    pub fn new(id: impl Into<String>, kind: SourceKind, created_ms: i64) -> Self {
        Self {
            id: id.into(),
            kind,
            created_ms,
            history: Vec::new(),
        }
    }

    /// The latest grade, or `None` while the source has never been assessed.
    pub fn latest_grade(&self) -> Option<ReliabilityGrade> {
        self.history.last().map(|a| a.grade)
    }
}

// ── Outcomes & errors ───────────────────────────────────────────────────────

/// What an [`SourceRegistry::upsert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpsertOutcome {
    /// The source was new and has been inserted, history as given.
    Inserted,
    /// The source already existed; metadata was updated. `history_added` is
    /// how many (newest) assessments the stored history gained — `0` when the
    /// incoming history was an older, shorter snapshot of the same history.
    Updated {
        /// Number of assessments appended to the stored history.
        history_added: usize,
    },
}

/// Errors from the source registry / item assessment log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Source id was empty.
    EmptySourceId,
    /// Item id was empty.
    EmptyItemId,
    /// No source is registered under this id.
    UnknownSource {
        /// The id that was looked up.
        id: String,
    },
    /// The source exists but has never been assessed.
    NoAssessments {
        /// The source id.
        id: String,
    },
    /// The assessment's timestamp precedes the last recorded one — the
    /// history is append-only and time-ordered.
    AssessmentOutOfOrder {
        /// The source id.
        id: String,
        /// Timestamp of the current last entry.
        last_ts_ms: i64,
        /// Timestamp that was offered.
        got_ts_ms: i64,
    },
    /// A history (incoming to `upsert`) is not time-ordered.
    HistoryOutOfOrder {
        /// The source id.
        id: String,
        /// Index of the offending entry (0-based; `< history[i-1].ts_ms`).
        at_index: usize,
    },
    /// The incoming history is neither equal to, an extension of, nor a
    /// prefix of the stored one — appending could rewrite or lose history.
    HistoryDiverged {
        /// The source id.
        id: String,
    },
    /// A grade string was not `A`–`F`.
    UnknownGrade {
        /// The raw input.
        raw: String,
    },
    /// A credibility digit was not `1`–`6`.
    UnknownCredibility {
        /// The raw input.
        raw: String,
    },
    /// No assessment is recorded for this item id.
    UnknownItem {
        /// The item id that was looked up.
        item_id: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySourceId => write!(f, "source id must not be empty"),
            Self::EmptyItemId => write!(f, "item id must not be empty"),
            Self::UnknownSource { id } => write!(f, "unknown source `{id}`"),
            Self::NoAssessments { id } => {
                write!(f, "source `{id}` has no assessments yet")
            }
            Self::AssessmentOutOfOrder {
                id,
                last_ts_ms,
                got_ts_ms,
            } => write!(
                f,
                "assessment for `{id}` is out of order: ts_ms {got_ts_ms} < last {last_ts_ms} \
                 (history is append-only)"
            ),
            Self::HistoryOutOfOrder { id, at_index } => write!(
                f,
                "history for `{id}` is not time-ordered at index {at_index}"
            ),
            Self::HistoryDiverged { id } => write!(
                f,
                "history for `{id}` diverges from the stored history \
                 (append-only: histories may only extend)"
            ),
            Self::UnknownGrade { raw } => {
                write!(f, "unknown reliability grade `{raw}` (expected A-F)")
            }
            Self::UnknownCredibility { raw } => {
                write!(f, "unknown item credibility `{raw}` (expected 1-6)")
            }
            Self::UnknownItem { item_id } => {
                write!(f, "no assessment recorded for item `{item_id}`")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ── Source registry (SOURCE side) ───────────────────────────────────────────

/// The registry of collection sources and their reliability histories.
///
/// SOURCE-side entry points: [`Self::upsert`], [`Self::record_assessment`] /
/// [`Self::assess_source`]. Item-side assessments live in
/// [`ItemAssessmentLog`] and can only *read* this registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRegistry {
    /// Sorted by id for deterministic serialization.
    records: BTreeMap<String, SourceRecord>,
}

impl SourceRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new source, or update an existing one.
    ///
    /// * New id → inserted as-is ([`UpsertOutcome::Inserted`]).
    /// * Existing id → `kind` is updated; `created_ms` keeps the first-seen
    ///   value; the history may only *extend* the stored one (append-only).
    ///   An incoming history that is equal, or a stale (shorter) prefix of
    ///   the stored one, is accepted with `history_added == 0`; an incoming
    ///   history that diverges (rewrite / shrink-with-different-content) is
    ///   rejected with [`RegistryError::HistoryDiverged`] and nothing changes.
    ///
    /// The incoming history must itself be time-ordered
    /// ([`RegistryError::HistoryOutOfOrder`] otherwise) and the id non-empty
    /// ([`RegistryError::EmptySourceId`]).
    pub fn upsert(&mut self, source: SourceRecord) -> Result<UpsertOutcome, RegistryError> {
        if source.id.is_empty() {
            return Err(RegistryError::EmptySourceId);
        }
        validate_history(&source.id, &source.history)?;
        match self.records.entry(source.id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(source);
                Ok(UpsertOutcome::Inserted)
            }
            Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                if is_prefix(&existing.history, &source.history) {
                    // Equal or an extension → adopt the longer incoming history.
                    let added = source.history.len() - existing.history.len();
                    existing.history = source.history;
                    existing.kind = source.kind;
                    Ok(UpsertOutcome::Updated {
                        history_added: added,
                    })
                } else if is_prefix(&source.history, &existing.history) {
                    // Stale (shorter) snapshot → keep the stored history.
                    existing.kind = source.kind;
                    Ok(UpsertOutcome::Updated { history_added: 0 })
                } else {
                    Err(RegistryError::HistoryDiverged {
                        id: existing.id.clone(),
                    })
                }
            }
        }
    }

    /// Append one assessment to a source's reliability history.
    ///
    /// SOURCE-side entry point. Append-only: the assessment must not be older
    /// than the current last entry (equal timestamps are allowed; ties keep
    /// insertion order). Unknown ids are [`RegistryError::UnknownSource`].
    pub fn record_assessment(
        &mut self,
        id: &str,
        assessment: Assessment,
    ) -> Result<(), RegistryError> {
        let Some(record) = self.records.get_mut(id) else {
            return Err(RegistryError::UnknownSource { id: id.to_string() });
        };
        if let Some(last) = record.history.last()
            && assessment.ts_ms < last.ts_ms
        {
            return Err(RegistryError::AssessmentOutOfOrder {
                id: id.to_string(),
                last_ts_ms: last.ts_ms,
                got_ts_ms: assessment.ts_ms,
            });
        }
        record.history.push(assessment);
        Ok(())
    }

    /// Explicit alias of [`Self::record_assessment`] naming the SOURCE side
    /// of the assessment pair (contrast [`ItemAssessmentLog::assess_item`]).
    pub fn assess_source(
        &mut self,
        id: &str,
        assessment: Assessment,
    ) -> Result<(), RegistryError> {
        self.record_assessment(id, assessment)
    }

    /// The most recent reliability grade for `id`.
    ///
    /// Errors with [`RegistryError::UnknownSource`] for an unregistered id and
    /// [`RegistryError::NoAssessments`] for a registered-but-unassessed one.
    pub fn current_grade(&self, id: &str) -> Result<ReliabilityGrade, RegistryError> {
        self.current_assessment(id).map(|a| a.grade)
    }

    /// The most recent assessment (grade + note + by) for `id`.
    pub fn current_assessment(&self, id: &str) -> Result<&Assessment, RegistryError> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| RegistryError::UnknownSource { id: id.to_string() })?;
        record
            .history
            .last()
            .ok_or_else(|| RegistryError::NoAssessments { id: id.to_string() })
    }

    /// Read-only grade snapshot for feeding the ITEM side:
    /// `Err(UnknownSource)` for unregistered ids, `Ok(None)` for a source that
    /// has not been assessed yet.
    pub fn grade_snapshot(&self, id: &str) -> Result<Option<ReliabilityGrade>, RegistryError> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| RegistryError::UnknownSource { id: id.to_string() })?;
        Ok(record.latest_grade())
    }

    /// The full reliability history of `id` (time-ordered, append-only).
    pub fn history(&self, id: &str) -> Result<&[Assessment], RegistryError> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| RegistryError::UnknownSource { id: id.to_string() })?;
        Ok(&record.history)
    }

    /// The stored record, if any.
    pub fn get(&self, id: &str) -> Option<&SourceRecord> {
        self.records.get(id)
    }

    /// Whether a source is registered under `id`.
    pub fn contains(&self, id: &str) -> bool {
        self.records.contains_key(id)
    }

    /// Number of registered sources.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// No sources registered.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// All source ids in deterministic (sorted) order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.records.keys().map(String::as_str)
    }
}

/// Histories must be non-decreasing in `ts_ms` (append-only assumption).
fn validate_history(id: &str, history: &[Assessment]) -> Result<(), RegistryError> {
    for (i, pair) in history.windows(2).enumerate() {
        if pair[1].ts_ms < pair[0].ts_ms {
            return Err(RegistryError::HistoryOutOfOrder {
                id: id.to_string(),
                at_index: i + 1,
            });
        }
    }
    Ok(())
}

/// True when `short` equals the first `short.len()` entries of `long`.
fn is_prefix(short: &[Assessment], long: &[Assessment]) -> bool {
    short.len() <= long.len() && short.iter().zip(long.iter()).all(|(a, b)| a == b)
}

// ── Item assessment log (ITEM side) ─────────────────────────────────────────

/// Assessment of one collected **ITEM** (report, claim, document, post).
///
/// This is the *other* axis: it records the item's own credibility and — for
/// provenance only — the source reliability that was current when the item was
/// assessed ([`Self::source_grade`]). It never feeds back into the source's
/// history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemAssessment {
    /// Id of the item being assessed.
    pub item_id: String,
    /// The source the item was collected from (must be registered).
    pub source_id: String,
    /// Epoch ms when the item was assessed.
    pub ts_ms: i64,
    /// Credibility of the item itself (Admiralty digit 1–6).
    pub credibility: ItemCredibility,
    /// Snapshot of the SOURCE axis at assessment time (the two axes are
    /// assessed in isolation; the snapshot is provenance, not coupling).
    pub source_grade: Option<ReliabilityGrade>,
    /// Free-text rationale.
    pub note: String,
    /// Who/what made the assessment.
    pub by: String,
}

/// Append-only log of [`ItemAssessment`]s.
///
/// ITEM-side entry point: [`Self::assess_item`]. Deliberately a *different
/// type* with a *different signature* than the SOURCE-side
/// [`SourceRegistry::assess_source`]: it borrows the registry shared
/// (`&SourceRegistry`) and can only read the source's current grade — source
/// history is structurally out of reach.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemAssessmentLog {
    entries: Vec<ItemAssessment>,
}

impl ItemAssessmentLog {
    /// Empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assess one item's credibility, capturing the source's current
    /// reliability as a read-only snapshot.
    ///
    /// Errors: empty `item_id` → [`RegistryError::EmptyItemId`];
    /// `source_id` not registered → [`RegistryError::UnknownSource`] (items
    /// always attach to a known source; items from a brand-new unregistered
    /// source must first get a [`SourceRecord`] via [`SourceRegistry::upsert`]).
    ///
    /// Returns the recorded entry. Append-only: existing entries are never
    /// modified.
    #[allow(clippy::too_many_arguments)]
    pub fn assess_item(
        &mut self,
        registry: &SourceRegistry,
        item_id: &str,
        source_id: &str,
        credibility: ItemCredibility,
        note: &str,
        by: &str,
        ts_ms: i64,
    ) -> Result<&ItemAssessment, RegistryError> {
        if item_id.is_empty() {
            return Err(RegistryError::EmptyItemId);
        }
        // Shared borrow only: this call cannot mutate source state.
        let source_grade = registry.grade_snapshot(source_id)?;
        self.entries.push(ItemAssessment {
            item_id: item_id.to_string(),
            source_id: source_id.to_string(),
            ts_ms,
            credibility,
            source_grade,
            note: note.to_string(),
            by: by.to_string(),
        });
        Ok(self.entries.last().expect("entry was just pushed"))
    }

    /// The most recently recorded assessment for `item_id`
    /// ([`RegistryError::UnknownItem`] if the item was never assessed).
    pub fn latest(&self, item_id: &str) -> Result<&ItemAssessment, RegistryError> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.item_id == item_id)
            .ok_or_else(|| RegistryError::UnknownItem {
                item_id: item_id.to_string(),
            })
    }

    /// All item assessments collected from `source_id`, in insertion order.
    pub fn for_source(&self, source_id: &str) -> Vec<&ItemAssessment> {
        self.entries
            .iter()
            .filter(|e| e.source_id == source_id)
            .collect()
    }

    /// The raw append-only entries.
    pub fn entries(&self) -> &[ItemAssessment] {
        &self.entries
    }

    /// Number of recorded item assessments.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No item assessments recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn assess(ts_ms: i64, grade: ReliabilityGrade) -> Assessment {
        Assessment::new(ts_ms, grade, "note", "tester")
    }

    fn rec(id: &str, kind: SourceKind) -> SourceRecord {
        SourceRecord::new(id, kind, 1_000)
    }

    #[test]
    fn grade_parsing_round_trip() {
        assert_eq!(ReliabilityGrade::from_letter("a").unwrap(), ReliabilityGrade::A);
        assert_eq!(" f ".parse::<ReliabilityGrade>().unwrap(), ReliabilityGrade::F);
        for (i, grade) in [
            ReliabilityGrade::A,
            ReliabilityGrade::B,
            ReliabilityGrade::C,
            ReliabilityGrade::D,
            ReliabilityGrade::E,
            ReliabilityGrade::F,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(grade.rank(), (i + 1) as u8);
            assert_eq!(ReliabilityGrade::from_rank((i + 1) as u8).unwrap(), *grade);
            assert_eq!(ReliabilityGrade::from_letter(grade.as_letter()).unwrap(), *grade);
        }
        assert!(ReliabilityGrade::from_letter("G").is_err());
        assert!(ReliabilityGrade::from_letter("").is_err());
        assert!(ReliabilityGrade::from_letter("AA").is_err());
        assert!(ReliabilityGrade::from_rank(0).is_err());
        assert!(ReliabilityGrade::from_rank(7).is_err());
        // Best-first ordering: A is the strongest and the smallest.
        assert!(ReliabilityGrade::A < ReliabilityGrade::F);
        assert_eq!(
            [ReliabilityGrade::F, ReliabilityGrade::C, ReliabilityGrade::A]
                .iter()
                .copied()
                .min(),
            Some(ReliabilityGrade::A)
        );
        // Serde form is the bare letter; other forms are rejected.
        assert_eq!(serde_json::to_string(&ReliabilityGrade::B).unwrap(), "\"B\"");
        assert_eq!(
            serde_json::from_str::<ReliabilityGrade>("\"B\"").unwrap(),
            ReliabilityGrade::B
        );
        assert!(serde_json::from_str::<ReliabilityGrade>("\"G\"").is_err());
    }

    #[test]
    fn credibility_parsing_round_trip() {
        let all = [
            ItemCredibility::Confirmed,
            ItemCredibility::ProbablyTrue,
            ItemCredibility::PossiblyTrue,
            ItemCredibility::Doubtful,
            ItemCredibility::Improbable,
            ItemCredibility::CannotBeJudged,
        ];
        for (i, cred) in all.iter().enumerate() {
            assert_eq!(cred.as_digit(), (i + 1) as u8);
            assert_eq!(ItemCredibility::from_digit((i + 1) as u8).unwrap(), *cred);
        }
        assert!(ItemCredibility::from_digit(0).is_err());
        assert!(ItemCredibility::from_digit(7).is_err());
        assert_eq!(ItemCredibility::Confirmed.as_digit(), 1);
        assert_eq!(ItemCredibility::Doubtful.as_digit(), 4);
        assert_eq!(ItemCredibility::Doubtful.word(), "doubtful");
        // Best-first ordering.
        assert!(ItemCredibility::Confirmed < ItemCredibility::CannotBeJudged);
    }

    #[test]
    fn upsert_insert_update_and_metadata() {
        let mut reg = SourceRegistry::new();
        let mut src = rec("wire.example", SourceKind::Domain);
        src.history.push(assess(100, ReliabilityGrade::B));
        assert_eq!(reg.upsert(src).unwrap(), UpsertOutcome::Inserted);
        assert!(reg.contains("wire.example"));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());

        // Re-upsert: same history, new kind → Updated (0 added), metadata
        // updated, created_ms stays first-seen.
        let mut again = SourceRecord::new("wire.example", SourceKind::Feed, 9_999);
        again.history.push(assess(100, ReliabilityGrade::B));
        assert_eq!(
            reg.upsert(again).unwrap(),
            UpsertOutcome::Updated { history_added: 0 }
        );
        let stored = reg.get("wire.example").unwrap();
        assert_eq!(stored.kind, SourceKind::Feed);
        assert_eq!(stored.created_ms, 1_000);
        assert_eq!(stored.history.len(), 1);
        assert_eq!(reg.current_grade("wire.example").unwrap(), ReliabilityGrade::B);
        assert_eq!(reg.ids().collect::<Vec<_>>(), vec!["wire.example"]);
    }

    #[test]
    fn upsert_only_extends_history() {
        let mut reg = SourceRegistry::new();
        let mut src = rec("s1", SourceKind::Domain);
        src.history.push(assess(100, ReliabilityGrade::C));
        reg.upsert(src).unwrap();

        // Extension: stored history is a prefix of the incoming one.
        let mut extended = rec("s1", SourceKind::Domain);
        extended.history = vec![assess(100, ReliabilityGrade::C), assess(200, ReliabilityGrade::B)];
        assert_eq!(
            reg.upsert(extended).unwrap(),
            UpsertOutcome::Updated { history_added: 1 }
        );
        assert_eq!(reg.history("s1").unwrap().len(), 2);
        assert_eq!(reg.current_grade("s1").unwrap(), ReliabilityGrade::B);

        // Stale shorter snapshot (prefix) → accepted, nothing lost.
        let mut stale = rec("s1", SourceKind::Domain);
        stale.history = vec![assess(100, ReliabilityGrade::C)];
        assert_eq!(
            reg.upsert(stale).unwrap(),
            UpsertOutcome::Updated { history_added: 0 }
        );
        assert_eq!(reg.history("s1").unwrap().len(), 2);

        // Diverged (same length, rewritten grade at index 0) → rejected.
        let before = reg.clone();
        let mut diverged = rec("s1", SourceKind::Domain);
        diverged.history = vec![assess(100, ReliabilityGrade::A), assess(200, ReliabilityGrade::B)];
        assert_eq!(
            reg.upsert(diverged),
            Err(RegistryError::HistoryDiverged { id: "s1".into() })
        );
        assert_eq!(reg, before);

        // Shorter but not a prefix → also rejected, registry untouched.
        let mut wrong = rec("s1", SourceKind::Domain);
        wrong.history = vec![assess(300, ReliabilityGrade::D)];
        assert!(matches!(
            reg.upsert(wrong),
            Err(RegistryError::HistoryDiverged { .. })
        ));
        assert_eq!(reg, before);

        // Incoming unordered history → validated up front.
        let mut unordered = rec("s2", SourceKind::Other);
        unordered.history = vec![assess(200, ReliabilityGrade::B), assess(100, ReliabilityGrade::C)];
        assert!(matches!(
            reg.upsert(unordered),
            Err(RegistryError::HistoryOutOfOrder { at_index: 1, .. })
        ));

        // Empty id → rejected.
        assert_eq!(
            reg.upsert(rec("", SourceKind::Other)),
            Err(RegistryError::EmptySourceId)
        );
    }

    #[test]
    fn record_assessment_appends_in_order() {
        let mut reg = SourceRegistry::new();
        reg.upsert(rec("acct:example", SourceKind::Account)).unwrap();
        reg.record_assessment("acct:example", assess(10, ReliabilityGrade::D))
            .unwrap();
        reg.assess_source("acct:example", assess(20, ReliabilityGrade::C))
            .unwrap(); // explicit SOURCE-side alias
        reg.record_assessment("acct:example", assess(20, ReliabilityGrade::B))
            .unwrap(); // equal ts allowed (tie keeps insertion order)
        let ts: Vec<i64> = reg
            .history("acct:example")
            .unwrap()
            .iter()
            .map(|a| a.ts_ms)
            .collect();
        assert_eq!(ts, vec![10, 20, 20]);
        assert_eq!(reg.current_grade("acct:example").unwrap(), ReliabilityGrade::B);
        assert_eq!(reg.current_assessment("acct:example").unwrap().ts_ms, 20);
        assert_eq!(reg.current_assessment("acct:example").unwrap().by, "tester");
    }

    #[test]
    fn append_only_enforcement() {
        let mut reg = SourceRegistry::new();
        reg.upsert(rec("s", SourceKind::Domain)).unwrap();
        reg.record_assessment("s", assess(100, ReliabilityGrade::B)).unwrap();
        let before = reg.clone();

        // Older timestamp → rejected, history byte-identical.
        let err = reg
            .record_assessment("s", assess(50, ReliabilityGrade::A))
            .unwrap_err();
        assert_eq!(
            err,
            RegistryError::AssessmentOutOfOrder {
                id: "s".into(),
                last_ts_ms: 100,
                got_ts_ms: 50,
            }
        );
        assert_eq!(reg, before);

        // Appending never rewrites earlier entries (append-only, per entry).
        let first_entry = reg.history("s").unwrap()[0].clone();
        reg.record_assessment("s", assess(300, ReliabilityGrade::F)).unwrap();
        let history = reg.history("s").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], first_entry);
        assert_eq!(history[1].grade, ReliabilityGrade::F);
        // The only mutators are upsert (extend-only, see
        // `upsert_only_extends_history`) and record_assessment/assess_source
        // (append-only): no API removes or edits an assessment.
    }

    #[test]
    fn unknown_source_errors() {
        let mut reg = SourceRegistry::new();
        assert_eq!(
            reg.record_assessment("nope", assess(1, ReliabilityGrade::A)),
            Err(RegistryError::UnknownSource { id: "nope".into() })
        );
        assert_eq!(
            reg.current_grade("nope"),
            Err(RegistryError::UnknownSource { id: "nope".into() })
        );
        assert!(matches!(
            reg.current_assessment("nope"),
            Err(RegistryError::UnknownSource { .. })
        ));
        assert!(matches!(reg.history("nope"), Err(RegistryError::UnknownSource { .. })));
        assert_eq!(
            reg.grade_snapshot("nope"),
            Err(RegistryError::UnknownSource { id: "nope".into() })
        );
        assert!(reg.get("nope").is_none());

        // Registered but never assessed → NoAssessments / None snapshot.
        reg.upsert(rec("fresh", SourceKind::Feed)).unwrap();
        assert_eq!(
            reg.current_grade("fresh"),
            Err(RegistryError::NoAssessments { id: "fresh".into() })
        );
        assert_eq!(reg.grade_snapshot("fresh").unwrap(), None);

        // Assessed → snapshot is Some(grade).
        reg.record_assessment("fresh", assess(1, ReliabilityGrade::C)).unwrap();
        assert_eq!(reg.grade_snapshot("fresh").unwrap(), Some(ReliabilityGrade::C));

        // Item side: unknown item on an empty log.
        let log = ItemAssessmentLog::new();
        assert!(log.is_empty());
        assert_eq!(
            log.latest("ghost"),
            Err(RegistryError::UnknownItem { item_id: "ghost".into() })
        );

        // Errors render as human-readable text.
        assert!(
            RegistryError::UnknownSource { id: "x".into() }
                .to_string()
                .contains("unknown source")
        );
        assert!(RegistryError::UnknownGrade { raw: "G".into() }
            .to_string()
            .contains("A-F"));
    }

    #[test]
    fn source_vs_item_separation() {
        let mut reg = SourceRegistry::new();
        reg.upsert(rec("wire.example", SourceKind::Domain)).unwrap();
        reg.assess_source("wire.example", assess(100, ReliabilityGrade::A))
            .unwrap();
        let source_history_before = reg.history("wire.example").unwrap().to_vec();

        let mut items = ItemAssessmentLog::new();
        // ITEM-side entry point: only a shared borrow of the registry is
        // passed, so this call structurally cannot touch source history.
        let entry = items
            .assess_item(
                &reg,
                "report-1",
                "wire.example",
                ItemCredibility::Doubtful,
                "single anonymous string",
                "analyst",
                150,
            )
            .unwrap();
        assert_eq!(entry.credibility, ItemCredibility::Doubtful);
        assert_eq!(entry.source_grade, Some(ReliabilityGrade::A)); // other axis, snapshot

        // The item assessment left the source history untouched.
        assert_eq!(reg.history("wire.example").unwrap(), source_history_before.as_slice());

        // Later re-grades do not retroactively change the item's snapshot...
        reg.assess_source("wire.example", assess(200, ReliabilityGrade::E))
            .unwrap();
        assert_eq!(items.latest("report-1").unwrap().source_grade, Some(ReliabilityGrade::A));
        assert_eq!(reg.current_grade("wire.example").unwrap(), ReliabilityGrade::E);

        // ...while a NEW item snapshots the updated source grade (axes are
        // assessed in isolation, each at its own time).
        let second = items
            .assess_item(
                &reg,
                "report-2",
                "wire.example",
                ItemCredibility::ProbablyTrue,
                "corroborated by two independent feeds",
                "analyst",
                210,
            )
            .unwrap();
        assert_eq!(second.source_grade, Some(ReliabilityGrade::E));
        assert_eq!(items.len(), 2);
        assert_eq!(items.for_source("wire.example").len(), 2);
        assert_eq!(items.for_source("other.example").len(), 0);

        // Items attach to a registered source; unregistered → error, log
        // unchanged.
        assert!(matches!(
            items.assess_item(
                &reg,
                "report-3",
                "ghost.example",
                ItemCredibility::Confirmed,
                "",
                "analyst",
                300,
            ),
            Err(RegistryError::UnknownSource { .. })
        ));
        // Empty item id → error.
        assert_eq!(
            items.assess_item(
                &reg,
                "",
                "wire.example",
                ItemCredibility::Confirmed,
                "",
                "analyst",
                300,
            ),
            Err(RegistryError::EmptyItemId)
        );
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn serde_round_trip() {
        let mut reg = SourceRegistry::new();
        let mut a = rec("a.example", SourceKind::Domain);
        a.history = vec![assess(100, ReliabilityGrade::B), assess(300, ReliabilityGrade::A)];
        reg.upsert(a).unwrap();
        reg.upsert(rec("feed:acct", SourceKind::Feed)).unwrap();
        reg.record_assessment("feed:acct", assess(42, ReliabilityGrade::D))
            .unwrap();

        let mut items = ItemAssessmentLog::new();
        items
            .assess_item(
                &reg,
                "i-1",
                "a.example",
                ItemCredibility::PossiblyTrue,
                "n",
                "analyst",
                400,
            )
            .unwrap();

        let json = serde_json::to_string(&reg).unwrap();
        let back: SourceRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
        assert_eq!(back.current_grade("a.example").unwrap(), ReliabilityGrade::A);
        assert_eq!(back.history("a.example").unwrap()[0].ts_ms, 100);
        assert_eq!(back.history("a.example").unwrap()[0].note, "note");

        let json = serde_json::to_string(&items).unwrap();
        let back: ItemAssessmentLog = serde_json::from_str(&json).unwrap();
        assert_eq!(back, items);
        assert_eq!(
            back.latest("i-1").unwrap().credibility,
            ItemCredibility::PossiblyTrue
        );
        assert_eq!(back.latest("i-1").unwrap().source_grade, Some(ReliabilityGrade::A));
    }
}
