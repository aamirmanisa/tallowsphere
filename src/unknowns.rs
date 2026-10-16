//! Unknowns registry + apophatic markers — tasks B3.1.1–B3.1.3, batch 10 §8.
//!
//! The registry tracks what is *not* known. Three markers, one status ladder:
//!
//! - [`UnknownKind::Unknown`] — "we don't know" (an admitted blind spot);
//! - [`UnknownKind::Gap`] — "a hole in coverage" (something *should* be
//!   known and the collection left a hole);
//! - [`UnknownKind::OpenQuestion`] — a posed question awaiting an answer.
//!
//! # The apophatic distinction pinned here
//!
//! [`UnknownStatus::Undescribed`] (never characterized at all) is **distinct
//! from** [`UnknownStatus::Unverified`] (characterized, not yet confirmed).
//! A fresh entry starts `Undescribed`; characterizing it moves it to
//! `Unverified`; confirming the characterization resolves it. The distinction
//! is visible everywhere — in the type system, in the serde wire names
//! (`"undescribed"` ≠ `"unverified"`) and in the pinned tests — because
//! conflating "we have not even looked" with "we looked but have not
//! confirmed" would silently upgrade ignorance into a candidate fact.
//!
//! # Frozen interface (batch 10, §8)
//! - [`UnknownKind`] `{ Unknown, Gap, OpenQuestion }`
//! - [`UnknownStatus`] `{ Undescribed, Unverified, Resolved }`
//! - [`Unknown`] `{ id, kind, title, status, note, opened_ms }`
//! - [`UnknownsRegistry`] — `add` (ids `unk-<seq:03>`, fresh status
//!   `Undescribed`) / `set_status` (forward-only) / `by_status` (id-sorted) /
//!   `open_count` (everything not Resolved) / `budget_check`
//!   (`BudgetExceeded{open, max}` — the self-limitation budget);
//! - [`render_dossier`] — deterministic markdown, no timestamps;
//! - [`check_promotion`] — promotion guard: only `Resolved` + non-empty note
//!   may be cited as established, else `NotResolved(id)`;
//! - [`UnknownsError`] `{ BadInput(&'static str), UnknownId, BadTransition,
//!   BudgetExceeded { open, max }, NotResolved(String) }`.
//!
//! # Semantics pinned here
//! - **Status ladder is forward-only**: `Undescribed → Unverified → Resolved`.
//!   Skipping forward (`Undescribed → Resolved`) is allowed — knowledge moves
//!   only in one direction. Backwards moves are refused with
//!   [`UnknownsError::BadTransition`]. An *equal*-status call is not a
//!   transition: it is an idempotent refresh that may enrich the note.
//! - **Notes are monotone**: an empty/whitespace-only note never erases an
//!   existing characterization (a note may be filled in or refined, never
//!   blanked) — erasure would be a knowledge downgrade the forward-only rule
//!   exists to prevent. Notes *may* be empty at `add` time: that is exactly
//!   what "undescribed" means. `add` refuses an empty/whitespace-only
//!   *title* ([`UnknownsError::BadInput`]).
//! - **Budget**: [`UnknownsRegistry::budget_check`] fails only when
//!   `open_count() > max_open` — the boundary `open == max` is allowed.
//! - **Promotion guard** ([`check_promotion`]): `Resolved` *and* a
//!   non-empty (non-whitespace) note, else `NotResolved(id)` — an entry
//!   resolved without a characterization note is not citable as established.
//! - **Dossier**: three sections always present, in ladder order, entries
//!   `- <id> [<kind word>] <title>` sorted by id; counts header; no
//!   timestamps ([`Unknown::opened_ms`] is deliberately absent from the
//!   render — the dossier is a knowledge view, not an audit log).
//! - **Wire names**: [`UnknownKind`]/[`UnknownStatus`] use `snake_case`
//!   (`"open_question"`, `"undescribed"`, …) and `word()` returns exactly
//!   those names, so the dossier's `[<kind word>]` and the serde wire form
//!   can never drift apart. [`UnknownsError`] keeps its variant names as
//!   wire form (matching `release_marks::MarkError` style), and its
//!   `Deserialize` is a hand-written *total* impl (see [`intern_field`]):
//!   a `&'static str` payload cannot be borrowed from non-`'static` input,
//!   so decoded field names are re-bound through a fixed table.


use std::fmt;

use serde::{Deserialize, Serialize};

/// What kind of not-knowing an entry records.
///
/// The three kinds are deliberately distinct: an [`UnknownKind::Unknown`] is
/// an admitted blind spot ("we don't know"), a [`UnknownKind::Gap`] is a hole
/// in coverage ("something should be known; collection left a hole") and an
/// [`UnknownKind::OpenQuestion`] is a posed question awaiting an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownKind {
    /// "We don't know" — an admitted blind spot.
    Unknown,
    /// "A hole in coverage" — an unmet coverage requirement.
    Gap,
    /// A posed question awaiting an answer.
    OpenQuestion,
}

impl UnknownKind {
    /// Stable lowercase word for this kind — identical to the serde wire
    /// name (pinned by tests, so dossier and wire form cannot drift).
    pub fn word(&self) -> &'static str {
        match self {
            UnknownKind::Unknown => "unknown",
            UnknownKind::Gap => "gap",
            UnknownKind::OpenQuestion => "open_question",
        }
    }
}

/// Where an entry sits on the characterization ladder.
///
/// **[`Undescribed`](UnknownStatus::Undescribed) ≠
/// [`Unverified`](UnknownStatus::Unverified).** `Undescribed` means the entry
/// was never characterized at all; `Unverified` means it *was* characterized
/// but the characterization is not yet confirmed. Keeping those apart is the
/// point of this registry — only `Resolved` entries are citable (see
/// [`check_promotion`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownStatus {
    /// Never characterized. (Distinct from `Unverified`.)
    Undescribed,
    /// Characterized, not yet confirmed. (Distinct from `Undescribed`.)
    Unverified,
    /// Characterization confirmed; citable subject to [`check_promotion`].
    Resolved,
}

impl UnknownStatus {
    /// Ladder position — values increase strictly forward-only.
    fn rank(self) -> u8 {
        match self {
            UnknownStatus::Undescribed => 0,
            UnknownStatus::Unverified => 1,
            UnknownStatus::Resolved => 2,
        }
    }

    /// Stable lowercase word for this status — identical to the serde wire
    /// name.
    pub fn word(&self) -> &'static str {
        match self {
            UnknownStatus::Undescribed => "undescribed",
            UnknownStatus::Unverified => "unverified",
            UnknownStatus::Resolved => "resolved",
        }
    }
}

/// A single registered not-knowing, with its characterization state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unknown {
    /// Registry-assigned id: `unk-<seq:03>` (fixed width, sortable).
    pub id: String,
    /// What kind of not-knowing this is.
    pub kind: UnknownKind,
    /// One-line title (non-empty; enforced at [`UnknownsRegistry::add`]).
    pub title: String,
    /// Ladder position (starts `Undescribed`).
    pub status: UnknownStatus,
    /// Characterization note. Empty while undescribed; never erased once set.
    pub note: String,
    /// When the entry was opened (absent from the dossier render by design).
    pub opened_ms: i64,
}

impl Unknown {
    /// An entry is open until it is resolved.
    pub fn is_open(&self) -> bool {
        self.status != UnknownStatus::Resolved
    }
}

/// Errors from registry operations.
///
/// `Serialize` is derived (wire form = variant name, matching
/// `release_marks::MarkError` style). `Deserialize` is implemented by hand
/// below: a derived impl for the `&'static str` payload would only accept
/// `'static` input, which would make error values undecodable from ordinary
/// (owned) buffers. The manual impl accepts any input lifetime and re-binds
/// the payload through [`intern_field`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UnknownsError {
    /// A required text field was empty / whitespace-only (field name).
    BadInput(&'static str),
    /// No entry with that id exists in the registry.
    UnknownId,
    /// A status change moved backwards on the ladder (or skipped nothing —
    /// only *backwards* moves are refused; equal-status refreshes are not
    /// transitions).
    BadTransition,
    /// The self-limitation budget is exceeded: `open > max`.
    BudgetExceeded { open: usize, max: usize },
    /// Promotion guard: the entry (id) is not citable as established — it is
    /// not `Resolved`, or it carries no characterization note.
    NotResolved(String),
}

impl fmt::Display for UnknownsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnknownsError::BadInput(field) => {
                write!(f, "invalid input: {field} must be non-empty")
            }
            UnknownsError::UnknownId => {
                write!(f, "unknown id: no entry with that id exists in the registry")
            }
            UnknownsError::BadTransition => write!(
                f,
                "illegal status transition: unknowns move forward only \
                 (undescribed -> unverified -> resolved)"
            ),
            UnknownsError::BudgetExceeded { open, max } => {
                write!(f, "unknowns budget exceeded: {open} open, max {max}")
            }
            UnknownsError::NotResolved(id) => write!(
                f,
                "unknown {id} is not promotable: only Resolved entries with a \
                 non-empty note may be cited as established"
            ),
        }
    }
}

impl std::error::Error for UnknownsError {}

/// Fixed table of field names this module cites in
/// [`UnknownsError::BadInput`]. Every name the module produces must appear
/// here so a deserialized error re-binds to the same `'static` name.
const BAD_INPUT_FIELDS: &[&str] = &["title"];

/// Re-bind a (possibly borrowed) field name to `'static`.
///
/// Known names come from [`BAD_INPUT_FIELDS`] with no allocation. An unknown
/// name (a payload from some future/foreign producer) is interned by leaking
/// — bounded by the number of distinct unknown names and paid only on
/// decoding of an error value, never on the normal error path.
fn intern_field(name: &str) -> &'static str {
    if let Some(known) = BAD_INPUT_FIELDS.iter().find(|f| **f == name) {
        return known;
    }
    Box::leak(name.to_string().into_boxed_str())
}

impl<'de> Deserialize<'de> for UnknownsError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Same wire shape as the derived `Serialize` on [`UnknownsError`]
        /// (external tagging, variant names), but the `BadInput` payload is
        /// decoded with the caller's lifetime instead of `'static`.
        #[derive(Deserialize)]
        enum WireUnknownsError<'a> {
            BadInput(std::borrow::Cow<'a, str>),
            UnknownId,
            BadTransition,
            BudgetExceeded { open: usize, max: usize },
            NotResolved(String),
        }

        Ok(match WireUnknownsError::deserialize(deserializer)? {
            WireUnknownsError::BadInput(field) => UnknownsError::BadInput(intern_field(&field)),
            WireUnknownsError::UnknownId => UnknownsError::UnknownId,
            WireUnknownsError::BadTransition => UnknownsError::BadTransition,
            WireUnknownsError::BudgetExceeded { open, max } => {
                UnknownsError::BudgetExceeded { open, max }
            }
            WireUnknownsError::NotResolved(id) => UnknownsError::NotResolved(id),
        })
    }
}

/// Append-only registry of unknowns, gaps and open questions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownsRegistry {
    entries: Vec<Unknown>,
}

impl UnknownsRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Register a new entry. The status starts
    /// [`Undescribed`](UnknownStatus::Undescribed) — registration is an
    /// admission of not-knowing, never a claim. The note may be empty (an
    /// undescribed entry has nothing to say yet); the *title* may not
    /// (`BadInput("title")`).
    ///
    /// Returns the inserted entry (id `unk-<seq:03>`, sequence from 1).
    pub fn add(
        &mut self,
        kind: UnknownKind,
        title: &str,
        note: &str,
        now_ms: i64,
    ) -> Result<&Unknown, UnknownsError> {
        if title.trim().is_empty() {
            return Err(UnknownsError::BadInput("title"));
        }
        let seq = self.entries.len() + 1;
        self.entries.push(Unknown {
            id: format!("unk-{seq:03}"),
            kind,
            title: title.to_string(),
            status: UnknownStatus::Undescribed,
            note: note.to_string(),
            opened_ms: now_ms,
        });
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Move an entry along the characterization ladder.
    ///
    /// Forward-only: `Undescribed → Unverified → Resolved` (forward skips
    /// allowed); backwards moves are refused with
    /// [`UnknownsError::BadTransition`]. An equal-status call is an
    /// idempotent refresh, not a transition. A non-empty `note` replaces the
    /// stored note; an empty/whitespace-only `note` leaves the prior note in
    /// place (notes are never erased).
    pub fn set_status(
        &mut self,
        id: &str,
        status: UnknownStatus,
        note: &str,
    ) -> Result<(), UnknownsError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|u| u.id == id)
            .ok_or(UnknownsError::UnknownId)?;
        if status.rank() < entry.status.rank() {
            return Err(UnknownsError::BadTransition);
        }
        entry.status = status;
        if !note.trim().is_empty() {
            entry.note = note.to_string();
        }
        Ok(())
    }

    /// Entries at `status`, sorted by id (ascending).
    pub fn by_status(&self, status: UnknownStatus) -> Vec<&Unknown> {
        let mut out: Vec<&Unknown> = self
            .entries
            .iter()
            .filter(|u| u.status == status)
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Number of entries not yet `Resolved`.
    pub fn open_count(&self) -> usize {
        self.entries.iter().filter(|u| u.is_open()).count()
    }

    /// Self-limitation budget: fail iff `open_count() > max_open`.
    /// The boundary `open == max` is within budget.
    pub fn budget_check(&self, max_open: usize) -> Result<(), UnknownsError> {
        let open = self.open_count();
        if open > max_open {
            Err(UnknownsError::BudgetExceeded {
                open,
                max: max_open,
            })
        } else {
            Ok(())
        }
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff the registry has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by id.
    pub fn get(&self, id: &str) -> Option<&Unknown> {
        self.entries.iter().find(|u| u.id == id)
    }
}

/// Deterministic markdown dossier: counts header, then one section per status
/// in ladder order (`## Undescribed (n)` / `## Unverified (n)` /
/// `## Resolved (n)`), entries sorted by id as `- <id> [<kind word>] <title>`.
/// Empty sections render `_(none)_`. No timestamps: `opened_ms` never appears
/// here.
pub fn render_dossier(reg: &UnknownsRegistry) -> String {
    let undescribed = reg.by_status(UnknownStatus::Undescribed);
    let unverified = reg.by_status(UnknownStatus::Unverified);
    let resolved = reg.by_status(UnknownStatus::Resolved);

    let mut out = String::new();
    out.push_str("# Unknowns dossier\n\n");
    out.push_str(&format!(
        "counts: total={} undescribed={} unverified={} resolved={} open={}\n",
        reg.len(),
        undescribed.len(),
        unverified.len(),
        resolved.len(),
        reg.open_count(),
    ));

    let sections = [
        ("Undescribed", &undescribed),
        ("Unverified", &unverified),
        ("Resolved", &resolved),
    ];
    for (name, entries) in sections {
        out.push_str(&format!("\n## {name} ({})\n", entries.len()));
        if entries.is_empty() {
            out.push_str("_(none)_\n");
        } else {
            for u in entries {
                out.push_str(&format!("- {} [{}] {}\n", u.id, u.kind.word(), u.title));
            }
        }
    }
    out
}

/// Promotion guard (B3.1.3): only an entry that is `Resolved` **and** carries
/// a non-empty (non-whitespace) note may be cited as established. Everything
/// else — undescribed, unverified, or resolved-without-note — is
/// `NotResolved(id)`.
pub fn check_promotion(u: &Unknown) -> Result<(), UnknownsError> {
    if u.status == UnknownStatus::Resolved && !u.note.trim().is_empty() {
        Ok(())
    } else {
        Err(UnknownsError::NotResolved(u.id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with(entries: &[(UnknownKind, &str, &str, i64)]) -> UnknownsRegistry {
        let mut reg = UnknownsRegistry::new();
        for (kind, title, note, ms) in entries {
            reg.add(*kind, title, note, *ms).unwrap();
        }
        reg
    }

    #[test]
    fn add_sequences_ids_and_starts_undescribed() {
        let mut reg = UnknownsRegistry::new();
        assert!(reg.is_empty());
        let first = reg.add(UnknownKind::Unknown, "alpha", "", 1_000).unwrap();
        assert_eq!(first.id, "unk-001");
        assert_eq!(first.status, UnknownStatus::Undescribed);
        assert_eq!(first.opened_ms, 1_000);
        assert_eq!(reg.add(UnknownKind::Gap, "beta", "", 2_000).unwrap().id, "unk-002");
        assert_eq!(
            reg.add(UnknownKind::OpenQuestion, "gamma?", "", 3_000).unwrap().id,
            "unk-003"
        );
        assert_eq!(reg.len(), 3);
        assert_eq!(reg.get("unk-002").unwrap().title, "beta");
        assert!(reg.get("unk-999").is_none());
    }

    #[test]
    fn add_rejects_empty_title() {
        let mut reg = UnknownsRegistry::new();
        assert_eq!(
            reg.add(UnknownKind::Unknown, "", "", 1).unwrap_err(),
            UnknownsError::BadInput("title")
        );
        assert_eq!(
            reg.add(UnknownKind::Gap, "   \t ", "", 1).unwrap_err(),
            UnknownsError::BadInput("title")
        );
        assert!(reg.is_empty(), "rejected adds must not occupy the id sequence");
        assert_eq!(reg.add(UnknownKind::Gap, "ok", "", 1).unwrap().id, "unk-001");
    }

    #[test]
    fn undescribed_is_distinct_from_unverified() {
        // "undescribed" = never characterized; "unverified" = characterized,
        // not yet confirmed. The two must never collapse.
        assert_ne!(UnknownStatus::Undescribed, UnknownStatus::Unverified);
        assert_eq!(UnknownStatus::Undescribed.word(), "undescribed");
        assert_eq!(UnknownStatus::Unverified.word(), "unverified");

        let mut reg = UnknownsRegistry::new();
        reg.add(UnknownKind::Unknown, "sensor drift", "", 10).unwrap();
        // Fresh entry: never characterized → Undescribed, no note, not citable.
        let u = reg.get("unk-001").unwrap();
        assert_eq!(u.status, UnknownStatus::Undescribed);
        assert!(u.note.is_empty());
        assert_eq!(
            check_promotion(u),
            Err(UnknownsError::NotResolved("unk-001".into()))
        );
        // Characterization (even a good one) only reaches Unverified;
        // unverified is still not established.
        reg.set_status("unk-001", UnknownStatus::Unverified, "drift measured at 3%/h")
            .unwrap();
        let u = reg.get("unk-001").unwrap();
        assert_eq!(u.status, UnknownStatus::Unverified);
        assert_eq!(u.status.word(), "unverified");
        assert!(!u.note.is_empty());
        assert_eq!(
            check_promotion(u),
            Err(UnknownsError::NotResolved("unk-001".into()))
        );
        assert!(u.is_open());

        // Wire names keep the distinction visible on the serialized form.
        assert_eq!(
            serde_json::to_string(&UnknownStatus::Undescribed).unwrap(),
            "\"undescribed\""
        );
        assert_eq!(
            serde_json::to_string(&UnknownStatus::Unverified).unwrap(),
            "\"unverified\""
        );
        assert_eq!(
            serde_json::to_string(&UnknownStatus::Resolved).unwrap(),
            "\"resolved\""
        );
    }

    #[test]
    fn forward_only_transitions() {
        let mut reg = reg_with(&[
            (UnknownKind::Unknown, "one", "", 0),
            (UnknownKind::Unknown, "two", "", 0),
            (UnknownKind::Gap, "three", "", 0),
        ]);
        // Undescribed -> Unverified -> Resolved (the canonical ladder).
        reg.set_status("unk-001", UnknownStatus::Unverified, "characterized").unwrap();
        reg.set_status("unk-001", UnknownStatus::Resolved, "confirmed twice").unwrap();
        assert_eq!(reg.get("unk-001").unwrap().status, UnknownStatus::Resolved);
        // Forward skip is still forward: Undescribed -> Resolved.
        reg.set_status("unk-002", UnknownStatus::Resolved, "direct confirmation").unwrap();
        assert_eq!(reg.get("unk-002").unwrap().status, UnknownStatus::Resolved);
        // Equal status = idempotent refresh, not a transition: allowed.
        reg.set_status("unk-001", UnknownStatus::Resolved, "note refined").unwrap();
        assert_eq!(reg.get("unk-001").unwrap().note, "note refined");
        // Backwards moves refused, and refused *before* any mutation.
        assert_eq!(
            reg.set_status("unk-003", UnknownStatus::Unverified, "n/a"),
            Ok(())
        );
        assert_eq!(
            reg.set_status("unk-003", UnknownStatus::Undescribed, "undo"),
            Err(UnknownsError::BadTransition)
        );
        assert_eq!(
            reg.set_status("unk-001", UnknownStatus::Unverified, "demote"),
            Err(UnknownsError::BadTransition)
        );
        assert_eq!(reg.get("unk-003").unwrap().status, UnknownStatus::Unverified);
        assert_eq!(reg.get("unk-003").unwrap().note, "n/a");
        assert_eq!(reg.get("unk-001").unwrap().note, "note refined");
    }

    #[test]
    fn set_status_unknown_id_and_empty_note_keeps_prior() {
        let mut reg = reg_with(&[(UnknownKind::Unknown, "one", "", 0)]);
        assert_eq!(
            reg.set_status("unk-404", UnknownStatus::Resolved, "x"),
            Err(UnknownsError::UnknownId)
        );
        reg.set_status("unk-001", UnknownStatus::Unverified, "first characterization")
            .unwrap();
        // An empty note never erases a characterization (monotone notes).
        reg.set_status("unk-001", UnknownStatus::Resolved, "").unwrap();
        assert_eq!(reg.get("unk-001").unwrap().note, "first characterization");
        reg.set_status("unk-001", UnknownStatus::Resolved, "   ").unwrap();
        assert_eq!(reg.get("unk-001").unwrap().note, "first characterization");
    }

    #[test]
    fn by_status_sorted_and_filtered() {
        let mut reg = reg_with(&[
            (UnknownKind::Unknown, "one", "", 0),
            (UnknownKind::Gap, "two", "", 0),
            (UnknownKind::Gap, "three", "", 0),
            (UnknownKind::OpenQuestion, "four?", "", 0),
        ]);
        reg.set_status("unk-002", UnknownStatus::Unverified, "n").unwrap();
        reg.set_status("unk-004", UnknownStatus::Resolved, "n").unwrap();

        let ids = |v: Vec<&Unknown>| v.into_iter().map(|u| u.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(reg.by_status(UnknownStatus::Undescribed)), ["unk-001", "unk-003"]);
        assert_eq!(ids(reg.by_status(UnknownStatus::Unverified)), ["unk-002"]);
        assert_eq!(ids(reg.by_status(UnknownStatus::Resolved)), ["unk-004"]);
        assert!(reg.by_status(UnknownStatus::Resolved)
            .iter()
            .all(|u| u.status == UnknownStatus::Resolved));

        // Ids are fixed-width, so ascending id == ascending sequence <= 9…
        let big = reg_with(
            &(1..=11)
                .map(|i| (UnknownKind::Unknown, "many", "", i))
                .collect::<Vec<_>>(),
        );
        let all = big.by_status(UnknownStatus::Undescribed);
        assert_eq!(all.first().unwrap().id, "unk-001");
        assert_eq!(all.last().unwrap().id, "unk-011");
        assert!(all.windows(2).all(|w| w[0].id < w[1].id));
    }

    #[test]
    fn open_count_and_budget_boundary() {
        let mut reg = reg_with(&[
            (UnknownKind::Unknown, "one", "", 0),
            (UnknownKind::Gap, "two", "", 0),
            (UnknownKind::Gap, "three", "", 0),
        ]);
        assert_eq!(reg.open_count(), 3);
        assert_eq!(reg.budget_check(3), Ok(()), "open == max is within budget");
        assert_eq!(
            reg.budget_check(2),
            Err(UnknownsError::BudgetExceeded { open: 3, max: 2 })
        );
        reg.set_status("unk-002", UnknownStatus::Resolved, "done").unwrap();
        assert_eq!(reg.open_count(), 2);
        assert_eq!(reg.budget_check(2), Ok(()));
        assert_eq!(reg.budget_check(0).unwrap_err(), UnknownsError::BudgetExceeded { open: 2, max: 0 });
        // Resolving frees budget headroom.
        reg.set_status("unk-003", UnknownStatus::Resolved, "done").unwrap();
        assert_eq!(reg.budget_check(0).unwrap_err(), UnknownsError::BudgetExceeded { open: 1, max: 0 });
        reg.set_status("unk-001", UnknownStatus::Resolved, "done").unwrap();
        assert_eq!(reg.open_count(), 0);
        assert_eq!(reg.budget_check(0), Ok(()));
    }

    #[test]
    fn render_exact_shape_pin() {
        let mut reg = reg_with(&[
            (UnknownKind::Gap, "supplier floor-3 records", "", 1_700_000_000_000),
            (UnknownKind::OpenQuestion, "does unit D pass vibration spec?", "", 1_700_000_001_000),
            (UnknownKind::Unknown, "firmware variant of node 7", "", 1_700_000_002_000),
        ]);
        reg.set_status("unk-002", UnknownStatus::Unverified, "characterized").unwrap();
        reg.set_status("unk-003", UnknownStatus::Resolved, "confirmed against bench 4").unwrap();
        let got = render_dossier(&reg);
        let want = "\
# Unknowns dossier

counts: total=3 undescribed=1 unverified=1 resolved=1 open=2

## Undescribed (1)
- unk-001 [gap] supplier floor-3 records

## Unverified (1)
- unk-002 [open_question] does unit D pass vibration spec?

## Resolved (1)
- unk-003 [unknown] firmware variant of node 7
";
        assert_eq!(got, want);
        // No timestamps anywhere in the dossier.
        assert!(!got.contains("1700"));
    }

    #[test]
    fn render_empty_registry_and_all_sections_present() {
        let reg = UnknownsRegistry::new();
        let want = "\
# Unknowns dossier

counts: total=0 undescribed=0 unverified=0 resolved=0 open=0

## Undescribed (0)
_(none)_

## Unverified (0)
_(none)_

## Resolved (0)
_(none)_
";
        assert_eq!(render_dossier(&reg), want);
    }

    #[test]
    fn render_deterministic_and_id_sorted_within_sections() {
        let mut a = reg_with(&[
            (UnknownKind::Unknown, "one", "", 5),
            (UnknownKind::Gap, "two", "", 5),
            (UnknownKind::OpenQuestion, "three?", "", 5),
            (UnknownKind::Unknown, "four", "", 5),
        ]);
        a.set_status("unk-002", UnknownStatus::Unverified, "n").unwrap();
        a.set_status("unk-004", UnknownStatus::Resolved, "n").unwrap();
        let mut b = reg_with(&[
            (UnknownKind::Unknown, "one", "", 5),
            (UnknownKind::Gap, "two", "", 5),
            (UnknownKind::OpenQuestion, "three?", "", 5),
            (UnknownKind::Unknown, "four", "", 5),
        ]);
        b.set_status("unk-002", UnknownStatus::Unverified, "n").unwrap();
        b.set_status("unk-004", UnknownStatus::Resolved, "n").unwrap();

        assert_eq!(render_dossier(&a), render_dossier(&b), "same ops ⇒ same dossier");
        assert_eq!(render_dossier(&a), render_dossier(&a), "render is pure");

        let text = render_dossier(&a);
        let lines: Vec<&str> = text.lines().collect();
        let sec_undescribed = lines.iter().position(|l| l.starts_with("## Undescribed")).unwrap();
        let sec_unverified = lines.iter().position(|l| l.starts_with("## Unverified")).unwrap();
        let sec_resolved = lines.iter().position(|l| l.starts_with("## Resolved")).unwrap();
        assert!(sec_undescribed < sec_unverified && sec_unverified < sec_resolved);
        // Entries are `- <id> [<kind word>] <title>`; ids ascend within a section.
        for l in &lines {
            if let Some(rest) = l.strip_prefix("- ") {
                let id = rest.split(' ').next().unwrap();
                assert!(id.starts_with("unk-"));
            }
        }
        let undescribed_ids: Vec<&str> = lines[sec_undescribed..sec_unverified]
            .iter()
            .filter_map(|l| l.strip_prefix("- ").and_then(|r| r.split(' ').next()))
            .collect();
        assert_eq!(undescribed_ids, ["unk-001", "unk-003"]);
    }

    #[test]
    fn kind_words_match_serde_wire_names() {
        for (kind, word) in [
            (UnknownKind::Unknown, "unknown"),
            (UnknownKind::Gap, "gap"),
            (UnknownKind::OpenQuestion, "open_question"),
        ] {
            assert_eq!(kind.word(), word);
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{word}\""));
        }
        for (status, word) in [
            (UnknownStatus::Undescribed, "undescribed"),
            (UnknownStatus::Unverified, "unverified"),
            (UnknownStatus::Resolved, "resolved"),
        ] {
            assert_eq!(status.word(), word);
            assert_eq!(serde_json::to_string(&status).unwrap(), format!("\"{word}\""));
        }
    }

    #[test]
    fn promotion_guard_allow_and_deny() {
        let mut reg = reg_with(&[
            (UnknownKind::Unknown, "one", "", 0),
            (UnknownKind::Unknown, "two", "preset note", 0),
            (UnknownKind::Unknown, "three", "", 0),
            (UnknownKind::Unknown, "four", "", 0),
        ]);
        // Deny: still Undescribed.
        assert_eq!(check_promotion(reg.get("unk-001").unwrap()), Err(UnknownsError::NotResolved("unk-001".into())));
        // Deny: Undescribed even with a note — status not yet Unverified.
        assert_eq!(check_promotion(reg.get("unk-002").unwrap()), Err(UnknownsError::NotResolved("unk-002".into())));
        // Deny: Unverified is characterized but not confirmed.
        reg.set_status("unk-003", UnknownStatus::Unverified, "seen once").unwrap();
        assert_eq!(check_promotion(reg.get("unk-003").unwrap()), Err(UnknownsError::NotResolved("unk-003".into())));
        // Deny: Resolved but resolved with *no* characterization note.
        reg.set_status("unk-004", UnknownStatus::Resolved, "").unwrap();
        assert_eq!(check_promotion(reg.get("unk-004").unwrap()), Err(UnknownsError::NotResolved("unk-004".into())));
        // Deny: Resolved with a whitespace-only note.
        reg.set_status("unk-001", UnknownStatus::Resolved, "   ").unwrap();
        assert_eq!(check_promotion(reg.get("unk-001").unwrap()), Err(UnknownsError::NotResolved("unk-001".into())));
        // Allow: Resolved + non-empty note.
        reg.set_status("unk-002", UnknownStatus::Unverified, "characterized").unwrap();
        reg.set_status("unk-002", UnknownStatus::Resolved, "confirmed against two sources").unwrap();
        assert_eq!(check_promotion(reg.get("unk-002").unwrap()), Ok(()));
    }

    #[test]
    fn errors_display() {
        let e = UnknownsError::BadInput("title");
        assert!(e.to_string().contains("title"));
        assert_eq!(
            UnknownsError::UnknownId.to_string(),
            "unknown id: no entry with that id exists in the registry"
        );
        assert!(UnknownsError::BadTransition.to_string().contains("forward only"));
        assert_eq!(
            UnknownsError::BudgetExceeded { open: 5, max: 3 }.to_string(),
            "unknowns budget exceeded: 5 open, max 3"
        );
        assert!(UnknownsError::NotResolved("unk-007".into())
            .to_string()
            .contains("unk-007"));
        // Still an Error (audit-line interchangeable).
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn serde_roundtrip_entries_and_errors() {
        // Unknown round-trips with clear wire names.
        let mut reg = reg_with(&[
            (UnknownKind::OpenQuestion, "where does line 3 terminate?", "", 42),
            (UnknownKind::Gap, "coverage hole: night shift", "", 43),
        ]);
        reg.set_status("unk-001", UnknownStatus::Unverified, "characterized").unwrap();
        let u = reg.get("unk-001").unwrap();
        let j = serde_json::to_string(u).unwrap();
        assert!(j.contains("\"kind\":\"open_question\""));
        assert!(j.contains("\"status\":\"unverified\""));
        let back: Unknown = serde_json::from_str(&j).unwrap();
        assert_eq!(&back, u);

        // Registry round-trips including order and statuses.
        let rj = serde_json::to_string(&reg).unwrap();
        let rback: UnknownsRegistry = serde_json::from_str(&rj).unwrap();
        assert_eq!(rback, reg);
        assert_eq!(render_dossier(&rback), render_dossier(&reg));

        // Errors round-trip (wire form = variant name for error enums).
        for err in [
            UnknownsError::BadInput("title"),
            UnknownsError::UnknownId,
            UnknownsError::BadTransition,
            UnknownsError::BudgetExceeded { open: 5, max: 3 },
            UnknownsError::NotResolved("unk-007".into()),
        ] {
            let j = serde_json::to_string(&err).unwrap();
            let back: UnknownsError = serde_json::from_str(&j).unwrap();
            assert_eq!(back, err);
        }
        assert_eq!(
            serde_json::to_string(&UnknownsError::BudgetExceeded { open: 5, max: 3 }).unwrap(),
            "{\"BudgetExceeded\":{\"open\":5,\"max\":3}}"
        );
    }
}
