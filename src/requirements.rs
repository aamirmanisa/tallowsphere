//! Requirement objects + PIR / EEI templates — task A3.2.1 (dossier E7).
//!
//! A *requirement* is the standing question a collection / research run is
//! chartered to answer:
//! - a **PIR** (Priority Intelligence Requirement) — the decision owner's
//!   question, stated so that collection can be tasked against it;
//! - an **EEI** (Essential Element of Information) — the concrete, observable
//!   indicator whose collection answers (part of) a PIR. See
//!   [`eei_template`] for the framing note.
//!
//! This module is the *model* half of A3.2.1: typed requirement objects with
//! validated priority, two template constructors, and an append-only store
//! with one-shot expiry transitions. Persistence / tasking integration is
//! wired by the parent on top of the serde forms.
//!
//! # Frozen interface (batch 04, §7)
//! - [`ReqKind`] `{ Pir, Eei }`; [`Requirement`] `{ id, kind, question, owner,
//!   priority: u8 (1..=3 validated), created_ms, expires_ms: Option<i64>,
//!   status: Open | Expired | Retired }`;
//! - [`pir_template`] / [`eei_template`] — constructors for Open
//!   requirements;
//! - [`RequirementStore`] — `append` (unique id, validated), `expire_due`
//!   (marks + returns ids), `get`, `len`.
//!
//! # Semantics pinned here
//! - **Priority** is `1..=3`, where `1` is the highest (most urgent) and `3`
//!   is the lowest (standing) priority. Validation happens at
//!   [`RequirementStore::append`]; templates accept any `u8` and leave
//!   rejection to the store (a single validation point).
//! - **Template ids are deterministic**: `"<kind>-<16 hex chars>"` derived
//!   by FNV-1a over `(question, owner, created_ms)`. Identical inputs yield
//!   the identical id — the store's uniqueness check is what keeps the
//!   collection a set, so vary `created_ms` when re-issuing a like-worded
//!   requirement.
//! - **Expiry is one-shot**: `expires_ms = Some(t)` means the requirement is
//!   due at `now_ms >= t` (inclusive). [`RequirementStore::expire_due`]
//!   flips `Open → Expired` exactly once per requirement and returns the
//!   affected ids; a second call with the same clock returns nothing for
//!   already-expired ids. `expires_ms = None` never expires (a standing
//!   requirement must be explicitly [`RequirementStore::retire`]d).
//! - **Retired is terminal for collection**: retired requirements are never
//!   returned by `expire_due` and stay `Retired` (serde round-trips the
//!   state).


use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Lowest valid priority (`1` = highest / most urgent).
pub const MIN_PRIORITY: u8 = 1;
/// Highest valid priority (`3` = lowest / standing).
pub const MAX_PRIORITY: u8 = 3;

/// Which class of requirement this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReqKind {
    /// Priority Intelligence Requirement — the decision owner's question.
    Pir,
    /// Essential Element of Information — an observable indicator that
    /// answers (part of) a PIR.
    Eei,
}

impl ReqKind {
    /// Lowercase wire/display name (`"pir"` / `"eei"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ReqKind::Pir => "pir",
            ReqKind::Eei => "eei",
        }
    }

    /// Prefix used for deterministic template ids.
    pub fn id_prefix(&self) -> &'static str {
        match self {
            ReqKind::Pir => "pir-",
            ReqKind::Eei => "eei-",
        }
    }
}

impl fmt::Display for ReqKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle of a requirement. `Open → Expired` happens via
/// [`RequirementStore::expire_due`]; `Retired` is the explicit terminal
/// state (withdrawal by the owner), reachable via
/// [`RequirementStore::retire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReqStatus {
    /// Active — collection may be tasked against it.
    Open,
    /// `expires_ms` has passed (transition happened once).
    Expired,
    /// Withdrawn by the owner; terminal.
    Retired,
}

impl ReqStatus {
    /// Lowercase wire/display name (`"open"` / `"expired"` / `"retired"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ReqStatus::Open => "open",
            ReqStatus::Expired => "expired",
            ReqStatus::Retired => "retired",
        }
    }
}

impl fmt::Display for ReqStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single PIR or EEI requirement record (frozen field set, §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    /// Unique id (`"<kind>-<16 hex>"` for template-built records).
    pub id: String,
    /// PIR vs EEI.
    pub kind: ReqKind,
    /// The verbatim question the requirement asks.
    pub question: String,
    /// Owner accountable for answering the requirement.
    pub owner: String,
    /// `1..=3` (`1` highest… `3` lowest); validated at
    /// [`RequirementStore::append`].
    pub priority: u8,
    /// Creation timestamp, milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Due time in ms since the epoch; `None` = never expires.
    pub expires_ms: Option<i64>,
    /// Lifecycle status.
    pub status: ReqStatus,
}

impl Requirement {
    /// `true` while the requirement is [`ReqStatus::Open`].
    pub fn is_open(&self) -> bool {
        self.status == ReqStatus::Open
    }

    /// `true` if this requirement is Open and its expiry is due at
    /// `now_ms` (`expires_ms <= now_ms`, inclusive).
    pub fn is_expired_at(&self, now_ms: i64) -> bool {
        self.is_open() && self.expires_ms.is_some_and(|t| t <= now_ms)
    }
}

/// Errors from requirement validation / store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReqError {
    /// Priority outside `1..=3` (the offending value is carried).
    InvalidPriority(u8),
    /// A requirement with this id is already in the store.
    DuplicateId(String),
    /// A required text field was empty / whitespace-only (field name.
    EmptyField(&'static str),
    /// Operation addressed an id the store does not hold.
    UnknownId(String),
}

impl fmt::Display for ReqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReqError::InvalidPriority(p) => write!(
                f,
                "invalid priority {p}: must be in {MIN_PRIORITY}..={MAX_PRIORITY}"
            ),
            ReqError::DuplicateId(id) => write!(f, "duplicate requirement id: {id}"),
            ReqError::EmptyField(field) => write!(f, "empty required field: {field}"),
            ReqError::UnknownId(id) => write!(f, "unknown requirement id: {id}"),
        }
    }
}

impl std::error::Error for ReqError {}

/// FNV-1a over `(question, 0x1f, owner, created_ms[le])` — the deterministic
/// template id seed. No external deps; stable across runs and platforms.
fn fnv1a64(question: &str, owner: &str, created_ms: i64) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
    };
    mix(question.as_bytes());
    mix(&[0x1f]);
    mix(owner.as_bytes());
    mix(&created_ms.to_le_bytes());
    h
}

/// Shared builder for the two templates: deterministic content-addressed id,
/// `expires_ms = None`, `status = Open`.
fn template(
    kind: ReqKind,
    question: String,
    owner: String,
    priority: u8,
    created_ms: i64,
) -> Requirement {
    let id = format!(
        "{}{:016x}",
        kind.id_prefix(),
        fnv1a64(&question, &owner, created_ms)
    );
    Requirement {
        id,
        kind,
        question,
        owner,
        priority,
        created_ms,
        expires_ms: None,
        status: ReqStatus::Open,
    }
}

/// Build a PIR (Priority Intelligence Requirement) template record.
///
/// The question is stored verbatim; the caller states the standing
/// intelligence question the decision owner needs answered. Returns an
/// `Open` requirement with a deterministic id (`"pir-<16 hex>"`), no expiry
/// (`expires_ms = None`), and `priority` as passed — range validation happens
/// at [`RequirementStore::append`] (single validation point), where `1` is
/// the highest priority.
pub fn pir_template(
    question: impl Into<String>,
    owner: impl Into<String>,
    priority: u8,
    created_ms: i64,
) -> Requirement {
    template(ReqKind::Pir, question.into(), owner.into(), priority, created_ms)
}

/// Build an EEI (Essential Element of Information) template record.
///
/// **EEI framing note.** An EEI is the decision-oriented refinement of a PIR:
/// where the PIR states the standing question ("what do we need to know about
/// X?"), each EEI states a concrete, observable indicator that — once
/// collected — answers (part of) that PIR ("who owns domain Y?", "which
/// endpoint serves the staging portal?", "what certificate fronts it?"). The
/// template records that framing via [`ReqKind::Eei`] and otherwise shares
/// the PIR template's exact shape (verbatim question, deterministic
/// `"eei-<16 hex>"` id, no expiry, priority as passed). The caller is
/// expected to phrase `question` as a specific observable with an
/// identifiable collection source. EEIs are not yet hierarchical — a future
/// revision may carry a parent-PIR field; that is deliberately not modeled
/// until a frozen vocabulary exists.
///
/// Same signature and defaults as [`pir_template`].
pub fn eei_template(
    question: impl Into<String>,
    owner: impl Into<String>,
    priority: u8,
    created_ms: i64,
) -> Requirement {
    template(ReqKind::Eei, question.into(), owner.into(), priority, created_ms)
}

/// Append-only in-memory store of requirements, keyed by unique id.
///
/// Insertion goes through [`RequirementStore::append`] only: it validates
/// priority (`1..=3`), rejects empty `id` / `question` / `owner`, and
/// enforces id uniqueness. Expiry transitions are one-shot
/// ([`RequirementStore::expire_due`]). The store serde-round-trips as a
/// transparent map of id → [`Requirement`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequirementStore {
    by_id: BTreeMap<String, Requirement>,
}

impl RequirementStore {
    /// Empty store.
    pub fn new() -> Self {
        RequirementStore {
            by_id: BTreeMap::new(),
        }
    }

    /// Validate and insert `r`. Returns:
    /// - [`ReqError::InvalidPriority`] if `r.priority` is outside `1..=3`;
    /// - [`ReqError::EmptyField`] if `id` / `question` / `owner` is empty or
    ///   whitespace-only;
    /// - [`ReqError::DuplicateId`] if the id is already present.
    ///
    /// On any error the store is left unchanged.
    pub fn append(&mut self, r: Requirement) -> Result<(), ReqError> {
        if !(MIN_PRIORITY..=MAX_PRIORITY).contains(&r.priority) {
            return Err(ReqError::InvalidPriority(r.priority));
        }
        if r.id.trim().is_empty() {
            return Err(ReqError::EmptyField("id"));
        }
        if r.question.trim().is_empty() {
            return Err(ReqError::EmptyField("question"));
        }
        if r.owner.trim().is_empty() {
            return Err(ReqError::EmptyField("owner"));
        }
        if self.by_id.contains_key(&r.id) {
            return Err(ReqError::DuplicateId(r.id));
        }
        self.by_id.insert(r.id.clone(), r);
        Ok(())
    }

    /// Mark every `Open` requirement whose `expires_ms <= now_ms` (inclusive)
    /// as `Expired` and return the affected ids (ascending, deterministic).
    ///
    /// One-shot: a requirement transitions at most once, so calling again
    /// with the same or a later clock returns nothing for ids already
    /// returned. `Retired` requirements are never touched; `None` expiry
    /// never expires.
    pub fn expire_due(&mut self, now_ms: i64) -> Vec<String> {
        let mut expired = Vec::new();
        for r in self.by_id.values_mut() {
            if r.status == ReqStatus::Open {
                if let Some(t) = r.expires_ms {
                    if t <= now_ms {
                        r.status = ReqStatus::Expired;
                        expired.push(r.id.clone());
                    }
                }
            }
        }
        expired
    }

    /// Look a requirement up by id.
    pub fn get(&self, id: &str) -> Option<&Requirement> {
        self.by_id.get(id)
    }

    /// Number of requirements held.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// `true` if no requirements are held.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Iterate requirements in ascending id order.
    pub fn iter(&self) -> impl Iterator<Item = &Requirement> {
        self.by_id.values()
    }

    /// Withdraw a requirement: sets `status = Retired` (terminal; never
    /// expires afterwards). Idempotent for an already-retired id; errors
    /// with [`ReqError::UnknownId`] if the id is not held.
    ///
    /// Delta vs §7: not named in the frozen list, added so the `Retired`
    /// status is reachable through the store (otherwise it is unreachable
    /// and collection withdrawal cannot be expressed).
    pub fn retire(&mut self, id: &str) -> Result<(), ReqError> {
        match self.by_id.get_mut(id) {
            Some(r) => {
                r.status = ReqStatus::Retired;
                Ok(())
            }
            None => Err(ReqError::UnknownId(id.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(id: &str, priority: u8) -> Requirement {
        Requirement {
            id: id.to_string(),
            kind: ReqKind::Pir,
            question: format!("question {id}"),
            owner: "owner".to_string(),
            priority,
            created_ms: 1_000,
            expires_ms: None,
            status: ReqStatus::Open,
        }
    }

    #[test]
    fn pir_template_fields() {
        let r = pir_template("Who operates AS64500?", "leo", 2, 1_700_000_000_000);
        assert_eq!(r.kind, ReqKind::Pir);
        assert_eq!(r.question, "Who operates AS64500?");
        assert_eq!(r.owner, "leo");
        assert_eq!(r.priority, 2);
        assert_eq!(r.created_ms, 1_700_000_000_000);
        assert_eq!(r.expires_ms, None);
        assert_eq!(r.status, ReqStatus::Open);
        assert!(r.is_open());
        assert!(r.id.starts_with("pir-"), "id was {}", r.id);
        // "pir-" + 16 hex chars
        assert_eq!(r.id.len(), 4 + 16);
        assert!(r.id[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn eei_template_fields() {
        let r = eei_template("Which cert fronts the staging portal?", "ops", 3, 42);
        assert_eq!(r.kind, ReqKind::Eei);
        assert_eq!(r.question, "Which cert fronts the staging portal?");
        assert_eq!(r.owner, "ops");
        assert_eq!(r.priority, 3);
        assert_eq!(r.created_ms, 42);
        assert_eq!(r.expires_ms, None);
        assert_eq!(r.status, ReqStatus::Open);
        assert!(r.id.starts_with("eei-"), "id was {}", r.id);
        assert_eq!(r.id.len(), 4 + 16);

        // Pir/eei of the same question differ by kind + id prefix.
        let p = pir_template("Which cert fronts the staging portal?", "ops", 3, 42);
        assert_ne!(p.id, r.id);
        assert_eq!(p.id[4..], r.id[4..], "same content, same hash body");
    }

    #[test]
    fn template_ids_deterministic_and_distinct() {
        let a = pir_template("q", "o", 1, 10);
        let b = pir_template("q", "o", 1, 10);
        assert_eq!(a.id, b.id, "identical inputs -> identical id");
        assert_eq!(a, b);

        // Any field change moves the id.
        assert_ne!(a.id, pir_template("q!", "o", 1, 10).id);
        assert_ne!(a.id, pir_template("q", "o2", 1, 10).id);
        assert_ne!(a.id, pir_template("q", "o", 1, 11).id);
        // Priority is NOT part of the identity.
        assert_eq!(a.id, pir_template("q", "o", 3, 10).id);
    }

    #[test]
    fn priority_validation() {
        let mut store = RequirementStore::new();
        for p in MIN_PRIORITY..=MAX_PRIORITY {
            store.append(mk(&format!("ok-{p}"), p)).unwrap();
        }
        assert_eq!(store.len(), 3);

        assert_eq!(
            store.append(mk("low", 0)),
            Err(ReqError::InvalidPriority(0))
        );
        assert_eq!(
            store.append(mk("high", 4)),
            Err(ReqError::InvalidPriority(4))
        );
        assert_eq!(store.len(), 3, "rejected appends left store unchanged");
    }

    #[test]
    fn append_rejects_duplicate_id() {
        let mut store = RequirementStore::new();
        store.append(mk("dup", 1)).unwrap();
        assert_eq!(
            store.append(mk("dup", 2)),
            Err(ReqError::DuplicateId("dup".to_string()))
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn append_rejects_empty_fields() {
        let mut store = RequirementStore::new();

        let mut empty_id = mk("x", 1);
        empty_id.id = "  ".to_string();
        assert_eq!(store.append(empty_id), Err(ReqError::EmptyField("id")));

        let mut empty_q = mk("y", 1);
        empty_q.question = String::new();
        assert_eq!(store.append(empty_q), Err(ReqError::EmptyField("question")));

        let mut empty_o = mk("z", 1);
        empty_o.owner = " \t ".to_string();
        assert_eq!(store.append(empty_o), Err(ReqError::EmptyField("owner")));

        assert_eq!(store.len(), 0);
    }

    #[test]
    fn expire_due_transitions_once_and_is_idempotent() {
        let mut store = RequirementStore::new();

        let mut a = mk("a", 1);
        a.expires_ms = Some(2_000);
        let mut b = mk("b", 1);
        b.expires_ms = Some(5_000);
        let c = mk("c", 1); // expires_ms = None -> standing

        store.append(a).unwrap();
        store.append(b).unwrap();
        store.append(c).unwrap();

        // Before due: nothing.
        assert_eq!(store.expire_due(1_999), Vec::<String>::new());

        // At the boundary (inclusive) `a` is due; `c` never expires.
        assert_eq!(store.expire_due(2_000), vec!["a".to_string()]);
        assert_eq!(store.get("a").unwrap().status, ReqStatus::Expired);
        assert_eq!(store.get("c").unwrap().status, ReqStatus::Open);

        // Second call: `a` already transitioned -> idempotent, no re-report.
        assert_eq!(store.expire_due(2_000), Vec::<String>::new());
        assert_eq!(store.expire_due(4_999), Vec::<String>::new());

        // `b` comes due later; both `b` and `c` remain either due-once or never.
        assert_eq!(store.expire_due(5_000), vec!["b".to_string()]);
        assert_eq!(store.expire_due(1_000_000), Vec::<String>::new());
        assert_eq!(store.get("c").unwrap().status, ReqStatus::Open);
    }

    #[test]
    fn expire_due_returns_all_due_ids_sorted() {
        let mut store = RequirementStore::new();
        for (id, t) in [("z", 10), ("m", 10), ("a", 10)] {
            let mut r = mk(id, 2);
            r.expires_ms = Some(t);
            store.append(r).unwrap();
        }
        // BTreeMap order -> deterministic ascending ids.
        assert_eq!(
            store.expire_due(10),
            vec!["a".to_string(), "m".to_string(), "z".to_string()]
        );
    }

    #[test]
    fn retire_is_terminal_and_reachable() {
        let mut store = RequirementStore::new();
        store.append(mk("r", 1)).unwrap();

        store.retire("r").unwrap();
        assert_eq!(store.get("r").unwrap().status, ReqStatus::Retired);

        // Retired is idempotent and never expires (even if it had a due time).
        let mut s = mk("s", 1);
        s.expires_ms = Some(1);
        store.append(s).unwrap();
        store.retire("s").unwrap();
        assert_eq!(store.expire_due(1_000_000), Vec::<String>::new());
        assert_eq!(store.get("s").unwrap().status, ReqStatus::Retired);

        // Unknown id is an error, store unchanged.
        assert_eq!(
            store.retire("nope"),
            Err(ReqError::UnknownId("nope".to_string()))
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn get_len_iter() {
        let mut store = RequirementStore::new();
        assert!(store.is_empty());
        assert_eq!(store.get("missing"), None);

        store.append(mk("b", 2)).unwrap();
        store.append(mk("a", 3)).unwrap();
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert_eq!(store.get("a").unwrap().priority, 3);
        let ids: Vec<&str> = store.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"], "iteration is ascending by id");
    }

    #[test]
    fn serde_round_trip_requirement_and_store() {
        // Requirement round-trip.
        let r = eei_template("Which cert fronts the staging portal?", "ops", 3, 42);
        let j = serde_json::to_string(&r).unwrap();
        let back: Requirement = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);

        // Wire names are snake_case.
        assert_eq!(serde_json::to_string(&ReqKind::Pir).unwrap(), "\"pir\"");
        assert_eq!(serde_json::to_string(&ReqKind::Eei).unwrap(), "\"eei\"");
        assert_eq!(serde_json::to_string(&ReqStatus::Open).unwrap(), "\"open\"");
        assert_eq!(
            serde_json::to_string(&ReqStatus::Expired).unwrap(),
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&ReqStatus::Retired).unwrap(),
            "\"retired\""
        );

        // Store round-trip preserves records AND expiry behavior.
        let mut store = RequirementStore::new();
        let mut due = pir_template("due question", "o", 1, 100);
        due.id = "due".to_string();
        due.expires_ms = Some(500);
        let mut standing = pir_template("standing question", "o", 2, 100);
        standing.id = "standing".to_string();
        store.append(r.clone()).unwrap();
        store.append(due).unwrap();
        store.append(standing).unwrap();

        let sj = serde_json::to_string(&store).unwrap();
        let mut back_store: RequirementStore = serde_json::from_str(&sj).unwrap();
        assert_eq!(back_store, store);
        assert_eq!(back_store.len(), 3);
        assert_eq!(back_store.get(&r.id).unwrap(), &r);

        // Transitions still work after the round-trip, one-shot.
        assert_eq!(back_store.expire_due(500), vec!["due".to_string()]);
        assert_eq!(back_store.expire_due(500), Vec::<String>::new());
        assert_eq!(back_store.get("standing").unwrap().status, ReqStatus::Open);
    }

    #[test]
    fn error_display_mentions_offending_value() {
        assert!(ReqError::InvalidPriority(7).to_string().contains('7'));
        assert!(ReqError::DuplicateId("x".into()).to_string().contains('x'));
        assert!(ReqError::EmptyField("owner").to_string().contains("owner"));
        assert!(ReqError::UnknownId("gone".into()).to_string().contains("gone"));
    }
}
