//! Cross-collection reunification index (task B6.1 · frozen interface §5 ·
//! B6.1.1–B6.1.3).
//!
//! Intelligence collected across separate runs arrives in separate identifier
//! spaces: run-scoped numbers, ad-hoc slugs, hand-renamed files. This module is
//! the deterministic bookkeeping layer that gives every artifact ONE stable
//! identity and one flat, renderable catalog, so the same item found twice —
//! or split across two runs — can be *reunified* instead of duplicated:
//!
//! * [`PersistentId`] + [`PersistentId::key`] + [`PersistentId::validate`]
//!   (B6.1.1) — the persistent-ID scheme. An id is the pair
//!   `(namespace, local_id)`; its canonical key is `namespace:local_id`.
//! * [`CatalogItem`] + [`ReunificationIndex::build`] /
//!   [`ReunificationIndex::insert`] / [`ReunificationIndex::runs`] /
//!   [`ReunificationIndex::for_run`] (B6.1.2) — the cross-run catalog:
//!   validated inserts, duplicate-refusing, run-partitionable.
//! * [`ReunificationIndex::render_catalog`] +
//!   [`ReunificationIndex::with_rights`] + [`ReunificationIndex::get`]
//!   (B6.1.3) — the virtual catalog: a deterministic markdown rendering plus
//!   the rights-link filter (`rights:` field, `unset` marker).
//!
//! # Documented rules (spec silent; conservative reading chosen)
//!
//! * **Key grammar.** `key()` is `format!("{namespace}:{local_id}")` — ONE
//!   colon, always. [`PersistentId::validate`] therefore refuses empty parts
//!   and any `:` *inside* a part: a colon inside a part would smuggle a second
//!   separator into the key and make two different pairs collapse onto one
//!   string. Check order is pinned: `namespace` before `local_id`, so a pair
//!   that is bad on both sides reports `BadInput("namespace")`.
//! * **Validation order in `build`/`insert`.**
//!   [`CatalogItem`] is checked as: `pid` → `title` → `source_run` →
//!   `locator` → duplicate-key. The FIRST refusal wins, so callers get the
//!   same error every time for the same input. Empty-string fields are
//!   refused; whitespace-only strings are NOT special-cased (the spec names
//!   only "empty" — no trimming is invented here).
//! * **Duplicate policy.** Duplicate detection is by full key, never by
//!   `local_id` alone: the *namespace is the disambiguator*. The same
//!   `local_id` under two different namespaces is two legitimate items (pinned
//!   in tests); the same key twice is `DupId`. A failed `insert` leaves the
//!   index byte-for-byte unchanged.
//! * **`get` is a pure lookup.** Items in the index always carry validated
//!   pids (construction invariant), so `get` searches by key without
//!   re-validating its argument: a malformed pid simply cannot match and
//!   reports `Unknown` — consistent with "not present".
//! * **Rights presence is `Some(_)`.** [`ReunificationIndex::with_rights`]
//!   keeps every item with `rights.is_some()` (the spec validates only
//!   `title`/`source_run`/`locator`, so an empty-string rights statement is
//!   still *a* rights statement). `render_catalog` prints
//!   `rights:<value>` for `Some`, `rights:unset` for `None`.
//! * **Render byte layout.** `render_catalog` emits the counts header
//!   `catalog: <N> items across <M> runs`, then one row per item sorted by
//!   pid key,
//!   `- <key> | <title> | <run> | rights:<rights|unset> | <locator>`,
//!   lines joined by `\n` with a trailing `\n` (so the empty index renders as
//!   `"catalog: 0 items across 0 runs\n"`). Exact strings are pinned in tests;
//!   the output is a pure function of the item set (order-independent).
//! * **Error serde (repo precedent).** [`IndexError`] carries a
//!   `&'static str`, so it derives `Serialize` only — `BadInput` serialises
//!   as `{"BadInput":"…"}`, unit variants as `"DupId"` / `"Unknown"` (see
//!   `ach_matrix.rs` / `decay_model.rs` for the same convention).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A persistent identifier for a catalogued artifact (B6.1.1).
///
/// The pair is the identity; [`PersistentId::key`] is its canonical
/// string form. Two ids are the same item iff their keys are equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentId {
    /// The identifier space the item was minted in (e.g. a run, a corpus, an
    /// issuing organisation). Must be non-empty and contain no `:`.
    pub namespace: String,
    /// The identifier within the namespace. Must be non-empty and contain no
    /// `:`. The same `local_id` under different namespaces denotes different
    /// items.
    pub local_id: String,
}

impl PersistentId {
    /// Canonical key: `namespace:local_id`.
    ///
    /// Formatting is unconditional (the single-colon invariant is enforced by
    /// [`PersistentId::validate`], not by this method), so `key()` is TOTAL
    /// and deterministic for every value of the struct.
    pub fn key(&self) -> String {
        format!("{}:{}", self.namespace, self.local_id)
    }

    /// Validate the id for use as a catalog key.
    ///
    /// Refusals, in pinned order: empty `namespace` → `BadInput("namespace")`;
    /// empty `local_id` → `BadInput("local_id")`; `:` in `namespace` →
    /// `BadInput("namespace")`; `:` in `local_id` → `BadInput("local_id")`.
    pub fn validate(&self) -> Result<(), IndexError> {
        if self.namespace.is_empty() || self.namespace.contains(':') {
            return Err(IndexError::BadInput("namespace"));
        }
        if self.local_id.is_empty() || self.local_id.contains(':') {
            return Err(IndexError::BadInput("local_id"));
        }
        Ok(())
    }
}

/// One catalogued artifact: its persistent id, display metadata, the run it
/// was collected in, an optional rights statement, and a locator (B6.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogItem {
    /// The item's persistent identity.
    pub pid: PersistentId,
    /// Human-readable title. Must be non-empty.
    pub title: String,
    /// The collection run this item came from. Must be non-empty.
    pub source_run: String,
    /// Optional rights/licence string. `None` renders as `unset`.
    pub rights: Option<String>,
    /// Where the item lives (path, URL, handle). Must be non-empty.
    pub locator: String,
}

impl CatalogItem {
    /// Field validation in pinned order: `pid` → `title` → `source_run` →
    /// `locator`. (Duplicate-key checking happens in the index, not here.)
    fn validate(&self) -> Result<(), IndexError> {
        self.pid.validate()?;
        if self.title.is_empty() {
            return Err(IndexError::BadInput("title"));
        }
        if self.source_run.is_empty() {
            return Err(IndexError::BadInput("source_run"));
        }
        if self.locator.is_empty() {
            return Err(IndexError::BadInput("locator"));
        }
        Ok(())
    }
}

/// The cross-run reunification catalog (B6.1.2/B6.1.3).
///
/// Holds validated [`CatalogItem`]s with unique pid keys. Construction goes
/// through [`ReunificationIndex::build`] or [`ReunificationIndex::insert`];
/// reads are `&self` and deterministic (all list-returning accessors sort by
/// pid key, so results never depend on insertion order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReunificationIndex {
    items: Vec<CatalogItem>,
}

impl ReunificationIndex {
    /// Build an index from items, validating each exactly as
    /// [`ReunificationIndex::insert`] does. The first refusal aborts the
    /// build (no partial index is returned).
    pub fn build(items: Vec<CatalogItem>) -> Result<ReunificationIndex, IndexError> {
        let mut index = ReunificationIndex { items: Vec::new() };
        for item in items {
            index.insert(item)?;
        }
        Ok(index)
    }

    /// Insert one item. Validates [`CatalogItem::validate`]'s fields in pinned
    /// order, then refuses a key already present with `DupId`. On any error
    /// the index is left unchanged.
    pub fn insert(&mut self, item: CatalogItem) -> Result<(), IndexError> {
        item.validate()?;
        let key = item.pid.key();
        if self.items.iter().any(|existing| existing.pid.key() == key) {
            return Err(IndexError::DupId);
        }
        self.items.push(item);
        Ok(())
    }

    /// Sorted, de-duplicated list of the `source_run`s represented in the
    /// index (B6.1.2: cross-run partition).
    pub fn runs(&self) -> Vec<String> {
        let mut runs: Vec<String> = self.items.iter().map(|i| i.source_run.clone()).collect();
        runs.sort();
        runs.dedup();
        runs
    }

    /// All items collected in `run`, sorted by pid key. Unknown run → empty
    /// vec.
    pub fn for_run(&self, run: &str) -> Vec<&CatalogItem> {
        let mut found: Vec<&CatalogItem> = self
            .items
            .iter()
            .filter(|i| i.source_run == run)
            .collect();
        found.sort_by(|a, b| a.pid.key().cmp(&b.pid.key()));
        found
    }

    /// Deterministic virtual-catalog rendering (B6.1.3).
    ///
    /// Byte layout (pinned in tests): the counts header
    /// `catalog: <N> items across <M> runs`, then one line per item sorted by
    /// pid key —
    /// `- <key> | <title> | <run> | rights:<rights|unset> | <locator>` —
    /// joined by `\n` with a trailing `\n`.
    pub fn render_catalog(&self) -> String {
        let mut rows: Vec<&CatalogItem> = self.items.iter().collect();
        rows.sort_by(|a, b| a.pid.key().cmp(&b.pid.key()));
        let mut out = format!(
            "catalog: {} items across {} runs\n",
            self.items.len(),
            self.runs().len()
        );
        for item in rows {
            out.push_str(&format!(
                "- {} | {} | {} | rights:{} | {}\n",
                item.pid.key(),
                item.title,
                item.source_run,
                item.rights.as_deref().unwrap_or("unset"),
                item.locator
            ));
        }
        out
    }

    /// Items carrying a rights statement (`rights.is_some()`), sorted by pid
    /// key. The rights *links* view of the catalog (B6.1.3).
    pub fn with_rights(&self) -> Vec<&CatalogItem> {
        let mut found: Vec<&CatalogItem> =
            self.items.iter().filter(|i| i.rights.is_some()).collect();
        found.sort_by(|a, b| a.pid.key().cmp(&b.pid.key()));
        found
    }

    /// Look up one item by persistent id. Absent (or malformed) id →
    /// `Unknown`; see the module docs for why no re-validation happens here.
    pub fn get(&self, pid: &PersistentId) -> Result<&CatalogItem, IndexError> {
        let key = pid.key();
        self.items
            .iter()
            .find(|i| i.pid.key() == key)
            .ok_or(IndexError::Unknown)
    }
}

/// Refusals from the reunification index.
///
/// `Serialize`-only (carries `&'static str`; repo precedent): `BadInput`
/// serialises as `{"BadInput":"…"}`, unit variants as `"DupId"` / `"Unknown"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IndexError {
    /// A named field is empty or (for pid parts) contains `:`.
    BadInput(&'static str),
    /// The pid key is already present in the index.
    DupId,
    /// No item with that pid key is present.
    Unknown,
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexError::BadInput(field) => write!(f, "invalid input: {field}"),
            IndexError::DupId => write!(f, "duplicate id"),
            IndexError::Unknown => write!(f, "unknown id"),
        }
    }
}

impl std::error::Error for IndexError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(ns: &str, local: &str) -> PersistentId {
        PersistentId {
            namespace: ns.into(),
            local_id: local.into(),
        }
    }

    fn item(ns: &str, local: &str, title: &str, run: &str, rights: Option<&str>) -> CatalogItem {
        CatalogItem {
            pid: pid(ns, local),
            title: title.into(),
            source_run: run.into(),
            rights: rights.map(Into::into),
            locator: format!("loc:{ns}/{local}"),
        }
    }

    // ---- B6.1.1 · key + validation -------------------------------------

    #[test]
    fn key_is_namespace_colon_local_id() {
        assert_eq!(pid("corpus-a", "0007").key(), "corpus-a:0007");
        assert_eq!(pid("run-2", "x/y").key(), "run-2:x/y");
    }

    #[test]
    fn validate_accepts_typical_parts() {
        assert_eq!(pid("corpus-a", "0007").validate(), Ok(()));
        assert_eq!(pid("n", "l").validate(), Ok(()));
        // single colon only: slash, space and unicode are all legal parts
        assert_eq!(pid("a/b c", "ü:no").validate(), Err(IndexError::BadInput("local_id")));
        assert_eq!(pid("a/b c", "ünïcode").validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_empty_namespace() {
        assert_eq!(
            pid("", "local").validate(),
            Err(IndexError::BadInput("namespace"))
        );
    }

    #[test]
    fn validate_rejects_empty_local_id() {
        assert_eq!(
            pid("ns", "").validate(),
            Err(IndexError::BadInput("local_id"))
        );
    }

    #[test]
    fn validate_rejects_colon_in_namespace() {
        assert_eq!(
            pid("a:b", "local").validate(),
            Err(IndexError::BadInput("namespace"))
        );
    }

    #[test]
    fn validate_rejects_colon_in_local_id() {
        assert_eq!(
            pid("ns", "a:b").validate(),
            Err(IndexError::BadInput("local_id"))
        );
    }

    #[test]
    fn validate_checks_namespace_before_local_id() {
        // bad on both sides -> the pinned first refusal wins
        assert_eq!(
            pid("", "").validate(),
            Err(IndexError::BadInput("namespace"))
        );
        assert_eq!(
            pid("a:b", "").validate(),
            Err(IndexError::BadInput("namespace"))
        );
    }

    // ---- B6.1.2 · build + insert ---------------------------------------

    #[test]
    fn build_accepts_wellformed_items() {
        let idx = ReunificationIndex::build(vec![
            item("run-a", "1", "first", "run-a", None),
            item("run-b", "2", "second", "run-b", Some("CC-BY-4.0")),
        ])
        .unwrap();
        assert_eq!(idx.runs(), vec!["run-a".to_string(), "run-b".to_string()]);
        assert_eq!(idx.for_run("run-a").len(), 1);
    }

    #[test]
    fn build_accepts_empty_input() {
        let idx = ReunificationIndex::build(vec![]).unwrap();
        assert!(idx.runs().is_empty());
        assert_eq!(idx.render_catalog(), "catalog: 0 items across 0 runs\n");
    }

    #[test]
    fn build_rejects_empty_title() {
        let bad = CatalogItem {
            title: String::new(),
            ..item("ns", "1", "t", "run", None)
        };
        assert_eq!(
            ReunificationIndex::build(vec![bad]),
            Err(IndexError::BadInput("title"))
        );
    }

    #[test]
    fn build_rejects_empty_source_run() {
        let bad = CatalogItem {
            source_run: String::new(),
            ..item("ns", "1", "t", "run", None)
        };
        assert_eq!(
            ReunificationIndex::build(vec![bad]),
            Err(IndexError::BadInput("source_run"))
        );
    }

    #[test]
    fn build_rejects_empty_locator() {
        let bad = CatalogItem {
            locator: String::new(),
            ..item("ns", "1", "t", "run", None)
        };
        assert_eq!(
            ReunificationIndex::build(vec![bad]),
            Err(IndexError::BadInput("locator"))
        );
    }

    #[test]
    fn build_rejects_invalid_pid_first() {
        // pid is checked before the metadata fields
        let bad = CatalogItem {
            title: String::new(),
            ..item("", "1", "t", "", None)
        };
        assert_eq!(
            ReunificationIndex::build(vec![bad]),
            Err(IndexError::BadInput("namespace"))
        );
    }

    #[test]
    fn build_rejects_duplicate_pid() {
        let dup = ReunificationIndex::build(vec![
            item("ns", "1", "one", "run-a", None),
            item("ns", "1", "one again", "run-b", None),
        ]);
        assert_eq!(dup, Err(IndexError::DupId));
    }

    #[test]
    fn build_rejects_duplicate_pid_later_in_input() {
        let dup = ReunificationIndex::build(vec![
            item("ns", "1", "one", "run-a", None),
            item("ns", "2", "two", "run-a", None),
            item("ns", "2", "two again", "run-b", None),
        ]);
        assert_eq!(dup, Err(IndexError::DupId));
    }

    #[test]
    fn insert_rejects_duplicate_and_leaves_index_unchanged() {
        let mut idx = ReunificationIndex::build(vec![item("ns", "1", "one", "run-a", None)]).unwrap();
        let before = idx.render_catalog();
        assert_eq!(
            idx.insert(item("ns", "1", "clash", "run-b", Some("x"))),
            Err(IndexError::DupId)
        );
        assert_eq!(idx.render_catalog(), before);
    }

    #[test]
    fn insert_rejects_invalid_item_and_leaves_index_unchanged() {
        let mut idx = ReunificationIndex::build(vec![item("ns", "1", "one", "run-a", None)]).unwrap();
        let bad = CatalogItem {
            locator: String::new(),
            ..item("ns", "2", "two", "run-a", None)
        };
        assert_eq!(idx.insert(bad), Err(IndexError::BadInput("locator")));
        assert_eq!(idx.for_run("run-a").len(), 1);
    }

    #[test]
    fn insert_accepts_new_key() {
        let mut idx = ReunificationIndex::default();
        assert_eq!(idx.insert(item("ns", "1", "one", "run-a", None)), Ok(()));
        assert_eq!(idx.insert(item("ns", "2", "two", "run-a", None)), Ok(()));
        assert_eq!(idx.for_run("run-a").len(), 2);
    }

    // ---- namespace disambiguation (pinned) -----------------------------

    #[test]
    fn same_local_id_under_different_namespaces_both_allowed() {
        // The namespace is the disambiguator: identical local_id, two items.
        let idx = ReunificationIndex::build(vec![
            item("alpha", "007", "alpha seven", "run-a", None),
            item("beta", "007", "beta seven", "run-b", Some("internal")),
        ])
        .unwrap();
        assert_eq!(idx.for_run("run-a")[0].pid.key(), "alpha:007");
        assert_eq!(idx.for_run("run-b")[0].pid.key(), "beta:007");
        assert_eq!(
            idx.get(&pid("alpha", "007")).unwrap().title,
            "alpha seven"
        );
        assert_eq!(
            idx.get(&pid("beta", "007")).unwrap().title,
            "beta seven"
        );
    }

    #[test]
    fn same_local_id_same_namespace_is_a_duplicate() {
        let dup = ReunificationIndex::build(vec![
            item("alpha", "007", "one", "run-a", None),
            item("alpha", "007", "two", "run-b", None),
        ]);
        assert_eq!(dup, Err(IndexError::DupId));
    }

    #[test]
    fn colon_in_pid_part_is_refused_at_insert() {
        let mut idx = ReunificationIndex::default();
        assert_eq!(
            idx.insert(item("a:b", "1", "t", "run", None)),
            Err(IndexError::BadInput("namespace"))
        );
        assert_eq!(
            idx.insert(item("ns", "a:b", "t", "run", None)),
            Err(IndexError::BadInput("local_id"))
        );
    }

    // ---- runs + for_run -------------------------------------------------

    #[test]
    fn runs_are_sorted_and_unique() {
        let idx = ReunificationIndex::build(vec![
            item("ns", "3", "three", "run-b", None),
            item("ns", "1", "one", "run-a", None),
            item("ns", "2", "two", "run-b", None),
        ])
        .unwrap();
        assert_eq!(idx.runs(), vec!["run-a".to_string(), "run-b".to_string()]);
    }

    #[test]
    fn for_run_filters_and_sorts_by_pid_key() {
        let idx = ReunificationIndex::build(vec![
            item("ns", "9", "nine", "run-a", None),
            item("ns", "1", "one", "run-a", None),
            item("other", "0", "zero", "run-a", None),
            item("ns", "5", "five", "run-b", None),
        ])
        .unwrap();
        let keys: Vec<String> = idx
            .for_run("run-a")
            .iter()
            .map(|i| i.pid.key())
            .collect();
        assert_eq!(keys, vec!["ns:1", "ns:9", "other:0"]);
    }

    #[test]
    fn for_run_unknown_run_is_empty() {
        let idx =
            ReunificationIndex::build(vec![item("ns", "1", "one", "run-a", None)]).unwrap();
        assert!(idx.for_run("no-such-run").is_empty());
    }

    // ---- B6.1.3 · render ------------------------------------------------

    #[test]
    fn render_catalog_exact_pin() {
        let idx = ReunificationIndex::build(vec![
            item("beta", "2", "Second", "run-b", Some("CC-BY-4.0")),
            item("alpha", "1", "First", "run-a", None),
        ])
        .unwrap();
        assert_eq!(
            idx.render_catalog(),
            "catalog: 2 items across 2 runs\n\
             - alpha:1 | First | run-a | rights:unset | loc:alpha/1\n\
             - beta:2 | Second | run-b | rights:CC-BY-4.0 | loc:beta/2\n"
        );
    }

    #[test]
    fn render_catalog_header_counts_items_and_runs() {
        let idx = ReunificationIndex::build(vec![
            item("ns", "1", "one", "run-a", None),
            item("ns", "2", "two", "run-a", None),
            item("ns", "3", "three", "run-b", None),
        ])
        .unwrap();
        let rendered = idx.render_catalog();
        assert!(rendered.starts_with("catalog: 3 items across 2 runs\n"));
        assert_eq!(rendered.lines().count(), 4); // header + 3 rows
    }

    #[test]
    fn render_catalog_marks_missing_rights_unset() {
        let idx = ReunificationIndex::build(vec![
            item("ns", "1", "no rights", "run-a", None),
            item("ns", "2", "has rights", "run-a", Some("internal-only")),
        ])
        .unwrap();
        let rendered = idx.render_catalog();
        assert!(rendered.contains("| rights:unset |"));
        assert!(rendered.contains("| rights:internal-only |"));
        assert!(!rendered.contains("rights:None"));
    }

    #[test]
    fn render_catalog_is_deterministic_and_order_independent() {
        let a = item("ns", "1", "one", "run-a", None);
        let b = item("ns", "2", "two", "run-b", Some("r"));
        let c = item("other", "0", "zero", "run-a", None);
        let idx1 = ReunificationIndex::build(vec![a.clone(), b.clone(), c.clone()]).unwrap();
        let idx2 = ReunificationIndex::build(vec![c, a, b]).unwrap();
        assert_eq!(idx1.render_catalog(), idx1.render_catalog());
        assert_eq!(idx1.render_catalog(), idx2.render_catalog());
    }

    #[test]
    fn render_catalog_empty_is_header_only() {
        let idx = ReunificationIndex::default();
        assert_eq!(idx.render_catalog(), "catalog: 0 items across 0 runs\n");
    }

    // ---- rights links ---------------------------------------------------

    #[test]
    fn with_rights_keeps_only_some_sorted_by_key() {
        let idx = ReunificationIndex::build(vec![
            item("ns", "3", "three", "run-a", Some("z-licence")),
            item("ns", "1", "one", "run-a", None),
            item("ns", "2", "two", "run-b", Some("a-licence")),
        ])
        .unwrap();
        let keys: Vec<String> = idx.with_rights().iter().map(|i| i.pid.key()).collect();
        assert_eq!(keys, vec!["ns:2", "ns:3"]);
    }

    #[test]
    fn with_rights_empty_when_no_item_has_rights() {
        let idx = ReunificationIndex::build(vec![
            item("ns", "1", "one", "run-a", None),
            item("ns", "2", "two", "run-b", None),
        ])
        .unwrap();
        assert!(idx.with_rights().is_empty());
    }

    #[test]
    fn with_rights_treats_empty_string_as_present() {
        // Presence is `Some(_)`; only the metadata fields are validated.
        let idx =
            ReunificationIndex::build(vec![item("ns", "1", "one", "run-a", Some(""))])
                .unwrap();
        assert_eq!(idx.with_rights().len(), 1);
        assert!(idx.render_catalog().contains("| rights: |"));
    }

    // ---- get ------------------------------------------------------------

    #[test]
    fn get_finds_present_item() {
        let idx = ReunificationIndex::build(vec![item(
            "ns",
            "1",
            "one",
            "run-a",
            Some("licence-x"),
        )])
        .unwrap();
        let found = idx.get(&pid("ns", "1")).unwrap();
        assert_eq!(found.title, "one");
        assert_eq!(found.rights.as_deref(), Some("licence-x"));
    }

    #[test]
    fn get_unknown_key_or_namespace_is_unknown() {
        let idx = ReunificationIndex::build(vec![item("ns", "1", "one", "run-a", None)]).unwrap();
        assert_eq!(idx.get(&pid("ns", "2")), Err(IndexError::Unknown));
        assert_eq!(idx.get(&pid("other", "1")), Err(IndexError::Unknown));
        // malformed pid cannot match any stored (validated) key
        assert_eq!(idx.get(&pid("", "1")), Err(IndexError::Unknown));
    }

    #[test]
    fn get_is_namespace_scoped() {
        let idx = ReunificationIndex::build(vec![
            item("alpha", "1", "first", "run-a", None),
            item("beta", "1", "second", "run-b", None),
        ])
        .unwrap();
        assert_eq!(idx.get(&pid("alpha", "1")).unwrap().title, "first");
        assert_eq!(idx.get(&pid("beta", "1")).unwrap().title, "second");
    }

    // ---- serde + display ------------------------------------------------

    #[test]
    fn serde_round_trips_pid_and_item() {
        let p = pid("corpus-a", "0007");
        let back: PersistentId =
            serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::json!({"namespace": "corpus-a", "local_id": "0007"})
        );

        let i = item("ns", "1", "one", "run-a", Some("CC-BY-4.0"));
        let back: CatalogItem =
            serde_json::from_str(&serde_json::to_string(&i).unwrap()).unwrap();
        assert_eq!(back, i);
        assert_eq!(serde_json::to_value(&i).unwrap()["rights"], "CC-BY-4.0");

        let no_rights = item("ns", "2", "two", "run-a", None);
        let back: CatalogItem =
            serde_json::from_str(&serde_json::to_string(&no_rights).unwrap()).unwrap();
        assert_eq!(back.rights, None);
        assert_eq!(
            serde_json::to_value(&no_rights).unwrap()["rights"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn serde_error_wire_pins() {
        // Serialize-only (repo precedent for `&'static str` payloads)
        assert_eq!(
            serde_json::to_string(&IndexError::BadInput("title")).unwrap(),
            "{\"BadInput\":\"title\"}"
        );
        assert_eq!(
            serde_json::to_string(&IndexError::DupId).unwrap(),
            "\"DupId\""
        );
        assert_eq!(
            serde_json::to_string(&IndexError::Unknown).unwrap(),
            "\"Unknown\""
        );
    }

    #[test]
    fn display_pins() {
        assert_eq!(
            IndexError::BadInput("locator").to_string(),
            "invalid input: locator"
        );
        assert_eq!(IndexError::DupId.to_string(), "duplicate id");
        assert_eq!(IndexError::Unknown.to_string(), "unknown id");
    }

    #[test]
    fn build_accepts_cross_run_items_and_preserves_full_render() {
        // B6.1 end-to-end: two runs, shared local_ids, one rights statement.
        let idx = ReunificationIndex::build(vec![
            item("run-1", "007", "Report seven", "run-1", Some("OGL-3.0")),
            item("run-2", "007", "Report seven (dup swap)", "run-2", None),
            CatalogItem {
                pid: pid("run-2", "008"),
                title: "Report eight".into(),
                source_run: "run-2".into(),
                rights: None,
                locator: "file:///runs/2/008.txt".into(),
            },
        ])
        .unwrap();
        assert_eq!(idx.runs(), vec!["run-1".to_string(), "run-2".to_string()]);
        assert_eq!(idx.with_rights().len(), 1);
        assert_eq!(
            idx.render_catalog(),
            "catalog: 3 items across 2 runs\n\
             - run-1:007 | Report seven | run-1 | rights:OGL-3.0 | loc:run-1/007\n\
             - run-2:007 | Report seven (dup swap) | run-2 | rights:unset | loc:run-2/007\n\
             - run-2:008 | Report eight | run-2 | rights:unset | file:///runs/2/008.txt\n"
        );
    }
}
