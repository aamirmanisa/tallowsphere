//! Compartment primitive with **deny-by-default** cross-compartment reads
//! (task A5.1.1 / spec §1 of B08).
//!
//! A [`CompartmentStore`] holds caller-supplied byte buckets keyed by
//! `(CompartmentId, CompartmentKind, name)`. Reads are always performed *by*
//! a requester compartment *against* a target compartment:
//!
//! * **Same-compartment reads are always allowed** (no grant needed).
//! * **Cross-compartment reads are DENIED BY DEFAULT.** They succeed only
//!   when an explicit, still-live (non-revoked) [`CompartmentStore::grant`]
//!   exists for the exact ordered pair `(target, requester)` — i.e. the
//!   grant's `from` is the target and the grant's `to` is the requester.
//! * Grants are **one-directional**: `grant(from, to, …)` lets `to` read
//!   `from`, and nothing else. `from` reading `to` stays denied.
//! * Grants are **revocable** ([`CompartmentStore::revoke`]); after revoke the
//!   pair is denied again.
//!
//! # Identity
//! [`CompartmentId`] is a plain `String` newtype (serde-transparent,
//! [`Display`]). Equality is exact byte equality of the inner string — no
//! normalization, no case folding, no trimming. Callers own naming policy.
//!
//! # Kinds
//! [`CompartmentKind`] is the closed set of bucket families this primitive
//! knows: [`Secrets`](CompartmentKind::Secrets),
//! [`Cookies`](CompartmentKind::Cookies),
//! [`Fingerprints`](CompartmentKind::Fingerprints),
//! [`Artifacts`](CompartmentKind::Artifacts). Serde renders them
//! `snake_case`. [`CompartmentKind::ALL`] lists all four for exhaustive
//! iteration.
//!
//! # Grant scope — judgment call (documented per frozen interface)
//! The frozen `grant(from, to, at_ms, note)` signature carries **no kind
//! parameter**, so grants are deliberately scoped to the *compartment pair*,
//! not to a kind: once `B` may read `A`, it may read every kind of `A`. The
//! interface's "other kinds still denied" is therefore honored as *"all other
//! compartment pairs remain denied, whatever the kind"* — kind-level gating is
//! not expressible in this API and is left to callers/policy layers.
//!
//! # Read algorithm (order matters)
//! 1. Determine the pair `(requester, target)`. If same compartment → go to 4.
//! 2. Look up grant `(from = target, to = requester)`. Absent → [`Denied`].
//! 3. Present → continue.
//! 4. Look up the entry `(target, kind, name)`. Absent → [`NotFound`].
//! 5. Present → return a clone of the stored bytes.
//!
//! Permission is checked **before** existence on cross reads so an ungranted
//! requester cannot distinguish "entry exists but denied" from "entry does
//! not exist" — both are [`Denied`]. Same-compartment and granted reads
//! report the true absence as [`NotFound`].
//!
//! # Entry semantics
//! `put` is an **overwrite** (last write wins) and accepts `bytes` of any
//! length, including empty — an empty byte string is a valid payload, not an
//! error. Only malformed *keys* are rejected: empty compartment id or empty
//! name → [`CompartmentError::EmptyField`].
//!
//! `read` performs no field validation: an empty name is simply a name under
//! which nothing was stored (subject to the permission rules above).
//!
//! # Grant semantics
//! * `grant` requires non-empty `from`, non-empty `to` and non-empty `note`;
//!   otherwise [`CompartmentError::EmptyField`].
//! * A duplicate of an existing `(from, to)` pair is
//!   [`CompartmentError::DuplicateGrant`] — grants are never silently
//!   overwritten, so the recorded `at_ms`/`note` always describe the *live*
//!   grant.
//! * A self-grant `from == to` is permitted (it is a no-op for the read
//!   policy, since same-compartment reads never consult grants); it exists so
//!   audit layers can record it explicitly.
//! * `revoke` of a pair with no live grant is
//!   [`CompartmentError::NoSuchGrant`].
//!
//! # Determinism
//! All state lives in `BTreeMap`s keyed by `Ord`-total types, so iteration
//! (and therefore [`CompartmentStore::list`]) is deterministic and sorted
//! by `(CompartmentId, CompartmentKind, name)`. `list` additionally filters
//! to one `(compartment, kind)` and yields names in Rust `String` order
//! (byte-order of UTF-8). There is no clock, no IO and no randomness in this
//! module — `at_ms` is caller-supplied and stored verbatim.
//!
//! # Serde note
//! [`CompartmentError`] derives `Serialize` **only**:
//! [`EmptyField`](CompartmentError::EmptyField) carries `&'static str`, which
//! cannot be `Deserialize`d into an arbitrary caller lifetime. This mirrors
//! the existing repo precedent (`decoy_flags::DecoyError`).
//!
//! [`CompartmentId`] and [`CompartmentKind`] round-trip through serde
//! (verified for JSON in tests). [`CompartmentStore`] deliberately derives
//! **no** serde traits: its entry keys are composite tuples
//! `(CompartmentId, CompartmentKind, name)`, which are not valid JSON object
//! keys, so a derive would only offer a round-trip that silently fails on
//! the repo's actual format. Store export/import is a caller concern and can
//! be built from [`CompartmentStore::list`] + [`CompartmentStore::read`].
//!
//! # Wiring
//! No call site is wired here; the parent integrates the module (A5.1.1).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Opaque compartment identity: exact-string equality, no normalization.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompartmentId(pub String);

impl fmt::Display for CompartmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for CompartmentId {
    fn from(s: &str) -> Self {
        CompartmentId(s.to_string())
    }
}

impl From<String> for CompartmentId {
    fn from(s: String) -> Self {
        CompartmentId(s)
    }
}

/// The closed set of bucket families a [`CompartmentStore`] knows about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompartmentKind {
    Secrets,
    Cookies,
    Fingerprints,
    Artifacts,
}

impl CompartmentKind {
    /// Every variant, in declaration order (exhaustive iteration).
    pub const ALL: [CompartmentKind; 4] = [
        CompartmentKind::Secrets,
        CompartmentKind::Cookies,
        CompartmentKind::Fingerprints,
        CompartmentKind::Artifacts,
    ];
}

/// Metadata recorded for a live grant. Not part of the frozen public
/// surface; kept private so the API stays exact.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GrantRecord {
    at_ms: i64,
    note: String,
}

/// `(compartment, kind, name)` → bytes.
type EntryKey = (CompartmentId, CompartmentKind, String);

/// Per-compartment byte buckets with deny-by-default cross-reads.
///
/// See the module docs for the full read/grant semantics. Pure and
/// deterministic: no clock, no IO, no randomness. (No serde derives — see
/// the module-level serde note.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompartmentStore {
    entries: BTreeMap<EntryKey, Vec<u8>>,
    grants: BTreeMap<(CompartmentId, CompartmentId), GrantRecord>,
}

impl CompartmentStore {
    /// Store `bytes` under `(compartment, kind, name)`.
    ///
    /// Overwrites any previous value (last write wins). Empty compartment id
    /// or empty name → [`CompartmentError::EmptyField`]. Empty `bytes` is a
    /// valid payload.
    pub fn put(
        &mut self,
        compartment: &CompartmentId,
        kind: CompartmentKind,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<(), CompartmentError> {
        if compartment.0.is_empty() {
            return Err(CompartmentError::EmptyField("compartment"));
        }
        if name.is_empty() {
            return Err(CompartmentError::EmptyField("name"));
        }
        self.entries
            .insert((compartment.clone(), kind, name.to_string()), bytes);
        Ok(())
    }

    /// Read `(target, kind, name)` as `requester`.
    ///
    /// Same compartment → allowed. Cross compartment → allowed only with a
    /// live grant `(from = target, to = requester)`, else
    /// [`CompartmentError::Denied`]. Missing entry (after permission is
    /// established) → [`CompartmentError::NotFound`].
    pub fn read(
        &self,
        requester: &CompartmentId,
        target: &CompartmentId,
        kind: CompartmentKind,
        name: &str,
    ) -> Result<Vec<u8>, CompartmentError> {
        if requester != target && !self.is_granted(target, requester) {
            return Err(CompartmentError::Denied);
        }
        self.entries
            .get(&(target.clone(), kind, name.to_string()))
            .cloned()
            .ok_or(CompartmentError::NotFound)
    }

    /// Grant one-directional read rights: `to` may read `from`.
    ///
    /// `note` must be non-empty; `from`/`to` must be non-empty. A duplicate
    /// `(from, to)` pair → [`CompartmentError::DuplicateGrant`].
    pub fn grant(
        &mut self,
        from: &CompartmentId,
        to: &CompartmentId,
        at_ms: i64,
        note: &str,
    ) -> Result<(), CompartmentError> {
        if from.0.is_empty() {
            return Err(CompartmentError::EmptyField("from"));
        }
        if to.0.is_empty() {
            return Err(CompartmentError::EmptyField("to"));
        }
        if note.is_empty() {
            return Err(CompartmentError::EmptyField("note"));
        }
        let key = (from.clone(), to.clone());
        if self.grants.contains_key(&key) {
            return Err(CompartmentError::DuplicateGrant);
        }
        self.grants.insert(
            key,
            GrantRecord {
                at_ms,
                note: note.to_string(),
            },
        );
        Ok(())
    }

    /// Revoke the live grant `(from = target, to = requester)`.
    ///
    /// No such grant → [`CompartmentError::NoSuchGrant`]. After revoke,
    /// cross reads relying on the pair are denied again.
    pub fn revoke(
        &mut self,
        from: &CompartmentId,
        to: &CompartmentId,
    ) -> Result<(), CompartmentError> {
        match self.grants.remove(&(from.clone(), to.clone())) {
            Some(_) => Ok(()),
            None => Err(CompartmentError::NoSuchGrant),
        }
    }

    /// Names stored under `(compartment, kind)`, sorted (`String` order).
    pub fn list(&self, compartment: &CompartmentId, kind: CompartmentKind) -> Vec<String> {
        self.entries
            .keys()
            .filter(|(c, k, _)| c == compartment && *k == kind)
            .map(|(_, _, name)| name.clone())
            .collect()
    }

    /// Whether `to` currently holds read rights on `from`.
    fn is_granted(&self, from: &CompartmentId, to: &CompartmentId) -> bool {
        self.grants.contains_key(&(from.clone(), to.clone()))
    }
}

/// Errors from [`CompartmentStore`] operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum CompartmentError {
    /// A required field was empty; the `&'static str` names it.
    EmptyField(&'static str),
    /// The entry does not exist (checked only after permission passes).
    NotFound,
    /// Cross-compartment read without a live grant (deny-by-default).
    Denied,
    /// A grant for this exact `(from, to)` pair already exists.
    DuplicateGrant,
    /// Revoke/read referenced a grant that is not live.
    NoSuchGrant,
}

impl fmt::Display for CompartmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompartmentError::EmptyField(field) => write!(f, "empty field: {field}"),
            CompartmentError::NotFound => f.write_str("compartment entry not found"),
            CompartmentError::Denied => {
                f.write_str("cross-compartment read denied (no live grant)")
            }
            CompartmentError::DuplicateGrant => f.write_str("grant already exists"),
            CompartmentError::NoSuchGrant => f.write_str("no such grant"),
        }
    }
}

impl std::error::Error for CompartmentError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(s: &str) -> CompartmentId {
        CompartmentId(s.to_string())
    }

    fn store_with_fixture() -> CompartmentStore {
        let mut store = CompartmentStore::default();
        store
            .put(&cid("alpha"), CompartmentKind::Secrets, "api-key", b"k1".to_vec())
            .unwrap();
        store
            .put(
                &cid("alpha"),
                CompartmentKind::Cookies,
                "session",
                b"c1".to_vec(),
            )
            .unwrap();
        store
            .put(
                &cid("beta"),
                CompartmentKind::Secrets,
                "api-key",
                b"k2".to_vec(),
            )
            .unwrap();
        store
            .put(
                &cid("gamma"),
                CompartmentKind::Artifacts,
                "note",
                b"g1".to_vec(),
            )
            .unwrap();
        store
    }

    #[test]
    fn same_compartment_roundtrip() {
        let mut store = store_with_fixture();
        assert_eq!(
            store
                .read(&cid("alpha"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
                .unwrap(),
            b"k1".to_vec()
        );
        // Overwrite (last write wins).
        store
            .put(&cid("alpha"), CompartmentKind::Secrets, "api-key", b"k1b".to_vec())
            .unwrap();
        assert_eq!(
            store
                .read(&cid("alpha"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
                .unwrap(),
            b"k1b".to_vec()
        );
        // Empty payload is a valid value, not an error.
        store
            .put(&cid("alpha"), CompartmentKind::Secrets, "blank", Vec::new())
            .unwrap();
        assert_eq!(
            store
                .read(&cid("alpha"), &cid("alpha"), CompartmentKind::Secrets, "blank")
                .unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn cross_read_denied_by_default() {
        let store = store_with_fixture();
        assert_eq!(
            store.read(
                &cid("beta"),
                &cid("alpha"),
                CompartmentKind::Secrets,
                "api-key"
            ),
            Err(CompartmentError::Denied)
        );
        // Denial does not depend on whether the target entry exists.
        assert_eq!(
            store.read(
                &cid("beta"),
                &cid("alpha"),
                CompartmentKind::Secrets,
                "no-such-entry"
            ),
            Err(CompartmentError::Denied)
        );
        // Same compartment still works.
        assert!(store
            .read(&cid("alpha"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
            .is_ok());
    }

    #[test]
    fn grant_enables_pair_and_all_its_kinds_only() {
        let mut store = store_with_fixture();
        store
            .grant(&cid("alpha"), &cid("beta"), 1_000, "beta may inspect alpha")
            .unwrap();
        // Beta may read alpha — every kind of alpha flows through the pair.
        assert_eq!(
            store
                .read(&cid("beta"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
                .unwrap(),
            b"k1".to_vec()
        );
        assert_eq!(
            store
                .read(&cid("beta"), &cid("alpha"), CompartmentKind::Cookies, "session")
                .unwrap(),
            b"c1".to_vec()
        );
        // Missing entry on a granted pair surfaces as NotFound.
        assert_eq!(
            store.read(&cid("beta"), &cid("alpha"), CompartmentKind::Artifacts, "nope"),
            Err(CompartmentError::NotFound)
        );
        // Other pairs remain denied: beta ↛ gamma, gamma ↛ alpha, alpha ↛ beta.
        assert_eq!(
            store.read(
                &cid("beta"),
                &cid("gamma"),
                CompartmentKind::Artifacts,
                "note"
            ),
            Err(CompartmentError::Denied)
        );
        assert_eq!(
            store.read(
                &cid("gamma"),
                &cid("alpha"),
                CompartmentKind::Secrets,
                "api-key"
            ),
            Err(CompartmentError::Denied)
        );
        assert_eq!(
            store.read(
                &cid("alpha"),
                &cid("beta"),
                CompartmentKind::Secrets,
                "api-key"
            ),
            Err(CompartmentError::Denied)
        );
    }

    #[test]
    fn directional_grants() {
        let mut store = store_with_fixture();
        store.grant(&cid("alpha"), &cid("beta"), 10, "a→b").unwrap();
        assert!(store
            .read(&cid("beta"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
            .is_ok());
        assert_eq!(
            store.read(
                &cid("alpha"),
                &cid("beta"),
                CompartmentKind::Secrets,
                "api-key"
            ),
            Err(CompartmentError::Denied)
        );
        // Adding the reverse grant makes the pair mutual.
        store.grant(&cid("beta"), &cid("alpha"), 11, "b→a").unwrap();
        assert!(store
            .read(&cid("alpha"), &cid("beta"), CompartmentKind::Secrets, "api-key")
            .is_ok());
    }

    #[test]
    fn revoke_restores_denial() {
        let mut store = store_with_fixture();
        store.grant(&cid("alpha"), &cid("beta"), 10, "temp").unwrap();
        assert!(store
            .read(&cid("beta"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
            .is_ok());
        store.revoke(&cid("alpha"), &cid("beta")).unwrap();
        assert_eq!(
            store.read(
                &cid("beta"),
                &cid("alpha"),
                CompartmentKind::Secrets,
                "api-key"
            ),
            Err(CompartmentError::Denied)
        );
        // Revoking again (or never-granted pairs) → NoSuchGrant.
        assert_eq!(
            store.revoke(&cid("alpha"), &cid("beta")),
            Err(CompartmentError::NoSuchGrant)
        );
        assert_eq!(
            store.revoke(&cid("alpha"), &cid("gamma")),
            Err(CompartmentError::NoSuchGrant)
        );
        // Revoke is wrong-direction sensitive: alpha→beta revoked does not
        // touch beta→alpha.
        store.grant(&cid("beta"), &cid("alpha"), 12, "reverse").unwrap();
        store.revoke(&cid("alpha"), &cid("beta")).unwrap_err();
        assert!(store
            .read(&cid("alpha"), &cid("beta"), CompartmentKind::Secrets, "api-key")
            .is_ok());
    }

    #[test]
    fn duplicate_grant_rejected() {
        let mut store = store_with_fixture();
        store.grant(&cid("alpha"), &cid("beta"), 10, "first").unwrap();
        assert_eq!(
            store.grant(&cid("alpha"), &cid("beta"), 11, "second"),
            Err(CompartmentError::DuplicateGrant)
        );
        // Still exactly one live grant; revoke once clears it.
        store.revoke(&cid("alpha"), &cid("beta")).unwrap();
        assert_eq!(
            store.read(
                &cid("beta"),
                &cid("alpha"),
                CompartmentKind::Secrets,
                "api-key"
            ),
            Err(CompartmentError::Denied)
        );
    }

    #[test]
    fn empty_field_errors() {
        let mut store = CompartmentStore::default();
        assert_eq!(
            store.put(&cid(""), CompartmentKind::Secrets, "n", vec![1]),
            Err(CompartmentError::EmptyField("compartment"))
        );
        assert_eq!(
            store.put(&cid("a"), CompartmentKind::Secrets, "", vec![1]),
            Err(CompartmentError::EmptyField("name"))
        );
        assert_eq!(
            store.grant(&cid(""), &cid("b"), 1, "note"),
            Err(CompartmentError::EmptyField("from"))
        );
        assert_eq!(
            store.grant(&cid("a"), &cid(""), 1, "note"),
            Err(CompartmentError::EmptyField("to"))
        );
        assert_eq!(
            store.grant(&cid("a"), &cid("b"), 1, ""),
            Err(CompartmentError::EmptyField("note"))
        );
        // Nothing was stored by the failed calls.
        assert!(store.list(&cid("a"), CompartmentKind::Secrets).is_empty());
        assert_eq!(
            store.read(&cid("b"), &cid("a"), CompartmentKind::Secrets, "n"),
            Err(CompartmentError::Denied)
        );
    }

    #[test]
    fn missing_entry_same_compartment_is_not_found() {
        let store = CompartmentStore::default();
        assert_eq!(
            store.read(&cid("a"), &cid("a"), CompartmentKind::Cookies, "nope"),
            Err(CompartmentError::NotFound)
        );
    }

    #[test]
    fn list_sorted_and_kind_scoped() {
        let mut store = CompartmentStore::default();
        for name in ["zeta", "alpha", "mid"] {
            store
                .put(&cid("x"), CompartmentKind::Secrets, name, vec![0])
                .unwrap();
        }
        store
            .put(&cid("x"), CompartmentKind::Cookies, "only", vec![0])
            .unwrap();
        store
            .put(&cid("y"), CompartmentKind::Secrets, "other", vec![0])
            .unwrap();
        assert_eq!(
            store.list(&cid("x"), CompartmentKind::Secrets),
            vec!["alpha".to_string(), "mid".to_string(), "zeta".to_string()]
        );
        assert_eq!(
            store.list(&cid("x"), CompartmentKind::Cookies),
            vec!["only".to_string()]
        );
        assert_eq!(
            store.list(&cid("y"), CompartmentKind::Artifacts),
            Vec::<String>::new()
        );
        // Unknown compartment → empty, never an error.
        assert!(store.list(&cid("nope"), CompartmentKind::Secrets).is_empty());
    }

    #[test]
    fn kind_serde_and_all() {
        assert_eq!(CompartmentKind::ALL.len(), 4);
        assert_eq!(
            serde_json::to_value(CompartmentKind::Secrets).unwrap(),
            serde_json::json!("secrets")
        );
        assert_eq!(
            serde_json::to_value(CompartmentKind::Fingerprints).unwrap(),
            serde_json::json!("fingerprints")
        );
        assert_eq!(
            serde_json::to_value(CompartmentKind::Cookies).unwrap(),
            serde_json::json!("cookies")
        );
        assert_eq!(
            serde_json::to_value(CompartmentKind::Artifacts).unwrap(),
            serde_json::json!("artifacts")
        );
        // Id round-trips transparently; Display echoes the raw string.
        let id = cid("comp-1");
        assert_eq!(id.to_string(), "comp-1");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"comp-1\"");
        let back: CompartmentId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn error_display_is_nonempty_and_specific() {
        assert_eq!(
            CompartmentError::EmptyField("name").to_string(),
            "empty field: name"
        );
        assert_eq!(
            CompartmentError::Denied.to_string(),
            "cross-compartment read denied (no live grant)"
        );
        assert_eq!(
            CompartmentError::NotFound.to_string(),
            "compartment entry not found"
        );
        assert_eq!(
            CompartmentError::DuplicateGrant.to_string(),
            "grant already exists"
        );
        assert_eq!(
            CompartmentError::NoSuchGrant.to_string(),
            "no such grant"
        );
    }

    #[test]
    fn determinism() {
        fn scenario() -> (CompartmentStore, Vec<u8>, Vec<String>) {
            let mut store = store_with_fixture();
            store.grant(&cid("alpha"), &cid("beta"), 7, "n").unwrap();
            let read = store
                .read(&cid("beta"), &cid("alpha"), CompartmentKind::Secrets, "api-key")
                .unwrap();
            let listed = store.list(&cid("alpha"), CompartmentKind::Secrets);
            (store, read, listed)
        }
        let (s1, r1, l1) = scenario();
        let (s2, r2, l2) = scenario();
        assert_eq!(s1, s2);
        assert_eq!(r1, r2);
        assert_eq!(l1, l2);
        // Determinism is not vacuous: the store's equality is sensitive to
        // live-grant state (revoking one grant changes it).
        let mut diverged = s1.clone();
        diverged.revoke(&cid("alpha"), &cid("beta")).unwrap();
        assert_ne!(diverged, s1);
    }
}
