//! Event schema evolution — declarative upcasters, snapshot cadence, and
//! deterministic replay (tasks B6.4.1–B6.4.3, frozen interface §8).
//!
//! Event-sourced logs persist events under the schema of the day they were
//! written; stored events are immutable facts and the schema they were written
//! with is part of their identity. When the schema evolves, old events are
//! not rewritten — they are *upcast* on read: walked forward, version by
//! version, through a chain of small, declarative transforms until they reach
//! a shape the current reader understands.
//!
//! This module is the pure engine for that walk. It has no clock, no I/O, no
//! storage, and no hidden state: every function is a deterministic transform
//! of its inputs, which is what makes replay reproducible (B6.4.3).
//!
//! # Declarative transforms (B6.4.1)
//! A [`SchemaEvent`] is a `version`, a `kind` (never touched by upcasting),
//! and an ordered list of [`Field`]s. An [`Upcaster`] covers exactly one
//! version step (`from_version → to_version`) and carries an ordered list of
//! [`Transform`]s:
//!
//! * [`Transform::RenameField`] — renames the *first* field named `from` in
//!   place (position preserved). The old name must exist
//!   ([`UpcastError::MissingField`]); the produced name must not already be
//!   used by a *different* field ([`UpcastError::DuplicateField`]). Renaming a
//!   field to its own name is a no-op (it produces no ambiguity).
//! * [`Transform::AddField`] — appends `(name, value)` at the end. The name
//!   must not already be present ([`UpcastError::DuplicateField`]).
//! * [`Transform::DropField`] — removes the first field named `name`,
//!   preserving the relative order of the rest. Missing →
//!   [`UpcastError::MissingField`].
//!
//! Transforms inside one upcaster apply **sequentially**: each transform sees
//! the fields as left by its predecessors, and duplicate detection is against
//! the live field list at that moment. A refusal aborts the whole upcast —
//! the partially transformed event is never returned (fail-closed).
//!
//! # The stepwise chase and its refusals
//! [`upcast`] walks from the event's version: at each version it stops at,
//! **exactly one** upcaster must claim `from_version == current`. The
//! rejection battery, in the order the chase applies it:
//!
//! 1. **more than one claimant** → [`UpcastError::BadInput`]`("upcaster")` —
//!    an ambiguous chain cannot be interpreted deterministically (argued
//!    below);
//! 2. **no claimant** → [`UpcastError::NoPath`] or a successful return,
//!    depending on the horizon rule (argued below);
//! 3. **claimant not contiguous** (`to_version != from_version + 1`, checked
//!    with `u32::checked_add` so `u32::MAX` cannot wrap) →
//!    [`UpcastError::NonContiguous`] — chains of *steps*, never leaps, are
//!    what keeps every intermediate version's transforms non-skippable.
//!
//! ## Horizon rule — the §8 reconciliation (argued)
//! §8 contains two clauses that conflict on one edge: *«at each version,
//! exactly one upcaster must claim `from_version == current`; none →
//! NoPath{from: current}»* and *«repeat until no upcaster claims the current
//! version; return final event»*. Read flatly, the second clause makes
//! `NoPath` unreachable, while the first makes every honest chain end a
//! refusal. This module reconciles them with a **horizon**:
//!
//! > `horizon(us) = max(to_version)` over the supplied upcasters — the
//! > furthest version the set knows how to *produce*.
//!
//! The chase steps while a claimant exists. When none claims the current
//! version, the walk is either *finished* or *stranded*:
//!
//! * `current >= horizon` (or the set is empty: no horizon, nothing was
//!   asked) → the event is at (or beyond) the newest shape this upcaster set
//!   knows; **return the final event** unchanged — this is the only reading
//!   under which mixed-version replay of an existing log (B6.4.3) is usable,
//!   since events already at the newest version would otherwise fail.
//! * `current < horizon` → the set promises later versions but does not know
//!   the step out of this one: the event cannot be brought current —
//!   **NoPath{from: current}**. Fail-closed: silently returning a not-fully-
//!   upcast event would let a reader misparse an old shape as a new one.
//!
//! This is the only reading that makes both clauses true on overlapping
//! domains, keeps `NoPath` reachable (the §8 test list requires it), and
//! keeps replay total over realistic logs. Pinned by tests.
//!
//! ## Ambiguous claims (argued)
//! §8 says *exactly one* upcaster must claim a version but pins no error for
//! the ≥ 2 case. This module refuses with `BadInput("upcaster")`: duplicated
//! claims make the walk non-deterministic (first-match would let the output
//! depend on slice order for a logically ambiguous set), and of the §8 error
//! variants `BadInput` is the only extensible one for a malformed *argument*.
//! Pinned by tests, including an ambiguity that only appears mid-chain.
//!
//! # Snapshot cadence (B6.4.2)
//! [`SnapshotPolicy::every_events`] is the writer's cadence: a materialised
//! snapshot should be persisted once at least `every_events` events have
//! accumulated since the last one. [`should_snapshot`] fires inclusively —
//! `events_since >= every_events` — and refuses a `0` cadence with
//! [`UpcastError::InvalidPolicy`] (a zero cadence has no meaning; it is a
//! writer bug, not a "never snapshot" request). The policy does not gate
//! upcasting: reading is exact regardless of how often snapshots are taken.
//!
//! # Replay determinism (B6.4.3)
//! [`replay`] upcasts a whole batch, short-circuiting on the first refusal
//! (no partial output). Because every step is pure and the chase is
//! deterministic, running the same batch twice yields serde-identical
//! streams; [`replay_fingerprint`] renders the replayed stream as canonical
//! JSON for CI byte-equality checks. The §8 pin — serde_json round-trip
//! equality across two runs — is asserted in the tests below.
//!
//! # Error taxonomy
//! [`UpcastError`] carries `Display` + `std::error::Error` + `Serialize`
//! (Serialize-only, matching repo precedent for `&'static str` payloads).
//! Refusal *order* inside one step is pinned by tests: uniqueness, then
//! contiguity, then transforms left to right.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One named field of a [`SchemaEvent`]. Values are carried as strings at
/// this layer — upcasting is a *structural* operation; decoding values into
/// richer types is the reader's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// Field name as it appears on the wire for this event version.
    pub name: String,
    /// Field value, uninterpreted.
    pub value: String,
}

/// A stored event under a specific schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEvent {
    /// Schema version this event was written with.
    pub version: u32,
    /// Event kind. Never touched by upcasting.
    pub kind: String,
    /// Ordered fields; order is significant and preserved by all transforms.
    pub fields: Vec<Field>,
}

/// A single declarative schema transform. Wire form is externally tagged
/// snake_case: `{"rename_field":{"from":…,"to":…}}` etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// Rename the first field named `from` to `to`, in place.
    RenameField {
        /// Existing field name.
        from: String,
        /// New field name.
        to: String,
    },
    /// Append `(name, value)` at the end of the field list.
    AddField {
        /// Name of the new field.
        name: String,
        /// Value of the new field.
        value: String,
    },
    /// Remove the first field named `name`.
    DropField {
        /// Field to remove.
        name: String,
    },
}

/// One step of a schema chain: version `from_version` is transformed into
/// `to_version` by applying `transforms` in order. Contiguity
/// (`to_version == from_version + 1`) is enforced by [`upcast`], not by the
/// struct — a non-contiguous step is representable but unpickable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upcaster {
    /// Version this step reads.
    pub from_version: u32,
    /// Version this step produces.
    pub to_version: u32,
    /// Transforms applied, in order, to walk from → to.
    pub transforms: Vec<Transform>,
}

/// Snapshot cadence for a writer of this event stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPolicy {
    /// Persist a materialised snapshot every this many events (≥ 1; a zero
    /// cadence is refused by [`should_snapshot`] as
    /// [`UpcastError::InvalidPolicy`]).
    pub every_events: u32,
}

/// Refusals raised by upcasting, snapshots, and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UpcastError {
    /// A malformed argument; the string names the offending input.
    BadInput(&'static str),
    /// No upcaster can move an event forward from `from`, while the supplied
    /// set still promises later versions (see the horizon rule in the module
    /// docs).
    NoPath {
        /// The version the chase was stranded at.
        from: u32,
    },
    /// A claimant upcaster is not a single step: `to_version` must equal
    /// `from_version + 1`.
    NonContiguous,
    /// A transform referenced a field that is not present.
    MissingField(String),
    /// A transform's produced or added name is already in use by another
    /// field.
    DuplicateField(String),
    /// A snapshot policy with `every_events == 0`.
    InvalidPolicy,
}

impl fmt::Display for UpcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpcastError::BadInput(what) => write!(f, "bad input: {what}"),
            UpcastError::NoPath { from } => {
                write!(f, "no upcaster path from version {from}")
            }
            UpcastError::NonContiguous => write!(
                f,
                "upcaster step is not contiguous: to_version must equal from_version + 1"
            ),
            UpcastError::MissingField(name) => write!(f, "field not found: {name}"),
            UpcastError::DuplicateField(name) => {
                write!(f, "field already present: {name}")
            }
            UpcastError::InvalidPolicy => write!(
                f,
                "invalid snapshot policy: every_events must be >= 1"
            ),
        }
    }
}

impl std::error::Error for UpcastError {}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The furthest version the supplied upcaster set knows how to produce
/// (`None` for an empty set). See the horizon rule in the module docs.
fn horizon(upcasters: &[Upcaster]) -> Option<u32> {
    upcasters.iter().map(|u| u.to_version).max()
}

/// Apply one transform to `fields`, mutating in place. Refusals leave
/// `fields` partially modified — callers commit only after the whole step
/// succeeds, so no partial state escapes this module.
fn apply_transform(fields: &mut Vec<Field>, transform: &Transform) -> Result<(), UpcastError> {
    match transform {
        Transform::RenameField { from, to } => {
            let idx = fields
                .iter()
                .position(|f| f.name == *from)
                .ok_or_else(|| UpcastError::MissingField(from.clone()))?;
            // Duplicate detection is against *other* fields: renaming a field
            // to the name it already has produces no ambiguity (no-op).
            if fields
                .iter()
                .enumerate()
                .any(|(i, f)| i != idx && f.name == *to)
            {
                return Err(UpcastError::DuplicateField(to.clone()));
            }
            fields[idx].name = to.clone();
            Ok(())
        }
        Transform::AddField { name, value } => {
            if fields.iter().any(|f| f.name == *name) {
                return Err(UpcastError::DuplicateField(name.clone()));
            }
            fields.push(Field {
                name: name.clone(),
                value: value.clone(),
            });
            Ok(())
        }
        Transform::DropField { name } => {
            let idx = fields
                .iter()
                .position(|f| f.name == *name)
                .ok_or_else(|| UpcastError::MissingField(name.clone()))?;
            fields.remove(idx);
            Ok(())
        }
    }
}

/// Walk `ev` forward through the upcaster chain, step by step, and return the
/// final event. The input is never mutated.
///
/// At each version the chase stops at, exactly one upcaster must claim
/// `from_version == current`:
///
/// * more than one claimant → [`UpcastError::BadInput`]`("upcaster")`;
/// * no claimant and the version is below the set's horizon →
///   [`UpcastError::NoPath`]; no claimant at/above the horizon (or with an
///   empty set) → the chain is complete, return the final event;
/// * the claimant must satisfy `to_version == from_version + 1`
///   ([`UpcastError::NonContiguous`]), then its transforms apply in order.
///
/// Refusals propagate unchanged; on any refusal no partially transformed
/// event is returned.
pub fn upcast(ev: &SchemaEvent, upcasters: &[Upcaster]) -> Result<SchemaEvent, UpcastError> {
    let mut event = ev.clone();
    loop {
        // Exactly-one-claimant check for the current version. The block ends
        // the immutable borrow of `event` taken by the filter closure before
        // the fields below are mutated.
        let claimant: Option<&Upcaster> = {
            let mut it = upcasters.iter().filter(|u| u.from_version == event.version);
            match (it.next(), it.next()) {
                (None, _) => None,
                (Some(one), None) => Some(one),
                (Some(_), Some(_)) => return Err(UpcastError::BadInput("upcaster")),
            }
        };

        let step = match claimant {
            Some(step) => step,
            None => {
                return match horizon(upcasters) {
                    Some(top) if event.version < top => {
                        Err(UpcastError::NoPath { from: event.version })
                    }
                    _ => Ok(event),
                };
            }
        };

        // Contiguity: one version at a time, no leaps, no wraps.
        match step.from_version.checked_add(1) {
            Some(next) if step.to_version == next => {}
            _ => return Err(UpcastError::NonContiguous),
        }

        for transform in &step.transforms {
            apply_transform(&mut event.fields, transform)?;
        }
        event.version = step.to_version;
    }
}

/// Whether a snapshot should be persisted after `events_since` events have
/// accumulated under `p`. Fires inclusively at the cadence boundary
/// (`events_since >= every_events`). A zero cadence is
/// [`UpcastError::InvalidPolicy`].
pub fn should_snapshot(p: &SnapshotPolicy, events_since: u32) -> Result<bool, UpcastError> {
    if p.every_events == 0 {
        return Err(UpcastError::InvalidPolicy);
    }
    Ok(events_since >= p.every_events)
}

/// Upcast every event of `events` in order, returning the replayed stream.
/// Short-circuits on the first refusal — replay never yields a partial batch.
/// Pure and deterministic: identical inputs give serde-identical outputs.
pub fn replay(
    events: &[SchemaEvent],
    upcasters: &[Upcaster],
) -> Result<Vec<SchemaEvent>, UpcastError> {
    events.iter().map(|e| upcast(e, upcasters)).collect()
}

/// Canonical JSON rendering of the replayed stream, for CI byte-equality
/// checks of replay determinism (B6.4.3). Runs the full [`replay`], so any
/// refusal propagates.
pub fn replay_fingerprint(
    events: &[SchemaEvent],
    upcasters: &[Upcaster],
) -> Result<String, UpcastError> {
    let replayed = replay(events, upcasters)?;
    // Serialising these plain structures cannot realistically fail; map any
    // residual failure to a BadInput refusal rather than panicking.
    serde_json::to_string(&replayed).map_err(|_| UpcastError::BadInput("json"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- fixtures -----------------------------------------------------------

    fn f(name: &str, value: &str) -> Field {
        Field {
            name: name.into(),
            value: value.into(),
        }
    }

    fn ev(version: u32, kind: &str, fields: Vec<Field>) -> SchemaEvent {
        SchemaEvent {
            version,
            kind: kind.into(),
            fields,
        }
    }

    /// One-step upcaster from `from` to `from + 1`.
    fn step(from: u32, transforms: Vec<Transform>) -> Upcaster {
        Upcaster {
            from_version: from,
            to_version: from.checked_add(1).unwrap(),
            transforms,
        }
    }

    fn names(e: &SchemaEvent) -> Vec<&str> {
        e.fields.iter().map(|f| f.name.as_str()).collect()
    }

    fn values(e: &SchemaEvent) -> Vec<&str> {
        e.fields.iter().map(|f| f.value.as_str()).collect()
    }

    fn rename(from: &str, to: &str) -> Transform {
        Transform::RenameField {
            from: from.into(),
            to: to.into(),
        }
    }

    fn add(name: &str, value: &str) -> Transform {
        Transform::AddField {
            name: name.into(),
            value: value.into(),
        }
    }

    fn drop(name: &str) -> Transform {
        Transform::DropField { name: name.into() }
    }

    // --- B6.4.1 · transform ops --------------------------------------------

    #[test]
    fn rename_field_rewrites_in_place_and_preserves_order() {
        let e = ev(1, "order", vec![f("a", "1"), f("b", "2"), f("c", "3")]);
        let out = upcast(&e, &[step(1, vec![rename("b", "bb")])]).unwrap();
        assert_eq!(out.version, 2);
        assert_eq!(names(&out), vec!["a", "bb", "c"], "position preserved");
        assert_eq!(values(&out), vec!["1", "2", "3"], "values preserved");
        assert_eq!(out.kind, "order");
    }

    #[test]
    fn rename_field_missing_source_is_refused() {
        let e = ev(1, "order", vec![f("a", "1")]);
        let err = upcast(&e, &[step(1, vec![rename("z", "zz")])]).unwrap_err();
        assert_eq!(err, UpcastError::MissingField("z".into()));
    }

    #[test]
    fn rename_field_to_existing_name_is_refused() {
        let e = ev(1, "order", vec![f("a", "1"), f("b", "2")]);
        let err = upcast(&e, &[step(1, vec![rename("a", "b")])]).unwrap_err();
        assert_eq!(err, UpcastError::DuplicateField("b".into()));
    }

    #[test]
    fn rename_field_to_own_name_is_a_noop() {
        let e = ev(1, "order", vec![f("a", "1"), f("b", "2")]);
        let out = upcast(&e, &[step(1, vec![rename("a", "a")])]).unwrap();
        assert_eq!(names(&out), vec!["a", "b"], "no ambiguity ⇒ no refusal");
        assert_eq!(values(&out), vec!["1", "2"]);
        assert_eq!(out.version, 2, "the step itself still commits");
    }

    #[test]
    fn add_field_appends_at_end() {
        let e = ev(1, "order", vec![f("a", "1")]);
        let out = upcast(&e, &[step(1, vec![add("b", "2"), add("c", "3")])]).unwrap();
        assert_eq!(names(&out), vec!["a", "b", "c"], "append order preserved");
        assert_eq!(values(&out), vec!["1", "2", "3"]);
    }

    #[test]
    fn add_field_existing_name_is_refused() {
        let e = ev(1, "order", vec![f("a", "1")]);
        let err = upcast(&e, &[step(1, vec![add("a", "9")])]).unwrap_err();
        assert_eq!(err, UpcastError::DuplicateField("a".into()));
    }

    #[test]
    fn drop_field_removes_in_place() {
        let e = ev(1, "order", vec![f("a", "1"), f("b", "2"), f("c", "3")]);
        let out = upcast(&e, &[step(1, vec![drop("b")])]).unwrap();
        assert_eq!(names(&out), vec!["a", "c"]);
        assert_eq!(values(&out), vec!["1", "3"]);
    }

    #[test]
    fn drop_field_missing_is_refused() {
        let e = ev(1, "order", vec![f("a", "1")]);
        let err = upcast(&e, &[step(1, vec![drop("z")])]).unwrap_err();
        assert_eq!(err, UpcastError::MissingField("z".into()));
    }

    #[test]
    fn transforms_apply_in_order_and_see_earlier_effects() {
        // Combo that succeeds: rename first, then free the name for re-add.
        let e = ev(1, "order", vec![f("a", "1"), f("b", "2")]);
        let out = upcast(
            &e,
            &[step(1, vec![rename("b", "bb"), drop("a"), add("a", "9")])],
        )
        .unwrap();
        assert_eq!(names(&out), vec!["bb", "a"]);
        assert_eq!(values(&out), vec!["2", "9"]);

        // Sequential visibility: a name produced earlier in the same step is
        // already present for the next transform.
        let err = upcast(
            &e,
            &[step(1, vec![rename("b", "bb"), add("bb", "x")])],
        )
        .unwrap_err();
        assert_eq!(err, UpcastError::DuplicateField("bb".into()));
    }

    // --- B6.4.1 · the chase ------------------------------------------------

    #[test]
    fn multi_step_chain_walks_to_top() {
        let e = ev(1, "click", vec![f("path", "/"), f("t_ms", "5")]);
        let chain = vec![
            step(1, vec![rename("path", "url")]),
            step(2, vec![add("source", "web")]),
        ];
        let out = upcast(&e, &chain).unwrap();
        assert_eq!(out.version, 3, "two steps ⇒ 1 → 3");
        assert_eq!(names(&out), vec!["url", "t_ms", "source"]);
        assert_eq!(values(&out), vec!["/", "5", "web"]);
        assert_eq!(out.kind, "click", "kind is never rewritten");

        // Determinism: a second run is equal and serde-identical.
        let out2 = upcast(&e, &chain).unwrap();
        assert_eq!(out, out2);
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            serde_json::to_string(&out2).unwrap()
        );
        // The input is untouched (upcast takes &Event).
        assert_eq!(e.version, 1);
        assert_eq!(names(&e), vec!["path", "t_ms"]);
    }

    #[test]
    fn event_at_horizon_passes_through_untouched() {
        let chain = vec![step(1, vec![rename("a", "b")])];
        let at_top = ev(2, "click", vec![f("b", "1")]);
        assert_eq!(upcast(&at_top, &chain).unwrap(), at_top);
        let beyond = ev(7, "click", vec![f("b", "1")]);
        assert_eq!(upcast(&beyond, &chain).unwrap(), beyond);
    }

    #[test]
    fn empty_upcaster_set_is_a_noop_replay() {
        // No horizon ⇒ nothing was asked ⇒ every version returns as-is.
        let e = ev(4, "click", vec![f("a", "1")]);
        assert_eq!(upcast(&e, &[]).unwrap(), e);
        let e0 = ev(0, "click", vec![]);
        assert_eq!(upcast(&e0, &[]).unwrap(), e0);
    }

    #[test]
    fn nopath_stranded_below_horizon_is_refused() {
        let chain = vec![step(1, vec![rename("a", "b")])];

        // Event older than the chain's first step.
        let old = ev(0, "click", vec![f("a", "1")]);
        assert_eq!(
            upcast(&old, &chain).unwrap_err(),
            UpcastError::NoPath { from: 0 }
        );

        // Gap: the set promises version 4 but cannot leave version 2 — a walk
        // that starts fine dead-ends below the horizon.
        let gapped = vec![
            step(1, vec![rename("a", "b")]),
            step(3, vec![rename("b", "c")]),
        ];
        let mid = ev(1, "click", vec![f("a", "1")]);
        assert_eq!(
            upcast(&mid, &gapped).unwrap_err(),
            UpcastError::NoPath { from: 2 }
        );

        // Set that starts above the event entirely.
        let higher = vec![step(2, vec![add("x", "1")])];
        let first = ev(1, "click", vec![f("a", "1")]);
        assert_eq!(
            upcast(&first, &higher).unwrap_err(),
            UpcastError::NoPath { from: 1 }
        );
    }

    #[test]
    fn noncontiguous_steps_are_refused() {
        let e = ev(1, "click", vec![f("a", "1")]);

        // Leap 1 → 3.
        let leap = Upcaster {
            from_version: 1,
            to_version: 3,
            transforms: vec![],
        };
        assert_eq!(
            upcast(&e, &[leap]).unwrap_err(),
            UpcastError::NonContiguous
        );

        // Self-loop and backward step are equally non-contiguous.
        let same = Upcaster {
            from_version: 1,
            to_version: 1,
            transforms: vec![],
        };
        assert_eq!(
            upcast(&e, &[same]).unwrap_err(),
            UpcastError::NonContiguous
        );
        let back = Upcaster {
            from_version: 1,
            to_version: 0,
            transforms: vec![],
        };
        assert_eq!(
            upcast(&e, &[back]).unwrap_err(),
            UpcastError::NonContiguous
        );

        // Mid-chain leap: the first step commits, the second is refused.
        let mid = vec![
            step(1, vec![]),
            Upcaster {
                from_version: 2,
                to_version: 4,
                transforms: vec![],
            },
        ];
        assert_eq!(
            upcast(&e, &mid).unwrap_err(),
            UpcastError::NonContiguous
        );

        // u32::MAX cannot wrap into a "contiguous" u32::MAX → 0 step.
        let wrap = Upcaster {
            from_version: u32::MAX,
            to_version: 0,
            transforms: vec![],
        };
        let top = ev(u32::MAX, "click", vec![]);
        assert_eq!(
            upcast(&top, &[wrap]).unwrap_err(),
            UpcastError::NonContiguous,
            "checked_add must block the wrap"
        );
    }

    #[test]
    fn ambiguous_claims_are_refused() {
        let e = ev(1, "click", vec![f("a", "1")]);
        let two = vec![
            step(1, vec![rename("a", "b")]),
            step(1, vec![rename("a", "c")]),
        ];
        assert_eq!(
            upcast(&e, &two).unwrap_err(),
            UpcastError::BadInput("upcaster"),
            "two claimants at the same version are not interpretable"
        );

        // Ambiguity that only appears mid-chain: 1 → 2 is unique, 2 → 3 is
        // not.
        let mid_ambiguous = vec![
            step(1, vec![]),
            step(2, vec![add("x", "1")]),
            step(2, vec![add("y", "2")]),
        ];
        let e1 = ev(1, "click", vec![f("a", "1")]);
        assert_eq!(
            upcast(&e1, &mid_ambiguous).unwrap_err(),
            UpcastError::BadInput("upcaster")
        );
    }

    #[test]
    fn refusals_are_deterministic_and_leave_input_untouched() {
        let e = ev(1, "click", vec![f("a", "1")]);
        let chain = vec![step(1, vec![drop("missing")])];
        let first = upcast(&e, &chain).unwrap_err();
        let second = upcast(&e, &chain).unwrap_err();
        assert_eq!(first, second);
        assert_eq!(first, UpcastError::MissingField("missing".into()));
        assert_eq!(e, ev(1, "click", vec![f("a", "1")]), "input pristine");
    }

    // --- B6.4.2 · snapshot cadence -----------------------------------------

    #[test]
    fn snapshot_cadence_boundary_pins() {
        let p5 = SnapshotPolicy { every_events: 5 };
        assert_eq!(should_snapshot(&p5, 4).unwrap(), false, "below boundary");
        assert_eq!(should_snapshot(&p5, 5).unwrap(), true, "inclusive boundary");
        assert_eq!(should_snapshot(&p5, 6).unwrap(), true, "above boundary");

        let p1 = SnapshotPolicy { every_events: 1 };
        assert_eq!(should_snapshot(&p1, 0).unwrap(), false);
        assert_eq!(should_snapshot(&p1, 1).unwrap(), true);

        let pmax = SnapshotPolicy {
            every_events: u32::MAX,
        };
        assert_eq!(should_snapshot(&pmax, u32::MAX).unwrap(), true);
        assert_eq!(should_snapshot(&pmax, u32::MAX - 1).unwrap(), false);
    }

    #[test]
    fn zero_cadence_policy_is_invalid() {
        let zero = SnapshotPolicy { every_events: 0 };
        assert_eq!(
            should_snapshot(&zero, 0).unwrap_err(),
            UpcastError::InvalidPolicy
        );
        assert_eq!(
            should_snapshot(&zero, 100).unwrap_err(),
            UpcastError::InvalidPolicy,
            "refused for every input, not just 0"
        );
    }

    // --- B6.4.3 · replay determinism ---------------------------------------

    #[test]
    fn replay_upcasts_every_event_and_is_deterministic() {
        let chain = vec![
            step(1, vec![rename("a", "b")]),
            step(2, vec![add("v", "2")]),
        ];
        let batch = vec![
            ev(1, "click", vec![f("a", "x")]),
            ev(2, "view", vec![f("b", "y")]),
            ev(3, "view", vec![f("b", "z"), f("v", "2")]),
        ];
        let run1 = replay(&batch, &chain).unwrap();
        let run2 = replay(&batch, &chain).unwrap();
        assert_eq!(run1, run2);
        assert_eq!(
            serde_json::to_string(&run1).unwrap(),
            serde_json::to_string(&run2).unwrap(),
            "§8 pin: serde_json round-trip equality across two runs"
        );
        assert_eq!(run1.len(), 3);
        assert!(run1.iter().all(|e| e.version == 3), "all at horizon");
        assert_eq!(names(&run1[0]), vec!["b", "v"]);
        assert_eq!(values(&run1[1]), vec!["y", "2"]);

        // Fingerprint: canonical JSON of the replay, stable across runs.
        let fp1 = replay_fingerprint(&batch, &chain).unwrap();
        let fp2 = replay_fingerprint(&batch, &chain).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1, serde_json::to_string(&run1).unwrap());

        // Empty batch replays to an empty stream.
        assert_eq!(replay(&[], &chain).unwrap(), Vec::<SchemaEvent>::new());
        assert_eq!(replay_fingerprint(&[], &chain).unwrap(), "[]");
    }

    #[test]
    fn replay_short_circuits_on_first_refusal() {
        let chain = vec![step(1, vec![rename("a", "b")])];
        let batch = vec![
            ev(1, "click", vec![f("a", "x")]),
            ev(0, "bad", vec![f("a", "y")]), // below horizon ⇒ NoPath
            ev(1, "click", vec![f("a", "z")]),
        ];
        let err = replay(&batch, &chain).unwrap_err();
        assert_eq!(err, UpcastError::NoPath { from: 0 });
        // Same refusal from the fingerprint path — no partial output anywhere.
        assert_eq!(
            replay_fingerprint(&batch, &chain).unwrap_err(),
            UpcastError::NoPath { from: 0 }
        );
    }

    // --- wire format --------------------------------------------------------

    #[test]
    fn serde_wire_pins() {
        // Transform: externally tagged, snake_case variants.
        assert_eq!(
            serde_json::to_value(rename("a", "b")).unwrap(),
            serde_json::json!({"rename_field": {"from": "a", "to": "b"}})
        );
        assert_eq!(
            serde_json::to_value(add("n", "v")).unwrap(),
            serde_json::json!({"add_field": {"name": "n", "value": "v"}})
        );
        assert_eq!(
            serde_json::to_value(drop("a")).unwrap(),
            serde_json::json!({"drop_field": {"name": "a"}})
        );
        let t = Transform::RenameField {
            from: "a".into(),
            to: "b".into(),
        };
        assert_eq!(
            serde_json::from_str::<Transform>(&serde_json::to_string(&t).unwrap()).unwrap(),
            t,
            "round-trip"
        );

        // Field / SchemaEvent / Upcaster / SnapshotPolicy round-trip.
        let e = ev(1, "click", vec![f("a", "1")]);
        let e2: SchemaEvent =
            serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(e2, e);
        let u = step(1, vec![rename("a", "b")]);
        let u2: Upcaster = serde_json::from_str(&serde_json::to_string(&u).unwrap()).unwrap();
        assert_eq!(u2, u);
        let p = SnapshotPolicy { every_events: 7 };
        let p2: SnapshotPolicy =
            serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(p2, p);

        // UpcastError is Serialize (repo precedent for &'static str payloads).
        assert_eq!(
            serde_json::to_value(UpcastError::NoPath { from: 2 }).unwrap(),
            serde_json::json!({"NoPath": {"from": 2}})
        );
        assert_eq!(
            serde_json::to_value(UpcastError::MissingField("x".into())).unwrap(),
            serde_json::json!({"MissingField": "x"})
        );
        assert_eq!(
            serde_json::to_value(UpcastError::NonContiguous).unwrap(),
            serde_json::json!("NonContiguous")
        );
    }

    #[test]
    fn upcast_error_display_pins() {
        assert_eq!(
            UpcastError::BadInput("upcaster").to_string(),
            "bad input: upcaster"
        );
        assert_eq!(
            UpcastError::NoPath { from: 3 }.to_string(),
            "no upcaster path from version 3"
        );
        assert_eq!(
            UpcastError::NonContiguous.to_string(),
            "upcaster step is not contiguous: to_version must equal from_version + 1"
        );
        assert_eq!(
            UpcastError::MissingField("a".into()).to_string(),
            "field not found: a"
        );
        assert_eq!(
            UpcastError::DuplicateField("b".into()).to_string(),
            "field already present: b"
        );
        assert_eq!(
            UpcastError::InvalidPolicy.to_string(),
            "invalid snapshot policy: every_events must be >= 1"
        );
    }
}
