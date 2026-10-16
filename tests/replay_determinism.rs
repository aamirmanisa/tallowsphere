//! B6.4.3 — replay-determinism CI: byte-equality checks for event replay.
//!
//! The upcaster suite (`src/upcasters.rs`) pins determinism at the unit level;
//! this integration target is the CI-callable byte-equality harness for the
//! replayed stream — identical inputs must produce serde-identical outputs
//! (fingerprint stability), and refusals must propagate without partial work.
//!
//! Run: `cargo test --test replay_determinism`
//! (wrapped by `scripts/replay_determinism.sh` as the CI job).

use tallow::upcasters::{
    replay, replay_fingerprint, should_snapshot, Field, SchemaEvent, SnapshotPolicy, Transform,
    Upcaster,
};

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

fn up(from: u32, to: u32, transforms: Vec<Transform>) -> Upcaster {
    Upcaster {
        from_version: from,
        to_version: to,
        transforms,
    }
}

/// A three-version chain: v1 -> v2 renames a field, v2 -> v3 adds one.
fn chain() -> Vec<Upcaster> {
    vec![
        up(
            1,
            2,
            vec![Transform::RenameField {
                from: "src".into(),
                to: "source".into(),
            }],
        ),
        up(
            2,
            3,
            vec![Transform::AddField {
                name: "replayed".into(),
                value: "true".into(),
            }],
        ),
    ]
}

fn events() -> Vec<SchemaEvent> {
    vec![
        ev(1, "ingest", vec![f("src", "alpha"), f("size", "12")]),
        ev(2, "ingest", vec![f("source", "beta"), f("size", "7")]),
        ev(3, "ingest", vec![f("source", "gamma")]),
    ]
}

#[test]
fn replay_is_byte_deterministic_across_runs() {
    let a = replay(&events(), &chain()).expect("first replay");
    let b = replay(&events(), &chain()).expect("second replay");
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap(),
        "replay outputs must be serde-identical for identical inputs"
    );
}

#[test]
fn fingerprint_is_stable_and_nonempty() {
    let fp1 = replay_fingerprint(&events(), &chain()).expect("fp1");
    let fp2 = replay_fingerprint(&events(), &chain()).expect("fp2");
    assert_eq!(fp1, fp2, "fingerprint must be byte-stable");
    assert!(!fp1.is_empty());
}

#[test]
fn fingerprint_changes_when_input_changes() {
    let base = replay_fingerprint(&events(), &chain()).expect("base");
    let mut altered = events();
    altered[0].fields[1].value = "13".into();
    let changed = replay_fingerprint(&altered, &chain()).expect("changed");
    assert_ne!(base, changed, "fingerprint must not be input-invariant");
}

#[test]
fn replay_refusal_propagates_without_partial_output() {
    // No upcaster claims version 1 -> NoPath refusal for a below-horizon event.
    let orphan = vec![ev(1, "ingest", vec![f("a", "1")])];
    let leap = vec![up(
        2,
        3,
        vec![Transform::AddField {
            name: "x".into(),
            value: "y".into(),
        }],
    )];
    assert!(replay(&orphan, &leap).is_err());
    assert!(replay_fingerprint(&orphan, &leap).is_err());
}

#[test]
fn snapshot_cadence_boundary_is_inclusive() {
    let pol = SnapshotPolicy { every_events: 5 };
    assert!(!should_snapshot(&pol, 4).unwrap());
    assert!(should_snapshot(&pol, 5).unwrap());
    let zero = SnapshotPolicy { every_events: 0 };
    assert!(should_snapshot(&zero, 1).is_err(), "zero cadence refused");
}
