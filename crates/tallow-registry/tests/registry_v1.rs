//! Library-level v1 tests: canonical encoding, receipt sign/verify, ledger
//! chain enforcement + tamper detection, store ops, bridge mapping.

use std::fs;

use serde_json::json;

use tallow_registry::bridge::to_device_entry;
use tallow_registry::receipt::dev_actor_key;
use tallow_registry::store::DeviceRow;
use tallow_registry::{canonical_json, Ledger, Query, Receipt, RegistryStore};

fn tmp(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("tallow-registry-test-{}-{tag}", std::process::id()));
    p
}

fn dev_pub_hex(name: &str) -> String {
    hex::encode(
        tallow_admission::device_identity(name)
            .ed
            .verifying_key()
            .to_bytes(),
    )
}

#[test]
fn canonical_order_independent() {
    let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).expect("parse");
    let b = json!({"a": {"x": 3, "y": 2}, "b": 1});
    assert_eq!(canonical_json(&a), canonical_json(&b));
}

#[test]
fn ledger_chain_append_verify_and_tamper() {
    let path = tmp("ledger.jsonl");
    let _ = fs::remove_file(&path);
    let led = Ledger::new(&path);
    let key = dev_actor_key();
    let vk = key.verifying_key();

    // empty ledger verifies clean
    let v = led.verify(&vk);
    assert!(v.ok() && v.rows == 0, "{:?}", v.errors);

    // three linked rows
    let r1 = Receipt::sign_new(
        1,
        "device.mint",
        "anchor-0",
        Some("operator-1"),
        json!({"role": "owner"}),
        None,
        &key,
    );
    led.append(&r1).expect("append r1");
    let r2 = Receipt::sign_new(
        2,
        "device.mint",
        "anchor-0",
        Some("guest-1"),
        json!({"role": "guest"}),
        Some(r1.digest_hex()),
        &key,
    );
    led.append(&r2).expect("append r2");
    let r3 = Receipt::sign_new(
        3,
        "device.revoke",
        "anchor-0",
        Some("guest-1"),
        json!({"prev_status": "active"}),
        Some(r2.digest_hex()),
        &key,
    );
    led.append(&r3).expect("append r3");

    let v = led.verify(&vk);
    assert!(v.ok(), "verdict errors: {:?}", v.errors);
    assert_eq!(v.rows, 3);

    // wrong seq refused
    let bad = Receipt::sign_new(
        9,
        "device.mint",
        "anchor-0",
        None,
        json!({}),
        Some(r3.digest_hex()),
        &key,
    );
    assert!(led.append(&bad).is_err(), "seq 9 must be refused");

    // wrong prev refused
    let bad2 = Receipt::sign_new(4, "device.mint", "anchor-0", None, json!({}), None, &key);
    assert!(led.append(&bad2).is_err(), "prev=None must be refused");

    // tamper the file itself → verification must fail
    let text = fs::read_to_string(&path).expect("read ledger");
    let doctored = text.replacen("\"device.mint\"", "\"device.MINT\"", 1);
    fs::write(&path, doctored).expect("write doctored");
    let v = led.verify(&vk);
    assert!(!v.ok(), "tampered ledger must fail verification");
    assert!(!v.errors.is_empty());

    let _ = fs::remove_file(&path);
}

#[test]
fn query_filters_and_limit_keeps_last() {
    let path = tmp("query.jsonl");
    let _ = fs::remove_file(&path);
    let led = Ledger::new(&path);
    let key = dev_actor_key();

    let mut prev: Option<String> = None;
    for (seq, kind, subj) in [
        (1u64, "device.mint", "a"),
        (2, "device.mint", "b"),
        (3, "device.revoke", "a"),
        (4, "door.auth", "c"),
    ] {
        let r = Receipt::sign_new(
            seq,
            kind,
            "anchor-0",
            Some(subj),
            json!({}),
            prev.clone(),
            &key,
        );
        prev = Some(r.digest_hex());
        led.append(&r).expect("append");
    }

    let mints = led
        .query(&Query {
            kind: Some("device.mint".into()),
            ..Default::default()
        })
        .expect("query");
    assert_eq!(mints.len(), 2);

    let subj_a = led
        .query(&Query {
            subject: Some("a".into()),
            ..Default::default()
        })
        .expect("query");
    assert_eq!(subj_a.len(), 2);

    let last2 = led
        .query(&Query {
            limit: Some(2),
            ..Default::default()
        })
        .expect("query");
    assert_eq!(
        last2.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![3, 4],
        "limit keeps the last n"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn store_ops_roundtrip() {
    let path = tmp("registry.json");
    let _ = fs::remove_file(&path);

    let mut store = RegistryStore::init(&path).expect("init");
    assert!(store.devices().is_empty());

    store
        .upsert(
            "operator-1",
            "owner",
            "active",
            &dev_pub_hex("operator-1"),
            Some("primary".into()),
        )
        .expect("upsert");
    let created = store.get("operator-1").expect("row").created_ms;

    std::thread::sleep(std::time::Duration::from_millis(3));
    store
        .upsert(
            "operator-1",
            "owner",
            "active",
            &dev_pub_hex("operator-1"),
            None,
        )
        .expect("re-upsert");
    assert_eq!(
        store.get("operator-1").expect("row").created_ms,
        created,
        "created_ms preserved on update"
    );

    store
        .upsert("guest-1", "guest", "active", &dev_pub_hex("guest-1"), None)
        .expect("upsert 2");
    store.revoke("guest-1").expect("revoke");
    store.save().expect("save");

    let reload = RegistryStore::load(&path).expect("reload");
    assert_eq!(reload.devices().len(), 2);
    assert_eq!(reload.get("guest-1").expect("guest").status, "revoked");

    // validation rejects bad inputs
    let mut s2 = RegistryStore::load(&path).expect("load");
    assert!(s2
        .upsert("x", "owner", "weird", &dev_pub_hex("x"), None)
        .is_err());
    assert!(s2.upsert("x", "owner", "active", "zz", None).is_err());
    assert!(s2.upsert("x", "owner", "active", "00", None).is_err());
    assert!(s2.revoke("nobody").is_err());

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("json.tmp"));
}

#[test]
fn bridge_maps_rows_to_entries() {
    let row = DeviceRow {
        id: "operator-1".into(),
        role: "owner".into(),
        status: "active".into(),
        ed_pub_hex: dev_pub_hex("operator-1"),
        created_ms: 0,
        updated_ms: 0,
        notes: None,
    };

    let entry = to_device_entry(&row).expect("bridge");
    assert_eq!(entry.id, "operator-1");
    assert!(entry.is_active());
    assert_eq!(
        entry.ed.to_bytes(),
        tallow_admission::device_identity("operator-1")
            .ed
            .verifying_key()
            .to_bytes()
    );

    let mut revoked = row.clone();
    revoked.status = "revoked".into();
    assert!(!to_device_entry(&revoked).expect("bridge").is_active());

    let mut bad_hex = row.clone();
    bad_hex.ed_pub_hex = "zz".into();
    assert!(to_device_entry(&bad_hex).is_err());

    let mut bad_status = row.clone();
    bad_status.status = "weird".into();
    assert!(to_device_entry(&bad_status).is_err());
}
