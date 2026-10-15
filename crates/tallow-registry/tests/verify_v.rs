//! VERITY V-pass — adversarial edges for the registry + receipts v1
//! (V-series). Black-box against the public API, trying to falsify the
//! E-side claims. Findings are filed in
//! `runs/2.2-fleet-registry-VERITY-V.md` beside the program artifacts.

use std::fs;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use tallow_registry::bridge::to_device_entry;
use tallow_registry::receipt::{dev_actor_key, ReceiptError};
use tallow_registry::store::DeviceRow;
use tallow_registry::{canonical_json, Ledger, LedgerError, Query, Receipt, RegistryStore};

fn tmp(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "tallow-registry-verify-{}-{tag}",
        std::process::id()
    ));
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

fn sign(seq: u64, prev: Option<String>, key: &SigningKey) -> Receipt {
    Receipt::sign_new(
        seq,
        "device.mint",
        "anchor-0",
        Some("subject-x"),
        json!({"n": seq}),
        prev,
        key,
    )
}

// ------------------------------------------------------------------ V-series

#[test]
fn v1_canonical_edge_cases() {
    // case ordering is UTF-8 code-point order: "B" (0x42) < "a" (0x61)
    assert_eq!(canonical_json(&json!({"a": 1, "B": 2})), r#"{"B":2,"a":1}"#);
    // empty containers
    assert_eq!(
        canonical_json(&json!({"e": {}, "a": []})),
        r#"{"a":[],"e":{}}"#
    );
    // array element order is semantic and preserved; nested objects sort
    assert_eq!(
        canonical_json(&json!([{"b": 1, "a": 2}, {"z": 3}])),
        r#"[{"a":2,"b":1},{"z":3}]"#
    );
    // large integers stay exact (no float coercion)
    let v: Value = serde_json::from_str(r#"{"n":9007199254740993}"#).expect("parse");
    assert_eq!(canonical_json(&v), r#"{"n":9007199254740993}"#);
    // unicode keys sort by code point; both emitted raw
    assert_eq!(canonical_json(&json!({"é": 1, "e": 2})), r#"{"e":2,"é":1}"#);
}

#[test]
fn v2_error_variants_are_precise() {
    let key = dev_actor_key();
    let vk = key.verifying_key();
    let r = Receipt::sign_new(
        1,
        "device.mint",
        "anchor-0",
        Some("x"),
        json!({}),
        None,
        &key,
    );

    // unsigned
    let mut unsigned = r.clone();
    unsigned.sig = None;
    assert!(matches!(unsigned.verify(&vk), Err(ReceiptError::Unsigned)));

    // non-hex signature
    let mut bad_hex = r.clone();
    bad_hex.sig.as_mut().expect("sig").sig_hex = "zz".into();
    assert!(matches!(bad_hex.verify(&vk), Err(ReceiptError::BadHex(_))));

    // wrong signature length
    let mut short = r.clone();
    short.sig.as_mut().expect("sig").sig_hex = "abcd".into();
    assert!(matches!(short.verify(&vk), Err(ReceiptError::BadSigLen(2))));

    // wrong key → fingerprint mismatch (key_fp checked before signature)
    let other = tallow_admission::devkeys::ed_from_label("tallow-test/registry/other");
    assert!(matches!(
        r.verify(&other.verifying_key()),
        Err(ReceiptError::KeyFp { .. })
    ));

    // right key, signature over the wrong message → BadSignature
    let mut wrong_msg = r.clone();
    let bogus = key.sign(b"not-the-digest");
    wrong_msg.sig.as_mut().expect("sig").sig_hex = hex::encode(bogus.to_bytes());
    assert!(matches!(
        wrong_msg.verify(&vk),
        Err(ReceiptError::BadSignature(_))
    ));
}

#[test]
fn v3_future_versions_rejected() {
    let key = dev_actor_key();
    let r = Receipt::sign_new(1, "device.mint", "anchor-0", None, json!({}), None, &key);
    let line = r.to_line();
    assert!(Receipt::from_line(&line).is_ok(), "v1 parses");

    let v2 = line.replace("\"v\":1", "\"v\":2");
    assert_ne!(v2, line, "replacement applied");
    assert!(
        matches!(
            Receipt::from_line(&v2),
            Err(ReceiptError::UnsupportedVersion(2))
        ),
        "a v1 reader must reject v2 rows (fail closed)"
    );
}

#[test]
fn v4_chain_rejects_skip_links_and_reorder() {
    let path = tmp("v4.jsonl");
    let _ = fs::remove_file(&path);
    let key = dev_actor_key();
    let led = Ledger::new(&path);

    let r1 = sign(1, None, &key);
    led.append(&r1).expect("r1");
    let r2 = sign(2, Some(r1.digest_hex()), &key);
    led.append(&r2).expect("r2");
    let r3 = sign(3, Some(r2.digest_hex()), &key);
    led.append(&r3).expect("r3");

    // a valid-but-non-adjacent digest as prev → refused (adjacency enforced)
    let skip = sign(4, Some(r1.digest_hex()), &key);
    assert!(matches!(led.append(&skip), Err(LedgerError::Prev)));

    // swapping two rows in the file → verification fails
    let text = fs::read_to_string(&path).expect("read");
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines.swap(1, 2);
    fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write swapped");

    let v = led.verify(&key.verifying_key());
    assert!(!v.ok(), "swapped rows must fail verification");
    assert_eq!(v.rows, 3);

    let _ = fs::remove_file(&path);
}

#[test]
fn v5_line_endings_and_blank_lines() {
    let path = tmp("v5.jsonl");
    let _ = fs::remove_file(&path);
    let key = dev_actor_key();
    let led = Ledger::new(&path);

    let r1 = sign(1, None, &key);
    led.append(&r1).expect("r1");
    let r2 = sign(2, Some(r1.digest_hex()), &key);
    led.append(&r2).expect("r2");

    // LF → CRLF conversion must not break verification
    let text = fs::read_to_string(&path).expect("read");
    fs::write(&path, text.replace('\n', "\r\n")).expect("crlf");
    let v = led.verify(&key.verifying_key());
    assert!(v.ok(), "CRLF must verify clean: {:?}", v.errors);

    // a blank line between rows is tolerated
    let text = fs::read_to_string(&path).expect("read");
    let with_blank = text.replacen("\r\n", "\r\n\r\n", 1);
    fs::write(&path, with_blank).expect("blank line");
    let v = led.verify(&key.verifying_key());
    assert!(
        v.ok() && v.rows == 2,
        "blank line tolerated: {:?}",
        v.errors
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn v6_query_zero_limit_and_actor_filter() {
    let path = tmp("v6.jsonl");
    let _ = fs::remove_file(&path);
    let key = dev_actor_key();
    let led = Ledger::new(&path);

    let r1 = sign(1, None, &key);
    led.append(&r1).expect("r1");
    let r2 = Receipt::sign_new(
        2,
        "device.mint",
        "other-actor",
        Some("subject-x"),
        json!({"n": 2}),
        Some(r1.digest_hex()),
        &key,
    );
    led.append(&r2).expect("r2");

    let none = led
        .query(&Query {
            limit: Some(0),
            ..Default::default()
        })
        .expect("query");
    assert!(none.is_empty(), "limit 0 returns nothing");

    let other = led
        .query(&Query {
            actor: Some("other-actor".into()),
            ..Default::default()
        })
        .expect("query");
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].seq, 2);

    let _ = fs::remove_file(&path);
}

#[test]
fn v7_store_revoke_idempotent_and_case_strict() {
    let path = tmp("v7.json");
    let _ = fs::remove_file(&path);
    let mut s = RegistryStore::init(&path).expect("init");

    s.upsert(
        "ünïcode-device",
        "owner",
        "active",
        &dev_pub_hex("operator-1"),
        Some("ünïcode notes ✓".into()),
    )
    .expect("upsert unicode");
    s.revoke("ünïcode-device").expect("revoke");
    let first_updated = s.get("ünïcode-device").expect("row").updated_ms;

    std::thread::sleep(std::time::Duration::from_millis(3));
    s.revoke("ünïcode-device").expect("re-revoke is ok");
    assert!(
        s.get("ünïcode-device").expect("row").updated_ms >= first_updated,
        "re-revoke bumps updated_ms"
    );

    // status is case-strict: "ACTIVE" is invalid
    assert!(
        s.upsert("x", "owner", "ACTIVE", &dev_pub_hex("x"), None)
            .is_err(),
        "uppercase status must be rejected"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn v8_bridge_passes_role_through_status_strict() {
    let row = DeviceRow {
        id: "d".into(),
        role: "operator/weird role".into(),
        status: "active".into(),
        ed_pub_hex: dev_pub_hex("guest-1"),
        created_ms: 0,
        updated_ms: 0,
        notes: None,
    };
    let entry = to_device_entry(&row).expect("bridge");
    assert_eq!(entry.role, "operator/weird role", "role is passthrough");

    let mut cased = row.clone();
    cased.status = "Active".into();
    assert!(to_device_entry(&cased).is_err(), "status is case-strict");
}

#[test]
fn v9_parse_errors_surface_with_row_numbers() {
    let path = tmp("v9.jsonl");
    let _ = fs::remove_file(&path);
    let key = dev_actor_key();

    let r1 = sign(1, None, &key);
    let content = format!("{}\nnot-json-at-all\n", r1.to_line());
    fs::write(&path, content).expect("write");

    let led = Ledger::new(&path);
    let err = led.iter().expect_err("row 2 must fail to parse");
    assert!(
        matches!(err, LedgerError::Receipt(2, _)),
        "row number carried: {err:?}"
    );

    let v = led.verify(&key.verifying_key());
    assert!(!v.ok());
    assert!(
        v.errors.iter().any(|e| e.contains("row 2")),
        "verdict names row 2: {:?}",
        v.errors
    );

    let _ = fs::remove_file(&path);
}
