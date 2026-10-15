//! Pin-registry integration tests (D1–D7 stub, registry side): lifecycle
//! receipts chain into the shared ledger, and every boundary fails closed.

use serde_json::json;

use tallow_registry::ledger::Ledger;
use tallow_registry::pins::{PinError, PinsStore, PIN_KIND_IDENTITY, PIN_KIND_SPKI};
use tallow_registry::receipt::{dev_actor_key, Receipt};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("tallow-pins-it-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn hex32(b: u8) -> String {
    hex::encode([b; 32])
}

/// Append a pin receipt the same way the CLI does (seq/prev from the ledger).
fn append_pin_receipt(
    ledger: &Ledger,
    kind: &str,
    actor: &str,
    id: &str,
    row_kind: &str,
    extra: serde_json::Value,
    key: &ed25519_dalek::SigningKey,
) {
    let mut data = json!({
        "id": id,
        "kind": row_kind,
        "mode": "pinned",
    });
    if let (Some(dst), Some(src)) = (data.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    let r = Receipt::sign_new(
        ledger.next_seq().unwrap(),
        kind,
        actor,
        Some(id),
        data,
        ledger.next_prev().unwrap(),
        key,
    );
    ledger.append(&r).expect("append");
}

#[test]
fn pin_lifecycle_receipts_chain_and_fail_closed() {
    let dir = tmpdir("lifecycle");
    let pins_path = dir.join("pins.json");
    let ledger = Ledger::new(dir.join("receipts.jsonl"));
    let key = dev_actor_key();
    let mut store = PinsStore::init(&pins_path).unwrap();

    let id = hex32(0x0a);

    // 1. add — receipt kind pin.add.
    let c = store.add(&id, PIN_KIND_IDENTITY, "oob", None).unwrap();
    assert!(!c.repin);
    append_pin_receipt(
        &ledger,
        "pin.add",
        "operator",
        &id,
        PIN_KIND_IDENTITY,
        json!({"source": "oob"}),
        &key,
    );

    // 2. re-pin — receipt kind pin.repin.
    let c = store
        .add(&id, PIN_KIND_IDENTITY, "operator", Some("renewed".into()))
        .unwrap();
    assert!(c.repin);
    append_pin_receipt(
        &ledger,
        "pin.repin",
        "operator",
        &id,
        PIN_KIND_IDENTITY,
        json!({"source": "operator", "repin": true}),
        &key,
    );

    // 3. revoke — receipt kind pin.revoke.
    store.revoke(&id).unwrap();
    append_pin_receipt(
        &ledger,
        "pin.revoke",
        "operator",
        &id,
        PIN_KIND_IDENTITY,
        json!({}),
        &key,
    );

    // Chain intact and all three kinds present, in order.
    let verdict = ledger.verify(&key.verifying_key());
    assert!(verdict.ok(), "ledger must verify: {:?}", verdict.errors);
    assert_eq!(verdict.rows, 3);
    let rows = ledger.iter().unwrap();
    let kinds: Vec<&str> = rows.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, vec!["pin.add", "pin.repin", "pin.revoke"]);
    // prev-chain: each row references the previous digest.
    assert!(rows[0].prev.is_none());
    assert_eq!(rows[1].prev.as_deref(), Some(rows[0].digest_hex().as_str()));
    assert_eq!(rows[2].prev.as_deref(), Some(rows[1].digest_hex().as_str()));

    // Fail-closed: revoked row must refuse resolution.
    assert!(matches!(
        store.require_active_identity_pin(&id),
        Err(PinError::Revoked(_))
    ));

    // Tamper detection: flip one byte of a receipt line → verify fails.
    let raw = std::fs::read_to_string(ledger.path()).unwrap();
    let tampered = raw.replacen("\"actor\":\"operator\"", "\"actor\":\"mallory\"", 1);
    assert_ne!(raw, tampered, "tamper must change the file");
    std::fs::write(ledger.path(), tampered).unwrap();
    let verdict = ledger.verify(&key.verifying_key());
    assert!(!verdict.ok(), "tampered ledger must fail");
}

#[test]
fn absent_pin_is_fail_closed_both_kinds() {
    let dir = tmpdir("absent");
    let store = PinsStore::init(&dir.join("pins.json")).unwrap();
    let id = hex32(0x0b);
    assert!(matches!(
        store.require_active_identity_pin(&id),
        Err(PinError::NotPinned(_))
    ));
    assert!(matches!(
        store.require_active_spki_pin(&id),
        Err(PinError::NotPinned(_))
    ));

    // An identity-kind row must not satisfy an SPKI resolution (and vice versa):
    // kind confusion is how a "pin" check becomes decorative.
    let mut store = store;
    store.add(&id, PIN_KIND_SPKI, "operator", None).unwrap();
    assert!(store.require_active_spki_pin(&id).is_ok());
    assert!(matches!(
        store.require_active_identity_pin(&id),
        Err(PinError::KindMismatch { .. })
    ));
}

#[test]
fn receipts_deny_unknown_fields_no_unsigned_ride_alongs() {
    // A receipt line with an extra top-level field must be rejected on parse —
    // the same strictness the pin rows rely on (deny_unknown_fields).
    let line = r#"{"v":1,"seq":1,"kind":"pin.add","ts_ms":1,"actor":"operator","subject":null,"data":{},"prev":null,"sig":null,"evil":"x"}"#;
    assert!(Receipt::from_line(line).is_err());
}
