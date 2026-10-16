//! Battery-equivalent suite — port of `veil_battery.js` scenarios S1–S10,
//! driven against the pure state machines (no sockets; the loopback TCP
//! layer has its own test in `loopback.rs`).
//!
//! Acceptance anchor: every unauthenticated rejection class must produce
//! byte-identical cover bytes (S8 equality matrix, 6/6).

use std::sync::{Arc, Mutex};

use ed25519_dalek::Signer;
use serde_json::{json, Value};

use tallow_admission::devkeys::ed_from_label;
use tallow_admission::handshake::{random_pad, s1_digest, server_sig_digest};
use tallow_admission::{
    cover, device_identity, frame, now_ms, server_identity, AuditEvent, AuditSink, ClientConfig,
    ClientError, ClientSession, DeviceEntry, DeviceStatus, ServerCore, ServerSession,
    StaticRegistry, COVER_LEN,
};

// ---------------------------------------------------------------- plumbing

fn build_registry() -> StaticRegistry {
    let mut reg = StaticRegistry::new();
    let rows = [
        ("operator-1", "owner", DeviceStatus::Active),
        ("guest-1", "guest", DeviceStatus::Active),
        ("revoked-1", "owner", DeviceStatus::Revoked),
    ];
    for (name, role, status) in rows {
        let d = device_identity(name);
        reg.insert(DeviceEntry {
            id: name.to_string(),
            ed: d.ed.verifying_key(),
            role: role.to_string(),
            status,
        });
    }
    reg
}

fn setup() -> (Arc<ServerCore>, Arc<Mutex<Vec<String>>>) {
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink_log = Arc::clone(&log);
    let sink: AuditSink = Arc::new(move |ev: AuditEvent| {
        sink_log.lock().expect("audit log").push(ev.line());
    });
    let core = ServerCore::new(server_identity(), Arc::new(build_registry()), Some(sink));
    (core, log)
}

fn cfg_for(name: &str) -> ClientConfig {
    let si = server_identity();
    ClientConfig {
        device: device_identity(name),
        server_ed: si.ed.verifying_key(),
        server_x: x25519_dalek::PublicKey::from(&si.x),
        ts_override: None,
        tamper_sig: false,
    }
}

fn only_write(acts: Vec<tallow_admission::Action>) -> Vec<u8> {
    assert_eq!(acts.len(), 1, "expected exactly one action, got {acts:?}");
    match acts.into_iter().next().expect("one action") {
        tallow_admission::Action::Write(b) => b,
        other => panic!("expected Write, got {other:?}"),
    }
}

fn render(acts: &[tallow_admission::Action]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in acts {
        match a {
            tallow_admission::Action::Write(b) => out.extend_from_slice(b),
            tallow_admission::Action::Cover => out.extend_from_slice(cover()),
            tallow_admission::Action::Close => {}
        }
    }
    out
}

struct Adm {
    client: ClientSession,
    server: ServerSession,
}

/// Full admission pump; `Err(reason)` for rejected handshakes.
fn admit(core: &Arc<ServerCore>, cfg: ClientConfig) -> Result<Adm, String> {
    let mut server = core.accept();
    let mut client = ClientSession::new(cfg);
    let m2 = only_write(server.feed(&client.start()));
    let m3 = match client.feed(&m2) {
        Ok(acts) => only_write(acts),
        Err(e) => return Err(format!("client-error:{e}")),
    };
    let server_acts = server.feed(&m3);
    if server_acts
        .iter()
        .any(|a| matches!(a, tallow_admission::Action::Cover))
    {
        return Err("covered".into());
    }
    let ok = only_write(server_acts);
    match client.feed(&ok) {
        Ok(_) => {}
        Err(e) => return Err(format!("admission-error:{e}")),
    }
    if !client.is_admitted() {
        return Err("not-admitted".into());
    }
    Ok(Adm { client, server })
}

/// Server's final response bytes for one complete handshake attempt.
fn handshake_bytes(core: &Arc<ServerCore>, cfg: ClientConfig) -> Vec<u8> {
    let mut server = core.accept();
    let mut client = ClientSession::new(cfg);
    let m2 = only_write(server.feed(&client.start()));
    let m3 = match client.feed(&m2) {
        Ok(acts) => only_write(acts),
        Err(_) => return b"CLIENT-ERROR".to_vec(),
    };
    render(&server.feed(&m3))
}

/// Capture a valid handshake, then replay msg1+msg3 to a fresh connection;
/// returns the replay connection's response bytes.
fn replay_response(core: &Arc<ServerCore>) -> Vec<u8> {
    let mut server = core.accept();
    let mut client = ClientSession::new(cfg_for("operator-1"));
    let m2 = only_write(server.feed(&client.start()));
    let m3 = only_write(client.feed(&m2).expect("client msg3"));
    let _ok = server.feed(&m3);
    let mut server2 = core.accept();
    let _m2b = only_write(server2.feed(&client.start()));
    render(&server2.feed(&m3))
}

// ---------------------------------------------------------------- scenarios

#[test]
fn s0_cover_anchor() {
    assert_eq!(cover().len(), COVER_LEN);
}

#[test]
fn s1_happy_path_echo() {
    let (core, _log) = setup();
    let mut adm = admit(&core, cfg_for("operator-1")).expect("admitted");
    let fp = adm.client.key_fp().expect("key fp");
    assert_eq!(fp.len(), 16, "fingerprint is 16 hex chars");
    for i in 0..50 {
        let payload = format!("frame-{i}-payload");
        let req = adm
            .client
            .seal_call("echo", Some(Value::String(payload.clone())))
            .expect("seal");
        let resp_bytes = only_write(adm.server.feed(&req));
        adm.client.feed(&resp_bytes).expect("feed response");
        let resp = adm.client.take_response().expect("response");
        assert_eq!(resp["ok"], json!(true), "frame {i} ok");
        assert_eq!(resp["result"], json!(payload), "frame {i} echo integrity");
    }
}

#[test]
fn s2_replay_rejected_with_cover() {
    let (core, _log) = setup();
    // capture: a full valid handshake succeeded first
    let mut server = core.accept();
    let mut client = ClientSession::new(cfg_for("operator-1"));
    let m2 = only_write(server.feed(&client.start()));
    let m3 = only_write(client.feed(&m2).expect("client msg3"));
    let ok = only_write(server.feed(&m3));
    assert_eq!(ok, frame(b"OK"), "capture handshake succeeded");
    client.feed(&ok).expect("admitted");
    // replay to a fresh connection
    let out = replay_response(&core);
    assert_eq!(
        out,
        cover(),
        "replayed transcript rejected with cover bytes"
    );
}

#[test]
fn s3_tampered_signature_cover() {
    let (core, _log) = setup();
    let mut cfg = cfg_for("operator-1");
    cfg.tamper_sig = true;
    assert_eq!(handshake_bytes(&core, cfg), cover());
}

#[test]
fn s4_stale_timestamp_cover() {
    let (core, _log) = setup();
    let mut cfg = cfg_for("operator-1");
    cfg.ts_override = Some(now_ms().saturating_sub(3_600_000));
    assert_eq!(handshake_bytes(&core, cfg), cover());
}

#[test]
fn s5_unknown_device_cover() {
    let (core, _log) = setup();
    assert_eq!(handshake_bytes(&core, cfg_for("intruder-9")), cover());
}

#[test]
fn s6_revoked_device_cover() {
    let (core, _log) = setup();
    assert_eq!(handshake_bytes(&core, cfg_for("revoked-1")), cover());
}

#[test]
fn s7_forged_server_rejected_by_client() {
    let mut client = ClientSession::new(cfg_for("operator-1"));
    let _m1 = client.start();
    let s1 = s1_digest(client.msg1_payload());
    let rogue_ed = ed_from_label("tallow-test/rogue/ed25519");
    let eph_s = x25519_dalek::StaticSecret::from([9u8; 32]);
    let eph_s_pub = x25519_dalek::PublicKey::from(&eph_s);
    let nonce_s = [7u8; 32];
    let digest = server_sig_digest(&s1, eph_s_pub.as_bytes(), &nonce_s);
    let sig = rogue_ed.sign(&digest).to_bytes();
    let msg2 = tallow_admission::build_msg2(eph_s_pub.as_bytes(), &nonce_s, &sig, random_pad());

    // S7a: forged server rejected
    let err = client
        .feed(&frame(&msg2))
        .expect_err("rogue server must fail client auth");
    assert_eq!(err, ClientError::ServerAuthFailed);
    // S7b: client sent nothing after rogue msg2 (the Err carries no actions,
    // and the session is closed to further output)
    let after = client
        .feed(&frame(&msg2))
        .expect("closed is a silent no-op");
    assert!(
        after.is_empty(),
        "client must send nothing after auth failure"
    );
}

#[test]
fn s8_cover_equality_matrix() {
    let (core, _log) = setup();
    let mut classes: Vec<(&str, Vec<u8>)> = Vec::new();

    // short garbage frame
    let mut s = core.accept();
    classes.push(("short-garbage-frame", render(&s.feed(&frame(b"nope")))));

    // http GET probe: not a frame; decoder buffers, deadline fires
    let mut s = core.accept();
    let acts = s.feed(b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n");
    assert!(acts.is_empty(), "probe bytes must not parse as a frame yet");
    classes.push(("http-get-probe", render(&s.on_deadline())));

    // silent linger
    let mut s = core.accept();
    classes.push(("silent-linger", render(&s.on_deadline())));

    // unknown device
    classes.push((
        "unknown-device",
        handshake_bytes(&core, cfg_for("intruder-9")),
    ));

    // replay
    classes.push(("replay", replay_response(&core)));

    // tampered
    let mut cfg = cfg_for("operator-1");
    cfg.tamper_sig = true;
    classes.push(("tampered", handshake_bytes(&core, cfg)));

    let mut equal = 0;
    for (name, bytes) in &classes {
        let eq = bytes == cover();
        if eq {
            equal += 1;
        }
        println!(
            "S8 class={name} len={} {}",
            bytes.len(),
            if eq { "===" } else { "!=" }
        );
        assert_eq!(bytes, cover(), "class {name} must be cover bytes");
    }
    assert_eq!(equal, 6, "6/6 classes byte-identical");
}

#[test]
fn s9_rbac_allow_deny_audit() {
    let (core, log) = setup();
    let mut adm = admit(&core, cfg_for("operator-1")).expect("owner admitted");

    // owner publish allowed
    let req = adm.client.seal_call("portal.publish", None).expect("seal");
    let resp = only_write(adm.server.feed(&req));
    adm.client.feed(&resp).expect("feed");
    let r = adm.client.take_response().expect("resp");
    assert_eq!(r["ok"], json!(true), "owner publish allowed");

    // guest publish denied
    let mut g = admit(&core, cfg_for("guest-1")).expect("guest admitted");
    let req = g.client.seal_call("portal.publish", None).expect("seal");
    let resp = only_write(g.server.feed(&req));
    g.client.feed(&resp).expect("feed");
    let r = g.client.take_response().expect("resp");
    assert_eq!(r["ok"], json!(false));
    assert_eq!(r["code"], json!("denied"));

    // unknown action denied
    let req = adm.client.seal_call("teleport.moon", None).expect("seal");
    let resp = only_write(adm.server.feed(&req));
    adm.client.feed(&resp).expect("feed");
    let r = adm.client.take_response().expect("resp");
    assert_eq!(r["ok"], json!(false));
    assert_eq!(r["code"], json!("denied"));

    let denies = log
        .lock()
        .expect("log")
        .iter()
        .filter(|l| l.starts_with("DENY"))
        .count();
    assert!(denies >= 2, "deny audit entries recorded: {denies}");
}

#[test]
fn s10_session_keys_independent() {
    let (core, _log) = setup();
    let a = admit(&core, cfg_for("operator-1")).expect("first");
    let b = admit(&core, cfg_for("operator-1")).expect("second");
    assert_ne!(
        a.client.key_fp().expect("fp"),
        b.client.key_fp().expect("fp"),
        "independent sessions must not share keys"
    );
}
