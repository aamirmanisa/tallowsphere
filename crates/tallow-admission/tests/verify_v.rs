//! VERITY V-pass — independent adversarial edge tests beyond the battery
//! (V-series). Written against the crate as a black box (public API only),
//! trying to falsify the battery's claims. Findings are filed in
//! `runs/1.4-admission-port-VERITY-V.md` beside the program artifacts.

use std::sync::{Arc, Mutex};

use serde_json::json;

use tallow_admission::{
    cover, device_identity, frame, now_ms, server_identity, Action, AuditEvent, AuditSink,
    ClientConfig, ClientError, ClientSession, DeviceEntry, DeviceStatus, ServerCore, ServerSession,
    StaticRegistry,
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

fn only_write(acts: Vec<Action>) -> Vec<u8> {
    assert_eq!(acts.len(), 1, "expected exactly one action, got {acts:?}");
    match acts.into_iter().next().expect("one action") {
        Action::Write(b) => b,
        other => panic!("expected Write, got {other:?}"),
    }
}

fn render(acts: &[Action]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in acts {
        match a {
            Action::Write(b) => out.extend_from_slice(b),
            Action::Cover => out.extend_from_slice(cover()),
            Action::Close => {}
        }
    }
    out
}

struct Adm {
    client: ClientSession,
    server: ServerSession,
}

fn admit(core: &Arc<ServerCore>, cfg: ClientConfig) -> Result<Adm, String> {
    let mut server = core.accept();
    let mut client = ClientSession::new(cfg);
    let m2 = only_write(server.feed(&client.start()));
    let m3 = match client.feed(&m2) {
        Ok(acts) => only_write(acts),
        Err(e) => return Err(format!("client-error:{e}")),
    };
    let server_acts = server.feed(&m3);
    if server_acts.iter().any(|a| matches!(a, Action::Cover)) {
        return Err("covered".into());
    }
    let ok = only_write(server_acts);
    if let Err(e) = client.feed(&ok) {
        return Err(format!("admission-error:{e}"));
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

/// A server holding an open handshake after msg1; returns (server, msg2).
fn server_with_msg1(core: &Arc<ServerCore>) -> (ServerSession, Vec<u8>) {
    let mut s = core.accept();
    let c = ClientSession::new(cfg_for("operator-1"));
    let m2 = only_write(s.feed(&c.start()));
    (s, m2)
}

fn msg3_raw(id_bytes: &[u8], ts: u64, sig: &[u8; 64]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"T1C");
    v.extend_from_slice(id_bytes);
    v.extend_from_slice(&ts.to_be_bytes());
    v.extend_from_slice(sig);
    v
}

// ------------------------------------------------------------------ V-series

#[test]
fn v1_msg1_length_boundaries() {
    let (core, _log) = setup();

    // one byte below the minimum (34 B) → cover
    let mut short = vec![b'T', b'1', b'S'];
    short.extend_from_slice(&[0u8; 31]);
    let mut s = core.accept();
    assert_eq!(
        render(&s.feed(&frame(&short))),
        cover(),
        "34-B msg1 must cover"
    );

    // exact minimum (3 + 32, zero pad) → accepted, msg2 returned
    let mut exact = vec![b'T', b'1', b'S'];
    exact.extend_from_slice(&[7u8; 32]);
    let mut s = core.accept();
    let acts = s.feed(&frame(&exact));
    assert_eq!(acts.len(), 1, "exact-minimum msg1 gets exactly one reply");
    match &acts[0] {
        Action::Write(b) => {
            assert_eq!(&b[2..5], b"T1A", "reply is a well-formed msg2 frame");
        }
        other => panic!("expected Write(msg2), got {other:?}"),
    }
}

#[test]
fn v2_msg2_and_msg3_length_boundaries() {
    let (core, _log) = setup();

    // client: 130-B frame (below msg2 minimum 131) → BadMsg2
    let mut client = ClientSession::new(cfg_for("operator-1"));
    let _ = client.start();
    let err = client
        .feed(&frame(&[0u8; 130]))
        .expect_err("short msg2 must be rejected");
    assert_eq!(err, ClientError::BadMsg2);

    // server: msg3 one byte below the minimum (75 B) → cover
    let (mut s, _m2) = server_with_msg1(&core);
    let mut short3 = vec![b'T', b'1', b'C'];
    short3.extend_from_slice(&[0u8; 72]); // 75 total
    assert_eq!(
        render(&s.feed(&frame(&short3))),
        cover(),
        "75-B msg3 must cover"
    );
}

#[test]
fn v3_malformed_device_id_bytes_cover() {
    let (core, _log) = setup();

    // non-UTF8 device-id bytes → cover (parse fails before any crypto check)
    let (mut s, _m2) = server_with_msg1(&core);
    let bogus3 = msg3_raw(&[0xff, 0xfe, 0xfd], now_ms(), &[0u8; 64]);
    assert_eq!(
        render(&s.feed(&frame(&bogus3))),
        cover(),
        "non-UTF8 id must cover"
    );
}

#[test]
fn v4_timestamp_window_boundaries() {
    let (core, _log) = setup();

    // 119 s old — inside the ±120 s window → admitted
    let mut cfg = cfg_for("operator-1");
    cfg.ts_override = Some(now_ms().saturating_sub(119_000));
    assert_eq!(
        handshake_bytes(&core, cfg),
        frame(b"OK"),
        "119-s-old handshake must be admitted"
    );

    // 121 s old — outside the window → cover
    let mut cfg = cfg_for("operator-1");
    cfg.ts_override = Some(now_ms().saturating_sub(121_000));
    assert_eq!(
        handshake_bytes(&core, cfg),
        cover(),
        "121-s-old handshake must cover"
    );

    // far future → cover
    let mut cfg = cfg_for("operator-1");
    cfg.ts_override = Some(now_ms() + 600_000);
    assert_eq!(
        handshake_bytes(&core, cfg),
        cover(),
        "future timestamp must cover"
    );

    // epoch 0 → cover
    let mut cfg = cfg_for("operator-1");
    cfg.ts_override = Some(0);
    assert_eq!(
        handshake_bytes(&core, cfg),
        cover(),
        "epoch-0 timestamp must cover"
    );
}

#[test]
fn v5_coalesced_msg1_plus_bogus_msg3() {
    let (core, _log) = setup();

    // attacker pipelines msg1 and a forged msg3 in ONE chunk: the server must
    // reply msg2 for frame 1 and cover for the (invalid-for-fresh-transcript)
    // frame 2 — exactly [Write(msg2), Cover], nothing more.
    let mut s = core.accept();
    let c = ClientSession::new(cfg_for("operator-1"));
    let m1 = c.start();
    let bogus3 = msg3_raw(b"operator-1", now_ms(), &[0u8; 64]);
    let mut chunk = m1.clone();
    chunk.extend_from_slice(&frame(&bogus3));

    let acts = s.feed(&chunk);
    assert_eq!(
        acts.len(),
        2,
        "expected exactly [Write(msg2), Cover], got {acts:?}"
    );
    match &acts[0] {
        Action::Write(b) => assert_eq!(&b[2..5], b"T1A", "first action is msg2"),
        other => panic!("expected Write(msg2) first, got {other:?}"),
    }
    assert_eq!(acts[1], Action::Cover, "second action is cover");
    // and the session is now silent
    assert!(s.feed(&frame(b"more")).is_empty());
    assert!(s.on_deadline().is_empty());
}

#[test]
fn v6_v1_sealed_frame_replay_rejected() {
    // v1 HARDENING (2026-10-15): rx-counter monotonicity is now enforced in
    // `AeadChan::open`, so a captured sealed frame replayed into a live
    // session is REFUSED (`AeadError::Replay`) instead of being processed.
    // The server's `step_session` maps any open failure to `Close`, so the
    // replay tears the session down rather than satisfying the request.
    //
    // This test was `v6_v0_known_limitation_sealed_frame_replay_processed`,
    // whose comment said: "When rx-counter enforcement lands, FLIP the second
    // assertion to expect rejection (this test is the tripwire)." That is
    // this change. The pre-fix behaviour is preserved as an executable proof
    // in `aead.rs` (`proof_replay_is_processed_on_the_unfixed_code`).
    let (core, _log) = setup();
    let mut adm = admit(&core, cfg_for("operator-1")).expect("admitted");

    let req = adm
        .client
        .seal_call("echo", Some(json!({"replay-me": true})))
        .expect("seal");
    let resp1 = only_write(adm.server.feed(&req));
    adm.client.feed(&resp1).expect("feed");
    let r1 = adm.client.take_response().expect("resp1");
    assert_eq!(r1["ok"], json!(true));

    // Replay the very same sealed frame bytes: the server must now REFUSE
    // and close, not answer a second time.
    let replay_actions = adm.server.feed(&req);
    assert_eq!(
        replay_actions.len(),
        1,
        "a replayed frame must produce exactly one action (Close), got {replay_actions:?}"
    );
    assert!(
        matches!(replay_actions[0], Action::Close),
        "v1 behaviour: a replayed sealed frame must CLOSE the session, got {:?}",
        replay_actions[0]
    );
}

#[test]
fn v7_oversized_declared_frame_waits_then_covers() {
    let (core, _log) = setup();
    let mut s = core.accept();
    // declares 65535 bytes, delivers 10
    let mut partial = vec![0xff, 0xff];
    partial.extend_from_slice(&[0u8; 10]);
    assert!(
        s.feed(&partial).is_empty(),
        "incomplete frame must not produce actions"
    );
    assert_eq!(render(&s.on_deadline()), cover(), "deadline must cover");
}

#[test]
fn v8_closed_session_is_silent() {
    let (core, _log) = setup();
    let mut s = core.accept();
    assert_eq!(render(&s.feed(&frame(b"nope"))), cover());
    assert!(
        s.feed(&frame(b"nope")).is_empty(),
        "no second reply after cover"
    );
    assert!(s.on_deadline().is_empty(), "no deadline reply after cover");
}

#[test]
fn v9_policy_surface_owner_guest() {
    let (core, _log) = setup();

    // owner: hermes.config.read allowed
    let mut adm = admit(&core, cfg_for("operator-1")).expect("owner admitted");
    let req = adm
        .client
        .seal_call("hermes.config.read", None)
        .expect("seal");
    let resp = only_write(adm.server.feed(&req));
    adm.client.feed(&resp).expect("feed");
    let r = adm.client.take_response().expect("resp");
    assert_eq!(r["ok"], json!(true), "owner hermes.config.read allowed");

    // guest: portal.view allowed
    let mut g = admit(&core, cfg_for("guest-1")).expect("guest admitted");
    let req = g.client.seal_call("portal.view", None).expect("seal");
    let resp = only_write(g.server.feed(&req));
    g.client.feed(&resp).expect("feed");
    let r = g.client.take_response().expect("resp");
    assert_eq!(r["ok"], json!(true), "guest portal.view allowed");

    // blank act → denied (server treats missing/blank act as unknown)
    let req = g.client.seal_call("", None).expect("seal");
    let resp = only_write(g.server.feed(&req));
    g.client.feed(&resp).expect("feed");
    let r = g.client.take_response().expect("resp");
    assert_eq!(r["ok"], json!(false));
    assert_eq!(r["code"], json!("denied"));
}
