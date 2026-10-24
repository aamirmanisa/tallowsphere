//! TallowTransfer transport fallback tests — rows #131/#132 (R-08 batch 3,
//! design P4-3): TCP+TLS 1.3 fallback transport over SOCKS5, policy-aware
//! negotiation, fail-closed routing, Happy Eyeballs v2.
//!
//! Real fixtures from `tallow_net::transport::test_support` (loopback only;
//! nothing leaves the box): a SOCKS5 CONNECT proxy, a TLS 1.3 echo server, and
//! a relay-v1 pairing fixture (plaintext or TLS 1.3).
//!
//! Asserted behaviors:
//!   1. Tor/proxied route ⇒ relay-v1 file data moves over SOCKS5 → TLS 1.3
//!      (the proxy receives the relay *name* — remote DNS, no local leak);
//!   2. fail-closed: a proxied route with an unreachable proxy refuses, and a
//!      direct trap endpoint never sees a connection;
//!   3. direct-route regression: the plain-TCP relay path still round-trips
//!      (hostname form exercises Happy Eyeballs v2);
//!   4. QUIC-blocked ⇒ the fallback transport engages TCP+TLS; a proxied route
//!      denies direct peer connects.
//!
//! W5-D (2026-09-27) note: the two tests that complete TLS handshakes against
//! self-signed fixtures (`relay_transfer_over_proxied_tls_round_trips`,
//! `peer_transport_fallback_engages_and_proxied_route_denies_direct`) carry an
//! `#[ignore]` gate: the root crate builds `tallow-net` with
//! `default-features = false`, so tallow-net's `dangerous_skip_verify`
//! (its self-signed dev cohort) is off and those handshakes are rejected
//! (UnknownIssuer) unless the dep feature is enabled:
//!   cargo test --test transfer_transport --features tallow-net/dangerous_skip_verify -- --ignored
//! See `artifacts/sendtallow-openwork-swarm-2026-09-27/lanes/transfer-tests-sweep.md`.

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use tallow::interp::Value;
use tallow::stdlib::transfer_net::{
    connect_peer_transport_with, resolve_transport_policy, transfer_policy_for, PeerTransportKind,
    TALLOW_ALLOW_DIRECT_ENV, TALLOW_PROXY_ENV, TALLOW_TOR_ENV,
};
use tallow_net::transport::test_support::{RelayFixture, Socks5Fixture, TlsEchoFixture};

const RELAY_WAIT_SECS: &str = "60";

// ── Helpers ─────────────────────────────────────────────────────────────────

fn dispatch_ok(function: &str, args: Vec<Value>) -> Value {
    match tallow::stdlib::transfer_net::dispatch(function, args) {
        Some(Ok(v)) => v,
        Some(Err(e)) => panic!("dispatch({function}) failed: {e}"),
        None => panic!("dispatch({function}) not routed"),
    }
}

fn struct_field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    if let Value::Struct { fields, .. } = v {
        fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    } else {
        None
    }
}

fn field_str(v: &Value, name: &str) -> String {
    struct_field(v, name)
        .unwrap_or_else(|| panic!("field {name} missing"))
        .as_string()
}

fn field_bool(v: &Value, name: &str) -> bool {
    matches!(struct_field(v, name), Some(Value::Bool(true)))
}

fn write_test_file(dir: &std::path::Path, name: &str, len: usize) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut data = Vec::with_capacity(len);
    let mut x: u32 = 0x1234_5678;
    while data.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.extend_from_slice(&x.to_le_bytes());
    }
    data.truncate(len);
    std::fs::write(&path, &data).expect("write test file");
    path
}

fn trap_is_quiet(listener: &TcpListener) -> bool {
    matches!(
        listener.accept(),
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
    )
}

fn set_relay_wait() {
    // SAFETY: single-threaded at this point; all tests set the same value and
    // no other code in this binary depends on the variable.
    unsafe { std::env::set_var("TALLOW_RELAY_WAIT_SECS", RELAY_WAIT_SECS) };
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Row acceptance (#131/#132): Tor-mode proxy route moves file data over
/// SOCKS5 → TLS 1.3, end-to-end relay-v1 send/receive, byte-identical.
///
/// Gated 2026-09-27 (W5-D hardened verify): the relay fixture serves a
/// runtime self-signed cert and the tallow-net TLS client verifies it
/// (UnknownIssuer) under the root crate's dependency features. Run with:
/// `cargo test --test transfer_transport --features tallow-net/dangerous_skip_verify -- --ignored`
#[ignore = "self-signed fixture vs hardened tallow-net verify; see lanes/transfer-tests-sweep.md"]
#[test]
fn relay_transfer_over_proxied_tls_round_trips() {
    set_relay_wait();

    let relay = RelayFixture::start(true).expect("relay fixture");
    let socks = Socks5Fixture::start(relay.addr).expect("socks5 fixture");
    let proxy_url = format!("socks5h://{}", socks.addr);

    let tmp = tempfile::tempdir().expect("tempdir");
    let src = write_test_file(tmp.path(), "payload.bin", 256 * 1024);
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).expect("mkdir out");

    let code = "131-fallback-transport-code";
    // Name-only relay address: only the SOCKS5 remote-DNS path can reach it.
    let relay_addr = format!("relay.invalid:{}", relay.addr.port());
    let out_dir_s = out_dir.display().to_string();
    let relay_s = relay_addr.clone();
    let proxy_s = proxy_url.clone();

    // NOTE: `tallow::Value` is not `Send` (interpreter values may hold Rc), so
    // the receiver thread builds its own args and returns only plain data.
    let receiver = std::thread::spawn(move || -> Result<(String, bool), String> {
        let args = vec![
            Value::String(code.to_string()),
            Value::String(out_dir_s),
            Value::String(relay_s),
            Value::String(String::new()),
            Value::Bool(true),
            Value::Bool(false),
            Value::String(proxy_s),
        ];
        match tallow::stdlib::transfer_net::dispatch("relay_receive", args) {
            Some(Ok(v)) => Ok((field_str(&v, "transport"), field_bool(&v, "verified"))),
            Some(Err(e)) => Err(e),
            None => Err("relay_receive not routed".to_string()),
        }
    });

    // Give the receiver time to register at the relay before the sender pairs.
    std::thread::sleep(Duration::from_millis(300));

    let sent = dispatch_ok(
        "relay_send",
        vec![
            Value::String(src.display().to_string()),
            Value::String(relay_addr.clone()),
            Value::String(code.to_string()),
            Value::Int(0),
            Value::Bool(false),
            Value::String(proxy_url.clone()),
        ],
    );
    assert!(
        field_str(&sent, "transport").contains("tor"),
        "send route must be the Tor/proxied route, got {:?}",
        field_str(&sent, "transport")
    );

    let (recv_transport, verified) = receiver
        .join()
        .expect("receiver thread")
        .expect("relay receive failed");
    assert!(verified);
    assert!(
        recv_transport.contains("tor"),
        "receive route must be the Tor/proxied route, got {recv_transport:?}"
    );

    // Byte-identical delivery.
    let got = std::fs::read(out_dir.join("payload.bin")).expect("received file");
    let want = std::fs::read(&src).expect("source file");
    assert_eq!(got, want, "received bytes differ from source");

    // The SOCKS5 proxy saw both clients, addressed by relay *name* (remote DNS).
    assert_eq!(
        socks.connects(),
        2,
        "both relay clients must ride the proxy"
    );
    let seen = socks.targets();
    assert_eq!(seen.len(), 2);
    for (host, port) in &seen {
        assert_eq!(host, "relay.invalid", "remote-DNS name must reach the proxy");
        assert_eq!(*port, relay.addr.port());
    }

    // The relay terminated TLS 1.3 for both clients.
    let versions = relay.tls_versions();
    assert_eq!(versions.len(), 2, "two TLS handshakes expected: {versions:?}");
    assert!(
        versions
            .iter()
            .all(|v| v.contains("TLSv1_3") || v.contains("TLSv1.3")),
        "TLS 1.3 required, got {versions:?}"
    );
}

/// Row acceptance (#132): a proxied route with an unreachable proxy refuses
/// and never falls back to a direct connection.
#[test]
fn proxied_route_refuses_when_proxy_unreachable_and_never_dials_direct() {
    let trap = TcpListener::bind("127.0.0.1:0").expect("bind trap");
    let trap_addr = trap.local_addr().unwrap();
    trap.set_nonblocking(true).unwrap();

    let tmp = tempfile::tempdir().expect("tempdir");
    let src = write_test_file(tmp.path(), "payload.bin", 4096);

    let dead_proxy = "socks5h://127.0.0.1:1";
    let result = tallow::stdlib::transfer_net::dispatch(
        "relay_send",
        vec![
            Value::String(src.display().to_string()),
            Value::String(format!("127.0.0.1:{}", trap_addr.port())),
            Value::String("132-fail-closed-code".to_string()),
            Value::Int(0),
            Value::Bool(false),
            Value::String(dead_proxy.to_string()),
        ],
    );
    match result {
        Some(Err(e)) => {
            assert!(
                e.contains("fail-closed"),
                "refusal must state the fail-closed policy, got: {e}"
            );
        }
        other => panic!("expected a fail-closed refusal, got {other:?}"),
    }

    std::thread::sleep(Duration::from_millis(150));
    assert!(
        trap_is_quiet(&trap),
        "fail-closed violation: the direct relay endpoint received a connection"
    );
}

/// Regression: the direct (non-proxied) relay path still round-trips; the
/// hostname form exercises Happy Eyeballs v2 in the product code.
#[test]
fn direct_relay_path_still_round_trips_via_happy_eyeballs() {
    set_relay_wait();

    let relay = RelayFixture::start(false).expect("relay fixture");
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = write_test_file(tmp.path(), "direct.bin", 64 * 1024);
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).expect("mkdir out");

    // The mint accepts 8 symbols only; this fixture predated that rule and used
    // a descriptive string, so the test failed on the code validator rather than
    // on the transport it is meant to exercise.
    let code = "K7M2QPHD";
    let out_dir_s = out_dir.display().to_string();
    let relay_s = format!("127.0.0.1:{}", relay.addr.port());

    // Receiver thread: build args in-thread (Value is not Send), return plain data.
    let receiver = std::thread::spawn(move || -> Result<(String, bool), String> {
        let args = vec![
            Value::String(code.to_string()),
            Value::String(out_dir_s),
            Value::String(relay_s),
            Value::String(String::new()),
            Value::Bool(true),
            Value::Bool(false),
        ];
        match tallow::stdlib::transfer_net::dispatch("relay_receive", args) {
            Some(Ok(v)) => Ok((field_str(&v, "transport"), field_bool(&v, "verified"))),
            Some(Err(e)) => Err(e),
            None => Err("relay_receive not routed".to_string()),
        }
    });
    std::thread::sleep(Duration::from_millis(300));

    // Sender uses the hostname form → Happy Eyeballs v2 dual-stack connect.
    let sent = dispatch_ok(
        "relay_send",
        vec![
            Value::String(src.display().to_string()),
            Value::String(format!("localhost:{}", relay.addr.port())),
            Value::String(code.to_string()),
            Value::Int(0),
            Value::Bool(false),
        ],
    );
    assert!(
        field_str(&sent, "transport").contains("direct"),
        "direct route expected, got {:?}",
        field_str(&sent, "transport")
    );

    let (_recv_transport, verified) = receiver
        .join()
        .expect("receiver thread")
        .expect("relay receive failed");
    assert!(verified);
    let got = std::fs::read(out_dir.join("direct.bin")).expect("received file");
    assert_eq!(got, std::fs::read(&src).unwrap());
}

/// QUIC-blocked ⇒ the fallback transport engages TCP+TLS; the proxied route
/// denies direct peer connects (fail-closed) at the transfer API level.
///
/// Gated 2026-09-27 (W5-D hardened verify): the `TlsEchoFixture` serves a
/// runtime self-signed cert; the fallback TLS leg is rejected (UnknownIssuer)
/// under the root crate's dependency features. Run with:
/// `cargo test --test transfer_transport --features tallow-net/dangerous_skip_verify -- --ignored`
#[ignore = "self-signed fixture vs hardened tallow-net verify; see lanes/transfer-tests-sweep.md"]
#[test]
fn peer_transport_fallback_engages_and_proxied_route_denies_direct() {
    let echo = TlsEchoFixture::start().expect("tls echo fixture");
    let addr: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();

    // Direct route with the explicit UDP opt-in; QUIC injected as blocked.
    let lookup = |key: &str| -> Option<String> {
        (key == TALLOW_ALLOW_DIRECT_ENV).then(|| "1".to_string())
    };
    let policy = resolve_transport_policy(&lookup, None, "10.0.0.9").unwrap();
    assert!(policy.quic_eligible());
    let kind = connect_peer_transport_with(&policy, addr, true).expect("fallback connect");
    assert_eq!(kind, PeerTransportKind::TcpTls, "QUIC blocked ⇒ TCP+TLS");

    // The fixture records the negotiated version asynchronously; give its task
    // a moment to run (handshake completion is what we assert).
    let mut versions = Vec::new();
    for _ in 0..50 {
        versions = echo.tls_versions();
        if !versions.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        versions
            .iter()
            .any(|v| v.contains("TLSv1_3") || v.contains("TLSv1.3")),
        "fallback leg must complete a TLS 1.3 handshake, got {versions:?}"
    );

    // Proxy route: direct peer connect denied (fail-closed).
    let proxied =
        transfer_policy_for("relay.invalid:6880", Some("socks5h://127.0.0.1:9050"))
            .expect("proxied policy");
    let denied = connect_peer_transport_with(&proxied, addr, true).unwrap_err();
    assert!(
        denied.contains("fail-closed"),
        "expected fail-closed denial, got: {denied}"
    );
}

/// Policy introspection surface (same resolution the CLI uses).
#[test]
fn transport_status_reports_proxied_route_and_tcp_tls_only() {
    let status = dispatch_ok(
        "transfer_transport_status",
        vec![
            Value::String("relay.invalid:6880".to_string()),
            Value::String("socks5h://127.0.0.1:9050".to_string()),
        ],
    );
    assert!(field_bool(&status, "proxied"));
    assert!(!field_bool(&status, "quic_eligible"));
    assert!(field_bool(&status, "tor_mode"));
    assert_eq!(field_str(&status, "candidates"), "TcpTls");

    // Environment-driven resolution matches the explicit form.
    let tor_policy = resolve_transport_policy(
        &|k: &str| (k == TALLOW_TOR_ENV).then(|| "1".to_string()),
        None,
        "x.org",
    )
    .unwrap();
    assert!(tor_policy.is_proxied());

    let proxy_env =
        |k: &str| -> Option<String> { (k == TALLOW_PROXY_ENV).then(|| "socks5://127.0.0.1:1080".to_string()) };
    let p = resolve_transport_policy(&proxy_env, None, "x.org").unwrap();
    assert!(p.is_proxied() && !p.proxy.as_ref().unwrap().tor_mode);
}
