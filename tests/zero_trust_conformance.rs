//! U-107 — zero-trust conformance: **negative boundary probes** (matrix row
//! #143, report R-5.15; seeds T-112).
//!
//! Every test in this file asserts a **refusal** at a trust boundary. A green
//! run proves the boundary said *no* — it is not a happy-path suite, and no
//! assertion is tautological (each one fails if the production guard under
//! probe is weakened or removed).
//!
//! Coverage (W2r slice; SVID probes deferred to W3 — see the `#[ignore]` hooks
//! at the bottom, which are deliberately NOT faked):
//!
//! * `zone_predicate_*` — `src/browser/zone.rs` (T-207): the single
//!   authoritative browser-zone egress predicate. Lookalike/encoded targets
//!   must NOT classify as in-zone, and a malformed or unknown-scheme contract
//!   proxy (`TALLOW_PROXY`) must hard-refuse every zone consumer (invariant
//!   N3) — never degrade to a direct connection.
//! * `zone_contract_*` — env-driven half of the same boundary (process env is
//!   global; all env mutation here serializes on [`ENV_MUTEX`] and restores
//!   prior values, mirroring the crate-internal T-128 discipline).
//! * `cdp_connect_*` — `CdpClient::connect` socket boundary: non-loopback and
//!   lookalike DevTools targets are refused before any connection attempt
//!   (CHAIN-5-4), while a genuine loopback target passes the zone gate and
//!   fails only at the transport layer (refusal-specificity control).
//! * `cdp_relay_*` — the distributed CDP relay's frame cap
//!   (`src/browser/distributed/relay.rs`): an oversized QUIC command frame
//!   (> 8 MiB) is refused with the explicit `command too large` error and never
//!   routed, while a small frame passes the cap and is refused only for its
//!   (unknown) session — end-to-end over loopback QUIC, no network.
//! * `daemon_*` — structural pin (negative): the daemon API listener binds an
//!   explicit loopback address only; any non-loopback bind spelling fails.
//!
//! Frame-cap honesty note: the CDP (WebSocket) path relies on
//! `tokio-tungstenite`'s library default message size; the Juggler (NUL-frame
//! pipe) reader is currently **uncapped** (`src/browser/juggler.rs`
//! `read_loop` grows `buf` without a limit). Both are recorded as residual in
//! the U-107 evidence — this suite probes the repo-owned cap that *does*
//! exist (the relay's 8 MiB command cap) instead of inventing enforcement.

use std::sync::Mutex;
use std::time::Duration;

use tallow::browser::distributed::{CdpRelay, SessionRegistry};
use tallow::browser::zone::{
    ZoneEgress, browser_zone_chrome_proxy, browser_zone_egress, browser_zone_egress_for,
    browser_zone_firefox_proxy, browser_zone_reqwest_proxy, is_in_zone_target,
};
use tallow::browser::{BrowserError, CdpClient};

/// The one lock every env-mutating probe in this binary takes (T-128
/// discipline: process env is global, the harness runs tests in parallel).
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Restores the listed env vars on drop so a refusal probe cannot leak env
/// state into a sibling probe.
struct EnvScope {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvScope {
    fn new(keys: &[&'static str]) -> Self {
        Self {
            saved: keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect(),
        }
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        for (key, prior) in &self.saved {
            match prior {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

// ── Zones: predicate-level refusals (pure, no env) ─────────────────────────

/// Adversarial destination strings must NOT buy in-zone status, and the
/// refusal must stay a *classification* boundary (exact loopback/pipe forms
/// remain accepted — the probe would be meaningless if it blanket-denied).
#[test]
fn zone_predicate_refuses_lookalike_encoded_and_empty_targets() {
    for target in [
        // Host lookalikes: contain "127.0.0.1"/"localhost" but resolve elsewhere.
        "https://127.evil.com/",
        "http://127.0.0.1.evil.com/",
        "ws://localhost.evil.com:9222/devtools",
        // Decoy positions: the loopback text is not the host.
        "http://evil.com/#127.0.0.1",
        "http://evil.com/127.0.0.1",
        "http://127.0.0.1@evil.com/",
        // Real non-loopback addresses (LAN + link-local metadata).
        "ws://10.0.0.1:9222/",
        "ws://192.168.1.2:9222",
        "http://169.254.169.254/latest/meta-data/",
        // Encodings that a resolver might normalize but the classifier must not.
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        // Empty is never in-zone.
        "",
    ] {
        assert!(
            !is_in_zone_target(target),
            "{target:?} must NOT be classified in-zone (WAN/LAN path)"
        );
    }

    // The exact in-zone forms stay accepted: the refusals above are a
    // boundary, not a blanket deny.
    for target in [
        "http://127.0.0.1:9222/json/version",
        "ws://127.0.0.1:9222/devtools/browser/abc",
        "ws://[::1]:9222/devtools/browser/x",
        "ws://localhost:9222",
        "unix:/tmp/cdp.sock",
        "pipe:3",
    ] {
        assert!(
            is_in_zone_target(target),
            "{target:?} must be classified in-zone"
        );
    }
}

/// A configured-but-unusable contract proxy is a **hard refusal** for every
/// zone consumer (no direct fallback anywhere), while in-zone loopback
/// destinations stay reachable and the no-env default stays the Tor contract.
#[test]
fn zone_contract_refuses_malformed_and_unknown_scheme_proxies() {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _scope = EnvScope::new(&["TALLOW_PROXY", "TALLOW_ALLOW_DIRECT"]);
    unsafe { std::env::remove_var("TALLOW_ALLOW_DIRECT") };

    for bad in [
        "::::nope",               // not a URL at all
        "gopher://127.0.0.1:70",  // unknown proxy scheme (ureq/reqwest will not honour it)
        "http://[::1",            // malformed authority (unclosed bracket)
    ] {
        unsafe { std::env::set_var("TALLOW_PROXY", bad) };

        let err = browser_zone_egress()
            .expect_err(&format!("{bad:?} must refuse — the zone must fail closed"));
        assert!(
            err.contains("refusing"),
            "{bad:?}: refusal must say so, got {err:?}"
        );
        assert!(
            browser_zone_chrome_proxy().is_err(),
            "{bad:?}: the browser launch must refuse, not spawn direct"
        );
        assert!(
            browser_zone_firefox_proxy().is_err(),
            "{bad:?}: the Firefox-family launch must refuse, not spawn unproxied"
        );
        assert!(
            browser_zone_reqwest_proxy().is_err(),
            "{bad:?}: in-process clients must refuse, not degrade to direct"
        );
        // The malformed contract must never be laundered into the explicit
        // direct opt-in.
        assert!(
            !matches!(browser_zone_egress(), Ok(ZoneEgress::DirectOptIn)),
            "{bad:?}: a broken contract must not read as an operator opt-in"
        );
        // WAN targets under the broken contract refuse…
        assert!(
            browser_zone_egress_for("https://example.com/").is_err(),
            "{bad:?}: WAN egress must refuse while the contract is unusable"
        );
        // …while in-zone loopback never rides the WAN contract and stays OK.
        assert_eq!(
            browser_zone_egress_for("ws://127.0.0.1:9222/devtools"),
            Ok(ZoneEgress::InZone),
            "{bad:?}: the in-zone CDP relay must stay reachable"
        );
    }

    // With no env at all the zone posture is the Tor contract (fail-closed
    // default) — never a silent direct posture.
    unsafe { std::env::remove_var("TALLOW_PROXY") };
    match browser_zone_egress().expect("the compiled default must not refuse") {
        ZoneEgress::Contract { proxy } => {
            // Fail-closed default since P1 W1-E1: Tor with a per-run circuit
            // identity bound into the URL — canonical source
            // `default_tor_proxy_url` (the bare `TOR_SOCKS_URL` is only the
            // `TALLOW_TOR_ISOLATE=0` opt-out form).
            assert_eq!(
                proxy,
                tallow::runtime::fetch::default_tor_proxy_url(),
                "no-env zone egress must ride the per-run Tor contract"
            );
            assert!(
                proxy.starts_with("socks5h://") && proxy.contains("127.0.0.1:9050"),
                "no-env zone contract must be the remote-DNS Tor endpoint, got {proxy:?}"
            );
        }
        other => panic!("no-env zone posture must be the Tor contract, got {other:?}"),
    }
}

// ── Socket boundary: CDP client refuses out-of-zone endpoints ──────────────

/// Non-loopback (and lookalike) CDP targets are refused by the zone gate
/// *before* any connection attempt; the refusal is specific — a genuine
/// loopback target passes the gate and only fails at the transport layer.
#[tokio::test]
async fn cdp_connect_refuses_non_loopback_and_lookalike_targets_then_attempts_loopback() {
    for target in [
        "ws://192.168.1.10:9222/devtools/browser/x", // LAN: unauthenticated CDP on the network
        "ws://127.evil.com:9222/",                   // lookalike host
        "ws://[2001:db8::1]:9222/",                  // global IPv6
    ] {
        let result = CdpClient::connect(target).await;
        match result {
            Ok(_) => panic!("{target:?} must be refused by the zone gate"),
            Err(BrowserError::ConnectionFailed(msg)) => assert!(
                msg.contains("refusing non-in-zone CDP target"),
                "{target:?}: refusal must carry the zone marker, got {msg:?}"
            ),
            Err(_) => panic!("{target:?} must be refused as ConnectionFailed"),
        }
    }

    // Control: loopback passes the zone gate and fails at the transport
    // (port 1 is closed). The error must NOT be the zone refusal — proving
    // the probes above hit the boundary check, not a blanket deny.
    let result = tokio::time::timeout(Duration::from_secs(10), CdpClient::connect("ws://127.0.0.1:1/"))
        .await
        .expect("a dead loopback port must fail fast, not hang");
    match result {
        Ok(_) => panic!("nothing listens on ws://127.0.0.1:1/ — connect must fail"),
        Err(BrowserError::ConnectionFailed(msg)) => assert!(
            !msg.contains("refusing non-in-zone CDP target"),
            "loopback must not be zone-refused, got {msg:?}"
        ),
        Err(_) => panic!("transport failure must surface as ConnectionFailed"),
    }
}

// ── Frame cap: CDP relay refuses oversized command frames (loopback QUIC) ──

/// End-to-end frame-cap probe against the real relay: > 8 MiB is refused with
/// the explicit `command too large` error; a small frame passes the cap and
/// reaches routing (refused there only as an unknown session). Also pins the
/// unstarted-listener boundary (routing fails closed before `start`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cdp_relay_refuses_oversized_frames_and_passes_small_ones() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Reserve a loopback UDP port for the relay's QUIC endpoint (probe-bind,
    // release, hand to the relay — the relay only ever binds its own addr).
    let port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        probe.local_addr().expect("probe addr").port()
    };
    let relay_addr: std::net::SocketAddr =
        format!("127.0.0.1:{port}").parse().expect("relay addr");
    let relay = CdpRelay::new(relay_addr, SessionRegistry::new(Duration::from_secs(300)));

    // Listener boundary: with no endpoint there is nothing to route to —
    // command routing must fail closed, never fabricate a success.
    let err = relay
        .route_command("u107-probe", "Page.navigate", None)
        .await
        .expect_err("an unstarted relay must refuse to route");
    assert!(
        err.contains("not running"),
        "unstarted-relay refusal must say so, got {err:?}"
    );

    relay.start().await.expect("relay must bind its QUIC endpoint");
    assert!(relay.is_running(), "relay must report running after start");

    // Test-only client with a skip-server-verification TLS config: the relay
    // serves a runtime self-signed cert, and this probe only exercises the
    // frame boundary on loopback.
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind addr"))
        .expect("client endpoint");
    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(skip_verify_client_crypto())
            .expect("quic client crypto"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("idle timeout"),
    ));
    client_config.transport_config(std::sync::Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(
        Duration::from_secs(20),
        endpoint
            .connect(relay_addr, "localhost")
            .expect("connect initiation"),
    )
    .await
    .expect("QUIC handshake must not hang")
    .expect("QUIC handshake to the relay must succeed");

    // — Oversized frame: the relay's 8 MiB cap must refuse explicitly. —
    let oversize = 8 * 1024 * 1024 + 64 * 1024;
    let (mut send, mut recv) = conn.open_bi().await.expect("open oversized-frame stream");
    let writer = tokio::spawn(async move {
        let blob = vec![b'x'; oversize];
        let _ = send.write_all(&blob).await;
        let _ = send.finish();
    });
    let refusal = read_stream_until_refusal(&mut recv, Duration::from_secs(30)).await;
    writer.abort();
    let refusal_text = String::from_utf8_lossy(&refusal).to_string();
    assert!(
        refusal_text.contains("command too large"),
        "an oversized CDP frame must be refused with the explicit cap error, got {refusal_text:?}"
    );

    // — Control: a small frame passes the cap gate and reaches routing; it is
    // refused there only because the probe session is not registered. —
    let (mut send2, mut recv2) = conn.open_bi().await.expect("open small-frame stream");
    let small = br#"{"session_id":"u107-probe","method":"Page.navigate"}"#;
    send2.write_all(small).await.expect("write small frame");
    send2.finish().expect("finish small frame");
    let reply = read_stream_until_refusal(&mut recv2, Duration::from_secs(20)).await;
    let reply_text = String::from_utf8_lossy(&reply).to_string();
    assert!(
        !reply_text.contains("command too large"),
        "a small frame must not be size-refused, got {reply_text:?}"
    );
    assert!(
        reply_text.contains("not found or expired"),
        "the small frame must reach routing and be refused as an unknown session, got {reply_text:?}"
    );

    conn.close(0u32.into(), b"u107 probe done");
    relay.stop();
    assert!(
        !relay.is_running(),
        "relay must report stopped after stop() — the boundary is observable"
    );
}

/// Read from a QUIC stream until the refusal payload has arrived, the stream
/// finishes, or `budget` elapses. Returns whatever was collected — the caller
/// asserts on it (an empty result fails the caller's assertion loudly).
async fn read_stream_until_refusal(recv: &mut quinn::RecvStream, budget: Duration) -> Vec<u8> {
    let mut collected: Vec<u8> = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, recv.read(&mut buf)).await {
            Ok(Ok(Some(n))) => {
                collected.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&collected);
                if text.contains("command too large")
                    || text.contains("not found or expired")
                    || collected.len() >= 4096
                {
                    break;
                }
            }
            // Stream finished, reset, or timed out — return what we have.
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
        }
    }
    collected
}

/// TLS client config that accepts any server certificate — justified: the
/// relay mints a runtime self-signed cert per start, and this probe tests the
/// frame boundary on loopback only (no identity claim is made).
fn skip_verify_client_crypto() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer,
            _intermediates: &[rustls::pki_types::CertificateDer],
            _server_name: &rustls::pki_types::ServerName,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(SkipServerVerification))
        .with_no_client_auth()
}

// ── Socket boundary: daemon API listener is loopback-only (structural pin) ─

/// Negative structural pin on the daemon's API listener: it must bind an
/// explicit loopback address, and any non-loopback bind spelling fails the
/// suite (that would expose the bearer-token API to the network).
#[test]
fn daemon_api_listener_binds_loopback_only() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/tallow-daemon/src/main.rs"
    ))
    .expect("daemon main.rs must be readable");
    assert!(
        src.contains("TcpListener::bind(\"127.0.0.1:"),
        "daemon API listener must bind an explicit 127.0.0.1 address"
    );
    for bad in ["bind(\"0.0.0.0", "bind(\"[::]", "bind(\"::"] {
        assert!(
            !src.contains(bad),
            "daemon must never bind a non-loopback listener ({bad:?} found)"
        );
    }
}

// ── W3 seed hooks — SVID expiry/replay (NOT faked) ─────────────────────────
//
// The R-5.15 matrix row also names expired/revoked/replayed SVID refusals.
// The slim in-daemon issuer (R-5.1) does not exist yet, so there is no honest
// probe to write. These hooks are marked `#[ignore]` and panic with a W3
// marker if anyone un-ignores them before the issuer lands — a red signal,
// never a plausible-looking green.

/// W3 seed — enable when the R-5.1 issuer lands: mint an SVID, advance past
/// its TTL, present it at a verifying boundary, assert refusal naming expiry.
#[test]
#[ignore = "W3 seed (U-107): needs the R-5.1 SVID issuer — not landed as of W2r"]
fn svid_expired_certificate_refused_probe() {
    panic!("W3 seed: SVID issuer under R-5.1 not landed — see impl/U-107.md");
}

/// W3 seed — enable when the R-5.1 issuer + replay guard land: replay a
/// previously accepted SVID/handshake transcript and assert refusal.
#[test]
#[ignore = "W3 seed (U-107): needs the R-5.1 issuer + replay guard — not landed as of W2r"]
fn svid_replayed_svid_refused_probe() {
    panic!("W3 seed: SVID replay guard under R-5.1/R-5.2C not landed — see impl/U-107.md");
}
