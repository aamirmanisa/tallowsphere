//! Transport fallback / policy integration tests (R-08 batch-3 · rows #131/#132).
//!
//! Covers the SOCKS5→TLS byte pipe end-to-end with real fixtures
//! (`tallow_net::transport::test_support`):
//!   * a minimal SOCKS5 (no-auth, CONNECT) server that records the requested
//!     target — a name reaches it only if the client used remote DNS (Tor mode);
//!   * a TLS 1.3 echo server (self-signed; exercised under the
//!     `dangerous_skip_verify` opt-in lane; the strict default's rejection is
//!     asserted by `strict_default_rejects_self_signed_direct_tls`) that
//!     records the negotiated version.
//!
//! Plus policy-level assertions (proxied route ⇒ TCP+TLS only; fail-closed
//! denial) and Happy Eyeballs v2 ordering.

#[cfg(feature = "dangerous_skip_verify")]
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use tallow_net::privacy::ProxyConfig;
use tallow_net::transport::fallback::FallbackTransport;
#[cfg(feature = "dangerous_skip_verify")]
use tallow_net::transport::fallback::ActiveTransport;
use tallow_net::transport::negotiation::{
    negotiate_with_policy, TransportProtocol, TransportRoute,
};
use tallow_net::transport::proxied::ProxiedTcpTlsTransport;
use tallow_net::transport::tcp_tls::{connect_happy_eyeballs, connect_std, interleave_addresses};
#[cfg(feature = "dangerous_skip_verify")]
use tallow_net::transport::test_support::{Socks5Fixture, TlsEchoFixture};
use tokio::net::TcpListener;

/// `write_all` over a tunnel half, retrying the 250 ms poll timeouts.
#[cfg(feature = "dangerous_skip_verify")]
fn write_all_retry<W: Write>(w: &mut W, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match w.write(data) {
            Ok(0) => return Err(std::io::Error::other("write returned 0")),
            Ok(n) => data = &data[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    w.flush()
}

#[cfg(feature = "dangerous_skip_verify")]
fn read_exact_retry<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tunnel closed",
                ))
            }
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Tor-mode tunnel: bytes move over SOCKS5 → TLS 1.3; the proxy receives the
/// *hostname* (remote DNS), proving no local resolution happened.
#[cfg(feature = "dangerous_skip_verify")]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn proxied_tunnel_moves_bytes_via_socks5_and_tls13() {
    let echo = TlsEchoFixture::start().unwrap();
    let socks = Socks5Fixture::start(SocketAddr::from(([127, 0, 0, 1], echo.port))).unwrap();

    let cfg = ProxyConfig::from_url(&format!("socks5h://{}", socks.addr)).unwrap();
    assert!(cfg.tor_mode, "socks5h:// is Tor mode");

    let tls_port = echo.port;
    let payload = b"relay-v1-frame-over-tor".to_vec();
    let payload_read = payload.clone();
    let handle = std::thread::spawn(move || -> Result<(), String> {
        let tunnel = ProxiedTcpTlsTransport::connect_blocking_tunnel(&cfg, "relay.test", tls_port)
            .map_err(|e| e.to_string())?;
        let mut writer = tunnel.writer;
        let mut reader = tunnel.reader;
        write_all_retry(&mut writer, &payload_read).map_err(|e| format!("write: {e}"))?;
        let mut got = vec![0u8; payload_read.len()];
        read_exact_retry(&mut reader, &mut got).map_err(|e| format!("read: {e}"))?;
        assert_eq!(got, payload_read, "echoed bytes differ");
        Ok(())
    });
    handle.join().unwrap().unwrap();

    assert_eq!(
        socks.targets(),
        vec![("relay.test".to_string(), tls_port)],
        "the proxy must receive the relay *name* (remote DNS), not a resolved IP"
    );

    let versions = echo.tls_versions();
    assert!(
        versions
            .iter()
            .any(|v| v.contains("TLSv1_3") || v.contains("TLSv1.3")),
        "expected a TLS 1.3 handshake, got {versions:?}"
    );
}

/// Fail-closed: a proxied route with an unreachable proxy must error — and the
/// would-be *direct* endpoint must never see a connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxied_route_failure_never_touches_direct_endpoint() {
    // "Direct trap": a plain TCP listener standing in for the relay.
    let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let trap_port = trap.local_addr().unwrap().port();
    trap.set_nonblocking(true).unwrap();

    // A dead SOCKS5 proxy (port 1 on loopback: nothing listens).
    let mut cfg = ProxyConfig::tor_default();
    cfg.socks5_addr = "127.0.0.1:1".parse().unwrap();
    cfg.tor_mode = false;

    let handle = std::thread::spawn(move || {
        ProxiedTcpTlsTransport::connect_blocking_tunnel(&cfg, "127.0.0.1", trap_port)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    let err = handle.join().unwrap().unwrap_err();
    assert!(
        err.contains("SOCKS5") || err.contains("Connection"),
        "unexpected error: {err}"
    );

    // The direct endpoint must not have been dialed (no silent direct fallback).
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        matches!(
            trap.accept(),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "fail-closed violation: the direct endpoint received a connection"
    );
}

/// Policy layer: Tor route negotiates TCP+TLS even when the peer offers QUIC;
/// a QUIC-only peer is refused (fail-closed), never connected direct.
#[tokio::test]
async fn tor_route_negotiation_is_tcp_tls_only() {
    let route = TransportRoute::proxied(true);
    let picked =
        negotiate_with_policy(route, &[TransportProtocol::Quic, TransportProtocol::TcpTls])
            .await
            .unwrap();
    assert_eq!(picked, TransportProtocol::TcpTls);

    let err = negotiate_with_policy(route, &[TransportProtocol::Quic])
        .await
        .unwrap_err();
    assert!(
        format!("{err}").contains("fail-closed"),
        "expected fail-closed denial, got {err}"
    );
}

/// QUIC-blocked ⇒ the fallback transport engages TCP+TLS (real TLS handshake).
#[cfg(feature = "dangerous_skip_verify")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_blocked_engages_tcp_tls_fallback() {
    let identity = tallow_net::transport::tls_config::generate_self_signed().unwrap();
    let server_cfg = tallow_net::transport::tls_config::rustls_server_config(&identity).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(stream).await.unwrap();
    });

    let mut t = FallbackTransport::with_policy(TransportRoute::direct(true));
    let active = t
        .connect_peer_with(addr, async {
            Err(tallow_net::NetworkError::ConnectionFailed(
                "UDP blocked (test)".to_string(),
            ))
        })
        .await
        .unwrap();
    assert_eq!(active, ActiveTransport::TcpTls);
}

/// Happy Eyeballs v2: interleaving + a real dual-stack race on loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn happy_eyeballs_ordering_and_race() {
    let v4a: SocketAddr = "127.0.0.1:1111".parse().unwrap();
    let v4b: SocketAddr = "127.0.0.1:2222".parse().unwrap();
    let v6a: SocketAddr = "[::1]:1111".parse().unwrap();
    let v6b: SocketAddr = "[::1]:2222".parse().unwrap();
    assert_eq!(
        interleave_addresses(&[v6a, v6b, v4a, v4b]),
        vec![v6a, v4a, v6b, v4b],
        "families must alternate after the first address"
    );

    // Real race: refused port + live listener. The live address must win.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live = listener.local_addr().unwrap();
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let stream = connect_happy_eyeballs(vec![dead, live], Duration::from_millis(250))
        .await
        .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), live);

    // Hostname path (`localhost` resolves dual-stack; fixture is IPv4-only).
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port2 = listener2.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = listener2.accept().await;
    });
    let stream = connect_std("localhost", port2).await.unwrap();
    assert!(stream.peer_addr().unwrap().is_ipv4());
}

/// Hardened default guard (fix-wave B, 2026-09-28): with
/// `dangerous_skip_verify` OFF — the default — the TCP+TLS client must REJECT
/// a self-signed server, proving verification is active rather than a no-op.
#[cfg(not(feature = "dangerous_skip_verify"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_default_rejects_self_signed_direct_tls() {
    let identity = tallow_net::transport::tls_config::generate_self_signed().unwrap();
    let server_cfg = tallow_net::transport::tls_config::rustls_server_config(&identity).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // The client must abort during the handshake; the server side sees Err.
        let (stream, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(stream).await;
    });

    let mut t = FallbackTransport::with_policy(TransportRoute::direct(true));
    let attempt = tokio::time::timeout(
        Duration::from_secs(10),
        t.connect_peer_with(addr, async {
            Err(tallow_net::NetworkError::ConnectionFailed(
                "UDP blocked (test)".to_string(),
            ))
        }),
    )
    .await
    .expect("connect attempt timed out");
    let err = attempt.expect_err("hardened default must reject a self-signed TLS server");
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains("cert") || msg.contains("tls"),
        "expected a certificate/TLS failure, got: {msg}"
    );
}
