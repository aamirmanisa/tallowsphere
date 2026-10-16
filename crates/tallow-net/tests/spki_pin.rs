//! Live SPKI-pin acceptance over real TLS sockets.
//!
//! The transport-layer counterpart of the RT-4 lab: a real TLS 1.3 server on
//! 127.0.0.1 with a self-signed identity. The pinned client must accept the
//! exact pinned SPKI and reject any substitution (the peer presenting a
//! different key than the one pinned out-of-band).

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use tallow_net::transport::spki_pin::spki_sha256;
use tallow_net::transport::tls_config::{
    client_config_pinned, generate_self_signed, rustls_server_config, TlsIdentity,
};

async fn spawn_tls_server(
    identity: TlsIdentity,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let server_cfg = rustls_server_config(&identity).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = tls.write_all(b"ok").await;
                let _ = tls.shutdown().await;
            }
        }
    });
    (addr, handle)
}

async fn connect_pinned(
    addr: std::net::SocketAddr,
    pin: [u8; 32],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let cfg = client_config_pinned(&[], pin).unwrap();
    let connector = TlsConnector::from(Arc::new(cfg));
    let stream = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
        .await
        .expect("handshake must not hang")
}

/// Matching pin: handshake completes, data flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_client_accepts_matching_spki() {
    let identity = generate_self_signed().unwrap();
    let pin = spki_sha256(&identity.cert_der).expect("pin extraction");
    let (addr, handle) = spawn_tls_server(identity).await;

    let mut tls = connect_pinned(addr, pin)
        .await
        .expect("pinned client must accept the pinned SPKI");
    let mut buf = [0u8; 2];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok", "data leg must flow after a pinned handshake");
    handle.await.unwrap();
}

/// Substituted certificate (different key than the pin): hard reject — this is
/// the transport-layer MITM scenario.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_client_rejects_substituted_spki() {
    let identity_a = generate_self_signed().unwrap();
    let identity_b = generate_self_signed().unwrap();
    let pin_a = spki_sha256(&identity_a.cert_der).expect("pin extraction");

    // The server presents B; the client pinned A.
    let (addr, handle) = spawn_tls_server(identity_b).await;

    let err = connect_pinned(addr, pin_a)
        .await
        .expect_err("substituted certificate must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("ApplicationVerificationFailure") || msg.contains("invalid peer certificate"),
        "rejection must be a certificate-verification failure, got: {msg}"
    );
    handle.await.unwrap();
}

/// A random (wrong) pin is rejected the same way — no accidental acceptance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_client_rejects_wrong_pin() {
    let identity = generate_self_signed().unwrap();
    let (addr, handle) = spawn_tls_server(identity).await;

    let err = connect_pinned(addr, [0x5a; 32])
        .await
        .expect_err("wrong pin must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("ApplicationVerificationFailure") || msg.contains("invalid peer certificate"),
        "rejection must be a certificate-verification failure, got: {msg}"
    );
    handle.await.unwrap();
}

/// The pinned QUIC variant builds (compile/feature coverage).
#[cfg(feature = "quic")]
#[test]
fn quinn_pinned_config_builds() {
    assert!(tallow_net::transport::tls_config::quinn_client_config_pinned([7u8; 32]).is_ok());
}
