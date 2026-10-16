//! Live-network checks that the STRICT TLS client (built WITHOUT
//! `dangerous_skip_verify`) verifies the production relay correctly.
//!
//! Crypto-audit F1 evidence:
//! - positive: the production QUIC handshake path (`QuicTransport::
//!   connect_with_server_name`, the exact function the relay client uses)
//!   succeeds against a configured relay under CA validation — the
//!   certificate covers the dialed name;
//! - negative: the same handshake against a name the relay certificate does
//!   NOT cover fails certificate verification — proving verification is
//!   active rather than a no-op.
//!
//! Independent cross-check: the relay's own journal records the join attempt
//! reaching its application layer ("authentication failed" for the synthetic
//! room join), i.e. the TLS layer was fully established.
//!
//! Ignored by default (needs network + production relay). Run with:
//! `cargo test -p tallow-net --no-default-features --features quic \
//!    --test live_relay_tls -- --ignored --nocapture`
#![cfg(feature = "quic")]

use std::net::SocketAddr;
use std::time::Duration;
use tallow_net::transport::QuicTransport;

const RELAY_HOST: &str = "relay.example";  // set TALLOW_RELAY_HOST to point the test at a real relay
const RELAY_PORT: u16 = 4433;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

fn relay_addr() -> SocketAddr {
    use std::net::ToSocketAddrs;
    format!("{RELAY_HOST}:{RELAY_PORT}")
        .to_socket_addrs()
        .expect("resolve relay.example")
        .next()
        .expect("no addresses for relay.example")
}

#[tokio::test]
#[ignore = "live network: connects to relay.example:4433"]
async fn strict_tls_handshake_accepts_named_relay_and_rejects_uncovered_name() {
    // 1) Positive: name covered by the relay certificate → strict TLS OK.
    let mut ok = QuicTransport::new();
    tokio::time::timeout(
        ATTEMPT_TIMEOUT,
        ok.connect_with_server_name(relay_addr(), RELAY_HOST),
    )
    .await
    .expect("positive attempt timed out")
    .expect("strict TLS handshake against relay.example must succeed");
    ok.close().await;
    println!("PASS positive: strict TLS verified relay.example");

    // 2) Negative: a name the certificate does not cover must fail verification.
    let mut bad = QuicTransport::new();
    let err = tokio::time::timeout(
        ATTEMPT_TIMEOUT,
        bad.connect_with_server_name(relay_addr(), "wrong.invalid"),
    )
    .await
    .expect("negative attempt timed out")
    .expect_err("strict TLS must reject an uncovered name");
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("certificate") || msg.contains("tls"),
        "expected a certificate/TLS verification error, got: {err}"
    );
    println!("PASS negative: strict TLS rejected uncovered name ({err})");
}
