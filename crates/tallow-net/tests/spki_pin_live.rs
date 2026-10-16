//! Live SPKI-pin acceptance against a REAL relay endpoint (manual, network-dependent).
//!
//! `#[ignore]`d by default: it dials the public relay over QUIC, so it is a manual acceptance check
//! rather than part of CI. Run it when a pin is issued or rotated:
//!
//! ```text
//! TALLOW_LIVE_SPKI_PIN=<64 hex> \
//!   cargo test -p tallow-net --test spki_pin_live -- --ignored --nocapture
//! ```
//!
//! It asserts BOTH halves, because a pin that accepts everything is worse than no pin: the correct
//! pin must complete a handshake, and a pin that is not the peer's must fail.

use std::time::Duration;

use tallow_net::transport::tls_config::{configured_spki_pin, parse_spki_pin, quinn_client_config_pinned};

const DEFAULT_RELAY: &str = "relay.sendtallow.com:4433";
const SERVER_NAME: &str = "relay.sendtallow.com";

async fn dial(pin: [u8; 32], target: &str) -> Result<(), String> {
    let addr = tokio::net::lookup_host(target)
        .await
        .map_err(|e| format!("resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to nothing"))?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| format!("endpoint: {e}"))?;
    endpoint.set_default_client_config(quinn_client_config_pinned(pin).map_err(|e| format!("config: {e}"))?);
    let connecting = endpoint.connect(addr, SERVER_NAME).map_err(|e| format!("connect: {e}"))?;
    match tokio::time::timeout(Duration::from_secs(20), connecting).await {
        Ok(Ok(conn)) => {
            conn.close(0u32.into(), b"probe done");
            Ok(())
        }
        Ok(Err(e)) => Err(format!("handshake rejected: {e}")),
        Err(_) => Err("handshake timed out".to_string()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live network: dials the public relay over QUIC"]
async fn production_relay_pin_accepts_the_right_pin_and_refuses_a_wrong_one() {
    let target = std::env::var("TALLOW_LIVE_RELAY").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let pin_hex = std::env::var("TALLOW_LIVE_SPKI_PIN")
        .expect("set TALLOW_LIVE_SPKI_PIN to the peer's SPKI (64 hex chars)");
    let pin = parse_spki_pin(&pin_hex).expect("pin must parse");

    let good = dial(pin, &target).await;
    println!("correct pin -> {good:?}");
    assert!(good.is_ok(), "the pinned key must be accepted: {good:?}");

    let mut wrong = pin;
    wrong[0] ^= 0x01;
    let bad = dial(wrong, &target).await;
    println!("wrong pin   -> {bad:?}");
    assert!(bad.is_err(), "a pin that is not the peer's MUST be refused");

    // and the operator-facing env path agrees with what we just proved
    if let Ok(Some(configured)) = configured_spki_pin() {
        println!("configured_spki_pin() -> {configured:02x?}");
    }
}
