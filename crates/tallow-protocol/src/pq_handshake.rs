//! v5+ PQ-auth driver exchange: completes a KEM handshake with hybrid
//! identity signatures before the data phase starts.
//!
//! When the receiver ACKs `PQ_AUTH_FLAG` (protocol >= 5), both sides send a
//! `Message::HandshakeSigned` frame — a hybrid ML-DSA-87 + Ed25519 signature
//! over `DOMAIN_HANDSHAKE_SIGNED || role || transcript_hash` — and verify the
//! peer's frame BEFORE any transfer data is sent or accepted (see
//! [`crate::kex`]).
//!
//! This module owns the transport choreography for native drivers (CLI, TUI):
//! encode + send our frame, wait for the peer's frame, verify it, and report
//! the outcome. Policy (rollout: Alarm, not Strict):
//!
//! * `pq_auth` negotiated + frame verified -> [`PqAuthOutcome`] with
//!   `verified == true` and the peer identity id
//! * `pq_auth` negotiated + verify fails   -> hard error, connection closed
//! * peer predates v5                      -> proceed, but a loud
//!   [`PqAuthAlarm`] is returned (never silent)
//!
//! Frames travel either directly (single-peer rooms) or wrapped in
//! `Message::Targeted` envelopes for multi-peer rooms — see [`FlightMode`].
//!
//! Lives here (not in `tallow-net`) because only this crate depends on both
//! the wire types and the `PeerChannel` abstraction; the CLI and TUI drivers
//! both reach it through `tallow-protocol`.

use crate::kex::{ReceiverHandshake, SenderHandshake};
use crate::wire::codec::TallowCodec;
use crate::wire::Message;
use bytes::BytesMut;
use std::io;
use std::time::Duration;
use tallow_crypto::sig::HybridSigner;
use tallow_net::transport::PeerChannel;

/// How the exchange frames travel over the room transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightMode {
    /// Single-peer room: frames go on the wire exactly like the handshake.
    Direct,
    /// Multi-peer room: frames are wrapped in `Targeted` envelopes addressed
    /// to the paired peer (same convention as the rest of the flight).
    Targeted { from_peer: u8, to_peer: u8 },
}

/// Rollout alarm: the transfer proceeds, but the peer predates protocol v5
/// and cannot sign the handshake — its identity stays unverified.
///
/// Mirrors the KEM negotiation `DowngradeAlarm` style: loud, structured,
/// never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqAuthAlarm;

impl std::fmt::Display for PqAuthAlarm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PQ-AUTH ALARM: peer does not support signed handshakes (pre-v5); \
             proceeding without a verified peer identity"
        )
    }
}

impl std::error::Error for PqAuthAlarm {}

/// Result of a driver-level PQ-auth exchange.
#[derive(Debug, Clone)]
pub struct PqAuthOutcome {
    /// True when the peer's `HandshakeSigned` frame was verified.
    pub verified: bool,
    /// Verified peer identity id (BLAKE3 of the peer's hybrid public key).
    pub peer_identity: Option<[u8; 32]>,
    /// Set when the peer predates v5 (rollout alarm — the transfer proceeds).
    pub alarm: Option<PqAuthAlarm>,
}

/// Timeout for the signed-frame exchange (matches the handshake flight's
/// per-step timeout).
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Complete the sender side of a v5+ handshake.
///
/// Call right after `SenderHandshake::verify_receiver_confirmation`, before
/// sending any transfer data. `signer` must be the local identity signer
/// (required whenever `pq_auth` was negotiated).
#[allow(clippy::too_many_arguments)]
pub async fn complete_sender<C: PeerChannel>(
    handshake: &mut SenderHandshake,
    signer: Option<&HybridSigner>,
    channel: &mut C,
    codec: &mut TallowCodec,
    encode_buf: &mut BytesMut,
    recv_buf: &mut [u8],
    pin: Option<&[u8; 32]>,
    mode: FlightMode,
) -> io::Result<PqAuthOutcome> {
    complete(
        handshake, signer, channel, codec, encode_buf, recv_buf, pin, mode,
    )
    .await
}

/// Complete the receiver side of a v5+ handshake.
///
/// Call right after sending `HandshakeComplete`, before processing any
/// transfer data.
#[allow(clippy::too_many_arguments)]
pub async fn complete_receiver<C: PeerChannel>(
    handshake: &mut ReceiverHandshake,
    signer: Option<&HybridSigner>,
    channel: &mut C,
    codec: &mut TallowCodec,
    encode_buf: &mut BytesMut,
    recv_buf: &mut [u8],
    pin: Option<&[u8; 32]>,
    mode: FlightMode,
) -> io::Result<PqAuthOutcome> {
    complete(
        handshake, signer, channel, codec, encode_buf, recv_buf, pin, mode,
    )
    .await
}

/// Internal view over both handshake state machines so the choreography
/// exists exactly once.
trait PqAuthFlight {
    fn is_pq_auth(&self) -> bool;
    fn create_frame(&self, signer: &HybridSigner) -> crate::Result<Message>;
    fn verify_frame(&mut self, msg: &Message, pin: Option<&[u8; 32]>) -> crate::Result<[u8; 32]>;
}

impl PqAuthFlight for SenderHandshake {
    fn is_pq_auth(&self) -> bool {
        self.pq_auth()
    }
    fn create_frame(&self, signer: &HybridSigner) -> crate::Result<Message> {
        self.create_signed_frame(signer)
    }
    fn verify_frame(&mut self, msg: &Message, pin: Option<&[u8; 32]>) -> crate::Result<[u8; 32]> {
        self.verify_signed_frame(msg, pin)
    }
}

impl PqAuthFlight for ReceiverHandshake {
    fn is_pq_auth(&self) -> bool {
        self.pq_auth()
    }
    fn create_frame(&self, signer: &HybridSigner) -> crate::Result<Message> {
        self.create_signed_frame(signer)
    }
    fn verify_frame(&mut self, msg: &Message, pin: Option<&[u8; 32]>) -> crate::Result<[u8; 32]> {
        self.verify_signed_frame(msg, pin)
    }
}

#[allow(clippy::too_many_arguments)]
async fn complete<F: PqAuthFlight, C: PeerChannel>(
    flight: &mut F,
    signer: Option<&HybridSigner>,
    channel: &mut C,
    codec: &mut TallowCodec,
    encode_buf: &mut BytesMut,
    recv_buf: &mut [u8],
    pin: Option<&[u8; 32]>,
    mode: FlightMode,
) -> io::Result<PqAuthOutcome> {
    if !flight.is_pq_auth() {
        // Pre-v5 peer: nothing to exchange. Proceed, but loudly.
        return Ok(PqAuthOutcome {
            verified: false,
            peer_identity: None,
            alarm: Some(PqAuthAlarm),
        });
    }

    let signer = signer.ok_or_else(|| {
        io::Error::other("PQ auth negotiated but no local identity is available to sign with")
    })?;

    let frame = flight
        .create_frame(signer)
        .map_err(|e| io::Error::other(format!("PQ auth frame creation failed: {e}")))?;

    encode_buf.clear();
    match mode {
        FlightMode::Direct => {
            codec
                .encode_msg(&frame, encode_buf)
                .map_err(|e| io::Error::other(format!("Encode HandshakeSigned: {e}")))?;
        }
        FlightMode::Targeted { from_peer, to_peer } => {
            let inner = postcard::to_stdvec(&frame)
                .map_err(|e| io::Error::other(format!("Encode HandshakeSigned: {e}")))?;
            let targeted = Message::Targeted {
                from_peer,
                to_peer,
                payload: inner,
            };
            codec
                .encode_msg(&targeted, encode_buf)
                .map_err(|e| io::Error::other(format!("Encode HandshakeSigned: {e}")))?;
        }
    }
    channel
        .send_message(encode_buf)
        .await
        .map_err(|e| io::Error::other(format!("Send HandshakeSigned: {e}")))?;

    // Wait for the peer's signed frame. In targeted mode other peers' frames
    // are skipped; ping keepalives are answered; anything else is a protocol
    // violation at this step.
    let peer_frame = loop {
        let n = tokio::time::timeout(EXCHANGE_TIMEOUT, channel.receive_message(recv_buf))
            .await
            .map_err(|_| io::Error::other("PQ auth timeout waiting for peer signature"))?
            .map_err(|e| io::Error::other(format!("Receive HandshakeSigned: {e}")))?;

        let mut decode_buf = BytesMut::from(&recv_buf[..n]);
        let msg = codec
            .decode_msg(&mut decode_buf)
            .map_err(|e| io::Error::other(format!("Decode HandshakeSigned: {e}")))?;

        match msg {
            Some(m @ Message::HandshakeSigned { .. }) => break m,
            Some(Message::Ping) => {
                encode_buf.clear();
                codec
                    .encode_msg(&Message::Pong, encode_buf)
                    .map_err(|e| io::Error::other(format!("Encode Pong: {e}")))?;
                channel
                    .send_message(encode_buf)
                    .await
                    .map_err(|e| io::Error::other(format!("Send Pong: {e}")))?;
            }
            Some(Message::Targeted {
                from_peer, payload, ..
            }) => {
                if let FlightMode::Targeted { to_peer, .. } = mode {
                    if from_peer == to_peer {
                        let inner: Message = postcard::from_bytes(&payload).map_err(|e| {
                            io::Error::other(format!("Decode peer HandshakeSigned: {e}"))
                        })?;
                        match inner {
                            m @ Message::HandshakeSigned { .. } => break m,
                            other => {
                                return Err(io::Error::other(format!(
                                    "Expected HandshakeSigned from peer, got: {other:?}"
                                )))
                            }
                        }
                    }
                    // else: another peer's frame — not ours; keep waiting.
                } else {
                    return Err(io::Error::other(
                        "Unexpected Targeted frame in direct flight",
                    ));
                }
            }
            Some(other) => {
                return Err(io::Error::other(format!(
                    "Expected HandshakeSigned, got: {other:?}"
                )))
            }
            None => return Err(io::Error::other("Empty HandshakeSigned frame")),
        }
    };

    match flight.verify_frame(&peer_frame, pin) {
        Ok(peer_id) => {
            tracing::info!(
                peer_id = %peer_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "PQ auth: peer identity verified (signed handshake)"
            );
            Ok(PqAuthOutcome {
                verified: true,
                peer_identity: Some(peer_id),
                alarm: None,
            })
        }
        Err(e) => {
            // Security failure: hard-fail and drop the connection. The
            // transfer must not proceed on an unverifiable handshake.
            channel.close().await;
            Err(io::Error::other(format!(
                "PQ auth signature verification failed: {e}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tallow_crypto::keys::IdentityKeyPair;
    use tallow_net::NetworkError;
    use tokio::sync::mpsc;

    const RECV_BUF_SIZE: usize = 256 * 1024;

    /// In-memory duplex channel between two ends (driver-level test harness).
    struct PipeChannel {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl PeerChannel for PipeChannel {
        async fn send_message(&mut self, data: &[u8]) -> tallow_net::Result<()> {
            self.tx
                .send(data.to_vec())
                .map_err(|e| NetworkError::RelayError(format!("pipe closed: {e}")))
        }
        async fn receive_message(&mut self, buf: &mut [u8]) -> tallow_net::Result<usize> {
            let data = self
                .rx
                .recv()
                .await
                .ok_or_else(|| NetworkError::RelayError("pipe closed".to_string()))?;
            if data.len() > buf.len() {
                return Err(NetworkError::RelayError("pipe frame too large".to_string()));
            }
            buf[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }
        async fn close(&mut self) {}
        fn transport_description(&self) -> String {
            "pipe".to_string()
        }
    }

    fn pipe_pair() -> (PipeChannel, PipeChannel) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        (
            PipeChannel { tx: a_tx, rx: b_rx },
            PipeChannel { tx: b_tx, rx: a_rx },
        )
    }

    /// Send one flight frame (mirrors driver-site code, incl. targeted mode).
    async fn flight_send(
        ch: &mut PipeChannel,
        codec: &mut TallowCodec,
        buf: &mut BytesMut,
        msg: &Message,
        mode: FlightMode,
    ) {
        buf.clear();
        match mode {
            FlightMode::Direct => codec.encode_msg(msg, buf).unwrap(),
            FlightMode::Targeted { from_peer, to_peer } => {
                let inner = postcard::to_stdvec(msg).unwrap();
                let wrapped = Message::Targeted {
                    from_peer,
                    to_peer,
                    payload: inner,
                };
                codec.encode_msg(&wrapped, buf).unwrap();
            }
        }
        ch.send_message(buf).await.unwrap();
    }

    /// Receive the next flight frame from the paired peer (unwraps `Targeted`
    /// in multi mode; answers pings).
    async fn flight_recv(
        ch: &mut PipeChannel,
        codec: &mut TallowCodec,
        buf: &mut BytesMut,
        recv: &mut [u8],
        mode: FlightMode,
    ) -> Message {
        loop {
            let n = ch.receive_message(recv).await.unwrap();
            let mut db = BytesMut::from(&recv[..n]);
            let msg = codec.decode_msg(&mut db).unwrap().unwrap();
            match msg {
                Message::Ping => {
                    buf.clear();
                    codec.encode_msg(&Message::Pong, buf).unwrap();
                    ch.send_message(buf).await.unwrap();
                }
                Message::Targeted {
                    from_peer, payload, ..
                } => {
                    if let FlightMode::Targeted { to_peer, .. } = mode {
                        if from_peer == to_peer {
                            return postcard::from_bytes(&payload).unwrap();
                        }
                    }
                    // Another peer's frame — keep waiting.
                }
                other => return other,
            }
        }
    }

    type DriverResult = (Result<PqAuthOutcome, String>, [u8; 32]);

    /// Drive a full sender flight + PQ exchange (the CLI driver shape).
    #[allow(clippy::too_many_arguments)]
    async fn sender_driver(
        ch: &mut PipeChannel,
        code: &str,
        version: u32,
        signer: Option<&HybridSigner>,
        pin: Option<[u8; 32]>,
        mode: FlightMode,
    ) -> DriverResult {
        let room_id = crate::room::code::derive_room_id(code);
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();
        let mut recv = vec![0u8; RECV_BUF_SIZE];
        let mut hs = SenderHandshake::new(code, &room_id);

        // Security review 2026-09-23: declare via `init_with_version` so the
        // sender's transcript matches what the receiver is told (v7+ binds
        // the declared version — no post-hoc wire rewrites in drivers).
        let init = hs.init_with_version(version).unwrap();
        flight_send(ch, &mut codec, &mut buf, &init, mode).await;

        let resp = flight_recv(ch, &mut codec, &mut buf, &mut recv, mode).await;
        let (selected_kem, cpace_public, kem_public_key, nonce) = match resp {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            } => (selected_kem, cpace_public, kem_public_key, nonce),
            other => panic!("expected HandshakeResponse, got {other:?}"),
        };
        let (kem, key) = hs
            .process_response(selected_kem, &cpace_public, &kem_public_key, &nonce)
            .unwrap();
        flight_send(ch, &mut codec, &mut buf, &kem, mode).await;

        let complete = flight_recv(ch, &mut codec, &mut buf, &mut recv, mode).await;
        match complete {
            Message::HandshakeComplete { confirmation } => {
                hs.verify_receiver_confirmation(&confirmation).unwrap();
            }
            other => panic!("expected HandshakeComplete, got {other:?}"),
        }

        let outcome = complete_sender(
            &mut hs,
            signer,
            ch,
            &mut codec,
            &mut buf,
            &mut recv,
            pin.as_ref(),
            mode,
        )
        .await
        .map_err(|e| e.to_string());
        (outcome, *key.as_bytes())
    }

    /// Drive a full receiver flight + PQ exchange (the CLI driver shape).
    async fn receiver_driver(
        ch: &mut PipeChannel,
        code: &str,
        signer: Option<&HybridSigner>,
        pin: Option<[u8; 32]>,
        mode: FlightMode,
    ) -> DriverResult {
        let room_id = crate::room::code::derive_room_id(code);
        let mut codec = TallowCodec::new();
        let mut buf = BytesMut::new();
        let mut recv = vec![0u8; RECV_BUF_SIZE];
        let mut hs = ReceiverHandshake::new(code, &room_id);

        let init = flight_recv(ch, &mut codec, &mut buf, &mut recv, mode).await;
        let (version, caps, cpace, nonce) = match init {
            Message::HandshakeInit {
                suite_code: _,
                protocol_version,
                kem_capabilities,
                cpace_public,
                nonce,
            } => (protocol_version, kem_capabilities, cpace_public, nonce),
            other => panic!("expected HandshakeInit, got {other:?}"),
        };
        let resp = hs.process_init(version, tallow_crypto::suite_code(), &caps, &cpace, &nonce).unwrap();
        flight_send(ch, &mut codec, &mut buf, &resp, mode).await;

        let kem = flight_recv(ch, &mut codec, &mut buf, &mut recv, mode).await;
        let (ct, confirmation) = match kem {
            Message::HandshakeKem {
                kem_ciphertext,
                confirmation,
            } => (kem_ciphertext, confirmation),
            other => panic!("expected HandshakeKem, got {other:?}"),
        };
        let (complete, key) = hs.process_kem(&ct, &confirmation).unwrap();
        flight_send(ch, &mut codec, &mut buf, &complete, mode).await;

        let outcome = complete_receiver(
            &mut hs,
            signer,
            ch,
            &mut codec,
            &mut buf,
            &mut recv,
            pin.as_ref(),
            mode,
        )
        .await
        .map_err(|e| e.to_string());
        (outcome, *key.as_bytes())
    }

    #[tokio::test]
    async fn test_pq_auth_v5_flight_verified_direct() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let alice_id = *alice.id();
        let bob_id = *bob.id();
        let (mut a_ch, mut b_ch) = pipe_pair();
        let code = "pq-pipe-v5-direct";

        let a = tokio::spawn(async move {
            sender_driver(
                &mut a_ch,
                code,
                5,
                Some(alice.signer()),
                Some(bob_id),
                FlightMode::Direct,
            )
            .await
        });
        let b = tokio::spawn(async move {
            receiver_driver(
                &mut b_ch,
                code,
                Some(bob.signer()),
                Some(alice_id),
                FlightMode::Direct,
            )
            .await
        });

        let (a_out, a_key) = a.await.unwrap();
        let (b_out, b_key) = b.await.unwrap();
        let a_out = a_out.unwrap();
        let b_out = b_out.unwrap();

        assert!(a_out.verified && b_out.verified);
        assert_eq!(a_out.peer_identity, Some(bob_id));
        assert_eq!(b_out.peer_identity, Some(alice_id));
        assert!(a_out.alarm.is_none() && b_out.alarm.is_none());
        assert_eq!(a_key, b_key, "session keys must match");
    }

    #[tokio::test]
    async fn test_pq_auth_v5_flight_verified_targeted() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let alice_id = *alice.id();
        let bob_id = *bob.id();
        let (mut a_ch, mut b_ch) = pipe_pair();
        let code = "pq-pipe-v5-targeted";
        let s_mode = FlightMode::Targeted {
            from_peer: 1,
            to_peer: 2,
        };
        let r_mode = FlightMode::Targeted {
            from_peer: 2,
            to_peer: 1,
        };

        let a = tokio::spawn(async move {
            sender_driver(&mut a_ch, code, 5, Some(alice.signer()), None, s_mode).await
        });
        let b = tokio::spawn(async move {
            receiver_driver(&mut b_ch, code, Some(bob.signer()), None, r_mode).await
        });

        let (a_out, a_key) = a.await.unwrap();
        let (b_out, b_key) = b.await.unwrap();
        let a_out = a_out.unwrap();
        let b_out = b_out.unwrap();

        assert!(a_out.verified && b_out.verified);
        assert_eq!(a_out.peer_identity, Some(bob_id));
        assert_eq!(b_out.peer_identity, Some(alice_id));
        assert_eq!(a_key, b_key);
    }

    #[tokio::test]
    async fn test_pq_auth_v4_flight_alarm_both_sides() {
        let (mut a_ch, mut b_ch) = pipe_pair();
        let code = "pq-pipe-v4-alarm";

        let a = tokio::spawn(async move {
            sender_driver(&mut a_ch, code, 4, None, None, FlightMode::Direct).await
        });
        let b = tokio::spawn(async move {
            receiver_driver(&mut b_ch, code, None, None, FlightMode::Direct).await
        });

        let (a_out, a_key) = a.await.unwrap();
        let (b_out, b_key) = b.await.unwrap();
        let a_out = a_out.unwrap();
        let b_out = b_out.unwrap();

        assert!(!a_out.verified && !b_out.verified);
        assert!(a_out.peer_identity.is_none() && b_out.peer_identity.is_none());
        assert!(a_out.alarm.is_some() && b_out.alarm.is_some());
        assert_eq!(a_key, b_key, "v4 flight must still complete");
    }

    #[tokio::test]
    async fn test_pq_auth_pin_mismatch_fails_sender() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let mallory = IdentityKeyPair::generate().unwrap();
        let alice_id = *alice.id();
        let mallory_id = *mallory.id();
        let (mut a_ch, mut b_ch) = pipe_pair();
        let code = "pq-pipe-pin-mismatch";

        // Sender pins the WRONG identity; receiver pins correctly.
        let a = tokio::spawn(async move {
            sender_driver(
                &mut a_ch,
                code,
                5,
                Some(alice.signer()),
                Some(mallory_id),
                FlightMode::Direct,
            )
            .await
        });
        let b = tokio::spawn(async move {
            receiver_driver(
                &mut b_ch,
                code,
                Some(bob.signer()),
                Some(alice_id),
                FlightMode::Direct,
            )
            .await
        });

        let (a_out, _) = a.await.unwrap();
        let (b_out, _) = b.await.unwrap();

        let err = a_out.expect_err("sender must reject the wrong pinned identity");
        assert!(err.contains("verification failed"), "got: {err}");
        let b_out = b_out.unwrap();
        assert!(b_out.verified, "receiver's own verification is unaffected");
    }
}
