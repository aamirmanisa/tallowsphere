//! Chat session management
//!
//! Manages a chat session between two peers using an async channel-based
//! message passing architecture. Optionally encrypts/decrypts messages
//! using a Triple Ratchet (Double Ratchet + Sparse PQ Ratchet) with
//! post-quantum re-keying.
//!
//! PQ rekey wiring (T-203 / ATK-4-4): the sparse PQ ratchet's ML-KEM rekey
//! exchange is carried end-to-end through this session API. Control records
//! (the rekey public key, the encapsulated ciphertext) ride inside the
//! ratchet-encrypted payload, so the wire format is unchanged. Until an
//! exchange has actually completed, `is_pq_active()` reports `false` and no
//! post-quantum forward secrecy may be claimed for the session.
//!
//! Boundary discipline (drain alignment): the peer that has just received a
//! rekey public key encapsulates on its *next send* (the ciphertext rides
//! that same message), and the owner processes the returned ciphertext on
//! receive. Both sides then mix the KEM secret into the double-ratchet root
//! key in the ratchet step that follows that same message, so the mixes land
//! on the same root-key state on both peers. Crossing that boundary with
//! in-flight traffic breaks decryption: the root-key mix replaces both chain
//! keys, so messages must not straddle the two drain points.

use super::ChatMessage;
use crate::{ProtocolError, Result};
use tallow_crypto::kem::mlkem::{Ciphertext, PublicKey};
use tallow_crypto::ratchet::TripleRatchet;
use tokio::sync::mpsc;

/// Default number of ratchet steps between sparse ML-KEM rekeys.
const DEFAULT_PQ_REKEY_INTERVAL: u64 = 10;

/// Magic prefix marking a ratchet payload that carries PQ rekey control data.
const PQ_FRAME_MAGIC: &[u8; 4] = b"TQP1";
/// Payload flag: an ML-KEM rekey public key record follows.
const PQ_FLAG_PK: u8 = 0b0000_0001;
/// Payload flag: an ML-KEM encapsulation ciphertext record follows.
const PQ_FLAG_CT: u8 = 0b0000_0010;

/// A ratchet payload split into (optional) PQ control records and user text.
struct PqPayload<'a> {
    /// Peer rekey public key to encapsulate against (owner side emitted it).
    rekey_pk: Option<&'a [u8]>,
    /// ML-KEM ciphertext completing the peer's rekey (owner side consumes it).
    ciphertext: Option<&'a [u8]>,
    /// Remaining bytes are the user text.
    text: &'a [u8],
}

/// Frame user text plus optional PQ control records for the ratchet payload.
///
/// Layout: `MAGIC(4) | flags(1) | [pk_len(2 LE) | pk] | [ct_len(2 LE) | ct] | text`.
/// Each record field is present iff its flag bit is set. Frames ride inside
/// the ratchet ciphertext, so PQ control data is transported (and
/// authenticated) without changing the wire format.
fn frame_pq_payload(
    rekey_pk: Option<&PublicKey>,
    ciphertext: Option<&Ciphertext>,
    text: &[u8],
) -> Vec<u8> {
    let mut flags = 0u8;
    if rekey_pk.is_some() {
        flags |= PQ_FLAG_PK;
    }
    if ciphertext.is_some() {
        flags |= PQ_FLAG_CT;
    }

    let mut out = Vec::with_capacity(
        5 + text.len()
            + rekey_pk.map_or(0, |pk| pk.as_bytes().len() + 2)
            + ciphertext.map_or(0, |ct| ct.as_bytes().len() + 2),
    );
    out.extend_from_slice(PQ_FRAME_MAGIC);
    out.push(flags);
    if let Some(pk) = rekey_pk {
        let bytes = pk.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    if let Some(ct) = ciphertext {
        let bytes = ct.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(text);
    out
}

/// Consume one length-prefixed control record (`u16 LE length || bytes`) from
/// `rest`, advancing it past the record. Absent records are a no-op.
fn take_record<'a>(rest: &mut &'a [u8], present: bool) -> Result<Option<&'a [u8]>> {
    if !present {
        return Ok(None);
    }
    let bytes = *rest;
    if bytes.len() < 2 {
        return Err(ProtocolError::TransferFailed(
            "Invalid PQ control framing: truncated record length".to_string(),
        ));
    }
    let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() - 2 < len {
        return Err(ProtocolError::TransferFailed(
            "Invalid PQ control framing: record length exceeds payload".to_string(),
        ));
    }
    let (record, tail) = bytes[2..].split_at(len);
    *rest = tail;
    Ok(Some(record))
}

/// Parse a ratchet payload into PQ control records plus user text.
///
/// Payloads without the frame magic are treated as plain user text for
/// backwards compatibility with sessions that predate the wiring.
fn parse_pq_payload(payload: &[u8]) -> Result<PqPayload<'_>> {
    if !payload.starts_with(PQ_FRAME_MAGIC) || payload.len() < PQ_FRAME_MAGIC.len() + 1 {
        return Ok(PqPayload {
            rekey_pk: None,
            ciphertext: None,
            text: payload,
        });
    }

    let flags = payload[4];
    if flags & !(PQ_FLAG_PK | PQ_FLAG_CT) != 0 {
        return Err(ProtocolError::TransferFailed(
            "Invalid PQ control framing: unknown flag bits".to_string(),
        ));
    }

    let mut rest = &payload[5..];
    let rekey_pk = take_record(&mut rest, flags & PQ_FLAG_PK != 0)?;
    let ciphertext = take_record(&mut rest, flags & PQ_FLAG_CT != 0)?;
    Ok(PqPayload {
        rekey_pk,
        ciphertext,
        text: rest,
    })
}

/// Chat session with a peer
pub struct ChatSession {
    /// Session ID
    pub id: String,
    /// Peer ID
    pub peer_id: String,
    /// Local sender ID
    local_id: String,
    /// Message history
    messages: Vec<ChatMessage>,
    /// Outbound message channel
    outbound_tx: mpsc::Sender<ChatMessage>,
    /// Inbound message channel
    inbound_rx: mpsc::Receiver<ChatMessage>,
    /// Optional Triple Ratchet for end-to-end encryption
    ratchet: Option<TripleRatchet>,
    /// PQ rekey public key emitted by our ratchet, to transmit to the peer
    /// in our next outgoing message (cleared once transmitted).
    pending_pq_rekey_key: Option<PublicKey>,
    /// ML-KEM ciphertext from encapsulating the peer's rekey key, to transmit
    /// back so the peer can complete the exchange. Rides the same message
    /// that produced it.
    pending_pq_ciphertext: Option<Ciphertext>,
    /// Peer's rekey public key received but not yet encapsulated. The
    /// encapsulation is deferred to our next send so that both peers drain
    /// the KEM secret into the root key at the same message boundary.
    pending_pq_peer_key: Option<PublicKey>,
}

impl std::fmt::Debug for ChatSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSession")
            .field("id", &self.id)
            .field("peer_id", &self.peer_id)
            .field("local_id", &self.local_id)
            .field("messages", &self.messages)
            .field("encrypted", &self.ratchet.is_some())
            .field("pq_active", &self.is_pq_active())
            .finish_non_exhaustive()
    }
}

impl ChatSession {
    /// Create a new chat session with channels for message I/O.
    ///
    /// Returns the session along with the channel endpoints that should
    /// be connected to the network transport layer.
    pub fn new(
        id: String,
        peer_id: String,
    ) -> (Self, mpsc::Receiver<ChatMessage>, mpsc::Sender<ChatMessage>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (inbound_tx, inbound_rx) = mpsc::channel(64);

        let session = Self {
            id,
            local_id: "local".to_string(),
            peer_id,
            messages: Vec::new(),
            outbound_tx,
            inbound_rx,
            ratchet: None,
            pending_pq_rekey_key: None,
            pending_pq_ciphertext: None,
            pending_pq_peer_key: None,
        };

        (session, outbound_rx, inbound_tx)
    }

    /// Set the local sender ID
    pub fn set_local_id(&mut self, id: String) {
        self.local_id = id;
    }

    /// Enable end-to-end encryption with a shared secret.
    ///
    /// Initializes the Triple Ratchet (Double Ratchet + Sparse PQ Ratchet).
    /// The sparse PQ ratchet periodically performs an ML-KEM rekey exchange
    /// (default interval: 10 ratchet steps); the exchange is wired through
    /// this session's send/receive API. The `is_initiator` flag determines
    /// which side of the ratchet this session takes.
    ///
    /// PQ forward secrecy is only in effect once an exchange has completed —
    /// check [`ChatSession::is_pq_active`].
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte shared secret from key exchange
    /// * `is_initiator` - `true` for the session initiator, `false` for the responder
    pub fn enable_encryption(&mut self, shared_secret: &[u8; 32], is_initiator: bool) {
        self.enable_encryption_with_rekey_interval(
            shared_secret,
            is_initiator,
            DEFAULT_PQ_REKEY_INTERVAL,
        );
    }

    /// Same as [`ChatSession::enable_encryption`] with an explicit sparse-PQ
    /// rekey interval (ratchet steps between ML-KEM rekeys).
    pub fn enable_encryption_with_rekey_interval(
        &mut self,
        shared_secret: &[u8; 32],
        is_initiator: bool,
        pq_rekey_interval: u64,
    ) {
        let ratchet = if is_initiator {
            TripleRatchet::init(shared_secret, pq_rekey_interval)
        } else {
            TripleRatchet::init_responder(shared_secret, pq_rekey_interval)
        };
        self.pending_pq_rekey_key = None;
        self.pending_pq_ciphertext = None;
        self.pending_pq_peer_key = None;
        self.ratchet = Some(ratchet);
    }

    /// Check whether encryption is enabled for this session
    pub fn is_encrypted(&self) -> bool {
        self.ratchet.is_some()
    }

    /// Whether the PQ ratchet has actually completed an ML-KEM rekey exchange
    /// for this session (forwarded from [`TripleRatchet::is_pq_active`]).
    ///
    /// `false` means no post-quantum secret has been mixed into the root key
    /// yet — do not claim PQ forward secrecy for this session.
    pub fn is_pq_active(&self) -> bool {
        self.ratchet.as_ref().is_some_and(|r| r.is_pq_active())
    }

    /// Send a message to the peer.
    ///
    /// If encryption is enabled, the message text is encrypted via the
    /// Triple Ratchet and sent as a hex-encoded ciphertext. Otherwise,
    /// the message is sent as plaintext.
    ///
    /// PQ rekey control records (rekey public key / exchanged ciphertext) are
    /// framed into the encrypted payload when pending.
    pub async fn send(&mut self, text: String) -> Result<()> {
        let msg = if let Some(ref mut ratchet) = self.ratchet {
            // Complete any pending peer-side exchange first: encapsulate
            // against the peer's rekey public key so the returned ciphertext
            // can ride in this same message. The KEM secret is mixed into the
            // sparse chain now and drained into the root key by the `step_pq`
            // below — i.e. at this message boundary on both peers.
            if let Some(pk) = self.pending_pq_peer_key.take() {
                let ct = ratchet.encapsulate_pq(&pk).map_err(|e| {
                    ProtocolError::TransferFailed(format!("PQ encapsulate failed: {}", e))
                })?;
                self.pending_pq_ciphertext = Some(ct);
            }

            // Frame the plaintext with any pending PQ control records.
            let payload = frame_pq_payload(
                self.pending_pq_rekey_key.as_ref(),
                self.pending_pq_ciphertext.as_ref(),
                text.as_bytes(),
            );
            // Everything framed above is transmitted by this message.
            self.pending_pq_rekey_key = None;
            self.pending_pq_ciphertext = None;

            // Encrypt before stepping: this message must remain decryptable
            // under the pre-mix chain keys (the root-key mix lands in the
            // step below, on both peers at this same boundary).
            let ciphertext = ratchet.encrypt_message(&payload).map_err(|e| {
                ProtocolError::TransferFailed(format!("Chat encrypt failed: {}", e))
            })?;

            // Advance the ratchet. A reached rekey boundary emits a fresh
            // ML-KEM public key that our next outgoing message will carry;
            // a completed exchange secret is drained into the root key here.
            if let Some(pk) = ratchet
                .step_pq()
                .map_err(|e| ProtocolError::TransferFailed(format!("Ratchet step failed: {}", e)))?
            {
                self.pending_pq_rekey_key = Some(pk);
            }

            // Hex-encode the ciphertext for wire transport
            let hex_ct =
                ciphertext
                    .iter()
                    .fold(String::with_capacity(ciphertext.len() * 2), |mut s, b| {
                        use std::fmt::Write;
                        let _ = write!(s, "{b:02x}");
                        s
                    });
            ChatMessage::new_encrypted(self.local_id.clone(), hex_ct)
        } else {
            ChatMessage::new(self.local_id.clone(), text)
        };

        self.messages.push(msg.clone());

        self.outbound_tx
            .send(msg)
            .await
            .map_err(|e| ProtocolError::TransferFailed(format!("Chat send failed: {}", e)))?;

        Ok(())
    }

    /// Receive a message from the peer.
    ///
    /// If encryption is enabled and the incoming message is marked encrypted,
    /// the hex-encoded ciphertext is decoded and decrypted via the Triple
    /// Ratchet before being returned as plaintext. PQ rekey control records
    /// embedded in the payload are applied to the ratchet before the step.
    pub async fn receive(&mut self) -> Result<ChatMessage> {
        let mut msg = self
            .inbound_rx
            .recv()
            .await
            .ok_or_else(|| ProtocolError::TransferFailed("Chat channel closed".to_string()))?;

        if msg.encrypted {
            if let Some(ref mut ratchet) = self.ratchet {
                // Validate hex string length before decoding
                if msg.text.len() % 2 != 0 {
                    return Err(ProtocolError::TransferFailed(
                        "Invalid ciphertext: odd-length hex string".to_string(),
                    ));
                }

                // Decode hex ciphertext
                let ct_bytes = (0..msg.text.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&msg.text[i..i + 2], 16).map_err(|e| {
                            ProtocolError::TransferFailed(format!(
                                "Invalid hex in ciphertext: {}",
                                e
                            ))
                        })
                    })
                    .collect::<std::result::Result<Vec<u8>, _>>()?;

                let payload = ratchet.decrypt_message(&ct_bytes).map_err(|e| {
                    ProtocolError::TransferFailed(format!("Chat decrypt failed: {}", e))
                })?;

                let parsed = parse_pq_payload(&payload)?;

                // Store the peer's rekey public key. Encapsulation is
                // deferred to our next outgoing message (the ciphertext must
                // ride that message so both peers drain the KEM secret into
                // the root key at the same boundary).
                if let Some(pk_bytes) = parsed.rekey_pk {
                    let pk = PublicKey::from_bytes(pk_bytes.to_vec()).map_err(|e| {
                        ProtocolError::TransferFailed(format!("Invalid PQ rekey key: {}", e))
                    })?;
                    self.pending_pq_peer_key = Some(pk);
                }

                // Owner side: a peer ciphertext completes the exchange; the
                // secret is drained into the root key by the `step_pq` below,
                // i.e. at this same message boundary on both peers.
                if let Some(ct_bytes) = parsed.ciphertext {
                    let ct = Ciphertext::from_bytes(ct_bytes.to_vec()).map_err(|e| {
                        ProtocolError::TransferFailed(format!("Invalid PQ ciphertext: {}", e))
                    })?;
                    ratchet.process_pq_ciphertext(&ct).map_err(|e| {
                        ProtocolError::TransferFailed(format!(
                            "PQ ciphertext processing failed: {}",
                            e
                        ))
                    })?;
                }

                // Advance the ratchet at this message boundary. A rekey
                // public key emitted here rides our next outgoing message.
                if let Some(pk) = ratchet.step_pq().map_err(|e| {
                    ProtocolError::TransferFailed(format!("Ratchet step failed: {}", e))
                })? {
                    self.pending_pq_rekey_key = Some(pk);
                }

                msg.text = String::from_utf8(parsed.text.to_vec()).map_err(|e| {
                    ProtocolError::TransferFailed(format!(
                        "Invalid UTF-8 in decrypted message: {}",
                        e
                    ))
                })?;
                // Mark as decrypted for display layer
                msg.encrypted = false;
            }
        }

        // Sanitize all incoming message text (whether decrypted or plaintext)
        // to strip ANSI escape sequences and control characters
        msg.text = crate::transfer::sanitize::sanitize_display(&msg.text);

        self.messages.push(msg.clone());
        Ok(msg)
    }

    /// Get message history
    pub fn messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    /// Get the number of messages in history
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_message() {
        let (mut session, mut outbound_rx, _inbound_tx) =
            ChatSession::new("sess1".to_string(), "peer1".to_string());

        session.send("hello".to_string()).await.unwrap();
        assert_eq!(session.messages().len(), 1);
        assert_eq!(session.messages()[0].text, "hello");

        // Message should be available on the outbound channel
        let msg = outbound_rx.recv().await.unwrap();
        assert_eq!(msg.text, "hello");
    }

    #[tokio::test]
    async fn test_receive_message() {
        let (mut session, _outbound_rx, inbound_tx) =
            ChatSession::new("sess1".to_string(), "peer1".to_string());

        // Simulate an inbound message
        let msg = ChatMessage::new("peer1".to_string(), "hi there".to_string());
        inbound_tx.send(msg).await.unwrap();

        let received = session.receive().await.unwrap();
        assert_eq!(received.text, "hi there");
        assert_eq!(session.messages().len(), 1);
    }

    #[tokio::test]
    async fn test_message_count() {
        let (mut session, _outbound_rx, inbound_tx) =
            ChatSession::new("sess1".to_string(), "peer1".to_string());

        session.send("msg1".to_string()).await.unwrap();

        let msg = ChatMessage::new("peer1".to_string(), "msg2".to_string());
        inbound_tx.send(msg).await.unwrap();
        session.receive().await.unwrap();

        assert_eq!(session.message_count(), 2);
    }

    #[tokio::test]
    async fn test_encrypted_send_receive() {
        let shared_secret = [42u8; 32];

        // Create sender session (initiator)
        let (mut sender_session, mut sender_outbound_rx, _sender_inbound_tx) =
            ChatSession::new("sess1".to_string(), "peer1".to_string());
        sender_session.enable_encryption(&shared_secret, true);
        assert!(sender_session.is_encrypted());

        // Create receiver session (responder)
        let (mut receiver_session, _receiver_outbound_rx, receiver_inbound_tx) =
            ChatSession::new("sess2".to_string(), "peer2".to_string());
        receiver_session.enable_encryption(&shared_secret, false);
        assert!(receiver_session.is_encrypted());

        // Send an encrypted message
        sender_session
            .send("secret message".to_string())
            .await
            .unwrap();

        // The outbound message should be encrypted (hex-encoded ciphertext)
        let wire_msg = sender_outbound_rx.recv().await.unwrap();
        assert!(wire_msg.encrypted);
        assert_ne!(wire_msg.text, "secret message");

        // Forward the encrypted message to the receiver's inbound channel
        receiver_inbound_tx.send(wire_msg).await.unwrap();

        // Receive and decrypt
        let received = receiver_session.receive().await.unwrap();
        assert_eq!(received.text, "secret message");
        assert!(!received.encrypted); // Should be marked as decrypted
    }

    #[tokio::test]
    async fn test_encrypted_multiple_messages() {
        let shared_secret = [99u8; 32];

        let (mut sender, mut sender_rx, _sender_tx) =
            ChatSession::new("s1".to_string(), "p1".to_string());
        sender.enable_encryption(&shared_secret, true);

        let (mut receiver, _receiver_rx, receiver_tx) =
            ChatSession::new("s2".to_string(), "p2".to_string());
        receiver.enable_encryption(&shared_secret, false);

        // Send multiple messages and verify round-trip
        let messages = ["hello", "world", "post-quantum secure!"];
        for text in &messages {
            sender.send(text.to_string()).await.unwrap();
            let wire_msg = sender_rx.recv().await.unwrap();
            assert!(wire_msg.encrypted);
            receiver_tx.send(wire_msg).await.unwrap();
            let received = receiver.receive().await.unwrap();
            assert_eq!(received.text, *text);
        }

        assert_eq!(sender.message_count(), 3);
        assert_eq!(receiver.message_count(), 3);
    }

    #[tokio::test]
    async fn test_unencrypted_session_unchanged() {
        // Verify that sessions without encryption still work identically
        let (mut session, mut outbound_rx, _inbound_tx) =
            ChatSession::new("sess1".to_string(), "peer1".to_string());
        assert!(!session.is_encrypted());

        session.send("plaintext".to_string()).await.unwrap();
        let msg = outbound_rx.recv().await.unwrap();
        assert!(!msg.encrypted);
        assert_eq!(msg.text, "plaintext");
    }

    // --- T-203: PQ rekey exchange wiring through the session API ---

    /// A pair of wired sessions (initiator + responder) plus the channel
    /// endpoints used to ferry ciphertexts between them.
    struct WiredPair {
        initiator: ChatSession,
        responder: ChatSession,
        init_out: mpsc::Receiver<ChatMessage>,
        resp_in: mpsc::Sender<ChatMessage>,
        resp_out: mpsc::Receiver<ChatMessage>,
        init_in: mpsc::Sender<ChatMessage>,
    }

    fn wired_pair(shared_secret: &[u8; 32], rekey_interval: u64) -> WiredPair {
        let (mut initiator, init_out, init_in) =
            ChatSession::new("init".to_string(), "resp".to_string());
        initiator.enable_encryption_with_rekey_interval(shared_secret, true, rekey_interval);

        let (mut responder, resp_out, resp_in) =
            ChatSession::new("resp".to_string(), "init".to_string());
        responder.enable_encryption_with_rekey_interval(shared_secret, false, rekey_interval);

        WiredPair {
            initiator,
            responder,
            init_out,
            resp_in,
            resp_out,
            init_in,
        }
    }

    impl WiredPair {
        /// One lockstep round trip: the chosen leader sends, the peer
        /// receives, then the peer replies and the leader receives.
        async fn round(&mut self, initiator_leads: bool, tag: &str) {
            if initiator_leads {
                Self::deliver(
                    &mut self.initiator,
                    &mut self.init_out,
                    &mut self.responder,
                    &mut self.resp_in,
                    &format!("{} init->resp", tag),
                )
                .await;
                Self::deliver(
                    &mut self.responder,
                    &mut self.resp_out,
                    &mut self.initiator,
                    &mut self.init_in,
                    &format!("{} resp->init", tag),
                )
                .await;
            } else {
                Self::deliver(
                    &mut self.responder,
                    &mut self.resp_out,
                    &mut self.initiator,
                    &mut self.init_in,
                    &format!("{} resp->init", tag),
                )
                .await;
                Self::deliver(
                    &mut self.initiator,
                    &mut self.init_out,
                    &mut self.responder,
                    &mut self.resp_in,
                    &format!("{} init->resp", tag),
                )
                .await;
            }
        }

        async fn deliver(
            sender: &mut ChatSession,
            out: &mut mpsc::Receiver<ChatMessage>,
            receiver: &mut ChatSession,
            inp: &mut mpsc::Sender<ChatMessage>,
            text: &str,
        ) {
            sender.send(text.to_string()).await.unwrap();
            let wire = out.recv().await.expect("outbound ciphertext");
            assert!(wire.encrypted, "wire message must be encrypted");
            inp.send(wire).await.unwrap();
            let received = receiver.receive().await.unwrap();
            assert_eq!(received.text, text, "round-trip must preserve text");
        }
    }

    #[tokio::test]
    async fn test_pq_exchange_round_trip_through_session_api_initiator_leads() {
        let shared_secret = [42u8; 32];
        let mut pair = wired_pair(&shared_secret, 5);

        // Pre-establishment: nothing may claim PQ activity yet.
        assert!(!pair.initiator.is_pq_active());
        assert!(!pair.responder.is_pq_active());

        // 8 rounds = 16 message boundaries per side. Rekey interval 5 puts
        // rekey boundaries at steps 5, 10 and 15, i.e. three ML-KEM exchanges
        // complete along the way — messages must keep round-tripping across
        // every root-key mix.
        for r in 0..8 {
            pair.round(true, &format!("r{}", r)).await;
        }

        assert!(
            pair.initiator.is_pq_active(),
            "a completed exchange must be reported as PQ-active"
        );
        assert!(pair.responder.is_pq_active());
    }

    #[tokio::test]
    async fn test_pq_exchange_round_trip_through_session_api_responder_leads() {
        let shared_secret = [77u8; 32];
        let mut pair = wired_pair(&shared_secret, 5);

        // Same exchange, opposite message order: the responder sends first
        // every round, so the rekey public keys and ciphertexts ride the
        // other direction.
        for r in 0..8 {
            pair.round(false, &format!("r{}", r)).await;
        }

        assert!(pair.initiator.is_pq_active());
        assert!(pair.responder.is_pq_active());
    }

    #[tokio::test]
    async fn test_pq_not_claimed_before_exchange_completes() {
        let shared_secret = [7u8; 32];
        let mut pair = wired_pair(&shared_secret, 4);

        // A plaintext session never claims PQ.
        let (plain, _out, _in) = ChatSession::new("p".to_string(), "q".to_string());
        assert!(!plain.is_pq_active());

        // Rounds 1-2 reach the step-4 rekey boundary: both sides generate a
        // fresh ML-KEM keypair and emit its public key for transmission, but
        // no ciphertext has been fed back yet. The claim must stay false —
        // emitting a rekey key is not establishment.
        pair.round(true, "pre1").await;
        assert!(!pair.initiator.is_pq_active());
        assert!(!pair.responder.is_pq_active());
        pair.round(true, "pre2").await;
        assert!(!pair.initiator.is_pq_active());
        assert!(!pair.responder.is_pq_active());

        // Round 3 completes the exchange on both sides.
        pair.round(true, "post").await;
        assert!(pair.initiator.is_pq_active());
        assert!(pair.responder.is_pq_active());

        // And the session keeps decrypting across the PQ root-key mix.
        pair.round(true, "after-mix").await;
        assert!(pair.initiator.is_pq_active());
        assert!(pair.responder.is_pq_active());
    }
}
