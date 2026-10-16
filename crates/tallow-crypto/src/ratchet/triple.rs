//! Triple Ratchet combining Double Ratchet and Sparse PQ Ratchet
//!
//! The Triple Ratchet provides post-quantum forward secrecy by periodically
//! mixing ML-KEM-derived secrets into the Double Ratchet's root key.
//! Key rotation occurs automatically on every direction change via
//! `mix_direction_change`, providing post-compromise security.
//!
//! ATK-4-4 (T-202): the PQ mix only happens after a *completed* ML-KEM
//! exchange — the transport must transmit the `step_pq()` public key and feed
//! the peer ciphertext back through `process_pq_ciphertext` (peer side:
//! `encapsulate_pq`). Until that plumbing completes, no fresh entropy enters
//! the root key, `is_pq_active()` reports `false`, and no PQ forward secrecy
//! may be claimed for the session. The earlier implementation instead re-mixed
//! the (never-advancing) sparse-ratchet secret on every rekey boundary — a
//! no-op.
//!
//! T-203 wires that exchange in `tallow-protocol`'s chat session
//! (`ChatSession`): rekey public keys and exchanged ciphertexts ride as
//! control records inside the ratchet-encrypted payload, the peer that
//! received a rekey key defers `encapsulate_pq` to the send that transmits
//! the ciphertext, and both sides drain the completed secret into the root
//! key in the ratchet step following that same message — so the mixes land
//! on the same root-key state on both peers. The header-framed entry points
//! (`encrypt_with_header`/`decrypt_with_header`) remain PQ-inert: their wire
//! framing has no space for the exchange and that work is tracked with the
//! header/counter finding (ATK-4-5). Do not claim PQ for sessions driven
//! through the header path.
//!
//! Phase 5 item 3: that "same message boundary" was a CALLER CONTRACT, and a
//! one-message skew broke it silently — a single pending slot meant the next
//! completed exchange overwrote an undrained secret, so the two peers applied
//! different mix sequences and their root keys never converged again. The
//! sparse ratchet now holds completed secrets in chain-epoch order
//! (`SparsePqRatchet::take_pending_mix` drains oldest-first), so the mix
//! sequence is derived from each secret's epoch tag rather than from the
//! caller's timing: a skew delays the mixes, it cannot reorder or silently
//! drop one. A capacity bound still exists and a drop is COUNTED
//! (`TripleRatchet::dropped_pq_mixes`), because a dropped mix means the
//! sessions diverge and PQ must not be claimed for them.

use crate::error::Result;
use crate::kem::mlkem::{Ciphertext, PublicKey};
use crate::mem::constant_time::ct_eq;
use crate::ratchet::{DoubleRatchet, SparsePqRatchet};
use zeroize::Zeroize;

/// Message direction for auto-step tracking
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    /// Sending a message
    Send,
    /// Receiving a message
    Receive,
    /// Initial state before first operation
    None,
}

/// Triple Ratchet state
///
/// Not Clone — ratchet state must never be duplicated (nonce reuse risk).
/// Serialize/Deserialize required for WASM session persistence.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TripleRatchet {
    double_ratchet: DoubleRatchet,
    sparse_pq_ratchet: SparsePqRatchet,
    /// Tracks last message direction for auto key rotation
    last_direction: Direction,
    /// Peer's last known DH ratchet public key (from their message header)
    peer_ratchet_key: Option<Vec<u8>>,
    /// Our ratchet public key as included in our last outgoing header.
    /// The peer stores this as their `peer_ratchet_key`. When the peer
    /// changes direction, they mix this value. We store it so we can
    /// perform the same mix on receive.
    own_last_sent_key: Option<[u8; 32]>,
}

impl Zeroize for TripleRatchet {
    fn zeroize(&mut self) {
        self.double_ratchet.zeroize();
        self.sparse_pq_ratchet.zeroize();
        if let Some(ref mut key) = self.peer_ratchet_key {
            key.zeroize();
        }
        if let Some(ref mut key) = self.own_last_sent_key {
            key.zeroize();
        }
    }
}

impl Drop for TripleRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl TripleRatchet {
    /// Initialize a new triple ratchet as the initiator
    pub fn init(shared_secret: &[u8; 32], pq_rekey_interval: u64) -> Self {
        Self {
            double_ratchet: DoubleRatchet::init(shared_secret),
            sparse_pq_ratchet: SparsePqRatchet::new(*shared_secret, pq_rekey_interval),
            last_direction: Direction::None,
            peer_ratchet_key: None,
            own_last_sent_key: None,
        }
    }

    /// Initialize a new triple ratchet as the responder
    pub fn init_responder(shared_secret: &[u8; 32], pq_rekey_interval: u64) -> Self {
        Self {
            double_ratchet: DoubleRatchet::init_responder(shared_secret),
            sparse_pq_ratchet: SparsePqRatchet::new(*shared_secret, pq_rekey_interval),
            last_direction: Direction::None,
            peer_ratchet_key: None,
            own_last_sent_key: None,
        }
    }

    /// Encrypt a message (internal, no header framing)
    ///
    /// Kept for backward compatibility with existing callers.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.double_ratchet.encrypt_message(plaintext)
    }

    /// Decrypt a message (internal, no header framing)
    ///
    /// Kept for backward compatibility with existing callers.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.double_ratchet.decrypt_message(ciphertext)
    }

    /// Decrypt the frame the sender labelled with `declared` — the position it
    /// says it used (v9: `ChatTextV9.sequence`).
    ///
    /// This is the entry point a transport should use when the frame carries
    /// its own position: a frame that arrives after a gap (a dropped frame, or
    /// two swapped in flight) decrypts at its own position through the skipped
    /// key cache, and the receive direction survives. A peer that does not label
    /// its frames is still placed positionally, so adopting this entry point
    /// does not refuse an unlabelled peer. See
    /// [`DoubleRatchet::decrypt_message_labeled`] for why the label cannot be
    /// trusted, and why it does not need to be.
    pub fn decrypt_message_labeled(&mut self, ciphertext: &[u8], declared: u64) -> Result<Vec<u8>> {
        self.double_ratchet
            .decrypt_message_labeled(ciphertext, declared)
    }

    /// Decrypt at an explicit ratchet position, with no positional fallback.
    pub fn decrypt_message_at(&mut self, ciphertext: &[u8], message_num: u64) -> Result<Vec<u8>> {
        self.double_ratchet
            .decrypt_message_at(ciphertext, message_num)
    }

    /// The ratchet position our next outgoing chat frame will use.
    ///
    /// A transport that labels frames (v9 `sequence`) must take the label from
    /// HERE, not from a counter of its own: a label that is not the ratchet's
    /// position is a label the peer cannot use.
    pub fn send_sequence(&self) -> u64 {
        self.double_ratchet.send_sequence()
    }

    /// The ratchet position we expect next from the peer (see
    /// [`DoubleRatchet::recv_sequence`]).
    pub fn recv_sequence(&self) -> u64 {
        self.double_ratchet.recv_sequence()
    }

    /// Encrypt with header framing and direction-aware key rotation.
    ///
    /// Returns `[ratchet_public_key(32) | counter_placeholder(8) | ciphertext]`.
    ///
    /// On direction change (Receive -> Send), the stored peer ratchet key is
    /// mixed into the root key to derive new chain keys, providing forward
    /// secrecy on every direction change. The peer performs the matching mix
    /// using `own_last_sent_key` (which equals what the sender stored).
    pub fn encrypt_with_header(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Auto key rotation on direction change (Receive -> Send)
        // Sender mixes peer_ratchet_key (the key from the peer's last header).
        // The receiver will match this by mixing own_last_sent_key.
        if self.last_direction == Direction::Receive {
            if let Some(ref peer_key) = self.peer_ratchet_key {
                if peer_key.len() == 32 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(peer_key);
                    self.double_ratchet.mix_direction_change(&key_bytes);
                    key_bytes.zeroize();
                }
            }
        }

        // Get current ratchet public key for header
        let ratchet_pk = self.double_ratchet.ratchet_public_key();

        // Encrypt using current send chain
        let ciphertext = self.double_ratchet.encrypt_message(plaintext)?;

        // Build header: [ratchet_pk(32) | counter_placeholder(8) | ciphertext]
        let mut framed = Vec::with_capacity(32 + 8 + ciphertext.len());
        framed.extend_from_slice(&ratchet_pk);
        framed.extend_from_slice(&0u64.to_le_bytes());
        framed.extend_from_slice(&ciphertext);

        // Record what we put in the header so the peer can match our rotation
        self.own_last_sent_key = Some(ratchet_pk);

        // Update direction
        self.last_direction = Direction::Send;

        // PQ ratchet advancement
        self.step()?;

        Ok(framed)
    }

    /// Decrypt with header framing and direction-aware key rotation.
    ///
    /// Parses `[peer_ratchet_key(32) | counter(8) | ciphertext]`.
    ///
    /// When the peer's ratchet key differs from the stored key, it indicates
    /// the peer performed a direction change and mixed `own_last_sent_key`
    /// (which the peer stored as their `peer_ratchet_key`). We perform the
    /// matching mix using our `own_last_sent_key` to derive the same chain keys.
    pub fn decrypt_with_header(&mut self, framed: &[u8]) -> Result<Vec<u8>> {
        if framed.len() < 40 {
            return Err(crate::error::CryptoError::Decryption(
                "framed message too short (need at least 40 bytes for header)".into(),
            ));
        }

        // Parse header
        let header_peer_key: [u8; 32] = framed[..32]
            .try_into()
            .map_err(|_| crate::error::CryptoError::Decryption("invalid header".into()))?;
        let ciphertext = &framed[40..];

        // Detect if the peer performed a direction change (new key in header)
        let need_key_rotation = match &self.peer_ratchet_key {
            Some(stored) if stored.len() == 32 => {
                // Use constant-time comparison (prevents timing side-channel)
                !ct_eq(stored, &header_peer_key)
            }
            None if self.last_direction == Direction::Send => {
                // First message from peer after we've been sending.
                // The peer changed from Receive to Send (direction change),
                // so they mixed our sent key. We need a matching rotation.
                true
            }
            _ => false,
        };

        if need_key_rotation {
            // The sender mixed their stored peer_ratchet_key, which is the
            // ratchet key WE included in our last outgoing header. We stored
            // this as own_last_sent_key. Mix the same value to derive matching
            // chain keys.
            if let Some(own_key) = self.own_last_sent_key {
                self.double_ratchet.mix_direction_change(&own_key);
            }
        }

        // Decrypt using current recv chain
        let plaintext = self.double_ratchet.decrypt_message(ciphertext)?;

        // Store new peer key and update direction
        self.last_direction = Direction::Receive;
        self.peer_ratchet_key = Some(header_peer_key.to_vec());

        // PQ ratchet advancement
        self.step()?;

        Ok(plaintext)
    }

    /// Get the last message direction
    pub fn last_direction(&self) -> Direction {
        self.last_direction
    }

    /// Get the peer's last known ratchet public key
    pub fn peer_ratchet_key(&self) -> Option<&[u8]> {
        self.peer_ratchet_key.as_deref()
    }

    /// Get the current DH ratchet public key
    pub fn ratchet_public_key(&self) -> [u8; 32] {
        self.double_ratchet.ratchet_public_key()
    }

    /// Perform a ratchet step, potentially emitting a PQ rekey public key.
    ///
    /// Returns `Some(public_key)` when a sparse-PQ rekey boundary was reached:
    /// the caller must transmit that key to the peer, who answers with a
    /// ciphertext to feed into `process_pq_ciphertext`.
    ///
    /// ATK-4-4: only a *completed* KEM exchange secret (drained from the
    /// sparse ratchet) is mixed into the double ratchet's root key; emitting
    /// a keypair no longer re-mixes the original shared secret.
    ///
    /// Phase 5 item 3: every completed-exchange secret waiting is drained here,
    /// OLDEST CHAIN EPOCH FIRST. The sparse ratchet holds them in production
    /// order, so a caller that is a boundary late applies the same sequence of
    /// mixes as its peer instead of dropping the older secret — the drain order
    /// is derived from each secret's epoch tag, not from the caller's timing.
    pub fn step_pq(&mut self) -> Result<Option<PublicKey>> {
        let pk = self.sparse_pq_ratchet.step()?;
        while let Some(mut pq_secret) = self.sparse_pq_ratchet.take_pending_mix() {
            // Fresh PQ secret from a completed ML-KEM exchange.
            self.double_ratchet.mix_pq_secret(&pq_secret);
            pq_secret.zeroize();
        }
        Ok(pk)
    }

    /// Perform ratchet step (compatibility entry point for the chat path).
    ///
    /// Any PQ rekey public key is discarded — use `step_pq` when the
    /// transport can transmit it.
    ///
    /// Discarding it is only safe because the keypair is retired with it
    /// ([`TripleRatchet::abandon_rekey_key`]): no ciphertext can ever arrive for
    /// a public key that was never transmitted, and a keypair left in the
    /// retention queue would shift every later ciphertext onto the wrong key
    /// (see `SparsePqRatchet::process_ciphertext`). Callers that *can* transmit
    /// must use `step_pq` and either send the key or retire it.
    pub fn step(&mut self) -> Result<()> {
        if let Some(discarded) = self.step_pq()? {
            self.abandon_rekey_key(&discarded);
        }
        Ok(())
    }

    /// Owner side of a sparse PQ exchange: process the peer's ML-KEM
    /// ciphertext for the pending rekey. The decapsulated secret is mixed
    /// into the sparse chain and drained into the root key on the next
    /// `step()` / `step_pq()` call.
    pub fn process_pq_ciphertext(&mut self, ct: &Ciphertext) -> Result<()> {
        self.sparse_pq_ratchet.process_ciphertext(ct)
    }

    /// Peer side of a sparse PQ exchange: encapsulate against the public key
    /// received from the rekey owner. Returns the ciphertext to transmit
    /// back; the shared secret is drained into the root key on the next
    /// `step()` / `step_pq()` call.
    pub fn encapsulate_pq(&mut self, pk: &PublicKey) -> Result<Ciphertext> {
        self.sparse_pq_ratchet.encapsulate_to(pk)
    }

    /// Get the double ratchet reference
    pub fn double_ratchet(&self) -> &DoubleRatchet {
        &self.double_ratchet
    }

    /// Get the sparse PQ ratchet reference
    pub fn sparse_pq_ratchet(&self) -> &SparsePqRatchet {
        &self.sparse_pq_ratchet
    }

    /// Check whether the PQ ratchet has actually been exercised.
    ///
    /// ATK-4-4: previously hardcoded `true`. Reports reality instead: `true`
    /// only after a completed ML-KEM exchange mixed a fresh secret into the
    /// chain. The current chat path does not transmit PQ keys/ciphertext, so
    /// it reports `false` there and no PQ forward secrecy may be claimed.
    pub fn is_pq_active(&self) -> bool {
        self.sparse_pq_ratchet.pq_established()
    }

    /// Completed-exchange PQ secrets still waiting to be mixed into the root key.
    ///
    /// A non-zero value after `step_pq` means a secret arrived after this
    /// boundary's drain; the queue holds it (in epoch order) for the next one.
    pub fn pending_pq_mixes(&self) -> usize {
        self.sparse_pq_ratchet.pending_mix_count()
    }

    /// The chain epoch of the oldest pending PQ mix, if one is waiting.
    pub fn pending_pq_mix_epoch(&self) -> Option<u64> {
        self.sparse_pq_ratchet.pending_mix_epoch()
    }

    /// Completed-exchange PQ secrets DROPPED because the pending queue was full.
    ///
    /// Phase 5 item 3: this is the honest signal that the two root keys no longer
    /// carry the same mix sequence. It must be zero for a session whose PQ forward
    /// secrecy is claimed; a non-zero value means the session diverged and the
    /// caller must not claim PQ for it.
    pub fn dropped_pq_mixes(&self) -> u64 {
        self.sparse_pq_ratchet.dropped_pending_mixes()
    }

    /// Rekey keypairs this session is still holding for their ciphertext.
    ///
    /// The owner emits a rekey public key at every boundary and keeps the
    /// keypair until the matching ciphertext comes back, so more than one can be
    /// outstanding at a time (a rekey exchange is a round trip). `step_pq`'s
    /// returned key is the NEWEST of these; `oldest_outstanding_rekey_key` is
    /// the one a returning ciphertext belongs to.
    pub fn retained_rekey_keypairs(&self) -> usize {
        self.sparse_pq_ratchet.retained_keypair_count()
    }

    /// The public key of the OLDEST outstanding rekey keypair, if any — the one
    /// a returning ciphertext is expected to be for.
    pub fn oldest_outstanding_rekey_key(&self) -> Option<&PublicKey> {
        self.sparse_pq_ratchet.oldest_outstanding_rekey_key()
    }

    /// Retire the keypair for a rekey public key that was never transmitted.
    ///
    /// Call this when a rekey public key handed out by `step_pq` cannot be sent
    /// after all (its outgoing record was superseded before the next send). No
    /// ciphertext can arrive for a key that never left, and a keypair left in
    /// the retention queue would shift every later ciphertext onto the wrong
    /// key. Returns whether a keypair was retired.
    pub fn abandon_rekey_key(&mut self, pk: &PublicKey) -> bool {
        self.sparse_pq_ratchet.abandon_rekey_key(pk)
    }

    /// Rekey keypairs retired because their public key never reached the peer.
    pub fn abandoned_rekeys(&self) -> u64 {
        self.sparse_pq_ratchet.abandoned_rekeys()
    }

    /// Rekey keypairs discarded because the retention bound was reached.
    ///
    /// Non-zero means an opened exchange can no longer be completed, so the mix
    /// sequence cannot be symmetric with the peer's and PQ forward secrecy must
    /// not be claimed for the session.
    pub fn dropped_rekey_keypairs(&self) -> u64 {
        self.sparse_pq_ratchet.dropped_keypairs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triple_ratchet_basic() {
        let shared_secret = [42u8; 32];
        let mut sender = TripleRatchet::init(&shared_secret, 10);
        let mut receiver = TripleRatchet::init_responder(&shared_secret, 10);

        let ct = sender.encrypt_message(b"hello").unwrap();
        let pt = receiver.decrypt_message(&ct).unwrap();

        assert_eq!(pt, b"hello");
    }

    #[test]
    fn test_triple_ratchet_pq_mixing() {
        let shared_secret = [42u8; 32];
        let mut ratchet = TripleRatchet::init(&shared_secret, 2);

        // Step 1: no PQ rekey
        ratchet.step().unwrap();

        // Step 2: PQ rekey should occur (interval = 2)
        ratchet.step().unwrap();

        // Verify the ratchet still works after PQ mixing
        let ct = ratchet.encrypt_message(b"after pq rekey").unwrap();
        assert!(!ct.is_empty());
    }

    // --- Direction tracking tests ---

    #[test]
    fn test_direction_tracking() {
        // Test 1: After encrypt, last_direction is Send; after decrypt, Receive
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 100);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 100);

        assert_eq!(alice.last_direction(), Direction::None);
        assert_eq!(bob.last_direction(), Direction::None);

        let framed = alice.encrypt_with_header(b"hello").unwrap();
        assert_eq!(alice.last_direction(), Direction::Send);

        let _pt = bob.decrypt_with_header(&framed).unwrap();
        assert_eq!(bob.last_direction(), Direction::Receive);
    }

    #[test]
    fn test_dh_auto_step_on_direction_change() {
        // Test 2: DH auto-step triggers on direction change
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 100);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 100);

        // Alice sends msg1
        let framed1 = alice.encrypt_with_header(b"msg1 from alice").unwrap();
        let pt1 = bob.decrypt_with_header(&framed1).unwrap();
        assert_eq!(pt1, b"msg1 from alice");

        // Bob sends msg2 (direction change Recv -> Send triggers key rotation)
        let framed2 = bob.encrypt_with_header(b"msg2 from bob").unwrap();
        let pt2 = alice.decrypt_with_header(&framed2).unwrap();
        assert_eq!(pt2, b"msg2 from bob");
    }

    #[test]
    fn test_no_dh_step_same_direction() {
        // Test 3: No DH step when direction unchanged
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 100);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 100);

        // Alice sends two consecutive messages (same direction)
        let framed1 = alice.encrypt_with_header(b"msg1").unwrap();
        let pt1 = bob.decrypt_with_header(&framed1).unwrap();
        assert_eq!(pt1, b"msg1");

        let framed2 = alice.encrypt_with_header(b"msg2").unwrap();
        let pt2 = bob.decrypt_with_header(&framed2).unwrap();
        assert_eq!(pt2, b"msg2");

        assert_eq!(alice.last_direction(), Direction::Send);
        assert_eq!(bob.last_direction(), Direction::Receive);
    }

    #[test]
    fn test_bidirectional_multi_direction_changes() {
        // Test 4: Bidirectional with multiple direction changes
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 100);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 100);

        // Alice sends 3 messages
        for i in 0..3 {
            let msg = format!("alice msg {}", i);
            let framed = alice.encrypt_with_header(msg.as_bytes()).unwrap();
            let pt = bob.decrypt_with_header(&framed).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // Bob sends 2 messages (direction change)
        for i in 0..2 {
            let msg = format!("bob msg {}", i);
            let framed = bob.encrypt_with_header(msg.as_bytes()).unwrap();
            let pt = alice.decrypt_with_header(&framed).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // Alice sends 1 more (another direction change)
        let framed = alice.encrypt_with_header(b"alice final").unwrap();
        let pt = bob.decrypt_with_header(&framed).unwrap();
        assert_eq!(pt, b"alice final");
    }

    #[test]
    fn test_pq_rekey_with_direction_changes() {
        // Test 5: PQ rekey works after DH auto-step
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 5);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 5);

        for i in 0..20 {
            if i % 3 == 0 {
                let msg = format!("alice {}", i);
                let framed = alice.encrypt_with_header(msg.as_bytes()).unwrap();
                let pt = bob.decrypt_with_header(&framed).unwrap();
                assert_eq!(pt, msg.as_bytes());
            } else {
                let msg = format!("bob {}", i);
                let framed = bob.encrypt_with_header(msg.as_bytes()).unwrap();
                let pt = alice.decrypt_with_header(&framed).unwrap();
                assert_eq!(pt, msg.as_bytes());
            }
        }
    }

    #[test]
    fn test_serialization_preserves_direction() {
        // Test 6: Serialization roundtrip preserves direction state
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 100);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 100);

        // Alice sends a message
        let framed1 = alice.encrypt_with_header(b"before export").unwrap();
        let pt1 = bob.decrypt_with_header(&framed1).unwrap();
        assert_eq!(pt1, b"before export");

        // Export Alice state
        let alice_bytes = bincode::serialize(&alice).unwrap();
        let mut alice_restored: TripleRatchet = bincode::deserialize(&alice_bytes).unwrap();

        // Verify direction and key preserved
        assert_eq!(alice_restored.last_direction(), Direction::Send);
        assert!(alice_restored.own_last_sent_key.is_some());

        // Bob sends (direction change)
        let framed2 = bob.encrypt_with_header(b"reply from bob").unwrap();
        let pt2 = alice_restored.decrypt_with_header(&framed2).unwrap();
        assert_eq!(pt2, b"reply from bob");

        // Alice can send again
        let framed3 = alice_restored
            .encrypt_with_header(b"after restore")
            .unwrap();
        let pt3 = bob.decrypt_with_header(&framed3).unwrap();
        assert_eq!(pt3, b"after restore");
    }

    // --- ATK-4-4 / T-202: sparse PQ ratchet honesty + exchange tests ---

    #[test]
    fn test_pq_ratchet_not_active_until_exchange_completes() {
        let shared_secret = [42u8; 32];
        let mut alice = TripleRatchet::init(&shared_secret, 1);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 1);

        // No PQ exchange has run: not active. Stepping alone must not fake PQ
        // activity (the old code re-mixed the original secret here).
        assert!(!alice.is_pq_active());
        alice.step().unwrap();
        assert!(!alice.is_pq_active());

        // Complete a real exchange: Bob encapsulates to Alice's rekey key.
        let pk = alice.step_pq().unwrap().expect("rekey at interval 1");
        bob.step_pq().unwrap();
        let ct = bob.encapsulate_pq(&pk).unwrap();
        alice.process_pq_ciphertext(&ct).unwrap();
        assert!(alice.is_pq_active());
        assert!(bob.is_pq_active());

        // Session keeps working across the PQ mix on both sides.
        let c1 = alice.encrypt_message(b"before mix").unwrap();
        assert_eq!(bob.decrypt_message(&c1).unwrap(), b"before mix");
        alice.step().unwrap(); // drains Alice's PQ secret into the root key
        bob.step().unwrap(); // drains Bob's PQ secret into the root key

        let c2 = alice.encrypt_message(b"after mix").unwrap();
        assert_eq!(bob.decrypt_message(&c2).unwrap(), b"after mix");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pq_skipped_step_desynchronizes_wired_exchange() {
        // T-203 wiring discipline: the KEM secret only lands on the same
        // sparse-chain state on both peers while the chains advance in
        // lockstep (one step per message boundary). Skipping a chain step —
        // the class of bug the transport wiring must not introduce — leaves
        // the chains desynchronized even once step counts are level again,
        // because the shared secret mixes in at a different chain depth.
        let shared_secret = [7u8; 32];
        let mut owner = TripleRatchet::init(&shared_secret, 1);
        let mut peer = TripleRatchet::init_responder(&shared_secret, 1);

        // Owner hits the rekey boundary and advances its chain once.
        let pk = owner.step_pq().unwrap().expect("rekey at interval 1");

        // Peer skips its chain step and encapsulates from the un-advanced
        // state (depth 0); the owner mixes the same secret one step deeper.
        let ct = peer.encapsulate_pq(&pk).unwrap();
        owner.process_pq_ciphertext(&ct).unwrap();

        // Drain the completed exchange on both sides...
        owner.step_pq().unwrap();
        peer.step_pq().unwrap();
        // ...then bring the step counts back in line so any divergence
        // cannot be blamed on a count offset alone.
        peer.step_pq().unwrap();

        assert_ne!(
            owner.sparse_pq_ratchet().current_secret(),
            peer.sparse_pq_ratchet().current_secret(),
            "a skipped chain step must leave the sparse chains desynchronized"
        );
        // Both sides still report the exchange as completed: the desync is
        // silent at the establishment-flag level, which is exactly why the
        // wiring (not just the flag) must preserve the lockstep drain order.
        assert!(owner.is_pq_active());
        assert!(peer.is_pq_active());
    }

    /// Phase 5 item 3 — the one-message drain skew, reproduced.
    ///
    /// Two ML-KEM exchanges complete; the owner drains after each one, the peer
    /// is a boundary behind and drains late, once. Correct behaviour: the peer
    /// applies BOTH completed secrets, in the order they completed, so its root
    /// key converges with the owner's and a message sent after the skew still
    /// decrypts.
    ///
    /// This is the caller-contract hazard the card names: `take_pending_mix`
    /// kept ONE slot, so the second exchange overwrote the peer's undrained
    /// first secret with no error and no signal, and the two root keys never
    /// converged again.
    ///
    /// Boundary advances that emit a rekey key the caller does NOT transmit go
    /// through `step()` (which retires that keypair) rather than `step_pq()`:
    /// a key that never left can never be answered, and a keypair left in the
    /// retention queue would shift the pairing of every later ciphertext —
    /// `SparsePqRatchet::process_ciphertext` documents why the queue cannot know
    /// the difference on its own.
    #[test]
    fn test_drain_skew_must_not_lose_a_completed_mix() {
        let shared = [0x5Au8; 32];
        let mut owner = TripleRatchet::init(&shared, 1);
        let mut peer = TripleRatchet::init_responder(&shared, 1);

        // Exchange 1: the owner rekeys, the peer answers.
        let pk1 = owner.step_pq().unwrap().expect("owner rekey 1");
        peer.step().unwrap(); // peer advances once (lockstep; nothing transmitted)
        let ct1 = peer.encapsulate_pq(&pk1).unwrap(); // peer: pending mix #1
        owner.process_pq_ciphertext(&ct1).unwrap(); // owner: pending mix #1
        owner.step().unwrap(); // owner drains #1

        // Exchange 2 completes on the peer BEFORE it has drained anything.
        let pk2 = owner.step_pq().unwrap().expect("owner rekey 2");
        let ct2 = peer.encapsulate_pq(&pk2).unwrap(); // peer: pending mix #2
        owner.process_pq_ciphertext(&ct2).unwrap(); // owner: pending mix #2
        owner.step().unwrap(); // owner drains #2

        // The peer finally drains — a boundary late.
        peer.step().unwrap();

        // Both completed secrets were carried, none was dropped, and the queue
        // is empty after the drain.
        assert_eq!(peer.pending_pq_mixes(), 0, "the backlog must be drained");
        assert_eq!(
            peer.dropped_pq_mixes(),
            0,
            "no completed mix may be dropped"
        );
        assert_eq!(owner.dropped_pq_mixes(), 0);

        // Convergence: a message sent after the skew still decrypts on the peer.
        let ct = owner.encrypt_message(b"after the skewed drain").unwrap();
        assert_eq!(
            peer.decrypt_message(&ct)
                .expect("the peer must have applied both completed mixes, in order"),
            b"after the skewed drain"
        );
    }

    /// The recovery property through the TripleRatchet, with a completed PQ mix
    /// already in the root key: a frame the relay drops costs that frame, and
    /// the frames after it still decrypt.
    #[test]
    fn test_dropped_frame_recovers_across_a_pq_mix() {
        let shared = [0x3Cu8; 32];
        let mut alice = TripleRatchet::init(&shared, 1);
        let mut bob = TripleRatchet::init_responder(&shared, 1);

        // Complete one ML-KEM exchange so the root key carries a real PQ mix
        // before the disturbance — recovery must survive the chain-key change.
        let pk = alice.step_pq().unwrap().expect("alice rekeys at interval 1");
        bob.step_pq().unwrap();
        let ct = bob.encapsulate_pq(&pk).unwrap();
        alice.process_pq_ciphertext(&ct).unwrap();
        alice.step_pq().unwrap(); // drain alice's secret into the root key
        bob.step_pq().unwrap(); // drain bob's
        assert!(alice.is_pq_active() && bob.is_pq_active());

        // Three frames from alice at positions 0, 1, 2 — the middle one is
        // dropped in flight.
        let c0 = alice.encrypt_message(b"before").unwrap();
        let c1 = alice.encrypt_message(b"dropped").unwrap();
        let c2 = alice.encrypt_message(b"after").unwrap();

        assert_eq!(bob.decrypt_message_labeled(&c0, 0).unwrap(), b"before");
        assert_eq!(
            bob.decrypt_message_labeled(&c2, 2).unwrap(),
            b"after",
            "the direction must survive a dropped frame"
        );
        // The dropped frame is still placeable if it turns up late: its key was
        // cached when the gap was stepped over.
        assert_eq!(bob.decrypt_message_labeled(&c1, 1).unwrap(), b"dropped");

        // And the conversation continues from there.
        let c3 = alice.encrypt_message(b"still alive").unwrap();
        assert_eq!(bob.decrypt_message_labeled(&c3, 3).unwrap(), b"still alive");

        // The label a transport must put on the frame is the ratchet's own
        // position, not a counter of the transport's own choosing.
        assert_eq!(alice.send_sequence(), 4);
        assert_eq!(bob.recv_sequence(), 4);
    }

    #[test]
    fn test_same_role_composition_cannot_communicate() {
        // Why this test exists: the web app derived the ratchet role from the
        // parity of the SHARED session key, so both peers constructed the same
        // role and every chat message was rejected by its recipient (Phase 37
        // defect, 2026-10-07). Every other test in this file deliberately pairs
        // `init` with `init_responder` — the same-role case, which is the one
        // the app actually built, was never exercised.
        //
        // The contract this locks: the role CANNOT come from the shared secret
        // (it is symmetric — identical on both peers), so it must come from the
        // handshake.
        let shared_secret = [9u8; 32];

        // Same role on both sides: encryption succeeds, decryption must not.
        let mut alice = TripleRatchet::init(&shared_secret, 100);
        let mut mallory = TripleRatchet::init(&shared_secret, 100);
        let ct = alice.encrypt_message(b"same role").unwrap();
        assert!(
            mallory.decrypt_message(&ct).is_err(),
            "two initiators sharing a secret must NOT be able to decrypt each \
             other — if this ever passes, the role is no longer load-bearing"
        );

        // The control: the same secret with opposite roles works, so the failure
        // above is attributable to the role and not to the secret. Fresh pair —
        // reusing `alice` here would desync the control, since its send chain
        // already advanced.
        let mut carol = TripleRatchet::init(&shared_secret, 100);
        let mut bob = TripleRatchet::init_responder(&shared_secret, 100);
        let ct2 = carol.encrypt_message(b"opposite roles").unwrap();
        assert_eq!(bob.decrypt_message(&ct2).unwrap(), b"opposite roles");
    }
}
