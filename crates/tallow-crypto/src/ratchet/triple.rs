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
    pub fn step_pq(&mut self) -> Result<Option<PublicKey>> {
        let pk = self.sparse_pq_ratchet.step()?;
        if let Some(mut pq_secret) = self.sparse_pq_ratchet.take_pending_mix() {
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
    pub fn step(&mut self) -> Result<()> {
        self.step_pq()?;
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
