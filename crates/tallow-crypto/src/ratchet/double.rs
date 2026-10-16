//! Double Ratchet protocol (Signal-style) with out-of-order message support

use crate::error::{CryptoError, Result};
use crate::hash::{blake3, domain};
use crate::kem::x25519::X25519KeyPair;
use crate::symmetric::{chacha_decrypt, chacha_encrypt};

use std::collections::HashMap;
use zeroize::Zeroize;

/// Maximum number of skipped message keys to cache
const MAX_SKIP: u64 = 1000;

/// Double Ratchet state
///
/// Not Clone — ratchet state must never be duplicated. Duplication would
/// produce identical nonce sequences, causing catastrophic AES-GCM nonce reuse.
/// Serialize/Deserialize is needed for WASM session persistence (encrypted IndexedDB)
/// but the serialized bytes MUST be encrypted by the caller.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DoubleRatchet {
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
    /// Whether this ratchet was initialized as the responder.
    /// Required for role-aware chain key derivation in mix_pq_secret().
    is_responder: bool,
    ephemeral_keypair: X25519KeyPair,
    /// Cache of skipped message keys for out-of-order delivery
    /// Key: (DH ratchet public key bytes, message number) → message key
    skipped_keys: HashMap<(Vec<u8>, u64), [u8; 32]>,
}

impl Zeroize for DoubleRatchet {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.send_chain_key.zeroize();
        self.recv_chain_key.zeroize();
        self.send_counter.zeroize();
        self.recv_counter.zeroize();
        // Zeroize all cached skipped keys
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
        self.skipped_keys.clear();
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DoubleRatchet {
    /// Initialize a new double ratchet as the initiator
    pub fn init(shared_secret: &[u8; 32]) -> Self {
        Self::init_with_role(shared_secret, false)
    }

    /// Initialize a new double ratchet as the responder
    ///
    /// The responder swaps send/recv chain keys relative to the initiator,
    /// so the initiator's send chain matches the responder's recv chain.
    pub fn init_responder(shared_secret: &[u8; 32]) -> Self {
        Self::init_with_role(shared_secret, true)
    }

    /// Initialize with a specific role (swap chain keys for responder)
    fn init_with_role(shared_secret: &[u8; 32], is_responder: bool) -> Self {
        let ephemeral_keypair = X25519KeyPair::generate();

        let chain_a = blake3::derive_key(domain::DOMAIN_RATCHET_SEND_CHAIN, shared_secret);
        let chain_b = blake3::derive_key(domain::DOMAIN_RATCHET_RECV_CHAIN, shared_secret);

        let (send_chain_key, recv_chain_key) = if is_responder {
            (chain_b, chain_a)
        } else {
            (chain_a, chain_b)
        };

        // Domain-separated root key derivation — never use raw shared secret
        let root_key = blake3::derive_key("tallow-ratchet-root-v1", shared_secret);

        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_counter: 0,
            recv_counter: 0,
            is_responder,
            ephemeral_keypair,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a message
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Derive message key from chain key
        let message_key = blake3::derive_key("message", &self.send_chain_key);

        // Advance chain key
        self.send_chain_key = blake3::derive_key("chain_advance", &self.send_chain_key);

        // Encrypt with nonce = counter
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.send_counter.to_le_bytes());

        let ciphertext = chacha_encrypt(&message_key, &nonce, plaintext, &[])?;

        self.send_counter = self.send_counter.checked_add(1).ok_or_else(|| {
            CryptoError::Encryption("send counter overflow — session must be re-established".into())
        })?;

        Ok(ciphertext)
    }

    /// Decrypt a message, with support for out-of-order delivery
    ///
    /// If the message counter is ahead of the current receive counter,
    /// intermediate message keys are cached for later decryption.
    ///
    /// This entry point is POSITIONAL: the message number is whatever this side
    /// expects next, because the caller has no number of its own to offer. A
    /// frame that arrives after a gap therefore cannot be placed, and is
    /// refused — with the receive state left untouched (see
    /// [`Self::decrypt_message_at`]), but still refused. Use
    /// [`Self::decrypt_message_labeled`] when the frame carries the sender's own
    /// position.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_message_at(ciphertext, self.recv_counter)
    }

    /// Decrypt the frame the sender LABELLED with `declared`.
    ///
    /// `declared` is the position the sender says it used for this frame (on
    /// the v9 chat wire that is `ChatTextV9.sequence`). The label is NOT
    /// authenticated — it is a key-selection hint and nothing else — and the
    /// AEAD decides whether it was right, because key and nonce are both
    /// functions of the position. Two attempts are made, in this order:
    ///
    /// 1. the declared position — what a labelling peer needs. This is what
    ///    makes a frame that arrives AFTER A GAP (a frame the relay dropped, or
    ///    two frames it swapped) decrypt at its own position via the skipped-key
    ///    cache, instead of leaving the receive direction unusable;
    /// 2. this side's own positional expectation, `recv_counter` — what a peer
    ///    that does not label its frames needs, so a receiver that adopts this
    ///    entry point does not refuse an honest unlabelled peer.
    ///
    /// Acceptance always means the frame authenticated AT THE POSITION USED, so
    /// neither attempt can accept a frame the peer did not produce at that
    /// position: a forgery or a replay fails both. The worst a lying label can
    /// do is cost a refusal — which any mutation of the frame costs anyway.
    pub fn decrypt_message_labeled(&mut self, ciphertext: &[u8], declared: u64) -> Result<Vec<u8>> {
        let first_err = match self.decrypt_message_at(ciphertext, declared) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => e,
        };

        // A peer that does not label its frames: tried at the position we
        // expect. Skipped when the declared position already WAS that one.
        let positional = self.recv_counter;
        if declared == positional {
            return Err(first_err);
        }
        match self.decrypt_message_at(ciphertext, positional) {
            Ok(plaintext) => Ok(plaintext),
            // Both attempts refused: report the first one (the sender's own
            // claim), so the caller sees why the frame as labelled did not fit.
            Err(_) => Err(first_err),
        }
    }

    /// Decrypt a message with an explicit message number
    ///
    /// Supports out-of-order delivery by checking the skipped keys cache.
    ///
    /// A refused frame is a NO-OP on receive state: nothing is committed until
    /// the frame authenticates. Concretely, the chain key and the counter are
    /// only moved, and skipped keys are only cached, after the AEAD call for
    /// this frame has returned `Ok`. A frame that fails to authenticate — a
    /// forgery, a bit-flipped frame, or one the caller placed wrongly — costs
    /// itself and nothing else.
    ///
    /// (The previous shape advanced `recv_chain_key` BEFORE the AEAD call and
    /// returned on the error before advancing `recv_counter`, leaving the chain
    /// key one step ahead of the counter forever: every later frame in that
    /// direction was keyed one step ahead of its own nonce and was refused too.
    /// One refused frame killed the direction — see the `refusal_is_a_noop`
    /// tests.)
    ///
    /// A position BELOW the receive counter with no cached key is refused as an
    /// ordering violation (the frame was already consumed, or is older than the
    /// skip window) rather than being decrypted against the wrong key.
    pub fn decrypt_message_at(&mut self, ciphertext: &[u8], message_num: u64) -> Result<Vec<u8>> {
        let dh_pub = self.ephemeral_keypair.public_bytes().to_vec();

        // A frame whose position is inside the skipped window: its key was
        // cached when the gap was stepped over. SINGLE USE — the entry is
        // consumed only when the frame authenticates, so a failed attempt
        // leaves the cache exactly as it was.
        if let Some(mut mk) = self
            .skipped_keys
            .get(&(dh_pub.clone(), message_num))
            .copied()
        {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&message_num.to_le_bytes());

            match chacha_decrypt(&mk, &nonce, ciphertext, &[]) {
                Ok(plaintext) => {
                    if let Some(mut consumed) =
                        self.skipped_keys.remove(&(dh_pub, message_num))
                    {
                        consumed.zeroize();
                    }
                    mk.zeroize();
                    return Ok(plaintext);
                }
                Err(e) => {
                    mk.zeroize();
                    return Err(e);
                }
            }
        }

        // Below the window, and no cached key for it: this position has been
        // passed and its key is gone. That is a replay of a consumed frame, or
        // a frame older than the skip window — an ordering refusal, not a
        // decryption attempt against a key that cannot be right.
        if message_num < self.recv_counter {
            return Err(CryptoError::Decryption(format!(
                "message number {} is below the receive counter {} and no skipped key is cached: \
                 the frame was already consumed or is older than the skip window",
                message_num, self.recv_counter
            )));
        }

        // Stepping over a gap: derive the keys of the positions crossed into a
        // STAGING list. Nothing is committed until this frame authenticates.
        let skip_count = message_num - self.recv_counter;
        if skip_count > MAX_SKIP {
            return Err(CryptoError::Decryption(format!(
                "Too many skipped messages: {} exceeds maximum of {}",
                skip_count, MAX_SKIP
            )));
        }

        let mut staged: Vec<(u64, [u8; 32])> = Vec::with_capacity(skip_count as usize);
        let mut chain = self.recv_chain_key;
        let mut position = self.recv_counter;
        while position < message_num {
            staged.push((position, blake3::derive_key("message", &chain)));
            chain = blake3::derive_key("chain_advance", &chain);
            position += 1;
        }
        let message_key = blake3::derive_key("message", &chain);

        // Decrypt with nonce = the position actually being attempted (this is
        // the message number, not "whatever the counter happens to be").
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&message_num.to_le_bytes());

        let plaintext = match chacha_decrypt(&message_key, &nonce, ciphertext, &[]) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                // Refused: every derived key is discarded and the receive state
                // is left exactly as it was.
                for (_, mut mk) in staged {
                    mk.zeroize();
                }
                chain.zeroize();
                return Err(e);
            }
        };

        // Commit — reached only by a frame that authenticated at this position.
        for (position, mk) in staged {
            self.skipped_keys.insert((dh_pub.clone(), position), mk);
        }
        let next_chain = blake3::derive_key("chain_advance", &chain);
        chain.zeroize();
        self.recv_chain_key = next_chain;
        self.recv_counter = message_num.checked_add(1).ok_or_else(|| {
            CryptoError::Decryption("recv counter overflow — session must be re-established".into())
        })?;

        // Prune oldest skipped keys if cache is too large
        self.prune_skipped_keys();

        Ok(plaintext)
    }

    /// The ratchet position this side will use for its NEXT outgoing frame.
    ///
    /// This is the number a transport must put in the frame's own sequence
    /// field so the peer can place it (see [`Self::decrypt_message_labeled`]).
    /// It is derived from the ratchet's own counter, deliberately: a caller's
    /// parallel counter and the ratchet's position can drift (a re-established
    /// session resets both, but only the ratchet's own counter cannot), and a
    /// label that is not the position is a label the peer cannot use.
    pub fn send_sequence(&self) -> u64 {
        self.send_counter
    }

    /// The ratchet position this side expects NEXT from the peer.
    ///
    /// With a labelling peer this is an expectation, not a verdict: a frame may
    /// legitimately arrive at a LATER position (a gap is stepped over) or at an
    /// earlier cached one. It is what a caller asserts on when it needs to show
    /// that a refusal moved nothing — see [`Self::decrypt_message_at`].
    pub fn recv_sequence(&self) -> u64 {
        self.recv_counter
    }

    /// Get the current DH ratchet public key bytes.
    ///
    /// Used by the TripleRatchet to include in message headers so the peer
    /// can detect when a DH ratchet step is needed.
    pub fn ratchet_public_key(&self) -> [u8; 32] {
        self.ephemeral_keypair.public_bytes()
    }

    /// Perform DH ratchet step from raw public key bytes.
    ///
    /// Convenience wrapper around `ratchet_step` that accepts `&[u8; 32]`.
    pub fn ratchet_step_from_bytes(&mut self, their_public_bytes: &[u8; 32]) -> Result<()> {
        let their_public = x25519_dalek::PublicKey::from(*their_public_bytes);
        self.ratchet_step(&their_public)
    }

    /// Perform DH ratchet step
    ///
    /// # Errors
    ///
    /// Returns an error if the peer's public key is a low-order point.
    pub fn ratchet_step(&mut self, their_public: &x25519_dalek::PublicKey) -> Result<()> {
        let dh_output = self.ephemeral_keypair.diffie_hellman(their_public)?;

        // KDF with root key and DH output
        let mut input = Vec::new();
        input.extend_from_slice(&self.root_key);
        input.extend_from_slice(&dh_output.0);

        self.root_key = blake3::derive_key("root", &input);
        self.send_chain_key = blake3::derive_key(domain::DOMAIN_RATCHET_SEND_CHAIN, &self.root_key);
        self.recv_chain_key = blake3::derive_key(domain::DOMAIN_RATCHET_RECV_CHAIN, &self.root_key);

        // Zeroize temporary key material
        input.zeroize();

        // Reset counters for new ratchet epoch.
        // SAFETY: Counter reset to 0 is safe because new chain keys were derived
        // above — the same nonce value with a different encryption key does not
        // constitute nonce reuse. Each ratchet epoch uses fresh chain-derived
        // message keys, so counter=0 in epoch N never collides with counter=0
        // in epoch N-1.
        self.send_counter = 0;
        self.recv_counter = 0;

        // Generate new ephemeral keypair
        self.ephemeral_keypair = X25519KeyPair::generate();

        Ok(())
    }

    /// Mix a post-quantum shared secret into the root key via HKDF
    ///
    /// Called by TripleRatchet when the sparse PQ ratchet produces a new secret.
    /// Uses role-aware chain key derivation so initiator's send_chain matches
    /// responder's recv_chain (and vice versa) after PQ re-keying.
    pub fn mix_pq_secret(&mut self, pq_secret: &[u8; 32]) {
        // HKDF: new_root = KDF(salt=root_key, ikm=pq_secret, info="pq_rekey")
        let mut input = Vec::new();
        input.extend_from_slice(&self.root_key);
        input.extend_from_slice(pq_secret);

        self.root_key = blake3::derive_key("pq_rekey", &input);

        // Derive new chain keys with role-aware swap (same logic as init_with_role)
        let chain_a = blake3::derive_key(domain::DOMAIN_RATCHET_SEND_CHAIN, &self.root_key);
        let chain_b = blake3::derive_key(domain::DOMAIN_RATCHET_RECV_CHAIN, &self.root_key);

        if self.is_responder {
            self.send_chain_key = chain_b;
            self.recv_chain_key = chain_a;
        } else {
            self.send_chain_key = chain_a;
            self.recv_chain_key = chain_b;
        }

        // Zeroize temporary key material
        input.zeroize();
    }

    /// Mix a direction-change secret into the root key for forward secrecy.
    ///
    /// Called by TripleRatchet on direction change. Both sides call this with
    /// the SAME `direction_entropy` (the peer's ratchet public key from the header)
    /// so they derive matching chain keys.
    ///
    /// Uses role-aware chain key derivation so initiator's send_chain matches
    /// responder's recv_chain after the mix.
    pub fn mix_direction_change(&mut self, direction_entropy: &[u8; 32]) {
        let mut input = Vec::new();
        input.extend_from_slice(&self.root_key);
        input.extend_from_slice(direction_entropy);

        self.root_key = blake3::derive_key("direction_change", &input);

        // Derive new chain keys with role-aware swap
        let chain_a = blake3::derive_key(domain::DOMAIN_RATCHET_SEND_CHAIN, &self.root_key);
        let chain_b = blake3::derive_key(domain::DOMAIN_RATCHET_RECV_CHAIN, &self.root_key);

        if self.is_responder {
            self.send_chain_key = chain_b;
            self.recv_chain_key = chain_a;
        } else {
            self.send_chain_key = chain_a;
            self.recv_chain_key = chain_b;
        }

        // Reset counters for new epoch
        self.send_counter = 0;
        self.recv_counter = 0;

        // Generate new ephemeral keypair for post-compromise security
        self.ephemeral_keypair = X25519KeyPair::generate();

        // Zeroize temporary key material
        input.zeroize();
    }

    /// Prune skipped keys cache if it exceeds twice the max skip limit
    fn prune_skipped_keys(&mut self) {
        if self.skipped_keys.len() > (MAX_SKIP as usize * 2) {
            // Remove oldest entries (by lowest message number)
            let mut entries: Vec<_> = self.skipped_keys.keys().cloned().collect();
            entries.sort_by_key(|(_pk, num)| *num);

            let remove_count = self.skipped_keys.len() - MAX_SKIP as usize;
            for key in entries.into_iter().take(remove_count) {
                if let Some(mut mk) = self.skipped_keys.remove(&key) {
                    mk.zeroize();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_ratchet_basic() {
        let shared_secret = [42u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct = sender.encrypt_message(b"hello").unwrap();
        let pt = receiver.decrypt_message(&ct).unwrap();

        assert_eq!(pt, b"hello");
    }

    #[test]
    fn test_double_ratchet_multiple_messages() {
        let shared_secret = [42u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        for i in 0..10 {
            let msg = format!("message {}", i);
            let ct = sender.encrypt_message(msg.as_bytes()).unwrap();
            let pt = receiver.decrypt_message(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_double_ratchet_out_of_order() {
        let shared_secret = [42u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        // Encrypt 4 messages
        let ct0 = sender.encrypt_message(b"msg0").unwrap();
        let ct1 = sender.encrypt_message(b"msg1").unwrap();
        let ct2 = sender.encrypt_message(b"msg2").unwrap();
        let ct3 = sender.encrypt_message(b"msg3").unwrap();

        // Decrypt in order: 0, 2, 1, 3
        let pt0 = receiver.decrypt_message_at(&ct0, 0).unwrap();
        assert_eq!(pt0, b"msg0");

        let pt2 = receiver.decrypt_message_at(&ct2, 2).unwrap();
        assert_eq!(pt2, b"msg2");

        let pt1 = receiver.decrypt_message_at(&ct1, 1).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt3 = receiver.decrypt_message_at(&ct3, 3).unwrap();
        assert_eq!(pt3, b"msg3");
    }

    #[test]
    fn test_double_ratchet_max_skip_exceeded() {
        let shared_secret = [42u8; 32];
        let mut receiver = DoubleRatchet::init(&shared_secret);

        // Try to skip more than MAX_SKIP
        let result = receiver.decrypt_message_at(&[0u8; 32], MAX_SKIP + 1);
        assert!(result.is_err());
        assert_eq!(
            receiver.recv_sequence(),
            0,
            "a refused frame must not move the window, not even for a too-far skip"
        );
    }

    // --- Phase 5 follow-up: one refused frame must not kill the direction ---

    /// The measurement the card was filed on, at the ratchet: a frame that fails
    /// to authenticate used to leave the chain key one step ahead of the
    /// counter, and every later frame in that direction was refused too.
    ///
    /// The contract now: a refusal moves NOTHING, and the frame that follows
    /// decrypts.
    #[test]
    fn test_refusal_is_a_noop_on_receive_state() {
        let shared_secret = [7u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct0 = sender.encrypt_message(b"alpha").unwrap();
        let ct1 = sender.encrypt_message(b"beta").unwrap();

        // The relay bit-flips the first frame.
        let mut corrupted = ct0.clone();
        corrupted[0] ^= 0x01;

        let before = receiver.recv_sequence();
        assert!(
            receiver.decrypt_message_labeled(&corrupted, 0).is_err(),
            "a corrupted frame must be refused"
        );
        assert_eq!(
            receiver.recv_sequence(),
            before,
            "a refused frame must leave the receive position exactly where it was"
        );

        // The undamaged frame at the same position still decrypts: the refusal
        // cost the corrupted frame and nothing else.
        assert_eq!(
            receiver.decrypt_message_labeled(&ct0, 0).unwrap(),
            b"alpha"
        );
        // ...and the direction continues.
        assert_eq!(receiver.decrypt_message_labeled(&ct1, 1).unwrap(), b"beta");
    }

    /// A frame that arrives AFTER A GAP decrypts at its own position.
    ///
    /// This is the property the positional path cannot have, and the reason the
    /// frame's own position has to be carried: the receiver cannot know it
    /// missed a frame. The contrast is asserted in the same test so the cost of
    /// choosing the positional path stays visible.
    #[test]
    fn test_frame_after_a_gap_decrypts_at_its_own_position() {
        let shared_secret = [8u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct0 = sender.encrypt_message(b"alpha").unwrap(); // dropped in flight
        let ct1 = sender.encrypt_message(b"beta").unwrap();
        let ct2 = sender.encrypt_message(b"gamma").unwrap();

        // Positional: the frame over the gap cannot be placed, and rollback
        // alone does not help — leaving the state untouched leaves the receiver
        // still expecting a frame that will never come.
        assert!(
            receiver.decrypt_message(&ct1).is_err(),
            "the positional path cannot place a frame that arrives after a gap"
        );
        assert_eq!(receiver.recv_sequence(), 0);
        assert!(
            receiver.decrypt_message(&ct2).is_err(),
            "and it stays unable to place the frames that follow — this is the \
             defect, measured: a dropped frame costs the DIRECTION"
        );

        // Labelled: the frame says where it belongs, so it decrypts, and the
        // direction survives. (ct1 is delivered once more here: the two
        // positional attempts above committed nothing.)
        assert_eq!(receiver.decrypt_message_labeled(&ct1, 1).unwrap(), b"beta");
        assert_eq!(receiver.decrypt_message_labeled(&ct2, 2).unwrap(), b"gamma");

        // And the frame that was never delivered is still placeable if it turns
        // up late: its key was cached when the gap was stepped over.
        assert_eq!(receiver.decrypt_message_labeled(&ct0, 0).unwrap(), b"alpha");
    }

    /// A replay of an already-consumed frame is refused as an ORDERING
    /// violation — the position is below the window and its key is gone — and
    /// the refusal names the rule rather than surfacing as a bare AEAD failure.
    #[test]
    fn test_replay_below_the_window_is_refused_as_an_ordering_violation() {
        let shared_secret = [9u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct0 = sender.encrypt_message(b"once").unwrap();
        assert_eq!(receiver.decrypt_message_labeled(&ct0, 0).unwrap(), b"once");
        assert_eq!(receiver.recv_sequence(), 1);

        let err = receiver
            .decrypt_message_labeled(&ct0, 0)
            .expect_err("the resent frame must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("below the receive counter"),
            "the refusal must credit the ordering rule: {msg}"
        );
        assert_eq!(
            receiver.recv_sequence(),
            1,
            "a refused replay must not move the receive position"
        );
    }

    /// A peer that does not label its frames at all still gets its traffic
    /// decrypted: the declared position is tried first, then this side's own
    /// positional expectation. Both are AEAD-checked, so the fallback cannot
    /// accept anything the peer did not produce at the position used.
    #[test]
    fn test_an_unlabelled_peers_frame_decrypts_positionally() {
        let shared_secret = [10u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct0 = sender.encrypt_message(b"no label").unwrap();
        // The peer claims a position it did not use — the shape a pre-label
        // peer presents when its label is a counter shared with another path.
        assert_eq!(
            receiver.decrypt_message_labeled(&ct0, 250).unwrap(),
            b"no label",
            "the positional fallback must still place it"
        );
        assert_eq!(receiver.recv_sequence(), 1);
    }

    /// A skipped key is SINGLE USE, and it survives a failed attempt on it: it
    /// is consumed only by the frame that authenticates with it.
    #[test]
    fn test_a_skipped_key_is_consumed_once() {
        let shared_secret = [11u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct0 = sender.encrypt_message(b"first").unwrap();
        let ct1 = sender.encrypt_message(b"second").unwrap();

        // ct1 first: ct0's key is cached as skipped.
        assert_eq!(receiver.decrypt_message_labeled(&ct1, 1).unwrap(), b"second");

        // A forgery at the skipped position must not eat the cached key.
        let mut corrupted = ct0.clone();
        corrupted[0] ^= 0xff;
        assert!(receiver.decrypt_message_labeled(&corrupted, 0).is_err());

        // The real frame still decrypts...
        assert_eq!(receiver.decrypt_message_labeled(&ct0, 0).unwrap(), b"first");
        // ...and a second delivery of it does not.
        assert!(
            receiver.decrypt_message_labeled(&ct0, 0).is_err(),
            "a consumed position must not decrypt twice"
        );
    }

    /// A forged frame claiming a position far ahead must not walk the receive
    /// window: the label is unauthenticated, and acting on it before the AEAD
    /// decides would be a free denial-of-service window-move for any middleman.
    #[test]
    fn test_a_forged_label_does_not_move_the_window() {
        let shared_secret = [12u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        let ct0 = sender.encrypt_message(b"honest").unwrap();

        // 500 positions of garbage.
        assert!(receiver.decrypt_message_labeled(&[0u8; 64], 500).is_err());
        assert_eq!(
            receiver.recv_sequence(),
            0,
            "an unauthenticated label must not advance the receive position"
        );

        // The honest first frame still decrypts at position 0, so no skipped-key
        // batch was committed for positions 0..500 either.
        assert_eq!(receiver.decrypt_message_labeled(&ct0, 0).unwrap(), b"honest");
    }

    #[test]
    fn test_pq_secret_mixing() {
        let shared_secret = [42u8; 32];
        let mut ratchet = DoubleRatchet::init(&shared_secret);
        let original_root = ratchet.root_key;

        let pq_secret = [99u8; 32];
        ratchet.mix_pq_secret(&pq_secret);

        // Root key must change after mixing
        assert_ne!(ratchet.root_key, original_root);
        // Root key must not equal the raw PQ secret
        assert_ne!(ratchet.root_key, pq_secret);
        // Root key must not equal the raw shared secret
        assert_ne!(ratchet.root_key, shared_secret);

        // Single-side encryption still works after mixing
        let ct = ratchet.encrypt_message(b"after pq mix").unwrap();
        assert!(!ct.is_empty());
    }

    #[test]
    fn test_pq_secret_mixing_cross_party() {
        let shared_secret = [42u8; 32];
        let mut sender = DoubleRatchet::init(&shared_secret);
        let mut receiver = DoubleRatchet::init_responder(&shared_secret);

        // Both sides mix the same PQ secret (simulates ML-KEM exchange)
        let pq_secret = [99u8; 32];
        sender.mix_pq_secret(&pq_secret);
        receiver.mix_pq_secret(&pq_secret);

        // Root keys must match after mixing
        assert_eq!(sender.root_key, receiver.root_key);

        // Sender's send_chain must match receiver's recv_chain (role-aware)
        assert_eq!(sender.send_chain_key, receiver.recv_chain_key);
        assert_eq!(sender.recv_chain_key, receiver.send_chain_key);

        // Cross-party encrypt/decrypt must work after PQ mixing
        let ct = sender.encrypt_message(b"post-pq message").unwrap();
        let pt = receiver.decrypt_message(&ct).unwrap();
        assert_eq!(pt, b"post-pq message");

        // And in the other direction
        let ct2 = receiver.encrypt_message(b"reply after pq").unwrap();
        let pt2 = sender.decrypt_message(&ct2).unwrap();
        assert_eq!(pt2, b"reply after pq");
    }

    #[test]
    fn test_root_key_domain_separated() {
        // Root key must NOT equal the raw shared secret
        let shared_secret = [42u8; 32];
        let ratchet = DoubleRatchet::init(&shared_secret);
        assert_ne!(
            ratchet.root_key, shared_secret,
            "Root key must be domain-separated from shared secret"
        );
    }
}
