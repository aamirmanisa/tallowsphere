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
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_message_at(ciphertext, self.recv_counter)
    }

    /// Decrypt a message with an explicit message number
    ///
    /// Supports out-of-order delivery by checking the skipped keys cache.
    pub fn decrypt_message_at(&mut self, ciphertext: &[u8], message_num: u64) -> Result<Vec<u8>> {
        let dh_pub = self.ephemeral_keypair.public_bytes().to_vec();

        // Check if this is a skipped message
        if let Some(mut mk) = self.skipped_keys.remove(&(dh_pub.clone(), message_num)) {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&message_num.to_le_bytes());

            let plaintext = chacha_decrypt(&mk, &nonce, ciphertext, &[])?;
            mk.zeroize();
            return Ok(plaintext);
        }

        // Skip ahead if necessary
        if message_num > self.recv_counter {
            let skip_count = message_num - self.recv_counter;
            if skip_count > MAX_SKIP {
                return Err(CryptoError::Decryption(format!(
                    "Too many skipped messages: {} exceeds maximum of {}",
                    skip_count, MAX_SKIP
                )));
            }

            // Cache intermediate keys
            while self.recv_counter < message_num {
                let mk = blake3::derive_key("message", &self.recv_chain_key);
                self.skipped_keys
                    .insert((dh_pub.clone(), self.recv_counter), mk);
                self.recv_chain_key = blake3::derive_key("chain_advance", &self.recv_chain_key);
                self.recv_counter = self.recv_counter.checked_add(1).ok_or_else(|| {
                    CryptoError::Decryption("recv counter overflow during skip".into())
                })?;
            }
        }

        // Derive message key for this message
        let message_key = blake3::derive_key("message", &self.recv_chain_key);

        // Advance chain key
        self.recv_chain_key = blake3::derive_key("chain_advance", &self.recv_chain_key);

        // Decrypt with nonce = counter
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.recv_counter.to_le_bytes());

        let plaintext = chacha_decrypt(&message_key, &nonce, ciphertext, &[])?;

        self.recv_counter = self.recv_counter.checked_add(1).ok_or_else(|| {
            CryptoError::Decryption("recv counter overflow — session must be re-established".into())
        })?;

        // Prune oldest skipped keys if cache is too large
        self.prune_skipped_keys();

        Ok(plaintext)
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
