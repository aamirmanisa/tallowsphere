//! Multi-peer key exchange orchestration
//!
//! Manages pairwise KEM sessions between N peers in a multi-peer room.
//! Each peer pair derives independent directional encryption keys via HKDF.

use std::collections::HashMap;
use zeroize::Zeroize;

/// Per-peer session state holding pairwise encryption keys
pub struct PeerSession {
    /// Peer's relay-assigned ID
    peer_id: u8,
    /// AES-256-GCM key for encrypting messages TO this peer
    send_key: [u8; 32],
    /// AES-256-GCM key for decrypting messages FROM this peer
    recv_key: [u8; 32],
    /// Nonce counter for sending (simple increment, no even/odd split)
    send_nonce: u64,
}

impl PeerSession {
    /// Get the peer ID
    pub fn peer_id(&self) -> u8 {
        self.peer_id
    }

    /// Get the send key
    pub fn send_key(&self) -> &[u8; 32] {
        &self.send_key
    }

    /// Get the recv key
    pub fn recv_key(&self) -> &[u8; 32] {
        &self.recv_key
    }

    /// Get current send nonce and advance counter
    pub fn next_send_nonce(&mut self) -> u64 {
        let n = self.send_nonce;
        self.send_nonce += 1;
        n
    }
}

impl Drop for PeerSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

/// Domain separation prefix for multi-peer key derivation
const MULTI_PEER_KEY_DOMAIN: &str = "tallow.multipeer.pairkey.v1";

/// Derive directional encryption keys from a pairwise session key.
///
/// Uses HKDF-SHA256 with peer IDs in the info field to derive two
/// distinct keys: one for each direction of communication.
///
/// The lower peer ID's "send_key" is the higher peer ID's "recv_key",
/// ensuring both sides derive the same key pair.
///
/// # Arguments
///
/// * `session_key` - The 32-byte pairwise session key from KEM handshake
/// * `my_peer_id` - This peer's relay-assigned ID
/// * `their_peer_id` - The other peer's relay-assigned ID
pub fn derive_peer_keys(
    session_key: &[u8; 32],
    my_peer_id: u8,
    their_peer_id: u8,
) -> Result<PeerSession, crate::ProtocolError> {
    // Deterministic ordering: lower ID is always "A", higher is "B"
    let (id_a, id_b) = if my_peer_id < their_peer_id {
        (my_peer_id, their_peer_id)
    } else {
        (their_peer_id, my_peer_id)
    };

    let info_a_to_b = format!("{}-{}-to-{}", MULTI_PEER_KEY_DOMAIN, id_a, id_b);
    let info_b_to_a = format!("{}-{}-to-{}", MULTI_PEER_KEY_DOMAIN, id_b, id_a);

    let key_a_to_b = tallow_crypto::kdf::hkdf::derive(
        &[0u8; 32], // salt
        session_key,
        info_a_to_b.as_bytes(),
        32,
    )
    .map_err(|e| crate::ProtocolError::HandshakeFailed(format!("HKDF derive failed: {}", e)))?;

    let key_b_to_a =
        tallow_crypto::kdf::hkdf::derive(&[0u8; 32], session_key, info_b_to_a.as_bytes(), 32)
            .map_err(|e| {
                crate::ProtocolError::HandshakeFailed(format!("HKDF derive failed: {}", e))
            })?;

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];

    if my_peer_id < their_peer_id {
        // I'm A: my send = A->B, my recv = B->A
        send_key.copy_from_slice(&key_a_to_b);
        recv_key.copy_from_slice(&key_b_to_a);
    } else {
        // I'm B: my send = B->A, my recv = A->B
        send_key.copy_from_slice(&key_b_to_a);
        recv_key.copy_from_slice(&key_a_to_b);
    }

    Ok(PeerSession {
        peer_id: their_peer_id,
        send_key,
        recv_key,
        send_nonce: 0,
    })
}

/// Manages all pairwise sessions for a multi-peer room
pub struct MultiPeerSessions {
    /// Our peer ID
    my_peer_id: u8,
    /// Pairwise sessions keyed by the other peer's ID
    sessions: HashMap<u8, PeerSession>,
}

impl MultiPeerSessions {
    /// Create a new session manager
    pub fn new(my_peer_id: u8) -> Self {
        Self {
            my_peer_id,
            sessions: HashMap::new(),
        }
    }

    /// Our peer ID
    pub fn my_peer_id(&self) -> u8 {
        self.my_peer_id
    }

    /// Add a pairwise session after a successful KEM handshake
    pub fn add_session(
        &mut self,
        session_key: &[u8; 32],
        their_peer_id: u8,
    ) -> Result<(), crate::ProtocolError> {
        let session = derive_peer_keys(session_key, self.my_peer_id, their_peer_id)?;
        self.sessions.insert(their_peer_id, session);
        Ok(())
    }

    /// Remove a session when a peer leaves
    pub fn remove_session(&mut self, peer_id: u8) {
        self.sessions.remove(&peer_id);
    }

    /// Get a session for a specific peer
    pub fn get(&self, peer_id: &u8) -> Option<&PeerSession> {
        self.sessions.get(peer_id)
    }

    /// Get a mutable session for a specific peer
    pub fn get_mut(&mut self, peer_id: &u8) -> Option<&mut PeerSession> {
        self.sessions.get_mut(peer_id)
    }

    /// Iterate over all sessions
    pub fn iter(&self) -> impl Iterator<Item = (&u8, &PeerSession)> {
        self.sessions.iter()
    }

    /// Iterate over all sessions mutably
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&u8, &mut PeerSession)> {
        self.sessions.iter_mut()
    }

    /// Number of active sessions
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether there are no sessions
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Whether we should be the handshake initiator for a given peer
    pub fn is_initiator_for(&self, their_peer_id: u8) -> bool {
        self.my_peer_id < their_peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_peer_keys_symmetric() {
        let session_key = [42u8; 32];
        let alice = derive_peer_keys(&session_key, 0, 1).unwrap();
        let bob = derive_peer_keys(&session_key, 1, 0).unwrap();

        // Alice's send key should be Bob's recv key
        assert_eq!(alice.send_key(), bob.recv_key());
        // Alice's recv key should be Bob's send key
        assert_eq!(alice.recv_key(), bob.send_key());
    }

    #[test]
    fn test_derive_peer_keys_different_pairs_produce_different_keys() {
        let session_key = [42u8; 32];
        let pair_01 = derive_peer_keys(&session_key, 0, 1).unwrap();
        let pair_02 = derive_peer_keys(&session_key, 0, 2).unwrap();

        assert_ne!(pair_01.send_key(), pair_02.send_key());
        assert_ne!(pair_01.recv_key(), pair_02.recv_key());
    }

    #[test]
    fn test_derive_peer_keys_different_sessions() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let s1 = derive_peer_keys(&key1, 0, 1).unwrap();
        let s2 = derive_peer_keys(&key2, 0, 1).unwrap();

        assert_ne!(s1.send_key(), s2.send_key());
    }

    #[test]
    fn test_multi_peer_sessions_initiator_role() {
        let sessions = MultiPeerSessions::new(2);
        assert!(sessions.is_initiator_for(5)); // 2 < 5
        assert!(!sessions.is_initiator_for(1)); // 2 > 1
    }

    #[test]
    fn test_multi_peer_sessions_add_remove() {
        let mut sessions = MultiPeerSessions::new(0);
        let key = [99u8; 32];

        sessions.add_session(&key, 1).unwrap();
        sessions.add_session(&key, 2).unwrap();
        assert_eq!(sessions.len(), 2);

        sessions.remove_session(1);
        assert_eq!(sessions.len(), 1);
        assert!(sessions.get(&1).is_none());
        assert!(sessions.get(&2).is_some());
    }

    #[test]
    fn test_nonce_counter_increments() {
        let key = [42u8; 32];
        let mut session = derive_peer_keys(&key, 0, 1).unwrap();

        assert_eq!(session.next_send_nonce(), 0);
        assert_eq!(session.next_send_nonce(), 1);
        assert_eq!(session.next_send_nonce(), 2);
    }

    #[test]
    fn test_four_peer_pairwise_encrypt_decrypt() {
        // Simulate 4 peers (IDs 0, 1, 2, 3), each with session keys to all others
        let session_keys: Vec<[u8; 32]> = (0..6).map(|i| [i as u8 + 1; 32]).collect();
        // Pairs: (0,1), (0,2), (0,3), (1,2), (1,3), (2,3)
        let pairs = [(0u8, 1u8), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];

        for (idx, (a, b)) in pairs.iter().enumerate() {
            let key = &session_keys[idx];
            let session_a = derive_peer_keys(key, *a, *b).unwrap();
            let session_b = derive_peer_keys(key, *b, *a).unwrap();

            // A encrypts to B
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&0u64.to_be_bytes());
            let ct = tallow_crypto::symmetric::aes_encrypt(
                session_a.send_key(),
                &nonce,
                b"hello from A",
                b"tallow-chat-v1",
            )
            .unwrap();

            // B decrypts from A
            let pt = tallow_crypto::symmetric::aes_decrypt(
                session_b.recv_key(),
                &nonce,
                &ct,
                b"tallow-chat-v1",
            )
            .unwrap();
            assert_eq!(pt, b"hello from A");

            // B encrypts to A
            let ct2 = tallow_crypto::symmetric::aes_encrypt(
                session_b.send_key(),
                &nonce,
                b"hello from B",
                b"tallow-chat-v1",
            )
            .unwrap();

            // A decrypts from B
            let pt2 = tallow_crypto::symmetric::aes_decrypt(
                session_a.recv_key(),
                &nonce,
                &ct2,
                b"tallow-chat-v1",
            )
            .unwrap();
            assert_eq!(pt2, b"hello from B");
        }
    }

    #[test]
    fn test_same_plaintext_different_ciphertext_across_peers() {
        // Sending "hello" to peers 1 and 2 must produce different ciphertexts
        // because the keys are different
        let session_key_01 = [1u8; 32];
        let session_key_02 = [2u8; 32];

        let s1 = derive_peer_keys(&session_key_01, 0, 1).unwrap();
        let s2 = derive_peer_keys(&session_key_02, 0, 2).unwrap();

        let nonce = [0u8; 12];
        let ct1 = tallow_crypto::symmetric::aes_encrypt(
            s1.send_key(),
            &nonce,
            b"hello",
            b"tallow-chat-v1",
        )
        .unwrap();
        let ct2 = tallow_crypto::symmetric::aes_encrypt(
            s2.send_key(),
            &nonce,
            b"hello",
            b"tallow-chat-v1",
        )
        .unwrap();

        assert_ne!(
            ct1, ct2,
            "Same plaintext to different peers must produce different ciphertext"
        );
    }
}
