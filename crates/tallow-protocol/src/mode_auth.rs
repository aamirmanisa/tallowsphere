//! Code-derived authentication for Simple (transport-only) mode frames.
//!
//! Security review 2026-09-23, R2 (crypto hack report, Attack 2): Simple mode
//! runs no handshake, so a receiver could not tell the real sender from an
//! injector racing `ModeAnnounce`/`ModeAccept` frames into the room. Both
//! frames now carry a MAC under a key derived from the room code the two users
//! already share: a forged announce/accept fails closed, and a peer that
//! cannot produce one (an older bundle) is surfaced as *unauthenticated*
//! instead of being silently trusted.
//!
//! Scope: this authenticates the mode handshake only. It does NOT make Simple
//! mode end-to-end encrypted — the relay still carries the bytes.

use subtle::ConstantTimeEq;
use tallow_crypto::hash::blake3;

/// Domain separation for the Simple-mode MAC key.
pub const SIMPLE_MODE_KEY_LABEL: &str = "tallow-simple-mode-mac-v1";
const ANNOUNCE_LABEL: &[u8] = b"tallow-mode-announce-v1";
const ACCEPT_LABEL: &[u8] = b"tallow-mode-accept-v1";

/// Derive the Simple-mode MAC key from the shared room code + room id.
///
/// Deterministic on both sides: the sender knows the code it minted, the
/// receiver got it from the share link / QR / typed it. Never persisted.
pub fn simple_mode_mac_key(code_phrase: &str, room_id: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(code_phrase.len() + 32);
    input.extend_from_slice(code_phrase.as_bytes());
    input.extend_from_slice(room_id);
    blake3::derive_key(SIMPLE_MODE_KEY_LABEL, &input)
}

fn frame_mac(key: &[u8; 32], label: &[u8], transfer_id: &[u8; 16], mode: u8) -> [u8; 32] {
    let mut data = Vec::with_capacity(label.len() + 17);
    data.extend_from_slice(label);
    data.extend_from_slice(transfer_id);
    data.push(mode);
    blake3::keyed_hash(key, &data)
}

/// MAC for a Simple-mode `ModeAnnounce` (sender side).
pub fn mode_announce_mac(key: &[u8; 32], transfer_id: &[u8; 16], mode: u8) -> [u8; 32] {
    frame_mac(key, ANNOUNCE_LABEL, transfer_id, mode)
}

/// MAC for a Simple-mode `ModeAccept` (receiver side).
pub fn mode_accept_mac(key: &[u8; 32], transfer_id: &[u8; 16], mode: u8) -> [u8; 32] {
    frame_mac(key, ACCEPT_LABEL, transfer_id, mode)
}

/// Verify a `ModeAnnounce` MAC (receiver side), constant-time.
pub fn verify_mode_announce_mac(
    key: &[u8; 32],
    transfer_id: &[u8; 16],
    mode: u8,
    mac: &[u8; 32],
) -> bool {
    mode_announce_mac(key, transfer_id, mode).ct_eq(mac).into()
}

/// Verify a `ModeAccept` MAC (sender side), constant-time.
pub fn verify_mode_accept_mac(
    key: &[u8; 32],
    transfer_id: &[u8; 16],
    mode: u8,
    mac: &[u8; 32],
) -> bool {
    mode_accept_mac(key, transfer_id, mode).ct_eq(mac).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "M0WZ9H";
    const OTHER_CODE: &str = "M0WZ9J";

    fn room(code: &str) -> [u8; 32] {
        blake3::derive_key("tallow-room-id-v1", code.as_bytes())
    }

    fn tid() -> [u8; 16] {
        [7u8; 16]
    }

    #[test]
    fn announce_mac_roundtrip() {
        let key = simple_mode_mac_key(CODE, &room(CODE));
        let mac = mode_announce_mac(&key, &tid(), 1);
        assert!(verify_mode_announce_mac(&key, &tid(), 1, &mac));
    }

    #[test]
    fn accept_mac_roundtrip() {
        let key = simple_mode_mac_key(CODE, &room(CODE));
        let mac = mode_accept_mac(&key, &tid(), 1);
        assert!(verify_mode_accept_mac(&key, &tid(), 1, &mac));
    }

    #[test]
    fn wrong_code_or_transfer_or_mode_rejected() {
        let key = simple_mode_mac_key(CODE, &room(CODE));
        let mac = mode_announce_mac(&key, &tid(), 1);

        let other_key = simple_mode_mac_key(OTHER_CODE, &room(OTHER_CODE));
        assert!(!verify_mode_announce_mac(&other_key, &tid(), 1, &mac));

        assert!(!verify_mode_announce_mac(&key, &[8u8; 16], 1, &mac));
        assert!(!verify_mode_announce_mac(&key, &tid(), 0, &mac));
    }

    #[test]
    fn announce_and_accept_domains_differ() {
        let key = simple_mode_mac_key(CODE, &room(CODE));
        assert_ne!(
            mode_announce_mac(&key, &tid(), 1),
            mode_accept_mac(&key, &tid(), 1)
        );
    }

    #[test]
    fn mac_is_deterministic_across_derivations() {
        // Both peers derive the key independently from the same code+room id.
        let a = simple_mode_mac_key(CODE, &room(CODE));
        let b = simple_mode_mac_key(CODE, &room(CODE));
        assert_eq!(a, b);
    }
}
