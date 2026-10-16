//! AEAD channel — ChaCha20-Poly1305 with 8-byte counter-prefixed nonces.
//!
//! Wire format per sealed frame: `ctr(8 BE) | ciphertext | tag(16)`; the
//! 12-byte IETF nonce is `0x00000000 | ctr`. Mirrors the reference
//! `AeadChan` byte-for-byte.
//!
//! v1 hardening (2026-10-15): `open` ENFORCES rx-counter monotonicity — the
//! counter in a received frame must be STRICTLY GREATER than the highest
//! counter opened so far, otherwise the frame is refused with
//! [`AeadError::Replay`]. Before this, the counter was carried in the clear
//! and used only to build the nonce, so a captured sealed frame replayed into
//! a live session decrypted again (the limitation `tests/verify_v.rs` pinned
//! as `v6_v0_known_limitation_sealed_frame_replay_processed`).
//!
//! Policy: strictly increasing, no window, no tolerance for reordering. This
//! channel is a request/response control plane over a reliable, ordered
//! transport (a single TCP stream to the daemon), so reordering is not
//! expected; accepting out-of-order frames would require a replay window and
//! buy nothing here. A refused frame does NOT advance the high-water mark.

use chacha20poly1305::aead::generic_array::typenum::{U12, U16};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use core::cell::Cell;
use thiserror::Error;

type Nonce12 = GenericArray<u8, U12>;
type Tag16 = GenericArray<u8, U16>;

/// AEAD failure modes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AeadError {
    /// Frame shorter than ctr(8) + tag(16).
    #[error("short-frame")]
    Short,
    /// Authentication failed (tampered or wrong key).
    #[error("tamper")]
    Tamper,
    /// Frame counter is not strictly greater than the highest already opened —
    /// a replay (or a reordered/copied frame). Refused before decryption.
    #[error("replay")]
    Replay,
}

/// One-directional ChaCha20-Poly1305 channel with a send counter and an
/// rx high-water mark.
pub struct AeadChan {
    cipher: ChaCha20Poly1305,
    ctr: u64,
    /// Highest rx counter successfully opened. `None` until the first frame,
    /// so counter 0 is accepted on a fresh channel. `Cell` (not `AtomicU64`)
    /// because a channel is owned by exactly one session and never shared
    /// across threads — see the struct's use in `client.rs`/`server.rs`.
    rx_high: Cell<Option<u64>>,
}

impl AeadChan {
    /// New channel; `ctr0` is the first send counter (0 in this protocol).
    pub fn new(key: &[u8; 32], ctr0: u64) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(GenericArray::from_slice(key)),
            ctr: ctr0,
            rx_high: Cell::new(None),
        }
    }

    fn nonce_for(ctr: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&ctr.to_be_bytes());
        n
    }

    /// Seal: returns `ctr(8) | ct | tag(16)`; bumps the send counter.
    pub fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let ctr = self.ctr;
        self.ctr = self.ctr.wrapping_add(1);
        let mut buf = plain.to_vec();
        let n = Self::nonce_for(ctr);
        let nonce = Nonce12::from_slice(&n);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, b"", &mut buf)
            .expect("chacha20poly1305 seal");
        let mut out = Vec::with_capacity(8 + buf.len() + 16);
        out.extend_from_slice(&ctr.to_be_bytes());
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        out
    }

    /// Open a sealed frame; the nonce is taken from the frame's counter.
    ///
    /// The counter must be strictly greater than every counter previously
    /// opened on this channel ([`AeadError::Replay`] otherwise). The check is
    /// made BEFORE decryption, so a replayed frame is refused without
    /// disclosing whether its tag would have verified.
    pub fn open(&self, payload: &[u8]) -> Result<Vec<u8>, AeadError> {
        if payload.len() < 8 + 16 {
            return Err(AeadError::Short);
        }
        let ctr = u64::from_be_bytes(payload[..8].try_into().expect("8 bytes"));

        // Replay gate: strictly increasing. A fresh channel (rx_high == None)
        // accepts any first counter, including 0.
        match self.rx_high.get() {
            Some(high) if ctr <= high => return Err(AeadError::Replay),
            _ => {}
        }

        let n = Self::nonce_for(ctr);
        let nonce = Nonce12::from_slice(&n);
        let ct = &payload[8..payload.len() - 16];
        let tag = Tag16::from_slice(&payload[payload.len() - 16..]);
        let mut buf = ct.to_vec();
        self.cipher
            .decrypt_in_place_detached(nonce, b"", &mut buf, tag)
            .map_err(|_| AeadError::Tamper)?;

        // Only a frame that authenticated may advance the high-water mark: a
        // forged frame must not be able to consume/invalidate a real counter.
        self.rx_high.set(Some(ctr));
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let key = [7u8; 32];
        let mut a = AeadChan::new(&key, 0);
        let b = AeadChan::new(&key, 0);
        let sealed = a.seal(b"hello veil");
        assert_eq!(sealed.len(), 8 + 10 + 16);
        assert_eq!(b.open(&sealed).unwrap(), b"hello veil");
        // counter increments in the output
        let sealed2 = a.seal(b"again");
        assert_eq!(&sealed2[..8], &1u64.to_be_bytes());
        // tamper
        let mut bad = sealed2.clone();
        bad[10] ^= 0x01;
        assert_eq!(b.open(&bad), Err(AeadError::Tamper));
        // short
        assert_eq!(b.open(&[0u8; 10]), Err(AeadError::Short));
    }

    /// C4: legitimate sequential frames still open (the fix must not break the
    /// normal path — this is the regression guard for the happy case).
    #[test]
    fn sequential_frames_open_in_order() {
        let key = [9u8; 32];
        let mut a = AeadChan::new(&key, 0);
        let b = AeadChan::new(&key, 0);
        for i in 0..8u64 {
            let msg = format!("frame-{i}");
            let sealed = a.seal(msg.as_bytes());
            assert_eq!(
                b.open(&sealed).unwrap(),
                msg.as_bytes(),
                "frame {i} must open in order"
            );
        }
    }

    /// C4: the replay the v0 code accepted is now refused.
    #[test]
    fn replayed_frame_is_rejected() {
        let key = [11u8; 32];
        let mut a = AeadChan::new(&key, 0);
        let b = AeadChan::new(&key, 0);

        let sealed = a.seal(b"replay-me");
        assert_eq!(b.open(&sealed).unwrap(), b"replay-me");

        // the same bytes again — genuine ciphertext, genuine tag, must be refused
        assert_eq!(b.open(&sealed), Err(AeadError::Replay));
        // and again, to prove the high-water mark did not move
        assert_eq!(b.open(&sealed), Err(AeadError::Replay));
    }

    /// C4: a counter BELOW the high-water mark is refused (older frame replayed
    /// after a newer one was accepted — the case a naive "!= last" check misses).
    #[test]
    fn counter_below_high_water_is_rejected() {
        let key = [13u8; 32];
        let mut a = AeadChan::new(&key, 0);
        let b = AeadChan::new(&key, 0);

        let f0 = a.seal(b"zero");
        let f1 = a.seal(b"one");
        let f2 = a.seal(b"two");

        assert_eq!(b.open(&f2).unwrap(), b"two"); // high-water = 2
        assert_eq!(b.open(&f1), Err(AeadError::Replay)); // older, refused
        assert_eq!(b.open(&f0), Err(AeadError::Replay)); // oldest, refused
        // the refused frames did not disturb the mark: 2 is still the high-water,
        // so a genuinely fresh frame at 3 still opens.
        let f3 = a.seal(b"three");
        assert_eq!(b.open(&f3).unwrap(), b"three");
    }

    /// A refused replay must not advance the high-water mark (otherwise a
    /// replayed frame could be used to poison the channel and reject the
    /// genuine next frame).
    #[test]
    fn refused_replay_does_not_advance_the_mark() {
        let key = [17u8; 32];
        let mut a = AeadChan::new(&key, 0);
        let b = AeadChan::new(&key, 0);

        let f0 = a.seal(b"a");
        assert_eq!(b.open(&f0).unwrap(), b"a");

        // a FORGED frame with a huge counter: fails auth, so must not move the mark
        let mut forged = a.seal(b"x");
        forged[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(b.open(&forged), Err(AeadError::Tamper));

        // a forged frame with a *lower* counter must be refused as replay, not
        // silently accepted
        let mut low = a.seal(b"y");
        low[..8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(b.open(&low), Err(AeadError::Replay));

        // the genuine next frame still opens — the mark is intact
        let f1 = a.seal(b"b");
        assert_eq!(b.open(&f1).unwrap(), b"b");
    }

    /// The replay gate fires BEFORE decryption, so a replayed frame is
    /// indistinguishable from any other non-advancing frame — it does not
    /// disclose whether its tag would have verified.
    #[test]
    fn replay_is_refused_before_decryption() {
        let key = [19u8; 32];
        let mut a = AeadChan::new(&key, 0);
        let b = AeadChan::new(&key, 0);

        let sealed = a.seal(b"secret");
        assert_eq!(b.open(&sealed).unwrap(), b"secret");

        // Corrupt the tag of a REPLAYED frame: if the gate ran after decryption
        // this would report Tamper; it must still report Replay.
        let mut replayed = sealed.clone();
        let n = replayed.len();
        replayed[n - 1] ^= 0x01;
        assert_eq!(b.open(&replayed), Err(AeadError::Replay));
    }

    /// C3 TRIPWIRE — the same behaviour the pre-fix code allowed.
    /// This test is INVERTED from the proof above: it asserts the replay is
    /// REFUSED. It fails on the unfixed code (shown in the C3 proof) and passes
    /// now that the monotonicity gate is in.
    #[test]
    fn tripwire_replay_is_refused_after_the_fix() {
        let key = [42u8; 32];
        let mut sender = AeadChan::new(&key, 0);
        let receiver = AeadChan::new(&key, 0);
        let sealed = sender.seal(b"replay-me");
        assert_eq!(receiver.open(&sealed).unwrap(), b"replay-me");
        assert_eq!(
            receiver.open(&sealed),
            Err(AeadError::Replay),
            "the replay must be refused once the counter gate is enforced"
        );
    }
}
