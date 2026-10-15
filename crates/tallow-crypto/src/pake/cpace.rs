//! CPace PAKE (Password-Authenticated Key Exchange) over Ristretto255
//!
//! Implements the CPace protocol using Ristretto255 from curve25519-dalek.
//! The code phrase is hashed to a group generator, preventing offline
//! dictionary attacks if one party is compromised.

use crate::error::{CryptoError, Result};
use crate::hash::blake3;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand_core::OsRng;

/// Domain separator for CPace generator derivation
const CPACE_DOMAIN: &str = "tallow-cpace-v1";

/// Context string for the second half of the generator's 64-byte input, so the two
/// halves are separated by domain rather than by a position-dependent counter byte.
const CPACE_GENERATOR_H2_CONTEXT: &str = "tallow-cpace-generator-h2-v1";

/// CPace initiator
pub struct CpaceInitiator {
    scalar: Scalar,
    /// Generator point derived from code phrase (retained for key confirmation)
    #[allow(dead_code)]
    generator: RistrettoPoint,
    public: CompressedRistretto,
    /// Hash of code phrase (retained for key confirmation)
    #[allow(dead_code)]
    code_phrase_hash: [u8; 32],
}

impl Drop for CpaceInitiator {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
        self.code_phrase_hash.zeroize();
    }
}

/// CPace responder (same protocol, different role label)
pub struct CpaceResponder {
    scalar: Scalar,
    /// Generator point derived from code phrase (retained for key confirmation)
    #[allow(dead_code)]
    generator: RistrettoPoint,
    public: CompressedRistretto,
    /// Hash of code phrase (retained for key confirmation)
    #[allow(dead_code)]
    code_phrase_hash: [u8; 32],
}

impl Drop for CpaceResponder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
        self.code_phrase_hash.zeroize();
    }
}

/// Derive the CPace generator from a code phrase and session context
///
/// Uses BLAKE3 to hash the code phrase with domain separation,
/// then maps to a Ristretto point using hash-to-group.
///
/// **Framing (fixed 2026-10-12, checklist 1.6):** every variable-length field is
/// length-prefixed (`u32` little-endian) rather than separated by raw `0x00` bytes,
/// and the second hash half is separated by a distinct **key context** rather than by
/// a counter byte appended to the same buffer. The old framing let
/// `("AB", 0x00‖"CD")` and `("AB\0", "CD")` build identical input and land in the same
/// exchange; `adversarial::raw_separator_credentials_no_longer_collide` now asserts
/// they do not, so a regression back to separators fails loudly.
fn derive_generator(code_phrase: &str, session_id: &[u8]) -> RistrettoPoint {
    let phrase = code_phrase.as_bytes();

    // DSI ‖ len32(phrase) ‖ phrase ‖ len32(session_id) ‖ session_id
    let mut input = Vec::with_capacity(CPACE_DOMAIN.len() + 8 + phrase.len() + session_id.len());
    input.extend_from_slice(CPACE_DOMAIN.as_bytes());
    input.extend_from_slice(&(phrase.len() as u32).to_le_bytes());
    input.extend_from_slice(phrase);
    input.extend_from_slice(&(session_id.len() as u32).to_le_bytes());
    input.extend_from_slice(session_id);

    // 64 bytes for Ristretto point derivation: a hash, then a second derivation
    // separated by context (not a counter appended to `input`).
    let h1 = blake3::hash(&input);
    let h2 = blake3::derive_key(CPACE_GENERATOR_H2_CONTEXT, &input);

    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&h1);
    wide[32..].copy_from_slice(&h2);

    // Map to Ristretto point (uniform, no cofactor issues)
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Test-only accessor: the compressed generator this implementation derives for
/// a `(code_phrase, session_id)` pair.
///
/// Exists so the deviation record (`cpace_draft_vectors`) can compare Tallow's
/// construction against the CPace draft's published vector **at the point where
/// the two actually diverge** — the generator derivation — instead of inferring
/// it from a handshake that also differs in transcript and KDF.
#[cfg(test)]
pub(crate) fn generator_point_for_test(code_phrase: &str, session_id: &[u8]) -> [u8; 32] {
    derive_generator(code_phrase, session_id)
        .compress()
        .to_bytes()
}


/// Deterministic session-key vector hook (ruling 0.1, test-only).
///
/// A real handshake draws ephemeral scalars at random, so its session key is NOT
/// reproducible across runs. This rebuilds the identical transcript from SUPPLIED
/// scalars, which is what lets the published TCS-PAKE-1 vectors pin the KDF
/// byte-for-byte: `blake3::derive_key("cpace-session-key", DSI ‖ pub_a ‖ pub_b ‖ shared)`.
/// Mirrors `finish()`'s construction exactly (same order, same shared point); the
/// only caller is `pake::vectors`.
#[cfg(test)]
pub(crate) fn session_key_for_scalars(
    code_phrase: &str,
    session_id: &[u8],
    a_bytes: [u8; 32],
    b_bytes: [u8; 32],
) -> [u8; 32] {
    let generator = derive_generator(code_phrase, session_id);
    let a = Scalar::from_bytes_mod_order(a_bytes);
    let b = Scalar::from_bytes_mod_order(b_bytes);
    let pub_a = (a * generator).compress().to_bytes();
    let pub_b = (b * generator).compress().to_bytes();
    let shared = (a * (b * generator)).compress().to_bytes();
    let mut transcript = Vec::new();
    transcript.extend_from_slice(CPACE_DOMAIN.as_bytes());
    transcript.extend_from_slice(&pub_a);
    transcript.extend_from_slice(&pub_b);
    transcript.extend_from_slice(&shared);
    blake3::derive_key("cpace-session-key", &transcript)
}

/// Decode and validate a peer's compressed Ristretto public message.
///
/// `CompressedRistretto::decompress` already rejects non-canonical and
/// otherwise invalid encodings (ristretto255 decoding is canonical: it
/// enforces canonical field representation, a non-negative `s` and a square
/// `y` candidate). The all-zero encoding of the identity (neutral) element,
/// however, *is* a valid encoding, so it must be rejected here explicitly:
/// a peer sending the identity contributes nothing to the exchange and the
/// allowed shared point would collapse to the identity, enabling a MITM /
/// non-contributory-key hazard (finding g1). Ristretto255 has prime group
/// order, so rejecting the identity is sufficient to guarantee a
/// non-trivial peer contribution.
fn decode_peer_point(their_bytes: [u8; 32]) -> Result<RistrettoPoint> {
    let point = CompressedRistretto(their_bytes)
        .decompress()
        .ok_or_else(|| CryptoError::PakeFailure("Invalid Ristretto point from peer".to_string()))?;

    if point.is_identity() {
        return Err(CryptoError::PakeFailure(
            "CPace peer sent the identity element".to_string(),
        ));
    }

    Ok(point)
}

impl CpaceInitiator {
    /// Start CPace protocol with a code phrase
    ///
    /// # Arguments
    ///
    /// * `code_phrase` - The shared code phrase (passphrase)
    /// * `session_id` - Unique session identifier for channel binding
    pub fn new(code_phrase: &str, session_id: &[u8]) -> Self {
        let generator = derive_generator(code_phrase, session_id);
        let scalar = Scalar::random(&mut OsRng);
        let public = (scalar * generator).compress();
        let code_phrase_hash = blake3::hash(code_phrase.as_bytes());

        Self {
            scalar,
            generator,
            public,
            code_phrase_hash,
        }
    }

    /// Get the public message to send to the responder (32 bytes)
    pub fn public_message(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Finish the protocol with the responder's public message
    ///
    /// Computes the shared secret and derives a session key via HKDF.
    ///
    /// # Arguments
    ///
    /// * `their_public` - The responder's 32-byte public message
    ///
    /// # Returns
    ///
    /// A 32-byte session key, or error if the public key is invalid
    pub fn finish(&self, their_public: &[u8]) -> Result<[u8; 32]> {
        if their_public.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "CPace public message must be 32 bytes".to_string(),
            ));
        }

        let their_bytes: [u8; 32] = their_public.try_into().map_err(|_| {
            CryptoError::InvalidKey("CPace public message must be 32 bytes".to_string())
        })?;

        let their_point = decode_peer_point(their_bytes)?;

        // Compute shared secret: scalar * their_public
        let shared_point = self.scalar * their_point;
        if shared_point.is_identity() {
            return Err(CryptoError::PakeFailure(
                "CPace shared point is the identity element".to_string(),
            ));
        }
        let shared_bytes = shared_point.compress().to_bytes();

        // Derive session key with transcript binding
        let mut transcript = Vec::new();
        transcript.extend_from_slice(CPACE_DOMAIN.as_bytes());
        transcript.extend_from_slice(&self.public.to_bytes());
        transcript.extend_from_slice(their_public);
        transcript.extend_from_slice(&shared_bytes);

        Ok(blake3::derive_key("cpace-session-key", &transcript))
    }
}

impl CpaceResponder {
    /// Start CPace protocol as responder
    ///
    /// # Arguments
    ///
    /// * `code_phrase` - The shared code phrase (passphrase)
    /// * `session_id` - Unique session identifier for channel binding
    pub fn new(code_phrase: &str, session_id: &[u8]) -> Self {
        let generator = derive_generator(code_phrase, session_id);
        let scalar = Scalar::random(&mut OsRng);
        let public = (scalar * generator).compress();
        let code_phrase_hash = blake3::hash(code_phrase.as_bytes());

        Self {
            scalar,
            generator,
            public,
            code_phrase_hash,
        }
    }

    /// Get the public message to send to the initiator (32 bytes)
    pub fn public_message(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Finish the protocol with the initiator's public message
    ///
    /// # Arguments
    ///
    /// * `their_public` - The initiator's 32-byte public message
    ///
    /// # Returns
    ///
    /// A 32-byte session key, or error if the public key is invalid
    pub fn finish(&self, their_public: &[u8]) -> Result<[u8; 32]> {
        if their_public.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "CPace public message must be 32 bytes".to_string(),
            ));
        }

        let their_bytes: [u8; 32] = their_public.try_into().map_err(|_| {
            CryptoError::InvalidKey("CPace public message must be 32 bytes".to_string())
        })?;

        let their_point = decode_peer_point(their_bytes)?;

        // Compute shared secret: scalar * their_public
        let shared_point = self.scalar * their_point;
        if shared_point.is_identity() {
            return Err(CryptoError::PakeFailure(
                "CPace shared point is the identity element".to_string(),
            ));
        }
        let shared_bytes = shared_point.compress().to_bytes();

        // Derive session key with transcript binding
        // Note: transcript ordering must match — initiator's public first
        let mut transcript = Vec::new();
        transcript.extend_from_slice(CPACE_DOMAIN.as_bytes());
        transcript.extend_from_slice(their_public); // initiator's public
        transcript.extend_from_slice(&self.public.to_bytes()); // responder's public
        transcript.extend_from_slice(&shared_bytes);

        Ok(blake3::derive_key("cpace-session-key", &transcript))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpace_same_password_derives_same_key() {
        let session_id = b"test-session-123";
        let code_phrase = "correct horse battery staple";

        let initiator = CpaceInitiator::new(code_phrase, session_id);
        let responder = CpaceResponder::new(code_phrase, session_id);

        let init_msg = initiator.public_message();
        let resp_msg = responder.public_message();

        let key_a = initiator.finish(&resp_msg).unwrap();
        let key_b = responder.finish(&init_msg).unwrap();

        assert_eq!(key_a, key_b, "Same password should derive same session key");
    }

    #[test]
    fn test_cpace_different_password_derives_different_key() {
        let session_id = b"test-session-123";

        let initiator = CpaceInitiator::new("password-one", session_id);
        let responder = CpaceResponder::new("password-two", session_id);

        let init_msg = initiator.public_message();
        let resp_msg = responder.public_message();

        let key_a = initiator.finish(&resp_msg).unwrap();
        let key_b = responder.finish(&init_msg).unwrap();

        assert_ne!(
            key_a, key_b,
            "Different passwords should derive different session keys"
        );
    }

    #[test]
    fn test_cpace_invalid_public_length() {
        let initiator = CpaceInitiator::new("password", b"session");
        let result = initiator.finish(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpace_different_session_ids_derive_different_keys() {
        let code_phrase = "same-password";

        let init_a = CpaceInitiator::new(code_phrase, b"session-1");
        let resp_a = CpaceResponder::new(code_phrase, b"session-1");

        let init_b = CpaceInitiator::new(code_phrase, b"session-2");
        let resp_b = CpaceResponder::new(code_phrase, b"session-2");

        let key_a = init_a.finish(&resp_a.public_message()).unwrap();
        let key_b = init_b.finish(&resp_b.public_message()).unwrap();

        assert_ne!(
            key_a, key_b,
            "Different session IDs should derive different keys"
        );
    }

    /// The all-zero 32-byte encoding is a *valid* Ristretto encoding of the
    /// identity element (decompression succeeds) — this was the g1 gap.
    /// It must now be rejected on the receive path for both roles.
    #[test]
    fn test_cpace_identity_element_fails_exchange() {
        assert!(
            CompressedRistretto([0u8; 32])
                .decompress()
                .unwrap()
                .is_identity(),
            "precondition: all-zero encoding decodes to the identity element"
        );

        let initiator = CpaceInitiator::new("password", b"session");
        let err = initiator.finish(&[0u8; 32]).unwrap_err();
        assert!(
            matches!(err, CryptoError::PakeFailure(_)),
            "initiator must hard-fail on identity element, got {err:?}"
        );

        let responder = CpaceResponder::new("password", b"session");
        let err = responder.finish(&[0u8; 32]).unwrap_err();
        assert!(
            matches!(err, CryptoError::PakeFailure(_)),
            "responder must hard-fail on identity element, got {err:?}"
        );
    }

    /// Non-canonical / undecodable encodings must be rejected as well.
    #[test]
    fn test_cpace_non_canonical_point_fails_exchange() {
        // Top bit set -> non-canonical field encoding -> decode must fail.
        let bad = [0xffu8; 32];
        assert!(
            CompressedRistretto(bad).decompress().is_none(),
            "precondition: 0xff..ff must not decode as a Ristretto point"
        );

        let initiator = CpaceInitiator::new("password", b"session");
        assert!(initiator.finish(&bad).is_err());

        let responder = CpaceResponder::new("password", b"session");
        assert!(responder.finish(&bad).is_err());
    }

    /// A rejected peer message must not poison or shortcut the exchange:
    /// the honest exchange on the same party states still succeeds and
    /// both sides derive the same key (no silent fallback to a default
    /// secret after a failed validation).
    #[test]
    fn test_cpace_valid_exchange_still_passes_after_validation() {
        let session_id = b"test-session-123";
        let code_phrase = "correct horse battery staple";

        let initiator = CpaceInitiator::new(code_phrase, session_id);
        let responder = CpaceResponder::new(code_phrase, session_id);

        let init_msg = initiator.public_message();
        let resp_msg = responder.public_message();

        // Identity input hard-fails...
        assert!(initiator.finish(&[0u8; 32]).is_err());
        // ...but the honest exchange on the same states still succeeds.
        let key_a = initiator.finish(&resp_msg).unwrap();
        let key_b = responder.finish(&init_msg).unwrap();
        assert_eq!(key_a, key_b);
    }
}
