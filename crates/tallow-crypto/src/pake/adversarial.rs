//! Adversarial and binding properties of the in-house PAKE.
//!
//! Checklist item 1.3 (2026-10-12). The existing `cpace.rs` tests already cover
//! same/different password, session separation, invalid length, the identity
//! element and non-canonical encodings. These add the properties that decide
//! whether the exchange resists a *relay* that can see and replay both public
//! messages:
//!
//! 1. the session id must actually separate exchanges — a mismatched session
//!    must produce no agreement, not a silent one;
//! 2. reflection must not agree with the legitimate exchange;
//! 3. an empty phrase must not panic or collapse (phrase validation is the
//!    caller's responsibility — the browser enforces the code shape);
//! 4. **the generator-input framing** — the encoding ambiguity this module once
//!    pinned is fixed (length-prefixed fields); the inverted test now guards against
//!    a regression back to raw separator bytes.
//!
//! These tests make no security claim beyond what they assert.

#![cfg(test)]

use super::cpace::{CpaceInitiator, CpaceResponder};

/// Same phrase, different session ids: each side completes, but the keys must
/// differ — the session id is bound into the generator, so a session mismatch
/// produces no agreement.
#[test]
fn mismatched_session_ids_produce_no_agreement() {
    let phrase = "K7M2QP";
    let initiator = CpaceInitiator::new(phrase, b"session-A");
    let responder = CpaceResponder::new(phrase, b"session-B");

    let initiator_key = initiator.finish(&responder.public_message());
    let responder_key = responder.finish(&initiator.public_message());

    // Both sides can compute *something* (each input is a valid point), and the
    // two somethings must not match.
    let (ik, rk) = match (initiator_key, responder_key) {
        (Ok(ik), Ok(rk)) => (ik, rk),
        (a, b) => panic!("mismatched sessions should still complete: {a:?} / {b:?}"),
    };
    assert_ne!(ik, rk, "session ids did not separate the exchanges");

    // Control: the matching pair agrees.
    let responder_ok = CpaceResponder::new(phrase, b"session-A");
    let control = responder_ok
        .finish(&initiator.public_message())
        .expect("matching session must complete");
    assert_eq!(
        initiator
            .finish(&responder_ok.public_message())
            .expect("matching session must complete"),
        control,
        "matching sessions must agree"
    );
    assert_ne!(
        control, rk,
        "control key must differ from the mismatched one"
    );
}

/// Reflection: feeding a party its own public message back must not reproduce
/// the legitimate key. The transcript binds the initiator/responder ordering,
/// so a reflected message is a different transcript.
#[test]
fn reflection_does_not_reproduce_the_legitimate_key() {
    let phrase = "K7M2QP";
    let session = b"session-reflect";
    let initiator = CpaceInitiator::new(phrase, session);
    let responder = CpaceResponder::new(phrase, session);

    let legitimate = initiator
        .finish(&responder.public_message())
        .expect("legitimate exchange must complete");

    let reflected_self = initiator
        .finish(&initiator.public_message())
        .expect("self-public is a valid point; it must not equal the legitimate key")
        .to_vec();
    assert_ne!(
        reflected_self.as_slice(),
        legitimate.as_slice(),
        "reflection reproduced the legitimate key"
    );

    let reflected_responder = responder
        .finish(&responder.public_message())
        .expect("self-public is a valid point")
        .to_vec();
    assert_ne!(
        reflected_responder.as_slice(),
        legitimate.as_slice(),
        "responder reflection reproduced the legitimate key"
    );
}

/// An empty phrase must not panic and must not make the exchange collapse to a
/// fixed value. Whether an empty phrase is *allowed* is a caller decision (the
/// browser validates a 6- or 8-symbol code first); this pins the library's
/// behaviour so a refactor cannot turn it into a panic.
#[test]
fn empty_phrase_does_not_panic_and_still_agrees() {
    let initiator = CpaceInitiator::new("", b"empty-phrase-session");
    let responder = CpaceResponder::new("", b"empty-phrase-session");
    let a = initiator
        .finish(&responder.public_message())
        .expect("empty phrase must still complete");
    let b = responder
        .finish(&initiator.public_message())
        .expect("empty phrase must still complete");
    assert_eq!(a, b);

    // And it must not be the same as a non-empty phrase's exchange (i.e. the
    // phrase actually feeds the generator).
    let other = CpaceResponder::new("AB", b"empty-phrase-session");
    let c = other
        .finish(&initiator.public_message())
        .expect("valid point");
    assert_ne!(a, c, "the phrase did not affect the generator");
}

/// **Documented ambiguity — this test asserts a collision that should not
/// exist.** `derive_generator` builds its input as
/// `DSI ‖ 0x00 ‖ phrase ‖ 0x00 ‖ session_id` with raw 0x00 separators and no
/// length framing, so `("AB", 0x00‖"CD")` and `("AB\0", "CD")` produce the
/// *identical* generator input — two distinct credentials that land in the same
/// exchange.
///
/// Impact today is bounded: the phrase upstream is a 6- or 8-symbol code from a
/// 32-character alphabet, so it cannot contain 0x00, and `session_id` is
/// caller-supplied (`room_id ‖ nonces`). It is still a correctness defect in the
/// derivation, and the fix is cheap: length-prefix each field instead of using a
/// separator byte.
///
/// **Status: fixed 2026-10-12 (checklist item 1.6).** This test used to assert the
/// collision; it now asserts the opposite, so a regression back to separator bytes
/// fails here loudly instead of silently re-widening the derivation.
///
/// With the old framing (`DSI ‖ 0x00 ‖ phrase ‖ 0x00 ‖ session_id`, raw separator
/// bytes, no length framing) the two credentials below built an *identical* generator
/// input: two distinct credentials landing in the same exchange. `derive_generator`
/// now length-prefixes each field, so they must **not** agree — and this test stays,
/// inverted, as the guard: a regression back to separator bytes fails here loudly
/// rather than silently re-widening the derivation.
#[test]
fn raw_separator_credentials_no_longer_collide() {
    // (phrase, session_id) pair that used to collide with the pair below.
    let phrase_a = "AB";
    let session_a: Vec<u8> = {
        let mut v = vec![0x00u8];
        v.extend_from_slice(b"CD");
        v
    };
    // Same concatenated bytes, split differently across the boundary.
    let phrase_b = "AB\u{0}";
    let session_b: &[u8] = b"CD";

    // The generator is the first place the two can disagree, so assert it there.
    assert_ne!(
        super::cpace::generator_point_for_test(phrase_a, &session_a),
        super::cpace::generator_point_for_test(phrase_b, session_b),
        "the two credentials still derive the same generator — the framing fix regressed \
         to raw separator bytes"
    );

    // And at the protocol level: a handshake between the two must not produce agreement.
    let init_a = CpaceInitiator::new(phrase_a, &session_a);
    let resp_b = CpaceResponder::new(phrase_b, session_b);

    let key_from_a = init_a.finish(&resp_b.public_message());
    let key_from_b = resp_b.finish(&init_a.public_message());

    match (key_from_a, key_from_b) {
        (Ok(key_from_a), Ok(key_from_b)) => assert_ne!(
            key_from_a, key_from_b,
            "the two credentials derive the same session key — the framing fix regressed"
        ),
        // Refusing the exchange outright is also a correct outcome for mismatched
        // credentials; only agreement would be a defect.
        _ => {}
    }
}
