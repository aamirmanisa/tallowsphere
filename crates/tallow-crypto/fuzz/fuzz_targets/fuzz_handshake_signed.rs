//! Fuzz target: the v5 `HandshakeSigned` consume path.
//!
//! Security property: decoding an attacker-supplied `HandshakeSigned` frame
//! (outer postcard `Message` decode, inner hybrid-key + signature decode) and
//! verifying it against arbitrary data must never panic — malformed input
//! returns clean errors.
//!
//! Run: cargo +nightly fuzz run fuzz_handshake_signed

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_protocol::wire::Message;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    signed_input: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if input.raw.len() > 65536 || input.signed_input.len() > 4096 {
        return;
    }
    // Outer decode — what a receiver runs on any wire frame.
    let Ok(msg) = postcard::from_bytes::<Message>(&input.raw) else {
        return;
    };
    if let Message::HandshakeSigned {
        identity_public_key,
        signature,
        ..
    } = msg
    {
        // Inner decode + hybrid verify — the actual attack surface.
        let Ok(pk) =
            postcard::from_bytes::<tallow_crypto::sig::HybridPublicKey>(&identity_public_key)
        else {
            return;
        };
        let Ok(sig) = postcard::from_bytes::<tallow_crypto::sig::HybridSignature>(&signature)
        else {
            return;
        };
        let _ = tallow_crypto::sig::hybrid::verify(&pk, &input.signed_input, &sig);
    }
});
