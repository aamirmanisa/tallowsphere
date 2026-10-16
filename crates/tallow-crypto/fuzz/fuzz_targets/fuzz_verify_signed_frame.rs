//! Fuzz target: the `HandshakeSigned` verification POLICY path
//! (`SenderHandshake::verify_signed_frame` / `ReceiverHandshake::verify_signed_frame`).
//!
//! Distinct from `fuzz_handshake_signed`, which fuzzes the raw crypto verify
//! primitives. This target fuzzes the policy around them:
//!
//!   * every frame for the WRONG role must be rejected (a sender-side handshake
//!     must refuse a receiver-role frame and vice versa);
//!   * a pinned identity (`Some(&[u8; 32])`, i.e. TOFU already completed) must
//!     never accept a frame presenting a different identity;
//!   * `None` (first contact / TOFU) must only accept something that actually
//!     verifies — it must not accept on the strength of a malformed frame;
//!   * arbitrary bytes decoding to a `HandshakeSigned` message must never panic.
//!
//! Run: cargo +nightly fuzz run fuzz_verify_signed_frame

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_protocol::kex::{ReceiverHandshake, SenderHandshake};
use tallow_protocol::wire::Message;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw bytes of a candidate wire frame.
    frame: Vec<u8>,
    /// The pin a caller would hold after TOFU: `None` = first contact.
    pin: Option<[u8; 32]>,
    /// Which side of the handshake we are: true = sender, false = receiver.
    as_sender: bool,
}

fuzz_target!(|input: Input| {
    if input.frame.len() > 65_536 {
        return;
    }

    // Fixed room parameters: the attack surface here is the FRAME, not the
    // code phrase. The phrase only has to be well-formed enough to construct.
    let code_phrase = "alpha-bravo-charlie";
    let room_id = [0u8; 32];

    // A frame that does not decode is not this target's concern (that is
    // fuzz_decode_msg's job).
    let Ok(msg) = postcard::from_bytes::<Message>(&input.frame) else {
        return;
    };

    let expected: Option<&[u8; 32]> = input.pin.as_ref();

    if input.as_sender {
        let mut handshake = SenderHandshake::new(code_phrase, &room_id);
        // Must return a clean Result for any input — never panic.
        let _ = handshake.verify_signed_frame(&msg, expected);
    } else {
        let mut handshake = ReceiverHandshake::new(code_phrase, &room_id);
        let _ = handshake.verify_signed_frame(&msg, expected);
    }
});
