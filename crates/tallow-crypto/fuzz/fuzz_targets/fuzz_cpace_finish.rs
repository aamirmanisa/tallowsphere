//! Fuzz target: CPace finish against arbitrary peer messages.
//!
//! Security property: finishing a CPace exchange with an attacker-controlled
//! peer public message must never panic — malformed points return a clean
//! error.
//!
//! Run: cargo +nightly fuzz run fuzz_cpace_finish

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_crypto::pake::cpace::{CpaceInitiator, CpaceResponder};

#[derive(Arbitrary, Debug)]
struct Input {
    code_phrase: String,
    session_id: Vec<u8>,
    their_public: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Session ids are short; peer public messages are Ristretto255 points
    // (32 bytes) — allow a margin around both.
    if input.session_id.len() > 256 || input.their_public.len() > 128 {
        return;
    }
    let initiator = CpaceInitiator::new(&input.code_phrase, &input.session_id);
    // Must not panic; Err is acceptable (invalid point encoding).
    let _ = initiator.finish(&input.their_public);

    let responder = CpaceResponder::new(&input.code_phrase, &input.session_id);
    let _ = responder.finish(&input.their_public);
});
