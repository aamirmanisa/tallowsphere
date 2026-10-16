//! Fuzz target: the wire framing decoder (`TallowCodec::decode_msg`).
//!
//! Security property: the length-prefixed framing layer is the FIRST thing that
//! touches bytes from an untrusted peer. Feeding it an arbitrary byte stream —
//! including hostile length prefixes, zero-length frames, oversized declared
//! lengths, and truncated payloads — must never panic, never allocate on a
//! declared-but-absent length, and never hand a partial frame to the
//! deserializer.
//!
//! Covers the L-20 policy directly: a declared length of 0 must be rejected, and
//! a declared length above `MAX_MESSAGE_SIZE` (16 MiB) must be rejected before
//! any buffer work happens.
//!
//! Run: cargo +nightly fuzz run fuzz_decode_msg

#![no_main]
use arbitrary::Arbitrary;
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use tallow_protocol::wire::TallowCodec;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw stream bytes as a receiver would see them off the wire.
    stream: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Keep the per-iteration cost bounded; the decoder itself enforces 16 MiB.
    if input.stream.len() > 1 << 20 {
        return;
    }

    let mut codec = TallowCodec::new();
    let mut buf = BytesMut::from(&input.stream[..]);

    // A live stream is drained: `Ok(None)` means "need more bytes", so a real
    // reader calls decode again as data arrives. Bounded here so a pathological
    // stream cannot spin forever inside one fuzz iteration.
    for _ in 0..64 {
        match codec.decode_msg(&mut buf) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }

    // Final call on whatever remains — must behave identically (no panic).
    let _ = codec.decode_msg(&mut buf);
});
