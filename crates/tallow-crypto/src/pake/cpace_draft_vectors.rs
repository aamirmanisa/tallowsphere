//! TCS-PAKE-1 vs the CPace **draft** — a deviation record (item 1.2, resolved 2026-10-13).
//!
//! Checklist item 1.2 (2026-10-12). The in-house PAKE is called "CPace" in code
//! and comments, but its generator derivation and session-key derivation are
//! Tallow's own construction. This module does two things, and the second one is
//! the point:
//!
//! 1. **Reproduces the draft's published vector** from
//!    `draft-irtf-cfrg-cpace-21` Appendix B.3.1 (group ristretto255, hash
//!    SHA-512, `PRS = b'Password'`, `DSI = b'CPaceRistretto255'`,
//!    `CI = b'\x0bA_initiator\x0bB_responder'`, `sid = 7e4b4791…`) using only
//!    dependencies this crate already has. That proves conformance is *reachable*
//!    — path (a) in the checklist is a real option, not a rewrite.
//! 2. **Shows where Tallow's construction diverges**, at the generator, which is
//!    the first and cheapest place the two stop agreeing.
//!
//! **Resolved 2026-10-13 (ruling 0.1): item 1.2 was executed as path (b), rename.**
//! So this module STAYS as the deviation record — test 2 keeps `assert_ne!` — and the published
//! material now names `TCS-PAKE-1` and claims no draft conformance
//! (`docs/security/pake-vectors-2026-10-13.md`). Test 1's reproduction of the draft's own vector is
//! retained deliberately: it is the evidence of exactly what the deviation departs *from*, which is
//! what makes the rename a factual statement rather than a way of avoiding the question.

#![cfg(test)]

use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};

use super::cpace::generator_point_for_test;

/// `draft-irtf-cfrg-cpace-21` B.3.1 inputs.
const DSI: &[u8] = b"CPaceRistretto255";
const PRS: &[u8] = b"Password";
const CI: &[u8] = b"\x0bA_initiator\x0bB_responder";
const SID: [u8; 16] = [
    0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57,
];

/// The draft's `lv_cat`: each field is prefixed with its length in one byte.
fn lv_cat(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        assert!(f.len() < 256, "lv_cat field must fit a one-byte length");
        out.push(f.len() as u8);
        out.extend_from_slice(f);
    }
    out
}

/// Draft B.3.1: `generator_string(G.DSI, PRS, CI, sid, s_in_bytes)` with
/// `len_zpad = MAX(0, s_in_bytes - len(prepend_len(PRS)) - len(prepend_len(DSI)) - 1)`
/// — 100 zero bytes for SHA-512 (128-byte block) with these inputs.
fn generator_string() -> Vec<u8> {
    let len_zpad = 100usize;
    let mut out = Vec::new();
    out.push(DSI.len() as u8);
    out.extend_from_slice(DSI);
    out.push(PRS.len() as u8);
    out.extend_from_slice(PRS);
    out.push(len_zpad as u8);
    out.extend(std::iter::repeat_n(0u8, len_zpad));
    out.extend_from_slice(&lv_cat(&[CI]));
    out.extend_from_slice(&lv_cat(&[&SID[..]]));
    out
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// 1 · The draft's own vector reproduces: generator_string (170 bytes) → SHA-512
/// → ristretto255 element derivation → the published encoded generator.
#[test]
fn cpace_draft_b31_vector_reproduces_with_existing_dependencies() {
    let gs = generator_string();
    assert_eq!(
        gs.len(),
        170,
        "draft says the generator_string is 170 bytes for these inputs"
    );
    assert_eq!(
        to_hex(&gs[..27]),
        "11435061636552697374726574746f3235350850617373776f7264",
        "generator_string prefix must match the draft's published bytes \
         (lv_cat(DSI) ‖ lv_cat(PRS))"
    );
    assert_eq!(gs[27], 100, "the draft's zero-padding length byte is 100");

    let hash = Sha512::digest(&gs);
    assert_eq!(
        to_hex(&hash),
        "da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288b6663af0\
         6bf645c93cd1c51512307199c80e84908916d983b34af77205f90851a657ee27",
        "SHA-512 of the generator_string must match the draft"
    );

    let generator = RistrettoPoint::from_uniform_bytes(
        hash.as_slice()
            .try_into()
            .expect("SHA-512 output is 64 bytes"),
    )
    .compress()
    .to_bytes();
    assert_eq!(
        to_hex(&generator),
        "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
        "the encoded generator must match the draft's published output"
    );
}

/// 2 · Where Tallow's construction diverges from the draft, measured at the
/// generator — the earliest point the two can disagree.
///
/// This documents a real claim gap: the same password fed to both constructions
/// yields different generators, so the component derives different public
/// messages, a different shared point and a different session key. Tallow's
/// PAKE is therefore CPace-*shaped*, not CPace.
#[test]
fn tallow_generator_differs_from_the_draft_generator() {
    let draft_hash: [u8; 64] = Sha512::digest(generator_string())
        .as_slice()
        .try_into()
        .expect("SHA-512 output is 64 bytes");
    let draft_encoded = to_hex(
        &RistrettoPoint::from_uniform_bytes(&draft_hash)
            .compress()
            .to_bytes(),
    );

    // Same password, same session id, through Tallow's derivation.
    let ours = to_hex(&generator_point_for_test(
        std::str::from_utf8(PRS).expect("ascii"),
        &SID,
    ));

    assert_ne!(
        ours, draft_encoded,
        "Tallow's generator now matches the draft — item 1.2 path (a) landed; \
         invert this test to assert_eq! and update the claims"
    );

    // And it is deterministic per (phrase, session): the divergence is in the
    // construction, not in randomness.
    assert_eq!(
        ours,
        to_hex(&generator_point_for_test(
            std::str::from_utf8(PRS).expect("ascii"),
            &SID
        )),
        "the generator must be deterministic for a given (phrase, session)"
    );
}
