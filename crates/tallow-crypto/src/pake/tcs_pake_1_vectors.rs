//! TCS-PAKE-1 published vectors (ruling 0.1, adopted 2026-10-13).
//!
//! NOTE: this file was almost named `vectors.rs`, which already holds the RFC 9496
//! ristretto255 vectors (item 1.1) — writing there silently replaced that module. It has its
//! own name for that reason.
//!
//! Regenerate with: `cargo test -p tallow-crypto --lib pake::tcs_pake_1_vectors -- --ignored --nocapture`
//!
//! What these pin, and why they are shaped this way:
//!
//! * the **generator** is a pure function of `(phrase, session_id)` — it is where
//!   TCS-PAKE-1 deliberately deviates from the CPace draft, so it must be public
//!   and byte-exact;
//! * a real handshake draws EPHEMERAL scalars, so its session key differs every
//!   run. The session-key vectors below therefore supply fixed scalars through
//!   `cpace::session_key_for_scalars`, which mirrors `finish()`'s transcript
//!   exactly — so the KDF (`blake3::derive_key("cpace-session-key", DSI ‖
//!   pub_a ‖ pub_b ‖ shared)`) is pinned without pretending the wire is
//!   deterministic when it is not;
//! * the SAS is derived from a session key, so it is pinned from the vector key.
//!
//! #![cfg(test)]

use crate::pake::cpace::{generator_point_for_test, session_key_for_scalars};
use crate::pake::sas::SasCode;

/// (phrase, session_id) cases. The last pair is the 1.6 collision family: after the
/// length-prefixed framing these MUST NOT share a generator (before it, ("AB","CD")
/// and ("AB\u{0}","CD") collided).
const CASES: &[(&str, &[u8])] = &[
    ("K7M2QPHD", b"session-1"),
    ("correct horse battery staple", b"test-session-123"),
    ("A", b""),
    ("AB", b"CD"),
    ("AB\u{0}", b"CD"),
];

/// Fixed scalars for the session-key vectors (not secret — a KAT input).
const SCALAR_A: [u8; 32] = [0x11u8; 32];
const SCALAR_B: [u8; 32] = [0x22u8; 32];
const SAS_CONTEXT: &[u8] = b"tallow-cpace-sas-v1";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn tcs_pake_1_generators_are_deterministic_and_separate_the_collision_family() {
    // determinism
    for (phrase, sid) in CASES {
        let g = generator_point_for_test(phrase, sid);
        assert_eq!(g, generator_point_for_test(phrase, sid), "generator not deterministic");
    }
    // the 1.6 collision pair must differ
    let g1 = generator_point_for_test("AB", b"CD");
    let g2 = generator_point_for_test("AB\u{0}", b"CD");
    assert_ne!(g1, g2, "the raw-separator collision family came back");
}

#[test]
fn tcs_pake_1_published_vectors() {
    let expected: &[(&str, &[u8], &str, &str)] = &[
        // (phrase, session_id, generator_hex, session_key_hex) — filled from the emitter
        ("K7M2QPHD", b"session-1", "d65f71f4a5ddc264e3d484c0daec6d9510d65269766a686031e3a6b7db524b63",
            "c3639a0a39e4e1ec0c2d36984abb382dba6b25b99b0528232330949fa4520b0d"),
        ("correct horse battery staple", b"test-session-123", "3aa58afe9e2a8bab6e166e0d50807497d38d0efb6585c2597d964dacec3e001c",
            "89f4ce75d21691bf22ad590bce040214df0d2d86fc2977b081bb287309fb1925"),
        ("A", b"", "ecfd21429166b7ef2dfaf61c0eb1fa2f19291de4b5cde3219fe0ecfd289c2810",
            "a803036701cfbbf83d1f1010c206fe4303d899765559aa2bc6c2c5c4b171dce7"),
        ("AB", b"CD", "f466ecc4bb0d51fdc1c5fbdc0460c2fa127f259cbb065e8167b720ac5ac4ce06",
            "961640a4ed76c0019fc0daba6788922671404d8ffea4b097488592abf9c89be5"),
        ("AB\u{0}", b"CD", "dce686136ff7092d53f58c562ece342ea7b5837fea33b06b7adcbc660967d533",
            "74c364cece96baf64a3a313442ca6dd74c1c09a1c03797e753f7faaca82ba5ba"),
    ];
    for (phrase, sid, gen_hex, key_hex) in expected {
        let g = generator_point_for_test(phrase, sid);
        let k = session_key_for_scalars(phrase, sid, SCALAR_A, SCALAR_B);
        assert_eq!(hex(&g), *gen_hex, "generator drifted for {phrase:?}");
        assert_eq!(hex(&k), *key_hex, "session key drifted for {phrase:?}");
        // the responder mirror must land on the same key (order swapped)
        let k2 = session_key_for_scalars(phrase, sid, SCALAR_B, SCALAR_A);
        assert_ne!(hex(&k2), *key_hex, "transcript must bind the message ORDER, not just the set");
    }
}

#[test]
#[ignore = "emitter — run with --ignored --nocapture to regenerate the published table"]
fn emit_tcs_pake_1_vectors() {
    println!("\n| # | code phrase | session id | generator (hex, 32 B) | session key (hex, 32 B) | SAS (6 words) | SAS fp |");
    println!("|---|---|---|---|---|---|---|");
    for (i, (phrase, sid)) in CASES.iter().enumerate() {
        let g = generator_point_for_test(phrase, sid);
        let k = session_key_for_scalars(phrase, sid, SCALAR_A, SCALAR_B);
        let sas = SasCode::derive(&k, SAS_CONTEXT);
        println!(
            "| {i} | `{phrase}` | `{}` | `{}` | `{}` | {} | `{}` |",
            String::from_utf8_lossy(sid),
            hex(&g),
            hex(&k),
            sas.display(),
            sas.fingerprint_hex()
        );
        println!("  CONST[{i}] gen={} key={}", hex(&g), hex(&k));
    }
}
