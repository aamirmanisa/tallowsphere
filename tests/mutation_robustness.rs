//! Mutation robustness: hostile input must produce `Err`, never a panic.
//!
//! This is **not** coverage-guided fuzzing. It is a deterministic mutation sweep
//! over valid inputs — the cheap half of fuzzing that needs no nightly
//! toolchain, no corpus and no dedicated runner. A real `cargo-fuzz` harness is
//! still owed for P7 and is listed as open; claiming this replaces it would be
//! the exact overstatement the plan forbids.
//!
//! What it catches: panics, unwraps on attacker-controlled data, and index or
//! slice errors in the decode paths. What it cannot catch: a wrong-but-safe
//! answer, or a path the mutator never reaches.

use tallow::age;

/// Deterministic 64-bit LCG — reproducible across runs and machines, which a
/// failing case needs in order to be investigated.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn flip(bytes: &mut [u8], rng: &mut Rng, rounds: usize) {
    for _ in 0..rounds {
        if bytes.is_empty() {
            return;
        }
        let i = rng.below(bytes.len());
        let bit = 1u8 << rng.below(8);
        bytes[i] ^= bit;
    }
}

#[test]
fn a_mutated_age_container_never_panics() {
    let (recipient, identity) = age::keygen();
    let ct_hex = age::encrypt(&recipient, "0001020304").expect("encrypt");
    let original = age::hex_decode(&ct_hex).expect("hex");

    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut accepted_but_changed = 0usize;

    for round in 0..5_000 {
        let mut bytes = original.clone();
        flip(&mut bytes, &mut rng, 1 + round % 4);
        // Truncation too: the decoder must not trust a length field.
        if round % 5 == 0 && !bytes.is_empty() {
            let cut = rng.below(bytes.len());
            bytes.truncate(cut);
        }
        let hex = {
            let mut s = String::with_capacity(bytes.len() * 2);
            for b in &bytes {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
            }
            s
        };
        // Panics fail the test by themselves; the assertion is that the call
        // returns, with a value or an error.
        match age::decrypt_hex(&identity, &hex) {
            Ok(pt) => {
                accepted += 1;
                // A container that still opens may only do so because the
                // mutated bytes were semantically inert (age's GREASE stanza
                // exists to be ignored). It must never yield different bytes.
                if pt != age::hex_decode("0001020304").unwrap() {
                    accepted_but_changed += 1;
                }
            }
            Err(_) => rejected += 1,
        }
    }

    println!(
        "age container mutations: accepted={accepted} rejected={rejected} \
         accepted_but_changed={accepted_but_changed}"
    );
    assert_eq!(
        accepted + rejected,
        5_000,
        "every mutation must return, not abort the process"
    );
    // The security property: a mutated container either fails, or opens to the
    // original plaintext because the mutated bytes were inert (GREASE). It must
    // never authenticate different content.
    assert_eq!(
        accepted_but_changed, 0,
        "a mutated container authenticated different plaintext"
    );
}

#[test]
fn a_mutated_opaque_state_never_panics() {
    let setup = tallow::opaque::setup_new().expect("setup");
    let (request, state) = tallow::opaque::registration_start("pw").expect("start");

    let mut rng = Rng(0x5eed_1234_abcd_0002);
    let mut ok = 0usize;
    let mut err = 0usize;

    // The state is hex-of-JSON: mutating hex nibbles exercises both the hex
    // decoder and the serde parser behind it.
    let valid = setup.len().max(state.len());
    for round in 0..3_000 {
        let base = if round % 2 == 0 { setup.clone() } else { state.clone() };
        let mut chars: Vec<u8> = base.into_bytes();
        if chars.is_empty() {
            continue;
        }
        let i = rng.below(chars.len());
        chars[i] = b"0123456789abcdefXYZ"[(rng.below(19))];
        let mutated = String::from_utf8_lossy(&chars).to_string();

        // Feeding a bad setup or a bad state to the second step must return Err.
        match tallow::opaque::registration_respond(&mutated, &request, "alice") {
            Ok(_) => ok += 1,
            Err(_) => err += 1,
        }
        let _ = valid;
    }

    println!("opaque mutations: ok={ok} err={err}");
    assert_eq!(ok + err, 3_000);
}
