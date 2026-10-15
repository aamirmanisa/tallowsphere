//! Room code generation and room ID derivation
//!
//! **THE join contract (operator directive, 2026-10-12): only the 8-symbol
//! passcode is ACCEPTED.** Every runtime — browser, CLI, TUI — accepts the eight
//! character format and nothing else; the older shapes below are retained for
//! byte-level history (frozen vectors, old-room derivation, the share-slug codec)
//! and are no longer reachable from any user input path. [`is_supported_code`]
//! is the predicate every input boundary must use.
//!
//! Code generations, and what remains reachable:
//! * **v4 passcodes** (since 2026-10-12): eight characters from the
//!   confusable-free 32-char alphabet (2^40) — **the only mint and the only
//!   accepted shape**; also the only shape whose CPace phrase is *derived*
//!   rather than literal;
//! * **v3 passcodes** (2026-09-20): six characters, same alphabet (2^30) —
//!   **RETIRED as input**; derive-only, kept so historical vectors and old-room
//!   derivations stay reproducible. `generate_passcode_v3` exists for fixtures
//!   and benches and must not be wired back into a mint path;
//! * **legacy word/PIN codes**: **RETIRED as input**; derive-only, same reason.
//!
//! Room-ID derivation is shape-routed (**THE compat rule**):
//! * v4-shaped codes (exactly eight ASCII alphanumerics) → Argon2id over 64
//!   bytes, split into room id + CPace phrase ([`derive_room_id_and_phrase_v4`]);
//! * v3-shaped codes (exactly six ASCII alphanumerics) → [`derive_room_id_v2`]
//!   (Argon2id, memory-hard — an observed room id can no longer be inverted
//!   offline at fast-hash cost);
//! * legacy-shaped codes → [`derive_room_id`] (BLAKE3, unchanged) so old
//!   peers, old links, and the CLI's word codes keep pairing.
//!
//! [`resolve_room_id`] is the single decision point every client must use.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use tallow_crypto::kdf::argon2::{derive_key_with_profile, Profile};

/// Default number of words in a code phrase.
///
/// 4 words from the EFF 7776-word list = ~51.7 bits entropy.
/// Sufficient for ephemeral PAKE sessions where offline brute-force
/// is prevented by the relay rate-limiting and session expiry.
pub const DEFAULT_WORD_COUNT: usize = 4;

/// Generate a memorable room code phrase using the EFF Diceware wordlist
///
/// # Arguments
///
/// * `word_count` - Number of words (6 recommended, ~77.5 bits entropy)
pub fn generate_code_phrase(word_count: usize) -> String {
    let wordlist = &tallow_crypto::kdf::eff_wordlist::EFF_WORDLIST;
    let mut rng = OsRng;

    let mut words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        if let Some(word) = wordlist.choose(&mut rng) {
            words.push(*word);
        }
    }

    words.join("-")
}

/// Derive a room ID from a code phrase
///
/// Uses BLAKE3 hash to produce a 32-byte room ID.
/// The relay uses this to pair sender and receiver.
///
/// **Legacy (v1) derivation** — only for legacy-shaped codes; v3 passcodes
/// must go through [`resolve_room_id`] / [`derive_room_id_v2`].
pub fn derive_room_id(code_phrase: &str) -> [u8; 32] {
    blake3::hash(code_phrase.as_bytes()).into()
}

/// Domain-separated salt for the v2 room-id derivation.
///
/// Fixed (not per-code) by necessity — both peers share only the code — and
/// correct by design: every candidate guess pays the full memory-hard cost.
pub const ROOM_ID_V2_SALT: &[u8] = b"tallow-room-id-v2";

/// Derive a room ID with the **v2** derivation: Argon2id (Room profile,
/// 64 MiB / t=3 / p=1) over the canonical code phrase.
///
/// Rationale: the relay routes on the room id, so anyone who observes one
/// (relay operator, logs, network position) could previously enumerate the
/// ~2^30 passcode space with a single fast hash. Memory-hard derivation makes
/// each guess cost ~64 MiB × 3 passes — offline inversion stops being
/// economically viable while a join still costs one derivation (~10³ ms
/// class on phones, faster on desktop).
pub fn derive_room_id_v2(code_phrase: &str) -> [u8; 32] {
    let key = derive_key_with_profile(Profile::Room, code_phrase.as_bytes(), ROOM_ID_V2_SALT, 32)
        .expect("room-id Argon2id derivation cannot fail with valid params");
    let mut out = [0u8; 32];
    out.copy_from_slice(&key);
    out
}

/// Which derivation produced (or should produce) a room id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomIdVersion {
    /// BLAKE3 — legacy codes only.
    V1 = 1,
    /// Argon2id (32-byte output) memory-hard — v3 passcodes.
    V2 = 2,
    /// Argon2id (64-byte output, split into room id + CPace phrase) — v4
    /// passcodes. See [`derive_room_id_and_phrase_v4`].
    V3 = 3,
}

/// **THE accepted-code predicate.** True only for the 8-symbol passcode.
///
/// OPERATOR DIRECTIVE, 2026-10-12: "the app also needs to only strictly accept 8,
/// even the cli". Every input boundary — CLI argument, TUI prompt, browser join
/// field, QR scan — must call this before deriving anything, and must refuse when
/// it is false. The v3 and legacy shapes remain derivable (see the module docs)
/// but are not accepted, so no caller may treat "resolvable" as "joinable".
pub fn is_supported_code(code: &str) -> bool {
    is_v4_passcode(code.trim())
}

/// The user-facing refusal for a code, or `None` when it is accepted.
///
/// The message deliberately names no retired width: the copy rule for this
/// product is that published text names the 8-symbol format only.
pub fn unsupported_code_reason(code: &str) -> Option<&'static str> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return Some("no code given");
    }
    if is_supported_code(trimmed) {
        return None;
    }
    Some("not a valid room code — codes are 8 characters; ask the sender to share the link again")
}

/// True when the code has the v3 passcode shape: exactly six ASCII
/// alphanumerics. Shape decides the derivation version on every client.
///
/// RETIRED as input (see [`is_supported_code`]); kept as a shape detector and for
/// the historical derivation path.
pub fn is_v3_passcode(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// **THE compatibility rule** — resolve `(room id, version)` for any code
/// string. Both peers must run this on the same canonical code and land on
/// the same room.
pub fn resolve_room_id(code_phrase: &str) -> ([u8; 32], RoomIdVersion) {
    if is_v4_passcode(code_phrase) {
        (derive_room_id_v4(code_phrase), RoomIdVersion::V3)
    } else if is_v3_passcode(code_phrase) {
        (derive_room_id_v2(code_phrase), RoomIdVersion::V2)
    } else {
        (derive_room_id(code_phrase), RoomIdVersion::V1)
    }
}

// ---------------------------------------------------------------------------
// v4 passcodes (2026-10-12) — wider space **and** a costed CPace phrase
// ---------------------------------------------------------------------------
//
// Two changes, one shape, because both are wire-compatible breaks and one flag
// day is cheaper than two:
//
// * **space** — eight symbols over the same 32-char confusable-free alphabet =
//   2^40, so a prebuilt inversion table stops being practical (32 TiB) and the
//   fixed salt stops being an amortisation gift to the attacker;
// * **phrase** — the passcode was previously handed to CPace verbatim
//   (`tallow-web/src/kex.rs`), so a captured handshake could be tested against
//   candidates at CPace speed (measured ~0.2–0.4 ms/guess) instead of at
//   Argon2id speed (measured 212 ms/guess). One widened Argon2id call fixes it
//   at **no added join cost**: the first half becomes the room id it already
//   was, the second half becomes the CPace phrase, and the relay never sees the
//   second half.
//
// Derivation is shape-routed exactly like v3 (see [`resolve_room_id`]), so an
// in-flight v3 room, an old share link, and a legacy word code all keep
// pairing on their original derivation.

/// v4 passcode length in characters: 8 × the 32-char alphabet = 2^40.
pub const PASSCODE_LEN_V4: usize = 8;

/// Domain-separated salt for the v4 derivation.
///
/// Distinct from [`ROOM_ID_V2_SALT`] on purpose: v4 must not be "the v2
/// derivation with a longer output", or a table built against v2 would carry
/// value over. A separate salt makes the domain separation structural rather
/// than incidental.
pub const ROOM_ID_V4_SALT: &[u8] = b"tallow-room-id-v4";

/// True when the code has the v4 passcode shape: exactly eight ASCII
/// alphanumerics.
///
/// Deliberately mirrors the v3 rule (length + alphanumeric) rather than
/// enforcing alphabet membership, so both peers route identically; alphabet
/// membership stays a mint-side property. The known compat edge is the same as
/// v3's: a legacy eight-*digit* PIN routes here (a six-digit PIN already routes
/// to v2 under the existing rule).
pub fn is_v4_passcode(code: &str) -> bool {
    code.len() == PASSCODE_LEN_V4 && code.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Derive **both** secrets from a v4 passcode in **one** Argon2id call:
/// `(room id, CPace phrase bytes)`.
///
/// `output[0..32]` = room id (the only half the relay ever learns);
/// `output[32..64]` = CPace phrase (hex-encoded by [`cpace_phrase_for_code`]).
///
/// Cost is one Room-profile evaluation — identical to the v3 derivation — so
/// this adds **no** join latency; that is the whole point of splitting the
/// existing call instead of running a second derivation.
pub fn derive_room_id_and_phrase_v4(code_phrase: &str) -> ([u8; 32], [u8; 32]) {
    let derived =
        derive_key_with_profile(Profile::Room, code_phrase.as_bytes(), ROOM_ID_V4_SALT, 64)
            .expect("v4 Argon2id derivation cannot fail with valid params");

    let mut room_id = [0u8; 32];
    let mut phrase = [0u8; 32];
    room_id.copy_from_slice(&derived[..32]);
    phrase.copy_from_slice(&derived[32..]);
    (room_id, phrase)
}

/// Room id for a v4 passcode (`output[0..32]` of [`derive_room_id_and_phrase_v4`]).
pub fn derive_room_id_v4(code_phrase: &str) -> [u8; 32] {
    derive_room_id_and_phrase_v4(code_phrase).0
}

/// Resolve **room id + CPace phrase + version** for a code in **one**
/// derivation. Preferred over [`resolve_room_id`] plus
/// [`cpace_phrase_for_code`] wherever a handshake will follow, since the latter
/// pair pays two evaluations for a v4 code.
pub fn resolve_room_and_phrase(code_phrase: &str) -> ([u8; 32], String, RoomIdVersion) {
    if is_v4_passcode(code_phrase) {
        let (room_id, phrase) = derive_room_id_and_phrase_v4(code_phrase);
        let mut hex = String::with_capacity(64);
        for byte in phrase {
            hex.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
            hex.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
        }
        (room_id, hex, RoomIdVersion::V3)
    } else if is_v3_passcode(code_phrase) {
        (
            derive_room_id_v2(code_phrase),
            code_phrase.to_string(),
            RoomIdVersion::V2,
        )
    } else {
        (
            derive_room_id(code_phrase),
            code_phrase.to_string(),
            RoomIdVersion::V1,
        )
    }
}

/// The CPace phrase a code maps to.
///
/// * v4 passcodes → lowercase hex of the derivation's second half (64 chars);
/// * v3 and legacy codes → the code itself, unchanged, so existing rooms and
///   old peers keep pairing byte-for-byte.
///
/// Callers that need **both** the room id and the phrase must use
/// [`derive_room_id_and_phrase_v4`] instead of calling this alongside
/// [`derive_room_id_v4`] — two calls would mean two Argon2id evaluations and
/// double the per-join cost.
pub fn cpace_phrase_for_code(code_phrase: &str) -> String {
    if is_v4_passcode(code_phrase) {
        let (_, phrase) = derive_room_id_and_phrase_v4(code_phrase);
        let mut out = String::with_capacity(64);
        for byte in phrase {
            out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
            out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
        }
        out
    } else {
        code_phrase.to_string()
    }
}

/// The v3 passcode alphabet — 32 chars, confusable-free (A–Z minus I/O,
/// 2–9 minus 0/1). Mirror of the web mint in `website/src/lib/code-gen.ts`;
/// keep both in lockstep.
pub const PASSCODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// v3 passcode length in characters.
pub const PASSCODE_LEN: usize = 6;

/// Generate a passcode — **v4** (8 symbols, 2^40) since 2026-10-12.
///
/// `256 % 32 == 0`, so `byte % 32` is bias-free — no rejection sampling, and
/// the same property holds for the wider length (one byte per symbol).
pub fn generate_passcode() -> String {
    mint_passcode(PASSCODE_LEN_V4)
}

/// Generate a **v3** passcode (6 symbols, 2^30).
///
/// Kept for tests, fixtures, and anything that must reproduce a pre-2026-10-12
/// room. New rooms use [`generate_passcode`].
pub fn generate_passcode_v3() -> String {
    mint_passcode(PASSCODE_LEN)
}

/// Mint an `len`-symbol passcode from [`PASSCODE_ALPHABET`].
fn mint_passcode(len: usize) -> String {
    let mut rng = OsRng;
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| PASSCODE_ALPHABET[(b % 32) as usize] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_phrase_default() {
        let code = generate_code_phrase(DEFAULT_WORD_COUNT);
        assert_eq!(code.split('-').count(), 4);

        // All words should be from EFF wordlist
        let wordlist = &tallow_crypto::kdf::eff_wordlist::EFF_WORDLIST;
        for word in code.split('-') {
            assert!(
                wordlist.contains(&word),
                "word '{}' not in EFF wordlist",
                word
            );
        }
    }

    #[test]
    fn test_configurable_word_count() {
        let code3 = generate_code_phrase(3);
        assert_eq!(code3.split('-').count(), 3);

        let code4 = generate_code_phrase(4);
        assert_eq!(code4.split('-').count(), 4);

        let code6 = generate_code_phrase(6);
        assert_eq!(code6.split('-').count(), 6);
    }

    #[test]
    fn test_derive_room_id_deterministic() {
        let id1 = derive_room_id("test-code-phrase");
        let id2 = derive_room_id("test-code-phrase");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_room_id_unique() {
        let id1 = derive_room_id("alpha-bravo-charlie");
        let id2 = derive_room_id("delta-echo-foxtrot");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_custom_code_produces_valid_room_id() {
        let id = derive_room_id("my-custom-code");
        assert_ne!(id, [0u8; 32]);
        // Same code always produces same room ID
        assert_eq!(id, derive_room_id("my-custom-code"));
    }

    #[test]
    fn test_short_codes_produce_unique_room_ids() {
        let id1 = derive_room_id("abcd");
        let id2 = derive_room_id("abce");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_v2_is_deterministic_distinct_and_pinned() {
        let a = derive_room_id_v2("K7M2QP");
        let b = derive_room_id_v2("K7M2QP");
        assert_eq!(a, b, "v2 derivation must be deterministic");
        assert_ne!(
            a,
            derive_room_id("K7M2QP"),
            "v2 must differ from the fast-hash v1 derivation"
        );
        assert_ne!(a, [0u8; 32]);
        // Pinned cross-version vector — an intentional param change in the
        // Room profile must land together with a v3 derivation version.
        let hex: String = a.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f7501e53287f2d0b870d021b5b175c0114d60c0e8457d04e39fc03c4dd529364"
        );
    }

    #[test]
    fn test_passcode_shape_and_resolver() {
        // Shape detection
        assert!(is_v3_passcode("K7M2QP"));
        assert!(is_v3_passcode("k7m2qp"));
        assert!(is_v3_passcode("123456"));
        assert!(!is_v3_passcode("cusp-knee-mayor"));
        assert!(!is_v3_passcode("A7X2"));
        assert!(!is_v3_passcode("A7X2Y3Z"));
        assert!(!is_v3_passcode("AB-2QP"));
        assert!(!is_v3_passcode(""));

        // Resolver: v3-shaped → v2; everything else → v1 (legacy intact).
        let (id_v3, ver_v3) = resolve_room_id("K7M2QP");
        assert_eq!(ver_v3, RoomIdVersion::V2);
        assert_eq!(id_v3, derive_room_id_v2("K7M2QP"));

        let (id_w, ver_w) = resolve_room_id("cusp-knee-mayor");
        assert_eq!(ver_w, RoomIdVersion::V1);
        assert_eq!(id_w, derive_room_id("cusp-knee-mayor"));
        // The legacy word vector stays byte-identical to v1 (compat).
        let expected_v1: [u8; 32] = blake3::hash(b"cusp-knee-mayor").into();
        assert_eq!(id_w, expected_v1);
    }

    #[test]
    fn test_is_supported_code_accepts_only_eight() {
        // Operator directive 2026-10-12: the 8-symbol passcode is the ONLY accepted
        // shape, on every runtime. Each retired shape must be refused, and the
        // refusals must be shapes the derivations can still resolve — the point is
        // that "resolvable" is not "joinable".
        assert!(is_supported_code("K7M2QPHD"));
        assert!(is_supported_code("  K7M2QPHD  "), "surrounding whitespace is trimmed");

        assert!(!is_supported_code("K7M2QP"), "6-symbol passcode is retired");
        assert!(!is_supported_code("K7M2QPH"), "7 symbols");
        assert!(!is_supported_code("K7M2QPHDX"), "9 symbols");
        assert!(!is_supported_code("cusp-knee-mayor"), "word phrase is retired");
        assert!(!is_supported_code("k7f2"), "legacy pin is retired");
        assert!(!is_supported_code("K7M2QPH!"), "punctuation");
        assert!(!is_supported_code(""), "empty");

        // Every refused shape above is still DERIVABLE (history stays reproducible),
        // which is exactly why acceptance cannot be inferred from resolvability.
        for retired in ["K7M2QP", "cusp-knee-mayor", "k7f2"] {
            let _ = resolve_room_and_phrase(retired);
        }
    }

    #[test]
    fn test_unsupported_code_reason_is_none_only_for_accepted_codes() {
        assert_eq!(unsupported_code_reason("K7M2QPHD"), None);
        assert_eq!(unsupported_code_reason("  K7M2QPHD  "), None);

        for refused in ["K7M2QP", "k7f2", "cusp-knee-mayor", "K7M2QPH!"] {
            let reason = unsupported_code_reason(refused).expect("refused shape must explain itself");
            assert!(!reason.is_empty());
            // Copy rule: published text names the 8-symbol format only, so a refusal
            // must not name a retired width.
            assert!(
                !reason.contains("six") && !reason.contains("6 character"),
                "refusal must not name a retired width: {reason:?}"
            );
            assert!(reason.contains("8"), "refusal should name the accepted width");
        }
        assert_eq!(unsupported_code_reason(""), Some("no code given"));
    }

    #[test]
    fn test_generate_passcode_matches_alphabet() {
        // The v4 mint (default since 2026-10-12): 8 symbols, same alphabet.
        for _ in 0..64 {
            let code = generate_passcode();
            assert_eq!(code.len(), PASSCODE_LEN_V4);
            for ch in code.chars() {
                assert!(
                    PASSCODE_ALPHABET.contains(&(ch as u8)),
                    "char '{ch}' outside the v4 alphabet"
                );
                assert!(!ch.is_ascii_lowercase());
            }
        }
        // The v3 mint stays available and unchanged (6 symbols).
        for _ in 0..64 {
            let code = generate_passcode_v3();
            assert_eq!(code.len(), PASSCODE_LEN);
            for ch in code.chars() {
                assert!(
                    PASSCODE_ALPHABET.contains(&(ch as u8)),
                    "char '{ch}' outside the v3 alphabet"
                );
            }
        }
        // Two mints differ (sanity, not a guarantee).
        assert_ne!(generate_passcode(), generate_passcode());
    }

    // -----------------------------------------------------------------------
    // v4 passcodes: A (2^40 space) + C' (derived CPace phrase), 2026-10-12
    // -----------------------------------------------------------------------

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn v4_shape_routes_to_the_v3_derivation_version() {
        assert!(is_v4_passcode("K7M2QPHD"));
        assert!(is_v4_passcode("k7m2qphd")); // case-tolerant, like v3
        assert!(is_v4_passcode("12345678")); // alnum rule; mint is stricter
        assert!(!is_v4_passcode("K7M2QP"));
        assert!(!is_v4_passcode("K7M2QPHDX"));
        assert!(!is_v4_passcode("K7M2-PHD"));
        assert!(!is_v4_passcode(""));

        // THE compat rule, all three shapes at once.
        assert_eq!(resolve_room_id("K7M2QPHD").1, RoomIdVersion::V3);
        assert_eq!(resolve_room_id("K7M2QP").1, RoomIdVersion::V2);
        assert_eq!(resolve_room_id("cusp-knee-mayor").1, RoomIdVersion::V1);
    }

    #[test]
    fn v4_is_one_derivation_split_into_room_id_and_phrase() {
        let code = "K7M2QPHD";
        let (room_id, phrase) = derive_room_id_and_phrase_v4(code);

        // Deterministic, and the halves are not each other.
        assert_eq!(derive_room_id_and_phrase_v4(code), (room_id, phrase));
        assert_ne!(room_id, phrase);
        assert_eq!(derive_room_id_v4(code), room_id);

        // Exactly the 64-byte derivation, split 32/32 — no second evaluation.
        let full = tallow_crypto::kdf::argon2::derive_key_with_profile(
            tallow_crypto::kdf::argon2::Profile::Room,
            code.as_bytes(),
            ROOM_ID_V4_SALT,
            64,
        )
        .expect("derivation");
        assert_eq!(&room_id[..], &full[..32]);
        assert_eq!(&phrase[..], &full[32..]);

        // The CPace phrase is hex of the second half — and never the code.
        let hex = cpace_phrase_for_code(code);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, hex_of(&phrase));
        assert_ne!(hex, code);
    }

    #[test]
    fn v4_is_domain_separated_from_v2() {
        // Same password text through the two salts must not collide: v4 must
        // not be "v2 with a longer output", or a v2 table would carry value.
        let code = "K7M2QPHD";
        let v4_room = derive_room_id_v4(code);
        let v2_style = tallow_crypto::kdf::argon2::derive_key_with_profile(
            tallow_crypto::kdf::argon2::Profile::Room,
            code.as_bytes(),
            ROOM_ID_V2_SALT,
            32,
        )
        .expect("derivation");
        assert_ne!(&v4_room[..], &v2_style[..]);
    }

    #[test]
    fn v2_and_v1_phrases_are_unchanged_by_the_v4_work() {
        // Regression guard for in-flight v3 rooms and old links: their CPace
        // phrase stays the literal code.
        assert_eq!(cpace_phrase_for_code("K7M2QP"), "K7M2QP");
        assert_eq!(cpace_phrase_for_code("cusp-knee-mayor"), "cusp-knee-mayor");
        // And the pinned v2 vector is untouched by the new salt.
        let v2 = derive_room_id_v2("K7M2QP");
        assert_eq!(
            hex_of(&v2),
            "f7501e53287f2d0b870d021b5b175c0114d60c0e8457d04e39fc03c4dd529364"
        );
    }
}
