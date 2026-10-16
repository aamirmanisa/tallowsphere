//! Deniable storage — chaff + hidden-region container model
//! (frozen interface §3 / B7.3.1–B7.3.3).
//!
//! A deniable container is a byte buffer ([`Vec<u8>`]; this module performs no
//! disk I/O) that carries two *unlock contexts* over one file:
//!
//! * a **visible plane** — plain bytes readable by
//!   [`open_visible`] with no key at all, and
//! * an optional **hidden region** — key-encrypted bytes readable only by
//!   [`open_hidden`] with the right key.
//!
//! The visible plane doubles as plausible content for the file's existence;
//! the hidden region is invisible to a reader who opens the visible plane
//! (and unforgeable to a reader without the key: [`open_hidden`] returns
//! [`DeniabilityError::None`]-free `Ok(None)` only when the container itself
//! declares no hidden region).
//!
//! ## Construction (v1, pinned by tests)
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! MAGIC "TDLV0001" (8 B) ‖ u32 visible_len ‖ visible bytes ‖ u32 hidden_field
//!   ‖ salt (8 B) ‖ body
//! ```
//!
//! `hidden_field` is a **presence-encoded length**: `0` = no hidden region;
//! `n ≥ 1` = a hidden region of `n − 1` bytes. (A raw length cannot satisfy
//! the frozen requirement that `hidden: Some(b"")` round-trips *and*
//! `0` means "none" simultaneously; see the §3 notes in
//! `docs/ops/deniability.md`.)
//!
//! * `salt` = first 8 bytes of `SHA-256("tdlv1-salt" ‖ seed_le64 ‖
//!   visible_len_le64 ‖ visible)`.
//! * `body` length = `2 · payload_len + jitter`, `payload_len = hidden_len +
//!   32`, `jitter = 32 + (salt_le64 mod 64)` ∈ `[32, 95]`. When no hidden
//!   region is present the body is sized with `payload_len = 32` so a
//!   visible-only container has the same outer length distribution as an
//!   empty-hidden one.
//! * The body starts as [`chaff_stream`]`(seed, body_len)` — a deterministic
//!   splitmix64 byte stream. With a hidden region, the *payload* (ciphertext
//!   ‖ 32-byte tag) overwrites the chaff at `payload_len` scattered
//!   **shard** positions derived from the salt (see [`scatter_positions`]);
//!   every shard is a single byte and no two shards are adjacent, so no
//!   payload run is ever contiguous in the body.
//! * Ciphertext = plaintext XOR keystream, where keystream block `i` is
//!   `HMAC-SHA256(key, "tdlv1" ‖ counter_le64(i))` (counter starts at 0).
//! * Tag = `HMAC-SHA256(key, plaintext)`, stored as the trailing 32 payload
//!   bytes; [`open_hidden`] verifies it in constant time via
//!   [`Mac::verify_slice`] — a wrong key fails the tag
//!   ([`DeniabilityError::BadKey`]).
//!
//! ## Limits (read before trusting this module)
//!
//! This is **obfuscation-grade, NOT audited cryptography**: the visible
//! plane is unauthenticated by design, chaff bytes are unauthenticated
//! filler, and the keystream/tag construction below has had no external
//! review. Size metadata (the container length and the declared lengths in
//! the header) is still observable. See `docs/ops/deniability.md` for the
//! full list of stated limits.

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Container magic, version 1 (`TDLV0001`), pinned by test.
pub const MAGIC: &[u8; 8] = b"TDLV0001";

/// Length of the trailing HMAC-SHA256 authentication tag, in bytes.
const TAG_LEN: usize = 32;

/// Domain separator for the HMAC-SHA256-CTR keystream (frozen §3, verbatim).
const KEYSTREAM_DOMAIN: &[u8] = b"tdlv1";

/// Domain separator for the salt derivation (build-side only).
const SALT_LABEL: &[u8] = b"tdlv1-salt";

/// Errors from building or opening deniable containers.
///
/// Serialize-only (the `&'static str` payload cannot deserialize without a
/// `'static` borrow — house `Serialize`-only precedent for this shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DeniabilityError {
    /// Invalid input field (the payload names the field).
    BadInput(&'static str),
    /// Structurally corrupt buffer: bad magic, truncated, non-canonical
    /// body length, or undecodable lengths.
    Corrupt,
    /// The hidden region's authentication tag rejected the key (wrong key,
    /// or a tampered payload byte / salt).
    BadKey,
}

impl std::fmt::Display for DeniabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeniabilityError::BadInput(field) => {
                write!(f, "invalid deniability input: {field}")
            }
            DeniabilityError::Corrupt => write!(f, "corrupt deniable container"),
            DeniabilityError::BadKey => write!(f, "hidden region key rejected"),
        }
    }
}

impl std::error::Error for DeniabilityError {}

/// Deterministic splitmix64 byte stream (chaff filler).
///
/// Same `seed`/`len` ⇒ byte-identical output; a different seed differs for
/// `len > 8` (frozen §3 pin; in fact splitmix64 is injective on the first
/// word, so distinct seeds differ for `len ≥ 1`). Bytes are produced 8 at a
/// time, little-endian per word, and a final partial word is truncated —
/// so `chaff_stream(s, n)` is always a prefix of `chaff_stream(s, m)` for
/// `n ≤ m`.
pub fn chaff_stream(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let word = splitmix64(&mut state).to_le_bytes();
        let take = (len - out.len()).min(8);
        out.extend_from_slice(&word[..take]);
    }
    out
}

/// One splitmix64 step: advance `state`, return the next 64-bit output.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Build a container holding `visible` (plain) and, when `hidden` is
/// `Some`, an HMAC-SHA256-CTR-encrypted hidden region with an auth tag.
///
/// Refusals (payload = field name):
/// * `visible` longer than `u32::MAX` bytes → `BadInput("visible")`;
/// * `hidden` longer than `u32::MAX − 1` bytes → `BadInput("hidden")`;
/// * hidden region present and `key` empty → `BadInput("key")`.
///
/// An empty `key` with no hidden region is fine (the key is unused).
/// Building is fully deterministic: identical inputs produce byte-identical
/// containers.
pub fn build_container(
    visible: &[u8],
    hidden: Option<&[u8]>,
    key: &[u8],
    seed: u64,
) -> Result<Vec<u8>, DeniabilityError> {
    if visible.len() > u32::MAX as usize {
        return Err(DeniabilityError::BadInput("visible"));
    }
    if let Some(h) = hidden {
        if h.len() > (u32::MAX as usize) - 1 {
            return Err(DeniabilityError::BadInput("hidden"));
        }
    }
    if hidden.is_some() && key.is_empty() {
        return Err(DeniabilityError::BadInput("key"));
    }

    let salt = derive_salt(seed, visible);
    let hidden_field: u32 = match hidden {
        None => 0,
        Some(h) => h.len() as u32 + 1,
    };
    let hidden_len = hidden.map_or(0, |h| h.len());
    let payload_len = hidden_len + TAG_LEN;
    let body_len = 2 * payload_len + body_jitter(&salt);

    let mut body = chaff_stream(seed, body_len);
    if let Some(h) = hidden {
        // Payload = ciphertext (HMAC-SHA256-CTR) ‖ tag (HMAC over plaintext).
        let keystream = keystream_bytes(key, hidden_len);
        let mut payload = vec![0u8; payload_len];
        for (i, &byte) in h.iter().enumerate() {
            payload[i] = byte ^ keystream[i];
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(h);
        payload[hidden_len..].copy_from_slice(&mac.finalize().into_bytes());

        let positions = scatter_positions(&salt, body_len, payload_len);
        debug_assert_eq!(positions.len(), payload_len);
        for (pos, byte) in positions.iter().zip(payload) {
            body[*pos] = byte;
        }
    }

    let mut out = Vec::with_capacity(24 + visible.len() + body_len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(visible.len() as u32).to_le_bytes());
    out.extend_from_slice(visible);
    out.extend_from_slice(&hidden_field.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open the **visible plane**: validate magic/lengths and return the visible
/// bytes. No key is involved; this never fails on a well-formed container,
/// whatever its hidden region contains.
///
/// [`DeniabilityError::Corrupt`] for: bad magic, a truncated buffer, or a
/// body whose length is not the canonical one for the declared header
/// (i.e. any truncation or appending, and most header field tampering).
pub fn open_visible(c: &[u8]) -> Result<Vec<u8>, DeniabilityError> {
    Ok(parse_container(c)?.visible.to_vec())
}

/// Open the **hidden region** with `key`.
///
/// * `Ok(None)` — the container declares no hidden region (empty `key` is
///   fine in that case).
/// * `Ok(Some(plaintext))` — the trailing HMAC-SHA256 tag verified; the
///   reassembled, decrypted plaintext is returned (may be empty).
/// * [`DeniabilityError::BadInput`]`("key")` — empty `key` but a hidden
///   region is present.
/// * [`DeniabilityError::BadKey`] — tag verification failed (wrong key, or
///   a tampered payload shard / salt).
/// * [`DeniabilityError::Corrupt`] — structural failure (see
///   [`open_visible`]).
///
/// Tag verification is constant-time (`hmac`'s [`Mac::verify_slice`]).
pub fn open_hidden(c: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, DeniabilityError> {
    let parsed = parse_container(c)?;
    if parsed.hidden_field == 0 {
        return Ok(None);
    }
    if key.is_empty() {
        return Err(DeniabilityError::BadInput("key"));
    }

    let hidden_len = parsed.hidden_field as usize - 1;
    let payload_len = hidden_len + TAG_LEN;
    let positions = scatter_positions(&parsed.salt, parsed.body.len(), payload_len);
    let payload: Vec<u8> = positions.iter().map(|&pos| parsed.body[pos]).collect();
    if payload.len() != payload_len {
        return Err(DeniabilityError::Corrupt);
    }
    let (ciphertext, tag) = payload.split_at(hidden_len);

    let keystream = keystream_bytes(key, hidden_len);
    let mut plaintext = ciphertext.to_vec();
    for (byte, k) in plaintext.iter_mut().zip(keystream) {
        *byte ^= k;
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(&plaintext);
    mac.verify_slice(tag).map_err(|_| DeniabilityError::BadKey)?;
    Ok(Some(plaintext))
}

/// Parsed header + body of a structurally valid container.
struct Parsed<'a> {
    visible: &'a [u8],
    /// Presence-encoded length: 0 = no hidden region, `n ≥ 1` = `n − 1` bytes.
    hidden_field: u32,
    salt: [u8; 8],
    body: &'a [u8],
}

/// Parse and structurally validate a container.
///
/// Validation order (pinned by tests):
/// 1. at least the fixed 12-byte prefix; 2. magic; 3. the full
/// declared header (`24 + visible_len`); 4. canonical body length
/// `2·payload_len(hidden_field) + jitter(salt)`.
fn parse_container(c: &[u8]) -> Result<Parsed<'_>, DeniabilityError> {
    use DeniabilityError::Corrupt;
    if c.len() < 12 {
        return Err(Corrupt);
    }
    if &c[..8] != &MAGIC[..] {
        return Err(Corrupt);
    }
    let visible_len = u32::from_le_bytes(c[8..12].try_into().expect("4 bytes")) as usize;
    let hidden_off = 12usize.checked_add(visible_len).ok_or(Corrupt)?;
    let salt_off = hidden_off.checked_add(4).ok_or(Corrupt)?;
    let body_off = salt_off.checked_add(8).ok_or(Corrupt)?;
    if c.len() < body_off {
        return Err(Corrupt);
    }

    let hidden_field =
        u32::from_le_bytes(c[hidden_off..salt_off].try_into().expect("4 bytes"));
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&c[salt_off..body_off]);
    let body = &c[body_off..];

    let expected = expected_body_len(hidden_field, &salt).ok_or(Corrupt)?;
    if body.len() != expected {
        return Err(Corrupt);
    }
    Ok(Parsed {
        visible: &c[12..hidden_off],
        hidden_field,
        salt,
        body,
    })
}

/// `payload_len` for a presence-encoded hidden field (`None` on overflow).
fn payload_len_for(hidden_field: u32) -> Option<usize> {
    let hidden_len = if hidden_field == 0 {
        0
    } else {
        (hidden_field as usize) - 1
    };
    hidden_len.checked_add(TAG_LEN)
}

/// Canonical body length: `2 · payload_len + jitter(salt)` (`None` on overflow).
fn expected_body_len(hidden_field: u32, salt: &[u8; 8]) -> Option<usize> {
    payload_len_for(hidden_field)?
        .checked_mul(2)?
        .checked_add(body_jitter(salt))
}

/// Salt-derived body padding, `32 + (salt_le64 mod 64)` ∈ `[32, 95]`.
fn body_jitter(salt: &[u8; 8]) -> usize {
    32 + (u64::from_le_bytes(*salt) % 64) as usize
}

/// Salt derivation: first 8 bytes of
/// `SHA-256("tdlv1-salt" ‖ seed_le64 ‖ visible_len_le64 ‖ visible)`.
///
/// Deliberately independent of the hidden region *and* of the key, so the
/// outer shape of a container never leaks key material and a visible-only
/// container shares its outer shape with an empty-hidden one.
fn derive_salt(seed: u64, visible: &[u8]) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(SALT_LABEL);
    hasher.update(seed.to_le_bytes());
    hasher.update((visible.len() as u64).to_le_bytes());
    hasher.update(visible);
    let digest = hasher.finalize();
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&digest[..8]);
    salt
}

/// Scatter rule (frozen §3, pinned by tests): the body's **even** indices
/// `0, 2, …, 2·(⌈body_len/2⌉ − 1)` are the candidate slots; a
/// salt-seeded splitmix64 Fisher–Yates shuffle orders them; the first
/// `count` slots are taken, converted back to even body positions, and
/// sorted ascending.
///
/// Because every shard position is even, no two shards are ever adjacent
/// (minimum gap 2 — at least one chaff byte between shards), so hidden
/// payload bytes are never contiguous in the body. `count` is clamped to
/// the number of slots (canonical containers always have enough slots).
fn scatter_positions(salt: &[u8; 8], body_len: usize, count: usize) -> Vec<usize> {
    let slots_len = body_len.div_ceil(2);
    let count = count.min(slots_len);
    let mut slots: Vec<usize> = (0..slots_len).collect();
    let mut state = u64::from_le_bytes(*salt);
    for i in (1..slots_len).rev() {
        let j = (splitmix64(&mut state) % (i as u64 + 1)) as usize;
        slots.swap(i, j);
    }
    let mut chosen: Vec<usize> = slots.into_iter().take(count).map(|s| 2 * s).collect();
    chosen.sort_unstable();
    chosen
}

/// HMAC-SHA256-CTR keystream: block `i` = `HMAC(key, "tdlv1" ‖
/// counter_le64(i))`, counter starting at 0; `len` bytes total.
fn keystream_bytes(key: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(KEYSTREAM_DOMAIN);
        mac.update(&counter.to_le_bytes());
        let block = mac.finalize().into_bytes();
        let take = (len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Distinctive hidden fixture (no natural byte runs to confuse the
    /// verbatim-absence checks).
    const HIDDEN: &[u8] = b"TOPSECRET-HIDDEN-REGION-0123456789-TOPSECRET";

    #[test]
    fn magic_and_header_layout_pinned() {
        assert_eq!(MAGIC, b"TDLV0001");
        let v = b"visible-plane";
        let c = build_container(v, None, b"", 7).unwrap();
        assert_eq!(&c[..8], &MAGIC[..]);
        assert_eq!(
            u32::from_le_bytes(c[8..12].try_into().unwrap()) as usize,
            v.len()
        );
        assert_eq!(&c[12..12 + v.len()], &v[..]);
        let off = 12 + v.len();
        assert_eq!(
            u32::from_le_bytes(c[off..off + 4].try_into().unwrap()),
            0,
            "no hidden region ⇒ hidden_field is 0"
        );
        assert_eq!(c.len(), 24 + v.len() + 64 + body_jitter(&{
            let mut s = [0u8; 8];
            s.copy_from_slice(&c[off + 4..off + 12]);
            s
        }));
    }

    #[test]
    fn salt_derivation_and_body_length_pinned() {
        let v = b"salty";
        let seed = 0x0123_4567_89AB_CDEFu64;
        let c = build_container(v, Some(HIDDEN), b"k", seed).unwrap();
        let off = 12 + v.len();
        let salt: [u8; 8] = c[off + 4..off + 12].try_into().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"tdlv1-salt");
        hasher.update(seed.to_le_bytes());
        hasher.update((v.len() as u64).to_le_bytes());
        hasher.update(v);
        let digest = hasher.finalize();
        assert_eq!(&salt[..], &digest[..8], "salt = SHA-256(...)[..8]");

        // Canonical body length: 2·(hidden_len + 32) + jitter.
        let expect = 24 + v.len() + 2 * (HIDDEN.len() + TAG_LEN) + body_jitter(&salt);
        assert_eq!(c.len(), expect);
    }

    #[test]
    fn chaff_stream_deterministic_and_seed_sensitive() {
        assert_eq!(chaff_stream(42, 64), chaff_stream(42, 64));
        assert!(chaff_stream(42, 0).is_empty());
        // Prefix property incl. sub-word truncation.
        assert_eq!(chaff_stream(42, 3), chaff_stream(42, 8)[..3].to_vec());
        // Frozen pin: different seeds differ for len > 8…
        assert_ne!(chaff_stream(1, 16), chaff_stream(2, 16));
        assert_ne!(chaff_stream(0, 9), chaff_stream(u64::MAX, 9));
        // …and here even from the first word (splitmix64 is injective).
        assert_ne!(chaff_stream(1, 8), chaff_stream(2, 8));
    }

    #[test]
    fn keystream_formula_pinned() {
        let key = b"ks-pin-key";
        let ks = keystream_bytes(key, 48);
        let mut expected = Vec::new();
        for counter in 0u64..2 {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(b"tdlv1");
            mac.update(&counter.to_le_bytes());
            expected.extend_from_slice(&mac.finalize().into_bytes());
        }
        assert_eq!(ks, expected[..48].to_vec());
        // Block alignment: byte 32 starts block 1.
        assert_eq!(keystream_bytes(key, 33)[32], expected[32]);
    }

    #[test]
    fn payload_placement_and_tag_pinned() {
        let v = b"visible-bytes";
        let key = b"placement-key";
        let c = build_container(v, Some(HIDDEN), key, 21).unwrap();
        let p = parse_container(&c).unwrap();
        let positions = scatter_positions(&p.salt, p.body.len(), HIDDEN.len() + TAG_LEN);

        let ks = keystream_bytes(key, HIDDEN.len());
        let mut expected: Vec<u8> = HIDDEN.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(HIDDEN);
        expected.extend_from_slice(&mac.finalize().into_bytes());

        assert_eq!(positions.len(), expected.len());
        for (i, &pos) in positions.iter().enumerate() {
            assert_eq!(p.body[pos], expected[i], "payload byte {i} at scatter {pos}");
        }
        // Plaintext never appears verbatim anywhere in the container.
        assert!(!c.windows(HIDDEN.len()).any(|w| w == HIDDEN));
    }

    #[test]
    fn scatter_positions_stride_rule_pinned() {
        let salt = [7u8; 8];
        let body_len = 200usize;
        let count = 16usize;
        let pos = scatter_positions(&salt, body_len, count);
        assert_eq!(pos.len(), count);
        assert_eq!(pos, scatter_positions(&salt, body_len, count), "deterministic");
        // Ascending, in range, all even (stride rule), never adjacent.
        assert!(pos.iter().all(|&p| p < body_len && p % 2 == 0));
        assert!(pos.windows(2).all(|w| w[0] < w[1]));
        assert!(pos.windows(2).all(|w| w[1] - w[0] >= 2));
        // Genuine salt-shuffled selection: a proper subset, not the prefix
        // lattice {0, 2, 4, …}.
        let prefix: Vec<usize> = (0..count).map(|i| 2 * i).collect();
        assert_ne!(pos, prefix);
        assert_ne!(pos, scatter_positions(&[8u8; 8], body_len, count));
        // Same salt but a different body/count still separates shards.
        let sparse = scatter_positions(&salt, 500, 8);
        assert_eq!(sparse.len(), 8);
        assert!(sparse.windows(2).all(|w| w[1] - w[0] >= 2));
    }

    #[test]
    fn scatter_shards_not_contiguous() {
        let c = build_container(b"v", Some(b"0123456789abcdef"), b"k", 2).unwrap();
        let p = parse_container(&c).unwrap();
        let pos = scatter_positions(&p.salt, p.body.len(), 16 + TAG_LEN);
        let mut is_shard = vec![false; p.body.len()];
        for &q in &pos {
            is_shard[q] = true;
        }
        let mut run = 0usize;
        let mut max_run = 0usize;
        for i in 0..p.body.len() {
            if is_shard[i] {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 0;
            }
        }
        assert_eq!(max_run, 1, "no two payload bytes are adjacent in the body");
    }

    #[test]
    fn visible_only_roundtrip() {
        let v = b"plain visible payload";
        let c = build_container(v, None, b"", 9).unwrap();
        assert_eq!(open_visible(&c).unwrap(), v);
        assert_eq!(open_hidden(&c, b"anything").unwrap(), None);
        // Empty key + no hidden region ⇒ still Ok(None), not BadInput.
        assert_eq!(open_hidden(&c, b"").unwrap(), None);
    }

    #[test]
    fn visible_hidden_roundtrip() {
        let v = b"visible plane";
        let key = b"s3cret-key";
        let c = build_container(v, Some(HIDDEN), key, 11).unwrap();
        assert_eq!(open_visible(&c).unwrap(), v);
        assert_eq!(open_hidden(&c, key).unwrap(), Some(HIDDEN.to_vec()));
        // Repeated open is deterministic.
        assert_eq!(open_hidden(&c, key).unwrap(), open_hidden(&c, key).unwrap());
    }

    #[test]
    fn empty_hidden_roundtrip_and_presence_flag() {
        let v = b"v";
        let none = build_container(v, None, b"", 5).unwrap();
        let empty = build_container(v, Some(b""), b"k", 5).unwrap();
        assert_eq!(open_hidden(&empty, b"k").unwrap(), Some(Vec::new()));
        assert_eq!(open_hidden(&none, b"k").unwrap(), None);
        // Presence encoding: 0 = absent, n + 1 = present with n bytes.
        let off = 12 + v.len();
        assert_eq!(
            u32::from_le_bytes(none[off..off + 4].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(empty[off..off + 4].try_into().unwrap()),
            1
        );
        // Same outer length for absent vs empty-hidden (uniform shape)…
        assert_eq!(none.len(), empty.len());
        // …while the containers themselves still differ (flag + payload).
        assert_ne!(none, empty);
        // Wrong key on an empty-hidden region still fails the tag.
        assert_eq!(
            open_hidden(&empty, b"x").unwrap_err(),
            DeniabilityError::BadKey
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let key = b"right-key";
        let c = build_container(b"v", Some(HIDDEN), key, 3).unwrap();
        assert_eq!(
            open_hidden(&c, b"wrong-key").unwrap_err(),
            DeniabilityError::BadKey
        );
        assert_eq!(
            open_hidden(&c, b"righT-key").unwrap_err(),
            DeniabilityError::BadKey,
            "same-length wrong key"
        );
        assert_eq!(
            open_hidden(&c, b"right-key-plus-more").unwrap_err(),
            DeniabilityError::BadKey,
            "longer wrong key"
        );
        // The right key still works afterwards (no state burned).
        assert_eq!(open_hidden(&c, key).unwrap(), Some(HIDDEN.to_vec()));
    }

    #[test]
    fn hidden_bytes_do_not_appear_verbatim() {
        let v = b"outer layer";
        let key = b"verbatim-key";
        let c = build_container(v, Some(HIDDEN), key, 6).unwrap();
        assert!(!c.windows(HIDDEN.len()).any(|w| w == HIDDEN));
        assert!(!open_visible(&c).unwrap().windows(HIDDEN.len()).any(|w| w == HIDDEN));
        // The gathered payload is ciphertext, not a copy of the plaintext.
        let p = parse_container(&c).unwrap();
        let positions = scatter_positions(&p.salt, p.body.len(), HIDDEN.len() + TAG_LEN);
        let gathered: Vec<u8> = positions.iter().map(|&q| p.body[q]).collect();
        assert_ne!(&gathered[..HIDDEN.len()], HIDDEN);
    }

    #[test]
    fn tamper_scenarios_pinned() {
        let v = b"visible-stays";
        let key = b"tamper-key";
        let c = build_container(v, Some(HIDDEN), key, 33).unwrap();
        let p = parse_container(&c).unwrap();
        let positions = scatter_positions(&p.salt, p.body.len(), HIDDEN.len() + TAG_LEN);
        let shards: BTreeSet<usize> = positions.iter().copied().collect();
        let body_off = c.len() - p.body.len();

        // (1) bad magic byte ⇒ Corrupt for both openers.
        let mut m = c.clone();
        m[0] ^= 0x01;
        assert_eq!(open_visible(&m).unwrap_err(), DeniabilityError::Corrupt);
        assert_eq!(open_hidden(&m, key).unwrap_err(), DeniabilityError::Corrupt);

        // (2) truncation ⇒ Corrupt for both openers.
        let t = &c[..c.len() - 1];
        assert_eq!(open_visible(t).unwrap_err(), DeniabilityError::Corrupt);
        assert_eq!(open_hidden(t, key).unwrap_err(), DeniabilityError::Corrupt);

        // (3) appending ⇒ Corrupt (canonical body-length check).
        let mut a = c.clone();
        a.push(0);
        assert_eq!(open_visible(&a).unwrap_err(), DeniabilityError::Corrupt);
        assert_eq!(open_hidden(&a, key).unwrap_err(), DeniabilityError::Corrupt);

        // (4) chaff-position tamper ⇒ undetected (chaff is unauthenticated
        // filler): both openers still succeed, hidden payload intact.
        let chaff_idx = (0..p.body.len()).find(|i| !shards.contains(i)).unwrap();
        let mut ch = c.clone();
        ch[body_off + chaff_idx] ^= 0xFF;
        assert_eq!(open_visible(&ch).unwrap(), v);
        assert_eq!(open_hidden(&ch, key).unwrap(), Some(HIDDEN.to_vec()));

        // (5) shard-position tamper ⇒ BadKey (payload auth); visible plane
        // is unaffected.
        let mut sh = c.clone();
        sh[body_off + positions[0]] ^= 0x01;
        assert_eq!(open_visible(&sh).unwrap(), v);
        assert_eq!(open_hidden(&sh, key).unwrap_err(), DeniabilityError::BadKey);

        // (6) hidden-field tamper ⇒ Corrupt (canonical body length no longer
        // matches the declared hidden region).
        let off = 12 + v.len();
        let mut hf = c.clone();
        hf[off..off + 4].copy_from_slice(&(HIDDEN.len() as u32 + 2).to_le_bytes());
        assert_eq!(open_hidden(&hf, key).unwrap_err(), DeniabilityError::Corrupt);

        // (7) visible-plane byte tamper ⇒ NOT authenticated (documented
        // limit): open_visible returns the modified bytes, hidden region
        // still opens.
        let mut vt = c.clone();
        vt[12] ^= 0x01;
        let mut expected_v = v.to_vec();
        expected_v[0] ^= 0x01;
        assert_eq!(open_visible(&vt).unwrap(), expected_v);
        assert_eq!(open_hidden(&vt, key).unwrap(), Some(HIDDEN.to_vec()));
    }

    #[test]
    fn salt_tamper_is_detected() {
        let v = b"v";
        let key = b"k";
        let c = build_container(v, Some(HIDDEN), key, 44).unwrap();
        let off = 16 + v.len();

        // (a) Low salt byte flip: the salt feeds the canonical body-length
        // check via the jitter, so this fixture (jitter 41 → 40) is a
        // deterministic Corrupt — for open_hidden *and* open_visible.
        let mut t = c.clone();
        t[off] ^= 0x01;
        assert_eq!(open_hidden(&t, key).unwrap_err(), DeniabilityError::Corrupt);
        assert_eq!(open_visible(&t).unwrap_err(), DeniabilityError::Corrupt);

        // (b) High salt byte flip: `2^56 mod 64 == 0`, so the jitter (and
        // thus the canonical body length) is unchanged; the scatter seed
        // changes instead and the tag check catches it → BadKey. The
        // visible plane is independent and still opens.
        let mut t2 = c.clone();
        t2[off + 7] ^= 0x01;
        assert_eq!(open_hidden(&t2, key).unwrap_err(), DeniabilityError::BadKey);
        assert_eq!(open_visible(&t2).unwrap(), v);
    }

    #[test]
    fn overlay_safety_visible_extraction_unaffected_by_hidden() {
        let v = b"identical visible plane";
        let a = build_container(v, None, b"", 55).unwrap();
        let b = build_container(v, Some(b"different hidden region"), b"key-x", 55).unwrap();
        let c = build_container(v, Some(b"x"), b"key-y", 55).unwrap();
        assert_eq!(open_visible(&a).unwrap(), open_visible(&b).unwrap());
        assert_eq!(open_visible(&a).unwrap(), open_visible(&c).unwrap());
        assert_eq!(open_visible(&a).unwrap(), v);
    }

    #[test]
    fn build_deterministic_and_seed_sensitive() {
        let v = b"determinism";
        let key = b"det-key";
        let a = build_container(v, Some(HIDDEN), key, 66).unwrap();
        let b = build_container(v, Some(HIDDEN), key, 66).unwrap();
        assert_eq!(a, b, "identical inputs ⇒ byte-identical container");
        assert_ne!(a, build_container(v, Some(HIDDEN), key, 67).unwrap());
        // The chaff body alone is seed-sensitive too.
        assert_ne!(
            build_container(v, None, b"", 1).unwrap(),
            build_container(v, None, b"", 2).unwrap()
        );
    }

    #[test]
    fn error_cases_pinned() {
        // Empty key + hidden region ⇒ BadInput("key") at build time.
        assert_eq!(
            build_container(b"v", Some(b"h"), b"", 1).unwrap_err(),
            DeniabilityError::BadInput("key")
        );
        assert_eq!(
            build_container(b"v", Some(b""), b"", 1).unwrap_err(),
            DeniabilityError::BadInput("key"),
            "present-but-empty region still requires a key"
        );
        // Empty key + hidden region at open time.
        let c = build_container(b"v", Some(b"h"), b"k", 1).unwrap();
        assert_eq!(
            open_hidden(&c, b"").unwrap_err(),
            DeniabilityError::BadInput("key")
        );
        // Empty key + no hidden region ⇒ fine everywhere.
        let n = build_container(b"v", None, b"", 1).unwrap();
        assert_eq!(open_hidden(&n, b"").unwrap(), None);
        // Garbage / short / truncated inputs ⇒ Corrupt.
        assert_eq!(open_visible(b"").unwrap_err(), DeniabilityError::Corrupt);
        assert_eq!(
            open_visible(b"TDLV").unwrap_err(),
            DeniabilityError::Corrupt
        );
        assert_eq!(
            open_hidden(b"not a container at all", b"k").unwrap_err(),
            DeniabilityError::Corrupt
        );
        assert_eq!(
            open_visible(b"TDLV0001\x01\x02").unwrap_err(),
            DeniabilityError::Corrupt
        );
    }

    #[test]
    fn serde_and_display_pins() {
        assert_eq!(
            serde_json::to_value(DeniabilityError::BadInput("key")).unwrap(),
            serde_json::json!({ "BadInput": "key" })
        );
        assert_eq!(
            serde_json::to_value(DeniabilityError::Corrupt).unwrap(),
            serde_json::json!("Corrupt")
        );
        assert_eq!(
            serde_json::to_value(DeniabilityError::BadKey).unwrap(),
            serde_json::json!("BadKey")
        );
        assert_eq!(
            DeniabilityError::BadInput("key").to_string(),
            "invalid deniability input: key"
        );
        assert_eq!(
            DeniabilityError::Corrupt.to_string(),
            "corrupt deniable container"
        );
        assert_eq!(
            DeniabilityError::BadKey.to_string(),
            "hidden region key rejected"
        );
        let dyn_err: &dyn std::error::Error = &DeniabilityError::Corrupt;
        assert!(dyn_err.to_string().contains("corrupt"));
    }
}
