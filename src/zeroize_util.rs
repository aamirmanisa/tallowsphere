//! Zeroization primitives — redacted secret wrappers and wipe helpers
//! (task A6.1.1, frozen interface §5).
//!
//! # What this is
//! [`SecretBytes`] and [`SecretString`] wrap raw secret material so that:
//! - the secret never leaks through `Debug` (redacted for both types),
//! - the secret cannot be cloned or serialized (`Clone` / `Serialize` are
//!   deliberately **not** implemented — compile-level invariant, see tests),
//! - the backing memory is wiped when the value drops
//!   (`#[derive(zeroize::ZeroizeOnDrop)]`), and
//! - callers can wipe eagerly via [`SecretBytes::zeroize_now`] /
//!   [`SecretString::zeroize_now`]; after that call `expose()` is empty.
//!
//! Access is borrow-only through [`SecretBytes::expose`] / [`SecretString::expose`]:
//! there is no `into_inner`, no `to_vec`, no `AsRef<[u8]>` — a caller cannot
//! obtain an owned copy of the secret through this API, so the wrapper always
//! knows every buffer it is responsible for wiping.
//!
//! # Free helpers
//! - [`zeroize_slice`] wipes a caller-owned `&mut [u8]` in place (length kept).
//! - [`wipe`] takes ownership of a `Vec<u8>` and zeroizes its backing buffer.
//!
//! # Guarantees & limits
//! Wipes are the `zeroize` crate's volatile-write based implementation, a
//! best-effort defense-in-depth measure. They are NOT a guarantee against
//! dead copies taken before wrapping, moved/reclaimed pages, CPU caches or
//! hibernation images. The A6.1.1 repository sweep (which existing
//! secret-bearing types still derive `Debug`, which ignore zeroization) is
//! documented in `docs/ops/zeroization.md`; adopting these primitives across
//! those types is the separate (pending) adoption follow-up.
//!
//! Not wired into `lib.rs` yet (the parent does that):
//! `pub mod zeroize_util;`

use std::fmt;

use zeroize::Zeroize;

/// Redaction marker printed in place of secret material.
pub const REDACTED: &str = "[redacted]";

/// Owned, non-clonable, self-wiping byte secret.
///
/// Construct with [`SecretBytes::new`]; read through [`SecretBytes::expose`]
/// (borrow only); wipe early with [`SecretBytes::zeroize_now`]. The buffer is
/// also wiped automatically on drop (`zeroize::ZeroizeOnDrop`).
///
/// `Debug` is hand-written (not derived) and prints exactly
/// `[redacted; N bytes]` where `N` is the **current** byte length at print
/// time — so a wiped instance prints `[redacted; 0 bytes]`. No `Clone`, no
/// `Serialize`.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Wrap `bytes` as a secret (takes ownership; nothing is copied out of
    /// the caller's value — the same allocation is adopted).
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the secret bytes. Returns a reference only — deliberately no
    /// copy, so the wrapper remains the sole owner of the buffer.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Current byte length (`0` after [`SecretBytes::zeroize_now`]).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the secret is empty (also true right after `zeroize_now`).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Wipe immediately: zeroizes the backing buffer and empties the wrapper.
    /// After this call `expose()` is `&[]` and `len() == 0`. Idempotent.
    pub fn zeroize_now(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Pinned format (frozen interface §5): current length at print time.
        write!(f, "[redacted; {} bytes]", self.bytes.len())
    }
}

/// Owned, non-clonable, self-wiping string secret.
///
/// Mirrors [`SecretBytes`] for `String`: borrow-only read via
/// [`SecretString::expose`], eager wipe via [`SecretString::zeroize_now`],
/// automatic wipe on drop. `Debug` is hand-written and prints
/// `SecretString([redacted])`. No `Clone`, no `Serialize`.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SecretString {
    value: String,
}

impl SecretString {
    /// Wrap `value` as a secret (takes ownership).
    pub fn new(value: String) -> Self {
        Self { value }
    }

    /// Borrow the secret string — reference only, no copy.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Current length in UTF-8 bytes (same convention as `String::len`).
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// True when the secret is empty (also true right after `zeroize_now`).
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Wipe immediately: zeroizes the backing buffer and empties the wrapper.
    /// After this call `expose()` is `""` and `len() == 0`. Idempotent.
    pub fn zeroize_now(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({REDACTED})")
    }
}

/// Wipe a caller-owned byte buffer in place via [`zeroize::Zeroize`].
///
/// The slice length is unchanged; every element becomes `0`. Works on empty
/// slices (no-op).
pub fn zeroize_slice(buf: &mut [u8]) {
    buf.zeroize();
}

/// Consume `v` and zeroize its backing buffer.
///
/// Takes the `Vec` by value (no return): the caller cannot observe the bytes
/// afterwards — the buffer is zeroized before it is released. Pinned by test.
pub fn wipe(mut v: Vec<u8>) {
    v.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- SecretBytes ------------------------------------------------------

    #[test]
    fn secret_bytes_expose_roundtrip() {
        let s = SecretBytes::new(b"hunter2".to_vec());
        assert_eq!(s.expose(), b"hunter2");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());
    }

    #[test]
    fn secret_bytes_empty_cases() {
        let s = SecretBytes::new(Vec::new());
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.expose(), b"" as &[u8]);
        assert_eq!(format!("{:?}", s), "[redacted; 0 bytes]");
    }

    #[test]
    fn secret_bytes_zeroize_now_empties_and_is_idempotent() {
        let mut s = SecretBytes::new(vec![0xAA; 32]);
        assert_eq!(s.len(), 32);
        s.zeroize_now();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.expose(), b"" as &[u8]);
        s.zeroize_now(); // idempotent
        assert_eq!(s.expose(), b"" as &[u8]);
    }

    #[test]
    fn secret_bytes_debug_format_pinned() {
        let s = SecretBytes::new(b"swordfish".to_vec());
        let d = format!("{:?}", s);
        assert_eq!(d, "[redacted; 9 bytes]");
        // Redaction marker present; the secret itself absent.
        assert!(d.contains("[redacted"));
        assert!(!d.contains("swordfish"));
        assert!(!d.contains("sword"));
    }

    #[test]
    fn secret_bytes_debug_tracks_current_length() {
        let mut s = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(format!("{:?}", s), "[redacted; 4 bytes]");
        s.zeroize_now();
        // Length is read at print time, not captured at construction.
        assert_eq!(format!("{:?}", s), "[redacted; 0 bytes]");
    }

    // -- SecretString -----------------------------------------------------

    #[test]
    fn secret_string_expose_roundtrip() {
        let s = SecretString::new("pässwörd-42".to_string());
        assert_eq!(s.expose(), "pässwörd-42");
        assert_eq!(s.len(), s.expose().as_bytes().len()); // bytes, not chars
        assert!(!s.is_empty());
    }

    #[test]
    fn secret_string_empty_cases() {
        let s = SecretString::new(String::new());
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.expose(), "");
        assert_eq!(format!("{:?}", s), "SecretString([redacted])");
    }

    #[test]
    fn secret_string_zeroize_now_empties_and_is_idempotent() {
        let mut s = SecretString::new("correct horse battery staple".to_string());
        s.zeroize_now();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.expose(), "");
        s.zeroize_now();
        assert_eq!(s.expose(), "");
    }

    #[test]
    fn secret_string_debug_redacted() {
        let s = SecretString::new("top-secret-token".to_string());
        let d = format!("{:?}", s);
        assert_eq!(d, "SecretString([redacted])");
        assert!(d.contains(REDACTED));
        assert!(!d.contains("top-secret-token"));
        assert!(!d.contains("token"));
    }

    #[test]
    fn redacted_const_pinned() {
        assert_eq!(REDACTED, "[redacted]");
    }

    #[test]
    fn debug_never_reveals_secret_material() {
        let raw: Vec<u8> = (0u8..=255).collect();
        let b = SecretBytes::new(raw.clone());
        let t = SecretString::new("AKIA-EXAMPLE-KEY-0123456789".to_string());
        let d_bytes = format!("{:?}", b);
        let d_string = format!("{:?}", t);
        for d in [&d_bytes, &d_string] {
            assert!(d.contains("[redacted"));
            assert!(!d.contains("AKIA-EXAMPLE-KEY-0123456789"));
        }
        // No readable prefix of the wrapped byte soup may appear either.
        let as_text = String::from_utf8_lossy(&raw[..16]).into_owned();
        assert!(!d_bytes.contains(&as_text));
    }

    // -- free helpers -----------------------------------------------------

    #[test]
    fn zeroize_slice_wipes_in_place_and_keeps_length() {
        let mut buf = [0x5Au8; 64];
        zeroize_slice(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn zeroize_slice_empty_is_ok() {
        let mut empty: [u8; 0] = [];
        zeroize_slice(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn wipe_consumes_and_returns_unit() {
        // Signature pin: `fn(Vec<u8>) -> ()` — ownership taken, nothing back.
        let f: fn(Vec<u8>) = wipe;
        assert_eq!(f(vec![1, 2, 3]), ());
        assert_eq!(wipe(vec![]), ());
        assert_eq!(wipe(vec![0xFF; 4096]), ());
    }

    #[test]
    fn wipe_uses_vec_zeroize_semantics() {
        // `wipe` delegates to `Zeroize for Vec<u8>`; pin that impl's
        // observable contract on an equivalent Vec (the argument itself is
        // consumed, so it cannot be inspected post-call by construction):
        // length cleared, allocation retained, wipe done in place. The
        // zeroize 1.8 impl additionally zeroes the full capacity (elements +
        // spare); the raw bytes of a cleared Vec are not legally observable
        // from safe code, so byte-level proof is delegated to the slice path
        // (see `zeroize_slice_on_vec_contents_is_observable`).
        let mut v = b"secret-material".to_vec();
        let addr = v.as_ptr();
        let cap = v.capacity();
        v.zeroize();
        assert!(v.is_empty());
        assert_eq!(v.as_ptr(), addr, "wipe is in place; no reallocation");
        assert_eq!(v.capacity(), cap, "capacity retained (no shrink on wipe)");
    }

    #[test]
    fn zeroize_slice_on_vec_contents_is_observable() {
        // Genuine, fully safe observation that a wipe lands on the bytes:
        // wipe through a `&mut [u8]` view of a Vec, then read it back.
        let mut v = vec![0xABu8; 16];
        zeroize_slice(&mut v);
        assert_eq!(v.len(), 16);
        assert!(v.iter().all(|&b| b == 0));
    }

    // -- compile-level invariants ----------------------------------------

    #[test]
    fn zeroize_on_drop_derive_in_place() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretBytes>();
        assert_zeroize_on_drop::<SecretString>();
    }

    #[test]
    fn expose_is_borrow_only_signature_pin() {
        // Both accessors return references tied to the wrapper's borrow:
        // there is no copy-out (no `to_vec`, no `into_inner`).
        let f: fn(&SecretBytes) -> &[u8] = SecretBytes::expose;
        let g: fn(&SecretString) -> &str = SecretString::expose;
        let b = SecretBytes::new(b"x".to_vec());
        let s = SecretString::new("y".to_string());
        assert_eq!(f(&b), b"x");
        assert_eq!(g(&s), "y");
        // serde absence (`Serialize`) is not testable in a plain `#[test]`
        // (needs a compile-fail harness); it is enforced by code review of
        // this file — see module docs. Note only, per frozen interface §5.
    }
}
