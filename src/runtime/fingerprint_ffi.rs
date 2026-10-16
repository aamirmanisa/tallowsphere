//! Runtime FFI: `ContentFingerprint.from_text`.
//!
//! # Shape
//!
//! The struct returned is `{hash: String, word_count: i32, text_length: i32}`
//! (`stdlib/browser.tl:417`). The hash is a string, so it is the return value;
//! the two integers come back through **out-params** and codegen allocates the
//! `%struct.ContentFingerprint` itself.
//!
//! That split is deliberate. The alternative — allocating the struct here and
//! returning a pointer — would couple the LLVM struct layout to a hand-written
//! Rust `#[repr(C)]`, which then breaks *silently* on any field reorder, width
//! change or padding difference. Out-params keep struct layout owned by codegen.
//! The same pattern is already used by `tallow_gzip_decompress(ptr, i64, ptr)`.
//!
//! # Contract
//!
//! Non-null returns and a successful call always write both out-params; a null
//! return means the out-params are untouched and `tallow_last_error` is set, so
//! the emitted code must branch on null before reading them. Counts that do not
//! fit the declared `i32` fail closed rather than wrapping — a silently wrong
//! length is worse than a refused call.
//!
//! The values themselves come from `stdlib::browser::fingerprint_fields`, the
//! same function the interpreter calls, so native and interpreted results cannot
//! disagree.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::stdlib::browser::{fingerprint_fields, similarity_from_hex};

/// `ContentFingerprint.from_text(text) -> ContentFingerprint`
///
/// Returns the hash as a NUL-terminated string (null on error), writing
/// `word_count` and `text_length` through the out-params.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fingerprint_from_text(
    text: *const c_char,
    word_count_out: *mut i32,
    text_length_out: *mut i32,
) -> *mut c_char {
    // Codegen always passes allocas; a null here is a codegen bug, so refuse
    // rather than write through a wild pointer.
    if word_count_out.is_null() || text_length_out.is_null() {
        set_last_error(
            "content_fingerprint_from_text: missing out-parameter slot".to_string(),
        );
        return std::ptr::null_mut();
    }
    let Some(text) = (unsafe { cstr_to_str(text) }) else {
        set_last_error("content_fingerprint_from_text: expected a string argument".to_string());
        return std::ptr::null_mut();
    };
    let (hash, word_count, text_length) = fingerprint_fields(text);
    let (Ok(word_count), Ok(text_length)) = (i32::try_from(word_count), i32::try_from(text_length))
    else {
        set_last_error(
            "content_fingerprint_from_text: count exceeds the declared i32 field width".to_string(),
        );
        return std::ptr::null_mut();
    };
    unsafe {
        *word_count_out = word_count;
        *text_length_out = text_length;
    }
    string_to_cstr(&hash)
}

/// `content_fingerprint_similarity(a, b) -> f64`, taking the two hashes read out
/// of the fingerprints' `hash` fields.
///
/// An `f64` return has no null to test, so failure is signalled as **NaN** with
/// `tallow_last_error` set; the emitted code branches on `fcmp uno` and exits
/// rather than using the NaN.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fingerprint_similarity(
    a_hash: *const c_char,
    b_hash: *const c_char,
) -> f64 {
    let (Some(a), Some(b)) = (
        unsafe { cstr_to_str(a_hash) },
        unsafe { cstr_to_str(b_hash) },
    ) else {
        set_last_error(
            "content_fingerprint_similarity: expected two fingerprint arguments".to_string(),
        );
        return f64::NAN;
    };
    match similarity_from_hex(a, b) {
        Some(similarity) => similarity,
        None => {
            set_last_error(format!(
                "content_fingerprint_similarity: `{a}` / `{b}` is not a 64-bit hex hash"
            ));
            f64::NAN
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    /// Call the FFI the way codegen does and return `(hash, wc, tl)`.
    fn fingerprint(text: &str) -> Option<(String, i32, i32)> {
        let c = CString::new(text).unwrap();
        let mut wc: i32 = -1;
        let mut tl: i32 = -1;
        let p = tallow_fingerprint_from_text(c.as_ptr(), &mut wc, &mut tl);
        if p.is_null() {
            return None;
        }
        let hash = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        Some((hash, wc, tl))
    }

    /// Pins the **canonical** value for `ContentFingerprint.from_text`.
    ///
    /// The declaration (`stdlib/browser.tl:425`) says "BLAKE3-based SimHash
    /// fingerprinting", so `stdlib::browser` is the reference implementation and
    /// both interpreter paths now delegate to it: the struct-static arm in
    /// `interp.rs` previously derived its own hash from a truncated
    /// `blake3::hash` and reported `text_length` in *bytes* — that duplicate was
    /// removed. `wc`/`tl` are 3/17 for this input.
    ///
    /// History worth keeping: this test originally pinned the *module* path's
    /// value while a second implementation behind
    /// `runtime::enterprise_ffi::tallow_content_fingerprint`
    /// (`crate::browser::privacy`, whose `hash` is a `u64`) returned a different
    /// hash (`b5b0ba5abbc7df00`) for the struct-static form. That divergence is
    /// closed — the privacy variant's helpers are declared in the IR prelude but
    /// never called, and no interpreter path can now disagree with this value.
    /// A future change that reintroduces a second implementation should fail
    /// this test rather than quietly pass it.
    #[test]
    fn matches_the_module_path_for_a_known_input() {
        assert_eq!(
            fingerprint("hello world hello"),
            Some(("928286b33d168fea".to_string(), 3, 17))
        );
    }

    /// `text_length` is a CHAR count: "é" is 2 UTF-8 bytes but 1 char, and
    /// 4 chars / 10 bytes here. A byte-counting implementation passes the ASCII
    /// test above and fails this one.
    #[test]
    fn text_length_counts_chars_not_bytes() {
        // "aébc" = 4 chars, 5 UTF-8 bytes.
        let (_, wc, tl) = fingerprint("aébc").unwrap();
        assert_eq!((wc, tl), (1, 4));
        let (_, wc, tl) = fingerprint("héllo wörld").unwrap();
        assert_eq!((wc, tl), (2, 11));
    }

    /// Empty input fingerprints as all-zero rather than erroring, so "nothing
    /// extracted" is still a comparable value (per the declaration's docs).
    #[test]
    fn empty_input_is_all_zero_not_an_error() {
        assert_eq!(fingerprint(""), Some(("0000000000000000".to_string(), 0, 0)));
    }

    /// The hash is always 16 lowercase hex digits.
    #[test]
    fn hash_is_sixteen_lowercase_hex_digits() {
        let (hash, _, _) = fingerprint("some longer text with several tokens").unwrap();
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// A null out-param slot is a codegen bug: refuse, never write through it.
    #[test]
    fn null_out_params_fail_closed() {
        let c = CString::new("x").unwrap();
        let mut tl: i32 = 0;
        assert!(tallow_fingerprint_from_text(c.as_ptr(), std::ptr::null_mut(), &mut tl).is_null());
        let mut wc: i32 = 0;
        assert!(tallow_fingerprint_from_text(c.as_ptr(), &mut wc, std::ptr::null_mut()).is_null());
    }

    /// Identical fingerprints score exactly 1.0 (the declaration's contract).
    #[test]
    fn identical_hashes_score_exactly_one() {
        let (hash, _, _) = fingerprint("hello world hello").unwrap();
        let a = CString::new(hash.clone()).unwrap();
        let b = CString::new(hash).unwrap();
        assert_eq!(tallow_fingerprint_similarity(a.as_ptr(), b.as_ptr()), 1.0);
    }

    /// The score is Hamming-driven: one differing bit of 64 is 1 - 1/64.
    #[test]
    fn hamming_distance_drives_the_score() {
        let a = CString::new("0000000000000000").unwrap();
        let b = CString::new("0000000000000001").unwrap();
        assert_eq!(
            tallow_fingerprint_similarity(a.as_ptr(), b.as_ptr()),
            1.0 - 1.0 / 64.0
        );
    }

    /// An unparsable hash cannot return a score, and an `f64` has no null to
    /// check — so it must be NaN, not 0.0 (which would read as "completely
    /// different" and be silently wrong).
    #[test]
    fn unparsable_hash_fails_closed_as_nan() {
        let bad = CString::new("nonsense").unwrap();
        let good = CString::new("0000000000000000").unwrap();
        assert!(tallow_fingerprint_similarity(bad.as_ptr(), good.as_ptr()).is_nan());
        assert!(tallow_fingerprint_similarity(std::ptr::null(), good.as_ptr()).is_nan());
    }
}
