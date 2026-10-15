//! Runtime FFI: `tallow.compress.compress_with` / `decompress_with`.
//!
//! `Bytes` is a base64 `String` at runtime (this module's existing convention),
//! so both directions are base64 in -> base64 out and **no native byte
//! representation is needed** — these are ordinary string->string arms.
//!
//! The interpreter and this FFI share ONE implementation: the `pub(crate)`
//! helpers in [`crate::stdlib::compress`] (`compress_bytes` / `decompress_bytes`
//! / `b64_encode` / `b64_decode` / `default_level`). Never reimplement
//! zstd/gzip/brotli here — a second implementation is how the two engines drift.
//!
//! A null return sets `tallow_last_error`; the emitted code turns that into a
//! message-bearing `exit(1)` rather than a usable-looking empty string.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::stdlib::compress;

/// Read an algorithm argument, lowercased for parity with the interpreter's
/// `extract_algo` (which accepts `"zstd"` or the `Algorithm.Zstd` enum and
/// normalises both). Returns `None` with `tallow_last_error` set on a null arg.
fn algo_arg(algo: *const c_char) -> Option<String> {
    match unsafe { cstr_to_str(algo) } {
        Some(a) => Some(a.to_ascii_lowercase()),
        None => {
            set_last_error("compress: expected an algorithm string".to_string());
            None
        }
    }
}

/// `compress.compress_with(data, algo, level)` — base64 in, base64 out.
/// A negative `level` means "use the algorithm's default", matching the
/// interpreter's fallback when `level` is not supplied.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_compress_with(
    data: *const c_char,
    algo: *const c_char,
    level: i32,
) -> *mut c_char {
    let Some(encoded) = (unsafe { cstr_to_str(data) }) else {
        set_last_error("compress_with requires a string argument".to_string());
        return std::ptr::null_mut();
    };
    let Some(algo) = algo_arg(algo) else {
        return std::ptr::null_mut();
    };
    let level = if level < 0 {
        compress::default_level(&algo)
    } else {
        level
    };
    let raw = match compress::b64_decode(encoded) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    match compress::compress_bytes(&raw, &algo, level) {
        Ok(out) => string_to_cstr(&compress::b64_encode(&out)),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// `compress.decompress_with(data, algo)` — base64 in, base64 out.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_decompress_with(data: *const c_char, algo: *const c_char) -> *mut c_char {
    let Some(encoded) = (unsafe { cstr_to_str(data) }) else {
        set_last_error("decompress_with requires a string argument".to_string());
        return std::ptr::null_mut();
    };
    let Some(algo) = algo_arg(algo) else {
        return std::ptr::null_mut();
    };
    let raw = match compress::b64_decode(encoded) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    match compress::decompress_bytes(&raw, &algo) {
        Ok(out) => string_to_cstr(&compress::b64_encode(&out)),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Round-trip every algorithm the interpreter supports, through the FFI
    /// boundary, including a payload with non-UTF-8 bytes so a text-only
    /// round-trip cannot pass by accident.
    #[test]
    fn compress_with_round_trips_each_algorithm() {
        let raw: Vec<u8> = vec![0x00, 0x01, 0xfe, 0xff, b'h', b'i'];
        let payload = compress::b64_encode(&raw);
        for algo in ["zstd", "gzip", "brotli"] {
            let compressed = tallow_compress_with(
                c(&payload).as_ptr(),
                c(algo).as_ptr(),
                -1, // default level
            );
            assert!(!compressed.is_null(), "{algo}: compress returned null");
            let compressed = unsafe { std::ffi::CStr::from_ptr(compressed) }
                .to_str()
                .unwrap()
                .to_string();

            let back = tallow_decompress_with(c(&compressed).as_ptr(), c(algo).as_ptr());
            assert!(!back.is_null(), "{algo}: decompress returned null");
            let back = unsafe { std::ffi::CStr::from_ptr(back) }
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(back, payload, "{algo}: round-trip diverged");
        }
    }

    /// An unknown algorithm must fail closed, not return the input unchanged.
    #[test]
    fn unknown_algorithm_fails_closed() {
        let payload = compress::b64_encode(b"x");
        assert!(tallow_compress_with(c(&payload).as_ptr(), c("lzma").as_ptr(), -1).is_null());
        assert!(tallow_decompress_with(c(&payload).as_ptr(), c("lzma").as_ptr()).is_null());
    }

    /// Algorithm names are lowercased for parity with the interpreter's
    /// `extract_algo` (which accepts the enum form and normalises it).
    #[test]
    fn algorithm_names_are_case_insensitive() {
        let payload = compress::b64_encode(b"hello");
        let upper = tallow_compress_with(c(&payload).as_ptr(), c("ZSTD").as_ptr(), -1);
        assert!(!upper.is_null(), "uppercase algorithm should be accepted");
    }
}
