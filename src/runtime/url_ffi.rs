//! Runtime FFI: `tallow.url.encode_query`.
//!
//! # The native map layout
//!
//! A map is a flat `i64` slot buffer: slot 0 is the pair count, then
//! `[k0, v0, k1, v1, …]`, with string keys/values stored as pointer-as-i64.
//! That is exactly the addressing `src/codegen.rs::emit_map_get` uses
//! (`stride = idx * 2`, key at `stride + 1`, value at `stride + 2`).
//!
//! # Safety contract (load-bearing)
//!
//! This helper dereferences every value *as a string*, so it may only be called
//! on a map proven all-string at compile time — `map_arg_is_all_strings` in
//! codegen is that proof, and the only caller. A non-string value is an
//! **integer** in a slot where a pointer is expected: dereferencing it faults.
//! The interpreter raises a clean error for the same program, so calling this on
//! an unproven map would trade a loud error for a segfault.
//!
//! Encoding is shared with the interpreter (`stdlib::url::percent_encode`), so
//! the `%20`-not-`+` rule cannot drift between the two engines.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::stdlib::url::percent_encode;

/// `url.encode_query(params: Map<String, String>) -> String`
///
/// Null on a non-map argument, or if any slot fails to read as a string; the
/// emitted code turns a null into a message-bearing `exit(1)`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_url_encode_query(map: *const i64) -> *mut c_char {
    if map.is_null() {
        set_last_error("url.encode_query: expected a Map<String, String> argument".to_string());
        return std::ptr::null_mut();
    }
    // SAFETY: slot 0 is the pair count by construction (see module docs).
    let count = unsafe { *map };
    if count < 0 {
        set_last_error("url.encode_query: corrupt map (negative pair count)".to_string());
        return std::ptr::null_mut();
    }
    let mut out = String::new();
    for i in 0..count {
        // SAFETY: the caller proved every key/value slot holds a NUL-terminated
        // string pointer (module contract above).
        let k = unsafe { *map.offset((1 + 2 * i) as isize) } as *const c_char;
        let v = unsafe { *map.offset((2 + 2 * i) as isize) } as *const c_char;
        let (k, v) = match (unsafe { cstr_to_str(k) }, unsafe { cstr_to_str(v) }) {
            (Some(k), Some(v)) => (k, v),
            _ => {
                set_last_error("url.encode_query: keys and values must be strings".to_string());
                return std::ptr::null_mut();
            }
        };
        if i > 0 {
            out.push('&');
        }
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    string_to_cstr(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    /// Build the exact native map layout: [count, k0, v0, k1, v1, …].
    /// Returns the slots plus the owning `CString`s so the pointers stay valid.
    fn map_slots(pairs: &[(&str, &str)]) -> (Vec<i64>, Vec<CString>) {
        let keep: Vec<CString> = pairs
            .iter()
            .flat_map(|(k, v)| {
                [
                    CString::new(*k).expect("key"),
                    CString::new(*v).expect("value"),
                ]
            })
            .collect();
        let mut slots: Vec<i64> = Vec::with_capacity(1 + keep.len());
        slots.push(pairs.len() as i64);
        for c in &keep {
            slots.push(c.as_ptr() as i64);
        }
        (slots, keep)
    }

    fn call(slots: &[i64]) -> Option<String> {
        let p = tallow_url_encode_query(slots.as_ptr());
        if p.is_null() {
            return None;
        }
        Some(unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string())
    }

    #[test]
    fn builds_pairs_in_order_with_percent20() {
        let (slots, _keep) = map_slots(&[("q", "a b"), ("n", "1")]);
        assert_eq!(call(&slots).unwrap(), "q=a%20b&n=1");
    }

    #[test]
    fn escapes_reserved_characters_in_keys_and_values() {
        let (slots, _keep) = map_slots(&[("a&b", "c=d")]);
        assert_eq!(call(&slots).unwrap(), "a%26b=c%3Dd");
    }

    #[test]
    fn empty_map_yields_empty_string_not_null() {
        let (slots, _keep) = map_slots(&[]);
        assert_eq!(call(&slots).unwrap(), "");
    }

    #[test]
    fn null_map_fails_closed() {
        assert!(tallow_url_encode_query(std::ptr::null()).is_null());
    }
}
