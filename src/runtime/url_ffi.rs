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
use crate::interp::Value;
use crate::stdlib::url::{parse_url_value, percent_encode};

/// Number of `i64` slots [`tallow_url_parse`] writes.
///
/// `codegen.rs::emit_stdlib_url` allocates exactly this many slots; the two
/// constants are one contract (see the slot table on the function).
pub const URL_PARSE_SLOTS: usize = 9;

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

/// `url.parse(raw) -> Result<URL>` — the parsed fields, written to `out`.
///
/// The parser is `stdlib::url::parse_url_value`, the SAME one the interpreter's
/// `url.parse` arm calls, so scheme/host/port/path/query/fragment/userinfo rules
/// cannot drift between the engines. This function only flattens the returned
/// `Value` into slots.
///
/// Slot table (`out[i]`, all `i64`; a pointer is bitcast through `i64`):
///
/// | i | field      | value                                              |
/// |---|------------|----------------------------------------------------|
/// | 0 | `scheme`   | `*mut c_char`, never null                          |
/// | 1 | `host`     | `*mut c_char`, never null                          |
/// | 2 | `port`     | the port number (only meaningful if slot 3 is 1)   |
/// | 3 | —          | 1 when `port` is `Some`, 0 when it is `None`       |
/// | 4 | `path`     | `*mut c_char`, never null                          |
/// | 5 | `query`    | `*mut c_char`, or null when the field is `Nil`     |
/// | 6 | `fragment` | `*mut c_char`, or null when the field is `Nil`     |
/// | 7 | `username` | `*mut c_char`, or null when the field is `Nil`     |
/// | 8 | `password` | `*mut c_char`, or null when the field is `Nil`     |
///
/// Returns 0 on success, -1 with `tallow_last_error` set on a null argument.
/// The string slots are heap copies owned by the returned struct, exactly like
/// every other struct-returning arm (the arena has no drop hook, so they are
/// never freed — a leak, not a dangling pointer).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_url_parse(raw: *const c_char, out: *mut i64) -> i32 {
    if out.is_null() {
        set_last_error("url.parse: null output buffer".to_string());
        return -1;
    }
    let Some(raw) = (unsafe { cstr_to_str(raw) }) else {
        set_last_error("url.parse: null or invalid URL string".to_string());
        return -1;
    };
    let parsed = parse_url_value(raw);
    let Value::Struct { name, fields } = &parsed else {
        set_last_error(format!(
            "url.parse: parser returned {parsed:?}, expected the URL struct"
        ));
        return -1;
    };
    if name != "URL" {
        set_last_error(format!(
            "url.parse: parser returned `{name}`, expected `URL`"
        ));
        return -1;
    }
    let get = |key: &str| fields.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    let string_slot = |key: &str| -> i64 {
        match get(key) {
            Some(Value::String(s)) => string_to_cstr(s) as i64,
            // parse_url_value leaves the mandatory fields as Strings; a missing
            // one is null rather than a fabricated empty string.
            _ => 0,
        }
    };
    let (port, has_port) = match get("port") {
        Some(Value::Int(p)) => {
            // A native int is i64; a u16 field cannot carry anything else.
            let clamped = i64::try_from(*p).unwrap_or(0);
            (clamped, if (0..=65535).contains(&clamped) { 1 } else { 0 })
        }
        _ => (0, 0),
    };
    // SAFETY: the caller allocated `URL_PARSE_SLOTS` i64 slots (the contract on
    // this function); every index below is < URL_PARSE_SLOTS.
    unsafe {
        *out.add(0) = string_slot("scheme");
        *out.add(1) = string_slot("host");
        *out.add(2) = port;
        *out.add(3) = has_port;
        *out.add(4) = string_slot("path");
        *out.add(5) = string_slot("query");
        *out.add(6) = string_slot("fragment");
        *out.add(7) = string_slot("username");
        *out.add(8) = string_slot("password");
    }
    0
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

    /// Read one slot as a string (`0` is the null pointer).
    fn slot_str(slots: &[i64], i: usize) -> Option<String> {
        let p = slots[i] as *const c_char;
        if p.is_null() {
            return None;
        }
        Some(unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string())
    }

    #[test]
    fn url_parse_flattens_every_declared_field() {
        let raw = CString::new("https://user:pw@h.example:8443/a/b?q=1#frag").unwrap();
        let mut slots = [0i64; URL_PARSE_SLOTS];
        assert_eq!(tallow_url_parse(raw.as_ptr(), slots.as_mut_ptr()), 0);
        assert_eq!(slot_str(&slots, 0).as_deref(), Some("https"));
        assert_eq!(slot_str(&slots, 1).as_deref(), Some("h.example"));
        assert_eq!(slots[2], 8443);
        assert_eq!(slots[3], 1, "port must be reported present");
        assert_eq!(slot_str(&slots, 4).as_deref(), Some("/a/b"));
        assert_eq!(slot_str(&slots, 5).as_deref(), Some("q=1"));
        assert_eq!(slot_str(&slots, 6).as_deref(), Some("frag"));
        assert_eq!(slot_str(&slots, 7).as_deref(), Some("user"));
        assert_eq!(slot_str(&slots, 8).as_deref(), Some("pw"));
    }

    /// The absent optionals must be NULL, not `""`: `url.parse(u).fragment` has
    /// to read as nil the way the interpreter's Nil does.
    #[test]
    fn url_parse_reports_absent_optionals_as_null() {
        let raw = CString::new("https://example.com/x").unwrap();
        let mut slots = [0i64; URL_PARSE_SLOTS];
        assert_eq!(tallow_url_parse(raw.as_ptr(), slots.as_mut_ptr()), 0);
        assert_eq!(slot_str(&slots, 1).as_deref(), Some("example.com"));
        assert_eq!(slot_str(&slots, 4).as_deref(), Some("/x"));
        assert_eq!(slots[3], 0, "no port in the input");
        assert!(slot_str(&slots, 6).is_none(), "fragment must be null");
        assert!(slot_str(&slots, 7).is_none(), "username must be null");
        assert!(slot_str(&slots, 8).is_none(), "password must be null");
    }

    #[test]
    fn url_parse_null_input_fails_closed() {
        let mut slots = [0i64; URL_PARSE_SLOTS];
        assert_eq!(tallow_url_parse(std::ptr::null(), slots.as_mut_ptr()), -1);
        assert_eq!(
            tallow_url_parse(CString::new("x").unwrap().as_ptr(), std::ptr::null_mut()),
            -1
        );
    }
}
