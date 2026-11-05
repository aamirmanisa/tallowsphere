//! Runtime FFI: `json.stringify()` for native (compiled) values.
//!
//! The interpreter answers with `serde_json`'s compact form: `{"a":1,"b":"x"}`,
//! no spaces, strings quoted and escaped, `null` for nil, and floats that keep
//! their `.0` (`1.0`, not `1`). The compiled plane refused the call by name
//! ("has no native lowering — refusing to emit a silently-truthy stub"), so a
//! program that stringified anything could not be compiled at all.
//!
//! Buffer layouts are the ones documented in `display_ffi.rs`:
//!   * array: `[count: i64][e0: i64]…` — bare slots, element kind passed in.
//!   * map:   `[count, k0,v0,…,kN,vN, t0,…,tN]` — values tagged (`TAG_*`),
//!     keys untagged, key kind passed in.
//!
//! Nested containers inherit the same limitation as `display_ffi`: a nested
//! array carries no per-element tag, so it is emitted with `ELEM_INT` and the
//! one-per-process note says so on stderr.

use std::ffi::CString;
use std::os::raw::c_char;

use crate::runtime::display_ffi::{ELEM_BOOL, ELEM_FLOAT, ELEM_INT, ELEM_STR};
use crate::runtime::display_ffi::{TAG_ARRAY, TAG_BOOL, TAG_FLOAT, TAG_INT, TAG_MAP, TAG_NIL, TAG_STR};

fn to_cstring(s: String) -> *mut c_char {
    let clean = if s.contains('\0') {
        s.replace('\0', "")
    } else {
        s
    };
    CString::new(clean)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

unsafe fn word(buf: *const i64, idx: usize) -> i64 {
    unsafe { *buf.add(idx) }
}

unsafe fn cstr(payload: i64) -> String {
    if payload == 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(payload as *const c_char) }
        .to_string_lossy()
        .into_owned()
}

/// JSON string escaping: the five escapes serde emits, plus `\u00XX` for the
/// remaining control characters.
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A float the way the *interpreter* writes one.
///
/// Measured, not assumed: `json.stringify(1.0)` prints `1` and
/// `json.stringify([1.0, 2.5])` prints `[1,2.5]` on the interpreter, so the
/// reference plane does NOT keep serde_json's `.0`. Matching it is the whole
/// point of this helper, so `{}` (Rust's shortest round-trip form) it is.
pub fn json_float(v: f64) -> String {
    if !v.is_finite() {
        return "null".to_string();
    }
    format!("{v}")
}

unsafe fn stringify_tagged(
    tag: i64,
    payload: i64,
    keys_are_strings: i32,
    nested: &mut bool,
) -> String {
    match tag {
        TAG_INT => payload.to_string(),
        TAG_STR => escape_json(&unsafe { cstr(payload) }),
        TAG_FLOAT => json_float(f64::from_bits(payload as u64)),
        TAG_BOOL => if payload != 0 { "true" } else { "false" }.to_string(),
        TAG_NIL => "null".to_string(),
        TAG_MAP => {
            *nested = true;
            unsafe { stringify_map(payload as *const i64, keys_are_strings) }
        }
        TAG_ARRAY => {
            *nested = true;
            unsafe { stringify_array(payload as *const i64, ELEM_INT) }
        }
        _ => "null".to_string(),
    }
}

pub unsafe fn stringify_map(buf: *const i64, keys_are_strings: i32) -> String {
    if buf.is_null() {
        return "null".to_string();
    }
    let count = unsafe { word(buf, 0) }.max(0) as usize;
    let mut parts: Vec<String> = Vec::with_capacity(count);
    let mut nested = false;
    for i in 0..count {
        let k = unsafe { word(buf, 1 + 2 * i) };
        let v = unsafe { word(buf, 2 + 2 * i) };
        let tag = unsafe { word(buf, 1 + 2 * count + i) };
        let key = if keys_are_strings != 0 {
            escape_json(&unsafe { cstr(k) })
        } else {
            escape_json(&k.to_string())
        };
        let val = unsafe { stringify_tagged(tag, v, keys_are_strings, &mut nested) };
        parts.push(format!("{key}:{val}"));
    }
    if nested {
        note_nested_default();
    }
    format!("{{{}}}", parts.join(","))
}

pub unsafe fn stringify_array(buf: *const i64, elem_kind: i32) -> String {
    if buf.is_null() {
        return "null".to_string();
    }
    let count = unsafe { word(buf, 0) }.max(0) as usize;
    let mut parts: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        let e = unsafe { word(buf, 1 + i) };
        parts.push(match elem_kind {
            ELEM_STR => escape_json(&unsafe { cstr(e) }),
            ELEM_FLOAT => json_float(f64::from_bits(e as u64)),
            ELEM_BOOL => if e != 0 { "true" } else { "false" }.to_string(),
            _ => e.to_string(),
        });
    }
    format!("[{}]", parts.join(","))
}

fn note_nested_default() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !NOTED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "tallow: json.stringify rendered a nested container with defaulted element kinds \
             (the native array layout has no per-element tags); nested values may not match \
             the interpreter"
        );
    }
}

/// `json.stringify(<map>)`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_stringify_map(buf: *const i64, keys_are_strings: i32) -> *mut c_char {
    to_cstring(unsafe { stringify_map(buf, keys_are_strings) })
}

/// `json.stringify(<array>)`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_stringify_array(buf: *const i64, elem_kind: i32) -> *mut c_char {
    to_cstring(unsafe { stringify_array(buf, elem_kind) })
}

/// `json.stringify(<scalar>)` — `tag` is one of the `TAG_*` codes, `payload`
/// follows that tag's slot convention.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_stringify_scalar(tag: i64, payload: i64) -> *mut c_char {
    let mut nested = false;
    to_cstring(unsafe { stringify_tagged(tag, payload, 1, &mut nested) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_match_serde_compact_form() {
        assert_eq!(escape_json("x"), "\"x\"");
        assert_eq!(escape_json("a\"b"), "\"a\\\"b\"");
        assert_eq!(escape_json("line\nnext"), "\"line\\nnext\"");
        assert_eq!(escape_json("tab\there"), "\"tab\\there\"");
        assert_eq!(escape_json("bell\u{7}"), "\"bell\\u0007\"");
        assert_eq!(json_float(1.0), "1");
        assert_eq!(json_float(1.5), "1.5");
        assert_eq!(json_float(3.0), "3");
        assert_eq!(json_float(f64::NAN), "null");
    }
}
