//! Runtime FFI: `print()` display rendering for composite (map/array) values.
//!
//! The interpreter renders composites through `Value::display()`:
//! `[1, 2, 3]`, `{"k": 1, "j": "v"}` (string keys/values quoted, entries joined
//! with ", "). The native backend types a map/array as `I8Ptr`, so `print`
//! used to fall into its `%s` arm and print the buffer's raw count byte
//! (`[1,2,3]` printed `\x03`). These helpers render the interpreter's exact
//! text into a C string.
//!
//! Buffer layouts (see `codegen.rs`, the tagged-value backend):
//!   * array: `[count: i64][e0: i64]…` — bare slots, NO per-element tags, so
//!     the emitter passes the statically-known element kind (`ELEM_*`).
//!   * map:   `[count, k0,v0,…,kN,vN, t0,…,tN]` — values carry tags
//!     (`TAG_*`), keys do not, so the emitter passes the static key kind.
//!     Composite value tags (5 map / 6 array) recurse; a nested ARRAY has no
//!     element tag to consult, so it is rendered with `ELEM_INT` and a loud
//!     one-per-process note is written to stderr.

use std::ffi::CString;
use std::os::raw::c_char;

/// Value tags written into a native map's trailing tags array.
pub const TAG_INT: i64 = 0;
pub const TAG_STR: i64 = 1;
pub const TAG_FLOAT: i64 = 2;
pub const TAG_BOOL: i64 = 3;
pub const TAG_NIL: i64 = 4;
pub const TAG_MAP: i64 = 5;
pub const TAG_ARRAY: i64 = 6;

/// Element-kind codes for native arrays (`[count][e0]…` — no per-element tags,
/// so the emitter's static hint is the only source of truth). These numbers
/// are mirrored by the `ELEM_*` constants emitted from `codegen.rs`.
pub const ELEM_INT: i32 = 0;
pub const ELEM_STR: i32 = 1;
pub const ELEM_FLOAT: i32 = 2;
pub const ELEM_BOOL: i32 = 3;

fn to_cstring(s: String) -> *mut c_char {
    // A stray NUL cannot be passed to printf; strip it rather than panic
    // (a panic would abort the whole program mid-print).
    let clean = if s.contains('\0') { s.replace('\0', "") } else { s };
    CString::new(clean)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// One i64 word out of a native buffer.
///
/// # Safety
/// `buf` must point at a native tallow buffer with at least `idx + 1` slots.
unsafe fn word(buf: *const i64, idx: usize) -> i64 {
    unsafe { *buf.add(idx) }
}

/// A string slot (`*const c_char` stored as i64) as a Rust string.
///
/// # Safety
/// `payload` must be 0 or a valid NUL-terminated C string.
unsafe fn cstr(payload: i64) -> String {
    if payload == 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(payload as *const c_char) }
        .to_string_lossy()
        .into_owned()
}

/// `Value::display()` for one tagged value: strings quoted, others plain.
///
/// # Safety
/// `payload` must match the tag's slot convention.
unsafe fn render_tagged(
    tag: i64,
    payload: i64,
    keys_are_strings: i32,
    nested: &mut bool,
) -> String {
    match tag {
        TAG_INT => payload.to_string(),
        TAG_STR => format!("\"{}\"", unsafe { cstr(payload) }),
        // A tagged float payload holds the f64 BIT PATTERN (the convention of
        // every tagged-float reader in codegen: `coerce_to_string`, result
        // printing). Rust's `{}` on f64 matches the interpreter's
        // `format!("{n}")` exactly, including shortest-round-trip digits.
        TAG_FLOAT => format!("{}", f64::from_bits(payload as u64)),
        TAG_BOOL => if payload != 0 { "true" } else { "false" }.to_string(),
        TAG_NIL => "nil".to_string(),
        TAG_MAP => {
            *nested = true;
            unsafe { render_map(payload as *const i64, keys_are_strings) }
        }
        TAG_ARRAY => {
            *nested = true;
            unsafe { render_array(payload as *const i64, ELEM_INT) }
        }
        _ => format!("<tag:{tag}>"),
    }
}

/// Render a native map buffer as the interpreter's `{…}` display.
///
/// # Safety
/// `buf` must be a native tagged map buffer, or null.
pub unsafe fn render_map(buf: *const i64, keys_are_strings: i32) -> String {
    if buf.is_null() {
        return "nil".to_string();
    }
    let count = unsafe { word(buf, 0) }.max(0) as usize;
    let mut parts: Vec<String> = Vec::with_capacity(count);
    let mut nested = false;
    for i in 0..count {
        let k = unsafe { word(buf, 1 + 2 * i) };
        let v = unsafe { word(buf, 2 + 2 * i) };
        let tag = unsafe { word(buf, 1 + 2 * count + i) };
        let key = if keys_are_strings != 0 {
            format!("\"{}\"", unsafe { cstr(k) })
        } else {
            k.to_string()
        };
        let val = unsafe { render_tagged(tag, v, keys_are_strings, &mut nested) };
        parts.push(format!("{key}: {val}"));
    }
    if nested {
        note_nested_default();
    }
    format!("{{{}}}", parts.join(", "))
}

/// Render a native array buffer as the interpreter's `[…]` display.
///
/// # Safety
/// `buf` must be a native array buffer, or null. `elem_kind` must describe the
/// slots' contents (`ELEM_*`) — pointer slots are dereferenced as strings.
pub unsafe fn render_array(buf: *const i64, elem_kind: i32) -> String {
    if buf.is_null() {
        return "nil".to_string();
    }
    let count = unsafe { word(buf, 0) }.max(0) as usize;
    let mut parts: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        let e = unsafe { word(buf, 1 + i) };
        parts.push(match elem_kind {
            ELEM_STR => format!("\"{}\"", unsafe { cstr(e) }),
            ELEM_FLOAT => format!("{}", f64::from_bits(e as u64)),
            ELEM_BOOL => if e != 0 { "true" } else { "false" }.to_string(),
            _ => e.to_string(),
        });
    }
    format!("[{}]", parts.join(", "))
}

/// Loud, one-per-process note: a NESTED container was rendered with a
/// defaulted element kind. The native array layout carries no per-element
/// tags, so the emitter's static hint cannot follow a buffer into a nested
/// slot — say so instead of silently rendering approximate values.
fn note_nested_default() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !NOTED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "tallow: print() rendered a nested container with defaulted element kinds \
             (the native array layout has no per-element tags); nested values may not match \
             the interpreter"
        );
    }
}

/// `print(<map>)` → the interpreter's `{…}` text.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_display_map(buf: *const i64, keys_are_strings: i32) -> *mut c_char {
    to_cstring(unsafe { render_map(buf, keys_are_strings) })
}

/// `print(<array>)` → the interpreter's `[…]` text. `elem_kind` is the
/// emitter's statically-known element kind (`ELEM_*`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_display_array(buf: *const i64, elem_kind: i32) -> *mut c_char {
    to_cstring(unsafe { render_array(buf, elem_kind) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a native array buffer `[count, e0, …]` (leaked on purpose — the
    /// emitted code never frees array buffers either).
    fn array_buf(items: &[i64]) -> *const i64 {
        let v: Vec<i64> = std::iter::once(items.len() as i64)
            .chain(items.iter().copied())
            .collect();
        Box::leak(v.into_boxed_slice()).as_ptr()
    }

    fn cstring(s: &str) -> i64 {
        CString::new(s).unwrap().into_raw() as i64
    }

    /// Build a native tagged map buffer `[count, k,v,…, t…]`.
    fn map_buf(keys_are_strings: bool, entries: &[(i64, i64, i64)]) -> *const i64 {
        let count = entries.len() as i64;
        let mut v: Vec<i64> = vec![count];
        for (k, val, _) in entries {
            v.push(*k);
            v.push(*val);
        }
        for (_, _, tag) in entries {
            v.push(*tag);
        }
        let _ = keys_are_strings;
        Box::leak(v.into_boxed_slice()).as_ptr()
    }

    fn render_map_s(buf: *const i64, string_keys: bool) -> String {
        unsafe { render_map(buf, if string_keys { 1 } else { 0 }) }
    }

    fn render_array_s(buf: *const i64, kind: i32) -> String {
        unsafe { render_array(buf, kind) }
    }

    #[test]
    fn array_of_ints_matches_interp_display() {
        let buf = array_buf(&[1, 2, 3]);
        assert_eq!(render_array_s(buf, ELEM_INT), "[1, 2, 3]");
    }

    #[test]
    fn empty_array_renders_brackets() {
        let buf = array_buf(&[]);
        assert_eq!(render_array_s(buf, ELEM_INT), "[]");
    }

    #[test]
    fn array_of_strings_matches_interp_display() {
        let buf = array_buf(&[cstring("ada"), cstring("bob")]);
        assert_eq!(render_array_s(buf, ELEM_STR), "[\"ada\", \"bob\"]");
    }

    #[test]
    fn array_of_bools_and_floats_match_interp_display() {
        let bools = array_buf(&[1, 0]);
        assert_eq!(render_array_s(bools, ELEM_BOOL), "[true, false]");
        let floats = array_buf(&[(3.5f64).to_bits() as i64, (2.0f64).to_bits() as i64]);
        assert_eq!(render_array_s(floats, ELEM_FLOAT), "[3.5, 2]");
    }

    #[test]
    fn map_of_scalars_matches_interp_display() {
        // {"k": 1, "j": "v"} — the 01_print_format fixture's map.
        let buf = map_buf(
            true,
            &[
                (cstring("k"), 1, TAG_INT),
                (cstring("j"), cstring("v"), TAG_STR),
            ],
        );
        assert_eq!(render_map_s(buf, true), "{\"k\": 1, \"j\": \"v\"}");
    }

    #[test]
    fn int_keyed_map_renders_keys_unquoted() {
        let buf = map_buf(false, &[(7, cstring("seven"), TAG_STR)]);
        assert_eq!(render_map_s(buf, false), "{7: \"seven\"}");
    }

    #[test]
    fn nested_map_value_recurses() {
        // {"u": {"n": 5}} — the nested-map edge case from the map backend.
        let inner = map_buf(true, &[(cstring("n"), 5, TAG_INT)]);
        let outer = map_buf(true, &[(cstring("u"), inner as i64, TAG_MAP)]);
        assert_eq!(render_map_s(outer, true), "{\"u\": {\"n\": 5}}");
    }

    #[test]
    fn map_keys_are_rendered_then_values_by_tag() {
        let buf = map_buf(
            true,
            &[
                (cstring("count"), 3, TAG_INT),
                (cstring("label"), cstring("x"), TAG_STR),
                (cstring("flag"), 1, TAG_BOOL),
                (cstring("nothing"), 0, TAG_NIL),
            ],
        );
        assert_eq!(
            render_map_s(buf, true),
            "{\"count\": 3, \"label\": \"x\", \"flag\": true, \"nothing\": nil}"
        );
    }

    #[test]
    fn null_buffer_renders_nil_not_garbage() {
        assert_eq!(render_map_s(std::ptr::null(), true), "nil");
        assert_eq!(render_array_s(std::ptr::null(), ELEM_INT), "nil");
    }

    #[test]
    fn ffi_entry_points_return_c_strings() {
        let buf = array_buf(&[1, 2, 3]);
        let p = tallow_display_array(buf, ELEM_INT);
        assert!(!p.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, "[1, 2, 3]");
    }
}
