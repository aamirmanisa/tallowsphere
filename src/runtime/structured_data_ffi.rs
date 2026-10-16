//! Runtime FFI: `StructuredData.extract`.
//!
//! # Shape
//!
//! `StructuredData` is `{json_ld: []String, open_graph: Map<String,String>,
//! has_json_ld: bool}` (`stdlib/browser.tl:434`). Codegen allocates
//! `%struct.StructuredData` itself and takes `json_ld` and `has_json_ld` through
//! out-params, while `open_graph` travels through the **return slot** — nothing is
//! returned through a struct pointer. That split follows `tallow_crawler_from_links`
//! exactly (it returns the one computed string field and writes the rest out-param),
//! which keeps refusal propagation on the path codegen already has:
//! `emit_runtime_string_null_check`.
//!
//! Returning a struct pointer from here would couple the LLVM struct layout to a
//! hand-written Rust `#[repr(C)]`, which then breaks *silently* on any field
//! reorder, width change or padding difference. Out-params keep layout owned by
//! codegen — the same trade `tallow_page_cache_create`, `tallow_crawler_from_links`
//! and `tallow_gzip_decompress(ptr, i64, ptr)` make.
//!
//! # The array is a real runtime array, not a raw `**c_char`
//!
//! `json_ld` is handed back as `*mut c_void`, the SAME shape every other string-array
//! producer returns (`html_ffi::string_array` → `native_array`: `[count][slot…]` as a
//! boxed `[i64]`), because that is what `tallow_array_len` / `tallow_array_get` read
//! and what codegen's `.len` routing expects for a `StringArray` field.
//!
//! An earlier draft of this binding specified a bare `*mut *mut c_char` here. That
//! would not have worked: the array object has exactly one constructor per producer
//! (`native_array`) and no public constructor exists, so a raw C array could not be
//! turned into a value the readers accept.
//!
//! # `open_graph` is a Map value, in the runtime's one Map layout
//!
//! The interpreter returns a genuine `Value::Map` (`stdlib/browser.rs:73`, asserted at
//! `:1430`). The native returns the same map in the layout `ExprKind::MapLit` lowers to
//! (`codegen.rs:4699`) and `emit_map_len` (`:15612`) / `emit_map_get` (`:15779`) /
//! `emit_map_keys` / `emit_map_values` read: `[count][k0][v0]…[kN][vN][t0]…[tN]`, key and
//! value slots carrying string pointers, each value tagged `TAG_I8PTR`. The struct field is
//! declared `Map<String,String>` in the `StructuredData` registration, which is what routes
//! `.len` and indexing on `sd.open_graph` to the map path instead of to `strlen`.
//!
//! This replaced a serialized `key<TAB>value` string. That encoding existed because the field
//! was declared `String` and the map kind had no consumer, so `.len` read the byte length in
//! AOT and the entry count when interpreted. Both engines now read the entry count;
//! `tests/structured_data_parity.rs` asserts that, key by key.
//!
//! # Contract
//!
//! A **non-null return** means both out-parameters were written; **null** means neither
//! may be read and `tallow_last_error` is set. Nothing is written until every
//! allocation has succeeded, so a partial write cannot be observed. A null
//! out-parameter is a codegen bug and is refused rather than written through.
//!
//! The values come from `stdlib::browser::structured_data_extract`, the same function
//! the interpreter's `StructuredData.extract` arm calls, so the two engines read one
//! HTML document the same way — their only difference is the `open_graph` encoding
//! described above.

use std::os::raw::{c_char, c_void};

use super::html_ffi::string_array;
use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::interp::Value;
use crate::stdlib::browser::structured_data_extract;

/// `structured_data_extract(html: String) -> StructuredData`.
///
/// Returns `open_graph` serialized (see the module header); writes `json_ld` (a native
/// string array) and `has_json_ld` (1 or 0) through the two out-parameters.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_structured_data_extract(
    html: *const c_char,
    out_json_ld: *mut *mut c_void,
    out_has_json_ld: *mut i64,
) -> *mut c_void {
    if out_json_ld.is_null() || out_has_json_ld.is_null() {
        set_last_error("StructuredData.extract: null out-parameter".to_string());
        return std::ptr::null_mut();
    }
    let html = match unsafe { cstr_to_str(html) } {
        Some(s) => s,
        None => {
            set_last_error("StructuredData.extract: expected an HTML string argument".to_string());
            return std::ptr::null_mut();
        }
    };

    let fields = match structured_data_extract(vec![Value::String(html.to_string())]) {
        Ok(Value::Struct { fields, .. }) => fields,
        Ok(other) => {
            set_last_error(format!(
                "StructuredData.extract: expected a Struct, got {}",
                value_kind(&other)
            ));
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(format!("StructuredData.extract: {e}"));
            return std::ptr::null_mut();
        }
    };

    // Read the three fields BY NAME. The facade's own doc records a revision where
    // one field was misnamed and `has_json_ld` was missing while its test still
    // passed on the invented name — positional reads are how that survives.
    let json_ld = match array_of_strings(&fields, "json_ld") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    let open_graph = match map_entries(&fields, "open_graph") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };
    let has_json_ld = match bool_field(&fields, "has_json_ld") {
        Ok(v) => v,
        Err(e) => {
            set_last_error(e);
            return std::ptr::null_mut();
        }
    };

    // Build every value BEFORE writing any of them: the contract says a partial
    // write is unobservable, so the allocations cannot be interleaved with stores.
    let array = string_array(json_ld);
    let map = map_value(&open_graph);

    unsafe {
        *out_json_ld = array;
        *out_has_json_ld = i64::from(has_json_ld);
    }
    map
}

/// The declared field, or a refusal naming the field that is missing.
fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Result<&'a Value, String> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
        .ok_or_else(|| format!("StructuredData.extract: no field named {name:?}"))
}

fn array_of_strings(fields: &[(String, Value)], name: &str) -> Result<Vec<String>, String> {
    match field(fields, name)? {
        Value::Array(items) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.clone()),
                other => Err(format!(
                    "StructuredData.extract: {name} must hold strings, found {}",
                    value_kind(other)
                )),
            })
            .collect(),
        other => Err(format!(
            "StructuredData.extract: {name} must be an array, found {}",
            value_kind(other)
        )),
    }
}

/// The `open_graph` entries as string pairs, in document order.
///
/// The interpreter hands back a `Value::Map` (`stdlib/browser.rs:73`) and this is
/// that map's contents, read by name so a renamed field is a refusal rather than a
/// silent empty result.
fn map_entries(fields: &[(String, Value)], name: &str) -> Result<Vec<(String, String)>, String> {
    match field(fields, name)? {
        Value::Map(pairs) => {
            let mut out = Vec::with_capacity(pairs.len());
            for (k, v) in pairs {
                match (k, v) {
                    (Value::String(k), Value::String(v)) => out.push((k.clone(), v.clone())),
                    (k, _) => {
                        return Err(format!(
                            "StructuredData.extract: {name} must hold string pairs, found {}",
                            value_kind(k)
                        ));
                    }
                }
            }
            Ok(out)
        }
        other => Err(format!(
            "StructuredData.extract: {name} must be a Map, found {}",
            value_kind(other)
        )),
    }
}

/// The tag `LLType::I8Ptr` carries in a map's trailing tag array (`codegen.rs:83`).
/// A `*mut c_char` slot is a pointer, and the map readers dispatch on the tag to
/// decide whether to `inttoptr` it back before printing or comparing.
const TAG_I8PTR: i64 = 1;

/// A Map value in the runtime's one Map layout — the shape `ExprKind::MapLit`
/// lowers to and `emit_map_len` / `emit_map_get` / `emit_map_keys` read:
///
/// ```text
/// [count][k0][v0][k1][v1]…[kN][vN][t0][t1]…[tN]
///   0     1    2   3    4      1+2N 2+2N  1+2N …      (i64 slots)
/// ```
///
/// Keys and values are string pointers carried as `i64` (the same coercion
/// `coerce_to_i64` applies to a string in a map literal), and every value's tag is
/// `TAG_I8PTR`. The keys are what make this a *string-keyed* map: the readers scan
/// with `strcmp` on the key slots, which is why the `String` in
/// `Map<String,String>` is load-bearing rather than documentation.
///
/// The boxed slice is handed to the caller, which owns it for the life of the
/// struct field — the same ownership a map literal's buffer has.
fn map_value(entries: &[(String, String)]) -> *mut c_void {
    let count = entries.len();
    let mut slots: Vec<i64> = Vec::with_capacity(1 + count * 3);
    slots.push(count as i64);
    for (k, v) in entries {
        slots.push(string_to_cstr(k) as i64);
        slots.push(string_to_cstr(v) as i64);
    }
    for _ in 0..count {
        slots.push(TAG_I8PTR);
    }
    let boxed: Box<[i64]> = slots.into_boxed_slice();
    Box::into_raw(boxed) as *mut c_void
}

fn bool_field(fields: &[(String, Value)], name: &str) -> Result<bool, String> {
    match field(fields, name)? {
        Value::Bool(b) => Ok(*b),
        other => Err(format!(
            "StructuredData.extract: {name} must be a bool, found {}",
            value_kind(other)
        )),
    }
}

/// Only for refusal messages — a mismatch must name what it actually got.
fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Nil => "nil",
        Value::Bool(_) => "a bool",
        Value::Int(_) => "an int",
        Value::Float(_) => "a float",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Map(_) => "a map",
        Value::Struct { .. } => "a struct",
        _ => "another value",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a native string array back the way generated code does: slot 0 is the
    /// count, slots 1..=n are `*mut c_char` values.
    fn read_array(arr: *mut c_void) -> Vec<String> {
        assert!(!arr.is_null(), "array must not be null");
        let slots = arr as *mut i64;
        let n = unsafe { *slots } as usize;
        (1..=n)
            .map(|i| {
                let p = unsafe { *slots.add(i) } as *const c_char;
                unsafe { cstr_to_str(p) }
                    .expect("slot holds a valid C string")
                    .to_string()
            })
            .collect()
    }

    /// Read a Map value the way generated code does: slot 0 is the count, entry `i`
    /// occupies key slot `1 + 2i` and value slot `2 + 2i`, and the `count` tags follow.
    /// The tags are asserted rather than skipped: a wrong tag is what makes a reader
    /// treat a string pointer as an integer, so a silent layout drift has to fail here.
    fn read_map(map: *mut c_void) -> Vec<(String, String)> {
        assert!(!map.is_null(), "map must not be null");
        let slots = map as *mut i64;
        let count = unsafe { *slots } as usize;
        let tags_at = 1 + 2 * count;
        for i in 0..count {
            let tag = unsafe { *slots.add(tags_at + i) };
            assert_eq!(tag, TAG_I8PTR, "value {i} must carry the pointer tag");
        }
        (0..count)
            .map(|i| {
                let key = unsafe { *slots.add(1 + 2 * i) } as *const c_char;
                let value = unsafe { *slots.add(2 + 2 * i) } as *const c_char;
                (
                    unsafe { cstr_to_str(key) }
                        .expect("key slot holds a valid C string")
                        .to_string(),
                    unsafe { cstr_to_str(value) }
                        .expect("value slot holds a valid C string")
                        .to_string(),
                )
            })
            .collect()
    }

    /// Returns `(json_ld, open_graph entries, has_json_ld)`.
    fn call(html: &str) -> (Vec<String>, Vec<(String, String)>, i64) {
        let c = std::ffi::CString::new(html).unwrap();
        let mut arr: *mut c_void = std::ptr::null_mut();
        let mut has: i64 = -1;
        let og = tallow_structured_data_extract(c.as_ptr(), &mut arr, &mut has);
        assert!(!og.is_null(), "expected success for {html:?}");
        (read_array(arr), read_map(og), has)
    }

    #[test]
    fn null_out_params_fail_closed() {
        let c = std::ffi::CString::new("<html></html>").unwrap();
        let mut arr: *mut c_void = std::ptr::null_mut();
        // a codegen bug, refused rather than written through
        let og = tallow_structured_data_extract(c.as_ptr(), &mut arr, std::ptr::null_mut());
        assert!(og.is_null(), "a bad call site must refuse, not half-write");
        assert!(arr.is_null(), "nothing may be written on refusal");
    }

    #[test]
    fn a_null_html_argument_is_refused() {
        let mut arr: *mut c_void = std::ptr::null_mut();
        let mut has: i64 = 0;
        let og = tallow_structured_data_extract(std::ptr::null(), &mut arr, &mut has);
        assert!(og.is_null());
        assert!(arr.is_null(), "nothing may be written on refusal");
    }

    #[test]
    fn json_ld_travels_as_a_real_array_and_the_flag_says_so() {
        let html = r#"<html><head>
            <meta property="og:title" content="Hello">
            <script type="application/ld+json">{"@type":"Product"}</script>
            </head><body>hi</body></html>"#;
        let (json_ld, open_graph, has) = call(html);
        assert_eq!(has, 1, "a page with JSON-LD reports the flag as 1");
        assert_eq!(json_ld.len(), 1, "one raw JSON-LD text block");
        assert!(
            json_ld[0].contains("Product"),
            "the TEXT form is what a []String field holds, got {:?}",
            json_ld[0]
        );
        assert!(
            open_graph.contains(&("title".to_string(), "Hello".to_string())),
            "open_graph should carry title -> Hello, got {open_graph:?}"
        );
    }

    #[test]
    fn a_page_without_json_ld_reports_the_flag_as_zero() {
        let (json_ld, _, has) = call("<html><body>no structured data</body></html>");
        assert_eq!(has, 0);
        assert!(json_ld.is_empty(), "an empty array, not a null pointer");
    }

    #[test]
    fn the_open_graph_map_keeps_document_order() {
        let html = r#"<html><head>
            <meta property="og:zeta" content="z">
            <meta property="og:alpha" content="a">
            </head></html>"#;
        let (_, open_graph, _) = call(html);
        assert_eq!(
            open_graph,
            vec![
                ("zeta".to_string(), "z".to_string()),
                ("alpha".to_string(), "a".to_string())
            ],
            "document order, not sorted"
        );
    }

    #[test]
    fn an_open_graph_meta_in_either_attribute_order_is_captured() {
        // The facade is deliberately order-independent; this binds the native to that
        // property so a future rewrite cannot silently drop half of real pages.
        let forward = call(r#"<meta property="og:title" content="Hello">"#).1;
        let reversed = call(r#"<meta content="Hello" property="og:title">"#).1;
        assert_eq!(forward, reversed);
        assert_eq!(forward, vec![("title".to_string(), "Hello".to_string())]);
    }

    #[test]
    fn several_json_ld_blocks_all_travel_in_one_array() {
        let html = r#"<html><head>
            <script type="application/ld+json">{"a":1}</script>
            <script type="application/ld+json">{"b":2}</script>
            </head></html>"#;
        let (json_ld, _, has) = call(html);
        assert_eq!(json_ld.len(), 2, "one slot per block, in document order");
        assert!(json_ld[0].contains("\"a\"") && json_ld[1].contains("\"b\""));
        assert_eq!(has, 1);
    }
}
