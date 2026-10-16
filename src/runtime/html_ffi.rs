//! Runtime FFI: native lowering for `tallow.html.*` and `Extract.pattern`.
//!
//! The interpreter implements these through the Rust stdlib (`src/stdlib/html.rs`,
//! `src/stdlib/extract.rs`). Compiled `.tl` binaries cannot call Rust directly, so
//! this module exposes the same behaviour as C-ABI functions that codegen links
//! against — the same pattern `Browser`/`Page`/`Response` already use.
//!
//! Handle model (mirrors the browser FFI):
//!   * document handle = `Box<Html>` (scraper's parsed document)
//!   * element handle  = `Box<HtmlElementBox>` — the element's data is
//!     materialised at select time, so no document borrow is retained.
//!   * array value     = NATIVE tallow array, `[count: i64][elem0: i64]...`,
//!     built by `native_array` below. NOT a `Box<Vec<*mut c_void>>` FFI handle:
//!     a handle's `.len()` works in emitted code but indexing and iteration
//!     reinterpret the `Vec` header as slots and leak raw pointers as integers.
//!     Pointers are stored bitcast to i64, like a native string-array literal.
//!
//! Every function returns null on error and sets the last-error message.
//!
//! Absent values are NULL, not "": the compiled value model represents the
//! interpreter's `nil` as a NULL string pointer, and codegen renders it as `nil`
//! at every coercion (a pure-IR `select` in `coerce_to_string`). So
//! `attr(name)`/`id()`/`title()` with nothing to return give NULL while a
//! present-but-empty value stays `""` — exactly the distinction the interpreter
//! makes.

use std::ffi::{c_char, c_void};

use scraper::{Html, Selector};

use super::browser::native_array;
use super::{cstr_to_str, set_last_error, string_to_cstr};

/// A parsed document. Held alive by the document handle.
pub struct HtmlDocBox(Html);

/// Materialised element: the fields a `.tl` `Element` can read.
pub struct HtmlElementBox {
    tag: String,
    text: String,
    inner_html: String,
    outer_html: String,
    attrs: Vec<(String, String)>,
}

fn parse_selector(sel: &str) -> Option<Selector> {
    match Selector::parse(sel) {
        Ok(s) => Some(s),
        Err(_) => {
            set_last_error(format!("html: invalid CSS selector '{sel}'"));
            None
        }
    }
}

fn element_box(el: scraper::ElementRef<'_>) -> *mut c_void {
    let text: String = el.text().collect::<Vec<_>>().join("");
    let boxed = HtmlElementBox {
        tag: el.value().name().to_string(),
        text,
        inner_html: el.inner_html(),
        outer_html: el.html(),
        attrs: el
            .value()
            .attrs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    };
    Box::into_raw(Box::new(boxed)) as *mut c_void
}

fn element_array<'a, I: Iterator<Item = scraper::ElementRef<'a>>>(it: I) -> *mut c_void {
    // `element_box` already returns the boxed element's raw pointer, so store it
    // directly — wrapping it in another Box would hand `tallow_html_el_*` a
    // pointer-to-pointer and crash on the first field read.
    let items: Vec<i64> = it.map(|el| element_box(el) as i64).collect();
    native_array(items)
}

/// Build a native string array: `native_array` slots holding `string_to_cstr` values.
///
/// The one representation of a string array the runtime has, so it is `pub(crate)`
/// rather than duplicated by each producer — a second copy of this idiom would be a
/// second definition of the shape `tallow_array_get` reads.
pub(crate) fn string_array(items: Vec<String>) -> *mut c_void {
    let slots: Vec<i64> = items
        .into_iter()
        .map(|s| string_to_cstr(&s) as i64)
        .collect();
    native_array(slots)
}

// ── Document ─────────────────────────────────────────────────────────────

/// `html.parse(input)` -> document handle. Returns null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_parse(html: *const c_char) -> *mut c_void {
    let h = match unsafe { cstr_to_str(html) } {
        Some(s) => s,
        None => {
            set_last_error("html.parse: null or invalid input".to_string());
            return std::ptr::null_mut();
        }
    };
    Box::into_raw(Box::new(HtmlDocBox(Html::parse_document(h)))) as *mut c_void
}

/// `html.parse_bytes(input)` -> document handle (input treated as UTF-8 lossy).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_parse_bytes(bytes: *const c_char) -> *mut c_void {
    tallow_html_parse(bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_doc_free(doc: *mut c_void) {
    if !doc.is_null() {
        unsafe {
            drop(Box::from_raw(doc as *mut HtmlDocBox));
        }
    }
}

/// `doc.select(selector)` -> array handle of elements (never null; empty on no match).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_doc_select(doc: *mut c_void, selector: *const c_char) -> *mut c_void {
    if doc.is_null() {
        set_last_error("html.select: null document handle".to_string());
        return std::ptr::null_mut();
    }
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("html.select: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let Some(selector) = parse_selector(sel) else {
        return std::ptr::null_mut();
    };
    let doc_ref = unsafe { &*(doc as *const HtmlDocBox) };
    element_array(doc_ref.0.select(&selector))
}

/// `doc.select_one(selector)` -> element handle, or null when nothing matches.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_doc_select_one(
    doc: *mut c_void,
    selector: *const c_char,
) -> *mut c_void {
    if doc.is_null() {
        set_last_error("html.select_one: null document handle".to_string());
        return std::ptr::null_mut();
    }
    let sel = match unsafe { cstr_to_str(selector) } {
        Some(s) => s,
        None => {
            set_last_error("html.select_one: null or invalid selector".to_string());
            return std::ptr::null_mut();
        }
    };
    let Some(selector) = parse_selector(sel) else {
        return std::ptr::null_mut();
    };
    let doc_ref = unsafe { &*(doc as *const HtmlDocBox) };
    match doc_ref.0.select(&selector).next() {
        Some(el) => element_box(el),
        None => std::ptr::null_mut(),
    }
}

/// `doc.text()` -> all text nodes of the document, tags stripped.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_doc_text(doc: *mut c_void) -> *mut c_char {
    if doc.is_null() {
        set_last_error("html.text: null document handle".to_string());
        return std::ptr::null_mut();
    }
    let doc_ref = unsafe { &*(doc as *const HtmlDocBox) };
    let text: String = doc_ref.0.root_element().text().collect::<Vec<_>>().join("");
    string_to_cstr(&text)
}

/// `doc.title()` -> contents of `<title>`, or the empty string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_doc_title(doc: *mut c_void) -> *mut c_char {
    if doc.is_null() {
        set_last_error("html.title: null document handle".to_string());
        return std::ptr::null_mut();
    }
    let doc_ref = unsafe { &*(doc as *const HtmlDocBox) };
    // No <title> element at all → NULL, which the compiled model renders as
    // `nil` (the interpreter's value there). A present-but-empty <title> stays "".
    match Selector::parse("title")
        .ok()
        .and_then(|sel| doc_ref.0.select(&sel).next())
    {
        Some(el) => string_to_cstr(&el.text().collect::<Vec<_>>().join("")),
        None => std::ptr::null_mut(),
    }
}

/// `doc.links()` -> array handle of href strings, in document order.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_doc_links(doc: *mut c_void) -> *mut c_void {
    if doc.is_null() {
        set_last_error("html.links: null document handle".to_string());
        return std::ptr::null_mut();
    }
    let doc_ref = unsafe { &*(doc as *const HtmlDocBox) };
    let Ok(selector) = Selector::parse("a[href]") else {
        return string_array(Vec::new());
    };
    let hrefs: Vec<String> = doc_ref
        .0
        .select(&selector)
        .filter_map(|el| el.value().attr("href").map(|h| h.to_string()))
        .collect();
    string_array(hrefs)
}

// ── Element ──────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_free(el: *mut c_void) {
    if !el.is_null() {
        unsafe {
            drop(Box::from_raw(el as *mut HtmlElementBox));
        }
    }
}

/// Free a NATIVE-layout array produced by `tallow_html_*` (elements OR
/// strings). `is_string_array` selects which element type to drop.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_array_free(arr: *mut c_void, is_string_array: i32) {
    if arr.is_null() {
        return;
    }
    let count = unsafe { *(arr as *const i64) } as usize;
    for i in 0..count {
        let ptr = unsafe { *((arr as *const i64).add(i + 1)) } as *mut c_void;
        if ptr.is_null() {
            continue;
        }
        unsafe {
            if is_string_array != 0 {
                drop(std::ffi::CString::from_raw(ptr as *mut c_char));
            } else {
                drop(Box::from_raw(ptr as *mut HtmlElementBox));
            }
        }
    }
    let slots: Box<[i64]> =
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(arr as *mut i64, count + 1)) };
    drop(slots);
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_text(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        return string_to_cstr("");
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    string_to_cstr(&el_ref.text)
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_tag_name(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        return string_to_cstr("");
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    string_to_cstr(&el_ref.tag)
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_inner_html(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        return string_to_cstr("");
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    string_to_cstr(&el_ref.inner_html)
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_outer_html(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        return string_to_cstr("");
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    string_to_cstr(&el_ref.outer_html)
}

/// `el.attr(name)` / `el.attribute(name)` -> attribute value, or the empty string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_attribute(el: *mut c_void, name: *const c_char) -> *mut c_char {
    if el.is_null() {
        return std::ptr::null_mut();
    }
    let Some(name) = (unsafe { cstr_to_str(name) }) else {
        set_last_error("html.attr: null attribute name".to_string());
        return std::ptr::null_mut();
    };
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    // Absent → NULL (`nil` in the compiled value model); present-but-empty stays
    // an empty string. The interpreter makes exactly this distinction, so
    // `attr("missing") == nil` is true and `attr("empty") == ""` is true.
    match el_ref.attrs.iter().find(|(k, _)| k == name) {
        Some((_, v)) => string_to_cstr(v),
        None => std::ptr::null_mut(),
    }
}

/// `el.id()` -> the element's own `id` attribute, or NULL when absent. NULL is
/// how the compiled value model represents the interpreter's `nil` (codegen
/// renders a NULL string as `nil`), so an absent id prints exactly like the
/// interpreter. A present-but-empty `id=""` stays an empty string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_id(el: *mut c_void) -> *mut c_char {
    if el.is_null() {
        return std::ptr::null_mut();
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    match el_ref.attrs.iter().find(|(k, _)| k == "id") {
        Some((_, v)) => string_to_cstr(v),
        None => std::ptr::null_mut(),
    }
}

/// `el.has_attr(name)` -> 1/0 (the i64 the emitted code narrows to a bool).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_has_attr(el: *mut c_void, name: *const c_char) -> i64 {
    if el.is_null() {
        return 0;
    }
    let Some(name) = (unsafe { cstr_to_str(name) }) else {
        set_last_error("html.has_attr: null attribute name".to_string());
        return 0;
    };
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    i64::from(el_ref.attrs.iter().any(|(k, _)| k == name))
}

/// `el.classes()` -> native array of the `class` attribute's tokens, in order.
/// Mirrors `element_classes`: an element with no `class` yields an empty array.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_classes(el: *mut c_void) -> *mut c_void {
    if el.is_null() {
        return string_array(Vec::new());
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    let classes: Vec<String> = el_ref
        .attrs
        .iter()
        .find(|(k, _)| k == "class")
        .map(|(_, v)| v.split_whitespace().map(|c| c.to_string()).collect())
        .unwrap_or_default();
    string_array(classes)
}

/// `el.children()` -> native array of child ELEMENTS, mirroring
/// `element_children`: the element's own HTML is re-parsed as a fragment (the
/// handle holds no document borrow) and its element children are materialised.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_html_el_children(el: *mut c_void) -> *mut c_void {
    if el.is_null() {
        return string_array(Vec::new());
    }
    let el_ref = unsafe { &*(el as *const HtmlElementBox) };
    let fragment = Html::parse_fragment(&el_ref.outer_html);
    match first_content_element(&fragment) {
        Some(root) => element_array(root.child_elements()),
        None => element_array(std::iter::empty()),
    }
}

/// First html/head/body-free element of a fragment — same rule as
/// `stdlib::html::first_content_element`, so `children()` matches the interpreter.
fn first_content_element(fragment: &Html) -> Option<scraper::ElementRef<'_>> {
    let selector = Selector::parse("*").unwrap();
    fragment
        .select(&selector)
        .find(|el| !matches!(el.value().name(), "html" | "head" | "body"))
}

// ── Extract ──────────────────────────────────────────────────────────────

/// `Extract.pattern(html, pattern)` -> array handle of capture-group matches.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_extract_pattern(html: *const c_char, pattern: *const c_char) -> *mut c_void {
    let h = match unsafe { cstr_to_str(html) } {
        Some(s) => s,
        None => {
            set_last_error("Extract.pattern: null html".to_string());
            return std::ptr::null_mut();
        }
    };
    let p = match unsafe { cstr_to_str(pattern) } {
        Some(s) => s,
        None => {
            set_last_error("Extract.pattern: null pattern".to_string());
            return std::ptr::null_mut();
        }
    };
    string_array(crate::stdlib::extract::pattern_matches(h, p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::Value;

    /// Read the NATIVE array layout these FFI functions return:
    /// `[count: i64][elem0: i64]...` (see `native_array`).
    unsafe fn nat_len(arr: *mut c_void) -> i64 {
        *(arr as *const i64)
    }
    unsafe fn nat_get(arr: *mut c_void, i: usize) -> *mut c_void {
        *((arr as *const i64).add(i + 1)) as *mut c_void
    }

    fn sel(s: &str) -> *mut c_char {
        string_to_cstr(s) as *mut c_char
    }

    #[test]
    fn parse_and_select_one_roundtrip() {
        let html = sel("<html><head><title>Hello World</title></head><body><h1>Heads</h1></body></html>");
        let doc = tallow_html_parse(html);
        assert!(!doc.is_null());
        let h1 = tallow_html_doc_select_one(doc, sel("h1"));
        assert!(!h1.is_null());
        let text = tallow_html_el_text(h1);
        let text = unsafe { cstr_to_str(text) }.unwrap();
        assert_eq!(text, "Heads");
        tallow_html_el_free(h1);
        tallow_html_doc_free(doc);
        unsafe { drop(std::ffi::CString::from_raw(html)) };
    }

    #[test]
    fn title_and_links_and_text() {
        let html = sel("<html><head><title> T </title></head><body><a href=\"/a\">A</a><a href=\"/b\">B</a>hi</body></html>");
        let doc = tallow_html_parse(html);
        let title = unsafe { cstr_to_str(tallow_html_doc_title(doc)) }.unwrap().to_string();
        // The interpreter's `html.title()` does NOT trim, so neither does this.
        assert_eq!(title, " T ");
        let links = tallow_html_doc_links(doc);
        assert_eq!(unsafe { nat_len(links) }, 2);
        tallow_html_array_free(links, 1);
        let text = unsafe { cstr_to_str(tallow_html_doc_text(doc)) }.unwrap().to_string();
        assert!(text.contains("hi"));
        tallow_html_doc_free(doc);
        unsafe { drop(std::ffi::CString::from_raw(html)) };
    }

    #[test]
    fn select_returns_element_array_and_attribute() {
        let html = sel("<ul><li>x</li><li>y</li></ul>");
        let doc = tallow_html_parse(html);
        let arr = tallow_html_doc_select(doc, sel("li"));
        assert_eq!(unsafe { nat_len(arr) }, 2);
        let first = unsafe { nat_get(arr, 0) };
        assert_eq!(unsafe { cstr_to_str(tallow_html_el_text(first)) }.unwrap(), "x");
        tallow_html_array_free(arr, 0);
        tallow_html_doc_free(doc);
        unsafe { drop(std::ffi::CString::from_raw(html)) };
    }

    /// `el.id()` / `has_attr` / `classes` / `children` must agree with the
    /// interpreter's `HtmlElement` dispatch — a native arm with different
    /// semantics is exactly the silent divergence this module exists to avoid.
    #[test]
    fn element_getters_match_interpreter() {
        let src = r#"<div id="lead" class="a b"><span>x</span><span>y</span></div>"#;

        let html = sel(src);
        let doc = tallow_html_parse(html);
        let el = tallow_html_doc_select_one(doc, sel("div"));
        assert!(!el.is_null());

        let n_id = unsafe { cstr_to_str(tallow_html_el_id(el)) }
            .unwrap()
            .to_string();
        let n_has_id = tallow_html_el_has_attr(el, sel("id")) != 0;
        let n_has_nope = tallow_html_el_has_attr(el, sel("nope")) != 0;

        let n_classes = tallow_html_el_classes(el);
        let n_class_list: Vec<String> = (0..unsafe { nat_len(n_classes) } as usize)
            .map(|i| {
                unsafe { cstr_to_str(nat_get(n_classes, i) as *const c_char) }
                    .unwrap()
                    .to_string()
            })
            .collect();

        let n_children = tallow_html_el_children(el);
        let n_kid_count = unsafe { nat_len(n_children) };
        let n_kid0 = unsafe { cstr_to_str(tallow_html_el_text(nat_get(n_children, 0))) }
            .unwrap()
            .to_string();

        // Same element, through the interpreter's stdlib dispatch.
        let i_doc = crate::stdlib::html::dispatch("parse", vec![Value::String(src.into())])
            .unwrap()
            .unwrap();
        let i_el = crate::stdlib::html::dispatch_method(
            &i_doc,
            "select_one",
            vec![Value::String("div".into())],
        )
        .unwrap()
        .unwrap();
        let i_id = crate::stdlib::html::dispatch_method(&i_el, "id", vec![])
            .unwrap()
            .unwrap();
        let i_has_id = crate::stdlib::html::dispatch_method(
            &i_el,
            "has_attr",
            vec![Value::String("id".into())],
        )
        .unwrap()
        .unwrap();
        let i_classes = crate::stdlib::html::dispatch_method(&i_el, "classes", vec![])
            .unwrap()
            .unwrap();
        let i_children = crate::stdlib::html::dispatch_method(&i_el, "children", vec![])
            .unwrap()
            .unwrap();

        assert!(matches!(i_id, Value::String(ref s) if s == "lead"));
        assert_eq!(n_id, "lead");
        assert!(matches!(i_has_id, Value::Bool(true)));
        assert!(n_has_id && !n_has_nope);
        let i_class_count = if let Value::Array(v) = &i_classes {
            v.len()
        } else {
            panic!("interpreter classes() should be an array")
        };
        assert_eq!(i_class_count, n_class_list.len());
        assert_eq!(n_class_list, vec!["a".to_string(), "b".to_string()]);
        let i_kid_count = if let Value::Array(v) = &i_children {
            v.len() as i64
        } else {
            panic!("interpreter children() should be an array")
        };
        assert_eq!(i_kid_count, n_kid_count);
        assert_eq!(n_kid0, "x");

        tallow_html_array_free(n_classes, 1);
        tallow_html_array_free(n_children, 0);
        tallow_html_el_free(el);
        tallow_html_doc_free(doc);
        unsafe { drop(std::ffi::CString::from_raw(html)) };
    }

    #[test]
    fn null_handles_are_safe() {
        assert!(tallow_html_parse(std::ptr::null()).is_null());
        assert!(tallow_html_doc_select(std::ptr::null_mut(), sel("p")).is_null());
        assert!(tallow_html_doc_text(std::ptr::null_mut()).is_null());
        tallow_html_doc_free(std::ptr::null_mut());
        tallow_html_el_free(std::ptr::null_mut());
    }

    #[test]
    fn extract_pattern_matches() {
        let html = sel("<title>Hello World</title>");
        let arr = tallow_extract_pattern(html, sel("<title>(.*?)</title>"));
        assert_eq!(unsafe { nat_len(arr) }, 1);
        let first = unsafe { cstr_to_str(nat_get(arr, 0) as *const c_char) }.unwrap();
        assert_eq!(first, "Hello World");
        tallow_html_array_free(arr, 1);
        unsafe { drop(std::ffi::CString::from_raw(html)) };
    }

    /// `doc.text()` must agree byte-for-byte with the interpreter's
    /// `stdlib::html` path — including a trailing newline after `</html>`,
    /// which the interpreter keeps. Dropping it is a silent 1-char divergence
    /// between the native and interpreted runs of the same program.
    #[test]
    fn doc_text_matches_interpreter_path() {
        for html in [
            "<html><body><p>hi</p></body></html>\n",
            "<html><body><p>hi</p></body></html>",
            "<html>\n<body>\n<p>hi</p>\n</body>\n</html>\n",
        ] {
            let c = string_to_cstr(html);
            let doc = tallow_html_parse(c);
            let mine = unsafe { cstr_to_str(tallow_html_doc_text(doc)) }
                .unwrap()
                .to_string();
            let theirs = match crate::stdlib::html::dispatch_method(
                &Value::Struct {
                    name: "HtmlDocument".to_string(),
                    fields: vec![("_raw".to_string(), Value::String(html.to_string()))],
                },
                "text",
                vec![],
            ) {
                Some(Ok(v)) => v.as_string(),
                other => panic!("interp html.text failed: {other:?}"),
            };
            assert_eq!(mine, theirs, "doc.text() diverged for {html:?}");
            tallow_html_doc_free(doc);
            unsafe { drop(std::ffi::CString::from_raw(c)) };
        }
    }
}
