//! Generic stdlib bridge: ONE C entry point so a compiled Tallow binary can
//! call any module the interpreter's router (`crate::stdlib::dispatch`) knows,
//! instead of one hand-written emitter per module.
//!
//! # The gap this closes
//!
//! `emit_stdlib_module_call` (src/codegen.rs) matches module names and calls a
//! hand-written emitter; an unlisted module returns `Ok(None)` and the build
//! refuses with `native backend has no lowering for method …`. Eleven of eighty
//! `stdlib/*.tl` modules had a lowering, so a compiled program could not call
//! the other sixty-nine at all.
//!
//! This module does not implement any module. It calls the same dispatch the
//! interpreter calls, so the *semantics* of a bridged module are the
//! interpreter's semantics by construction — there is no second implementation
//! to drift.
//!
//! # ABI
//!
//! ```c
//! char *tallow_stdlib_call(const char *module, const char *method,
//!                          long argc, const char *const *argv);
//! ```
//!
//! `argv` (when `argc > 0`) points at `argc` C strings. Each element is one
//! already-marshalled argument:
//!
//! * an element that starts with [`RAW_PREFIX`] is JSON; it is decoded back into
//!   an interpreter `Value` (a struct keeps its `__type`, a JSON string becomes
//!   a `String` with its full byte length);
//! * an element that starts with [`FLOAT_PREFIX`] is a non-finite `f64`
//!   (`nan` / `inf` / `-inf`), decoded to `Value::Float`;
//! * any other element is the UTF-8 bytes of a `String`.
//!
//! `tallow_json_i64` / `tallow_json_f64` / `tallow_json_bool` marshal the
//! non-string scalars into **prefixed** text, so the codegen side does not
//! need to know anything about the callee's signature and the callee still sees
//! an `Int`/`Float`/`Bool` rather than the string `"2"`.
//!
//! # Memory contract
//!
//! The returned pointer is heap-allocated and **owned by the caller**: free it
//! with `tallow_free_string` (src/runtime/mod.rs). It is never aliased with an
//! argument. On failure the function returns NULL and sets
//! `tallow_last_error()`; the emitted code calls `tallow_stdlib_bridge_abort`,
//! which prints that message and aborts — a bridge failure is never a silent
//! default value.
//!
//! Which caller frees it, per declared result kind (`emit_stdlib_bridge_call`):
//!
//! * `Int` / `Float` / `Bool` — the decoder (`tallow_json_as_*`) takes ownership
//!   (`CString::from_raw`) and releases it before returning the scalar;
//! * `()` — released immediately at the call site, the program never reads it;
//! * `String`, a named struct, `BridgeOpaque`, and an undeclared result — the
//!   pointer is the program's value, so codegen releases it at the end of the
//!   block that binds it, and only when the binding provably does not escape
//!   (`bridge_binding_escapes`); a binding that escapes is left allocated rather
//!   than freed under an alias.
//!
//! Nothing frees a result twice: the two paths are exclusive by result kind.
//!
//! # Result encoding
//!
//! * a `String` result is returned as its raw UTF-8 bytes, so native `print`,
//!   concatenation and comparison see an ordinary C string;
//! * a non-finite `Float` result is returned as [`FLOAT_PREFIX`] + `nan` /
//!   `inf` / `-inf` (JSON cannot spell them, and `value_to_json` refuses them);
//! * every other result is returned as `RAW_PREFIX ++ JSON`.
//!
//! The prefix is how the call site tells "a string the program should use" from
//! "a value that must go back to the bridge unchanged". It is a *runtime*
//! discriminator, and on its own it is not a type: [FINDING — spike] a `String`
//! whose first two bytes are `\x1fJ` would be indistinguishable from a bridged
//! value when passed back into a bridged call.
//!
//! # Where the type comes from now
//!
//! `src/stdlib/signatures.rs` reads the declaration (`native fn ip.lookup(…) ->
//! AsnMatch`) out of the `stdlib/*.tl` sources the build script embeds, and
//! codegen maps it onto a representation: `Int`/`Float`/`Bool` are unboxed by
//! [`tallow_json_as_i64`] / [`tallow_json_as_f64`] / [`tallow_json_as_bool`],
//! `String` and structs keep the pointer, and a kind this pass does not decode
//! (`T?`, `[]T`, `Map<K,V>`, `Result<T>`) becomes `LLType::BridgeOpaque`, whose
//! only legal consumer is another bridged call — the bytes are never sniffed to
//! decide what a value is.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error};
use crate::agent_comm::{json_to_value, value_to_json};
use crate::interp::Value;

/// Marks a C string as "this is JSON for a bridged value, not a program string".
///
/// `\x1f` (unit separator) is not produced by any Tallow string literal renderer
/// and makes an accidental match on ordinary text vanishingly unlikely; it is
/// still a discriminator, not a type — see the module docs.
pub const RAW_PREFIX: &[u8] = b"\x1fJ";

/// Marks a C string as "this is an `f64` in [`float_tag`] spelling".
///
/// A typed tag, not JSON: JSON has no spelling for NaN or ±inf, and the only
/// alternatives are to send `null` (which the callee reads as `nil` and refuses
/// with `Expected number, got nil` — measured before this tag existed) or to
/// refuse a non-finite argument by name (which would make the compiled plane
/// diverge from the interpreter, which computes with NaN/inf). The tag carries
/// the value, so the callee receives the bit pattern the program wrote.
///
/// It is used in both directions: `tallow_json_f64` emits it for a non-finite
/// argument, `encode_result` emits it for a non-finite `Float` result, and both
/// `decode_argument` and `tallow_json_as_f64` accept it.
pub const FLOAT_PREFIX: &[u8] = b"\x1fF";

/// The spelling of a non-finite float inside a [`FLOAT_PREFIX`] payload.
///
/// These are exactly the words the interpreter prints for these values
/// (`format_float_c`, src/interp.rs) and the words C's `%g` prints for them, so
/// a payload that is echoed back to the program reads the same on both planes.
fn float_tag(value: f64) -> &'static str {
    if value.is_nan() {
        "nan"
    } else if value.is_sign_positive() {
        "inf"
    } else {
        "-inf"
    }
}

/// Read a [`FLOAT_PREFIX`] payload back to the `f64` it encodes.
///
/// A whitelist rather than `str::parse`, so a payload this runtime did not
/// write (and a spelling a locale might accept) is refused instead of
/// interpreted.
fn parse_float_tag(tag: &[u8]) -> Option<f64> {
    match tag {
        b"nan" => Some(f64::NAN),
        b"inf" => Some(f64::INFINITY),
        b"-inf" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

/// Call `module.method(args)` through the interpreter's own stdlib router.
///
/// See the module docs for the argument and result encodings and for who owns
/// the returned string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_stdlib_call(
    module: *const c_char,
    method: *const c_char,
    argc: i64,
    argv: *const *const c_char,
) -> *mut c_char {
    let Some(module) = (unsafe { cstr_to_str(module) }) else {
        set_last_error("stdlib bridge: module name is not a UTF-8 string".to_string());
        return std::ptr::null_mut();
    };
    let Some(method) = (unsafe { cstr_to_str(method) }) else {
        set_last_error("stdlib bridge: method name is not a UTF-8 string".to_string());
        return std::ptr::null_mut();
    };
    if argc < 0 {
        set_last_error(format!(
            "stdlib bridge: {module}.{method} called with negative argument count {argc}"
        ));
        return std::ptr::null_mut();
    }
    let argc = argc as usize;

    let mut args: Vec<Value> = Vec::with_capacity(argc);
    if argc > 0 {
        if argv.is_null() {
            set_last_error(format!(
                "stdlib bridge: {module}.{method} declared {argc} argument(s) but got a null argv"
            ));
            return std::ptr::null_mut();
        }
        for index in 0..argc {
            // SAFETY: the caller emitted an alloca'd array of `argc` pointers.
            let element = unsafe { *argv.add(index) };
            if element.is_null() {
                set_last_error(format!(
                    "stdlib bridge: {module}.{method} argument {} is a null pointer",
                    index + 1
                ));
                return std::ptr::null_mut();
            }
            match unsafe { decode_argument(element) } {
                Ok(value) => args.push(value),
                Err(message) => {
                    set_last_error(format!(
                        "stdlib bridge: {module}.{method} argument {}: {message}",
                        index + 1
                    ));
                    return std::ptr::null_mut();
                }
            }
        }
    }

    match crate::stdlib::dispatch(module, method, args) {
        Some(Ok(value)) => match encode_result(&value) {
            Ok(bytes) => match CString::new(bytes) {
                Ok(cstring) => cstring.into_raw(),
                Err(_) => {
                    set_last_error(format!(
                        "stdlib bridge: {module}.{method} returned a string containing a NUL byte; \
                         a C string cannot carry it"
                    ));
                    std::ptr::null_mut()
                }
            },
            Err(message) => {
                set_last_error(format!("stdlib bridge: {module}.{method}: {message}"));
                std::ptr::null_mut()
            }
        },
        Some(Err(message)) => {
            set_last_error(format!("{message}"));
            std::ptr::null_mut()
        }
        None => {
            set_last_error(format!(
                "stdlib bridge: the interpreter's router has no dispatch for {module}.{method}"
            ));
            std::ptr::null_mut()
        }
    }
}

/// Decode one marshalled argument. See "Argument encoding" in the module docs:
/// [`RAW_PREFIX`] is JSON, [`FLOAT_PREFIX`] is a typed non-finite float, and
/// anything else is the raw UTF-8 of a program `String`.
unsafe fn decode_argument(pointer: *const c_char) -> Result<Value, String> {
    // SAFETY: `pointer` is a non-null C string supplied by the emitted code.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if let Some(json_bytes) = bytes.strip_prefix(RAW_PREFIX) {
        let json: serde_json::Value = serde_json::from_slice(json_bytes)
            .map_err(|error| format!("bridged value is not valid JSON: {error}"))?;
        json_to_value(&json)
    } else if let Some(tag) = bytes.strip_prefix(FLOAT_PREFIX) {
        parse_float_tag(tag)
            .map(Value::Float)
            .ok_or_else(|| format!("malformed float tag `{}`", String::from_utf8_lossy(tag)))
    } else {
        // A program `String` arrives as its raw UTF-8 bytes. Compiled Tallow
        // strings are C strings, so the byte range this reads is the one the
        // producer wrote up to the terminator; a `String` whose bytes the
        // compiler knows contain an interior NUL is marshalled by codegen as a
        // `RAW_PREFIX` JSON string instead, which carries its length (F3).
        let text = std::str::from_utf8(bytes)
            .map_err(|error| format!("argument is not valid UTF-8: {error}"))?;
        Ok(Value::String(text.to_string()))
    }
}

/// Encode a dispatch result for the call site. See "Result encoding" above.
fn encode_result(value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        // A non-finite float has no JSON spelling and `value_to_json` refuses it
        // outright (`cannot serialize NaN/Infinity float`), which would turn a
        // legitimate NaN result into a bridge failure. The typed float tag
        // carries the bit pattern instead.
        Value::Float(number) if !number.is_finite() => Ok(float_payload(*number)),
        // A `Result` has no native representation at a bridged call site: the
        // emitted code cannot `?`-unwrap it, so a domain error must fail loudly
        // rather than be silently unwrapped like the interpreter's `?` would.
        Value::Err(message) => Err(format!(
            "module returned Err({}) and the generic bridge has no Result unwrapping",
            message.as_string()
        )),
        other => {
            let json = value_to_json(other)?;
            let text = serde_json::to_vec(&json)
                .map_err(|error| format!("cannot serialise the result to JSON: {error}"))?;
            let mut encoded = Vec::with_capacity(RAW_PREFIX.len() + text.len());
            encoded.extend_from_slice(RAW_PREFIX);
            encoded.extend_from_slice(&text);
            Ok(encoded)
        }
    }
}

/// A [`FLOAT_PREFIX`] payload for one non-finite `f64`.
fn float_payload(value: f64) -> Vec<u8> {
    let tag = float_tag(value);
    let mut encoded = Vec::with_capacity(FLOAT_PREFIX.len() + tag.len());
    encoded.extend_from_slice(FLOAT_PREFIX);
    encoded.extend_from_slice(tag.as_bytes());
    encoded
}

/// Marshal an `i64` argument into JSON number text. Free with `tallow_free_string`.
///
/// The text carries [`RAW_PREFIX`]: without it the decoder cannot tell the
/// number `2` from the string `"2"`, and `decimal.decimal_add(a, b, 2)` would
/// receive the *string* `"2"` as its scale (measured: native `3.7500000000`
/// where the interpreter printed `3.75`). A prefixed element is JSON and keeps
/// its type; an unprefixed element is a string.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_i64(value: i64) -> *mut c_char {
    json_cstring(&value.to_string())
}

/// Marshal an `f64` argument into JSON number text. Free with `tallow_free_string`.
///
/// A finite float is the shortest decimal text that round-trips (`serde_json`
/// parses it back to the same bits). A non-finite one has no JSON spelling, so
/// it is marshalled as a [`FLOAT_PREFIX`] typed tag instead: sending `null` made
/// the callee read `nil` and abort with `Expected number, got nil`, and refusing
/// by name would make the compiled plane disagree with the interpreter, which
/// computes with NaN/±inf.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_f64(value: f64) -> *mut c_char {
    if value.is_finite() {
        json_cstring(&value.to_string())
    } else {
        cstring_from_bytes(&float_payload(value))
    }
}

/// Marshal a `bool` (as an i32 from the emitted `zext`) into JSON `true`/`false`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_bool(value: i32) -> *mut c_char {
    json_cstring(if value != 0 { "true" } else { "false" })
}

/// Prefix JSON text with [`RAW_PREFIX`] so `decode_argument` reads it as JSON
/// and not as a program string.
fn json_cstring(json: &str) -> *mut c_char {
    let mut bytes = Vec::with_capacity(RAW_PREFIX.len() + json.len());
    bytes.extend_from_slice(RAW_PREFIX);
    bytes.extend_from_slice(json.as_bytes());
    cstring_from_bytes(&bytes)
}

/// Hand a marshalled payload to the caller. `None` (null) when the bytes
/// contain a NUL, which no payload this module builds ever does.
fn cstring_from_bytes(bytes: &[u8]) -> *mut c_char {
    match CString::new(bytes) {
        Ok(cstring) => cstring.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ── Result unboxing ─────────────────────────────────────────────────────────
//
// These are the missing half of the bridge. Codegen used to have no declared
// return type for a stdlib module call, so a bridged `Int` came back as a `ptr`
// and `print` rendered the marshalled form (`\x1fJ1`). `stdlib/signatures.rs`
// now reads the declaration and the emitted code calls one of these three.
//
// Contract, shared by all three:
//
// * the pointer is **taken and freed** — it is the value `tallow_stdlib_call`
//   returned and nothing else aliases it;
// * `what` is the interned `module.method` label, used only in the message;
// * a payload that is not the declared scalar **aborts**, naming the call and
//   what arrived. It never returns 0/false as a default: a bridge that answers
//   0 for a failed decode is the defect the runtime removed from `len()`.

/// What a bridged result payload turned out to be.
///
/// Two shapes, because one of them has no JSON spelling: a non-finite `Float`
/// arrives as a [`FLOAT_PREFIX`] typed tag (see [`float_payload`]) and would
/// otherwise have to be refused.
enum BridgePayload {
    Json(serde_json::Value),
    NonFinite(f64),
}

/// Decode a bridged result as an `Int` (`i64`). Aborts on anything else.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_as_i64(value: *mut c_char, what: *const c_char) -> i64 {
    match take_payload(value, what, "Int") {
        BridgePayload::Json(json) => match json.as_i64() {
            Some(number) => number,
            None => abort_expected(what, "Int", &json),
        },
        BridgePayload::NonFinite(number) => abort_expected_raw(
            what,
            "Int",
            &format!("the bridge returned the non-finite float `{}`", float_tag(number)),
        ),
    }
}

/// Decode a bridged result as a `Float` (`f64`). Aborts on anything else.
///
/// A JSON *integer* payload is accepted and widens exactly — it is a number, and
/// `serde_json`'s `as_f64` cannot lose it. A non-numeric payload (a string, an
/// object, `null`) aborts rather than becoming `0.0`. A non-finite result
/// arrives as a [`FLOAT_PREFIX`] tag and is returned as the bit pattern it names.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_as_f64(value: *mut c_char, what: *const c_char) -> f64 {
    match take_payload(value, what, "Float") {
        BridgePayload::Json(json) => match json.as_f64() {
            Some(number) => number,
            None => abort_expected(what, "Float", &json),
        },
        BridgePayload::NonFinite(number) => number,
    }
}

/// Decode a bridged result as a `Bool`, returned as `i32` (`0`/`1`) because the
/// emitted code narrows it with `icmp ne i32 …, 0`. Aborts on anything else.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_as_bool(value: *mut c_char, what: *const c_char) -> i32 {
    match take_payload(value, what, "Bool") {
        BridgePayload::Json(json) => match json.as_bool() {
            Some(flag) => i32::from(flag),
            None => abort_expected(what, "Bool", &json),
        },
        BridgePayload::NonFinite(number) => abort_expected_raw(
            what,
            "Bool",
            &format!("the bridge returned the non-finite float `{}`", float_tag(number)),
        ),
    }
}

/// Take ownership of a bridged result and decode it as prefixed JSON, or as a
/// non-finite float tag.
///
/// Aborts — naming the call — when the pointer is NULL, when it is not a
/// marshalled (`\x1fJ` / `\x1fF`) value at all (a plain `String` result reaching
/// a call site that declared `Int`), when the bytes are not JSON, or when a
/// float tag is not one this runtime writes.
fn take_payload(
    value: *mut c_char,
    what: *const c_char,
    expected: &str,
) -> BridgePayload {
    if value.is_null() {
        abort_expected_raw(what, expected, "the call returned no value (null)");
    }
    // SAFETY: `value` came from `tallow_stdlib_call` (or an equivalent
    // `CString::into_raw`) and is handed to us exactly once; `from_raw` takes
    // ownership so the allocation is released on every path out of here.
    let cstring = unsafe { CString::from_raw(value) };
    let bytes = cstring.as_bytes();
    if let Some(tag) = bytes.strip_prefix(FLOAT_PREFIX) {
        return match parse_float_tag(tag) {
            Some(number) => BridgePayload::NonFinite(number),
            None => abort_expected_raw(
                what,
                expected,
                &format!("the bridge returned the malformed float tag `{}`", lossy_preview(tag)),
            ),
        };
    }
    let Some(json_bytes) = bytes.strip_prefix(RAW_PREFIX) else {
        let shown = lossy_preview(bytes);
        abort_expected_raw(
            what,
            expected,
            &format!("the bridge returned the plain string `{shown}`"),
        );
    };
    match serde_json::from_slice::<serde_json::Value>(json_bytes) {
        Ok(json) => BridgePayload::Json(json),
        Err(error) => abort_expected_raw(
            what,
            expected,
            &format!("the bridged payload is not valid JSON: {error}"),
        ),
    }
}

/// A short, printable rendering of a bridged payload for a diagnostic.
fn lossy_preview(bytes: &[u8]) -> String {
    const LIMIT: usize = 64;
    let text = String::from_utf8_lossy(bytes).replace('\n', "\\n");
    if text.chars().count() <= LIMIT {
        text
    } else {
        let head: String = text.chars().take(LIMIT).collect();
        format!("{head}…")
    }
}

/// The payload decoded, but not to the scalar the declaration promised.
fn abort_expected(what: *const c_char, expected: &str, got: &serde_json::Value) -> ! {
    abort_expected_raw(what, expected, &format!("the bridge returned {got}"))
}

/// Print the standard task-and-reason sentence and abort.
///
/// The interpreter raises at the same point, so failing loudly here keeps the
/// two planes' *verdicts* aligned even though the native plane has no exception
/// mechanism.
fn abort_expected_raw(what: *const c_char, expected: &str, reason: &str) -> ! {
    let call = if what.is_null() {
        "a bridged stdlib call".to_string()
    } else {
        // SAFETY: `what` is the interned literal the emitted code passed.
        unsafe { CStr::from_ptr(what) }
            .to_string_lossy()
            .into_owned()
    };
    eprintln!(
        "runtime error: {call} declared a{} {expected} result, but {reason}",
        expected_article(expected)
    );
    std::process::abort();
}

/// `a`/`an` for the type name, so the sentence reads as English.
fn expected_article(expected: &str) -> &'static str {
    match expected.as_bytes().first() {
        Some(b'A' | b'E' | b'I' | b'O' | b'U') => "n",
        _ => "",
    }
}

/// Report a failed bridged call and abort.
///
/// The interpreter raises at the same point; native code has no exception
/// mechanism, so it prints the same kind of sentence and aborts. Emitting a
/// default value instead would be the silently-wrong class this backend refuses
/// everywhere else.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_stdlib_bridge_abort() -> ! {
    let last = super::tallow_last_error();
    let message = if last.is_null() {
        "stdlib bridge: call failed without an error message".to_string()
    } else {
        // SAFETY: `tallow_last_error` returns a valid NUL-terminated string.
        unsafe { CStr::from_ptr(last) }
            .to_string_lossy()
            .into_owned()
    };
    eprintln!("runtime error: {message}");
    std::process::abort();
}
