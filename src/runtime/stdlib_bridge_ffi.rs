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
//! * an element that starts with [`RAW_PREFIX`] is a value produced by an
//!   earlier bridge call; the bytes after the prefix are JSON and are decoded
//!   back into an interpreter `Value` (a struct keeps its `__type`);
//! * any other element is the UTF-8 bytes of a `String`.
//!
//! `tallow_json_i64` / `tallow_json_f64` / `tallow_json_bool` marshal the
//! non-string scalars into **prefixed** JSON text, so the codegen side does not
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
//! # Result encoding (and its known sharp edge)
//!
//! * a `String` result is returned as its raw UTF-8 bytes, so native `print`,
//!   concatenation and comparison see an ordinary C string;
//! * every other result is returned as `RAW_PREFIX ++ JSON`.
//!
//! The prefix is how the call site tells "a string the program should use" from
//! "a value that must go back to the bridge unchanged". It is a *runtime*
//! discriminator because codegen has no declared return type for stdlib module
//! calls: `import tallow.*` declarations are dropped during import resolution
//! (src/codegen.rs `resolve_imports`), so the bridge result is a bare `ptr`.
//! [FINDING — spike] a `String` whose first two bytes are `\x1fJ` is therefore
//! indistinguishable from a bridged value when passed back into a bridged call.
//! The sound fix is a distinct static kind (`LLType::JsonPtr`) so the decision
//! is made by the compiler, not by byte sniffing; see the spike report.

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

/// Decode one marshalled argument. `RAW_PREFIX` means JSON; otherwise a string.
unsafe fn decode_argument(pointer: *const c_char) -> Result<Value, String> {
    // SAFETY: `pointer` is a non-null C string supplied by the emitted code.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if let Some(json_bytes) = bytes.strip_prefix(RAW_PREFIX) {
        let json: serde_json::Value = serde_json::from_slice(json_bytes)
            .map_err(|error| format!("bridged value is not valid JSON: {error}"))?;
        json_to_value(&json)
    } else {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| format!("argument is not valid UTF-8: {error}"))?;
        Ok(Value::String(text.to_string()))
    }
}

/// Encode a dispatch result for the call site. See "Result encoding" above.
fn encode_result(value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
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
/// A non-finite float has no JSON spelling; it is marshalled as `null` and the
/// callee sees `nil`. Rust's own `Display` for `f64` is the shortest text that
/// round-trips, and `serde_json` parses it back to the same bits.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_json_f64(value: f64) -> *mut c_char {
    if value.is_finite() {
        json_cstring(&value.to_string())
    } else {
        json_cstring("null")
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
    match CString::new(bytes) {
        Ok(cstring) => cstring.into_raw(),
        // JSON text and the prefix are ASCII and contain no NUL.
        Err(_) => std::ptr::null_mut(),
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
