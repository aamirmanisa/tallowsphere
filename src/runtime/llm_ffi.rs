//! FFI bridge for `llm.complete` in compiled Tallow programs.
//!
//! The interpreter builds a `Completion` struct from `stdlib::llm::dispatch`.
//! Compiled code cannot call that Rust function directly, so this module
//! exposes one C symbol that does the same work and hands back a
//! `#[repr(C)]` record whose layout matches codegen's `%struct.Completion`
//! field for field — the same shape `Transfer.chunk` uses for `ChunkInfo`.
//!
//! Ownership: the returned record and every string in it are heap allocations
//! owned by the compiled program; nothing is freed, because a Tallow program
//! has no destructor for a struct and the process is short-lived. Returning
//! `null` means the call failed; `tallow_llm_last_error()` then holds the
//! redacted reason (the same sentence the interpreter would return as `Err`).

use std::ffi::{c_char, CStr, CString};

/// Mirrors `%struct.Completion` in `src/codegen.rs` and the parser's field
/// order in `stdlib/llm.tl`:
/// `text, model, provider, prompt_hash, response_hash, tokens_in, tokens_out,
/// elapsed_ms`.
#[repr(C)]
pub struct CompletionRaw {
    pub text: *mut c_char,
    pub model: *mut c_char,
    pub provider: *mut c_char,
    pub prompt_hash: *mut c_char,
    pub response_hash: *mut c_char,
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub elapsed_ms: i64,
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> =
        const { std::cell::RefCell::new(None) };
}

fn set_error(message: String) {
    let cleaned = CString::new(message.replace('\0', "")).unwrap_or_default();
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(cleaned));
}

/// The redacted failure reason from the last failed call, or an empty string.
/// Never null, so callers can print it unconditionally.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_llm_last_error() -> *const c_char {
    thread_local! {
        static EMPTY: CString = CString::new("").unwrap();
    }
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(msg) => msg.as_ptr(),
        None => EMPTY.with(|e| e.as_ptr()),
    })
}

fn take_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn own(value: String) -> *mut c_char {
    CString::new(value.replace('\0', ""))
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `llm.complete(provider, model, prompt, max_tokens = 1024) -> Completion`
///
/// Returns null on failure with the reason in `tallow_llm_last_error()`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_llm_complete(
    provider: *const c_char,
    model: *const c_char,
    prompt: *const c_char,
    max_tokens: i64,
) -> *mut CompletionRaw {
    use crate::interp::Value;

    let provider = take_cstr(provider);
    let model = take_cstr(model);
    let prompt = take_cstr(prompt);
    let max_tokens = if max_tokens <= 0 { 1024 } else { max_tokens };

    let Some(result) = crate::stdlib::llm::dispatch(
        "complete",
        vec![
            Value::String(provider),
            Value::String(model),
            Value::String(prompt),
            Value::Int(max_tokens as i128),
        ],
    ) else {
        set_error("llm.complete is not routed by the stdlib".to_string());
        return std::ptr::null_mut();
    };

    let value = match result {
        Ok(v) => v,
        Err(e) => {
            set_error(e);
            return std::ptr::null_mut();
        }
    };

    let Value::Struct { name, fields } = value else {
        set_error(format!(
            "llm.complete returned {} where a Completion was expected",
            crate::interp::type_name(&value)
        ));
        return std::ptr::null_mut();
    };
    if name != "Completion" {
        set_error(format!("llm.complete returned a {name} struct"));
        return std::ptr::null_mut();
    }

    let text_of = |key: &str| -> String {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_string())
            .unwrap_or_default()
    };
    let int_of = |key: &str| -> i64 {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                Value::Int(i) => *i as i64,
                other => other.as_string().parse().unwrap_or(0),
            })
            .unwrap_or(0)
    };

    let record = Box::new(CompletionRaw {
        text: own(text_of("text")),
        model: own(text_of("model")),
        provider: own(text_of("provider")),
        prompt_hash: own(text_of("prompt_hash")),
        response_hash: own(text_of("response_hash")),
        tokens_in: int_of("tokens_in"),
        tokens_out: int_of("tokens_out"),
        elapsed_ms: int_of("elapsed_ms"),
    });
    Box::into_raw(record)
}

/// Print a failure the compiled program cannot recover from and abort.
///
/// The interpreter returns `Err(message)` here; compiled code has no Result to
/// branch on yet, so the same sentence goes to stderr and the process exits 1.
/// That is a loud, honest difference — never a zero-filled struct.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_llm_abort() -> ! {
    let msg = LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|m| m.to_string_lossy().into_owned())
            .unwrap_or_else(|| "llm.complete failed".to_string())
    });
    eprintln!("runtime error: {msg}");
    std::process::exit(1);
}

/// Mirrors `%struct.ModelInfo` (stdlib/llm.tl): `id`, `owned_by`.
#[repr(C)]
pub struct ModelInfoRaw {
    pub id: *mut c_char,
    pub owned_by: *mut c_char,
}

/// `llm.models(provider) -> []ModelInfo`
///
/// The array has the same shape `Transfer.chunk` returns — `[count][ptr…]` of
/// heap records — so `models[0].id` and `.len` work through the ordinary array
/// path instead of needing a second representation.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_llm_models(provider: *const c_char) -> *mut std::ffi::c_void {
    use crate::interp::Value;

    let provider = take_cstr(provider);
    let Some(result) = crate::stdlib::llm::dispatch("models", vec![Value::String(provider)])
    else {
        set_error("llm.models is not routed by the stdlib".to_string());
        return std::ptr::null_mut();
    };
    let value = match result {
        Ok(v) => v,
        Err(e) => {
            set_error(e);
            return std::ptr::null_mut();
        }
    };
    let Value::Array(items) = value else {
        set_error("llm.models did not return an array".to_string());
        return std::ptr::null_mut();
    };

    let mut slots: Vec<i64> = Vec::with_capacity(items.len());
    for item in items {
        let Value::Struct { name, fields } = item else {
            set_error("llm.models returned a non-struct entry".to_string());
            return std::ptr::null_mut();
        };
        if name != "ModelInfo" {
            set_error(format!("llm.models returned a {name} entry"));
            return std::ptr::null_mut();
        }
        let field = |key: &str| -> String {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_string())
                .unwrap_or_default()
        };
        let record = Box::new(ModelInfoRaw {
            id: own(field("id")),
            owned_by: own(field("owned_by")),
        });
        slots.push(Box::into_raw(record) as i64);
    }
    crate::runtime::browser::native_array(slots)
}

/// Mirrors `%struct.VerifyReport` (stdlib/llm.tl):
/// `provider`, `ok` (i1), `models`, `elapsed_ms`, `detail`.
#[repr(C)]
pub struct VerifyReportRaw {
    pub provider: *mut c_char,
    pub ok: i32,
    pub models: i64,
    pub elapsed_ms: i64,
    pub detail: *mut c_char,
}

/// `llm.verify(provider) -> VerifyReport`
///
/// Resolves credentials and lists models — the check an operator runs after
/// entering a key. Returns null on failure with the redacted reason in
/// `tallow_llm_last_error()`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_llm_verify(provider: *const c_char) -> *mut VerifyReportRaw {
    use crate::interp::Value;

    let provider = take_cstr(provider);
    let Some(result) = crate::stdlib::llm::dispatch("verify", vec![Value::String(provider)])
    else {
        set_error("llm.verify is not routed by the stdlib".to_string());
        return std::ptr::null_mut();
    };
    let value = match result {
        Ok(v) => v,
        Err(e) => {
            set_error(e);
            return std::ptr::null_mut();
        }
    };
    let Value::Struct { name, fields } = value else {
        set_error("llm.verify did not return a VerifyReport".to_string());
        return std::ptr::null_mut();
    };
    if name != "VerifyReport" {
        set_error(format!("llm.verify returned a {name} struct"));
        return std::ptr::null_mut();
    }
    let text = |key: &str| -> String {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_string())
            .unwrap_or_default()
    };
    let int = |key: &str| -> i64 {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                Value::Int(i) => *i as i64,
                other => other.as_string().parse().unwrap_or(0),
            })
            .unwrap_or(0)
    };
    let ok = fields
        .iter()
        .find(|(k, _)| k == "ok")
        .map(|(_, v)| matches!(v, Value::Bool(true)))
        .unwrap_or(false);

    Box::into_raw(Box::new(VerifyReportRaw {
        provider: own(text("provider")),
        ok: ok as i32,
        models: int("models"),
        elapsed_ms: int("elapsed_ms"),
        detail: own(text("detail")),
    }))
}

/// Mirrors `%struct.ProviderInfo` (stdlib/llm.tl): eight string fields.
#[repr(C)]
pub struct ProviderInfoRaw {
    pub id: *mut c_char,
    pub label: *mut c_char,
    pub protocol: *mut c_char,
    pub base_url: *mut c_char,
    pub key_env: *mut c_char,
    pub status: *mut c_char,
    pub docs: *mut c_char,
    pub unavailable_reason: *mut c_char,
}

/// `llm.providers() -> []ProviderInfo`
///
/// Same native array shape as `llm.models`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_llm_providers() -> *mut std::ffi::c_void {
    use crate::interp::Value;

    let Some(result) = crate::stdlib::llm::dispatch("providers", Vec::new()) else {
        set_error("llm.providers is not routed by the stdlib".to_string());
        return std::ptr::null_mut();
    };
    let value = match result {
        Ok(v) => v,
        Err(e) => {
            set_error(e);
            return std::ptr::null_mut();
        }
    };
    let Value::Array(items) = value else {
        set_error("llm.providers did not return an array".to_string());
        return std::ptr::null_mut();
    };
    let mut slots: Vec<i64> = Vec::with_capacity(items.len());
    for item in items {
        let Value::Struct { name, fields } = item else {
            set_error("llm.providers returned a non-struct entry".to_string());
            return std::ptr::null_mut();
        };
        if name != "ProviderInfo" {
            set_error(format!("llm.providers returned a {name} entry"));
            return std::ptr::null_mut();
        }
        let text = |key: &str| -> String {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_string())
                .unwrap_or_default()
        };
        let record = Box::new(ProviderInfoRaw {
            id: own(text("id")),
            label: own(text("label")),
            protocol: own(text("protocol")),
            base_url: own(text("base_url")),
            key_env: own(text("key_env")),
            status: own(text("status")),
            docs: own(text("docs")),
            unavailable_reason: own(text("unavailable_reason")),
        });
        slots.push(Box::into_raw(record) as i64);
    }
    crate::runtime::browser::native_array(slots)
}
