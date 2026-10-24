//! FFI bridge for `Mesh.plan` in compiled Tallow programs.
//!
//! `Mesh.plan(tasks: []MeshTask, seed) -> MeshPlan` takes an array of structs
//! the *program* declares, so the bridge cannot assume a field order. Codegen
//! reads the program's own declaration, verifies the five field types, and
//! passes the byte offset of each field; this module reads the records through
//! those offsets. A declaration that does not match the contract is refused at
//! compile time instead of being read at the wrong offsets.
//!
//! Record shape for one task (all fields 8 bytes in this backend):
//!
//! ```text
//! +0  id              ptr -> c string
//! ... func            ptr
//! ... deps            ptr -> native array [count][ptr…] of c strings
//! ... class           ptr
//! ... idempotency_key ptr (null = nil)
//! ```
//!
//! The array of tasks is the backend's usual native array: `[count][ptr…]`,
//! each slot pointing at one record.

use std::ffi::{c_char, c_void, CStr};

/// Mirrors `%struct.MeshPlan`: `waves`, `tasks`, `seed`, `wave_sizes`.
#[repr(C)]
pub struct MeshPlanRaw {
    pub waves: i64,
    pub tasks: i64,
    pub seed: i64,
    /// Native array `[count][i64…]` — the same shape `[]i64` has everywhere.
    pub wave_sizes: *mut c_void,
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<std::ffi::CString>> =
        const { std::cell::RefCell::new(None) };
}

fn set_error(message: String) {
    let cleaned = std::ffi::CString::new(message.replace('\0', "")).unwrap_or_default();
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(cleaned));
}

/// The redacted failure reason from the last failed call (empty when none).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_mesh_last_error() -> *const c_char {
    thread_local! {
        static EMPTY: std::ffi::CString = std::ffi::CString::new("").unwrap();
    }
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(msg) => msg.as_ptr(),
        None => EMPTY.with(|e| e.as_ptr()),
    })
}

/// Print the stored failure and exit 1 — the compiled counterpart of the
/// interpreter returning `Err(sentence)`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_mesh_abort() -> ! {
    let msg = LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|m| m.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Mesh.plan failed".to_string())
    });
    eprintln!("runtime error: {msg}");
    std::process::exit(1);
}

unsafe fn read_str(base: *const u8, offset: i64) -> String {
    if offset < 0 || base.is_null() {
        return String::new();
    }
    let ptr = unsafe { *(base.offset(offset as isize) as *const *const c_char) };
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
}

/// Read a native `[]String` (the deps field): `[count][ptr…]`.
unsafe fn read_string_array(base: *const u8, offset: i64) -> Vec<String> {
    if offset < 0 || base.is_null() {
        return Vec::new();
    }
    let arr = unsafe { *(base.offset(offset as isize) as *const *const i64) };
    if arr.is_null() {
        return Vec::new();
    }
    let len = unsafe { *arr };
    if len <= 0 {
        return Vec::new();
    }
    // Guard against a mis-declared field: a sane deps list is small, and a
    // garbage count would otherwise walk far past the buffer.
    if len > 4096 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(len as usize);
    for i in 0..len as isize {
        let slot = unsafe { *arr.offset(1 + i) };
        if slot == 0 {
            out.push(String::new());
            continue;
        }
        let s = unsafe { CStr::from_ptr(slot as *const c_char) };
        out.push(s.to_string_lossy().into_owned());
    }
    out
}

/// `Mesh.plan(tasks, seed) -> MeshPlan`
///
/// `off_*` are byte offsets of the five `MeshTask` fields in the program's own
/// declaration; `-1` means the field is absent and reads as empty.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_mesh_plan(
    tasks: *const c_void,
    seed: i64,
    off_id: i64,
    off_func: i64,
    off_deps: i64,
    off_class: i64,
    off_key: i64,
) -> *mut MeshPlanRaw {
    use crate::interp::Value;

    if tasks.is_null() {
        set_error("Mesh.plan: null task array".to_string());
        return std::ptr::null_mut();
    }
    let base = tasks as *const i64;
    let count = unsafe { *base };
    if count < 0 || count > 100_000 {
        set_error(format!("Mesh.plan: implausible task count {count}"));
        return std::ptr::null_mut();
    }

    let mut values: Vec<Value> = Vec::with_capacity(count as usize);
    for i in 0..count as isize {
        let slot = unsafe { *base.offset(1 + i) };
        if slot == 0 {
            set_error(format!("Mesh.plan: task {i} is a null record"));
            return std::ptr::null_mut();
        }
        let rec = slot as *const u8;
        let key = unsafe { read_str(rec, off_key) };
        let fields = vec![
            ("id".to_string(), Value::String(unsafe { read_str(rec, off_id) })),
            (
                "func".to_string(),
                Value::String(unsafe { read_str(rec, off_func) }),
            ),
            (
                "deps".to_string(),
                Value::Array(
                    unsafe { read_string_array(rec, off_deps) }
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            (
                "class".to_string(),
                Value::String(unsafe { read_str(rec, off_class) }),
            ),
            (
                "idempotency_key".to_string(),
                if key.is_empty() {
                    Value::Nil
                } else {
                    Value::String(key)
                },
            ),
        ];
        values.push(Value::Struct {
            name: "MeshTask".to_string(),
            fields,
        });
    }

    let Some(result) = crate::stdlib::mesh_exec::dispatch(
        "plan",
        vec![Value::Array(values), Value::Int(seed as i128)],
    ) else {
        set_error("Mesh.plan is not routed by the stdlib".to_string());
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
        set_error("Mesh.plan did not return a MeshPlan".to_string());
        return std::ptr::null_mut();
    };
    if name != "MeshPlan" {
        set_error(format!("Mesh.plan returned a {name} struct"));
        return std::ptr::null_mut();
    }
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
    let wave_sizes: Vec<i64> = fields
        .iter()
        .find(|(k, _)| k == "wave_sizes")
        .map(|(_, v)| match v {
            Value::Array(items) => items
                .iter()
                .map(|i| match i {
                    Value::Int(n) => *n as i64,
                    other => other.as_string().parse().unwrap_or(0),
                })
                .collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default();

    Box::into_raw(Box::new(MeshPlanRaw {
        waves: int("waves"),
        tasks: int("tasks"),
        seed: int("seed"),
        wave_sizes: crate::runtime::browser::native_array(wave_sizes),
    }))
}
