//! Tallow runtime shim library.
//!
//! Provides `extern "C"` wrappers around browser and fetch operations
//! for use by compiled Tallow binaries. The codegen emits LLVM IR `call`
//! instructions targeting these functions, and clang links against the
//! static library produced from this module.
//!
//! All async operations are bridged to synchronous via a global tokio
//! runtime initialized on first use (OnceLock singleton).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

pub mod browser;
pub mod crypto_ffi;
pub mod db_ffi;
pub mod url_ffi;
pub mod fingerprint_ffi;
pub mod page_cache_ffi;
pub mod crawler_ffi;
pub mod compress_ffi;
pub mod display_ffi;
pub mod dns_guard;
pub mod egress_http;
pub mod env_ffi;
pub mod enterprise_ffi;
pub mod fetch;
pub mod fs_ffi;
pub mod string_ffi;
pub mod gzip_ffi;
pub mod hardening;
pub mod html_ffi;
pub mod io_uring_runtime;
pub mod ippool_ffi;
pub mod kernel_tune;
pub mod net_ffi;
pub mod diag_ffi;
pub mod process_ffi;
pub mod regex_ffi;
pub mod sync_ffi;
pub mod structured_data_ffi;
pub mod time_ffi;
pub mod transfer_ffi;

// ── Global Tokio Runtime ────────────────────────────────────────────────────

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Get or create the global tokio runtime (current-thread, all features enabled).
/// This is shared across all FFI calls to avoid per-call overhead.
pub(crate) fn get_runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

// ── Thread-local Error Reporting ────────────────────────────────────────────

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

/// Store an error message for retrieval via tallow_last_error().
pub(crate) fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).ok();
    });
}

// ── C String Helpers ────────────────────────────────────────────────────────

/// Convert a C string pointer to &str. Returns None if null or invalid UTF-8.
///
/// # Safety
/// The caller must ensure `ptr` points to a valid null-terminated C string
/// (or is null, in which case None is returned).
pub(crate) unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok() }
}

/// Allocate a C string on the heap. Caller must free with tallow_free_string.
pub(crate) fn string_to_cstr(s: &str) -> *mut c_char {
    CString::new(s)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

// ── FFI Utility Functions ───────────────────────────────────────────────────

/// Retrieve the last error message. Returns null if no error.
/// The returned pointer is valid until the next error is set.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_last_error() -> *const c_char {
    LAST_ERROR.with(|e| match &*e.borrow() {
        Some(cstr) => cstr.as_ptr(),
        None => std::ptr::null(),
    })
}

/// Free a string previously returned by a runtime function.
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Print an optional box the way the interpreter renders an optional: `nil`
/// when absent, otherwise the payload formatted by its boxed kind. Uses the
/// same libc formats as the rest of `print`, so `%g`/`%lld` agree with the
/// scalar paths byte for byte.
#[repr(C)]
pub struct OptionalBox {
    pub kind: i64,
    pub payload: i64,
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_print_optional(boxed: *const OptionalBox) {
    unsafe {
        if boxed.is_null() {
            libc::printf(b"nil\0".as_ptr() as *const libc::c_char);
            return;
        }
        let b = &*boxed;
        match b.kind {
            // LLType::type_tag: 0 int, 1 string, 2 float, 3 bool
            3 => {
                let text: &[u8] = if b.payload != 0 {
                    b"true\0"
                } else {
                    b"false\0"
                };
                libc::printf(text.as_ptr() as *const libc::c_char);
            }
            2 => {
                let f = f64::from_bits(b.payload as u64);
                libc::printf(b"%g\0".as_ptr() as *const libc::c_char, f);
            }
            1 => {
                if b.payload == 0 {
                    libc::printf(b"nil\0".as_ptr() as *const libc::c_char);
                } else {
                    libc::printf(
                        b"%s\0".as_ptr() as *const libc::c_char,
                        b.payload as *const libc::c_char,
                    );
                }
            }
            _ => {
                libc::printf(b"%lld\0".as_ptr() as *const libc::c_char, b.payload);
            }
        }
    }
}
