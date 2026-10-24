//! C ABI for the age surface, so `tallow build` can lower `crypto.age_*`.
//!
//! Both planes call `crate::age`; this file only marshals strings. The keypair
//! record is heap-allocated and owned by the caller's runtime, matching the
//! `llm` FFI convention (a null return means "aborted", and the codegen path
//! calls `tallow_llm_abort`).

use std::ffi::{c_char, CString};

use crate::age;

#[repr(C)]
pub struct AgeKeypairRaw {
    pub recipient: *mut c_char,
    pub identity: *mut c_char,
}

fn cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe fn borrow<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(p).to_str().ok()
}

/// Returns a heap `AgeKeypairRaw`; both strings are heap C strings.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_age_keygen() -> *mut AgeKeypairRaw {
    let (recipient, identity) = age::keygen();
    let rec = AgeKeypairRaw {
        recipient: cstring(recipient),
        identity: cstring(identity),
    };
    if rec.recipient.is_null() || rec.identity.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(rec))
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_age_encrypt(
    recipient: *const c_char,
    plaintext_hex: *const c_char,
) -> *mut c_char {
    let (recipient, pt) = unsafe {
        match (borrow(recipient), borrow(plaintext_hex)) {
            (Some(r), Some(p)) => (r, p),
            _ => return std::ptr::null_mut(),
        }
    };
    match age::encrypt(recipient, pt) {
        Ok(out) => cstring(out),
        Err(e) => {
            crate::runtime::set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_age_decrypt(
    identity: *const c_char,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    let (identity, ct) = unsafe {
        match (borrow(identity), borrow(ciphertext_hex)) {
            (Some(i), Some(c)) => (i, c),
            _ => return std::ptr::null_mut(),
        }
    };
    match age::decrypt(identity, ct) {
        Ok(out) => cstring(out),
        Err(e) => {
            crate::runtime::set_last_error(e);
            std::ptr::null_mut()
        }
    }
}
