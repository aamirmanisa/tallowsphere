//! C ABI for the MLS surface, so `tallow build --features mls` can lower
//! `crypto.mls_*`.
//!
//! Only compiled with the `mls` feature; the codegen arms are gated the same way
//! and refuse by name without it, so a default build never links a symbol that
//! does not exist.
//!
//! Group state stays in `crate::mls`'s process-global registry keyed by handle —
//! a native binary and the interpreter both call that same registry.

use std::ffi::{c_char, CString};

#[repr(C)]
pub struct StrIntRaw {
    pub s: *mut c_char,
    pub n: i64,
}

#[repr(C)]
pub struct StrStrRaw {
    pub a: *mut c_char,
    pub b: *mut c_char,
}

#[repr(C)]
pub struct StrStrIntRaw {
    pub a: *mut c_char,
    pub b: *mut c_char,
    pub n: i64,
}

#[repr(C)]
pub struct IntIntRaw {
    pub a: i64,
    pub b: i64,
}

fn cstring(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

unsafe fn borrow<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(p).to_str().ok()
}

fn fail<T>(msg: String) -> *mut T {
    crate::runtime::set_last_error(msg);
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_key_package(identity: *const c_char) -> *mut StrStrRaw {
    let Some(id) = (unsafe { borrow(identity) }) else {
        return fail("crypto.mls_key_package: null identity".into());
    };
    match crate::mls::key_package_new(id) {
        Ok((handle, kp)) => {
            let rec = StrStrRaw {
                a: cstring(handle),
                b: cstring(kp),
            };
            if rec.a.is_null() || rec.b.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_create_group(identity: *const c_char) -> *mut StrStrRaw {
    let Some(id) = (unsafe { borrow(identity) }) else {
        return fail("crypto.mls_create_group: null identity".into());
    };
    match crate::mls::create_group(id) {
        Ok((handle, kp)) => {
            let rec = StrStrRaw {
                a: cstring(handle),
                b: cstring(kp),
            };
            if rec.a.is_null() || rec.b.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_add_member(
    handle: *const c_char,
    key_package: *const c_char,
) -> *mut StrIntRaw {
    let (Some(h), Some(kp)) = (unsafe { borrow(handle) }, unsafe { borrow(key_package) }) else {
        return fail("crypto.mls_add_member: null argument".into());
    };
    match crate::mls::add_member(h, kp) {
        Ok((welcome, epoch)) => {
            let rec = StrIntRaw {
                s: cstring(welcome),
                n: epoch as i64,
            };
            if rec.s.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_join(
    pending: *const c_char,
    welcome: *const c_char,
) -> *mut StrIntRaw {
    let (Some(p), Some(w)) = (unsafe { borrow(pending) }, unsafe { borrow(welcome) }) else {
        return fail("crypto.mls_join: null argument".into());
    };
    match crate::mls::join_from_welcome(p, w) {
        Ok((handle, epoch)) => {
            let rec = StrIntRaw {
                s: cstring(handle),
                n: epoch as i64,
            };
            if rec.s.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_encrypt(
    handle: *const c_char,
    plaintext_hex: *const c_char,
) -> *mut StrIntRaw {
    let (Some(h), Some(pt)) = (unsafe { borrow(handle) }, unsafe { borrow(plaintext_hex) }) else {
        return fail("crypto.mls_encrypt: null argument".into());
    };
    match crate::mls::encrypt(h, pt) {
        Ok((message, epoch)) => {
            let rec = StrIntRaw {
                s: cstring(message),
                n: epoch as i64,
            };
            if rec.s.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_process(
    handle: *const c_char,
    message: *const c_char,
) -> *mut StrStrIntRaw {
    let (Some(h), Some(m)) = (unsafe { borrow(handle) }, unsafe { borrow(message) }) else {
        return fail("crypto.mls_process: null argument".into());
    };
    match crate::mls::process(h, m) {
        Ok((kind, plaintext, epoch)) => {
            let rec = StrStrIntRaw {
                a: cstring(kind),
                b: cstring(plaintext),
                n: epoch as i64,
            };
            if rec.a.is_null() || rec.b.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mls_info(handle: *const c_char) -> *mut IntIntRaw {
    let Some(h) = (unsafe { borrow(handle) }) else {
        return fail("crypto.mls_info: null handle".into());
    };
    match crate::mls::group_info(h) {
        Ok((members, epoch)) => Box::into_raw(Box::new(IntIntRaw {
            a: members as i64,
            b: epoch as i64,
        })),
        Err(e) => fail(e),
    }
}
