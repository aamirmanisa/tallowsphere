//! C ABI for OPAQUE (RFC 9807), matching the interpreter surface in
//! `src/stdlib/crypto.rs`. Both planes call `crate::opaque`.
//!
//! Multi-value results come back as heap records with a fixed field order; the
//! codegen layouts in `src/codegen.rs` must match these structs exactly. A null
//! return means "error, see tallow_last_error"; the emitted IR calls
//! `tallow_check_string` on the record pointer, which turns that null into a
//! hard runtime error before any field is dereferenced.

use std::ffi::{c_char, CString};

use crate::opaque;

/// A single-field record. `crypto.opaque_register_respond` returns a named
/// struct on the language surface, so the ABI must return a record — returning
/// the bare string made codegen dereference the string as a struct and crash.
#[repr(C)]
pub struct OneRaw {
    pub a: *mut c_char,
}

#[repr(C)]
pub struct PairRaw {
    pub a: *mut c_char,
    pub b: *mut c_char,
}

#[repr(C)]
pub struct TripleRaw {
    pub a: *mut c_char,
    pub b: *mut c_char,
    pub c: *mut c_char,
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

fn fail(e: String) -> *mut c_char {
    crate::runtime::set_last_error(e);
    std::ptr::null_mut()
}

fn fail_pair(e: String) -> *mut PairRaw {
    crate::runtime::set_last_error(e);
    std::ptr::null_mut()
}

fn fail_triple(e: String) -> *mut TripleRaw {
    crate::runtime::set_last_error(e);
    std::ptr::null_mut()
}

fn pair(a: String, b: String) -> *mut PairRaw {
    let rec = PairRaw {
        a: cstring(a),
        b: cstring(b),
    };
    if rec.a.is_null() || rec.b.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(rec))
}

fn triple(a: String, b: String, c: String) -> *mut TripleRaw {
    let rec = TripleRaw {
        a: cstring(a),
        b: cstring(b),
        c: cstring(c),
    };
    if rec.a.is_null() || rec.b.is_null() || rec.c.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(rec))
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_suite() -> *mut c_char {
    cstring(opaque::suite_name().to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_setup() -> *mut c_char {
    match opaque::setup_new() {
        Ok(s) => cstring(s),
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_register_start(password: *const c_char) -> *mut PairRaw {
    let pw = unsafe { borrow(password) };
    let Some(pw) = pw else {
        return fail_pair("opaque_register_start: null password".into());
    };
    match opaque::registration_start(pw) {
        Ok((request, state)) => pair(request, state),
        Err(e) => fail_pair(e),
    }
}

/// Returns the registration response string; the second tuple element from the
/// protocol layer is empty and carries no meaning.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_register_respond(
    setup: *const c_char,
    request: *const c_char,
    credential_id: *const c_char,
) -> *mut OneRaw {
    let (setup, request, cred) = unsafe {
        match (borrow(setup), borrow(request), borrow(credential_id)) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => {
                crate::runtime::set_last_error(
                    "opaque_register_respond: null argument".into(),
                );
                return std::ptr::null_mut();
            }
        }
    };
    match opaque::registration_respond(setup, request, cred) {
        Ok((response, _)) => {
            let rec = OneRaw {
                a: cstring(response),
            };
            if rec.a.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => {
            crate::runtime::set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_register_finish(
    state: *const c_char,
    password: *const c_char,
    response: *const c_char,
) -> *mut PairRaw {
    let (state, pw, resp) = unsafe {
        match (borrow(state), borrow(password), borrow(response)) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return fail_pair("opaque_register_finish: null argument".into()),
        }
    };
    match opaque::registration_finish(state, pw, resp) {
        Ok((upload, export_key)) => pair(upload, export_key),
        Err(e) => fail_pair(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_register_store(upload: *const c_char) -> *mut c_char {
    let Some(upload) = (unsafe { borrow(upload) }) else {
        return fail("opaque_register_store: null upload".into());
    };
    match opaque::registration_server_finish(upload) {
        Ok(s) => cstring(s),
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_login_start(password: *const c_char) -> *mut PairRaw {
    let Some(pw) = (unsafe { borrow(password) }) else {
        return fail_pair("opaque_login_start: null password".into());
    };
    match opaque::login_start(pw) {
        Ok((request, state)) => pair(request, state),
        Err(e) => fail_pair(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_login_respond(
    setup: *const c_char,
    record: *const c_char,
    request: *const c_char,
    credential_id: *const c_char,
) -> *mut PairRaw {
    let (setup, record, request, cred) = unsafe {
        match (
            borrow(setup),
            borrow(record),
            borrow(request),
            borrow(credential_id),
        ) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => return fail_pair("opaque_login_respond: null argument".into()),
        }
    };
    match opaque::login_respond(setup, record, request, cred) {
        Ok((response, state)) => pair(response, state),
        Err(e) => fail_pair(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_login_finish(
    state: *const c_char,
    password: *const c_char,
    response: *const c_char,
) -> *mut TripleRaw {
    let (state, pw, resp) = unsafe {
        match (borrow(state), borrow(password), borrow(response)) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return fail_triple("opaque_login_finish: null argument".into()),
        }
    };
    match opaque::login_finish(state, pw, resp) {
        Ok((fin, session, export)) => triple(fin, session, export),
        Err(e) => fail_triple(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_opaque_login_server_finish(
    state: *const c_char,
    finalization: *const c_char,
) -> *mut c_char {
    let (state, fin) = unsafe {
        match (borrow(state), borrow(finalization)) {
            (Some(a), Some(b)) => (a, b),
            _ => return fail("opaque_login_server_finish: null argument".into()),
        }
    };
    match opaque::login_server_finish(state, fin) {
        Ok(s) => cstring(s),
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn s(p: *mut c_char) -> String {
        assert!(!p.is_null(), "null C string");
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }

    #[test]
    fn ffi_drives_a_full_registration_and_login() {
        let setup = unsafe { s(tallow_opaque_setup()) };
        let pw = CString::new("pw").unwrap();
        let rec = unsafe { tallow_opaque_register_start(pw.as_ptr()) };
        assert!(!rec.is_null());
        let request = unsafe { s((*rec).a) };
        let state = unsafe { s((*rec).b) };

        let cred = CString::new("alice").unwrap();
        let setup_c = CString::new(setup.clone()).unwrap();
        let req_c = CString::new(request).unwrap();
        let response = unsafe {
            tallow_opaque_register_respond(setup_c.as_ptr(), req_c.as_ptr(), cred.as_ptr())
        };
        let response = unsafe { s(response) };

        let state_c = CString::new(state).unwrap();
        let resp_c = CString::new(response).unwrap();
        let up = unsafe {
            tallow_opaque_register_finish(state_c.as_ptr(), pw.as_ptr(), resp_c.as_ptr())
        };
        assert!(!up.is_null(), "register_finish returned null");
        let upload = unsafe { s((*up).a) };
        let upload_c = CString::new(upload).unwrap();
        let record = unsafe { s(tallow_opaque_register_store(upload_c.as_ptr())) };
        assert!(record.len() > 100);
    }
}
