//! C ABI for the chunked resumable transfer, so `tallow build` can lower
//! `crypto.age_encrypt_dir` / `crypto.age_decrypt_dir`.
//!
//! Record layouts mirror the codegen structs exactly:
//! `AgeStreamEncryptedRaw { parts: i64, resumed_from: i64, digest: *mut c_char }`
//! and `AgeStreamDecryptedRaw { parts: i64, total_len: i64 }`.

use std::ffi::{c_char, CString};

#[repr(C)]
pub struct AgeStreamEncryptedRaw {
    pub parts: i64,
    pub resumed_from: i64,
    pub digest: *mut c_char,
}

#[repr(C)]
pub struct AgeStreamDecryptedRaw {
    pub parts: i64,
    pub total_len: i64,
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
pub extern "C" fn tallow_age_encrypt_dir(
    recipient: *const c_char,
    src: *const c_char,
    out_dir: *const c_char,
    chunk_bytes: i64,
) -> *mut AgeStreamEncryptedRaw {
    let (recipient, src, out_dir) = unsafe {
        match (borrow(recipient), borrow(src), borrow(out_dir)) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return fail("crypto.age_encrypt_dir: null argument".into()),
        }
    };
    let chunk = if chunk_bytes > 0 {
        Some(chunk_bytes as usize)
    } else {
        None
    };
    match crate::age_stream::encrypt_file(recipient, src, out_dir, chunk) {
        Ok((parts, resumed_from, digest)) => {
            let rec = AgeStreamEncryptedRaw {
                parts: parts as i64,
                resumed_from: resumed_from as i64,
                digest: cstring(digest),
            };
            if rec.digest.is_null() {
                return std::ptr::null_mut();
            }
            Box::into_raw(Box::new(rec))
        }
        Err(e) => fail(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_age_decrypt_dir(
    identity: *const c_char,
    in_dir: *const c_char,
    dst: *const c_char,
) -> *mut AgeStreamDecryptedRaw {
    let (identity, in_dir, dst) = unsafe {
        match (borrow(identity), borrow(in_dir), borrow(dst)) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return fail("crypto.age_decrypt_dir: null argument".into()),
        }
    };
    match crate::age_stream::decrypt_file(identity, in_dir, dst) {
        Ok((parts, total)) => Box::into_raw(Box::new(AgeStreamDecryptedRaw {
            parts: parts as i64,
            total_len: total as i64,
        })),
        Err(e) => fail(e),
    }
}
