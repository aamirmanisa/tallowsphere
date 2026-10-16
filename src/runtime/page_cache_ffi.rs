//! Runtime FFI: the `PageCache` struct-static constructor.
//!
//! # Shape
//!
//! `PageCache` is `{max_age_seconds: i64, max_size_mb: i64, entries: i32,
//! hits: i32, misses: i32, keyed_by: String}` (`stdlib/browser.tl:402`) — five
//! integers and one string. The integers come back through a single **out
//! buffer** in declaration order and the string is the return value; codegen
//! allocates `%struct.PageCache` itself.
//!
//! Both halves of that split exist for the same reason: returning a struct
//! pointer from here would couple the LLVM struct layout to a hand-written Rust
//! `#[repr(C)]`, which then breaks *silently* on any field reorder, width change
//! or padding difference. One buffer plus one return keeps layout owned by
//! codegen, and is the same trade `tallow_fingerprint_from_text` and
//! `tallow_gzip_decompress(ptr, i64, ptr)` make.
//!
//! # Contract
//!
//! A non-null return means all [`PAGE_CACHE_INT_FIELDS`] slots of `out_fields`
//! were written; a null return means they are untouched and `tallow_last_error`
//! is set, so the emitted code must branch on null before reading them.
//!
//! The values come from `stdlib::browser::page_cache_fields`, the same function
//! the interpreter's `PageCache.create` arm calls, so native and interpreted
//! results cannot disagree.

use std::os::raw::c_char;

use super::{set_last_error, string_to_cstr};
use crate::stdlib::browser::page_cache_fields;

/// Integer fields written into the `out_fields` buffer, in declaration order:
/// `max_age_seconds`, `max_size_mb`, `entries`, `hits`, `misses`.
pub const PAGE_CACHE_INT_FIELDS: usize = 5;

/// `PageCache.create(...) -> PageCache`.
///
/// Both arguments are optional: `has_age` / `has_size` are 0 when the argument
/// was omitted, and the declared default then applies (3600 s / 1024 MB),
/// matching the interpreter arm exactly. `max_age_seconds` / `max_size_mb` are
/// only read when their flag is set, so an omitted argument may pass anything.
///
/// The five integer fields are written into `out_fields` in declaration order and
/// `keyed_by` is returned.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_page_cache_create(
    out_fields: *mut i64,
    has_age: i32,
    max_age_seconds: i64,
    has_size: i32,
    max_size_mb: i64,
) -> *mut c_char {
    // Codegen always passes an alloca; a null here is a codegen bug, so refuse
    // rather than write through a wild pointer.
    if out_fields.is_null() {
        set_last_error("PageCache.create: missing integer-field out-buffer".to_string());
        return std::ptr::null_mut();
    }
    let age = if has_age != 0 {
        Some(max_age_seconds)
    } else {
        None
    };
    let size = if has_size != 0 {
        Some(max_size_mb)
    } else {
        None
    };
    let fields = page_cache_fields(age, size);
    let values = [
        fields.max_age_seconds,
        fields.max_size_mb,
        fields.entries,
        fields.hits,
        fields.misses,
    ];
    // SAFETY: the caller allocated at least PAGE_CACHE_INT_FIELDS slots, and the
    // pointer was checked non-null above. `values.len()` is exactly that constant.
    unsafe {
        for (i, value) in values.iter().enumerate() {
            *out_fields.add(i) = *value;
        }
    }
    string_to_cstr(&fields.keyed_by)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    /// Call the FFI the way codegen does and return `(int fields, keyed_by)`.
    fn page_cache(age: Option<i64>, size: Option<i64>) -> (Vec<i64>, String) {
        let mut slots = [0i64; PAGE_CACHE_INT_FIELDS];
        let ptr = tallow_page_cache_create(
            slots.as_mut_ptr(),
            age.is_some() as i32,
            age.unwrap_or(0),
            size.is_some() as i32,
            size.unwrap_or(0),
        );
        assert!(!ptr.is_null(), "keyed_by must be returned on the happy path");
        let keyed_by = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .unwrap()
            .to_string();
        (slots.to_vec(), keyed_by)
    }

    /// The struct-static constructor's defaults, pinned to the interpreter's
    /// observed values (probe `p36`): `PageCache.create()` → 3600 / 1024.
    #[test]
    fn missing_arguments_take_the_declared_defaults() {
        let (fields, keyed_by) = page_cache(None, None);
        assert_eq!(fields, vec![3600, 1024, 0, 0, 0]);
        assert_eq!(keyed_by, "blake3");
    }

    /// Supplied arguments pass straight through and the counters start at zero —
    /// the interpreter's values for `PageCache.create(60, 10)` in `p36`.
    #[test]
    fn supplied_arguments_pass_through_with_zeroed_counters() {
        let (fields, keyed_by) = page_cache(Some(60), Some(10));
        assert_eq!(fields, vec![60, 10, 0, 0, 0]);
        assert_eq!(keyed_by, "blake3");
    }

    /// The arguments default *independently*: one supplied and one omitted must
    /// give 60 / 1024, not two defaults and not a rejection. This is the case a
    /// single combined flag would get wrong.
    #[test]
    fn arguments_default_independently() {
        assert_eq!(page_cache(Some(60), None).0, vec![60, 1024, 0, 0, 0]);
        assert_eq!(page_cache(None, Some(10)).0, vec![3600, 10, 0, 0, 0]);
    }

    /// A null out-buffer is a codegen bug: refuse, never write through it.
    #[test]
    fn null_out_buffer_fails_closed() {
        let ptr = tallow_page_cache_create(std::ptr::null_mut(), 0, 0, 0, 0);
        assert!(ptr.is_null());
    }
}
