//! Runtime FFI: `tallow.provenance.record`.
//!
//! `record(source_url, egress_label, egress_tier, status_code, body_hash) ->
//! CollectionRecord` fills `fetched_at` from the clock and the base confidence
//! from `DEFAULT_BASE_CONFIDENCE`, then hands the eight declared fields back to
//! codegen, which builds `%struct.CollectionRecord` from the program's own
//! declaration (`codegen.rs::emit_stdlib_provenance`, `build_plain_struct`).
//!
//! # One implementation
//!
//! The constructor is the interpreter's: `stdlib::provenance::dispatch("record",
//! …)`. Nothing here re-derives the timestamp, the default confidence or the
//! `clamp(0, 1)` rule — those live in `CollectionRecord::record`, and a second
//! copy in the runtime is exactly how the two engines would drift. This module
//! only flattens the returned `Value::Struct` into slots.
//!
//! A null argument or an unexpected shape sets `tallow_last_error`; the emitted
//! code turns a negative return into a message-bearing `exit(1)`.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::interp::Value;

/// Number of `i64` slots [`tallow_provenance_record`] writes.
///
/// `codegen.rs::emit_stdlib_provenance` allocates exactly this many slots; the
/// two constants are one contract (see the slot table on the function).
pub const PROVENANCE_RECORD_SLOTS: usize = 8;

/// `provenance.record(url, label, tier, status_code, hash) -> CollectionRecord`.
///
/// Slot table (`out[i]`, all `i64`; a pointer is bitcast through `i64`, and a
/// float is its IEEE-754 bit pattern):
///
/// | i | field         | value                                    |
/// |---|---------------|------------------------------------------|
/// | 0 | `source_url`  | `*mut c_char`                            |
/// | 1 | `fetched_at`  | unix epoch seconds                       |
/// | 2 | `egress_label`| `*mut c_char`                            |
/// | 3 | `egress_tier` | `*mut c_char`                            |
/// | 4 | `status_code` | HTTP status (0 = no response)            |
/// | 5 | `body_hash`   | `*mut c_char`                            |
/// | 6 | `confidence`  | `f64` bits (`bitcast` in the emitted IR) |
/// | 7 | `grade`       | `*mut c_char` (empty before `grade()`)   |
///
/// Returns 0 on success, -1 with `tallow_last_error` set otherwise. The string
/// slots are heap copies owned by the returned record — the arena has no drop
/// hook, so they are never freed (a leak, not a dangling pointer).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_provenance_record(
    source_url: *const c_char,
    egress_label: *const c_char,
    egress_tier: *const c_char,
    status_code: i64,
    body_hash: *const c_char,
    out: *mut i64,
) -> i32 {
    if out.is_null() {
        set_last_error("provenance.record: null output buffer".to_string());
        return -1;
    }
    let (Some(url), Some(label), Some(tier), Some(hash)) = (
        unsafe { cstr_to_str(source_url) },
        unsafe { cstr_to_str(egress_label) },
        unsafe { cstr_to_str(egress_tier) },
        unsafe { cstr_to_str(body_hash) },
    ) else {
        set_last_error("provenance.record: null string argument".to_string());
        return -1;
    };
    let args = vec![
        Value::String(url.to_string()),
        Value::String(label.to_string()),
        Value::String(tier.to_string()),
        Value::Int(status_code as i128),
        Value::String(hash.to_string()),
    ];
    let value = match crate::stdlib::provenance::dispatch("record", args) {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            set_last_error(format!("provenance.record: {e}"));
            return -1;
        }
        None => {
            set_last_error(
                "provenance.record: no `record` arm in the provenance module".to_string(),
            );
            return -1;
        }
    };
    let Value::Struct { fields, .. } = &value else {
        set_last_error(format!(
            "provenance.record: constructor returned {}, expected the CollectionRecord struct",
            crate::interp::type_name(&value)
        ));
        return -1;
    };
    let get = |key: &str| fields.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    let str_slot = |key: &str| -> i64 {
        match get(key) {
            Some(Value::String(s)) => string_to_cstr(s) as i64,
            _ => 0,
        }
    };
    let int_slot = |key: &str| -> i64 {
        match get(key) {
            Some(Value::Int(n)) => i64::try_from(*n).unwrap_or(0),
            _ => 0,
        }
    };
    let confidence = match get("confidence") {
        Some(Value::Float(f)) => f.to_bits() as i64,
        // A record's confidence is always a Float out of `CollectionRecord`;
        // anything else means the constructor changed shape under us, and a
        // silent 0.0 would be a wrong answer rather than a missing one.
        other => {
            set_last_error(format!(
                "provenance.record: confidence came back as {:?}, expected a Float",
                other.map(crate::interp::type_name).unwrap_or("missing")
            ));
            return -1;
        }
    };
    // SAFETY: the caller allocated `PROVENANCE_RECORD_SLOTS` i64 slots (the
    // contract on this function); every index below is < PROVENANCE_RECORD_SLOTS.
    unsafe {
        *out.add(0) = str_slot("source_url");
        *out.add(1) = int_slot("fetched_at");
        *out.add(2) = str_slot("egress_label");
        *out.add(3) = str_slot("egress_tier");
        *out.add(4) = int_slot("status_code");
        *out.add(5) = str_slot("body_hash");
        *out.add(6) = confidence;
        *out.add(7) = str_slot("grade");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn slot_str(slots: &[i64], i: usize) -> Option<String> {
        let p = slots[i] as *const c_char;
        if p.is_null() {
            return None;
        }
        Some(
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_str()
                .unwrap()
                .to_string(),
        )
    }

    /// The eight declared fields, with the constructor's defaults: `fetched_at`
    /// from the clock, `DEFAULT_BASE_CONFIDENCE`, and an EMPTY grade.
    #[test]
    fn record_fills_every_declared_field() {
        let mut slots = [0i64; PROVENANCE_RECORD_SLOTS];
        let rc = tallow_provenance_record(
            c("https://example.com/x").as_ptr(),
            c("pool-us-1").as_ptr(),
            c("residential").as_ptr(),
            200,
            c("abc123").as_ptr(),
            slots.as_mut_ptr(),
        );
        assert_eq!(rc, 0);
        assert_eq!(
            slot_str(&slots, 0).as_deref(),
            Some("https://example.com/x")
        );
        assert_eq!(slot_str(&slots, 2).as_deref(), Some("pool-us-1"));
        assert_eq!(slot_str(&slots, 3).as_deref(), Some("residential"));
        assert_eq!(slots[4], 200);
        assert_eq!(slot_str(&slots, 5).as_deref(), Some("abc123"));
        assert_eq!(
            slot_str(&slots, 7).as_deref(),
            Some(""),
            "grade starts empty"
        );
        let confidence = f64::from_bits(slots[6] as u64);
        assert!(
            (confidence - crate::stdlib::provenance::DEFAULT_BASE_CONFIDENCE).abs() < f64::EPSILON,
            "base confidence must be the module default, got {confidence}"
        );
        // A plausible clock reading: after 2020 and before 2100.
        assert!(
            slots[1] > 1_577_836_800 && slots[1] < 4_102_444_800,
            "fetched_at {} is not a current unix timestamp",
            slots[1]
        );
    }

    #[test]
    fn null_arguments_fail_closed() {
        let mut slots = [0i64; PROVENANCE_RECORD_SLOTS];
        assert_eq!(
            tallow_provenance_record(
                std::ptr::null(),
                c("l").as_ptr(),
                c("t").as_ptr(),
                200,
                c("h").as_ptr(),
                slots.as_mut_ptr(),
            ),
            -1
        );
        assert_eq!(
            tallow_provenance_record(
                c("u").as_ptr(),
                c("l").as_ptr(),
                c("t").as_ptr(),
                200,
                c("h").as_ptr(),
                std::ptr::null_mut(),
            ),
            -1
        );
    }
}
