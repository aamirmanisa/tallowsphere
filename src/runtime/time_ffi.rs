//! Runtime FFI: `tallow.time.*` helpers for compiled programs.
//!
//! The interpreter implements both `time.now` and `time.parse_iso` in Rust and
//! both speak **milliseconds since the Unix epoch** (`src/interp.rs` "now",
//! `src/stdlib/time.rs::time_parse_iso`). Compiled `.tl` binaries call these
//! C-ABI functions instead, so parity requires the same unit and the same
//! accept/reject set.

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error};

/// Failure sentinel for [`tallow_time_parse_iso`].
///
/// `i64::MIN` cannot be a real millisecond timestamp, so it is unambiguous. The
/// emitted code branches on it and exits non-zero bearing the message from
/// `tallow_last_error`, mirroring the interpreter's runtime error. Returning
/// `0` would be worse than useless — `0` is the epoch, i.e. a silently valid
/// wrong answer (the P3 hazard this backend is built to avoid).
pub const TIME_PARSE_FAILED: i64 = i64::MIN;

/// `time.now()` -> milliseconds since the Unix epoch.
///
/// Must stay in milliseconds: the interpreter's `time.now` is millis, and the
/// only other consumer of that number in a compiled program is
/// [`tallow_time_parse_iso`], which is also millis.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_time_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `time.parse_iso(s)` -> milliseconds since the Unix epoch, or
/// [`TIME_PARSE_FAILED`] (with `tallow_last_error` set) when `s` is not a valid
/// RFC 3339 timestamp carrying an explicit offset.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_time_parse_iso(input: *const c_char) -> i64 {
    let Some(s) = (unsafe { cstr_to_str(input) }) else {
        set_last_error("expected string argument".to_string());
        return TIME_PARSE_FAILED;
    };
    match chrono::DateTime::parse_from_rfc3339(s) {
        Ok(dt) => dt.timestamp_millis(),
        Err(e) => {
            set_last_error(e.to_string());
            TIME_PARSE_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Same lower bound the interpreter test uses: > 1.7e12 ms (~2023). A
    /// seconds-valued implementation (1.7e9) fails this by three orders of
    /// magnitude.
    #[test]
    fn now_is_millis_not_seconds() {
        let ms = tallow_time_now_ms();
        assert!(ms > 1_700_000_000_000, "time.now must be millis, got {ms}");
    }

    #[test]
    fn parse_iso_matches_chrono_millis() {
        let s = CString::new("2026-10-12T00:00:00Z").unwrap();
        assert_eq!(tallow_time_parse_iso(s.as_ptr()), 1_791_763_200_000);
    }

    #[test]
    fn parse_iso_rejects_missing_offset() {
        // RFC 3339 requires an offset; the interpreter refuses to guess local
        // time, so the native path must refuse too (see the stdlib doc comment).
        let s = CString::new("2026-10-12T00:00:00").unwrap();
        assert_eq!(tallow_time_parse_iso(s.as_ptr()), TIME_PARSE_FAILED);
    }
}
