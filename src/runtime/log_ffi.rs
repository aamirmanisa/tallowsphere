//! Timestamp for the compiled plane's `log.*` lines.
//!
//! The interpreter renders a log line as
//! `[INFO] [2026-11-05T01:34:26Z] message` (`src/stdlib/log.rs` + `chrono`), and writes it to
//! stderr. The native backend printed `[INFO] message` to *stdout* — no timestamp, no stream parity,
//! and only the first argument. This helper supplies the timestamp; codegen does the rest.

use std::ffi::CString;
use std::os::raw::c_char;

/// ISO-8601 UTC at second precision, e.g. `2026-11-05T01:34:26Z` — the same shape the interpreter
/// produces with `Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_log_timestamp() -> *mut c_char {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    CString::new(ts)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn timestamp_is_iso8601_seconds_utc() {
        let p = tallow_log_timestamp();
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        assert!(s.ends_with('Z'), "must be UTC with a Z suffix: {s}");
        assert_eq!(s.len(), 20, "YYYY-MM-DDTHH:MM:SSZ is 20 chars: {s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
