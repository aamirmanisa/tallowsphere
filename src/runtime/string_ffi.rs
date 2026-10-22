//! Runtime FFI: string conversions that both planes must agree on.
//!
//! The interpreter's `String.parse()` is dynamically typed: an integer string
//! becomes `Value::Int`, anything else that parses as a float becomes
//! `Value::Float`, and only a string that is neither raises
//! `cannot parse '<s>' as number`. The native plane has one static type per
//! expression, so its lowering is deliberately narrower and refuses the case it
//! cannot represent rather than guessing — see `tallow_str_parse_i64`.

use std::os::raw::c_char;

use super::cstr_to_str;

/// Result of [`tallow_str_parse_i64`]: the text is a valid `i64`.
pub const PARSE_OK: i32 = 0;
/// The text is not an integer and not a float either — the interpreter would
/// have raised `cannot parse '<s>' as number`.
pub const PARSE_NOT_A_NUMBER: i32 = 1;
/// The text parses as a float. The interpreter returns it as a float; the native
/// plane cannot, so the emitted code names the float path instead of silently
/// truncating.
pub const PARSE_FLOAT: i32 = 2;

/// `String.parse()` on the native plane: `0` and `*out` set on success,
/// `PARSE_NOT_A_NUMBER` or `PARSE_FLOAT` otherwise.
///
/// # Safety
///
/// `s` must be a NUL-terminated string and `out` must point to a writable `i64`
/// for the duration of the call. Both come from generated IR (`alloca`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_str_parse_i64(s: *const c_char, out: *mut i64) -> i32 {
    let Some(text) = (unsafe { cstr_to_str(s) }) else {
        return PARSE_NOT_A_NUMBER;
    };

    // `str::parse` is the interpreter's own parser, so the accepted spelling is
    // identical: optional sign, ASCII digits, no surrounding whitespace, no
    // separators, no radix prefix.
    if let Ok(n) = text.parse::<i64>() {
        // SAFETY: the caller guarantees `out` is writable (generated alloca).
        unsafe { *out = n };
        return PARSE_OK;
    }

    // Classify the failure so the caller can distinguish "not a number" (the
    // interpreter's own error) from "a number this ABI cannot carry".
    if text.parse::<f64>().is_ok() {
        PARSE_FLOAT
    } else {
        PARSE_NOT_A_NUMBER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn parse(text: &str) -> (i32, i64) {
        let c = CString::new(text).unwrap();
        let mut out: i64 = -999;
        let rc = tallow_str_parse_i64(c.as_ptr(), &mut out);
        (rc, out)
    }

    #[test]
    fn parses_the_integer_spellings_the_interpreter_accepts() {
        for (text, want) in [
            ("8080", 8080),
            ("0", 0),
            ("-42", -42),
            ("+7", 7),
            ("000123", 123),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
        ] {
            assert_eq!(parse(text), (PARSE_OK, want), "text {text:?}");
        }
    }

    #[test]
    fn refuses_what_the_interpreter_refuses_to_parse_as_a_number() {
        for text in ["", "abc", "12abc", " 42", "4 2", "0x10", "1_000", "1.5.5"] {
            let (rc, out) = parse(text);
            assert_eq!(rc, PARSE_NOT_A_NUMBER, "text {text:?}");
            assert_eq!(out, -999, "no write on failure, text {text:?}");
        }
    }

    #[test]
    fn names_float_text_separately_so_the_caller_can_refuse_it() {
        // The interpreter returns Float for these; the native plane must say so
        // rather than truncate them into an integer.
        for text in ["1.5", "-0.25", "1e3", "inf"] {
            assert_eq!(parse(text).0, PARSE_FLOAT, "text {text:?}");
        }
        // Beyond i64 but inside the interpreter's i128: still a number the
        // native plane cannot carry, and it parses as a float.
        assert_eq!(parse("170141183460469231731687303715884105727").0, PARSE_FLOAT);
    }
}
