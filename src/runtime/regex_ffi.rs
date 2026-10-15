//! Runtime FFI: `tallow.regex.*` for the compiled path.
//!
//! Both helpers call the interpreter's own dispatch (`stdlib::regex::dispatch`)
//! instead of re-implementing the match, so the pattern language (character
//! classes, `\d`/`\w`, `(?i)` inline flags, Unicode), the replacement syntax
//! (`$1` group references) and the replace-all rule **cannot drift** between the
//! engines — the same sharing rule `url_ffi` uses for `percent_encode`.
//!
//! # Why this replaced hand-rolled POSIX IR (t_7a8efe20)
//!
//! The native lowering used to emit POSIX `regcomp`/`regexec` IR. POSIX ERE is a
//! *different* regex language from the `regex` crate the interpreter uses, and the
//! emitted loop replaced only the **first** match. Measured, both engines, rc=0:
//!
//! ```text
//! regex.replace("[0-9a-f]", "az1", "")   interp "z"   native-POSIX "z1"
//! regex.replace("[a-f0-9]", "9a",  "")   interp ""    native-POSIX "a"
//! regex.replace("(cat|dog)", "cat dog", "x")  interp "x x"  native-POSIX "x dog"
//! regex.is_match("\\d", "5")             interp true  native-POSIX false
//! regex.is_match("(?i)abc", "ABC")       interp true  native-POSIX false
//! regex.replace("(a)(b)", "ab", "$2$1")  interp "ba"  native-POSIX "$2$1"
//! ```
//!
//! Every one of those was silent at rc=0 — the G-14 "plausible success, wrong
//! answer" class, in a primitive a scrub-scan/redactor is expected to trust.
//!
//! # Error contract
//!
//! A pattern the engine rejects is the interpreter's `Err("regex error: …")`: an
//! invalid pattern has no "no match" answer, so `is_match` returns `-1` and
//! `replace` returns `NULL` with the message in `tallow_last_error()`. The emitted
//! code turns both into a non-zero exit naming the reason, so a broken pattern can
//! never masquerade as `false` / "unchanged text" (the old POSIX path answered
//! `false` on a failed `regcomp`).

use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};
use crate::interp::Value;
use crate::stdlib::regex;

/// `regex.is_match(pattern, text) -> bool` / `regex.matches(pattern, text)`.
///
/// 1 = match, 0 = no match, -1 = pattern/argument error (see module docs).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_regex_is_match(pattern: *const c_char, text: *const c_char) -> i32 {
    let (Some(pattern), Some(text)) = (unsafe { cstr_to_str(pattern) }, unsafe {
        cstr_to_str(text)
    }) else {
        set_last_error("regex.is_match: pattern and text must be strings".to_string());
        return -1;
    };
    let args = vec![
        Value::String(pattern.to_string()),
        Value::String(text.to_string()),
    ];
    match regex::dispatch("is_match", args) {
        Some(Ok(Value::Bool(matched))) => i32::from(matched),
        Some(Ok(Value::Err(msg))) => {
            set_last_error(format!("regex.is_match: {}", msg.as_string()));
            -1
        }
        Some(Err(msg)) => {
            set_last_error(format!("regex.is_match: {msg}"));
            -1
        }
        Some(Ok(other)) => {
            set_last_error(format!(
                "regex.is_match: unexpected result {}",
                other.as_string()
            ));
            -1
        }
        None => {
            set_last_error("regex.is_match: interpreter dispatch has no is_match".to_string());
            -1
        }
    }
}

/// `regex.replace(pattern, text, replacement) -> String` — replaces **every**
/// match, exactly as the interpreter does (`Regex::replace_all`).
///
/// NULL on a pattern/argument error, with the message in `tallow_last_error()`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_regex_replace(
    pattern: *const c_char,
    text: *const c_char,
    replacement: *const c_char,
) -> *mut c_char {
    let (Some(pattern), Some(text), Some(replacement)) = (
        unsafe { cstr_to_str(pattern) },
        unsafe { cstr_to_str(text) },
        unsafe { cstr_to_str(replacement) },
    ) else {
        set_last_error(
            "regex.replace: pattern, text and replacement must all be strings".to_string(),
        );
        return std::ptr::null_mut();
    };
    let args = vec![
        Value::String(pattern.to_string()),
        Value::String(text.to_string()),
        Value::String(replacement.to_string()),
    ];
    match regex::dispatch("replace", args) {
        Some(Ok(Value::String(out))) => string_to_cstr(&out),
        Some(Ok(Value::Err(msg))) => {
            set_last_error(format!("regex.replace: {}", msg.as_string()));
            std::ptr::null_mut()
        }
        Some(Err(msg)) => {
            set_last_error(format!("regex.replace: {msg}"));
            std::ptr::null_mut()
        }
        Some(Ok(other)) => {
            set_last_error(format!(
                "regex.replace: unexpected result {}",
                other.as_string()
            ));
            std::ptr::null_mut()
        }
        None => {
            set_last_error("regex.replace: interpreter dispatch has no replace".to_string());
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    fn cs(s: &str) -> CString {
        CString::new(s).expect("cstring")
    }

    fn is_match(pattern: &str, text: &str) -> i32 {
        tallow_regex_is_match(cs(pattern).as_ptr(), cs(text).as_ptr())
    }

    /// `replace` returns a heap C string the emitted code owns; read it out for
    /// the assertion (the test process exits before the leak matters).
    fn replace(pattern: &str, text: &str, repl: &str) -> String {
        let p = tallow_regex_replace(cs(pattern).as_ptr(), cs(text).as_ptr(), cs(repl).as_ptr());
        assert!(!p.is_null(), "replace returned NULL for a valid pattern");
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .expect("utf8 result")
            .to_string()
    }

    /// The card's engine matrix (t_7a8efe20), every row: the class body is
    /// ALL of `[0-9a-f]`, not just its first range, and `replace` removes
    /// every match, not just the first.
    #[test]
    fn class_members_and_replace_all_match_the_interpreter_matrix() {
        // "[0-9a-f]" on "1a" — both the digit and the hex letter go.
        assert_eq!(replace("[0-9a-f]", "1a", ""), "");
        assert_eq!(replace("[a-f0-9]", "1a", ""), "");
        assert_eq!(replace("[0-9A-Fa-f]", "1Aaz", ""), "z");
        assert_eq!(replace("[0-9xyz]", "1xz", ""), "");
        assert_eq!(replace("[ab]", "ab", ""), "");
        assert_eq!(replace("[abc]", "abc", ""), "");
        assert_eq!(replace("[0-9ab]", "1ab", ""), "");
        assert_eq!(replace("(a|b)", "ab", ""), "");
        // Single-range classes were always right — keep them in the pin.
        assert_eq!(replace("[0-9]", "1a", ""), "a");
        assert_eq!(replace("[a-f]", "1a", ""), "1");
        // Discriminators: the FIRST match is a letter, so
        // "only the first class member survives" and "only the first match is
        // replaced" predict different answers ("z1" / "az" / "a" / "ab" / "a").
        assert_eq!(replace("[0-9a-f]", "az1", ""), "z");
        assert_eq!(replace("[a-f0-9]", "9a", ""), "");
        assert_eq!(replace("[abc]", "cab", ""), "");
        assert_eq!(replace("(a|b)", "ba", ""), "");
        assert_eq!(replace("\\d", "a1b2", "-"), "a-b-");
        assert_eq!(replace("cat|dog", "cat dog cat", "x"), "x x x");
    }

    /// Class *membership* is the same question `is_match` answers, with no
    /// replace-first/all confound — it must be true for every member of a class.
    #[test]
    fn is_match_honours_every_class_member() {
        assert_eq!(is_match("[0-9a-f]", "f"), 1);
        assert_eq!(is_match("[0-9a-f]", "9"), 1);
        assert_eq!(is_match("[0-9xyz]", "y"), 1);
        assert_eq!(is_match("[0-9A-Fa-f]", "B"), 1);
        assert_eq!(is_match("[0-9A-Fa-f]", "f"), 1);
        assert_eq!(is_match("[ab]", "b"), 1);
        assert_eq!(is_match("(a|b)", "b"), 1);
        assert_eq!(is_match("[a-f0-9]", "9"), 1);
        assert_eq!(is_match("[0-9a-f]", "z"), 0);
    }

    /// POSIX ERE / Rust `regex` language rows: the two engines must speak one
    /// language (`\d`, inline flags, `$1` replacement groups).
    #[test]
    fn pattern_language_matches_the_interpreter_engine() {
        assert_eq!(is_match("\\d", "5"), 1);
        assert_eq!(is_match("\\w", "a"), 1);
        assert_eq!(is_match("\\s", " "), 1);
        assert_eq!(is_match("a+", "aaa"), 1);
        assert_eq!(is_match("^ab$", "ab"), 1);
        assert_eq!(is_match("(?i)abc", "ABC"), 1);
        assert_eq!(replace("(a)(b)", "ab", "$2$1"), "ba");
    }

    /// A pattern the engine rejects is loud (the interpreter's `Err`), never a
    /// silent `false` / unchanged text.
    #[test]
    fn invalid_pattern_is_an_error_not_a_silent_false() {
        assert_eq!(is_match("[", "abc"), -1);
        let p = tallow_regex_replace(cs("[").as_ptr(), cs("abc").as_ptr(), cs("x").as_ptr());
        assert!(
            p.is_null(),
            "replace on an invalid pattern must return NULL, not the unchanged text"
        );
        let msg = unsafe { CStr::from_ptr(crate::runtime::tallow_last_error()) }
            .to_str()
            .expect("utf8 last_error")
            .to_string();
        assert!(
            msg.contains("regex error"),
            "last_error should carry the engine's message, got: {msg}"
        );
    }

    #[test]
    fn null_arguments_fail_closed() {
        assert_eq!(tallow_regex_is_match(std::ptr::null(), cs("a").as_ptr()), -1);
        assert!(tallow_regex_replace(
            std::ptr::null(),
            cs("a").as_ptr(),
            cs("b").as_ptr()
        )
        .is_null());
    }
}
