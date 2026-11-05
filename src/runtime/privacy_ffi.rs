//! Native `redact()` / `mask()` for privacy-qualified values.
//!
//! The rules mirror `Value::redact` / `Value::mask` in `src/interp.rs` **as the
//! interpreter applies them to these values**: a cast such as
//! `let c = "user@example.com" as Email` binds a plain `Value::String`, so the
//! string rules apply. Measured on `examples/privacy_valid.tl`:
//!
//!   Email    redact -> `u***@***.com`   mask -> `****@example.com`
//!   IP       redact -> `10****.7`       (first two and last two kept)
//!   Phone    mask   -> `********`       (one star per character)
//!   Password redact -> `co……le`         (28 chars: first two + 24 stars + last two)
//!
//! Character counting is by `char`, never by byte: the interpreter uses
//! `chars().count()`, so a byte-based port stars the wrong number of glyphs on
//! any non-ASCII value.
//!
//! These replace the inline LLVM IR helper `tallow_redact_private` emitted by
//! `emit_module` (src/codegen.rs), whose rule was a third variant
//! (first + last character kept, everything between starred) and produced
//! `u**************m` where the interpreter produces `u***@***.com`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn into_c(s: String) -> *mut c_char {
    // The interpreter never emits an interior NUL for these inputs; if one ever
    // arrives, answer with the generic redaction rather than a dangling pointer.
    CString::new(s).map(|c| c.into_raw()).unwrap_or_else(|_| {
        CString::new("***")
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut())
    })
}

fn input(src: *const c_char) -> Option<String> {
    if src.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(src) }.to_string_lossy().into_owned())
}

/// `<first local char>***@***.<tld>` for anything with an `@`, `***` for values
/// of four characters or fewer, otherwise keep the first and last two characters
/// and star the middle.
///
/// These are the rules the interpreter applies to a **plain String** value, which
/// is what `let x = "…" as Email` / `let p: Phone = …` actually bind: the cast
/// does not wrap the value in `Value::Private`. Measured against
/// `examples/privacy_valid.tl` — `Phone("555-0100").mask()` → `********`,
/// `IPAddress("10.0.0.7").redact()` → `10****.7`,
/// `Password(28 chars).redact()` → `co…le`.
pub fn redact_value(s: &str) -> String {
    if let Some((local, domain)) = s.split_once('@') {
        let first: String = local.chars().take(1).collect();
        let tld = domain.rsplit('.').next().unwrap_or("com");
        return format!("{first}***@***.{tld}");
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 4 {
        return "***".to_string();
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - 4))
}

/// `****@<domain>` for anything with an `@`, otherwise one `*` per character.
pub fn mask_value(s: &str) -> String {
    if let Some((_, domain)) = s.split_once('@') {
        return format!("****@{domain}");
    }
    "*".repeat(s.chars().count())
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_redact_privacy(src: *const c_char) -> *mut c_char {
    match input(src) {
        Some(s) => into_c(redact_value(&s)),
        None => into_c("***".to_string()),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tallow_mask_privacy(src: *const c_char) -> *mut c_char {
    match input(src) {
        Some(s) => into_c(mask_value(&s)),
        None => into_c("****".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_matches_the_interpreter() {
        assert_eq!(redact_value("user@example.com"), "u***@***.com");
        assert_eq!(redact_value("10.0.0.7"), "10****.7");
        assert_eq!(redact_value("correct horse battery staple"), "co************************le");
        assert_eq!(redact_value("abcd"), "***");
        // Char-based: 7 chars -> first two + three stars + last two.
        assert_eq!(redact_value("üñïçødé"), "üñ***dé");
    }

    #[test]
    fn mask_matches_the_interpreter() {
        assert_eq!(mask_value("user@example.com"), "****@example.com");
        assert_eq!(mask_value("555-0100"), "********");
        assert_eq!(mask_value("üñïçødé"), "*******");
    }
}
