//! Comprehensive filename and path sanitization
//!
//! Defends against 20+ attack vectors for filenames received from untrusted senders.
//! Two-layer defense: component-level filtering + post-join path verification.
//!
//! # Attack vectors defended
//!
//! - Empty filenames
//! - Null bytes
//! - Directory traversal (`../`, `..\\`)
//! - Absolute paths (`/etc/passwd`, `C:\Windows`)
//! - Windows drive letters (`C:`)
//! - Windows reserved device names (CON, PRN, AUX, NUL, COM0-9, LPT0-9)
//! - Unicode fullwidth path separators (U+FF0F, U+FF3C)
//! - ANSI escape sequences (CSI, OSC, etc.)
//! - Control characters (0x00-0x1F, 0x7F)
//! - Overlength components (>255 bytes)
//! - Tilde expansion (`~`)
//! - Dot-only components (`.`, `..`)
//! - Trailing dots and spaces (Windows)
//! - Leading/trailing whitespace

use std::path::{Component, Path, PathBuf};

/// Error type for sanitization failures
#[derive(Debug, thiserror::Error)]
pub enum SanitizeError {
    /// The input filename was empty
    #[error("empty filename")]
    EmptyFilename,

    /// The filename contains a null byte (0x00)
    #[error("filename contains null byte")]
    NullByte,

    /// After sanitization, the resulting filename was empty
    #[error("filename sanitized to empty string")]
    SanitizedToEmpty,

    /// The sanitized path would escape the output directory
    #[error("path escapes output directory: {0}")]
    PathEscape(String),
}

/// Windows reserved device names (case-insensitive).
///
/// Opening files with these names on Windows can trigger device I/O
/// instead of normal file operations.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Maximum length for a single path component (bytes).
///
/// Most filesystems (ext4, NTFS, APFS, HFS+) limit filenames to 255 bytes.
const MAX_COMPONENT_LEN: usize = 255;

/// Sanitize a filename received from an untrusted sender.
///
/// Applies two layers of defense:
/// 1. **Component-level filtering**: Each path component is individually cleaned
///    of dangerous characters, reserved names, traversal attempts, etc.
/// 2. **Post-join verification**: The final joined path is verified to remain
///    within `output_dir` using lexical component analysis.
///
/// # Errors
///
/// Returns [`SanitizeError`] if:
/// - The input is empty ([`SanitizeError::EmptyFilename`])
/// - The input contains null bytes ([`SanitizeError::NullByte`])
/// - Sanitization removes all content ([`SanitizeError::SanitizedToEmpty`])
/// - The result escapes `output_dir` ([`SanitizeError::PathEscape`])
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use tallow_protocol::transfer::sanitize::sanitize_filename;
///
/// let output = Path::new("/tmp/downloads");
/// let safe = sanitize_filename("hello.txt", output).unwrap();
/// assert_eq!(safe, output.join("hello.txt"));
///
/// // Traversal attacks are neutralized
/// let safe = sanitize_filename("../../../etc/passwd", output).unwrap();
/// assert!(safe.starts_with(output));
/// ```
pub fn sanitize_filename(name: &str, output_dir: &Path) -> Result<PathBuf, SanitizeError> {
    // Check for empty input
    if name.is_empty() {
        return Err(SanitizeError::EmptyFilename);
    }

    // Check for null bytes
    if name.contains('\0') {
        return Err(SanitizeError::NullByte);
    }

    // Strip ANSI escape sequences
    let stripped = strip_ansi(name);

    // Normalize Unicode fullwidth separators to regular separators
    let normalized = stripped.replace(['\u{FF0F}', '\u{FF3C}'], "/");

    // Normalize backslashes to forward slashes
    let normalized = normalized.replace('\\', "/");

    // Filter control characters (keep printable + newline + tab)
    let cleaned: String = normalized
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();

    // Trim leading/trailing whitespace
    let trimmed = cleaned.trim();

    if trimmed.is_empty() {
        return Err(SanitizeError::SanitizedToEmpty);
    }

    // Split into components and filter dangerous ones
    let parts: Vec<&str> = trimmed.split('/').collect();
    let mut safe_components: Vec<String> = Vec::new();

    for part in parts {
        let part = part.trim();

        // Skip empty components (from double slashes or leading slash)
        if part.is_empty() {
            continue;
        }

        // Skip dot-only components (current dir and parent dir)
        if part == "." || part == ".." {
            continue;
        }

        // Skip tilde-prefixed components (prevent shell expansion)
        if part.starts_with('~') {
            continue;
        }

        // Strip Windows drive letter prefixes (e.g., "C:") — loop handles chained "A:B:C:"
        let mut part = part;
        while part.len() >= 2
            && part.as_bytes()[0].is_ascii_alphabetic()
            && part.as_bytes()[1] == b':'
        {
            part = &part[2..];
        }

        if part.is_empty() {
            continue;
        }

        // Replace remaining colons — invalid on Windows filenames, can trigger
        // NTFS ADS access or be misinterpreted as drive letters in PathBuf
        let colon_safe = part.replace(':', "_");
        let part = colon_safe.as_str();

        // Trim trailing dots and spaces (Windows compatibility)
        let part = part.trim_end_matches(['.', ' ']);
        if part.is_empty() {
            continue;
        }

        // Truncate overlength components (byte-level, respecting UTF-8)
        let part = truncate_to_byte_len(part, MAX_COMPONENT_LEN);

        // Prefix Windows reserved names to defuse them
        let mut component = part.to_string();
        let stem = if let Some(dot_pos) = part.find('.') {
            &part[..dot_pos]
        } else {
            part
        };
        if WINDOWS_RESERVED
            .iter()
            .any(|r| r.eq_ignore_ascii_case(stem))
        {
            component = format!("_{part}");
        }

        safe_components.push(component);
    }

    if safe_components.is_empty() {
        return Err(SanitizeError::SanitizedToEmpty);
    }

    // Build relative path from safe components
    let relative: PathBuf = safe_components.iter().collect();

    // Layer 2: Post-join verification
    // Join with output_dir and verify no escape via lexical component walk
    let joined = output_dir.join(&relative);

    let mut depth: i32 = 0;
    for component in relative.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(SanitizeError::PathEscape(relative.display().to_string()));
                }
            }
            Component::Normal(_) => depth += 1,
            _ => {}
        }
    }

    Ok(joined)
}

/// Truncate a string to at most `max_bytes` bytes, respecting UTF-8 boundaries.
fn truncate_to_byte_len(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Find the largest char boundary <= max_bytes
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Strip ANSI escape sequences from a string.
///
/// On native builds, uses the `strip-ansi-escapes` crate with its VTE parser.
/// On WASM builds, uses a lightweight state machine that handles CSI, OSC,
/// and single-character escape sequences.
#[cfg(feature = "full")]
fn strip_ansi(input: &str) -> String {
    let stripped = strip_ansi_escapes::strip(input);
    String::from_utf8_lossy(&stripped).into_owned()
}

/// WASM-compatible ANSI escape stripping using a simple state machine.
///
/// Handles the most common escape sequences:
/// - CSI sequences: `ESC [ ... final_byte`
/// - OSC sequences: `ESC ] ... (BEL | ST)`
/// - Two-character escapes: `ESC X` where X is a single character
#[cfg(not(feature = "full"))]
fn strip_ansi(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC detected — determine sequence type
            match chars.peek() {
                Some('[') => {
                    // CSI sequence: ESC [ ... (0x40-0x7E final byte)
                    chars.next(); // consume '['
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        if ('\x40'..='\x7e').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: ESC ] ... (BEL or ST)
                    chars.next(); // consume ']'
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        if next == '\x07' {
                            break; // BEL terminates OSC
                        }
                        if next == '\x1b' {
                            // ST = ESC + backslash
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    // Two-character escape: ESC + single char
                    chars.next();
                }
                None => {
                    // Trailing ESC at end of string — discard
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Strip ANSI escape sequences and control characters from a display string.
///
/// Use this on ANY string shown to the user that originated from the network.
/// Preserves newlines and tabs but strips all other control characters
/// and terminal escape sequences.
///
/// # Examples
///
/// ```
/// use tallow_protocol::transfer::sanitize::sanitize_display;
///
/// let malicious = "\x1b[31mred text\x1b[0m";
/// assert_eq!(sanitize_display(malicious), "red text");
///
/// // Newlines and tabs are preserved
/// assert_eq!(sanitize_display("line1\nline2\ttab"), "line1\nline2\ttab");
/// ```
pub fn sanitize_display(input: &str) -> String {
    // On native builds with strip-ansi-escapes, the VTE parser consumes ALL
    // C0 control characters including \t and \n. Protect the ones we want to
    // keep by substituting with Unicode private-use-area placeholders.
    #[cfg(feature = "full")]
    let input_for_strip = input.replace('\t', "\u{F0001}").replace('\n', "\u{F0002}");
    #[cfg(feature = "full")]
    let stripped = strip_ansi(&input_for_strip);
    #[cfg(feature = "full")]
    let after_restore = stripped
        .replace('\u{F0001}', "\t")
        .replace('\u{F0002}', "\n");

    // On WASM builds, our state machine does not eat tabs/newlines, so no
    // PUA placeholder dance is needed.
    #[cfg(not(feature = "full"))]
    let after_restore = strip_ansi(input);

    after_restore
        .chars()
        .filter(|c| {
            // Allow newlines and tabs
            if *c == '\n' || *c == '\t' {
                return true;
            }
            // Strip all other control chars
            if c.is_control() {
                return false;
            }
            // Strip Unicode bidi overrides (U+202A-U+202E, U+2066-U+2069)
            // and invisible formatting chars that enable text spoofing
            !matches!(*c,
                '\u{200B}'..='\u{200F}' | // zero-width, LRM, RLM
                '\u{202A}'..='\u{202E}' | // bidi embedding/override
                '\u{2066}'..='\u{2069}' | // bidi isolate
                '\u{FEFF}' |              // BOM / zero-width no-break space
                '\u{00AD}'               // soft hyphen
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output_dir() -> PathBuf {
        PathBuf::from("/tmp/tallow-test")
    }

    #[test]
    fn test_basic_filename() {
        let result = sanitize_filename("hello.txt", &output_dir()).unwrap();
        assert_eq!(result, output_dir().join("hello.txt"));
    }

    #[test]
    fn test_subdirectory_path() {
        let result = sanitize_filename("dir/file.txt", &output_dir()).unwrap();
        assert_eq!(result, output_dir().join("dir").join("file.txt"));
    }

    #[test]
    fn test_path_traversal_simple() {
        let result = sanitize_filename("../../../etc/passwd", &output_dir()).unwrap();
        // Should strip the .. components, leaving just "etc/passwd"
        assert!(result.starts_with(output_dir()));
    }

    #[test]
    fn test_path_traversal_mixed() {
        let result = sanitize_filename("foo/../../bar", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
    }

    #[test]
    fn test_absolute_path_unix() {
        let result = sanitize_filename("/etc/passwd", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
        // Should contain "etc" and "passwd" but not start with /etc
    }

    #[test]
    fn test_absolute_path_windows() {
        let result = sanitize_filename("C:\\Windows\\System32\\cmd.exe", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
    }

    #[test]
    fn test_null_byte() {
        let result = sanitize_filename("file\0.txt", &output_dir());
        assert!(matches!(result, Err(SanitizeError::NullByte)));
    }

    #[test]
    fn test_empty_filename() {
        let result = sanitize_filename("", &output_dir());
        assert!(matches!(result, Err(SanitizeError::EmptyFilename)));
    }

    #[test]
    fn test_dots_only() {
        assert!(matches!(
            sanitize_filename(".", &output_dir()),
            Err(SanitizeError::SanitizedToEmpty)
        ));
        assert!(matches!(
            sanitize_filename("..", &output_dir()),
            Err(SanitizeError::SanitizedToEmpty)
        ));
    }

    #[test]
    fn test_windows_reserved_con() {
        let result = sanitize_filename("CON", &output_dir()).unwrap();
        assert!(result.to_string_lossy().contains("_CON"));
    }

    #[test]
    fn test_windows_reserved_with_extension() {
        let result = sanitize_filename("CON.txt", &output_dir()).unwrap();
        assert!(result.to_string_lossy().contains("_CON.txt"));
    }

    #[test]
    fn test_windows_reserved_case_insensitive() {
        for name in &["con", "Con", "cOn", "CON"] {
            let result = sanitize_filename(name, &output_dir()).unwrap();
            assert!(
                result.to_string_lossy().to_uppercase().contains("_CON"),
                "Failed for: {}",
                name
            );
        }
    }

    #[test]
    fn test_windows_reserved_nul() {
        let result = sanitize_filename("NUL", &output_dir()).unwrap();
        assert!(result.to_string_lossy().contains("_NUL"));
    }

    #[test]
    fn test_windows_reserved_com1() {
        let result = sanitize_filename("COM1.txt", &output_dir()).unwrap();
        assert!(result.to_string_lossy().contains("_COM1.txt"));
    }

    #[test]
    fn test_windows_reserved_lpt3() {
        let result = sanitize_filename("lpt3", &output_dir()).unwrap();
        assert!(result.to_string_lossy().to_uppercase().contains("_LPT3"));
    }

    #[test]
    fn test_ansi_escape_in_filename() {
        let result = sanitize_filename("\x1b[31mmalicious\x1b[0m.txt", &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert!(!name.contains("\x1b"));
        assert!(name.contains("malicious"));
    }

    #[test]
    fn test_osc_escape_in_filename() {
        let result = sanitize_filename("\x1b]0;evil\x07file.txt", &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert!(!name.contains("\x1b"));
    }

    #[test]
    fn test_unicode_fullwidth_slash() {
        // U+FF0F = fullwidth solidus
        let result = sanitize_filename("dir\u{FF0F}file.txt", &output_dir()).unwrap();
        // Should be treated as path separator, resulting in dir/file.txt
        assert!(result.starts_with(output_dir()));
    }

    #[test]
    fn test_unicode_fullwidth_backslash() {
        // U+FF3C = fullwidth reverse solidus
        let result = sanitize_filename("dir\u{FF3C}file.txt", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
    }

    #[test]
    fn test_control_characters() {
        let result = sanitize_filename("file\x01\x02\x03.txt", &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn test_overlength_component() {
        let long_name = "a".repeat(300);
        let result = sanitize_filename(&long_name, &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert!(name.len() <= MAX_COMPONENT_LEN);
    }

    #[test]
    fn test_overlength_component_utf8() {
        // Use multi-byte characters to verify we don't split in the middle of one
        let long_name = "\u{1F600}".repeat(100); // each is 4 bytes = 400 bytes total
        let result = sanitize_filename(&long_name, &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert!(name.len() <= MAX_COMPONENT_LEN);
        // Verify valid UTF-8 (no replacement characters from mid-codepoint split)
        assert!(!name.contains('\u{FFFD}'));
    }

    #[test]
    fn test_tilde_expansion() {
        let result = sanitize_filename("~/secret", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
        assert!(result.to_string_lossy().contains("secret"));
    }

    #[test]
    fn test_tilde_only() {
        let result = sanitize_filename("~", &output_dir());
        assert!(matches!(result, Err(SanitizeError::SanitizedToEmpty)));
    }

    #[test]
    fn test_trailing_dots_windows() {
        let result = sanitize_filename("file...", &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "file");
    }

    #[test]
    fn test_trailing_spaces_windows() {
        let result = sanitize_filename("file   ", &output_dir()).unwrap();
        let name = result.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "file");
    }

    #[test]
    fn test_whitespace_only() {
        let result = sanitize_filename("   ", &output_dir());
        assert!(matches!(result, Err(SanitizeError::SanitizedToEmpty)));
    }

    #[test]
    fn test_double_slashes() {
        let result = sanitize_filename("dir//file.txt", &output_dir()).unwrap();
        assert_eq!(result, output_dir().join("dir").join("file.txt"));
    }

    #[test]
    fn test_drive_letter_stripping() {
        let result = sanitize_filename("D:important.doc", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
        assert!(result.to_string_lossy().contains("important.doc"));
    }

    #[test]
    fn test_chained_drive_letters() {
        // Regression: "A:A:" → strip "A:" → "A:" still looks like a drive letter
        // Must not escape output_dir on Windows
        let result = sanitize_filename("A:A:", &output_dir());
        if let Ok(path) = result {
            assert!(
                path.starts_with(output_dir()),
                "Path {} escaped output dir",
                path.display()
            );
        } // SanitizedToEmpty is also acceptable
    }

    #[test]
    fn test_triple_chained_drive_letters() {
        let result = sanitize_filename("C:D:E:file.txt", &output_dir());
        if let Ok(path) = result {
            assert!(path.starts_with(output_dir()));
            assert!(path.to_string_lossy().contains("file"));
        }
    }

    #[test]
    fn test_colon_in_filename() {
        // Colons in filenames should be replaced (NTFS ADS prevention)
        let result = sanitize_filename("file:stream.txt", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
        // Colon should be replaced with underscore
        let name = result.file_name().unwrap().to_string_lossy();
        assert!(!name.contains(':'));
        assert!(name.contains("file_stream"));
    }

    #[test]
    fn test_mixed_attack_vectors() {
        // Combine multiple attack vectors in one filename
        let result = sanitize_filename(
            "\x1b[31m../../../C:\\Windows\\..\u{FF0F}..\\CON.txt\x1b[0m",
            &output_dir(),
        )
        .unwrap();
        assert!(result.starts_with(output_dir()));
        // CON.txt should be prefixed
        assert!(result.to_string_lossy().contains("_CON.txt"));
    }

    #[test]
    fn test_sanitize_display_strips_ansi() {
        let input = "\x1b[31mred text\x1b[0m";
        let result = sanitize_display(input);
        assert_eq!(result, "red text");
    }

    #[test]
    fn test_sanitize_display_strips_osc() {
        let input = "\x1b]0;evil title\x07safe text";
        let result = sanitize_display(input);
        assert!(!result.contains("\x1b"));
        assert!(result.contains("safe text"));
    }

    #[test]
    fn test_sanitize_display_preserves_newlines() {
        let input = "line1\nline2\ttab";
        let result = sanitize_display(input);
        assert_eq!(result, "line1\nline2\ttab");
    }

    #[test]
    fn test_sanitize_display_strips_control_chars() {
        let input = "hello\x01\x02\x03world";
        let result = sanitize_display(input);
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_hidden_dotfile_preserved() {
        // Dotfiles are legitimate, only "." and ".." are stripped
        let result = sanitize_filename(".gitignore", &output_dir()).unwrap();
        // .gitignore has trailing dots/spaces trimmed: ".gitignore" has no trailing dots
        assert!(result.to_string_lossy().contains(".gitignore"));
    }

    #[test]
    fn test_deeply_nested_path() {
        let result = sanitize_filename("a/b/c/d/e/f/g/h/i/j/file.txt", &output_dir()).unwrap();
        assert!(result.starts_with(output_dir()));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn output_dir() -> PathBuf {
        PathBuf::from("/tmp/tallow-proptest")
    }

    proptest! {
        #[test]
        fn sanitized_path_never_escapes_output_dir(name in "\\PC{1,200}") {
            if let Ok(path) = sanitize_filename(&name, &output_dir()) {
                prop_assert!(
                    path.starts_with(output_dir()),
                    "Path {} escaped output dir",
                    path.display()
                );
            }
        }

        #[test]
        fn sanitized_path_no_dotdot(name in "\\PC{1,200}") {
            if let Ok(path) = sanitize_filename(&name, &output_dir()) {
                let relative = path.strip_prefix(output_dir()).unwrap();
                for component in relative.components() {
                    prop_assert!(
                        !matches!(component, std::path::Component::ParentDir),
                        "Path {} contains ..",
                        path.display()
                    );
                }
            }
        }

        #[test]
        fn sanitized_path_no_null_bytes(name in "\\PC{1,200}") {
            if let Ok(path) = sanitize_filename(&name, &output_dir()) {
                prop_assert!(
                    !path.to_string_lossy().contains('\0'),
                    "Path {} contains null byte",
                    path.display()
                );
            }
        }

        #[test]
        fn sanitized_display_no_control_chars(input in "\\PC{1,500}") {
            let result = sanitize_display(&input);
            for c in result.chars() {
                prop_assert!(
                    !c.is_control() || c == '\n' || c == '\t',
                    "Display output contains control char: {:?}",
                    c
                );
            }
        }
    }
}
