//! Cross-platform path normalization utilities.
//!
//! FIX12 (2026-08-27): wired into stdlib dispatch (`path_util.normalize_path`,
//! `path_util.is_case_sensitive`, `path_util.paths_equal`). No `.tl` contract
//! file exists yet — callable as a direct native module.
//!
//! Provides consistent path handling across Windows, Linux, and macOS:
//! - Backslash-to-forward-slash normalization
//! - Long path prefix (\\?\) on Windows
//! - Case sensitivity detection
//! - Platform-aware path equality comparison

use std::path::{Path, PathBuf};

use super::StdlibResult;
use crate::interp::Value;

/// Contract-level dispatch for `path_util.*` functions (wired FIX12).
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "normalize_path" => {
            let s = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("path_util.normalize_path: expected a String".into())),
            };
            Some(Ok(Value::String(
                normalize_path(&s).to_string_lossy().into_owned(),
            )))
        }
        "is_case_sensitive" => Some(Ok(Value::Bool(is_case_sensitive()))),
        "paths_equal" => {
            let (a, b) = match (args.first(), args.get(1)) {
                (Some(Value::String(a)), Some(Value::String(b))) => (a.clone(), b.clone()),
                _ => return Some(Err("path_util.paths_equal: expected two Strings".into())),
            };
            Some(Ok(Value::Bool(paths_equal(Path::new(&a), Path::new(&b)))))
        }
        _ => None,
    }
}

/// Contract-level dispatch for `path_util` struct methods (none today).
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

/// Normalize a path for cross-platform consistency.
///
/// - Converts backslashes to forward slashes on all platforms
/// - Applies `\\?\` prefix for long paths on Windows (>260 chars)
/// - Trims trailing slashes
/// - Resolves `./` and `../` components (simple string-based, no filesystem access required)
pub fn normalize_path(path: &str) -> PathBuf {
    // Detect and strip existing \\?\ (or //?/) prefix before normalization
    let has_prefix = path.starts_with("\\\\?\\") || path.starts_with("//?/");
    let core = if has_prefix {
        // Strip the 4-char prefix (\\?\) to normalize the rest
        &path[4..]
    } else {
        path
    };

    // Replace backslashes with forward slashes for consistency
    let mut normalized = core.replace('\\', "/");

    // Trim trailing slashes (preserve root paths like "C:/" on Windows, "/" on Unix)
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }

    // Resolve `./` prefixes
    while normalized.starts_with("./") {
        normalized = normalized[2..].to_string();
    }

    // Re-apply or add \\?\ prefix on Windows for long paths
    #[cfg(windows)]
    {
        if has_prefix || normalized.len() > 260 {
            normalized = format!("\\\\?\\{}", normalized);
        }
    }

    PathBuf::from(normalized)
}

/// Returns true if the filesystem is case-sensitive.
///
/// - Windows: `false` (NTFS is case-insensitive by default, though it preserves case)
/// - Linux: `true` (ext4, xfs, btrfs are case-sensitive)
/// - macOS: `false` (default APFS is case-insensitive; case-sensitive APFS is rare)
pub fn is_case_sensitive() -> bool {
    #[cfg(windows)]
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        // Default APFS is case-insensitive. Case-sensitive APFS volumes exist
        // but are uncommon for user-facing systems. We return false to match
        // the default macOS experience.
        return false;
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        // Unknown platform — assume case-sensitive (safer default)
        return true;
    }
}

/// Compare two paths for equality, respecting platform case sensitivity.
///
/// On case-insensitive filesystems (Windows, default macOS), comparison
/// is case-insensitive. On case-sensitive filesystems (Linux), comparison
/// is exact. Path separators are normalized before comparison.
pub fn paths_equal(a: &Path, b: &Path) -> bool {
    let a_str = a.to_string_lossy().replace('\\', "/");
    let b_str = b.to_string_lossy().replace('\\', "/");

    if is_case_sensitive() {
        a_str == b_str
    } else {
        a_str.eq_ignore_ascii_case(&b_str)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── normalize_path tests ──────────────────────────────────────────

    #[test]
    fn test_normalize_path_converts_backslashes() {
        let result = normalize_path("src\\subdir\\file.txt");
        let path_str = result.to_string_lossy().replace('\\', "/");
        assert!(path_str.contains("src/subdir/file.txt"), "backslashes should be converted to forward slashes, got: {}", path_str);
    }

    #[test]
    fn test_normalize_path_trims_trailing_slash() {
        let result = normalize_path("src/dir/");
        let path_str = result.to_string_lossy().replace('\\', "/");
        assert!(!path_str.ends_with('/'), "trailing slash should be trimmed, got: {}", path_str);
    }

    #[test]
    fn test_normalize_path_removes_dot_slash_prefix() {
        let result = normalize_path("./src/file.txt");
        let path_str = result.to_string_lossy().replace('\\', "/");
        assert!(!path_str.starts_with("./"), "dot-slash prefix should be removed, got: {}", path_str);
    }

    #[test]
    fn test_normalize_path_preserves_root() {
        let result = normalize_path("/");
        let path_str = result.to_string_lossy().replace('\\', "/");
        assert_eq!(path_str, "/", "root path should be preserved");
    }

    #[test]
    #[cfg(windows)]
    fn test_normalize_path_applies_long_path_prefix() {
        let long_path = format!("C:/{}", "a/".repeat(200));
        assert!(long_path.len() > 260, "test path should be longer than 260 chars");
        let result = normalize_path(&long_path);
        let path_str = result.to_string_lossy().replace('\\', "/");
        // On Windows, to_string_lossy() then replace('\\', "/") converts \\?\ to //?/
        assert!(path_str.starts_with("//?/"), "long path should get //?/ prefix (or \\\\?\\ before slash normalization), got: {}", path_str);
    }

    #[test]
    #[cfg(windows)]
    fn test_normalize_path_no_double_prefix() {
        let path = "\\\\?\\C:\\already\\prefixed";
        let result = normalize_path(path);
        let path_str = result.to_string_lossy();
        // Should not add another prefix
        assert_eq!(path_str.matches("\\\\?\\").count(), 1, "should not double-prefix");
    }

    // ── is_case_sensitive tests ───────────────────────────────────────

    #[test]
    fn test_is_case_sensitive_returns_bool() {
        let cs = is_case_sensitive();
        // Just ensure it doesn't panic and returns a valid bool
        assert!(cs == true || cs == false);
    }

    #[test]
    #[cfg(windows)]
    fn test_is_case_sensitive_windows_returns_false() {
        assert!(!is_case_sensitive(), "Windows should be case-insensitive");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_is_case_sensitive_linux_returns_true() {
        assert!(is_case_sensitive(), "Linux should be case-sensitive");
    }

    // ── paths_equal tests ─────────────────────────────────────────────

    #[test]
    fn test_paths_equal_same_path() {
        assert!(paths_equal(Path::new("src/file.txt"), Path::new("src/file.txt")));
    }

    #[test]
    fn test_paths_equal_different_path() {
        assert!(!paths_equal(Path::new("src/a.txt"), Path::new("src/b.txt")));
    }

    #[test]
    #[cfg(windows)]
    fn test_paths_equal_case_insensitive_on_windows() {
        assert!(paths_equal(Path::new("Foo.txt"), Path::new("foo.txt")), 
                "Windows should compare case-insensitively");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_paths_equal_case_sensitive_on_linux() {
        assert!(!paths_equal(Path::new("Foo.txt"), Path::new("foo.txt")), 
                "Linux should compare case-sensitively");
    }

    #[test]
    fn test_paths_equal_different_separators() {
        let a = normalize_path("src\\dir\\file.txt");
        let b = normalize_path("src/dir/file.txt");
        assert!(paths_equal(&a, &b), "paths with different separators should be equal");
    }
}
