//! Unix extended attribute (xattr) and symlink preservation.
//!
//! Copies user-space extended attributes and recreates symbolic
//! links at the destination without following them.

use std::path::Path;

/// Copy all extended attributes from source to destination.
///
/// Enumerates xattrs on `src` using the `xattr` crate, reads each
/// attribute value, and writes it to `dst`. Security-sensitive
/// attributes (e.g., `security.selinux`) may fail to copy — these
/// are skipped with a log message rather than aborting.
///
/// Returns the number of attributes successfully copied.
pub fn copy_xattrs(src: &Path, dst: &Path) -> Result<usize, String> {
    let attrs = xattr::list(src).map_err(|e| format!("xattr list failed: {}", e))?;

    let mut count: usize = 0;

    let attr_list: Vec<_> = attrs.into_iter().collect();
    for attr in &attr_list {
        // Read the attribute value
        let value = match xattr::get(src, attr) {
            Ok(Some(v)) => v,
            Ok(None) => continue, // attribute disappeared? skip
            Err(e) => {
                eprintln!(
                    "tallow: xattr read warning for '{}': attr={}: {}",
                    src.display(),
                    attr.to_string_lossy(),
                    e
                );
                continue;
            }
        };

        // Write to destination
        match xattr::set(dst, attr, &value) {
            Ok(()) => {
                count += 1;
            }
            Err(e) => {
                eprintln!(
                    "tallow: xattr write warning for '{}': attr={}: {}",
                    dst.display(),
                    attr.to_string_lossy(),
                    e
                );
            }
        }
    }

    Ok(count)
}

/// Preserve a symbolic link by re-creating it at the destination.
///
/// Reads the symlink target from `src` via `std::fs::read_link()`
/// and creates an equivalent symlink at `dst` via
/// `std::os::unix::fs::symlink()`. If `dst` already exists, it is
/// removed first.
///
/// Returns an error if `src` is not a symlink or if symlink
/// creation fails.
pub fn preserve_symlink(src: &Path, dst: &Path) -> Result<(), String> {
    // Verify source is a symlink
    let meta = std::fs::symlink_metadata(src)
        .map_err(|e| format!("preserve_symlink: cannot stat '{}': {}", src.display(), e))?;

    if !meta.file_type().is_symlink() {
        return Err(format!(
            "preserve_symlink: '{}' is not a symlink",
            src.display()
        ));
    }

    // Read the symlink target
    let target = std::fs::read_link(src)
        .map_err(|e| format!("preserve_symlink: cannot read link '{}': {}", src.display(), e))?;

    // Remove destination if it exists
    if dst.exists() {
        if dst.is_symlink() || dst.is_file() {
            std::fs::remove_file(dst)
                .map_err(|e| format!("preserve_symlink: cannot remove '{}': {}", dst.display(), e))?;
        } else if dst.is_dir() {
            std::fs::remove_dir_all(dst).map_err(|e| {
                format!(
                    "preserve_symlink: cannot remove dir '{}': {}",
                    dst.display(),
                    e
                )
            })?;
        }
    }

    // Create the symlink at destination
    std::os::unix::fs::symlink(&target, dst).map_err(|e| {
        format!(
            "preserve_symlink: cannot create symlink '{}' -> '{}': {}",
            dst.display(),
            target.display(),
            e
        )
    })?;

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    // ── xattr tests ────────────────────────────────────────────────────

    #[test]
    fn test_copy_xattrs_copies_attributes() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("xattr_src.txt");
        let dst = tmp.path().join("xattr_dst.txt");

        std::fs::write(&src, b"xattr test file").unwrap();
        std::fs::write(&dst, b"").unwrap();

        // Set an xattr on the source
        xattr::set(&src, "user.comment", b"test attribute value").unwrap();

        let count = copy_xattrs(&src, &dst).unwrap();
        assert_eq!(count, 1, "should copy 1 xattr");

        // Verify xattr on destination
        let value = xattr::get(&dst, "user.comment").unwrap().unwrap();
        assert_eq!(value.as_slice(), b"test attribute value");
    }

    #[test]
    fn test_copy_xattrs_returns_zero_for_no_xattrs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("no_xattr.txt");
        let dst = tmp.path().join("no_xattr_copy.txt");

        std::fs::write(&src, b"plain file, no xattrs").unwrap();
        std::fs::write(&dst, b"").unwrap();

        let count = copy_xattrs(&src, &dst).unwrap();
        assert_eq!(count, 0, "should return 0 for files with no xattrs");
    }

    #[test]
    fn test_copy_xattrs_skips_security_attrs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("security_test.txt");
        let dst = tmp.path().join("security_test_copy.txt");

        std::fs::write(&src, b"security xattr test").unwrap();
        std::fs::write(&dst, b"").unwrap();

        // Try setting a selinux attr — this may fail on non-SELinux systems,
        // which is fine; the test verifies graceful handling.
        let _ = xattr::set(&src, "security.test.x", b"fake selinux data");

        // Should not crash, even if some attrs fail to copy
        let result = copy_xattrs(&src, &dst);
        assert!(
            result.is_ok(),
            "copy_xattrs should not crash on security attrs"
        );
    }

    // ── Symlink tests ──────────────────────────────────────────────────

    #[test]
    fn test_preserve_symlink_recreates_link() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target_file.txt");
        let link_src = tmp.path().join("link_src");
        let link_dst = tmp.path().join("link_dst");

        std::fs::write(&target, b"symlink target content").unwrap();
        symlink(&target, &link_src).unwrap();

        preserve_symlink(&link_src, &link_dst).unwrap();

        assert!(link_dst.is_symlink(), "destination should be a symlink");

        let resolved = std::fs::read_link(&link_dst).unwrap();
        // The stored symlink target should point to the same path
        assert_eq!(
            resolved, target,
            "symlink should point to same target"
        );
    }

    #[test]
    fn test_preserve_symlink_errors_on_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("regular.txt");
        let dst = tmp.path().join("attempted_link");

        std::fs::write(&src, b"not a symlink").unwrap();

        let result = preserve_symlink(&src, &dst);
        assert!(
            result.is_err(),
            "should error when source is not a symlink"
        );
    }
}
