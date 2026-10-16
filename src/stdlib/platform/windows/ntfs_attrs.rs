//! NTFS-specific filesystem attribute preservation.
//!
//! Handles Alternate Data Streams (ADS), ACL security descriptors,
//! junctions/reparse-points, and sparse file reconstruction.
//!
//! All functions operate best-effort — failures are reported as
//! warnings by the caller rather than aborting the copy operation.

use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFirstStreamW, FindNextStreamW, FlushFileBuffers,
    GetFileAttributesW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, WIN32_FIND_STREAM_DATA,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

// FSCTL control codes (defined inline to avoid module-location issues across windows-sys versions)
const FSCTL_SET_SPARSE: u32 = 0x000900C4;
const FSCTL_GET_REPARSE_POINT: u32 = 0x000900A8;
const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;

// GENERIC_WRITE
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;

// ── Wide-string helpers ────────────────────────────────────────────────

/// Convert a Path to a null-terminated UTF-16 wide string.
fn to_wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

// ── ADS: Alternate Data Streams ────────────────────────────────────────

/// Copy all alternate data streams from source to destination.
///
/// Enumerates ADS on `src` via FindFirstStreamW/FindNextStreamW,
/// reads each stream's contents, and writes them to `dst`.
/// Returns the number of streams successfully copied.
///
/// The default "::$DATA" stream is excluded (it represents
/// the main file content, already copied).
pub fn copy_alternate_data_streams(src: &Path, dst: &Path) -> Result<usize, String> {
    let src_wide = to_wide_path(src);

    let mut stream_data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };

    let find_handle = unsafe {
        FindFirstStreamW(
            src_wide.as_ptr(),
            0, // FindStreamInfoStandard
            &mut stream_data as *mut WIN32_FIND_STREAM_DATA as *mut _,
            0,
        )
    };

    if find_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        // ERROR_HANDLE_EOF (38) — no streams at all
        if err == 38 {
            return Ok(0);
        }
        return Err(format!("FindFirstStreamW failed: error {}", err));
    }

    let mut count: usize = 0;

    // Process all streams
    loop {
        // Extract stream name from cStreamName (null-terminated wide string)
        let stream_name = extract_stream_name(&stream_data);

        // Skip the default data stream and empty names
        // After stripping :$DATA, the default stream name is ":"
        if !stream_name.is_empty() && stream_name != ":" {
            // Build source ADS path and destination ADS path
            let stream_suffix = stream_name.trim_start_matches(':');
            let src_ads = format!("{}:{}", src.display(), stream_suffix);
            let dst_ads = format!("{}:{}", dst.display(), stream_suffix);

            // Read ADS contents
            match read_ads_raw(&src_ads) {
                Ok(contents) => {
                    // Write to destination ADS
                    match write_ads_raw(&dst_ads, &contents) {
                        Ok(()) => {
                            count += 1;
                        }
                        Err(e) => eprintln!("tallow: ADS write warning: {}", e),
                    }
                }
                Err(e) => eprintln!("tallow: ADS read warning: {}", e),
            }
        }

        // Next stream
        let more = unsafe {
            FindNextStreamW(find_handle, &mut stream_data as *mut _ as *mut _)
        };
        if more == 0 {
            break;
        }
    }

    unsafe {
        FindClose(find_handle);
    }

    Ok(count)
}

/// Extract stream name from WIN32_FIND_STREAM_DATA as a Rust String.
/// Strips the trailing `:$DATA` type suffix from stream names.
fn extract_stream_name(data: &WIN32_FIND_STREAM_DATA) -> String {
    let name_ptr = data.cStreamName.as_ptr();
    let len = (0usize..).take_while(|&i| unsafe { *name_ptr.add(i) != 0 }).count();
    if len == 0 {
        return String::new();
    }
    let raw = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(name_ptr, len)) };
    // Strip trailing :$DATA stream type suffix (the name portion is what we need)
    raw.trim_end_matches(":$DATA").to_string()
}

/// Read raw ADS contents via standard file I/O (supports ADS paths on Windows).
fn read_ads_raw(ads_path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(ads_path)
        .map_err(|e| format!("ADS read: cannot read '{}': {}", ads_path, e))
}

/// Write raw data to an ADS.
fn write_ads_raw(ads_path: &str, data: &[u8]) -> Result<(), String> {
    // Ensure the base file exists (required before writing an ADS to it)
    if let Some(colon_pos) = ads_path.rfind(':') {
        let base_path = &ads_path[..colon_pos];
        if !Path::new(base_path).exists() {
            std::fs::write(base_path, b"")
                .map_err(|e| format!("ADS write: cannot create base file '{}': {}", base_path, e))?;
        }
    }

    // Use Rust's standard file I/O which handles ADS paths correctly on Windows
    let mut f = std::fs::File::create(ads_path)
        .map_err(|e| format!("ADS write: cannot create '{}': {}", ads_path, e))?;
    std::io::Write::write_all(&mut f, data)
        .map_err(|e| format!("ADS write: write error for '{}': {}", ads_path, e))?;
    f.flush()
        .map_err(|e| format!("ADS write: flush error for '{}': {}", ads_path, e))?;

    Ok(())
}

// ── ACL: Security descriptors ──────────────────────────────────────────

/// Preserve the NTFS security descriptor (DACL) from source to destination.
///
/// Uses GetFileSecurityW to read the source ACL and SetFileSecurityW
/// to apply it to the destination. Best-effort — some locations
/// (e.g., network shares, certain system directories) may deny
/// ACL read or write.
pub fn preserve_acl(src: &Path, dst: &Path) -> Result<(), String> {
    let src_wide = to_wide_path(src);
    let dst_wide = to_wide_path(dst);

    // First, determine the required buffer size
    let mut needed = 0u32;
    unsafe {
        GetFileSecurityW(
            src_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };

    // ok == 0 with needed > 0 is expected (buffer too small)
    // If needed is still 0, there's no security descriptor
    if needed == 0 {
        return Ok(());
    }

    // Allocate buffer and retrieve security descriptor
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetFileSecurityW(
            src_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        )
    };

    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("GetFileSecurityW failed: error {}", err));
    }

    // Apply to destination
    let ok = unsafe {
        SetFileSecurityW(
            dst_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            buf.as_mut_ptr() as *mut _,
        )
    };

    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("SetFileSecurityW failed: error {}", err));
    }

    Ok(())
}

// ── Junctions / Reparse points ─────────────────────────────────────────

/// Check whether a path is a junction or reparse point.
///
/// Uses GetFileAttributesW to look for FILE_ATTRIBUTE_REPARSE_POINT.
/// Returns true for directory junctions (IO_REPARSE_TAG_MOUNT_POINT),
/// symbolic links, and other reparse points.
pub fn is_junction_or_reparse(path: &Path) -> bool {
    let wide = to_wide_path(path);
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == 0xFFFFFFFF {
        return false;
    }
    (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

/// Recreate a junction or reparse point at the destination.
///
/// Reads the reparse data from `src` via DeviceIoControl with
/// FSCTL_GET_REPARSE_POINT, then creates the reparse point at
/// `dst` via FSCTL_SET_REPARSE_POINT. The caller should verify
/// with `is_junction_or_reparse()` before calling.
pub fn recreate_junction(src: &Path, dst: &Path) -> Result<(), String> {
    let src_wide = to_wide_path(src);

    // Open source with reparse point and backup semantics
    let src_handle = unsafe {
        CreateFileW(
            src_wide.as_ptr(),
            0, // no read/write needed
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };

    if src_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "CreateFileW(junction src) failed: error {}",
            err
        ));
    }

    // Allocate buffer for reparse data (16KB should be sufficient)
    let mut buf = vec![0u8; 16384];
    let mut bytes_returned = 0u32;

    let ok = unsafe {
        DeviceIoControl(
            src_handle,
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    unsafe {
        CloseHandle(src_handle);
    }

    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!(
            "DeviceIoControl(GET_REPARSE_POINT) failed: error {}",
            err
        ));
    }

    let reparse_data_len = bytes_returned as usize;
    if reparse_data_len == 0 || reparse_data_len > buf.len() {
        return Err("reparse point has no data".to_string());
    }

    // Now create the reparse point at destination
    let dst_wide = to_wide_path(dst);

    // Ensure parent directory exists
    if let Some(parent) = dst.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create parent dir: {}", e))?;
        }
    }

    // Create the destination directory/file first (reparse points are set on existing entries)
    if src.is_dir() {
        if !dst.exists() {
            std::fs::create_dir(dst)
                .map_err(|e| format!("failed to create junction dir: {}", e))?;
        }
    } else {
        std::fs::write(dst, b"").map_err(|e| format!("failed to create junction file: {}", e))?;
    }

    let dst_handle = unsafe {
        CreateFileW(
            dst_wide.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };

    if dst_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        // Clean up the stub on failure
        let _ = std::fs::remove_file(dst);
        let _ = std::fs::remove_dir(dst);
        return Err(format!(
            "CreateFileW(junction dst) failed: error {}",
            err
        ));
    }

    let ok = unsafe {
        DeviceIoControl(
            dst_handle,
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr() as *const _,
            reparse_data_len as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    unsafe {
        CloseHandle(dst_handle);
    }

    if ok == 0 {
        let err = unsafe { GetLastError() };
        // Clean up the stub file on failure
        let _ = std::fs::remove_file(dst);
        let _ = std::fs::remove_dir(dst);
        return Err(format!(
            "DeviceIoControl(SET_REPARSE_POINT) failed: error {}",
            err
        ));
    }

    Ok(())
}

// ── Sparse files ───────────────────────────────────────────────────────

/// Check whether a file is a sparse file.
///
/// Uses GetFileAttributesW to check for FILE_ATTRIBUTE_SPARSE_FILE.
pub fn is_sparse_file(path: &Path) -> bool {
    let wide = to_wide_path(path);
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == 0xFFFFFFFF {
        return false;
    }
    (attrs & FILE_ATTRIBUTE_SPARSE_FILE) != 0
}

/// Mark a file as sparse on the destination.
///
/// Uses DeviceIoControl with FSCTL_SET_SPARSE to set the sparse
/// attribute. Typically called after copying a file that was
/// detected as sparse at the source via `is_sparse_file()`.
pub fn recreate_as_sparse(path: &Path) -> Result<(), String> {
    let wide = to_wide_path(path);

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(format!("CreateFileW(sparse) failed: error {}", err));
    }

    let mut bytes_returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    // Flush the change and close
    unsafe {
        FlushFileBuffers(handle);
        CloseHandle(handle);
    }

    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("FSCTL_SET_SPARSE failed: error {}", err));
    }

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    /// Helper: create an ADS on a file by writing to `path:stream_name`.
    fn create_ads(file_path: &Path, stream_name: &str, data: &[u8]) {
        let ads_path = format!("{}:{}", file_path.display(), stream_name);
        let mut f = std::fs::File::create(&ads_path).expect("should create ADS stream");
        f.write_all(data).expect("should write ADS data");
        f.flush().expect("should flush ADS");
    }

    /// Helper: read an ADS from a file.
    fn read_ads(file_path: &Path, stream_name: &str) -> Option<Vec<u8>> {
        let ads_path = format!("{}:{}", file_path.display(), stream_name);
        std::fs::read(&ads_path).ok()
    }

    // ── ADS tests ──────────────────────────────────────────────────────

    #[test]
    fn test_copy_ads_streams_copies_data() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("ads_src.txt");
        let dst = tmp.path().join("ads_dst.txt");

        // Create source file first
        std::fs::write(&src, b"main file content").unwrap();
        // ADS streams
        create_ads(&src, "secret", b"hidden data here");
        create_ads(&src, "metadata", b"extra metadata");

        let count = copy_alternate_data_streams(&src, &dst).unwrap();
        assert!(
            count >= 1,
            "should copy at least 1 ADS stream (got {})",
            count
        );

        // Verify at least one ADS on destination
        let secret_data = read_ads(&dst, "secret");
        assert!(
            secret_data.is_some(),
            "destination should have 'secret' ADS"
        );
        assert_eq!(secret_data.unwrap(), b"hidden data here");
    }

    #[test]
    fn test_copy_ads_returns_zero_for_no_streams() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("plain.txt");
        let dst = tmp.path().join("plain_copy.txt");
        std::fs::write(&src, b"no streams here").unwrap();

        let count = copy_alternate_data_streams(&src, &dst).unwrap();
        assert_eq!(count, 0, "should return 0 for files with no ADS");
    }

    // ── ACL tests ──────────────────────────────────────────────────────

    #[test]
    fn test_preserve_acl_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("acl_src.txt");
        let dst = tmp.path().join("acl_dst.txt");
        std::fs::write(&src, b"acl test").unwrap();
        std::fs::write(&dst, b"acl dest").unwrap();

        let result = preserve_acl(&src, &dst);
        assert!(
            result.is_ok(),
            "ACL preservation should succeed on temp dir: {:?}",
            result.err()
        );
    }

    // ── Junction / reparse tests ───────────────────────────────────────

    #[test]
    fn test_is_junction_returns_false_for_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("regular.txt");
        std::fs::write(&f, b"regular").unwrap();

        assert!(
            !is_junction_or_reparse(&f),
            "regular file is not a junction"
        );
    }

    #[test]
    fn test_is_junction_returns_false_for_regular_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("regular_dir");
        std::fs::create_dir(&d).unwrap();

        assert!(
            !is_junction_or_reparse(&d),
            "regular directory is not a junction"
        );
    }

    // ── Sparse file tests ──────────────────────────────────────────────

    #[test]
    fn test_is_sparse_file_returns_false_for_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("dense.txt");
        std::fs::write(&f, b"not sparse").unwrap();

        assert!(
            !is_sparse_file(&f),
            "regular file should not be detected as sparse"
        );
    }

    #[test]
    fn test_create_sparse_file_and_detect() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("sparse_test.bin");

        // Create an empty file and mark it sparse
        std::fs::write(&f, b"").unwrap();
        recreate_as_sparse(&f).unwrap();

        assert!(is_sparse_file(&f), "should detect sparse file after marking");
    }

    #[test]
    fn test_recreate_as_sparse_on_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("make_sparse.bin");
        std::fs::write(&f, vec![0u8; 1024]).unwrap();

        let result = recreate_as_sparse(&f);
        assert!(result.is_ok(), "should succeed in making file sparse");

        assert!(is_sparse_file(&f), "file should now be sparse");
    }
}
