//! Runtime FFI: `tallow.fs.*` operations for compiled programs.
//!
//! Mirrors `src/stdlib/fs.rs` semantics exactly — the interpreter raises a
//! runtime error where these return a negative code, and the emitted code turns
//! that into a message-bearing `exit(1)`.

use std::ffi::c_void;
use std::os::raw::c_char;

use super::browser::native_array;
use super::{cstr_to_str, set_last_error, string_to_cstr};

/// `fs.append_file(path, content)` -> `0` on success, `-1` on failure (with
/// `tallow_last_error` set).
///
/// Parent directories are created first, exactly as the interpreter does, and
/// the file is opened `create + append` so repeated calls concatenate.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_append_file(path: *const c_char, content: *const c_char) -> i32 {
    use std::io::Write;

    let (Some(path), Some(content)) = (unsafe { cstr_to_str(path) }, unsafe {
        cstr_to_str(content)
    }) else {
        set_last_error("expected string path as first argument".to_string());
        return -1;
    };

    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut file) => match file.write_all(content.as_bytes()) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(e.to_string());
                -1
            }
        },
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// `fs.remove_dir_all(path)` -> `0` on success, `-1` on failure (with
/// `tallow_last_error` set). A missing path is a failure, matching the
/// interpreter, which reports the `std::fs` error rather than defaulting.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_remove_dir_all(path: *const c_char) -> i32 {
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("expected string path argument".to_string());
        return -1;
    };
    match std::fs::remove_dir_all(path) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// `fs.read_lines(path)` -> native array of the file's lines, or null (with
/// `tallow_last_error` set) when the file cannot be read.
///
/// Splits on newlines exactly as the interpreter does (`src/stdlib/fs.rs`
/// `do_read_lines`): `str::lines()` already drops the trailing empty element that
/// a final newline would produce and handles CRLF, so there is no
/// post-processing. An unreadable file sets the error and returns null — the
/// emitted code turns that into a message-bearing `exit(1)` rather than an empty
/// array, matching the interpreter, which surfaces the `std::fs` error instead
/// of defaulting.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_read_lines(path: *const c_char) -> *mut c_void {
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("expected string path argument".to_string());
        return std::ptr::null_mut();
    };
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let slots: Vec<i64> = text
                .lines()
                .map(|line| string_to_cstr(line) as i64)
                .collect();
            native_array(slots)
        }
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// `FileCopy.copy_metadata(src, dst)` -> bytes copied (or -1 with
/// `tallow_last_error`), `out[0] = metadata_preserved`, `out[1] = mtime_preserved`.
///
/// Same steps as the interpreter's `copy_with_metadata`: kernel copy, then mtime
/// via `File::set_times`, then the source's permission bits. The flags report
/// what actually succeeded, so a caller can tell "copied" from "copied with
/// metadata" instead of assuming.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_filecopy_copy_metadata(
    src: *const c_char,
    dst: *const c_char,
    out: *mut i64,
) -> i64 {
    let (Some(src), Some(dst)) = (unsafe { cstr_to_str(src) }, unsafe { cstr_to_str(dst) }) else {
        set_last_error("copy_metadata: expected string paths".to_string());
        return -1;
    };
    let bytes = match std::fs::copy(src, dst) {
        Ok(b) => b as i64,
        Err(e) => {
            set_last_error(format!("copy failed: {e}"));
            return -1;
        }
    };
    let mut mtime_preserved = false;
    let mut perms_preserved = false;
    if let Ok(meta) = std::fs::metadata(src) {
        if let Ok(mtime) = meta.modified() {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(dst) {
                let times = std::fs::FileTimes::new().set_modified(mtime);
                if f.set_times(times).is_ok() {
                    mtime_preserved = true;
                }
            }
        }
        #[cfg(unix)]
        {
            if std::fs::set_permissions(dst, meta.permissions()).is_ok() {
                perms_preserved = true;
            }
        }
    }
    unsafe {
        *out.add(0) = i64::from(mtime_preserved || perms_preserved);
        *out.add(1) = i64::from(mtime_preserved);
    }
    bytes
}

/// `fs.stat(path)` -> fills `out[0..5] = [size, is_file, is_dir, modified, created]`
/// (epoch seconds; `created` falls back to `modified`, as the interpreter does)
/// and returns 0, or -1 with `tallow_last_error` set.
///
/// Slots rather than a struct pointer: the layout of `%struct.FileInfo` is the
/// code generator's business, so it allocates and fills the struct itself from
/// these plain integers.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_stat(path: *const c_char, out: *mut i64) -> i32 {
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("expected string path argument".to_string());
        return -1;
    };
    match std::fs::metadata(path) {
        Ok(md) => {
            let epoch_secs = |t: std::io::Result<std::time::SystemTime>| {
                t.ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            };
            let modified = epoch_secs(md.modified());
            let created = match md.created() {
                Ok(t) => t
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(modified),
                Err(_) => modified,
            };
            unsafe {
                *out.add(0) = md.len() as i64;
                *out.add(1) = i64::from(md.is_file());
                *out.add(2) = i64::from(md.is_dir());
                *out.add(3) = modified;
                *out.add(4) = created;
            }
            0
        }
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// `fs.list_dir(path)` -> a native array of entry NAMES (not full paths), or
/// null with `tallow_last_error` set.
///
/// Mirrors the interpreter exactly: `std::fs::read_dir`, `file_name()` per
/// entry, no sort, "." and ".." absent, error surfaces rather than an empty
/// array. Returning names (not joined paths) is what callers assume —
/// tallowx's walker does `rel + "/" + entry`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_list_dir(path: *const c_char) -> *mut c_void {
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("expected string path argument".to_string());
        return std::ptr::null_mut();
    };
    match std::fs::read_dir(path) {
        Ok(entries) => {
            let slots: Vec<i64> = entries
                .filter_map(|e| e.ok())
                .map(|e| string_to_cstr(&e.file_name().to_string_lossy()) as i64)
                .collect();
            native_array(slots)
        }
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// `fs.read_bytes(path)` -> the file's raw bytes **base64-encoded** as a string,
/// or null (with `tallow_last_error` set) when the file cannot be read.
///
/// `Bytes` is a base64 `String` at runtime — the convention `src/stdlib/fs.rs`
/// (`do_read_bytes`) and `tallow.compress` already use — so binary content
/// survives the `Value` boundary and no new native representation is needed.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_read_bytes(path: *const c_char) -> *mut c_char {
    use base64::Engine;

    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("expected string path argument".to_string());
        return std::ptr::null_mut();
    };
    match std::fs::read(path) {
        Ok(bytes) => string_to_cstr(&base64::engine::general_purpose::STANDARD.encode(&bytes)),
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// `fs.write_bytes(path, data)` -> `0` on success, `-1` on failure (with
/// `tallow_last_error` set).
///
/// `data` is base64 (the runtime `Bytes` convention). Parent directories are
/// created first, mirroring `fs.write_file` and the interpreter's
/// `do_write_bytes`. Invalid base64 is a failure, never a silent truncation.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_write_bytes(path: *const c_char, data: *const c_char) -> i32 {
    use base64::Engine;

    let (Some(path), Some(data)) = (unsafe { cstr_to_str(path) }, unsafe { cstr_to_str(data) })
    else {
        set_last_error("expected string path and base64 payload".to_string());
        return -1;
    };
    let bytes = match base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("invalid base64: {e}"));
            return -1;
        }
    };
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match std::fs::write(path, &bytes) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(e.to_string());
            -1
        }
    }
}

/// Copy `len` bytes of `src` from `offset` to the end of `dst` (created if
/// absent). Returns 0 on success, -1 on error with `tallow_last_error` set.
/// Mirrors the interpreter's `fs.copy_range`: a short read is an error, not a
/// silent partial append.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_copy_range(
    src: *const c_char,
    dst: *const c_char,
    offset: i64,
    len: i64,
) -> i32 {
    use std::io::{Read, Seek, SeekFrom, Write};

    let (Some(src), Some(dst)) = (unsafe { cstr_to_str(src) }, unsafe { cstr_to_str(dst) }) else {
        set_last_error("copy_range: expected string paths".to_string());
        return -1;
    };
    if offset < 0 || len < 0 {
        set_last_error(format!("copy_range: negative offset/len ({offset}, {len})"));
        return -1;
    }
    let mut f = match std::fs::File::open(src) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(format!("copy_range: cannot open '{src}': {e}"));
            return -1;
        }
    };
    if let Err(e) = f.seek(SeekFrom::Start(offset as u64)) {
        set_last_error(format!("copy_range: cannot seek '{src}' to {offset}: {e}"));
        return -1;
    }
    let mut out = match std::fs::OpenOptions::new().create(true).append(true).open(dst) {
        Ok(o) => o,
        Err(e) => {
            set_last_error(format!("copy_range: cannot open '{dst}' for append: {e}"));
            return -1;
        }
    };
    let mut remaining = len as u64;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let want = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = match f.read(&mut buf[..want]) {
            Ok(0) => {
                set_last_error(format!(
                    "copy_range: short read on '{src}' at offset {} (wanted {remaining} more bytes)",
                    offset + (len as u64 - remaining) as i64
                ));
                return -1;
            }
            Ok(n) => n,
            Err(e) => {
                set_last_error(format!("copy_range: read error on '{src}': {e}"));
                return -1;
            }
        };
        if let Err(e) = out.write_all(&buf[..n]) {
            set_last_error(format!("copy_range: write error on '{dst}': {e}"));
            return -1;
        }
        remaining -= n as u64;
    }
    // Carry the source's mtime, as the interpreter does: a resumed file must not
    // look newer than its source or the next run re-copies it.
    if let Ok(meta) = std::fs::metadata(src) {
        if let Ok(modified) = meta.modified() {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(dst) {
                let _ = f.set_times(std::fs::FileTimes::new().set_modified(modified));
            }
        }
    }
    0
}

/// `fs.set_mtime(path, epoch_secs)` — 0 on success, -1 with
/// `tallow_last_error` set. A resumed copy needs this: `copy_range` writes
/// bytes only, so the mtime has to be restored explicitly or the next run
/// re-copies a file it already has.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_fs_set_mtime(path: *const c_char, secs: i64) -> i32 {
    let Some(p) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("set_mtime: null path".to_string());
        return -1;
    };
    if secs < 0 {
        set_last_error(format!("set_mtime: negative timestamp {secs}"));
        return -1;
    }
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64);
    let f = match std::fs::OpenOptions::new().write(true).open(p) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(format!("set_mtime: cannot open '{p}': {e}"));
            return -1;
        }
    };
    match f.set_times(std::fs::FileTimes::new().set_modified(t)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!("set_mtime: cannot set mtime on '{p}': {e}"));
            -1
        }
    }
}

// ── `Bytes` value surface (t_70cad4f2) ──────────────────────────────────────
//
// A `Bytes` value crosses the **compiled value ABI** as the base64 text
// `tallow_fs_read_bytes` returns: that ABI is a NUL-terminated `ptr`, so raw
// bytes (which may contain `\0`) have no representation of their own without a
// new ABI. These helpers give the compiled backend the *language surface* the
// interpreter's `Value::Bytes(Vec<u8>)` has, so `.len`, `.hex()` and
// `provenance.hash_bytes(b)` answer about the DECODED bytes instead of the
// encoded text — `b.len` used to report the base64 length (16 raw bytes read as
// 24) while the interpreter reported 16.
//
// Every helper is fail-closed: a value that is not valid base64 cannot be a
// `Bytes`, so each returns its failure sentinel (`-1` / null) with
// `tallow_last_error` set — never a plausible number or string. The emitted
// code turns the sentinel into a message-bearing `exit(1)`.

/// Decode the base64 text a `Bytes` value carries. Shared by the surface
/// helpers so they agree on what "not a Bytes" means.
fn decode_bytes(data: *const c_char) -> Result<Vec<u8>, String> {
    use base64::Engine;

    let Some(text) = (unsafe { cstr_to_str(data) }) else {
        return Err("expected a base64 Bytes value".to_string());
    };
    base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map_err(|e| format!("invalid base64: {e}"))
}

/// `s[i]` on a String -> a one-character String (a fresh C string), or null
/// (with `tallow_last_error` set) when the index is past the character count.
///
/// Strings and native arrays share the `i8*` type, so the index lowering used
/// to treat every `i8*` as a length-prefixed array. Indexing is by Unicode
/// scalar (the interpreter's `s.chars().nth(i)`), not by UTF-8 byte: `"αβ"[0]`
/// is `α`, and an out-of-range index is a runtime error with the same sentence
/// the tree-walker prints (`index N out of bounds`). Codegen aborts on the
/// null via `tallow_check_string`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_string_index(s: *const c_char, idx: i64) -> *mut c_char {
    let Some(text) = (unsafe { cstr_to_str(s) }) else {
        set_last_error("expected a string to index".to_string());
        return std::ptr::null_mut();
    };
    if idx < 0 {
        set_last_error(format!("index {idx} out of bounds"));
        return std::ptr::null_mut();
    }
    let i = idx as usize;
    match text.chars().nth(i) {
        Some(c) => string_to_cstr(&c.to_string()),
        None => {
            set_last_error(format!("index {i} out of bounds"));
            std::ptr::null_mut()
        }
    }
}

/// `Bytes.len` -> the **decoded** byte count, or `-1` (with `tallow_last_error`
/// set) when the value is not base64. `strlen` on the same pointer would report
/// the encoded length — the divergence this closes.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_bytes_len(data: *const c_char) -> i64 {
    match decode_bytes(data) {
        Ok(bytes) => bytes.len() as i64,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

/// `Bytes.hex()` -> lowercase hex of the decoded bytes, or null (with
/// `tallow_last_error` set). One formatter for both engines: the interpreter's
/// `hex()` is `format!("{byte:02x}")` per byte.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_bytes_hex(data: *const c_char) -> *mut c_char {
    match decode_bytes(data) {
        Ok(bytes) => {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            string_to_cstr(&hex)
        }
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// `provenance.hash_bytes(b)` -> sha256 hex digest of the decoded bytes, or null
/// (with `tallow_last_error` set). Calls the interpreter's own
/// `provenance::hash_bytes`, so the digest is identical by construction rather
/// than by a re-implementation that could drift (G-14: a `Bytes` is never
/// fingerprinted through its encoded form).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_bytes_sha256(data: *const c_char) -> *mut c_char {
    match decode_bytes(data) {
        Ok(bytes) => string_to_cstr(&crate::stdlib::provenance::hash_bytes(&bytes)),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn append_file_creates_parents_and_appends() {
        let dir = std::env::temp_dir().join(format!("tallow-fs-ffi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested/deep/out.txt");
        let ps = c(path.to_str().unwrap());

        assert_eq!(tallow_fs_append_file(ps.as_ptr(), c("alpha").as_ptr()), 0);
        assert_eq!(tallow_fs_append_file(ps.as_ptr(), c("beta").as_ptr()), 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "alphabeta");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_dir_all_reports_missing_path_as_failure() {
        let missing = c("/nonexistent-tallow-fs-ffi-probe/deep");
        assert_eq!(tallow_fs_remove_dir_all(missing.as_ptr()), -1);
    }

    #[test]
    fn remove_dir_all_removes_a_populated_tree() {
        let dir = std::env::temp_dir().join(format!("tallow-fs-ffi-rm-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/f.txt"), "x").unwrap();
        let ps = c(dir.to_str().unwrap());

        assert_eq!(tallow_fs_remove_dir_all(ps.as_ptr()), 0);
        assert!(!dir.exists());
    }

    #[test]
    fn read_lines_splits_on_newlines_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("tallow-fs-ffi-lines-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lines.txt");
        // A trailing newline must not add a final empty element (the
        // interpreter's `str::lines()` drops it).
        std::fs::write(&path, "alpha\nbeta\ngamma\n").unwrap();
        let ps = c(path.to_str().unwrap());

        let arr = tallow_fs_read_lines(ps.as_ptr());
        assert!(!arr.is_null());
        unsafe {
            assert_eq!(*(arr as *const i64), 3, "3 lines, no trailing empty");
            let elem = |i: usize| {
                let s = *((arr as *const i64).add(i + 1)) as *const c_char;
                std::ffi::CStr::from_ptr(s).to_str().unwrap().to_string()
            };
            assert_eq!(elem(0), "alpha");
            assert_eq!(elem(2), "gamma");
        }

        // A missing file is a failure, never an empty array.
        let missing = c("/nonexistent-tallow-fs-ffi-lines/none.txt");
        assert!(tallow_fs_read_lines(missing.as_ptr()).is_null());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_write_bytes_round_trip_is_base64() {
        let dir = std::env::temp_dir().join(format!("tallow-fs-ffi-bytes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob.bin");
        let ps = c(path.to_str().unwrap());

        // 0x00 0x01 0xfe 0xff is not valid UTF-8, which pins the binary path:
        // a text round-trip would pass this by accident.
        let payload: &[u8] = &[0u8, 1, 0xfe, 0xff];
        let b64 = "AAH+/w==";
        assert_eq!(tallow_fs_write_bytes(ps.as_ptr(), c(b64).as_ptr()), 0);
        assert_eq!(std::fs::read(&path).unwrap(), payload);

        let out = tallow_fs_read_bytes(ps.as_ptr());
        assert!(!out.is_null());
        let got = unsafe { std::ffi::CStr::from_ptr(out).to_str().unwrap() };
        assert_eq!(got, b64);

        // Invalid base64 is a refusal, never a silent empty write.
        assert_eq!(
            tallow_fs_write_bytes(ps.as_ptr(), c("!!!not-base64!!!").as_ptr()),
            -1
        );
        // A missing file is null, never an empty string.
        let missing = c("/nonexistent-tallow-fs-ffi-bytes/x");
        assert!(tallow_fs_read_bytes(missing.as_ptr()).is_null());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// t_70cad4f2: the `Bytes` surface answers about the DECODED bytes — the
    /// same answers the interpreter's `Value::Bytes(Vec<u8>)` gives — and fails
    /// closed when the value is not base64 (never a plausible number/string).
    #[test]
    fn bytes_surface_reads_the_decoded_form_and_fails_closed() {
        // The card's fixture: 16 raw bytes, base64 24 chars, not valid UTF-8.
        let b64 = c("YmluYXJ5AHBheWxvYWT//g==");
        assert_eq!(tallow_bytes_len(b64.as_ptr()), 16, "raw byte count, not 24");

        let hex = tallow_bytes_hex(b64.as_ptr());
        assert!(!hex.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(hex).to_str().unwrap() },
            "62696e617279007061796c6f6164fffe"
        );

        let digest = tallow_bytes_sha256(b64.as_ptr());
        assert!(!digest.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(digest).to_str().unwrap() },
            "274d198c0ff7f261224e0b8d53c5fd7de6dc4041c320819772b71028fd187fdc",
            "true sha256 of the raw bytes (== sha256sum payload.bin)"
        );

        // An empty payload is 0 bytes, not a failure.
        assert_eq!(tallow_bytes_len(c("").as_ptr()), 0);

        // Not base64 at all: every helper refuses rather than answering.
        let bad = c("!!!not-base64!!!");
        assert_eq!(tallow_bytes_len(bad.as_ptr()), -1);
        assert!(tallow_bytes_hex(bad.as_ptr()).is_null());
        assert!(tallow_bytes_sha256(bad.as_ptr()).is_null());
        // A null pointer (no Bytes value at all) is a refusal too.
        assert_eq!(tallow_bytes_len(std::ptr::null()), -1);
    }
}
