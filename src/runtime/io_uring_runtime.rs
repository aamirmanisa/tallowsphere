//! io_uring runtime wrapper with tokio fallback.
//!
//! Provides an abstraction layer for asynchronous file I/O that can be
//! backed by io_uring on supported Linux kernels, falling back to tokio's
//! standard async I/O on other platforms. On Linux with the
//! `io-uring-backend` feature enabled and kernel >= 5.6, file reads and
//! writes use real io_uring submission/completion queues via
//! `IORING_OP_READ` / `IORING_OP_WRITE`. All other platforms fall back to
//! tokio's standard async I/O.
//!
//! Qualifiers (W2-12, cycle-02/06 §3.4 — descope + label; no default-enable):
//! opt-in EXPERIMENTAL file-I/O backend — single-operation submit, file I/O
//! only, NOT the network path (fetch stays ureq/tokio). Never default-enabled:
//! default builds use the tokio/std path. Post-V1 spike gate before any
//! default flip: multi-op batch + copy-engine routing must show >=1.5x on the
//! 80K-small-file copy class vs the std path — spec filed at
//! research/tallow-v1/exec/W2-12-io-uring-spike-spec.md.

use std::path::Path;

// ---------------------------------------------------------------------------
// Real io_uring implementation (Linux + feature gate)
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
mod uring_impl {
    use io_uring::{IoUring, opcode, types};
    use std::os::unix::io::AsRawFd;

    /// Read an entire file using a single io_uring `Read` submission.
    pub fn uring_read_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let fd = types::Fd(file.as_raw_fd());
        let file_size = file
            .metadata()
            .map_err(|e| format!("metadata: {e}"))?
            .len() as usize;

        let mut buf = vec![0u8; file_size];
        let mut ring =
            IoUring::new(8).map_err(|e| format!("io_uring::new: {e}"))?;

        let read_e = opcode::Read::new(fd, buf.as_mut_ptr(), buf.len() as _)
            .build()
            .user_data(0x42);

        unsafe { ring.submission().push(&read_e) }
            .map_err(|e| format!("submission: {e}"))?;
        ring.submit_and_wait(1)
            .map_err(|e| format!("submit: {e}"))?;

        let cqe = ring.completion().next().ok_or("no completion event")?;
        let bytes_read = cqe.result();
        if bytes_read < 0 {
            return Err(format!("read error: {}", -bytes_read));
        }
        buf.truncate(bytes_read as usize);
        Ok(buf)
    }

    /// Write data to a file using a single io_uring `Write` submission.
    ///
    /// Creates or truncates the target file before submitting the write.
    pub fn uring_write_file(
        path: &std::path::Path,
        data: &[u8],
    ) -> Result<(), String> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let fd = types::Fd(file.as_raw_fd());

        let mut ring =
            IoUring::new(8).map_err(|e| format!("io_uring::new: {e}"))?;

        let write_e =
            opcode::Write::new(fd, data.as_ptr(), data.len() as _)
                .build()
                .user_data(0x43);

        unsafe { ring.submission().push(&write_e) }
            .map_err(|e| format!("submission: {e}"))?;
        ring.submit_and_wait(1)
            .map_err(|e| format!("submit: {e}"))?;

        let cqe = ring.completion().next().ok_or("no completion event")?;
        let bytes_written = cqe.result();
        if bytes_written < 0 {
            return Err(format!("write error: {}", -bytes_written));
        }
        if (bytes_written as usize) != data.len() {
            return Err(format!(
                "short write: wrote {} of {} bytes",
                bytes_written,
                data.len()
            ));
        }
        Ok(())
    }
}

/// Check whether io_uring is available on the current platform.
///
/// Returns `true` on Linux with the `io-uring-backend` feature enabled and
/// a kernel version >= 5.6. Returns `false` on all other platforms.
pub fn is_available() -> bool {
    #[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
    {
        if let Some(available) = check_kernel_version() {
            return available;
        }
    }
    false
}

/// Parse kernel version from `uname -r` output and check >= 5.6.
#[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
fn check_kernel_version() -> Option<bool> {
    let output = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()?;
    let release = String::from_utf8_lossy(&output.stdout);
    let version_str = release.trim();
    // Kernel release looks like "5.15.0-generic" — take major.minor
    let mut parts = version_str.split(|c: char| !c.is_ascii_digit());
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some(major > 5 || (major == 5 && minor >= 6))
}

/// Returns the name of the active I/O backend.
///
/// Returns `"io_uring"` if io_uring is available on this system,
/// otherwise returns `"epoll"`.
pub fn backend_name() -> &'static str {
    if is_available() {
        "io_uring"
    } else {
        "epoll"
    }
}

/// Read the entire contents of a file asynchronously.
///
/// On Linux with `io-uring-backend`, uses a real io_uring `IORING_OP_READ`
/// submission (run on a blocking thread to avoid starving the tokio
/// executor). Falls back to `tokio::fs::read` on other platforms.
pub async fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
    if is_available() {
        return tokio::task::spawn_blocking({
            let path = path.to_owned();
            move || uring_impl::uring_read_file(&path)
        })
        .await
        .map_err(|e| format!("spawn: {e}"))?;
    }

    // Fallback to tokio
    tokio::fs::read(path)
        .await
        .map_err(|e| format!("read {}: {e}", path.display()))
}

/// Write data to a file asynchronously, creating or truncating it.
///
/// On Linux with `io-uring-backend`, uses a real io_uring `IORING_OP_WRITE`
/// submission. Falls back to `tokio::fs::write` on other platforms.
pub async fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    #[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
    if is_available() {
        return tokio::task::spawn_blocking({
            let path = path.to_owned();
            let data = data.to_vec();
            move || uring_impl::uring_write_file(&path, &data)
        })
        .await
        .map_err(|e| format!("spawn: {e}"))?;
    }

    // Fallback to tokio
    tokio::fs::write(path, data)
        .await
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// Append data to a file asynchronously, creating it if it does not exist.
///
/// Currently delegates to tokio's `OpenOptions` with append mode.
pub async fn append_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|e| format!("append_file open failed: {e}"))?;

    file.write_all(data)
        .await
        .map_err(|e| format!("append_file write failed: {e}"))?;

    file.flush()
        .await
        .map_err(|e| format!("append_file flush failed: {e}"))?;

    Ok(())
}

// ── FFI Wrappers ────────────────────────────────────────────────────────────
//
// `extern "C"` entry points matching the declarations the LLVM codegen emits
// in its preamble (src/codegen.rs: `declare ptr @tallow_iouring_read_file(ptr)`
// etc.). Compiled Tallow binaries link these from libtallow.a / the runtime
// archive, so no declared symbol is ever left undefined at link time.

use std::ffi::c_char;

/// Read a file through the io_uring/tokio backend.
///
/// Returns a NUL-terminated heap string with the file contents (UTF-8), or
/// null on error (check `tallow_last_error`). Free with `tallow_free_string`.
/// Binary content is rejected with an explicit error — the codegen string
/// model is C-string based, and silently truncating at a NUL would corrupt
/// the data.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_iouring_read_file(path: *const c_char) -> *mut c_char {
    let path_str = match unsafe { super::cstr_to_str(path) } {
        Some(s) => s,
        None => {
            super::set_last_error("io_uring.read_file: null or invalid path".to_string());
            return std::ptr::null_mut();
        }
    };
    let rt = super::get_runtime();
    match rt.block_on(read_file(std::path::Path::new(path_str))) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => super::string_to_cstr(&s),
            Err(_) => {
                super::set_last_error(
                    "io_uring.read_file: file content is not valid UTF-8 (binary files are not representable over the C-string FFI)"
                        .to_string(),
                );
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            super::set_last_error(format!("io_uring.read_file: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Write `data_len` bytes of `data` to `path` through the io_uring/tokio
/// backend (creates/truncates the file). Returns 0 on success, -1 on error
/// (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_iouring_write_file(
    path: *const c_char,
    data: *const c_char,
    data_len: i64,
) -> i32 {
    let path_str = match unsafe { super::cstr_to_str(path) } {
        Some(s) => s,
        None => {
            super::set_last_error("io_uring.write_file: null or invalid path".to_string());
            return -1;
        }
    };
    let bytes: Vec<u8> = if data.is_null() || data_len <= 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data as *const u8, data_len as usize) }.to_vec()
    };
    let rt = super::get_runtime();
    match rt.block_on(write_file(std::path::Path::new(path_str), &bytes)) {
        Ok(()) => 0,
        Err(e) => {
            super::set_last_error(format!("io_uring.write_file: {e}"));
            -1
        }
    }
}

/// Name of the active I/O backend ("io_uring" or "epoll") as a static C
/// string. Do not free.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_iouring_backend_name() -> *const c_char {
    backend_name().as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_name_returns_string() {
        let name = backend_name();
        assert!(
            name == "io_uring" || name == "epoll",
            "unexpected backend name: {name}"
        );
    }

    #[test]
    fn is_available_returns_bool() {
        // Just call it — must not panic.
        let _available: bool = is_available();
    }

    #[tokio::test]
    async fn write_and_read_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let content = b"hello io_uring";

        write_file(&path, content).await.unwrap();
        let read_back = read_file(&path).await.unwrap();

        assert_eq!(read_back, content);
    }

    #[tokio::test]
    async fn append_file_creates_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.txt");

        append_file(&path, b"line one\n").await.unwrap();
        append_file(&path, b"line two\n").await.unwrap();

        let contents = read_file(&path).await.unwrap();
        assert_eq!(contents, b"line one\nline two\n");
    }
}
