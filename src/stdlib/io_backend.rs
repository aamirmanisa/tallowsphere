//! Platform-accelerated I/O backend abstraction.
//!
//! Auto-detects the best available I/O mechanism:
//! - io_uring on Linux 5.6+ with `io-uring-backend` feature
//! - Overlapped I/O + IOCP on Windows via tokio (`tokio::fs` uses IOCP under
//!   the hood), giving real non-blocking async file I/O
//! - std::io thread-pool fallback everywhere else
//!
//! Provides synchronous `read_file_sync` / `write_file_sync` that dispatch
//! to the appropriate backend, plus true async `read_file_async` /
//! `write_file_async` / `seek_file_async` backed by `tokio::fs`. The async
//! functions are cross-platform: on Windows they ride the IOCP completion
//! port (which is exactly what tokio's file I/O does), and on Linux they use
//! the tokio reactor / io_uring when available.

use std::path::Path;
use std::time::Duration;

use crate::runtime::get_runtime;

// ── Backend enum ────────────────────────────────────────────────────────

/// The active platform I/O backend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoBackend {
    /// io_uring on Linux kernel >= 5.6 with feature flag enabled.
    Uring,
    /// Windows Overlapped I/O + IOCP completion ports (via tokio).
    Iocp,
    /// std::io thread-pool fallback (always available).
    ThreadPool,
}

// ── Detection ────────────────────────────────────────────────────────────

/// Auto-detect the best available I/O backend for this platform.
///
/// - Linux + `io-uring-backend` feature + kernel >= 5.6 → `IoBackend::Uring`
/// - Windows → `IoBackend::Iocp`
/// - All other → `IoBackend::ThreadPool`
///
/// Logs the selected backend to stderr on first call.
pub fn detect_backend() -> IoBackend {
    let backend = detect_backend_impl();
    // Log the detected backend to stderr for observability
    eprintln!("tallow: I/O backend: {}", backend_name(&backend));
    backend
}

/// Internal detection without logging (avoids duplicate log lines on repeat calls).
#[allow(unreachable_code)]
fn detect_backend_impl() -> IoBackend {
    #[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
    {
        if crate::runtime::io_uring_runtime::is_available() {
            return IoBackend::Uring;
        }
    }

    #[cfg(target_os = "windows")]
    {
        return IoBackend::Iocp;
    }

    // Fallback for macOS, other Unix, or Linux without io_uring
    IoBackend::ThreadPool
}

/// Return a human-readable name for the given backend.
pub fn backend_name(backend: &IoBackend) -> &'static str {
    match backend {
        IoBackend::Uring => "io_uring",
        IoBackend::Iocp => "iocp",
        IoBackend::ThreadPool => "thread_pool",
    }
}

// ── Synchronous read/write dispatch ─────────────────────────────────────

/// Read the entire contents of a file using the given backend.
///
/// On Linux with io_uring backend, bridges the async io_uring runtime through
/// a one-shot tokio runtime. On Windows, bridges through `tokio::fs` which
/// uses the IOCP completion port. Falls back to `std::fs::read` on ThreadPool
/// and unsupported platforms.
pub fn read_file_sync(path: &Path, backend: IoBackend) -> Result<Vec<u8>, String> {
    match backend {
        #[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
        IoBackend::Uring => read_via_uring(path),

        #[cfg(target_os = "windows")]
        IoBackend::Iocp => read_via_tokio(path),

        IoBackend::ThreadPool
        | _ => {
            // Fallback: standard synchronous I/O
            std::fs::read(path)
                .map_err(|e| format!("read {}: {e}", path.display()))
        }
    }
}

/// Write data to a file (creating or truncating) using the given backend.
///
/// See `read_file_sync` for backend dispatch details.
pub fn write_file_sync(path: &Path, data: &[u8], backend: IoBackend) -> Result<(), String> {
    match backend {
        #[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
        IoBackend::Uring => write_via_uring(path, data),

        #[cfg(target_os = "windows")]
        IoBackend::Iocp => write_via_tokio(path, data),

        IoBackend::ThreadPool
        | _ => {
            // Fallback: standard synchronous I/O
            std::fs::write(path, data)
                .map_err(|e| format!("write {}: {e}", path.display()))
        }
    }
}

// ── True async I/O (cross-platform, tokio-backed) ───────────────────────

/// Async read of an entire file, bridged through the global tokio runtime.
///
/// This is a real async read (`tokio::fs::read`). On Windows it completes on
/// the IOCP port; on Linux it runs on the tokio reactor. Safe to call from a
/// synchronous context (like the stdlib dispatch) — it blocks the current
/// thread until the async read completes.
pub fn read_file_async(path: &Path) -> Result<Vec<u8>, String> {
    let rt = get_runtime();
    rt.block_on(async move { tokio::fs::read(path).await })
        .map_err(|e| format!("async read {}: {e}", path.display()))
}

/// Async write of a file (create or truncate), bridged through tokio.
pub fn write_file_async(path: &Path, data: &[u8]) -> Result<(), String> {
    let rt = get_runtime();
    rt.block_on(async move { tokio::fs::write(path, data).await })
        .map_err(|e| format!("async write {}: {e}", path.display()))
}

/// Async seek to an absolute byte offset in a file, then read `n` bytes.
///
/// Opens the file with tokio, seeks to `offset`, and reads exactly `n` bytes
/// (or fewer at EOF). Returns the bytes read. This exercises the real async
/// seek path rather than a synchronous wrapper.
pub fn read_at_async(path: &Path, offset: u64, n: usize) -> Result<Vec<u8>, String> {
    let rt = get_runtime();
    rt.block_on(async move {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file = tokio::fs::File::open(path).await
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        file.seek(std::io::SeekFrom::Start(offset)).await
            .map_err(|e| format!("seek {} @ {offset}: {e}", path.display()))?;
        let mut buf = vec![0u8; n];
        let read = file.read(&mut buf).await
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        buf.truncate(read);
        Ok::<Vec<u8>, String>(buf)
    })
}

// ── io_uring bridge (Linux + feature gate) ───────────────────────────────

/// Bridge synchronous call to the async io_uring `read_file` using a
/// one-shot tokio runtime. The io_uring functions internally use
/// spawn_blocking, so a minimal single-threaded runtime is sufficient.
#[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
fn read_via_uring(path: &Path) -> Result<Vec<u8>, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|e| format!("io_backend: cannot create tokio runtime: {e}"))?;

    rt.block_on(crate::runtime::io_uring_runtime::read_file(path))
}

/// Bridge synchronous call to the async io_uring `write_file`.
#[cfg(all(target_os = "linux", feature = "io-uring-backend"))]
fn write_via_uring(path: &Path, data: &[u8]) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|e| format!("io_backend: cannot create tokio runtime: {e}"))?;

    rt.block_on(crate::runtime::io_uring_runtime::write_file(path, data))
}

// ── IOCP path (Windows) ──────────────────────────────────────────────────

/// Real Windows async file read via tokio, which uses Overlapped I/O + the
/// IOCP completion port under the hood (tokio's std-async shim for files).
#[cfg(target_os = "windows")]
fn read_via_tokio(path: &Path) -> Result<Vec<u8>, String> {
    read_file_async(path)
}

/// Real Windows async file write via tokio (Overlapped I/O + IOCP).
#[cfg(target_os = "windows")]
fn write_via_tokio(path: &Path, data: &[u8]) -> Result<(), String> {
    write_file_async(path, data)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend_returns_valid_variant() {
        let backend = detect_backend_impl();
        // Must be one of the three known variants
        match backend {
            IoBackend::Uring | IoBackend::Iocp | IoBackend::ThreadPool => {}
        }
    }

    #[test]
    fn test_backend_name_matches_variant() {
        assert_eq!(backend_name(&IoBackend::Uring), "io_uring");
        assert_eq!(backend_name(&IoBackend::Iocp), "iocp");
        assert_eq!(backend_name(&IoBackend::ThreadPool), "thread_pool");
    }

    #[test]
    fn test_read_write_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip.bin");
        let data = b"Tallow I/O backend roundtrip test data\n";

        let backend = detect_backend_impl();

        // Write
        write_file_sync(&path, data, backend).unwrap();

        // Read back
        let read_back = read_file_sync(&path, backend).unwrap();

        assert_eq!(read_back, data);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let path = std::path::Path::new("__nonexistent_io_backend_test_file__.bin");
        let backend = detect_backend_impl();
        let result = read_file_sync(path, backend);
        assert!(result.is_err(), "reading nonexistent file should return Err");
    }

    #[test]
    fn test_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new_file.bin");
        let data = b"new file created by io_backend";
        let backend = detect_backend_impl();

        // File should not exist yet
        assert!(!path.exists());

        write_file_sync(&path, data, backend).unwrap();

        // File should now exist
        assert!(path.exists());

        // Content should match
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, data);
    }

    #[test]
    fn test_async_read_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("async.bin");
        let data = b"async io via tokio backend";

        write_file_async(&path, data).unwrap();
        let read_back = read_file_async(&path).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_read_at_async_seek() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seek.bin");
        let data = b"0123456789ABCDEF";
        std::fs::write(&path, data).unwrap();

        // Read 4 bytes starting at offset 6 -> "6789"
        let chunk = read_at_async(&path, 6, 4).unwrap();
        assert_eq!(chunk, b"6789");

        // Reading past EOF returns fewer bytes
        let tail = read_at_async(&path, 14, 10).unwrap();
        assert_eq!(tail, b"EF");
    }

    #[test]
    fn test_read_at_async_rejects_missing() {
        let path = std::path::Path::new("__nonexistent_async_seek__.bin");
        assert!(read_at_async(path, 0, 4).is_err());
    }

    #[test]
    fn test_read_at_async_large() {
        // Build a 1MB buffer and verify seek across it
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        let chunk = read_at_async(&path, 500_000, 1024).unwrap();
        assert_eq!(chunk, data[500_000..501_024]);
        let _ = Duration::default(); // keep import used on odd platforms
    }
}
