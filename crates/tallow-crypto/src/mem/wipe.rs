//! Memory wiping and protection utilities
//!
//! Note: `std::io` is imported in `#[cfg(unix)]` blocks below for
//! `io::Error::last_os_error()`. This is stdlib (not an I/O crate),
//! used only for OS error reporting in platform-specific memory safety code.
//!
//! # Safety
//!
//! This module contains unavoidable `unsafe` blocks for OS-level memory
//! protection syscalls (`setrlimit`, `mlock`, `munlock`). These are the
//! only `unsafe` blocks permitted in `tallow-crypto`. All other modules
//! must remain `unsafe`-free. Each unsafe function is annotated with
//! `#[allow(unsafe_code)]` and a `// SAFETY:` comment documenting the
//! invariants being upheld.

#[cfg(unix)]
use crate::error::CryptoError;
use crate::error::Result;

/// Prevent core dumps from being generated
///
/// This reduces the risk of sensitive cryptographic material being written to disk.
///
/// # Platform Support
///
/// - **Unix**: Uses `setrlimit(RLIMIT_CORE, 0)`
/// - **Windows**: Currently a no-op (core dumps not typical on Windows)
#[allow(unsafe_code)]
pub fn prevent_core_dumps() -> Result<()> {
    #[cfg(unix)]
    {
        use std::io;
        // SAFETY: setrlimit is safe to call with valid parameters.
        // We're setting RLIMIT_CORE to 0 to disable core dumps,
        // which is a non-destructive operation.
        unsafe {
            let rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
                return Err(CryptoError::Io(io::Error::last_os_error().to_string()));
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows doesn't typically generate core dumps in the Unix sense
        // No action needed
    }

    Ok(())
}

/// Lock memory pages to prevent swapping to disk
///
/// Pins the specified memory region in physical RAM so it cannot be
/// swapped out by the operating system. Use this for key material.
///
/// # Arguments
///
/// * `ptr` - Pointer to the memory region
/// * `len` - Length of the memory region in bytes
///
/// # Platform Support
///
/// - **Unix**: Uses `mlock(2)` to pin pages
/// - **Windows**: No-op (VirtualLock deferred to future release)
/// - **Other**: No-op
#[allow(unsafe_code)]
pub fn lock_memory(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 || ptr.is_null() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::io;
        // SAFETY: mlock is safe to call with any valid pointer and length.
        // It merely advises the kernel to keep pages resident in RAM.
        // Failure (e.g., RLIMIT_MEMLOCK exceeded) is non-fatal.
        unsafe {
            if libc::mlock(ptr as *const libc::c_void, len) != 0 {
                let err = io::Error::last_os_error();
                // EPERM or ENOMEM are non-fatal — key material still works,
                // it just might be swappable. Log but don't fail.
                return Err(CryptoError::Io(format!(
                    "mlock failed (non-fatal): {}",
                    err
                )));
            }
        }
    }

    #[cfg(not(unix))]
    {
        // Windows VirtualLock and other platforms: deferred
        let _ = (ptr, len);
    }

    Ok(())
}

/// Unlock previously locked memory pages
///
/// Allows the OS to swap the memory region again. Call this when
/// the key material has been zeroized and is no longer needed.
///
/// # Arguments
///
/// * `ptr` - Pointer to the memory region
/// * `len` - Length of the memory region in bytes
#[allow(unsafe_code)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> Result<()> {
    if len == 0 || ptr.is_null() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        // SAFETY: munlock is safe to call with any valid pointer and length.
        // It merely allows the kernel to swap pages out again.
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
    }

    Ok(())
}

/// Wipe memory on drop using a closure
///
/// Returns a guard that will execute the wipe function when dropped.
///
/// # Example
///
/// ```ignore
/// let mut secret = vec![1, 2, 3, 4];
/// let _guard = wipe_on_drop(|| {
///     secret.iter_mut().for_each(|b| *b = 0);
/// });
/// // secret is automatically zeroed when _guard is dropped
/// ```
pub fn wipe_on_drop<F: FnOnce()>(f: F) -> WipeGuard<F> {
    WipeGuard { wipe_fn: Some(f) }
}

/// Guard that executes a wipe function on drop
pub struct WipeGuard<F: FnOnce()> {
    wipe_fn: Option<F>,
}

impl<F: FnOnce()> Drop for WipeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.wipe_fn.take() {
            f();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(miri))] // miri cannot execute setrlimit syscall
    fn test_prevent_core_dumps() {
        // Should not panic
        let _ = prevent_core_dumps();
    }

    #[test]
    fn test_lock_memory_null() {
        // Should succeed with null/zero
        assert!(lock_memory(std::ptr::null(), 0).is_ok());
    }

    #[test]
    #[cfg(not(miri))] // miri cannot execute mlock/munlock syscalls
    fn test_lock_memory_real() {
        let data = [0u8; 64];
        // May fail due to permissions, but should not panic
        let _ = lock_memory(data.as_ptr(), data.len());
        let _ = unlock_memory(data.as_ptr(), data.len());
    }

    #[test]
    fn test_wipe_on_drop() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let value = AtomicU32::new(42);
        {
            let _guard = wipe_on_drop(|| {
                value.store(0, Ordering::SeqCst);
            });
            assert_eq!(value.load(Ordering::SeqCst), 42);
        }
        assert_eq!(value.load(Ordering::SeqCst), 0);
    }
}
