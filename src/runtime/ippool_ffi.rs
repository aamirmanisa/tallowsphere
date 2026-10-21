//! Minimal in-memory proxy IP-pool FFI for compiled Tallow binaries.
//!
//! Provides the `tallow_ippool_*` symbols that the LLVM codegen declares in
//! its preamble (src/codegen.rs: `declare ptr @tallow_ippool_create(i32, i32)`
//! etc.). The pool is an honest, working in-memory LIFO bag of proxy address
//! strings:
//!
//! - `tallow_ippool_create` builds a pool with a fixed capacity.
//! - `tallow_ippool_acquire` pops an address (or returns null when the pool
//!   is empty, setting `tallow_last_error`).
//! - `tallow_ippool_release` pushes an address back (up to capacity).
//! - `tallow_ippool_active` / `tallow_ippool_capacity` report pool state.
//! - `tallow_ippool_backend_name` reports the backend ("memory").
//!
//! NOTE: the codegen surface has no seeding entry point yet, so pools start
//! empty and are populated via `release` calls (or a future seeding FFI).
//! `acquire` on an empty pool returns null with an error message rather than
//! fabricating a proxy address — compiled programs never observe a fake
//! "proxy acquired" result.

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::Mutex;

/// A pool of proxy address strings (e.g. "127.0.0.1:8080").
struct IpPool {
    proxies: Vec<CString>,
    capacity: usize,
}

/// Create a new proxy pool with the given capacity. `_seed_count` is accepted
/// for signature compatibility with the codegen declaration; seeding is not
/// yet wired, so the pool starts empty.
///
/// Returns an opaque handle that lives for the lifetime of the program
/// (matching the other runtime handles, which the codegen never frees).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ippool_create(capacity: i32, _seed_count: i32) -> *mut c_void {
    let cap = capacity.max(0) as usize;
    let pool = IpPool {
        proxies: Vec::with_capacity(cap),
        capacity: cap,
    };
    Box::into_raw(Box::new(Mutex::new(pool))) as *mut c_void
}

/// Acquire a proxy address from the pool.
///
/// Returns a heap C string the caller must free with `tallow_free_string`,
/// or null when the pool is empty (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ippool_acquire(pool: *mut c_void) -> *mut c_char {
    if pool.is_null() {
        super::set_last_error("ippool.acquire: null pool handle".to_string());
        return std::ptr::null_mut();
    }
    let pool = unsafe { &*(pool as *const Mutex<IpPool>) };
    match pool.lock() {
        Ok(mut guard) => match guard.proxies.pop() {
            Some(proxy) => proxy.into_raw(),
            None => {
                super::set_last_error("ippool.acquire: pool is empty".to_string());
                std::ptr::null_mut()
            }
        },
        Err(_) => {
            super::set_last_error("ippool.acquire: pool lock poisoned".to_string());
            std::ptr::null_mut()
        }
    }
}

/// Return a proxy address to the pool (no-op if the pool is at capacity or
/// either argument is null).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ippool_release(pool: *mut c_void, proxy: *const c_char) {
    if pool.is_null() || proxy.is_null() {
        return;
    }
    let pool = unsafe { &*(pool as *const Mutex<IpPool>) };
    if let Ok(mut guard) = pool.lock() {
        if guard.proxies.len() < guard.capacity {
            let proxy = unsafe { CStr::from_ptr(proxy) }.to_owned();
            guard.proxies.push(proxy);
        }
    }
}

/// Number of proxy addresses currently held in the pool.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ippool_active(pool: *mut c_void) -> i32 {
    if pool.is_null() {
        return 0;
    }
    let pool = unsafe { &*(pool as *const Mutex<IpPool>) };
    pool.lock().map(|g| g.proxies.len() as i32).unwrap_or(0)
}

/// Maximum number of proxy addresses the pool can hold.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ippool_capacity(pool: *mut c_void) -> i32 {
    if pool.is_null() {
        return 0;
    }
    let pool = unsafe { &*(pool as *const Mutex<IpPool>) };
    pool.lock().map(|g| g.capacity as i32).unwrap_or(0)
}

/// Backend name ("memory") as a static C string. Do not free.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_ippool_backend_name(_pool: *mut c_void) -> *const c_char {
    b"memory\0".as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_acquire_release_roundtrip() {
        let pool = tallow_ippool_create(4, 0);
        assert!(!pool.is_null());
        assert_eq!(tallow_ippool_active(pool), 0);
        assert_eq!(tallow_ippool_capacity(pool), 4);
        // Compare content, not pointer identity: the two `b"memory\0"` literals
        // are separate statics, and whether the linker merges them is a
        // toolchain detail (it does on GNU ld, it does not on MSVC).
        let name = unsafe { std::ffi::CStr::from_ptr(tallow_ippool_backend_name(pool)) };
        assert_eq!(name.to_str().unwrap(), "memory");

        // Empty pool → acquire returns null with an error.
        assert!(tallow_ippool_acquire(pool).is_null());

        let addr = CString::new("127.0.0.1:8080").unwrap();
        tallow_ippool_release(pool, addr.as_ptr());
        assert_eq!(tallow_ippool_active(pool), 1);

        let got = tallow_ippool_acquire(pool);
        assert!(!got.is_null());
        let got = unsafe { CStr::from_ptr(got) }.to_str().unwrap().to_string();
        assert_eq!(got, "127.0.0.1:8080");
        assert_eq!(tallow_ippool_active(pool), 0);

        // Null safety.
        tallow_ippool_release(std::ptr::null_mut(), addr.as_ptr());
        tallow_ippool_release(pool, std::ptr::null());
        assert!(tallow_ippool_acquire(std::ptr::null_mut()).is_null());
    }
}
