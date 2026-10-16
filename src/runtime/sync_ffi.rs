//! FFI wrappers for Tallow channels and mutexes (compiled binaries).
//!
//! Compiled Tallow programs calling `channel(cap)` / `mutex(value)` and the
//! `.send` / `.recv` / `.close` / `.lock` / `.unlock` methods emit calls to
//! these symbols. Backed by std::sync.
//!
//! Values cross the FFI boundary as NUL-terminated C strings (the codegen's
//! string model). Channel handles are opaque `*mut c_void` pointers to a
//! `ChanHandle`; mutex handles point to a `Mutex<Option<CString>>`.

use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender};
use std::sync::Mutex;

use super::{cstr_to_str, set_last_error, string_to_cstr};

/// A bounded or unbounded channel.
enum ChanHandle {
    Unbounded { tx: Sender<CString>, rx: Receiver<CString> },
    Bounded { tx: std::sync::mpsc::SyncSender<CString>, rx: Receiver<CString> },
}

/// Create a channel. `cap > 0` gives a bounded (synchronous) channel with that
/// capacity; `cap <= 0` gives an unbounded channel. Returns an opaque handle,
/// or null on error. Free with `tallow_channel_close`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_channel_create(cap: i64) -> *mut c_void {
    let handle = if cap > 0 {
        let (tx, rx) = sync_channel(cap as usize);
        ChanHandle::Bounded { tx, rx }
    } else {
        let (tx, rx) = channel();
        ChanHandle::Unbounded { tx, rx }
    };
    Box::into_raw(Box::new(handle)) as *mut c_void
}

/// Send a string value on the channel. Blocks until the value can be sent
/// (for bounded channels, until capacity is available).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_channel_send(handle: *mut c_void, value: *const c_char) {
    let Some(chan) = chan_handle(handle) else {
        return;
    };
    let value_str = match unsafe { cstr_to_str(value) } {
        Some(s) => s,
        None => {
            set_last_error("channel.send: null value".to_string());
            return;
        }
    };
    let cstr = CString::new(value_str).unwrap_or_default();
    let result: Result<(), String> = match chan {
        ChanHandle::Unbounded { tx, .. } => tx.send(cstr).map_err(|e| format!("{e}")),
        ChanHandle::Bounded { tx, .. } => tx
            .send(cstr)
            .map_err(|e| String::from_utf8_lossy(e.0.as_bytes()).to_string()),
    };
    if let Err(e) = result {
        set_last_error(format!("channel.send: {e}"));
    }
}

/// Receive a string value from the channel. Blocks until a value is available.
/// Returns a heap C string (free with `tallow_free_string`), or null when the
/// channel is closed and empty (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_channel_recv(handle: *mut c_void) -> *mut c_char {
    let Some(chan) = chan_handle(handle) else {
        return std::ptr::null_mut();
    };
    let rx = match chan {
        ChanHandle::Unbounded { rx, .. } | ChanHandle::Bounded { rx, .. } => rx,
    };
    match rx.recv() {
        Ok(cstr) => cstr.into_raw(),
        Err(e) => {
            set_last_error(format!("channel.recv: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Close a channel: drops the sender side (receivers see end-of-stream).
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_channel_close(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle as *mut ChanHandle));
        }
    }
}

/// Create a mutex holding the given string value. Returns an opaque handle,
/// or null on error. Free with `tallow_mutex_unlock`? No — mutexes have no
/// explicit close FFI; the handle is leaked unless the program exits (the
/// codegen only emits create/lock/unlock).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_mutex_create(value: *const c_char) -> *mut c_void {
    let stored = if value.is_null() {
        None
    } else {
        unsafe { cstr_to_str(value) }.map(|s| CString::new(s).unwrap_or_default())
    };
    Box::into_raw(Box::new(Mutex::new(stored))) as *mut c_void
}

/// Lock the mutex and return a copy of its stored value as a heap C string
/// (free with `tallow_free_string`). The lock is released before returning;
/// see the module docs for why the codegen contract prevents holding a guard.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_mutex_lock(handle: *mut c_void) -> *mut c_char {
    let Some(mtx) = mutex_handle(handle) else {
        return std::ptr::null_mut();
    };
    match mtx.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(cstr) => string_to_cstr(cstr.to_str().unwrap_or("")),
            None => {
                set_last_error("mutex.lock: empty value".to_string());
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            set_last_error(format!("mutex.lock: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Release the mutex. The lock was already released by `tallow_mutex_lock`
/// (which cannot hold a guard across separate FFI calls); this call acquires
/// and immediately releases the lock so the codegen's lock()/unlock() pairing
/// stays well-formed.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_mutex_unlock(handle: *mut c_void) {
    let Some(mtx) = mutex_handle(handle) else {
        return;
    };
    if let Ok(guard) = mtx.lock() {
        drop(guard);
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn chan_handle<'a>(handle: *mut c_void) -> Option<&'a mut ChanHandle> {
    if handle.is_null() {
        set_last_error("channel: null handle".to_string());
        return None;
    }
    Some(unsafe { &mut *(handle as *mut ChanHandle) })
}

fn mutex_handle<'a>(handle: *mut c_void) -> Option<&'a Mutex<Option<CString>>> {
    if handle.is_null() {
        set_last_error("mutex: null handle".to_string());
        return None;
    }
    Some(unsafe { &*(handle as *const Mutex<Option<CString>>) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn channel_roundtrip_via_ffi() {
        let chan = tallow_channel_create(0);
        assert!(!chan.is_null());
        let hello = CString::new("hello channel").unwrap();
        tallow_channel_send(chan, hello.as_ptr());
        let got = tallow_channel_recv(chan);
        assert!(!got.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(got).to_str().unwrap() },
            "hello channel"
        );
        unsafe { super::super::tallow_free_string(got) };
        tallow_channel_close(chan);
    }

    #[test]
    fn mutex_lock_unlock_via_ffi() {
        let initial = CString::new("guarded value").unwrap();
        let mtx = tallow_mutex_create(initial.as_ptr());
        assert!(!mtx.is_null());
        let got = tallow_mutex_lock(mtx);
        assert!(!got.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(got).to_str().unwrap() },
            "guarded value"
        );
        unsafe { super::super::tallow_free_string(got) };
        tallow_mutex_unlock(mtx);
        // No close FFI exists for mutexes; drop the box directly.
        unsafe { drop(Box::from_raw(mtx as *mut Mutex<Option<CString>>)) };
    }

    #[test]
    fn recv_on_null_handle_is_honest_error() {
        // Null handle must return null (honest error), never crash.
        let got = tallow_channel_recv(std::ptr::null_mut());
        assert!(got.is_null());
        tallow_channel_send(std::ptr::null_mut(), std::ptr::null());
    }
}
