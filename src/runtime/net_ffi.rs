//! FFI wrappers for Tallow TCP networking (compiled binaries).
//!
//! Compiled Tallow programs calling `net.connect` / `net.listen` / `net.close`
//! emit calls to these symbols. Backed by std::net. Handles are opaque
//! `*mut c_void` pointers to a `NetHandle` (stream or listener).

use std::ffi::c_void;
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error};

/// A connection or listener handle, tagged so `tallow_net_close` can drop
/// whichever kind `net.connect` / `net.listen` produced.
enum NetHandle {
    Stream(TcpStream),
    Listener(TcpListener),
}

/// Connect to `host:port` (e.g. "example.com:80"). Returns an opaque handle,
/// or null on error. Free with `tallow_net_close`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_net_connect(addr: *const c_char) -> *mut c_void {
    let addr_str = match unsafe { cstr_to_str(addr) } {
        Some(s) => s,
        None => {
            set_last_error("net.connect: null or invalid address".to_string());
            return std::ptr::null_mut();
        }
    };
    match TcpStream::connect(addr_str) {
        Ok(stream) => Box::into_raw(Box::new(NetHandle::Stream(stream))) as *mut c_void,
        Err(e) => {
            set_last_error(format!("net.connect({addr_str}): {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Bind a TCP listener on `host:port` (e.g. "127.0.0.1:8080"). Returns an
/// opaque handle, or null on error. Free with `tallow_net_close`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_net_listen(addr: *const c_char) -> *mut c_void {
    let addr_str = match unsafe { cstr_to_str(addr) } {
        Some(s) => s,
        None => {
            set_last_error("net.listen: null or invalid address".to_string());
            return std::ptr::null_mut();
        }
    };
    match TcpListener::bind(addr_str) {
        Ok(listener) => Box::into_raw(Box::new(NetHandle::Listener(listener))) as *mut c_void,
        Err(e) => {
            set_last_error(format!("net.listen({addr_str}): {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Close a handle previously returned by `tallow_net_connect`/`tallow_net_listen`.
/// Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_net_close(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle as *mut NetHandle));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn net_listen_and_close_via_ffi() {
        let addr = CString::new("127.0.0.1:0").unwrap();
        let handle = tallow_net_listen(addr.as_ptr());
        assert!(!handle.is_null());
        tallow_net_close(handle);
        tallow_net_close(std::ptr::null_mut());
    }

    #[test]
    fn net_connect_failure_is_honest() {
        // Port 1 on localhost is virtually never listening; connect must fail
        // fast rather than fake success.
        let addr = CString::new("127.0.0.1:1").unwrap();
        let handle = tallow_net_connect(addr.as_ptr());
        assert!(handle.is_null());
    }
}
