//! `tallow.process.exec` / `.run` in the native plane.
//!
//! The language declares `Output { stdout, stderr, exit_code, success }`.
//! Before this FFI the codegen could only run a shell and read its exit status,
//! so every field read turned into 0 — a silent wrong answer. The interpreter
//! already captured output through `std::process::Command::output`; this is the
//! same operation behind a C ABI.
//!
//! argv crosses in two shapes: a NUL-separated blob plus a count for literal
//! arrays (one interned constant, no loop in IR), and a real `*const *const
//! c_char` array via `tallow_process_execv` for a runtime `[]String`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Out-parameter for `tallow_process_exec`. Field order is fixed: codegen reads
/// `stdout` at 0, `stderr` at 8, `exit_code` at 16, `success` at 24.
#[repr(C)]
pub struct ProcessOutputRaw {
    pub stdout: *mut c_char,
    pub stderr: *mut c_char,
    pub exit_code: i64,
    pub success: i32,
    /// 0 = the child ran (whatever its status); -1 = it could not be started,
    /// and `stderr` carries the reason.
    pub ok: i32,
}

/// Run `cmd` with `argc` arguments packed NUL-separated in `argv` and fill
/// `out` with the captured output. Returns 0 on success, -1 on a null argument
/// or a spawn failure.
///
/// A spawn failure is reported as `exit_code = -1`, `success = 0` and the
/// reason in `stderr`: the declared return type is `Output`, not `Result`, so
/// the native plane cannot hand back an `Err` value. Every field is still
/// true — the command did not run, and the reason is visible.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_process_exec(
    cmd: *const c_char,
    argv: *const c_char,
    argc: i64,
    out: *mut ProcessOutputRaw,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    unsafe {
        *out = ProcessOutputRaw {
            stdout: std::ptr::null_mut(),
            stderr: std::ptr::null_mut(),
            exit_code: -1,
            success: 0,
            ok: -1,
        };
    }
    if cmd.is_null() {
        return -1;
    }
    let cmd = unsafe { CStr::from_ptr(cmd) }.to_string_lossy().to_string();
    if cmd.trim().is_empty() {
        unsafe {
            (*out).stderr = to_c("process.exec requires a command string");
        }
        return -1;
    }

    // argv is `argc` NUL-terminated strings packed back to back. Walk them by
    // pointer rather than through one CStr: a CStr stops at the first NUL, which
    // is the end of argv[0], not of the blob.
    let mut args: Vec<String> = Vec::new();
    if !argv.is_null() && argc > 0 {
        let mut cursor = argv as *const u8;
        for _ in 0..argc {
            let part = unsafe { CStr::from_ptr(cursor as *const c_char) };
            let bytes = part.to_bytes();
            args.push(part.to_string_lossy().to_string());
            cursor = unsafe { cursor.add(bytes.len() + 1) };
        }
    }
    run_with_args(&cmd, &args, out)
}

/// Run `cmd` with a real `argv` pointer array — the dynamic form.
///
/// Codegen uses this when the argument list is a runtime `[]String`: it calls
/// `tallow_array_len` / `tallow_array_get` to build the pointer array in IR and
/// hands it here. The blob entry point above stays for literal arrays, which
/// need no loop.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_process_execv(
    cmd: *const c_char,
    argv: *const *const c_char,
    argc: i64,
    out: *mut ProcessOutputRaw,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    unsafe {
        *out = ProcessOutputRaw {
            stdout: std::ptr::null_mut(),
            stderr: std::ptr::null_mut(),
            exit_code: -1,
            success: 0,
            ok: -1,
        };
    }
    if cmd.is_null() {
        return -1;
    }
    let cmd = unsafe { CStr::from_ptr(cmd) }.to_string_lossy().to_string();
    if cmd.trim().is_empty() {
        unsafe {
            (*out).stderr = to_c("process.exec requires a command string");
        }
        return -1;
    }
    let mut args: Vec<String> = Vec::new();
    if !argv.is_null() && argc > 0 {
        let slots = unsafe { std::slice::from_raw_parts(argv, argc as usize) };
        for slot in slots {
            if slot.is_null() {
                args.push(String::new());
                continue;
            }
            args.push(unsafe { CStr::from_ptr(*slot) }.to_string_lossy().to_string());
        }
    }
    run_with_args(&cmd, &args, out)
}

/// The shared tail: spawn, capture, fill `out`.
fn run_with_args(cmd: &str, args: &[String], out: *mut ProcessOutputRaw) -> i32 {
    match std::process::Command::new(cmd).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            unsafe {
                (*out).stdout = to_c(&stdout);
                (*out).stderr = to_c(&stderr);
                (*out).exit_code = output.status.code().map(i64::from).unwrap_or(-1);
                (*out).success = if output.status.success() { 1 } else { 0 };
                (*out).ok = 0;
            }
            0
        }
        Err(e) => {
            unsafe {
                (*out).stderr = to_c(&format!("process.exec: {e}"));
                (*out).exit_code = -1;
                (*out).success = 0;
                (*out).ok = -1;
            }
            -1
        }
    }
}

fn to_c(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn exec_captures_stdout_stderr_and_status() {
        let cmd = CString::new("/bin/sh").unwrap();
        let argv: Vec<&str> = vec!["-c", "printf out; printf err 1>&2; exit 3"];
        // The blob is NUL-separated by construction, so it cannot be a CString
        // (which rejects interior NULs). Codegen emits the same bytes as one
        // LLVM string constant.
        let mut blob: Vec<u8> = Vec::new();
        for part in &argv {
            blob.extend_from_slice(part.as_bytes());
            blob.push(0);
        }
        let mut out = ProcessOutputRaw {
            stdout: std::ptr::null_mut(),
            stderr: std::ptr::null_mut(),
            exit_code: 0,
            success: 1,
            ok: 0,
        };
        let rc = unsafe {
            tallow_process_exec(
                cmd.as_ptr(),
                blob.as_ptr() as *const c_char,
                argv.len() as i64,
                &mut out,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(out.exit_code, 3);
        assert_eq!(out.success, 0);
        let stdout = unsafe { CStr::from_ptr(out.stdout) }
            .to_string_lossy()
            .to_string();
        let stderr = unsafe { CStr::from_ptr(out.stderr) }
            .to_string_lossy()
            .to_string();
        assert_eq!(stdout, "out");
        assert_eq!(stderr, "err");
    }

    #[test]
    fn exec_reports_a_missing_binary_as_a_failed_output() {
        let cmd = CString::new("tallow-no-such-binary-xyz").unwrap();
        let mut out = ProcessOutputRaw {
            stdout: std::ptr::null_mut(),
            stderr: std::ptr::null_mut(),
            exit_code: 0,
            success: 1,
            ok: 0,
        };
        let rc = unsafe { tallow_process_exec(cmd.as_ptr(), std::ptr::null(), 0, &mut out) };
        assert_eq!(rc, -1);
        assert_eq!(out.exit_code, -1);
        assert_eq!(out.success, 0);
        assert!(!out.stderr.is_null());
    }
}
