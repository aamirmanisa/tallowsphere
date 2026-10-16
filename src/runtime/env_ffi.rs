//! Runtime FFI: process environment (`env.*`) for compiled programs.
//!
//! The interpreter reaches `std::env` directly; compiled `.tl` binaries call
//! these C-ABI functions instead. Arrays use the NATIVE tallow layout
//! `[count: i64][elem0: i64]…` (see `runtime::browser::native_array`), so `len`,
//! indexing and iteration work in emitted code without a conversion call.

use std::ffi::c_void;

use super::browser::native_array;
use super::{set_last_error, string_to_cstr};

/// `env.args()` -> native array of the PROGRAM arguments (`argv[1..]`).
///
/// The interpreter's `env.args()` returns the CLI's program args (the ones
/// after `--`), i.e. it excludes the program file/binary path — so a compiled
/// binary must skip `argv[0]` to stay byte-identical (B4: with `argv[0]`
/// included, `env.args().len()` was 3 for `prog alpha beta` natively vs 2 in
/// the interpreter). Never null: no program args yields an empty array.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_env_args() -> *mut c_void {
    let slots: Vec<i64> = std::env::args()
        .skip(1)
        .map(|a| string_to_cstr(&a) as i64)
        .collect();
    native_array(slots)
}

/// `env.exe_path()` -> the path of the running executable, as the interpreter's
/// `std::env::current_exe()` returns it (`src/stdlib/env.rs`).
///
/// NOT a `getenv` lowering: it resolves through `current_exe()`, which on Linux
/// is a `readlink("/proc/self/exe")` underneath — there is no environment
/// variable to read. Returns null (with `tallow_last_error` set) if the path
/// cannot be resolved; the emitted code turns that into a non-zero exit.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_env_exe_path() -> *mut std::os::raw::c_char {
    match std::env::current_exe() {
        Ok(p) => string_to_cstr(&p.to_string_lossy()),
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read element `i` out of a native array.
    unsafe fn elem(arr: *mut c_void, i: usize) -> String {
        let count = *(arr as *const i64);
        assert!(count >= 0);
        let slot = (arr as *const i64).add(i + 1);
        let s = *slot as *const std::ffi::c_char;
        std::ffi::CStr::from_ptr(s).to_str().unwrap().to_string()
    }

    #[test]
    fn args_array_matches_program_args() {
        let arr = tallow_env_args();
        assert!(!arr.is_null());
        // B4 parity: the interpreter's `env.args()` excludes the program
        // path, so the native array must skip `argv[0]` (the binary path).
        let expected: Vec<String> = std::env::args().skip(1).collect();
        assert_eq!(unsafe { *(arr as *const i64) } as usize, expected.len());
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(unsafe { elem(arr, i) }, *want, "arg {i} diverged");
        }
    }
}
