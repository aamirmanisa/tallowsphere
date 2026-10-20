//! Runtime diagnostics that a compiled program can hit at run time.
//!
//! The interpreter reports a non-exhaustive `match` as a runtime error. The native
//! backend used to fall through to its result type's default value instead — for a
//! `String` subject that printed `(null)` and exited 0, i.e. a silent wrong answer
//! from a shipped binary (register #123). `tallow_no_match` makes that path fail
//! the same way the interpreter does: a message, then a non-zero exit.

use std::ffi::c_int;

/// Abort the process, reporting a non-exhaustive `match`.
///
/// `line`/`col` are the `match` site when the code generator knows it; 0 means
/// unknown. Marked `-> !` so LLVM sees the call as terminating and no fallthrough
/// edge survives into the merge block.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_no_match(line: c_int, col: c_int) -> ! {
    if line > 0 {
        eprintln!("runtime error: non-exhaustive match (at {line}:{col})");
    } else {
        eprintln!("runtime error: non-exhaustive match");
    }
    std::process::exit(1)
}
