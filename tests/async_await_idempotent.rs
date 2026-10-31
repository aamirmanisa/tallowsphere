//! Regression: awaiting a task handle twice must not double-free.
//!
//! Measured before the fix: the built binary aborted with
//! `free(): double free detected in tcache 2` (exit 134, 5/5 runs) for
//!
//! ```tl
//! let h = spawn worker(5)
//! let a = h.await
//! let b = h.await
//! ```
//!
//! `tallow_async_await` waited on the task, then unconditionally
//! `free(t)`'d the node — so the second await entered a destroyed mutex and
//! freed the same memory again. The task is now marked `reaped` and a repeat
//! await returns the recorded result.
//!
//! **The masking trap this test exists to close:** `tallow run` does NOT show
//! this failure. When the native child is killed by a signal, `run` re-executes
//! the program in the interpreter, prints the interpreter's answer and exits 0
//! (`src/main.rs`, the signal-crash arm). Verified: `tallow run` on this
//! program printed `0 0` and exited 0 while the built binary aborted. So this
//! test builds with `tallow build` — which never falls back — and executes the
//! artifact directly, then asserts on the exit status.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow")
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tallow-await-regress-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("work dir");
    dir
}

fn build_and_run(tag: &str, source: &str) -> (Option<i32>, String, String) {
    let dir = workdir(tag);
    let path = dir.join("prog.tl");
    std::fs::write(&path, source).expect("write program");
    let out = Command::new(bin())
        .args(["build", "-q"])
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow build");
    assert!(
        out.status.success(),
        "[{tag}] the program did not build:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let binary = path.with_extension("");
    assert!(binary.exists(), "[{tag}] no binary at {}", binary.display());
    let run = Command::new(&binary).output().expect("run built binary");
    let _ = std::fs::remove_dir_all(&dir);
    (
        run.status.code(),
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&run.stderr).into_owned(),
    )
}

const DOUBLE_AWAIT: &str = r#"
fn worker(x: i32) -> i32 { x * 10 }
fn main() {
    let h = spawn worker(5)
    let a = h.await
    let b = h.await
    print(a)
    print(b)
}
"#;

#[test]
fn awaiting_a_handle_twice_does_not_abort() {
    let (code, _stdout, stderr) = build_and_run("twice", DOUBLE_AWAIT);
    assert!(
        !stderr.contains("double free"),
        "the built binary reported a double free:\n{stderr}"
    );
    // A signal kill (SIGABRT from glibc's malloc check) surfaces as `None`
    // here because there is no exit code for a signalled process.
    assert_eq!(
        code,
        Some(0),
        "awaiting the same handle twice must not abort; stderr:\n{stderr}"
    );
}

#[test]
fn awaiting_a_handle_twice_under_comparison_does_not_abort() {
    // The shape that aborted too: the value is used in a comparison before the
    // second await. A fix that only special-cases "await, discard, await"
    // would leave this one crashing.
    let source = r#"
fn worker(x: i32) -> i32 { x * 10 }
fn main() {
    let h = spawn worker(5)
    print(h.await == 50)
    print(h.await)
}
"#;
    let (code, _stdout, stderr) = build_and_run("cmp", source);
    assert!(
        !stderr.contains("double free"),
        "the built binary reported a double free:\n{stderr}"
    );
    assert_eq!(code, Some(0), "must not abort; stderr:\n{stderr}");
}

#[test]
fn the_canonical_spawn_await_form_is_unchanged() {
    // `spawn_await(h)` is the fixture-blessed spelling and was already correct
    // on both planes; the idempotence fix must not disturb it.
    let source = r#"
fn worker(x: i32) -> i32 { x * 10 }
fn main() {
    let h = spawn worker(5)
    let r = spawn_await(h)
    print(r.unwrap())
}
"#;
    let (code, stdout, stderr) = build_and_run("canonical", source);
    assert_eq!(code, Some(0), "stderr:\n{stderr}");
    assert_eq!(stdout.trim(), "50", "the awaited value changed");
}

#[allow(dead_code)]
fn _unused(_p: &Path) {}
