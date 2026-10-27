//! `len()` on a scalar, on both planes.
//!
//! The defect: `5.len()` answered `0`. It looked like a measurement and was
//! accepted by `tallow check`, so a caller comparing `x.len() < n` saw a
//! plausible number. Two separate implementations produced it:
//!
//! * `Value::len` had a `_ => Value::Int(0)` fallback in the interpreter;
//! * `stdlib::json::dispatch_method` answered `"len"` for **every** non-struct
//!   receiver with `_ => Value::Int(0)`, and the interpreter consults that
//!   dispatcher *before* its own method match — so for scalars the interpreter's
//!   implementation was never reached at all.
//!
//! The pin is deliberately at the CLI, because the unit tests live inside one
//! implementation and could not have caught the shadowing: they call
//! `Value::len` directly, which is exactly the path the dispatcher skipped.
//!
//! Both planes must refuse. Measured before the fix: the interpreter printed
//! `0`; the native backend refuses `len` on a statically-known int with "no
//! lowering ... failing loudly", which is the safe direction but is not the same
//! error, so the native assertion checks for refusal, not for a shared message.

use std::process::Command;

const PROGRAM: &str = r#"fn main() {
    let x = 5
    print(x.len())
}
"#;

fn write_program(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("len_scalar.tl");
    std::fs::write(&path, PROGRAM).expect("write probe");
    path
}

fn run(args: &[&str], program: &std::path::Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .arg(program)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn interpreter_refuses_len_on_an_int() {
    let dir = std::env::temp_dir().join("tallow-len-scalar-interp");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let program = write_program(&dir);
    // A cross target forces the interpreter leg.
    let (ok, stdout, stderr) = run(&["run", "--target", "x86_64-linux"], &program);
    assert!(!ok, "the interpreter must refuse; stdout:\n{stdout}");
    assert!(
        !stdout.contains("0\n"),
        "a wrong answer must not be printed as though it were measured: {stdout}"
    );
    assert!(
        stderr.contains("len() is not defined for"),
        "the refusal must name the operation; stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn native_backend_refuses_len_on_an_int_rather_than_answering() {
    let dir = std::env::temp_dir().join("tallow-len-scalar-native");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let program = write_program(&dir);
    let (ok, stdout, stderr) = run(&["run", "--require-native"], &program);
    assert!(
        !ok,
        "an int has no length on either plane; native answered: {stdout}"
    );
    // Either the backend refuses the lowering, or it compiles a call that fails
    // at runtime. What it must not do is print a number.
    assert!(
        stderr.contains("no lowering for method 'len'") || stderr.contains("len"),
        "the refusal must name the method; stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("0\n"),
        "native must not answer 0 for a type with no length: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
