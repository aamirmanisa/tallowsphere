//! A call through a function-typed binding is an indirect call; native must refuse
//! rather than call a symbol that does not exist (register #126).
//!
//! `apply(add, 2, 40)` printed 2 natively (exit 0) while the interpreter printed 42:
//! the backend emitted `call @f` for the parameter name. It now refuses, so `tallow run`
//! falls back to the interpreter and `--require-native` says why.

const PROGRAM: &str = r#"
fn add(a: i64, b: i64) -> i64 { a + b }

fn apply(f: fn(i64, i64) -> i64, a: i64, b: i64) -> i64 {
    f(a, b)
}

fn main() {
    print(apply(add, 2, 40))
}
"#;

fn run(args: &[&str], name: &str) -> std::process::Output {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    PROGRAM.hash(&mut h);
    let path = std::env::temp_dir().join(format!("tallow-fnvalue-{:016x}-{name}.tl", h.finish()));
    std::fs::write(&path, PROGRAM).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(args)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    out
}

#[test]
fn calling_a_function_value_natively_refuses_instead_of_returning_a_wrong_number() {
    let default = run(&[], "default");
    let stdout = String::from_utf8_lossy(&default.stdout).to_string();
    assert!(default.status.success(), "default run failed: {stdout}");
    assert_eq!(stdout.trim(), "42", "must render the interpreter's answer: {stdout:?}");

    let native = run(&["--require-native"], "native");
    let stderr = String::from_utf8_lossy(&native.stderr).to_string();
    let native_stdout = String::from_utf8_lossy(&native.stdout).to_string();
    assert_eq!(native.status.code(), Some(1), "expected refusal: {stderr}");
    assert!(
        stderr.contains("cannot call a function value natively"),
        "expected the refusal message, got: {stderr}"
    );
    // A `\`-continued literal leaves its source indentation inside the sentence.
    assert!(
        stderr.contains("binding and the backend"),
        "the refusal message carries continuation padding: {stderr}"
    );
    assert!(
        !native_stdout.trim().eq("2"),
        "the old silent wrong answer is back: {native_stdout:?}"
    );
}
