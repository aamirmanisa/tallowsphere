//! Function values must be callable on both planes (register #124).
//!
//! A `fn(..)`-typed binding used to be uncallable natively: the backend emitted a call
//! to the binding's name, which is not a symbol, and `apply(add, 2, 40)` returned 2 with
//! exit 0. Function values now carry the closure ABI — a pointer called as
//! `i64 (ptr env, args…)` — with a thunk generated per named function and a null env for
//! non-capturing values. A *capturing* closure still cannot cross a call boundary,
//! because its environment lives in the caller's frame; that case must refuse loudly.

const NAMED: &str = r#"
fn add(a: i64, b: i64) -> i64 { a + b }
fn apply(f: fn(i64, i64) -> i64, a: i64, b: i64) -> i64 { f(a, b) }

fn main() {
    print(apply(add, 2, 40))
    let g = add
    print(g(20, 22))
}
"#;

const CLOSURE_VALUE: &str = r#"
fn apply(f: fn(i64) -> i64, x: i64) -> i64 { f(x) }

fn main() {
    print(apply({ y -> y * 3 }, 14))
}
"#;

const CAPTURING_ACROSS: &str = r#"
fn apply(f: fn(i64) -> i64, x: i64) -> i64 { f(x) }

fn main() {
    let triple = 3
    print(apply({ y -> y * triple }, 14))
}
"#;

fn run(program: &str, args: &[&str], name: &str) -> std::process::Output {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    let path = std::env::temp_dir().join(format!("tallow-fnvalue-{:016x}-{name}.tl", h.finish()));
    std::fs::write(&path, program).expect("write program");
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

fn assert_renders(program: &str, expected: &str, name: &str) {
    for plane in [&["--interpret"][..], &["--require-native"][..]] {
        let out = run(program, plane, name);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "[{plane:?}] failed: {stdout}{stderr}");
        assert!(
            !stderr.contains("native build unavailable"),
            "[{plane:?}] fell back to the interpreter: {stderr}"
        );
        assert_eq!(stdout, expected, "[{plane:?}] {name}");
    }
}

#[test]
fn a_named_function_value_is_callable_on_both_planes() {
    assert_renders(NAMED, "42\n42\n", "named");
}

#[test]
fn a_non_capturing_closure_is_callable_through_a_parameter() {
    assert_renders(CLOSURE_VALUE, "42\n", "closure-value");
}

#[test]
fn a_capturing_closure_across_a_call_still_refuses_loudly() {
    let native = run(CAPTURING_ACROSS, &["--require-native"], "capturing");
    let stderr = String::from_utf8_lossy(&native.stderr).to_string();
    assert_eq!(native.status.code(), Some(1), "expected refusal: {stderr}");
    assert!(
        stderr.contains("capturing closure"),
        "expected the capture-boundary refusal, got: {stderr}"
    );
    // The default path stays correct by falling back to the interpreter.
    let default = run(CAPTURING_ACROSS, &[], "capturing-default");
    let stdout = String::from_utf8_lossy(&default.stdout).to_string();
    assert!(default.status.success(), "default run failed: {stdout}");
    assert_eq!(stdout.trim(), "42");
}
