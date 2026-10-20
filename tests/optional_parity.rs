//! Boxed optionals: the two engines must agree on `true`, `false` and `nil`.
//!
//! `T?` used to be an `i64` with `nil == 0`, so `false` and `nil` were the same
//! value and a present `true` printed `1`. `docs/optional-representation.md`
//! records the fix: a null pointer is `nil`, anything else is a
//! `%struct.Optional` box whose kind selects the rendering.
//!
//! Three distinct outcomes from one function is the smallest case that can tell
//! the two encodings apart, so it is the acceptance gate for the representation.

const PROGRAM: &str = r#"
fn pick(n: i64) -> bool? {
    if n > 0 {
        return true
    }
    if n == 0 {
        return false
    }
    return nil
}

fn main() {
    print(pick(1))
    print(pick(0))
    print(pick(-1))
}
"#;

fn run(program: &std::path::Path, extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(extra)
        .arg(program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}

#[test]
fn optional_true_false_and_nil_render_the_same_in_both_engines() {
    let path = std::env::temp_dir().join(format!("tallow-optparity-{}.tl", std::process::id()));
    std::fs::write(&path, PROGRAM).expect("write program");

    let interpreted = run(&path, &["--interpret"]);
    let native = run(&path, &["--require-native"]);
    let _ = std::fs::remove_file(&path);

    let interp_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let native_out = String::from_utf8_lossy(&native.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();

    assert!(
        interpreted.status.success(),
        "interpreter leg failed:\n{interp_out}\n{}",
        String::from_utf8_lossy(&interpreted.stderr)
    );
    assert!(
        native.status.success(),
        "native leg failed — the optional lowering is not reachable:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );

    assert_eq!(
        interp_out, "true\nfalse\nnil\n",
        "the interpreter stopped distinguishing the three cases"
    );
    assert_eq!(
        native_out, interp_out,
        "the two engines disagree on an optional: native printed {native_out:?}"
    );
}

/// Presence and payload are different questions: a present `false` is falsy but
/// not absent. Both engines must answer `if` and `== nil` from the payload, not
/// from the pointer's non-nullness — the exact failure mode of the old `i64`
/// encoding, where `false` and `nil` were the same zero.
const PRESENCE_PROGRAM: &str = r#"
fn pick(n: i64) -> bool? {
    if n > 0 {
        return true
    }
    if n == 0 {
        return false
    }
    return nil
}

fn main() {
    let a = pick(1)
    let b = pick(0)
    let c = pick(-1)
    if a { print("a1") } else { print("a0") }
    if b { print("b1") } else { print("b0") }
    if c { print("c1") } else { print("c0") }
    print(a == nil)
    print(b == nil)
    print(c == nil)
    print(b == false)
    print(a == true)
}
"#;

#[test]
fn optional_truthiness_and_nil_equality_agree() {
    let path =
        std::env::temp_dir().join(format!("tallow-optpresence-{}.tl", std::process::id()));
    std::fs::write(&path, PRESENCE_PROGRAM).expect("write program");

    let interpreted = run(&path, &["--interpret"]);
    let native = run(&path, &["--require-native"]);
    let _ = std::fs::remove_file(&path);

    let interp_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let native_out = String::from_utf8_lossy(&native.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();

    assert!(
        interpreted.status.success(),
        "interpreter leg failed:\n{interp_out}\n{}",
        String::from_utf8_lossy(&interpreted.stderr)
    );
    assert!(
        native.status.success(),
        "native leg failed:\n{native_out}\n{native_err}"
    );
    assert!(
        !native_err.contains("native build unavailable"),
        "native leg fell back to the interpreter:\n{native_err}"
    );

    let expected = "a1\nb0\nc0\nfalse\nfalse\ntrue\ntrue\ntrue\n";
    assert_eq!(interp_out, expected, "interpreter presence semantics moved");
    assert_eq!(
        native_out, expected,
        "the native plane disagrees on optional presence: {native_out:?}"
    );
}

