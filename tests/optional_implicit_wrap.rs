//! Implicit wrapping into an optional, on the compiled plane (register #135).
//!
//! The interpreter always wrapped implicitly: `return a` from a `-> i64?`
//! function, an i64 argument to an `i64?` parameter, `let x: T? = v`. The
//! compiler refused all of these with "optional values have no native lowering
//! yet (I64 -> Optional)" whenever the value was not a literal, which made the
//! natural program fail on the plane that ships. Boxing is now implicit on both
//! planes.
//!
//! What is *not* covered here, because it is the other direction (register
//! #136): a `T?` reaching a `T` destination. That is a type-checker rule, not a
//! wrapping problem, and it is asserted in `tests/optional_exhaustiveness.rs`
//! — including the two planes agreeing on the refusal.

const WRAP: &str = r#"
fn show(v: i64?) {
    print(v)
    print(v == nil)
}

fn src(n: i64) -> i64? {
    return n
}

fn name_or_none(s: String) -> String? {
    if s == "" { return nil }
    return s
}

fn main() {
    let a = 42
    show(a)
    show(src(7))
    print(name_or_none("ok"))
    print(name_or_none("") == nil)
}
"#;

#[test]
fn a_variable_wraps_into_an_optional_on_both_planes() {
    let native = run(WRAP, "native", &["run", "--require-native"]);
    assert!(
        native.status.success(),
        "native plane refused: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    let interp = run(WRAP, "interp", &["run", "--interpret"]);
    assert!(interp.status.success(), "interpreter refused");

    let want = "42\nfalse\n7\nfalse\nok\ntrue\n";
    assert_eq!(String::from_utf8_lossy(&native.stdout), want);
    assert_eq!(String::from_utf8_lossy(&interp.stdout), want);
}

fn run(program: &str, tag: &str, args: &[&str]) -> std::process::Output {
    let path = std::env::temp_dir().join(format!("tallow-optional-wrap-{tag}.tl"));
    std::fs::write(&path, program).expect("write program");
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}
