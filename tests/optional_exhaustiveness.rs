//! Register #136: an optional reaches a plain slot only through an unwrap.
//!
//! The rule, as decided: a `T?` may fill a `T` destination only through an
//! explicit unwrap (there is no `??` operator in this language -- `match`, or
//! `if let`, is the read side) or through a `nil` check that *dominates* the
//! use. Anything else is a type error at the destination.
//!
//! Why it has to be a check-time error rather than a late one: the two
//! execution planes disagreed. Measured at `b205b51` (the revision this branch
//! was cut from), on `fn want() -> i64 { return maybe_i64() }`:
//!
//! ```text
//! tallow check        -> exit 0        (accepted the program)
//! tallow run --interpret -> prints nil  (answers `nil` for an i64)
//! tallow run --require-native -> exit 1 ("cannot use an optional where a
//!                                        plain value is expected (Optional ->
//!                                        I64)")
//! ```
//!
//! So the checker accepted what the shipping plane refuses and the fallback
//! plane quietly answered with a value of the wrong type. Register #136 was
//! recorded as the `let`/`var`/assignment positions only (`E0116`); the
//! return, tail-expression and argument positions were still open, and a
//! dominating guard was still rejected as if the check had not happened.
//!
//! `T` into `T?` stays implicit -- that is register #135, and it is asserted
//! here so this rule cannot be widened into breaking it.

const REFUSED_BIND: &str = r#"
fn maybe_i64() -> i64? {
    return nil
}

fn main() {
    let x: i64 = maybe_i64()
    print(x)
}
"#;

const REFUSED_RETURN: &str = r#"
fn maybe_i64() -> i64? {
    return nil
}

fn want() -> i64 {
    return maybe_i64()
}

fn main() {
    print(want())
}
"#;

const REFUSED_ARGUMENT: &str = r#"
fn maybe_i64() -> i64? {
    return nil
}

fn take(v: i64) {
    print(v)
}

fn main() {
    take(maybe_i64())
    take(7)
}
"#;

/// `if m == nil { return }` leaves the function on the absent branch, so every
/// later statement is reached only with `m` present.
const GUARDED: &str = r#"
fn find(n: i64) -> i64? {
    if n == 0 { return nil }
    return n
}

fn main() {
    let m = find(5)
    if m == nil { return }
    let x: i64 = m
    print(x)
}
"#;

/// The guard is on `x` itself: the source of the refused binding is the same
/// expression the test named, which is the shape the register describes.
const GUARDED_DIRECT: &str = r#"
fn find(n: i64) -> i64? {
    if n == 0 { return nil }
    return n
}

fn main() {
    let m = find(5)
    if m == nil { return }
    print(m)
}
"#;

/// The wrap direction (#135): a plain value into an optional slot.
const WRAPS: &str = r#"
fn show(v: i64?) {
    print(v)
    print(v == nil)
}

fn src(n: i64) -> i64? {
    return n
}

fn main() {
    let a = 42
    show(a)
    show(src(7))
}
"#;

/// A `nil` test whose branch does *not* leave the function proves nothing about
/// the code after it, so the binding stays refused. Without this case the rule
/// could pass by looking only for the presence of a `nil` test.
const NON_DOMINATING: &str = r#"
fn find(n: i64) -> i64? {
    if n == 0 { return nil }
    return n
}

fn main() {
    let m = find(5)
    if m == nil { print("absent") }
    let x: i64 = m
    print(x)
}
"#;

#[test]
fn binding_a_plain_local_from_an_optional_is_refused() {
    let out = check(REFUSED_BIND, "refused-bind");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "check accepted a `T?` binding into a `T`: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
    assert!(
        err.contains("`i64?`"),
        "the message must name the optional source type: {err}"
    );
    assert!(
        err.contains("where `i64` is required"),
        "the message must name the destination type: {err}"
    );
    assert!(
        err.contains("unwrap after checking for nil"),
        "the message must name the fix: {err}"
    );
    assert!(
        err.contains("maybe_i64()"),
        "the message must name the expression that produced the optional: {err}"
    );
}

#[test]
fn a_dominating_nil_check_makes_the_binding_legal() {
    let out = check(GUARDED, "guarded");
    assert!(
        out.status.success(),
        "a `nil` check that dominates the use must be accepted: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_nil_check_that_does_not_dominate_is_still_refused() {
    let out = check(NON_DOMINATING, "non-dominating");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a `nil` test whose branch falls through proves nothing: {err}"
    );
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
}

#[test]
fn returning_an_optional_where_a_plain_value_is_required_is_refused() {
    let out = check(REFUSED_RETURN, "refused-return");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "check accepted an unchecked return: {err}");
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
    assert!(
        err.contains("cannot return `i64?` where `i64` is required"),
        "the message must name the position and both types: {err}"
    );
}

#[test]
fn passing_an_optional_to_a_plain_parameter_is_refused() {
    let out = check(REFUSED_ARGUMENT, "refused-argument");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "check accepted an unchecked argument: {err}");
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
    assert!(
        err.contains("`i64?`") && err.contains("where `i64` is required"),
        "the message must name both types: {err}"
    );
}

#[test]
fn a_plain_value_still_wraps_into_an_optional() {
    let out = check(WRAPS, "wraps");
    assert!(
        out.status.success(),
        "register #135 must stay green: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let native = run(WRAPS, "wraps-native", &["run", "--require-native"]);
    let interp = run(WRAPS, "wraps-interp", &["run", "--interpret"]);
    let want = "42\nfalse\n7\nfalse\n";
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        want,
        "native plane: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&interp.stdout),
        want,
        "interpreter: {}",
        String::from_utf8_lossy(&interp.stderr)
    );
}

#[test]
fn the_refused_program_fails_on_the_interpreter_too() {
    // The point of the rule: the two planes must agree about the program. Before
    // the rule the interpreter ran it and printed `nil` for an `i64`; now both
    // planes refuse it, and they refuse it with the same diagnosis.
    for (plane, args) in [
        ("native", ["run", "--require-native"].as_slice()),
        ("interp", ["run", "--interpret"].as_slice()),
    ] {
        let out = run(REFUSED_RETURN, &format!("refused-run-{plane}"), args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{plane}: a refused program must exit 1, stdout was {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).is_empty(),
            "{plane}: the refused program must print nothing"
        );
        assert!(
            err.contains("E0116"),
            "{plane}: the diagnosis must be the checker's: {err}"
        );
    }
}

#[test]
fn a_guarded_program_prints_identical_stdout_on_both_planes() {
    for (tag, program) in [("guarded", GUARDED), ("guarded-direct", GUARDED_DIRECT)] {
        let native = run(program, &format!("{tag}-native"), &["run", "--require-native"]);
        let interp = run(program, &format!("{tag}-interp"), &["run", "--interpret"]);
        assert!(
            native.status.success(),
            "{tag}: native plane refused: {}",
            String::from_utf8_lossy(&native.stderr)
        );
        assert!(
            interp.status.success(),
            "{tag}: interpreter refused: {}",
            String::from_utf8_lossy(&interp.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&native.stdout), "5\n", "{tag}");
        assert_eq!(
            String::from_utf8_lossy(&native.stdout),
            String::from_utf8_lossy(&interp.stdout),
            "{tag}: the planes disagree"
        );
    }
}

fn check(program: &str, tag: &str) -> std::process::Output {
    run(program, tag, &["check"])
}

fn run(program: &str, tag: &str, args: &[&str]) -> std::process::Output {
    let path = std::env::temp_dir().join(format!(
        "tallow-optional-exhaustiveness-{tag}-{}.tl",
        std::process::id()
    ));
    std::fs::write(&path, program).expect("write program");
    std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow")
}
