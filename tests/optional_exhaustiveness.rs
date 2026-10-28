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

/// The *value* the guard leaves behind, not just its type.
///
/// The checker's narrowing was implemented on one plane only. Measured at
/// `c3ca375`, this program typechecked and then answered with two different
/// values depending on the plane:
///
/// ```text
/// tallow run prog.tl --interpret      -> x=6 / v=6 / in=6
/// tallow run prog.tl --require-native -> x=nil / v=nil / in=nil
/// ```
///
/// The emitter ignored `VarInfo::non_nil` and read the boxed
/// `%struct.Optional` pointer wherever the guard had proved a payload: into an
/// `i64` slot for `let x: i64 = v`, and into the string coercion for `{v}`,
/// which renders an unknown optional as the literal `nil`. Every read below is
/// one of those shapes, and all three must be the payload.
const GUARD_READS_THE_PAYLOAD: &str = r#"
fn maybe() -> i64? { return 6 }

fn main() {
    let v = maybe()
    if v == nil { return }
    let x: i64 = v
    print("x={x}")
    print("v={v}")
    if v != nil {
        print("in={v}")
    }
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

/// The value-side regression for the guard: a `nil`-checked optional read on
/// the compiled plane must be the payload. A `nil` here is the silent
/// wrong answer this test exists to make impossible.
#[test]
fn a_guarded_optional_reads_as_its_payload_on_both_planes() {
    let want = "x=6\nv=6\nin=6\n";
    let native = run(
        GUARD_READS_THE_PAYLOAD,
        "guard-payload-native",
        &["run", "--require-native"],
    );
    let interp = run(
        GUARD_READS_THE_PAYLOAD,
        "guard-payload-interp",
        &["run", "--interpret"],
    );
    assert!(
        native.status.success(),
        "native plane refused: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(
        interp.status.success(),
        "interpreter refused: {}",
        String::from_utf8_lossy(&interp.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        want,
        "the compiled plane did not read the payload the guard proved present"
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interp.stdout),
        "the planes disagree about the guarded value"
    );
}

/// The measured residual: the join of the two arms must consult the narrowing
/// the condition established. Inside `if m != nil { .. }` the visible type of
/// `m` is `i64`, so the true arm yields `i64` and the join with the `0` arm
/// yields `i64` — a plain slot. Both values are exercised, so the test proves
/// the program runs, not merely that the checker smiled.
const ARM_NARROWS: &str = r#"
fn maybe_i64(n: i64) -> i64? {
    if n == 0 { return nil }
    return n
}

fn main() {
    let a = maybe_i64(5)
    let va: i64 = if a != nil { a } else { 0 }
    print(va)
    let b = maybe_i64(0)
    let vb: i64 = if b != nil { b } else { 0 }
    print(vb)
}
"#;

/// The narrowing is a property of one arm, so it does not survive the join:
/// the else-branch is reached exactly when `m` is nil, and its `m` is the
/// optional again. Accepting this would be the runtime hole the rule exists to
/// close.
const ELSE_DOES_NOT_NARROW: &str = r#"
fn maybe_i64(n: i64) -> i64? {
    if n == 0 { return nil }
    return n
}

fn main() {
    let m = maybe_i64(5)
    let v: i64 = if m != nil { m } else { m }
    print(v)
}
"#;

/// The documented restriction: `var` never narrows, because the binding can be
/// reassigned to a fresh optional and the evidence would then be stale.
const VAR_DOES_NOT_NARROW: &str = r#"
fn maybe_i64(n: i64) -> i64? {
    if n == 0 { return nil }
    return n
}

fn main() {
    var m = maybe_i64(5)
    let v: i64 = if m != nil { m } else { 0 }
    print(v)
}
"#;

#[test]
fn the_nil_check_narrows_the_arm_so_the_join_is_plain() {
    let out = check(ARM_NARROWS, "arm-narrows");
    assert!(
        out.status.success(),
        "`if m != nil {{ m }} else {{ 0 }}` must fill an `i64` slot: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let want = "5\n0\n";
    let native = run(ARM_NARROWS, "arm-narrows-native", &["run", "--require-native"]);
    let interp = run(ARM_NARROWS, "arm-narrows-interp", &["run", "--interpret"]);
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        want,
        "native plane: refused={} stderr={}",
        !native.status.success(),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&interp.stdout),
        want,
        "interpreter: refused={} stderr={}",
        !interp.status.success(),
        String::from_utf8_lossy(&interp.stderr)
    );
}

#[test]
fn the_else_arm_is_not_narrowed_by_the_condition() {
    let out = check(ELSE_DOES_NOT_NARROW, "else-not-narrowed");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the else-branch is reached when `m` is nil, so the join is `i64?`: {err}"
    );
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
    assert!(
        err.contains("`i64?`") && err.contains("where `i64` is required"),
        "the message must name both types: {err}"
    );
}

#[test]
fn a_var_is_not_narrowed_by_the_branch_condition() {
    let out = check(VAR_DOES_NOT_NARROW, "var-not-narrowed");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a `var` may be reassigned, so the branch must not narrow it: {err}"
    );
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
}

/// The residual that made the help text self-contradictory: the narrowing
/// reached the binding rule but not the expression rule, so `let x: i64 = v`
/// was accepted after a guard while `v + 1` was refused — with the advice
/// "unwrap after checking for nil: `if v == nil { return }`".
///
/// Measured at `af67522`:
///
/// ```text
/// error[E0116]: cannot bind `i64?` where `i64` is required ... unwrap after
///               checking for nil: `if v == nil { return }` and use `v` after
///               the guard
/// error[E0110]: left operand of `+` must be numeric, got i64?
/// ```
///
/// Both planes answer 6 and 7 for it, so the refusal was the checker's alone.
const NARROWED_OPERAND: &str = r#"
fn maybe() -> i64? { return 6 }

fn main() {
    let v = maybe()
    if v == nil { return }
    print("v={v}")
    let x: i64 = v + 1
    print("x={x}")
}
"#;

/// The same narrowing, in the argument position: a parameter is a slot for a
/// plain value, and a guarded name fills it as the payload.
const NARROWED_ARGUMENT: &str = r#"
fn maybe() -> i64? { return 6 }

fn take(n: i64) {
    print(n)
}

fn main() {
    let v = maybe()
    if v == nil { return }
    take(v)
    take(v + 2)
}
"#;

/// The narrowed name in the remaining expression positions named by the rule:
/// a `return` expression and an index base.
const NARROWED_RETURN_AND_INDEX: &str = r#"
fn maybe() -> i64? { return 6 }

fn strict(a: i64?) -> i64 {
    if a == nil { return 0 }
    return a
}

fn main() {
    let v = maybe()
    if v == nil { return }
    let xs = [10, 20, 30]
    print(xs[v - 5])
    print(strict(maybe()))
}
"#;

/// The documented limit, in the shape that would otherwise look narrowed: a
/// `var` is reassignable, so the guard proves nothing about it and the
/// reassignment below hands it a fresh optional. Widening the expression rule
/// must not widen this.
const VAR_REASSIGNED_AFTER_GUARD: &str = r#"
fn maybe() -> i64? { return 6 }

fn main() {
    var v = maybe()
    if v == nil { return }
    v = maybe()
    let x: i64 = v + 1
    print("x={x}")
}
"#;

/// The non-guarded path, unchanged: no `nil` test dominates the use, so the
/// operand is still the optional and both codes fire.
const UNGUARDED_OPERAND: &str = r#"
fn maybe() -> i64? { return 6 }

fn main() {
    let v = maybe()
    let x: i64 = v + 1
    print("x={x}")
}
"#;

#[test]
fn a_narrowed_name_is_plain_in_the_operand_position() {
    let out = check(NARROWED_OPERAND, "narrowed-operand");
    assert!(
        out.status.success(),
        "a name a dominating guard narrowed must type as its payload in an operand: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let want = "v=6\nx=7\n";
    let native = run(
        NARROWED_OPERAND,
        "narrowed-operand-native",
        &["run", "--require-native"],
    );
    let interp = run(
        NARROWED_OPERAND,
        "narrowed-operand-interp",
        &["run", "--interpret"],
    );
    assert!(
        native.status.success(),
        "native plane refused: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(
        interp.status.success(),
        "interpreter refused: {}",
        String::from_utf8_lossy(&interp.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        want,
        "compiled plane printed the wrong values: stderr={}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interp.stdout),
        "the planes disagree about the guarded operand"
    );
}

#[test]
fn a_narrowed_name_fills_a_plain_parameter() {
    let out = check(NARROWED_ARGUMENT, "narrowed-argument");
    assert!(
        out.status.success(),
        "a guarded name must pass as the payload: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let native = run(
        NARROWED_ARGUMENT,
        "narrowed-argument-native",
        &["run", "--require-native"],
    );
    let interp = run(
        NARROWED_ARGUMENT,
        "narrowed-argument-interp",
        &["run", "--interpret"],
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        "6\n8\n",
        "native plane: refused={} stderr={}",
        !native.status.success(),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interp.stdout),
        "the planes disagree about the guarded argument"
    );
}

#[test]
fn a_narrowed_name_is_plain_in_return_and_index_positions() {
    let out = check(NARROWED_RETURN_AND_INDEX, "narrowed-return-index");
    assert!(
        out.status.success(),
        "a guarded name must be the payload as a return value and an index base: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let want = "20\n6\n";
    let native = run(
        NARROWED_RETURN_AND_INDEX,
        "narrowed-return-index-native",
        &["run", "--require-native"],
    );
    let interp = run(
        NARROWED_RETURN_AND_INDEX,
        "narrowed-return-index-interp",
        &["run", "--interpret"],
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        want,
        "native plane: refused={} stderr={}",
        !native.status.success(),
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&interp.stdout),
        "the planes disagree about the guarded return/index"
    );
}

#[test]
fn a_reassigned_var_is_still_refused_in_the_operand_position() {
    let out = check(VAR_REASSIGNED_AFTER_GUARD, "var-reassigned-after-guard");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a `var` may be reassigned after the guard, so it never narrows: {err}"
    );
    assert!(err.contains("E0116"), "the rule's code must be named: {err}");
    assert!(
        err.contains("E0110"),
        "the operand must still be seen as the optional: {err}"
    );
}

#[test]
fn an_unguarded_operand_is_still_refused() {
    let out = check(UNGUARDED_OPERAND, "unguarded-operand");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "without a dominating guard the operand is still the optional: {err}"
    );
    assert!(err.contains("E0116"), "E0116 must still fire: {err}");
    assert!(err.contains("E0110"), "E0110 must still fire: {err}");
    assert!(
        err.contains("`i64?`"),
        "the message must still name the optional type: {err}"
    );
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
