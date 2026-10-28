//! Braces in string literals: `{{` is a literal `{`, `}}` is a literal `}`.
//!
//! MEASURED at `b205b51`: `print("{\"a\":1}")` failed with
//! `unexpected character: '\'` — the `{` opened an interpolation — and
//! `print("{{a}}")` warned `W0102: possibly undefined variable a`, so `{{` was
//! not an escape. No JSON literal could be written in Tallow source at all.
//!
//! Both planes are exercised whenever the program is accepted (compiled native
//! and the tree-walking interpreter), because a source rule that only one plane
//! honours is not a rule.

use std::process::{Command, Output};

const NATIVE: &[&str] = &["--require-native"];
const INTERPRETED: &[&str] = &["--interpret"];

/// Run `program` through `tallow run` with `flags`, from a unique temp file.
///
/// `tag` keeps concurrent tests from colliding on the same path.
fn run(program: &str, flags: &[&str], tag: &str) -> Output {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    program.hash(&mut h);
    let path = std::env::temp_dir().join(format!("tallow-braces-{:016x}-{tag}.tl", h.finish()));
    std::fs::write(&path, program).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(flags)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    out
}

/// Run a program that must be accepted, and require byte-identical stdout from
/// both planes plus the exact expected text.
fn assert_both_planes_print(program: &str, expected: &str, tag: &str) {
    let native = run(program, NATIVE, &format!("{tag}-native"));
    let interpreted = run(program, INTERPRETED, &format!("{tag}-interp"));

    let native_out = String::from_utf8_lossy(&native.stdout).to_string();
    let interp_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let native_err = String::from_utf8_lossy(&native.stderr).to_string();
    let interp_err = String::from_utf8_lossy(&interpreted.stderr).to_string();

    assert!(
        native.status.success(),
        "{tag}: native plane failed ({}): {native_err}",
        native.status
    );
    assert!(
        interpreted.status.success(),
        "{tag}: interpreter plane failed ({}): {interp_err}",
        interpreted.status
    );
    assert_eq!(
        native_out, interp_out,
        "{tag}: the planes disagree — native {native_out:?} vs interpreter {interp_out:?}"
    );
    assert_eq!(
        native_out, expected,
        "{tag}: printed {native_out:?}, expected {expected:?}"
    );
}

// ── 1. literal braces ───────────────────────────────────────────────────────

#[test]
fn escaped_braces_print_the_braces() {
    // The case the defect was filed for: a JSON body. `\"` still escapes inside
    // a literal run, and `{{`/`}}` supply the braces.
    let program = r#"
fn main() {
    print("{{\"a\":1}}")
}
"#;
    assert_both_planes_print(program, "{\"a\":1}\n", "json");
}

#[test]
fn escaped_braces_with_a_colon_and_digits() {
    // `{a:1}` would read as interpolation `a` followed by a specifier `1`; with
    // the escapes it is inert text on both planes.
    let program = r#"
fn main() {
    print("{{a:1}}")
}
"#;
    assert_both_planes_print(program, "{a:1}\n", "braces-text");
}

#[test]
fn escaped_braces_do_not_warn_as_a_variable() {
    // At b205b51 this warned `W0102: possibly undefined variable a` — proof
    // that `{{` was not an escape. Silence on stderr is the assertion.
    let program = r#"
fn main() {
    print("{{a}}")
}
"#;
    let out = run(program, NATIVE, "no-warn");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "run failed: {stderr}");
    assert!(
        !stderr.contains("W0102"),
        "escaped braces must not be read as a variable: {stderr}"
    );
}

// ── 2. interpolation next to escaped braces ─────────────────────────────────

#[test]
fn interpolation_still_works_beside_escaped_braces() {
    let program = r#"
fn main() {
    let x = 7
    print("{{x}} = {x}")
}
"#;
    assert_both_planes_print(program, "{x} = 7\n", "mixed");
}

#[test]
fn escaped_braces_after_an_interpolation() {
    // `scan_string_continuation` resumes literal text after `}`; `}}` there must
    // also be an escape, and a `{` must still open a second interpolation.
    let program = r#"
fn main() {
    let a = 1
    let b = 2
    print("{a}{{}}, }}{b}")
}
"#;
    assert_both_planes_print(program, "1{}, }2\n", "continuation");
}

#[test]
fn escaped_quote_inside_a_literal_run_still_works() {
    // Named in the task as verified at b205b51; it must keep working now that
    // the brace branches sit next to the escape branch.
    let program = r#"
fn main() {
    print("he said \"hi\"")
}
"#;
    assert_both_planes_print(program, "he said \"hi\"\n", "quote");
}

// ── 3. a stray `}` names the escape ─────────────────────────────────────────

#[test]
fn stray_closing_brace_is_refused_by_name() {
    let program = r#"
fn main() {
    print("a } b")
}
"#;
    for flags in [NATIVE, INTERPRETED] {
        let out = run(program, flags, "stray");
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            !out.status.success(),
            "a stray `}}` must not be accepted (flags {flags:?}); stderr: {stderr}"
        );
        assert!(
            stderr.contains("write `}}` for a literal brace"),
            "the refusal must name the escape (flags {flags:?}); stderr: {stderr}"
        );
    }
}
