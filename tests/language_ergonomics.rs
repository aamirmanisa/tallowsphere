//! Conformance for two 2.0 ergonomics items, exercised through the real
//! binary because both are properties of what a user sees:
//!
//! * G04 — a non-exhaustive `match` names the variant(s) no arm handles, at the
//!   match site, for `Result`/`T?` as well as for a declared enum.
//! * G08 — `break 'outer v` delivers `v` as the value of the labeled `loop`.
//!
//! Run: `cargo test --test language_ergonomics`.

use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn check(name: &str) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("check")
        .arg(fixture(name))
        .output()
        .expect("run tallow check");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run(name: &str) -> (i32, String, String) {
    run_with(name, &[])
}

fn run_with(name: &str, extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .args(extra)
        .arg(fixture(name))
        .output()
        .expect("run tallow run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn g04_names_the_missing_variant_of_an_enum_and_of_a_result() {
    let (code, stderr) = check("g04_exhaustiveness.tl");

    // A warning, not a refusal: the program still compiles and runs, which is
    // what W0120 has always meant in this compiler.
    assert_eq!(code, 0, "warnings must not fail `check`:\n{stderr}");

    assert!(
        stderr.contains("missing variant(s): Retired"),
        "the enum arm set must be diffed and the gap named:\n{stderr}"
    );
    assert!(
        stderr.contains("missing variant(s): Err"),
        "`Result` must be diffed as Ok/Err and the gap named:\n{stderr}"
    );
    assert!(
        !stderr.contains("Ok,"),
        "a covered variant must not be listed as missing:\n{stderr}"
    );
    assert!(
        stderr.contains("g04_exhaustiveness.tl:12:5"),
        "the enum report must be anchored at its own match site (12:5):\n{stderr}"
    );
    assert!(
        stderr.contains("g04_exhaustiveness.tl:19:5"),
        "the Result report must be anchored at its own match site (19:5):\n{stderr}"
    );
}

#[test]
fn g08_labeled_break_delivers_its_value() {
    let (code, stdout, stderr) = run("g08_labeled_break.tl");
    assert_eq!(
        code, 0,
        "a labeled break with a value must run cleanly:\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "40",
        "the loop must evaluate to the value of `break 'search n * 10`:\n{stdout}"
    );
}

/// The two engines must agree on labeled-break output. `run` uses native
/// codegen first and the interpreter only as a fallback, so a regression in
/// one leg is invisible unless both are asked for explicitly.
#[test]
fn g08_native_and_interpreter_agree_on_labeled_break() {
    let (n_code, n_out, n_err) = run("g08_labeled_break.tl");
    let (i_code, i_out, i_err) = run_with("g08_labeled_break.tl", &["--interpret"]);

    // The interpreter announces itself on stderr; the native leg must not have
    // silently fallen back, or this test would compare the interpreter twice.
    assert!(
        !n_err.contains("running in the interpreter")
            && !n_err.contains("native build unavailable")
            && !n_err.contains("re-running in the interpreter"),
        "the native leg must not fall back to the interpreter:\n{n_err}"
    );

    assert_eq!(i_code, 0, "interpreter must run cleanly:\n{i_err}");
    assert_eq!(
        n_out, i_out,
        "engines disagree on labeled-break output (native rc={n_code}, interp rc={i_code})"
    );
}
