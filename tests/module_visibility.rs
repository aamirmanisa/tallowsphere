//! G09 — module visibility (`docs/spec/MODULE-VISIBILITY.md`).
//!
//! Visibility is decided at import resolution, which is a full-pipeline phase:
//! a unit test on the parser or the checker would prove the marker parses and
//! nothing about what a user sees. Every test here runs the real binary on a
//! fixture package, so the assertion is on the refusal (or the program's
//! output) that actually happens.
//!
//! Package = the directory tree rooted at the entry file's directory. The
//! fixtures place the entry at `<case>/src/main.tl`, so `<case>/src/*.tl` is
//! in-package and `<case>/*.tl` is out of it.

use std::process::Command;

fn fixture(relative: &str) -> String {
    format!(
        "{}/tests/fixtures/module_visibility/{relative}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Run the compiled `tallow` binary: (exit ok, stdout, stderr).
fn tallow(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(args)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn check(relative: &str) -> (bool, String) {
    let (ok, _stdout, stderr) = tallow(&["check", &fixture(relative)]);
    (ok, stderr)
}

fn run(relative: &str) -> (bool, String, String) {
    tallow(&["run", &fixture(relative)])
}

// ── E0153 — importing an item that is not visible ────────────────────────────

#[test]
fn a_private_function_is_refused_with_e0153() {
    // `wire.tl` declares `fn helper` with no marker: it is visible only inside
    // wire.tl, and `main.tl` calls it.
    let (ok, stderr) = check("private_refused/src/main.tl");
    assert!(
        !ok,
        "a call to a private item must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0153"),
        "the refusal must carry the private-import code:\n{stderr}"
    );
    assert!(
        stderr.contains("`helper` is private to paths.tl")
            || stderr.contains("`helper` is private to src/wire.tl"),
        "the refusal must name the item and the file that declares it:\n{stderr}"
    );
    assert!(
        stderr.contains("src/main.tl:"),
        "the refusal must point at the use in the importing file:\n{stderr}"
    );
    assert!(
        stderr.contains("mark it `pub`"),
        "the refusal must say how to fix it:\n{stderr}"
    );
}

#[test]
fn pub_crate_is_refused_outside_the_package() {
    // The module resolves to `<case>/paths.tl`, which is outside the package
    // rooted at the entry file's directory (`<case>/src`).
    let (ok, stderr) = check("pubcrate_out_of_package/src/main.tl");
    assert!(
        !ok,
        "a `pub(crate)` item must not cross a package boundary:\n{stderr}"
    );
    assert!(
        stderr.contains("E0153"),
        "the refusal must carry the private-import code:\n{stderr}"
    );
    assert!(
        stderr.contains("`normalise` is `pub(crate)` in paths.tl")
            || stderr.contains("`normalise` is `pub(crate)` in pubcrate_out_of_package/paths.tl"),
        "the refusal must name the marker and the declaring file:\n{stderr}"
    );
    assert!(
        stderr.contains("outside that package"),
        "the refusal must say which rule stopped it:\n{stderr}"
    );
}

// ── What does cross the boundary ────────────────────────────────────────────

#[test]
fn a_pub_function_is_imported_and_called() {
    let (ok, stderr) = check("pub_imported/src/main.tl");
    assert!(ok, "a `pub` item must cross the boundary:\n{stderr}");
    assert!(
        !stderr.contains("E0153"),
        "no visibility refusal expected:\n{stderr}"
    );

    // The point of merging is that the call binds and runs.
    let (ran, stdout, stderr) = run("pub_imported/src/main.tl");
    assert!(ran, "the imported `pub` function must run:\n{stderr}");
    assert_eq!(stdout.trim(), "7", "the imported function's result");
}

#[test]
fn pub_crate_is_visible_inside_the_package() {
    // `paths.tl` sits beside the entry file, inside the entry file's directory.
    let (ok, stderr) = check("pubcrate_in_package/src/main.tl");
    assert!(
        ok,
        "a `pub(crate)` item must be visible inside its package:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0153"),
        "no visibility refusal expected:\n{stderr}"
    );

    let (ran, stdout, stderr) = run("pubcrate_in_package/src/main.tl");
    assert!(ran, "the in-package call must run:\n{stderr}");
    assert_eq!(stdout.trim(), "crate-visible", "the imported function's result");
}

#[test]
fn a_pub_struct_is_constructible_from_the_importer() {
    let (ok, stderr) = check("pub_struct/src/main.tl");
    assert!(
        ok,
        "a `pub struct` must be usable by the importer:\n{stderr}"
    );

    let (ran, stdout, stderr) = run("pub_struct/src/main.tl");
    assert!(ran, "the importer must construct the struct:\n{stderr}");
    assert_eq!(stdout.trim(), "8080", "the field readback");
}

// ── E0154 — `pub` on an import ──────────────────────────────────────────────

#[test]
fn pub_import_is_refused_with_e0154() {
    // Re-exports are out of scope for 2.0; the marker is refused rather than
    // silently ignored.
    let (ok, stderr) = check("pub_import_refused/src/main.tl");
    assert!(!ok, "`pub import` must not compile:\n{stderr}");
    assert!(
        stderr.contains("E0154"),
        "the refusal must carry the re-export code:\n{stderr}"
    );
    assert!(
        stderr.contains("`pub import` is not supported"),
        "the refusal must name the rule:\n{stderr}"
    );
}

// ── The marker is contextual ────────────────────────────────────────────────

#[test]
fn pub_is_a_valid_identifier() {
    // `pub` is not a keyword: a function name, a parameter name and a binding
    // named `pub` all stay ordinary.
    let (ok, stderr) = check("pub_identifier/src/main.tl");
    assert!(
        ok,
        "`pub` must remain usable as an ordinary identifier:\n{stderr}"
    );

    let (ran, stdout, stderr) = run("pub_identifier/src/main.tl");
    assert!(ran, "the program must run:\n{stderr}");
    assert_eq!(stdout.trim(), "42", "the program's output");
}
