//! The three open findings from capability audit round 2 that are not bypasses:
//! N-9 (an imported item's span rendered against the entry file), N-10 (a
//! missing import dropped silently) and N-12 (E0146 false-positive on a user
//! function named like a module).
//!
//! Each test runs the real binary: these are diagnostics-shape properties, and
//! a unit test on the checker would not prove what a user sees.

use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/checker/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn check(name: &str) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("check")
        .arg(fixture(name))
        .output()
        .expect("run tallow check");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_user_function_named_like_a_module_is_a_value() {
    // N-12: `db` is a registered stdlib module name, but this program declares
    // `fn db`. A declaration shadows the module for value positions, exactly as
    // a local does; only the module table was consulted.
    let (ok, stderr) = check("n12_fn_named_like_module.tl");
    assert!(
        ok,
        "a user function named like a module must not be refused as a namespace:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0146"),
        "no namespace diagnostic expected:\n{stderr}"
    );
}

#[test]
fn an_import_that_resolves_to_no_file_is_refused() {
    // N-10: the import was dropped on the floor, so the program compiled
    // against a module it never loaded.
    let (ok, stderr) = check("n10_missing_import.tl");
    assert!(
        !ok,
        "an unresolvable import must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0149"),
        "the refusal must carry the unresolved-import code:\n{stderr}"
    );
    assert!(
        stderr.contains("cannot resolve import 'nosuchmodule'"),
        "the refusal must name the import:\n{stderr}"
    );
}

#[test]
fn an_imported_main_is_rendered_against_its_own_file() {
    // N-9: the refusal was right and the caret was drawn against the entry
    // file's text, pointing at an unrelated line.
    let (ok, stderr) = check("n9_imported_main_entry.tl");
    assert!(
        !ok,
        "an imported `main` must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0147"),
        "the refusal must carry the trust-root code:\n{stderr}"
    );
    assert!(
        stderr.contains("n9_imported_main_lib.tl:3:1"),
        "the location line must name the imported file and its own line:\n{stderr}"
    );
    assert!(
        stderr.contains("LIB_ONLY_MARKER_n9"),
        "the quoted source line must come from the imported file, not the entry file:\n{stderr}"
    );
    assert!(
        !stderr.contains("print(\"entry\")"),
        "the entry file's text must not be quoted for an imported span:\n{stderr}"
    );
}
