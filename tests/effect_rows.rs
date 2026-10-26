//! G01 — effect rows (blueprint §2.1 / §4), the P0 gate.
//!
//! A function body that calls a socket-opening primitive must declare the
//! effect in its signature; `with Net(connect)` on the signature is what makes
//! the call legal. The refusal (`E0141`) is reported at the call site.
//!
//! Every fixture passes `@legal` so the pre-existing @legal gate (`E0100`) can
//! never be what the assertion is reading — the only difference between the
//! negative and the positive fixture is the effect row.

use std::process::Command;

fn fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/effect_rows/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Run `tallow check <fixture>` and return (success, stderr).
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
fn negative_socket_call_without_row_is_refused() {
    let (ok, stderr) = check("no_row.tl");
    assert!(
        !ok,
        "a socket call without a row must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0141"),
        "the refusal must carry code E0141:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "function body requires effect Net(connect) but the signature does not declare it"
        ),
        "the refusal must name the effect and the operation:\n{stderr}"
    );
    assert!(
        stderr.contains("help: add: with Net(connect)"),
        "the refusal must say how to fix it:\n{stderr}"
    );
    // The gate is the effect row, not the older @legal rule.
    assert!(
        !stderr.contains("E0100"),
        "fixture carries @legal, so E0100 must not fire:\n{stderr}"
    );
}

#[test]
fn positive_same_body_with_row_compiles() {
    let (ok, stderr) = check("with_row.tl");
    assert!(ok, "`with Net(connect)` must satisfy the gate:\n{stderr}");
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
}

#[test]
fn unannotated_also_fails() {
    // Different callee shape: a static method on a type name, not a module path.
    let (ok, stderr) = check("unannotated_also_fails.tl");
    assert!(
        !ok,
        "`Tcp.connect` without a row must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0141"),
        "the refusal must carry code E0141:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "function body requires effect Net(connect) but the signature does not declare it"
        ),
        "the refusal must name the effect and the operation:\n{stderr}"
    );
}

#[test]
fn multi_entry_row_parses_and_satisfies() {
    // `with Net(connect), Net(read)` — two rows, comma separated.
    let (ok, stderr) = check("with_multi_row.tl");
    assert!(
        ok,
        "a two-entry row must parse and satisfy the gate:\n{stderr}"
    );
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
}
