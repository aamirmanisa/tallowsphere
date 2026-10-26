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

#[test]
fn indirect_call_without_row_is_refused_at_the_call_site() {
    // `outer` names no socket family; it reaches one only through `probe`,
    // whose declared row `Net(connect)` is the caller's requirement too.
    let (ok, stderr) = check("indirect_without_row.tl");
    assert!(
        !ok,
        "a body that reaches a socket through a user function must not compile:\n{stderr}"
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
    // The span is the call in the caller, not the callee's declaration
    // (`probe` is on line 8). Anything else tells the author to edit the
    // wrong function.
    assert!(
        stderr.contains("indirect_without_row.tl:14:"),
        "the refusal must be reported at the call in `outer` (line 14):\n{stderr}"
    );
    assert!(
        !stderr.contains("E0100"),
        "fixture carries @legal, so E0100 must not fire:\n{stderr}"
    );
}

#[test]
fn indirect_call_with_row_on_the_caller_compiles() {
    let (ok, stderr) = check("indirect_with_row.tl");
    assert!(
        ok,
        "`with Net(connect)` on the caller must satisfy the forwarded row:\n{stderr}"
    );
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
}

// ── G01 P0.2 — `Grant<Net>` as a lattice capability type ─────────────────────
//
// The row says what a body does; the grant says where the authority came from.
// Both are required, and the grant is a *value*: it cannot be declared into
// existence, only obtained from `scope.grant` (or taken as a parameter).

#[test]
fn grant_parameter_satisfies_the_row() {
    let (ok, stderr) = check("grant_param_satisfies_row.tl");
    assert!(
        ok,
        "a `Grant<Net>` parameter must authorise the call:\n{stderr}"
    );
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
    assert!(!stderr.contains("E0142"), "no E0142 expected:\n{stderr}");
}

#[test]
fn declared_row_without_a_grant_is_refused() {
    let (ok, stderr) = check("row_without_grant_is_refused.tl");
    assert!(
        !ok,
        "a declared row with no `Grant<Net>` in scope must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0142"),
        "the refusal must carry code E0142:\n{stderr}"
    );
    // The row *is* declared, so E0141 must not be what fired: the missing
    // authority is the finding, not the missing declaration.
    assert!(
        !stderr.contains("E0141"),
        "the row is declared, so E0141 must not fire:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "effect Net(connect) requires a Grant<Net> in scope; take one as a parameter or obtain it with scope.grant(Net)"
        ),
        "the refusal must name the effect, the capability and both fixes:\n{stderr}"
    );
}

#[test]
fn main_is_the_trust_root_and_may_grant_itself() {
    let (ok, stderr) = check("main_may_grant_itself.tl");
    assert!(
        ok,
        "`main` obtains its own grant from scope.grant and needs no incoming one:\n{stderr}"
    );
    assert!(!stderr.contains("E0142"), "no E0142 expected:\n{stderr}");
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
}

#[test]
fn grant_is_not_forgeable() {
    let (ok, stderr) = check("grant_is_not_forgeable.tl");
    assert!(
        !ok,
        "a capability cannot be constructed or coerced into existence:\n{stderr}"
    );
    // The gate is assignability: there is no literal, cast or default for the
    // type, so a struct value and an `int` both fail to bind.
    assert!(
        stderr.contains("E0117"),
        "the refusal must carry code E0117:\n{stderr}"
    );
    assert!(
        stderr.contains("Grant<Net>"),
        "the refusal must name the capability type:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0142"),
        "the forgery, not a missing grant, is the finding:\n{stderr}"
    );
}

#[test]
fn grant_of_an_unknown_effect_is_refused() {
    let (ok, stderr) = check("grant_wrong_effect.tl");
    assert!(
        !ok,
        "`Grant<Bogus>` names an effect no pass enforces and must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0143"),
        "the refusal must carry code E0143:\n{stderr}"
    );
    assert!(
        stderr.contains("unknown effect `Bogus` in capability type"),
        "the refusal must name the unknown effect:\n{stderr}"
    );
}
