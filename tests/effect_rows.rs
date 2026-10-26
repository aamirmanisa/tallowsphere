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

// ── G01 P0.2 — authority may only be originated in `main` (E0144) ─────────────
//
// The row half of P0.2 says what a body does; the grant half says where the
// authority came from. `scope.grant` is the only producer of a capability, so
// confining it to `main` is what stops a helper from printing its own.

#[test]
fn grant_outside_main_is_refused() {
    // `helper` declares the row *and* grants itself: before E0144 it satisfied
    // both halves of the rule while never being handed any authority.
    let (ok, stderr) = check("grant_only_in_main.tl");
    assert!(
        !ok,
        "a body that is not `main` must not originate authority:\n{stderr}"
    );
    assert!(
        stderr.contains("E0144"),
        "the refusal must carry code E0144:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "authority may only be originated in main; take a Grant<Net> parameter instead"
        ),
        "the refusal must name the rule and the fix:\n{stderr}"
    );
    // The finding is the origin of authority, not a missing row or a missing
    // grant: `helper` declares `Net(connect)` and holds a grant value.
    assert!(
        !stderr.contains("E0141"),
        "the row is declared, so E0141 must not fire:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0142"),
        "the grant is in scope, so E0142 must not fire:\n{stderr}"
    );
    // The span is the `scope.grant` call in `helper` (line 10), not `main`'s
    // legitimate grant further down.
    assert!(
        stderr.contains("grant_only_in_main.tl:10:"),
        "the refusal must be reported at the offending scope.grant call:\n{stderr}"
    );
}

#[test]
fn grant_threaded_from_main_compiles() {
    // The shape every network helper must have: `main` originates the
    // capability, the helper takes it as a parameter and declares its row.
    let (ok, stderr) = check("grant_param_threaded.tl");
    assert!(
        ok,
        "a `Grant<Net>` threaded from main must authorise the helper:\n{stderr}"
    );
    assert!(!stderr.contains("E0144"), "no E0144 expected:\n{stderr}");
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
    assert!(!stderr.contains("E0142"), "no E0142 expected:\n{stderr}");
}

// ── F-2…F-7: `Grant<E>` is unfabricable in every position ────────────────────
//
// The assignability rule (E0117) used to run only where `let`/`var` binds a
// value. These fixtures cover the remaining producer and consumer positions:
// return expressions, struct-literal fields, `native fn` signatures, default
// parameter values and call arguments. Each one is the audit's reproduction.

/// A refusal must carry `code` and must not be the row/grant gates, which are
/// satisfied in these fixtures by construction.
fn assert_refused_with(name: &str, code: &str) -> String {
    let (ok, stderr) = check(name);
    assert!(!ok, "{name} must be refused:\n{stderr}");
    assert!(
        stderr.contains(code),
        "{name} must be refused with {code}:\n{stderr}"
    );
    assert!(
        stderr.contains("Grant<Net>"),
        "{name}: the refusal must name the capability type:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0141"),
        "{name}: the row is declared, so E0141 must not fire:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0142"),
        "{name}: a grant is in scope at the call, so E0142 must not fire:\n{stderr}"
    );
    stderr
}

#[test]
fn return_position_forgery_is_refused() {
    // F-2: `fn mk() -> Grant<Net> { 0 }` — the tail expression is the return
    // value and must be assignable to the declared type.
    let stderr = assert_refused_with("forge_return_int.tl", "E0117");
    assert!(
        stderr.contains("forge_return_int.tl:9:"),
        "the refusal must be reported at the forged tail expression:\n{stderr}"
    );
}

#[test]
fn explicit_return_forgery_is_refused() {
    // F-3: the same forgery through `return <expr>`.
    let stderr = assert_refused_with("forge_return_str.tl", "E0117");
    assert!(
        stderr.contains("forge_return_str.tl:8:"),
        "the refusal must be reported at the explicit return:\n{stderr}"
    );
}

#[test]
fn struct_field_forgery_is_refused() {
    // F-4: `Holder { g: 7 }` — a field initialiser is a producer position.
    let stderr = assert_refused_with("forge_struct_field.tl", "E0117");
    assert!(
        stderr.contains("forge_struct_field.tl:13:"),
        "the refusal must be reported at the field initialiser:\n{stderr}"
    );
}

#[test]
fn native_fn_cannot_produce_a_capability() {
    // F-5: no body to check, so the declaration itself is refused (E0145) and
    // `scope.grant` stays the only declared producer.
    let stderr = assert_refused_with("forge_native_fn.tl", "E0145");
    assert!(
        stderr.contains("native fn get_grant"),
        "the refusal must name the native declaration:\n{stderr}"
    );
}

#[test]
fn default_parameter_forgery_is_refused() {
    // F-6: `fn scan(g: Grant<Net> = 7, ..)` — a default is a producer position.
    let stderr = assert_refused_with("forge_default_param.tl", "E0117");
    assert!(
        stderr.contains("forge_default_param.tl:7:"),
        "the refusal must be reported at the default value:\n{stderr}"
    );
}

#[test]
fn call_argument_forgery_is_refused() {
    // F-7: `scan(7, ...)` from a caller that legitimately holds a grant. The
    // finding is the argument, not a missing row or a missing grant.
    assert_refused_with("forge_call_arg.tl", "E0117");
}

#[test]
fn grant_passed_as_argument_compiles() {
    // The positive half: a real `Grant<Net>` passed from `main` to a helper is
    // accepted, so tightening the argument slot did not break the sanctioned
    // flow of authority through a call.
    let (ok, stderr) = check("grant_passed_as_argument.tl");
    assert!(
        ok,
        "a `Grant<Net>` argument must satisfy the parameter slot:\n{stderr}"
    );
    assert!(!stderr.contains("E0117"), "no E0117 expected:\n{stderr}");
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
    assert!(!stderr.contains("E0142"), "no E0142 expected:\n{stderr}");
    assert!(!stderr.contains("E0144"), "no E0144 expected:\n{stderr}");
}
