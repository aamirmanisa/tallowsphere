//! Acceptance consumer for the program-level OPSEC corpus (task A5.2.3).
//!
//! For every fixture in `tests/opsec_corpus/` this test runs the pipeline
//! frozen by `B03_INTERFACES.md` §1 — lex → `Parser::parse` →
//! `TypeChecker::new(&program).check()` →
//! `opsec_gates::OpsecGatesPass::new(&program, &env).check()` — and asserts
//! the diagnostic the fixture was authored to provoke (A5.2.1 §5 index and
//! AGT-08's report; every fixture carries its own `// expected:` header).
//!
//! Setup mirrors the pass's own scaffold (`opsec_gates::tests::run_gates_pass`,
//! identical call sequence). As an integration test this links the lib crate
//! as `tallow::…` where the in-crate scaffold says `crate::…` — same APIs;
//! `crate::` cannot resolve to the lib from a `tests/` target. No env
//! mutation; fixtures are embedded with `include_str!`, so the test never
//! depends on the process cwd.
//!
//! Frozen expectation mapping (§1; one `#[test]` per fixture):
//! - `identity_mixing.tl`          → E5001
//! - `direct_egress_optout.tl`     → E5002
//! - `fingerprint_reuse.tl`        → E5003
//! - `missing_plan_annotations.tl` → E5004 (legacy E0100/E0400/W1900 come
//!   from the sibling per-function passes and are NOT exercised here)
//! - `missing_burn_plan.tl`        → E5004 only — additive proof (AGT-08:
//!   "E5004 only"; its E5004 message must name @burn_plan alone)
//! - `clean_control.tl`            → no errors (E-codes absent)

use tallow::error::Diagnostics;
use tallow::lexer;
use tallow::opsec_gates::OpsecGatesPass;
use tallow::parser::Parser;
use tallow::typeck::TypeChecker;

// ── Scaffold — mirror of `opsec_gates::tests::run_gates_pass` ──────────────

fn run_gates_pass(source: &str) -> Diagnostics {
    let (tokens, _) = lexer::tokenize(source);
    let program = Parser::parse(tokens).unwrap();
    let (env, _) = TypeChecker::new(&program).check();
    OpsecGatesPass::new(&program, &env).check()
}

fn has(diags: &Diagnostics, code: &str) -> bool {
    diags.items.iter().any(|d| d.code == code)
}

fn count(diags: &Diagnostics, code: &str) -> usize {
    diags.items.iter().filter(|d| d.code == code).count()
}

/// Message of the first diagnostic carrying `code`; panics when absent.
fn msg_of<'a>(diags: &'a Diagnostics, code: &str) -> &'a str {
    diags
        .items
        .iter()
        .find(|d| d.code == code)
        .unwrap_or_else(|| panic!("expected {code} diagnostic, got: {:?}", diags.items))
        .msg
        .as_str()
}

// ── E5001 · identity mixing ────────────────────────────────────────────────

#[test]
fn opsec_corpus_identity_mixing() {
    // Fixture header: `// expected: E5001`. Rule: a build unit must act as
    // exactly one identity — here alex-01 (collect_a) and morgan-02
    // (collect_b), both reachable from `main`.
    let diags = run_gates_pass(include_str!("opsec_corpus/identity_mixing.tl"));

    assert!(
        has(&diags, "E5001"),
        "identity_mixing.tl must yield E5001, got: {:?}",
        diags.items
    );
    assert_eq!(
        count(&diags, "E5001"),
        1,
        "E5001 is one combined program-level error: {:?}",
        diags.items
    );
    // `main` carries no program-scope bundle, so the collection-program rule
    // co-fires on this fixture too: main is network-reachable through
    // collect_a/collect_b. Expected behavior (E5004 complements E5001) —
    // asserted so the corpus documents the combined diagnostic picture.
    assert!(
        has(&diags, "E5004"),
        "identity_mixing.tl `main` lacks the plan bundle → E5004 co-fires: {:?}",
        diags.items
    );
}

// ── E5002 · direct-egress opt-out misuse ───────────────────────────────────

#[test]
fn opsec_corpus_direct_egress_optout() {
    // Fixture header: `// expected: E5002`. Rule: `TALLOW_ALLOW_DIRECT` is an
    // operator process-level decision, never a program affordance — here
    // `env.get("TALLOW_ALLOW_DIRECT")` branches on it.
    let diags = run_gates_pass(include_str!("opsec_corpus/direct_egress_optout.tl"));

    assert!(
        has(&diags, "E5002"),
        "direct_egress_optout.tl must yield E5002, got: {:?}",
        diags.items
    );
    assert_eq!(
        count(&diags, "E5002"),
        1,
        "exactly one flag-literal reference in the fixture: {:?}",
        diags.items
    );
    // The fixture's `main` does fetch directly (collection program) but
    // carries no @persona/@burn_plan, so E5004 co-fires listing those two —
    // asserted to pin the combined picture (E5002 + E5004 both expected).
    assert!(
        has(&diags, "E5004"),
        "direct_egress_optout.tl `main` lacks @persona/@burn_plan → E5004 co-fires: {:?}",
        diags.items
    );
    let msg = msg_of(&diags, "E5004");
    assert!(
        msg.contains("@persona") && msg.contains("@burn_plan"),
        "E5004 must name the missing categories: {msg}"
    );
}

// ── E5003 · fingerprint / persona reuse ────────────────────────────────────

#[test]
fn opsec_corpus_fingerprint_reuse() {
    // Fixture header: `// expected: E5003`. Rule: persona p-7 is burned by
    // @burn_plan on `main`, then re-declared by @persona on run_one AND
    // run_two — burn-then-reuse. (The same shared seed literal does not
    // double-fire the seed sub-rule here: both sites carry the SAME id, and
    // the seed rule guards cross-id reuse only.)
    let diags = run_gates_pass(include_str!("opsec_corpus/fingerprint_reuse.tl"));

    assert!(
        has(&diags, "E5003"),
        "fingerprint_reuse.tl must yield E5003, got: {:?}",
        diags.items
    );
    assert_eq!(
        count(&diags, "E5003"),
        2,
        "one E5003 per offending @persona site (run_one, run_two): {:?}",
        diags.items
    );
    // `main` burns p-7 but carries no @persona of its own, so E5004
    // co-fires on the missing bundle category — pinned here.
    assert!(
        has(&diags, "E5004"),
        "fingerprint_reuse.tl `main` lacks @persona → E5004 co-fires: {:?}",
        diags.items
    );
}

// ── E5004 · missing plan annotations (zero annotations) ────────────────────

#[test]
fn opsec_corpus_missing_plan_annotations() {
    // Fixture header: `// expected: E5004 (plus existing E0100/E0400/W1900)`.
    // Those legacy codes are emitted by the sibling per-function passes
    // (legal_pass/stealth_pass/cra_pass), which this corpus consumer does not
    // run; the new program-level gate must produce ONE combined E5004 here.
    let diags = run_gates_pass(include_str!("opsec_corpus/missing_plan_annotations.tl"));

    assert!(
        has(&diags, "E5004"),
        "missing_plan_annotations.tl must yield E5004, got: {:?}",
        diags.items
    );
    assert_eq!(
        count(&diags, "E5004"),
        1,
        "E5004 is one combined error listing every missing category: {:?}",
        diags.items
    );
    // Collection program with browser navigation and zero annotations: the
    // single error must enumerate all five required categories.
    let msg = msg_of(&diags, "E5004");
    for cat in ["@legal", "@cra_class", "@persona", "@burn_plan", "@stealth"] {
        assert!(msg.contains(cat), "E5004 must list {cat}: {msg}");
    }
}

// ── E5004 · missing burn plan (additive proof) ─────────────────────────────

#[test]
fn opsec_corpus_missing_burn_plan() {
    // Fixture header: `// expected: E5004`. Ambiguity resolution (per
    // B03_INTERFACES §1 → ruleset doc + AGT-08 report): this fixture asserts
    // E5004 ONLY — legacy gates are green (@legal/@cra_class/@stealth
    // present) and the missing category is @burn_plan alone. The fixture
    // predates the landed E5004 wording, so the message-content assertions
    // pin its documented behavior (AGT-08: "E5004 only — additive proof").
    let diags = run_gates_pass(include_str!("opsec_corpus/missing_burn_plan.tl"));

    assert!(
        has(&diags, "E5004"),
        "missing_burn_plan.tl must yield E5004, got: {:?}",
        diags.items
    );
    assert_eq!(
        count(&diags, "E5004"),
        1,
        "one combined E5004 expected: {:?}",
        diags.items
    );
    let msg = msg_of(&diags, "E5004");
    assert!(
        msg.contains("@burn_plan"),
        "E5004 must name the missing burn plan: {msg}"
    );
    assert!(
        !msg.contains("@legal"),
        "legal is present, must not be listed: {msg}"
    );
    assert!(
        !msg.contains("@stealth"),
        "stealth is present, must not be listed: {msg}"
    );
}

// ── clean control ──────────────────────────────────────────────────────────

#[test]
fn opsec_corpus_clean_control() {
    // Fixture header: `// expected: clean`. Full plan bundle (single persona,
    // unique seed, burn plan, legal, class), proxy-default egress, no browser
    // nav — the new gates must stay silent: no errors, no E5xxx codes.
    let diags = run_gates_pass(include_str!("opsec_corpus/clean_control.tl"));

    assert!(
        !diags.has_errors(),
        "clean_control.tl must stay green, got: {:?}",
        diags.items
    );
    for code in ["E5001", "E5002", "E5003", "E5004"] {
        assert!(
            !has(&diags, code),
            "clean_control.tl must not emit {code}: {:?}",
            diags.items
        );
    }
}
