//! G3 — a `.tl` program must never make clang complain about `@tallow.`.
//!
//! ## Defect 1: the emitter fell out of the module match
//!
//! `emit_method_call` dispatches `math | env | time | fs | json | …` to a
//! hand-written lowering table per module. When a table returned `Ok(None)` for
//! a method it did not implement, the arm simply **ended**: nothing resolved the
//! identifier as a namespace, and the next receiver path emitted the *module
//! identifier* as an LLVM global. `json.parse("{{}}")` therefore compiled to
//!
//! ```text
//! %1 = call i32 @tallow_str_parse_i64(ptr @tallow.json, ptr %0)
//! ```
//!
//! and clang answered `use of undefined value '@tallow.json'` (json2.ll:485 at
//! 61b18b5). The interpreted plane was correct throughout, because
//! `src/interp.rs` implements `json.parse` inline. So `tallow run --interpret`
//! printed `Ok({})` while `tallow build` failed with a diagnostic naming LLVM
//! internals — the worst shape of failure: not a refusal, not a lowering, an
//! LLVM error.
//!
//! The fix refuses by name at build time (`json.parse() has no native lowering
//! — refusing to emit a silently-truthy stub`), which is the `regex` idiom:
//! `tallow build` names the gap and `tallow run` falls back to the interpreter
//! that implements the call. The generic bridge is not an option here and this
//! test is the place that says why: `stdlib::dispatch` returns `None` for
//! `json.parse` on purpose (the interpreter handles it inline), so a bridged
//! call would abort at *run* time instead of refusing at build time.
//!
//! ## What this file asserts
//!
//! 1. `json.parse` and `jwt.parse` reach an honest outcome: a built binary, or
//!    a refusal that names the call. The `use of undefined value` signature is
//!    forbidden outright, and so is a linker `undefined reference` (that was
//!    the other way a module call could leave the emitter without saying why).
//! 2. Every module the census recorded as `lowers` still builds (the sweep).
//!
//! The sweep reuses `tests/support/stdlib_census.rs`, the harness behind
//! `tests/stdlib_native_lowering.rs`, rather than keeping a second probe
//! builder: a copy would drift from the baseline it is meant to protect.

#[path = "support/stdlib_census.rs"]
mod census;

use census::{build_probe, discover, load_baseline, run_census, Status, BASELINE_REL};
use std::path::PathBuf;

/// The program alden measured at 61b18b5 (blueprint G3).
const JSON_PARSE: &str = r#"import tallow.json

fn main() {
    let v = json.parse("{{}}")
    print("{v}")
}
"#;

/// The same shape one namespace over. `jwt` is *not* in the hand-written arm,
/// so it reaches the generic bridge instead — this pins that it stays honest
/// there too (at 61b18b5 it built, via `stdlib::dispatch("jwt", "parse")`).
const JWT_PARSE: &str = r#"import tallow.jwt

fn main() {
    let v = jwt.parse("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMiJ9.c2ln")
    print("{v}")
}
"#;

/// Build `src` and apply the G3 rule to the outcome.
///
/// Two forbidden signatures: clang's `use of undefined value` (the emitter
/// emitted a module ident as a global) and the linker's `undefined reference`
/// (the emitted call names a runtime symbol nothing provides). Everything else
/// is acceptable **only if** it is a named refusal — i.e. the build failed and
/// the diagnostic says there is no native lowering.
fn assert_honest_outcome(label: &str, src: &str) -> (bool, String) {
    let (built, text) = build_probe(&format!("g3-{label}"), src);

    assert!(
        !text.contains("use of undefined value"),
        "{label}: the emitter fell out of the module match again — clang reported an \
         undefined `@tallow.` global instead of the compiler refusing by name.\n{text}"
    );
    assert!(
        !text.contains("undefined reference"),
        "{label}: the emitted call names a runtime symbol the linked archive does not \
         provide; that is a linker diagnostic, not a compiler refusal.\n{text}"
    );

    if !built {
        assert!(
            text.contains("has no native lowering"),
            "{label}: the build failed without a named refusal. Expected either a built \
             binary or `<call>() has no native lowering — refusing to emit a \
             silently-truthy stub`.\n{text}"
        );
    }
    (built, text)
}

#[test]
fn json_parse_is_either_lowered_or_refused_by_name() {
    let (_, text) = assert_honest_outcome("json.parse", JSON_PARSE);
    // When it refuses, the refusal must name the call — not the module, not the
    // file, not `@tallow.json`.
    if text.contains("has no native lowering") {
        assert!(
            text.contains("json.parse()"),
            "the refusal must name `json.parse()`, got:\n{text}"
        );
    }
}

#[test]
fn jwt_parse_is_either_lowered_or_refused_by_name() {
    assert_honest_outcome("jwt.parse", JWT_PARSE);
}

/// The sweep: every module the census recorded as `lowers` still builds.
///
/// This is the half of the G3 fix that is not about `json`: a module whose
/// hand-written table returns `Ok(None)` used to fall out of the match, so the
/// *same* LLVM diagnostic was one unsupported method away in every module in
/// the list. The census baseline is the contract — a call that compiled before
/// must compile now.
#[test]
fn every_recorded_lowering_still_builds() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let modules = discover(&root.join("stdlib"));
    let baseline = load_baseline(&root.join(BASELINE_REL)).unwrap_or_else(|| {
        panic!(
            "no readable baseline at {} — run \
             `BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering` once",
            root.join(BASELINE_REL).display()
        )
    });

    let mut lowers = Vec::new();
    for module in modules {
        if baseline.statuses.get(&module.stem) == Some(&Status::Lowers) {
            lowers.push(module);
        }
    }
    assert!(
        lowers.len() > 20,
        "only {} modules are recorded as `lowers` — the sweep would be vacuous",
        lowers.len()
    );

    let results = run_census(&lowers);
    let broke: Vec<String> = results
        .iter()
        .filter(|(_, outcome)| outcome.status != Status::Lowers)
        .map(|(module, outcome)| {
            format!(
                "{module}: recorded `lowers`, now {} — {}",
                outcome.status.as_str(),
                outcome.evidence
            )
        })
        .collect();

    assert!(
        broke.is_empty(),
        "the emitter sweep broke module(s) the census recorded as lowering:\n  {}\n\
         A recorded `lowers` module must still compile. If the change is deliberate, \
         re-bless the baseline in the same commit and say so.",
        broke.join("\n  ")
    );
}
