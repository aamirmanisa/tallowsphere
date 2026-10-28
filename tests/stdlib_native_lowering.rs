//! A census gate for native lowering of `stdlib/*.tl` modules.
//!
//! Two lanes (topology, ip) shipped acceptance evidence from the interpreter
//! alone because the native backend has no lowering for their calls: the
//! compiled build refuses and `tallow run` silently falls back. That gap was
//! found three times, late, by hand. This test makes it a checked-in number.
//!
//! ## What it measures
//!
//! For every `stdlib/*.tl` file that declares at least one module-level
//! `native fn`, the census picks the first declaration whose arguments it can
//! synthesize, generates a program that *calls* it inside a function `main`
//! never calls, and compiles that program:
//!
//! ```text
//! import tallow.<file-stem>
//!
//! fn probe_unused(...) {
//!     let _probe = <module>.<fn>(<synthesized args>)
//! }
//!
//! fn main() {
//! }
//! ```
//!
//! Nothing is executed. `main` is empty and the call sits in a function no
//! path reaches, so no socket is opened and no process is spawned — the call
//! exists only to be *compiled*.
//!
//! ## The command that requires native codegen
//!
//! `tallow build <file>` has no `--require-native` flag; `build` **is** the
//! native plane. Its only outcome is `built: <path>` (exit 0) or
//! `build failed: <reason>` (non-zero) — there is no interpreter to fall back
//! to, which is why the census drives `build` and not `run`.
//!
//! `--require-native` exists only on `tallow run`; there it means "do not
//! substitute the interpreter when the native build is unavailable". The two
//! reach the same codegen: `cargo run -- run --require-native probe.tl` on a
//! module with no lowering exits non-zero with
//! `* native build unavailable (<reason>); --require-native refuses the
//! interpreter fallback`, where `<reason>` is the same string `build` prints
//! after `build failed: `. The census uses `build` because it stops before the
//! produced binary is launched at all.
//!
//! ## Statuses
//!
//! - `lowers`          — the probe compiled; a native lowering exists for that call.
//! - `refuses`         — codegen refused the call by name (the interpreter-only gap).
//! - `not_expressible` — no declared free function takes arguments the census can
//!   synthesize (a `fn()` value, a struct array, a `Grant`, a live handle), or the
//!   program is stopped by a front-end gate before codegen runs. The reason is
//!   recorded; it is *not* counted as passing.
//!
//! ## Rules the test enforces (read-only unless blessed)
//!
//! - a module recorded `lowers` that now refuses **fails** the test (regression);
//! - a module with natives and no baseline entry **fails** the test (a new lane
//!   cannot ship an interpreter-only module silently);
//! - refusals are **reported**, never fatal, so the debt is a number in the log;
//! - `refuses` → `lowers` is fine: re-bless in the commit that lands the lowering.
//!
//! Regenerate the baseline with:
//!
//! ```text
//! BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering
//! ```
//!
//! The baseline is `tests/fixtures/stdlib_native_lowering/baseline.json`.
//!
//! The harness itself (discovery, probe rendering, the front-end gate ladder,
//! baseline I/O) lives in `tests/support/stdlib_census.rs` so that
//! `tests/codegen_fallthrough.rs` measures the same thing this gate does
//! instead of keeping a second copy of it.

#[path = "support/stdlib_census.rs"]
mod census;

use census::{
    compare, discover, load_baseline, map, run_census, write_baseline, Status, BASELINE_REL,
};
use std::path::PathBuf;

// ───────────────────────────── test ─────────────────────────────

#[test]
fn stdlib_native_lowering_census() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let modules = discover(&root.join("stdlib"));
    assert!(
        modules.len() > 20,
        "stdlib discovery found only {} modules — the census would be vacuous",
        modules.len()
    );

    let results = run_census(&modules);
    let statuses: Vec<(String, Status)> =
        results.iter().map(|(m, o)| (m.clone(), o.status)).collect();

    let baseline_path = root.join(BASELINE_REL);
    let bless = std::env::var("BLESS_STDLIB_LOWERING").is_ok_and(|v| v == "1");

    if bless {
        write_baseline(&baseline_path, &results);
        let lowers = results
            .iter()
            .filter(|(_, o)| o.status == Status::Lowers)
            .count();
        let refuses = results
            .iter()
            .filter(|(_, o)| o.status == Status::Refuses)
            .count();
        let nexpr = results.len() - lowers - refuses;
        println!(
            "stdlib native-lowering census blessed: {} modules — lowers {lowers}, \
             refuses {refuses}, not_expressible {nexpr}",
            results.len()
        );
        for (module, o) in &results {
            if o.status != Status::Lowers {
                println!("  {:16} {:16} {}", module, o.status.as_str(), o.evidence);
            }
        }
        return;
    }

    let baseline = load_baseline(&baseline_path).unwrap_or_else(|| {
        panic!(
            "no readable baseline at {} — run \
             `BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering` once, \
             review the diff, and commit it with the census",
            baseline_path.display()
        )
    });

    let c = compare(&statuses, &baseline.statuses);

    // The debt, as a number, on every run.
    println!(
        "stdlib native-lowering census: {} modules — lowers {}, refuses {}, not_expressible {}",
        results.len(),
        c.lowers,
        c.refuses,
        c.not_expressible
    );
    for (module, o) in &results {
        if o.status == Status::Refuses {
            println!("  refuses         {module:16} {}", o.evidence);
        }
    }
    for (module, o) in &results {
        if o.status == Status::NotExpressible {
            println!("  not_expressible {module:16} {}", o.evidence);
        }
    }
    for change in &c.changes {
        println!("  note: {change} (re-bless to record)");
    }
    for stale in &c.stale {
        println!("  note: {stale} is in the baseline but declares no native fn now");
    }

    assert!(
        c.new_modules.is_empty(),
        "new stdlib module(s) with native declarations and no baseline entry: {:?}\n\
         A lane must not ship an interpreter-only module silently. Add the module by \
         running BLESS_STDLIB_LOWERING=1 cargo test --test stdlib_native_lowering and \
         commit the baseline with the change.",
        c.new_modules
    );

    assert!(
        c.regressions.is_empty(),
        "native-lowering regression(s) — recorded as `lowers`, now refused: {:?}\n\
         The baseline is the contract: a call that compiled before must compile now. \
         If the removal is deliberate, re-bless in the same commit and say so.",
        c.regressions
    );
}

// ───────────────────────────── gate self-tests ─────────────────────────────

#[test]
fn gate_fails_a_recorded_lowering_that_now_refuses() {
    let baseline = map(&[("topology", Status::Lowers)]);
    let results = vec![("topology".to_string(), Status::Refuses)];
    let c = compare(&results, &baseline);
    assert_eq!(c.regressions, vec!["topology".to_string()]);
}

#[test]
fn gate_fails_a_new_module_with_no_baseline_entry() {
    let baseline = map(&[("math", Status::Lowers)]);
    let results = vec![
        ("math".to_string(), Status::Lowers),
        ("shiny".to_string(), Status::Refuses),
    ];
    let c = compare(&results, &baseline);
    assert_eq!(c.new_modules, vec!["shiny".to_string()]);
    assert!(c.regressions.is_empty());
}

#[test]
fn gate_allows_a_refusal_that_starts_lowering() {
    let baseline = map(&[("ip", Status::Refuses)]);
    let results = vec![("ip".to_string(), Status::Lowers)];
    let c = compare(&results, &baseline);
    assert!(c.regressions.is_empty() && c.new_modules.is_empty());
    assert_eq!(c.changes, vec!["ip: refuses -> lowers".to_string()]);
}

#[test]
fn gate_counts_not_expressible_separately_from_lowers() {
    let baseline = map(&[("http", Status::NotExpressible)]);
    let results = vec![("http".to_string(), Status::NotExpressible)];
    let c = compare(&results, &baseline);
    assert_eq!(
        (c.lowers, c.refuses, c.not_expressible),
        (0, 0, 1),
        "not_expressible must never be counted as passing"
    );
    assert!(c.regressions.is_empty() && c.new_modules.is_empty());
}
