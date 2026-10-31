//! Repository gates: checks that a healthy tree must pass, ported out of Python
//! so they run through the same toolchain as everything else.
//!
//! Each gate exposes a pure `check(&root) -> Report` plus a CLI entry point that
//! prints the report in the shape the Python original printed, so the two can be
//! diffed while a port is being adopted and the CI step never has to change
//! format mid-flight.

pub mod capability_registry;
pub mod census_page_methods;
pub mod census_surface;
pub mod crypto_inventory;
pub mod docs_examples;
pub mod ffi_symbols;
pub mod panic_policy;
pub mod release_body;
pub mod sbom;
pub mod test_summary;

use std::path::Path;
use std::process::ExitCode;

pub fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// `tallow gate ffi-symbols` — exit 0 when the FFI boundary is consistent.
pub fn run_ffi_symbols() -> ExitCode {
    let report = ffi_symbols::check(&repo_root());
    for line in report.problem_lines() {
        println!("{line}");
    }
    println!("{}", report.summary_line());
    if report.problems() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Dispatch `tallow gate <verb>`; the exit code is the verdict.
pub fn run_cli(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("ffi-symbols") => {
            let code = run_ffi_symbols();
            if code == ExitCode::SUCCESS { 0 } else { 1 }
        }
        Some("capability-registry") => {
            let code = run_capability_registry();
            if code == ExitCode::SUCCESS { 0 } else { 1 }
        }
        Some("census-page-methods") => run_census_page_methods(),
        Some("census-surface") => run_census_surface(),
        Some("panic-policy") => run_panic_policy(),
        Some("sbom") => run_sbom(&args[1..]),
        Some("release-body") => run_release_body(&args[1..]),
        Some("test-summary") => run_test_summary(&args[1..]),
        Some("docs-examples") => run_docs_examples(&args[1..]),
        Some("crypto-inventory") => run_crypto_inventory(&args[1..]),
        Some(other) => {
            eprintln!(
                "unknown gate `{other}`: known gates are `ffi-symbols`, `capability-registry`, `census-page-methods`, `census-surface`, `panic-policy`, `sbom`, `release-body`, `test-summary`, `docs-examples`, `crypto-inventory`"
            );
            2
        }
        None => {
            eprintln!("usage: tallow gate <ffi-symbols|capability-registry>");
            2
        }
    }
}

/// `tallow gate capability-registry` — exit 0 when the registry matches the code.
pub fn run_capability_registry() -> ExitCode {
    let report = capability_registry::check(&repo_root());
    for line in report.problem_lines() {
        println!("{line}");
    }
    println!("{}", report.summary_line());
    if report.problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `tallow gate census-page-methods` — exit 0 when every Page method is on both
/// planes (or explicitly refused), 1 on a mismatch, 2 when the parse found
/// nothing.
pub fn run_census_page_methods() -> i32 {
    let report = census_page_methods::check(&repo_root());
    if report.parse_failed {
        println!(
            "FAIL: parsed 0 Page methods from stdlib/browser.tl — the parse broke, not the surface"
        );
        return 2;
    }
    for line in &report.lines {
        println!("{line}");
    }
    println!("{}", report.summary_line());
    if report.problems == 0 { 0 } else { 1 }
}

/// `tallow gate crypto-inventory [--write PATH | --check PATH | --selftest]`
///
/// Exit codes mirror the Python: 0 ok, 1 drift, 2 generator error.
pub fn run_crypto_inventory(args: &[String]) -> i32 {
    let root = repo_root();
    let reg = match crypto_inventory::Registry::load() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("crypto-inventory: {e}");
            return 2;
        }
    };

    let mut write: Option<&str> = None;
    let mut check: Option<Option<&str>> = None;
    let mut roots: Vec<String> = reg.default_roots.clone();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--write" => write = it.next().map(String::as_str),
            // `--check` takes an OPTIONAL path: bare `--check` is the registry
            // conformance gate, `--check PATH` adds the artifact byte gate.
            "--check" => {
                check = Some(match it.peek() {
                    Some(v) if !v.starts_with("--") => {
                        let v = it.next().map(String::as_str);
                        v
                    }
                    _ => None,
                })
            }
            "--roots" => {
                if let Some(v) = it.next() {
                    roots = v.split(',').map(str::to_string).collect();
                }
            }
            "--self-test" => {
                return crypto_inventory::self_test();
            }
            // Python's `--root` is repeatable and overrides the default roots
            // entirely; used by the drift drills.
            "--root" => match it.next() {
                Some(v) => {
                    if roots == reg.default_roots {
                        roots.clear();
                    }
                    roots.push(v.to_string());
                }
                None => {
                    eprintln!("crypto-inventory: --root requires a value");
                    return 2;
                }
            },
            other => {
                eprintln!("crypto-inventory: unrecognized argument `{other}`");
                return 2;
            }
        }
    }

    let inv = match crypto_inventory::scan(&root, &reg, &roots) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("crypto-inventory: {e}");
            return 2;
        }
    };
    let text = crypto_inventory::render(&inv, &reg.policy);

    if let Some(path) = write {
        let out = std::path::Path::new(path);
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        if let Err(e) = std::fs::write(out, &text) {
            eprintln!("crypto-inventory: cannot write {}: {e}", out.display());
            return 2;
        }
        println!(
            "crypto-inventory: wrote {} ({} registered, {} present, {} occurrences)",
            out.display(),
            inv.registry_entry_count,
            inv.algorithm_count,
            inv.total_occurrences
        );
        if !inv.unregistered.is_empty() {
            eprintln!(
                "crypto-inventory: note: {} unregistered candidate(s) recorded — \
                 --check will fail until they are registered: {}",
                inv.unregistered.len(),
                inv.unregistered.join(", ")
            );
        }
        if !inv.rejected_found.is_empty() {
            let names: Vec<String> = inv.rejected_found.iter().map(|(n, _, _)| n.clone()).collect();
            eprintln!(
                "crypto-inventory: note: REJECTED primitive(s) present — fix the use site(s), \
                 they cannot be registered: {}",
                names.join(", ")
            );
        }
        if !inv.novel_aeads.is_empty() {
            eprintln!(
                "crypto-inventory: note: {} novel AEAD token(s) recorded — --check will fail \
                 until consciously registered or removed: {}",
                inv.novel_aeads.len(),
                inv.novel_aeads.join(", ")
            );
        }
        if !inv.aegis_outside.is_empty() {
            eprintln!(
                "crypto-inventory: note: AEGIS (optional at most) used outside \
                 crates/tallow-crypto/: {}",
                inv.aegis_outside.join(", ")
            );
        }
        return 0;
    }

    if let Some(path) = check {
        // Problems are reported first and do not short-circuit the artifact
        // comparison: the Python accumulates `drift` across both and reports
        // everything in one run.
        let mut drift = false;
        for problem in crypto_inventory::conformance_problems(&inv, &reg) {
            drift = true;
            eprintln!("crypto-inventory: REGISTRY DRIFT — {problem}");
        }
        let Some(path) = path else {
            // Registry-conformance-only mode: no artifact to compare, and the
            // OK line is the whole stdout contract.
            if drift {
                return 1;
            }
            println!(
                "crypto-inventory: registry OK — {} registered, {} present, {} occurrences, \
                 no unregistered tokens; guardrail enforced (no rejected primitives, \
                 no novel AEADs, AEGIS inside tallow-crypto or the single annotated \
                 occurrence-ceilinged allowance)",
                inv.registry_entry_count, inv.algorithm_count, inv.total_occurrences
            );
            return 0;
        };
        let snapshot = std::path::Path::new(path);
        if !snapshot.is_file() {
            eprintln!("crypto-inventory: artifact {} not found", snapshot.display());
            return 2;
        }
        let expected = std::fs::read_to_string(snapshot).unwrap_or_default();
        if expected == text {
            println!(
                "crypto-inventory: CBOM drift gate OK — regenerated artifact matches {}",
                snapshot.display()
            );
        } else {
            drift = true;
            let from = format!("{} (committed)", snapshot.display());
            eprint!(
                "{}",
                sbom::unified_diff(&expected, &text, &from, "regenerated")
            );
            eprintln!(
                "crypto-inventory: CBOM DRIFT — {} does not match the regenerated artifact; \
                 update it in the same change:\n  python3 scripts/crypto-inventory.py --write {}",
                snapshot.display(),
                snapshot.display()
            );
        }
        return if drift { 1 } else { 0 };
    }

    // No --write and no --check: emit the artifact itself, as the Python does.
    print!("{text}");
    0
}

/// `tallow gate docs-examples [--bin PATH] [--only SUBSTRING]`
pub fn run_docs_examples(args: &[String]) -> i32 {
    let root = repo_root();
    let mut bin: Option<&str> = None;
    let mut only: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--bin" => bin = it.next().map(String::as_str),
            "--only" => only = it.next().map(String::as_str),
            // Accepted for CI symmetry, as in the Python: failures always exit 1.
            "--check" => {}
            other => {
                eprintln!("docs_examples: unrecognized argument `{other}`");
                return 2;
            }
        }
    }
    let Some(binary) = docs_examples::find_binary(bin, &root) else {
        eprintln!(
            "docs_examples: no repo tallow binary — build it (cargo build --bin tallow) or set \
             TALLOW_BIN; refusing to fall back to a `tallow` on PATH, which is a different build"
        );
        return 1;
    };
    let report = docs_examples::run(&root, &binary, only);
    for line in report.lines() {
        println!("{line}");
    }
    if report.failed == 0 {
        0
    } else {
        1
    }
}

/// `tallow gate release-body <vX.Y.Z> [--check] [--verified PATH]`
pub fn run_release_body(args: &[String]) -> i32 {
    let changelog = repo_root().join("CHANGELOG.md");
    let req = match release_body::parse(args) {
        Ok(r) => r,
        Err(release_body::Outcome::Usage(msg)) => {
            eprintln!("{msg}");
            return 64;
        }
        Err(other) => return finish_release_body(other),
    };
    finish_release_body(release_body::run(&changelog, &req))
}

fn finish_release_body(outcome: release_body::Outcome) -> i32 {
    match outcome {
        release_body::Outcome::Ok(text) => {
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
            0
        }
        release_body::Outcome::Rejected(msg) => {
            eprintln!("{msg}");
            1
        }
        release_body::Outcome::Usage(msg) => {
            eprintln!("{msg}");
            64
        }
    }
}

/// `tallow gate test-summary --lib L --conformance C --sha S [--cases-dir D]`
pub fn run_test_summary(args: &[String]) -> i32 {
    let mut lib: Option<&str> = None;
    let mut conformance: Option<&str> = None;
    let mut sha: Option<&str> = None;
    let mut cases_dir: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--lib" => lib = it.next().map(String::as_str),
            "--conformance" => conformance = it.next().map(String::as_str),
            "--sha" => sha = it.next().map(String::as_str),
            "--cases-dir" => cases_dir = it.next().map(String::as_str),
            other => {
                eprintln!("test_summary: unrecognized argument `{other}`");
                return 64;
            }
        }
    }
    let (Some(lib), Some(conformance), Some(sha)) = (lib, conformance, sha) else {
        eprintln!("usage: test_summary --lib PATH --conformance PATH --sha SHA [--cases-dir DIR]");
        return 64;
    };
    let cases = cases_dir.unwrap_or("conformance/cases");
    let cases_path = {
        let p = std::path::Path::new(cases);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            repo_root().join(p)
        }
    };
    match test_summary::run(
        std::path::Path::new(lib),
        std::path::Path::new(conformance),
        sha,
        &cases_path,
    ) {
        test_summary::Outcome::Ok(text) => {
            print!("{text}");
            0
        }
        test_summary::Outcome::Refused(msg) => {
            eprintln!("{msg}");
            1
        }
    }
}

/// `tallow gate sbom [--write PATH | --check PATH]` — regenerate the inventory,
/// print it, or compare it against a committed snapshot.
///
/// Exit codes mirror the Python: 0 ok, 1 drift, 2 generator/snapshot error.
pub fn run_sbom(args: &[String]) -> i32 {
    let root = repo_root();
    let sbom = match sbom::build(&root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sbom-gen: {e}");
            return 2;
        }
    };
    let text = sbom::render(&sbom);

    let mut write: Option<&str> = None;
    let mut check: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--write" => write = it.next().map(String::as_str),
            "--check" => check = it.next().map(String::as_str),
            "-h" | "--help" => {
                println!("usage: tallow gate sbom [--write PATH] [--check PATH]");
                return 0;
            }
            other => {
                eprintln!("sbom-gen: unrecognized argument `{other}`");
                return 2;
            }
        }
    }

    if let Some(path) = write {
        let out = std::path::Path::new(path);
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        if let Err(e) = std::fs::write(out, &text) {
            eprintln!("sbom-gen: cannot write {}: {e}", out.display());
            return 2;
        }
        println!(
            "sbom-gen: wrote {} ({} packages)",
            out.display(),
            sbom.packages.len()
        );
        return 0;
    }

    if let Some(path) = check {
        let snapshot = std::path::Path::new(path);
        if !snapshot.is_file() {
            eprintln!("sbom-gen: snapshot {} not found", snapshot.display());
            return 2;
        }
        let expected = match std::fs::read_to_string(snapshot) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("sbom-gen: cannot read {}: {e}", snapshot.display());
                return 2;
            }
        };
        if expected == text {
            println!(
                "sbom-gen: SBOM drift gate OK — regenerated artifact matches {}",
                snapshot.display()
            );
            return 0;
        }
        let from = format!("{} (committed)", snapshot.display());
        eprint!(
            "{}",
            sbom::unified_diff(&expected, &text, &from, "regenerated")
        );
        eprintln!(
            "sbom-gen: SBOM DRIFT — {} does not match the regenerated artifact; \
             update the snapshot in the same change:\n  python3 scripts/sbom-gen.py --write {}",
            snapshot.display(),
            snapshot.display()
        );
        return 1;
    }

    print!("{text}");
    0
}

/// `tallow gate panic-policy` — exit 0 when `docs/PANIC-POLICY.md` matches the
/// tree, 1 on drift, 2 when the manifest could not be evaluated.
pub fn run_panic_policy() -> i32 {
    let report = panic_policy::check(&repo_root());
    for line in report.lines() {
        println!("{line}");
    }
    if report.unevaluable {
        2
    } else if report.drift {
        1
    } else {
        0
    }
}

/// `tallow gate census-surface` — exit 0 clean, 1 an unmentioned declaration,
/// 2 the scan is broken.
pub fn run_census_surface() -> i32 {
    let report = census_surface::check(&repo_root());
    if report.parse_failed {
        println!(
            "FAIL: parsed 0 empty-bodied declarations from {} impl blocks — the body rule does not match the manifest's current form",
            report.impl_blocks
        );
        return 2;
    }
    for line in &report.lines {
        println!("{line}");
    }
    println!("{}", report.summary_line());
    if report.unmentioned == 0 { 0 } else { 1 }
}
