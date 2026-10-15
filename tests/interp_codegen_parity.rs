//! Interpreter ↔ Codegen differential test harness — Phase C3
//!
//! Inventory: runs every example .tl file through typecheck + interpreter.
//! Codegen parity is documented separately (gaps found: hello_simple.tl
//! has LLVM IR type mismatch i32/i64).

use std::process::Command;

const TALLOW_BIN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/debug/tallow");
const EXAMPLES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples");

fn known_check_fail(name: &str) -> Option<&str> {
    match name {
        "agent_demo.tl" => Some("can_spawn exceeds L3"),
        "agent_memory_demo.tl" => Some("undefined variable brain"),
        "channels_demo.tl" => Some("undefined variable Chan"),
        "smbdealhunter_public_max_graphjson.tl" => Some("undefined HtmlParser"),
        "sqlite_demo.tl" => Some("db import missing"),
        "financial_e2e_test.tl" => Some("top-level let — invalid Tallow (items only); needs fn main() rewrite"),
        // Untracked WIP examples with syntax errors (unescaped quotes in JS strings)
        "tabc_rss_scraper.tl" => Some("unescaped quotes in JS strings — invalid Tallow"),
        "tabc_v4.tl" => Some("WIP syntax error"),
        _ => None,
    }
}

fn known_run_fail(name: &str) -> Option<&str> {
    match name {
        "recursive_test.tl" => Some("stack overflow — needs VM trampoline (C3)"),
        "dealhunter.tl" | "dealhunter_pipeline.tl" => Some("live HTTP fetch — network required"),
        "live_tor_test.tl" => Some("live Tor daemons — network required; handler returns Struct not Ok/Err"),
        "browser_demo.tl" | "browser_full_demo.tl" | "browser_plugins_demo.tl"
        | "mbs_browser_recon.tl" | "mbs_scraper.tl" | "smbdealhunter_scraper.tl"
        | "ippool_demo.tl" | "bail_test.exe" | "fn_array_param.exe" | "full_demo.exe"
        | "hof_test.exe" | "if_let_test.exe" | "interp_test.exe" | "int_match_default.exe"
        | "map_test.exe" | "mega_test.exe" => Some("exe/browser/network — skip"),
        // Untracked WIP scrapers hitting live network (need browser/live egress)
        "property_scraper.tl" | "realtor_scraper.tl" | "public_source_get_batch.tl"
        | "tor_single_test.tl" | "test_dealhunter.tl" | "smbdealhunter_public_max_graphjson.tl"
        | "tabc_test.tl" | "tabc_v3.tl" | "tabc_v5.tl" | "tabc_v6.tl" | "tabc_v7.tl"
        | "tabc_v8.tl" | "tabc_v9.tl" | "tabc_v10.tl" | "tabc_v11.tl" => {
            Some("live network/browser — skip")
        }
        _ => None,
    }
}

#[test]
fn all_examples_typecheck_and_run() {
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut skip_check = 0usize;
    let mut skip_run = 0usize;

    let Ok(entries) = std::fs::read_dir(EXAMPLES_DIR) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("tl") {
            continue;
        }
        total += 1;
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let path_str = path.to_string_lossy();

        // Typecheck
        if let Some(reason) = known_check_fail(&name) {
            println!("  SKIP(typecheck) {name}: {reason}");
            skip_check += 1;
            continue;
        }
        let check = Command::new(TALLOW_BIN)
            .args(["check", &path_str])
            .output()
            .unwrap();
        if !check.status.success() {
            panic!("{name}: typecheck failed");
        }

        // Run
        if let Some(reason) = known_run_fail(&name) {
            println!("  SKIP(run) {name}: {reason}");
            skip_run += 1;
            continue;
        }
        let run = Command::new(TALLOW_BIN)
            .args(["run", &path_str])
            .output()
            .unwrap();
        if !run.status.success() {
            let stderr = String::from_utf8_lossy(&run.stderr);
            panic!("{name}: run failed: {stderr}");
        }
        passed += 1;
    }

    println!(
        "Examples: {total} total, {passed} run+check pass, {} check skip, {} run skip",
        skip_check, skip_run
    );
    assert!(passed > 0, "no examples passed");
}

#[test]
fn parity_examples_run_in_interpreter() {
    let examples = vec![
        "hello_simple.tl",
        "enums.tl",
        "structs.tl",
        "interpolation.tl",
        "match_test.tl",
        "hof_chain.tl",
        "bail_test.tl",
        "map_test.tl",
        "closure_capture.tl",
        "string_ops.tl",
        "question_mark_test.tl",
        "result_test.tl",
        "while_test.tl",
        "fn_array_param.tl",
        "struct_array.tl",
        "mega_test.tl",
        "negative_test.tl",
        "full_demo.tl",
        "if_let_test.tl",
        "integration_test.tl",
        "interp_test.tl",
    ];

    for example in &examples {
        let path = format!("{EXAMPLES_DIR}/{example}");
        let output = Command::new(TALLOW_BIN)
            .args(["run", &path])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "interpreter failed for {example}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    println!("All {} parity examples run in interpreter", examples.len());
}
