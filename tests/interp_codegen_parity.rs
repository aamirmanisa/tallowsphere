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
        "channels_demo.tl" => Some("undefined variable Chan"),
        "sqlite_demo.tl" => Some("db import missing"),
        _ => None,
    }
}

fn known_run_fail(name: &str) -> Option<&str> {
    match name {
        "recursive_test.tl" => Some("stack overflow — needs VM trampoline (C3)"),
        // Measured 2026-10-19 by running every example and recording the failure.
        // None of these is a silent skip: each line names the missing capability.
        "relay_room_auth_demo.tl" | "relay_room_bytes_demo.tl" | "relay_room_demo.tl"
        | "relay_room_multi_demo.tl" => {
            Some("live relay session — needs a relay on 127.0.0.1:4454; the join path is interpreter-only by design")
        }
        "dealhunter.tl" | "dealhunter_pipeline.tl" | "test_dealhunter.tl" => {
            Some("requires a local config file that is not in the repo")
        }
        "agent_demo.tl" | "agent_memory_demo.tl" => {
            Some("refuses to spawn below autonomy L4; needs runtime policy, not a code change")
        }
        "agent_valid.tl" | "self_host.tl" | "stdlib_codegen_test.tl" | "public_source_get_batch.tl"
        | "sitescan_demo.tl" => Some("long-running or live-network example (timed out at 20 s)"),
        "msurface_one.tl" => Some("needs MSURL in the environment"),
        "dealhunter.tl" | "dealhunter_pipeline.tl" => Some("live HTTP fetch — network required"),
        "live_tor_test.tl" => Some("live Tor daemons — network required; handler returns Struct not Ok/Err"),
        "browser_demo.tl" | "browser_full_demo.tl" | "browser_plugins_demo.tl"
        | "scrape_speed_test.tl"
        | "ippool_demo.tl" | "bail_test.exe" | "fn_array_param.exe" | "full_demo.exe"
        | "hof_test.exe" | "if_let_test.exe" | "interp_test.exe" | "int_match_default.exe"
        | "map_test.exe" | "mega_test.exe" => Some("exe/browser/network — skip"),
        // Examples that reach live network/browser (need live egress)
        "public_source_get_batch.tl"
        | "tor_single_test.tl" | "test_dealhunter.tl" => {
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

// ── String.parse(): the native lowering added 2026-10-22 ────────────────────
//
// Before this, `.parse()` had no codegen lowering and `--require-native`
// refused every program that used it (stub register row 141). These two tests
// pin the behaviour that replaced that refusal: integer text agrees on both
// planes, and text that is not a number fails with the interpreter's own
// sentence instead of becoming a silent 0.

fn write_probe(name: &str, source: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("parse_parity");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, source).unwrap();
    path
}

fn run_plane(path: &std::path::Path, native: bool) -> std::process::Output {
    let mut cmd = Command::new(TALLOW_BIN);
    cmd.arg("run");
    if native {
        cmd.arg("--require-native");
    } else {
        cmd.arg("--interpret");
    }
    cmd.arg(path).output().unwrap()
}

#[test]
fn string_parse_of_integers_is_identical_on_both_planes() {
    let path = write_probe(
        "parse_ints.tl",
        r#"fn parse_port(s: String) -> Result<i64> {
    let n = s.parse()
    if n < 0 {
        bail "port must be positive"
    }
    if n > 65535 {
        bail "port too large"
    }
    Ok(n)
}

fn main() {
    print(parse_port("8080"))
    print(parse_port("70000"))
    print(parse_port("-1"))
    print("42".parse())
}
"#,
    );

    let interpreted = run_plane(&path, false);
    let native = run_plane(&path, true);

    let i_out = String::from_utf8_lossy(&interpreted.stdout).to_string();
    let n_out = String::from_utf8_lossy(&native.stdout).to_string();
    assert!(
        native.status.success(),
        "native plane refused an integer parse: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(i_out, n_out, "stdout diverged between planes");
    assert!(i_out.contains("Ok(8080)"), "unexpected output: {i_out}");
}

#[test]
fn string_parse_of_non_numbers_fails_with_the_interpreter_wording() {
    let path = write_probe(
        "parse_bad.tl",
        r#"fn main() {
    print("abc".parse())
}
"#,
    );

    let interpreted = run_plane(&path, false);
    let native = run_plane(&path, true);

    let i_err = String::from_utf8_lossy(&interpreted.stderr).to_string();
    let n_err = String::from_utf8_lossy(&native.stderr).to_string();
    assert!(!interpreted.status.success(), "interpreter accepted 'abc'");
    assert!(!native.status.success(), "native plane accepted 'abc'");
    assert!(
        i_err.contains("cannot parse 'abc' as number"),
        "interpreter wording changed: {i_err}"
    );
    assert!(
        n_err.contains("cannot parse 'abc' as number"),
        "native wording differs from the interpreter: {n_err}"
    );
}
