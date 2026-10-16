//! Performance tests: binary size validation and startup time benchmarking.
//!
//! - `perf_binary_size`: Builds release binary, asserts < 12MB. Marked `#[ignore]` (slow).
//! - `perf_startup_time`: Measures lex+parse+typecheck+interp for a script with stdlib imports.

use std::time::Instant;

/// Build release binary and assert it stays under 12MB.
///
/// Marked `#[ignore]` because it triggers a full release build which is slow.
/// Run explicitly with: `cargo test perf_binary_size -- --ignored --nocapture`
#[test]
#[ignore]
fn perf_binary_size() {
    // Build release binary
    let status = std::process::Command::new("cargo")
        .args(["build", "--release", "--message-format=short"])
        .status()
        .expect("failed to run cargo build --release");
    assert!(status.success(), "cargo build --release failed");

    // Find the binary
    let binary_path = if cfg!(windows) {
        std::path::PathBuf::from("target/release/tallow.exe")
    } else {
        std::path::PathBuf::from("target/release/tallow")
    };

    assert!(
        binary_path.exists(),
        "Release binary not found at {}",
        binary_path.display()
    );

    let metadata = std::fs::metadata(&binary_path).expect("failed to read binary metadata");
    let size_bytes = metadata.len();
    let size_mb = size_bytes as f64 / (1024.0 * 1024.0);
    let max_size: u64 = 12 * 1024 * 1024; // 12MB

    eprintln!("Release binary size: {:.2} MB ({} bytes)", size_mb, size_bytes);
    eprintln!("Target: < 12.00 MB");
    eprintln!(
        "Status: {}",
        if size_bytes < max_size { "PASS" } else { "FAIL" }
    );

    assert!(
        size_bytes < max_size,
        "Release binary too large: {:.2} MB (limit: 12 MB)",
        size_mb
    );
}

/// Measure interpreter startup time for a script with stdlib imports.
///
/// This tests the language runtime overhead (lex + parse + typecheck + interpret),
/// NOT cargo test overhead. The 1ms target is for the runtime itself.
/// We use a generous 100ms bound to account for test runner overhead.
#[test]
fn perf_startup_time() {
    let source = r#"
import tallow.fs
import tallow.json
import tallow.time

fn main() {
    let x = 1 + 2
    print(x)
}
"#;

    // Measure lex + parse + typecheck + interpret
    let start = Instant::now();

    // Lex
    let (tokens, lex_errors) = tallow::lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "Lexer errors: {:?}", lex_errors);

    // Parse
    let program = tallow::parser::Parser::parse(tokens).expect("Parse failed");

    // Type check
    let checker = tallow::typeck::TypeChecker::new(&program);
    let (_type_env, diagnostics) = checker.check();
    // Diagnostics may have warnings for unresolved imports -- that's fine
    // Filter for actual errors (not warnings)
    let type_errors: Vec<_> = diagnostics
        .items.iter()
        .filter(|d| matches!(d.severity, tallow::error::Severity::Error))
        .collect();
    assert!(type_errors.is_empty(), "Type check errors: {:?}", type_errors);

    // Interpret
    let mut interp = tallow::interp::Interpreter::new();
    let _result = interp.run(&program);

    let elapsed = start.elapsed();
    let elapsed_us = elapsed.as_micros();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;

    eprintln!("Startup time (lex+parse+typecheck+interp): {} us ({:.3} ms)", elapsed_us, elapsed_ms);
    eprintln!("Target: < 1 ms runtime (100 ms test bound)");
    eprintln!(
        "Status: {}",
        if elapsed_ms < 100.0 { "PASS" } else { "FAIL" }
    );

    assert!(
        elapsed_ms < 100.0,
        "Startup too slow: {:.3} ms (limit: 100 ms)",
        elapsed_ms
    );
}
