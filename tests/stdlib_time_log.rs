//! Integration tests for time and log stdlib functions (Phase 12-03).

use tallow::interp::Interpreter;
use tallow::lexer;
use tallow::parser::Parser;

fn run_interp_output(source: &str) -> (tallow::interp::Value, Vec<String>) {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    let result = interp.run(&program).unwrap();
    (result, interp.output)
}

// ── Time tests ──────────────────────────────────────────────────────────

#[test]
fn test_time_now_millis() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let t = time.now()
            print(t)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let val: i128 = output[0].parse().expect("should be numeric");
    assert!(
        val > 1_700_000_000_000,
        "time.now() should return millis (> 1.7 trillion), got {val}"
    );
}

#[test]
fn test_time_sleep() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let t1 = time.now()
            time.sleep(50)
            let t2 = time.now()
            print(t2 - t1)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let diff: i128 = output[0].parse().expect("should be numeric");
    assert!(
        diff >= 40,
        "sleep(50) should cause >= 40ms difference, got {diff}ms"
    );
}

#[test]
fn test_time_parse() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let t = time.parse("2024-01-01T00:00:00Z")
            print(t)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "1704067200", "2024-01-01 UTC should be 1704067200 epoch seconds");
}

#[test]
fn test_time_parse_space_format() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let t = time.parse("2024-06-15 12:30:00")
            print(t)
        }"#,
    );
    assert_eq!(output.len(), 1);
    // 2024-06-15 12:30:00 UTC
    let val: i64 = output[0].parse().expect("should be numeric");
    assert!(val > 1_700_000_000, "should be a valid epoch timestamp");
}

#[test]
fn test_time_format() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let s = time.format(1704067200, "%Y-%m-%d")
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "2024-01-01");
}

#[test]
fn test_time_format_full() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let s = time.format(1704067200)
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "2024-01-01 00:00:00");
}

#[test]
fn test_time_roundtrip() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            let epoch = time.parse("2026-03-05T14:30:45Z")
            let formatted = time.format(epoch, "%Y-%m-%d %H:%M:%S")
            print(formatted)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "2026-03-05 14:30:45");
}

// ── Log tests ───────────────────────────────────────────────────────────

#[test]
fn test_log_info_structured() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            log.info("hello world")
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert!(
        output[0].starts_with("[INFO] ["),
        "should start with [INFO] [timestamp]: {}",
        output[0]
    );
    assert!(
        output[0].contains("hello world"),
        "should contain message: {}",
        output[0]
    );
    // Verify timestamp format: [INFO] [YYYY-MM-DDThh:mm:ssZ] message
    assert!(
        output[0].contains("T") && output[0].contains("Z"),
        "should contain ISO timestamp: {}",
        output[0]
    );
}

#[test]
fn test_log_levels() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            log.debug("d")
            log.warn("w")
            log.error("e")
        }"#,
    );
    assert_eq!(output.len(), 3);
    assert!(output[0].starts_with("[DEBUG] ["), "debug level: {}", output[0]);
    assert!(output[1].starts_with("[WARN] ["), "warn level: {}", output[1]);
    assert!(output[2].starts_with("[ERROR] ["), "error level: {}", output[2]);
}

#[test]
fn test_log_multiple_args() {
    let (_, output) = run_interp_output(
        r#"fn main() {
            log.info("count:", 42)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert!(output[0].contains("count:") && output[0].contains("42"),
        "should contain both args: {}", output[0]);
}
