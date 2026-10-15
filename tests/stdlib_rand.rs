//! Integration tests for rand and url stdlib functions.
//!
//! Verifies rand.bytes, rand.u64, rand.range, rand.uuid, rand.token
//! produce correctly formatted random output.
//! Verifies url.parse, url.encode, url.decode (inline in interp.rs) work.

use tallow::interp::Interpreter;
use tallow::lexer;
use tallow::parser;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn run_output(source: &str) -> Vec<String> {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    interp.run(&program).expect("runtime error");
    interp.output
}

// ── Rand tests ──────────────────────────────────────────────────────────────

#[test]
fn test_rand_bytes() {
    let output = run_output(
        r#"fn main() {
            let b = rand.bytes(16)
            print(b)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let hex = &output[0];
    assert_eq!(hex.len(), 32, "16 bytes = 32 hex chars, got {}", hex.len());
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "Expected hex string, got: {hex}"
    );
}

#[test]
fn test_rand_bytes_different_each_call() {
    let output = run_output(
        r#"fn main() {
            let a = rand.bytes(16)
            let b = rand.bytes(16)
            print(a)
            print(b)
        }"#,
    );
    assert_eq!(output.len(), 2);
    // Extremely unlikely to be equal for 16 random bytes
    assert_ne!(output[0], output[1], "Two rand.bytes calls should differ");
}

#[test]
fn test_rand_u64() {
    let output = run_output(
        r#"fn main() {
            let n = rand.u64()
            print(n)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let parsed: u64 = output[0]
        .parse()
        .unwrap_or_else(|_| panic!("Expected u64, got: {}", output[0]));
    // Just verify it parsed -- any u64 is valid
    let _ = parsed;
}

#[test]
fn test_rand_range() {
    let output = run_output(
        r#"fn main() {
            let n = rand.range(10, 20)
            print(n)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let val: i64 = output[0]
        .parse()
        .unwrap_or_else(|_| panic!("Expected integer, got: {}", output[0]));
    assert!(
        (10..20).contains(&val),
        "Expected value in [10, 20), got {val}"
    );
}

#[test]
fn test_rand_range_error_on_invalid() {
    let (tokens, _) = lexer::tokenize(
        r#"fn main() {
            rand.range(20, 10)
        }"#,
    );
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    let result = interp.run(&program);
    assert!(result.is_err(), "rand.range(20, 10) should error");
}

#[test]
fn test_rand_uuid() {
    let output = run_output(
        r#"fn main() {
            let u = rand.uuid()
            print(u)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let uuid = &output[0];
    // UUID v4 format: 8-4-4-4-12 = 36 chars
    assert_eq!(uuid.len(), 36, "UUID should be 36 chars, got {}", uuid.len());
    // Check hyphens at positions 8, 13, 18, 23
    assert_eq!(uuid.as_bytes()[8], b'-', "Hyphen at position 8");
    assert_eq!(uuid.as_bytes()[13], b'-', "Hyphen at position 13");
    assert_eq!(uuid.as_bytes()[18], b'-', "Hyphen at position 18");
    assert_eq!(uuid.as_bytes()[23], b'-', "Hyphen at position 23");
    // Version 4: char at position 14 should be '4'
    assert_eq!(uuid.as_bytes()[14], b'4', "UUID v4: position 14 should be '4'");
    // Variant: char at position 19 should be 8, 9, a, or b
    let variant = uuid.as_bytes()[19];
    assert!(
        [b'8', b'9', b'a', b'b'].contains(&variant),
        "UUID variant char should be 8/9/a/b, got '{}'",
        variant as char
    );
}

#[test]
fn test_rand_token() {
    let output = run_output(
        r#"fn main() {
            let t = rand.token(32)
            print(t)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let token = &output[0];
    assert_eq!(
        token.len(),
        32,
        "Token should be 32 chars, got {}",
        token.len()
    );
    // URL-safe base64: alphanumeric plus - and _
    assert!(
        token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "Token should be URL-safe base64, got: {token}"
    );
}

// ── URL tests (verify existing inline implementations) ──────────────────────

#[test]
fn test_url_parse() {
    // url.parse returns Ok(Struct{scheme, host, path, query, raw})
    let output = run_output(
        r#"fn main() {
            if let Ok(u) = url.parse("https://example.com/path?q=1") {
                print(u.scheme)
                print(u.host)
                print(u.path)
                print(u.query)
            }
        }"#,
    );
    assert_eq!(output.len(), 4);
    assert_eq!(output[0], "https");
    assert_eq!(output[1], "example.com");
    assert_eq!(output[2], "/path");
    assert_eq!(output[3], "q=1");
}

#[test]
fn test_url_encode() {
    let output = run_output(
        r#"fn main() {
            let e = url.encode("hello world&foo=bar")
            print(e)
        }"#,
    );
    assert_eq!(output.len(), 1);
    // Spaces should be %20, & should be %26, = should be %3D
    assert!(
        output[0].contains("%20"),
        "Space should be percent-encoded: {}",
        output[0]
    );
    assert!(
        output[0].contains("%26"),
        "Ampersand should be percent-encoded: {}",
        output[0]
    );
}

#[test]
fn test_url_decode() {
    // url.decode returns Ok(String) -- unwrap with if-let
    let output = run_output(
        r#"fn main() {
            if let Ok(d) = url.decode("hello%20world") {
                print(d)
            }
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "hello world");
}
