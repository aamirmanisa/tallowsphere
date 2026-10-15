//! Integration tests for json stdlib functions.
//!
//! Verifies json.to_string serialization, json.parse/decode round-trip,
//! json.stringify backward compatibility, and typed access on parsed JSON values.

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

// ── json.to_string tests ────────────────────────────────────────────────────

#[test]
fn test_json_to_string_map() {
    let output = run_output(
        r#"fn main() {
            let m = {"name": "test", "count": 42}
            let s = json.to_string(m)
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let json = &output[0];
    assert!(json.contains("\"name\""), "should contain key 'name': {json}");
    assert!(json.contains("\"test\""), "should contain value 'test': {json}");
    assert!(json.contains("42"), "should contain value 42: {json}");
}

#[test]
fn test_json_to_string_array() {
    let output = run_output(
        r#"fn main() {
            let a = [1, 2, 3]
            let s = json.to_string(a)
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let json = &output[0];
    assert!(
        json.contains("1") && json.contains("2") && json.contains("3"),
        "should contain 1,2,3: {json}"
    );
    assert!(json.starts_with('[') && json.ends_with(']'), "should be array: {json}");
}

#[test]
fn test_json_to_string_nested() {
    let output = run_output(
        r#"fn main() {
            let m = {"items": [10, 20], "ok": true}
            let s = json.to_string(m)
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let json = &output[0];
    assert!(json.contains("[10,20]"), "should contain nested array: {json}");
    assert!(json.contains("true"), "should contain bool: {json}");
}

#[test]
fn test_json_to_string_nil() {
    let output = run_output(
        r#"fn main() {
            let s = json.to_string(nil)
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "null");
}

#[test]
fn test_json_to_string_string() {
    let output = run_output(
        r#"fn main() {
            let s = json.to_string("hello world")
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "\"hello world\"");
}

// ── json.stringify backward compatibility ───────────────────────────────────

#[test]
fn test_json_stringify_still_works() {
    let output = run_output(
        r#"fn main() {
            let m = {"a": 1}
            let s = json.stringify(m)
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let json = &output[0];
    assert!(json.contains("\"a\""), "stringify should still work: {json}");
    assert!(json.contains("1"), "stringify should still work: {json}");
}

#[test]
fn test_json_encode_still_works() {
    let output = run_output(
        r#"fn main() {
            let s = json.encode([true, false])
            print(s)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let json = &output[0];
    assert!(json.contains("true") && json.contains("false"), "encode should work: {json}");
}

// ── json.parse round-trip ───────────────────────────────────────────────────

#[test]
fn test_json_round_trip() {
    // Build a map, serialize, parse back, serialize again
    let output = run_output(
        r#"fn main() {
            let m = {"x": 10, "y": 20}
            let serialized = json.to_string(m)
            let parsed = json.parse(serialized) match {
                Ok(v) -> v,
                Err(e) -> nil
            }
            let back = json.to_string(parsed)
            print(back)
        }"#,
    );
    assert_eq!(output.len(), 1);
    let json = &output[0];
    assert!(json.contains("10"), "round-trip should preserve 10: {json}");
    assert!(json.contains("20"), "round-trip should preserve 20: {json}");
}

// ── json.parse typed access (JSON-03) ───────────────────────────────────────

#[test]
fn test_json_parse_array_indexing() {
    // Parse a JSON array and access by index
    let output = run_output(
        r#"fn main() {
            let arr = json.parse("[10, 20, 30]") match {
                Ok(v) -> v,
                Err(e) -> [0]
            }
            print(arr[0])
            print(arr[2])
        }"#,
    );
    assert_eq!(output.len(), 2);
    assert_eq!(output[0], "10");
    assert_eq!(output[1], "30");
}

#[test]
fn test_json_parse_field_access() {
    // Parse a JSON object and access fields
    // json.parse returns Value::Map with string keys
    // FieldAccess on maps looks up the field name as a string key
    // Build JSON via map literal -> json.to_string -> json.parse round-trip
    let output = run_output(
        r#"fn main() {
            let m = {"name": "alice", "age": 30}
            let json_str = json.to_string(m)
            let obj = json.parse(json_str) match {
                Ok(v) -> v,
                Err(e) -> nil
            }
            print(obj.name)
            print(obj.age)
        }"#,
    );
    assert_eq!(output.len(), 2, "Expected 2 outputs from field access on parsed JSON");
    assert_eq!(output[0], "alice");
    assert_eq!(output[1], "30");
}

#[test]
fn test_json_parse_nested_access() {
    // Parse nested JSON and access deep fields via round-trip
    let output = run_output(
        r#"fn main() {
            let m = {"items": [1, 2, 3]}
            let json_str = json.to_string(m)
            let data = json.parse(json_str) match {
                Ok(v) -> v,
                Err(e) -> nil
            }
            let items = data.items
            print(items[1])
        }"#,
    );
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], "2");
}
