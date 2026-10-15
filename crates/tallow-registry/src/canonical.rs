//! Canonical JSON (receipt format v1) + digests.
//!
//! Rules (spec: `RECEIPT-FORMAT-v1.md` §canonicalization):
//! - object keys sorted lexicographically (UTF-8 code-point order), recursive
//! - no insignificant whitespace
//! - strings escaped with the minimal JSON escapes (serde_json escaping);
//!   UTF-8 is emitted raw
//! - numbers are serialized as-is (integer payloads recommended in v1)
//!
//! The implementation sorts keys itself and never relies on map ordering
//! features of serde_json, so the encoding is stable across feature flags.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical serialization of a JSON value (receipt format v1).
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

/// Lowercase hex sha256 of the canonical encoding.
pub fn canonical_digest_hex(v: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json(v).as_bytes()))
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string encode")),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key encode"));
                out.push(':');
                write_value(&map[*k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_and_escapes() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": "x"})),
            r#"{"a":"x","b":1}"#
        );
        assert_eq!(
            canonical_json(&json!({"b": {"d": 1, "c": 2}, "a": []})),
            r#"{"a":[],"b":{"c":2,"d":1}}"#
        );
        assert_eq!(
            canonical_json(&json!({"a": "x\"y\n"})),
            "{\"a\":\"x\\\"y\\n\"}"
        );
        // UTF-8 emitted raw, not \u-escaped
        assert_eq!(canonical_json(&json!({"k": "héllo"})), r#"{"k":"héllo"}"#);
    }

    #[test]
    fn digest_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).expect("parse");
        let b = json!({"a": {"x": 3, "y": 2}, "b": 1});
        assert_eq!(canonical_digest_hex(&a), canonical_digest_hex(&b));
    }
}
