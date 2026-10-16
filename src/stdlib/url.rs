//! Standard library: `tallow.url` -- URL parsing/manipulation.

use super::StdlibResult;
use crate::interp::Value;

/// Dispatch a `tallow.url.*` function call.
///
/// Functions already implemented inline in interp.rs (parse, encode, decode)
/// return None to fall through.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "parse" | "encode" | "decode" => None,

        // Declared in stdlib/url.tl with an empty `// native:` body and previously
        // absent from every dispatcher. Implemented 2026-10-12.
        "encode_query" => Some(do_encode_query(args)),

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.url` object (e.g., UrlParts).
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

// ── Implementations ──────────────────────────────────────────────────────────

/// `url.encode_query(params: Map<String, String>) -> String`
///
/// Builds `"key=value&key2=value2"`, percent-encoding keys and values.
fn do_encode_query(args: Vec<Value>) -> StdlibResult {
    let pairs = match args.first() {
        Some(Value::Map(p)) => p,
        _ => return Err("url.encode_query: expected a Map<String, String> argument".into()),
    };
    let mut out: Vec<String> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let (key, val) = match (k, v) {
            (Value::String(a), Value::String(b)) => (a, b),
            _ => return Err("url.encode_query: keys and values must be strings".into()),
        };
        out.push(format!("{}={}", percent_encode(key), percent_encode(val)));
    }
    Ok(Value::String(out.join("&")))
}

/// Percent-encode per RFC 3986: unreserved = ALPHA / DIGIT / `-` `.` `_` `~`.
///
/// Space encodes as `%20`, **not** `+` — this is a query *component* encoder,
/// not an `application/x-www-form-urlencoded` one. Getting this wrong silently
/// corrupts values that contain `+`.
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: Vec<(&str, &str)>) -> Value {
        Value::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (Value::String(k.into()), Value::String(v.into())))
                .collect(),
        )
    }

    #[test]
    fn percent_encode_leaves_unreserved_alone() {
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
    }

    #[test]
    fn percent_encode_escapes_space_as_percent20_not_plus() {
        assert_eq!(percent_encode("a b"), "a%20b");
    }

    #[test]
    fn percent_encode_escapes_reserved_and_utf8() {
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn encode_query_builds_pairs_in_order() {
        let r = do_encode_query(vec![map(vec![("q", "a b"), ("n", "1")])]).unwrap();
        match r {
            Value::String(s) => assert_eq!(s, "q=a%20b&n=1"),
            other => panic!("expected String, got {other:?}"),
        }
    }

    #[test]
    fn encode_query_rejects_non_map() {
        assert!(do_encode_query(vec![Value::String("x".into())]).is_err());
        assert!(do_encode_query(vec![]).is_err());
    }

    #[test]
    fn encode_query_rejects_non_string_values() {
        let bad = Value::Map(vec![(Value::String("k".into()), Value::Int(1))]);
        assert!(do_encode_query(vec![bad]).is_err());
    }
}
