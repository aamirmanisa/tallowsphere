//! Standard library: `tallow.json` -- JSON parse/serialize.

use super::StdlibResult;
use crate::interp::Value;

/// Dispatch a `tallow.json.*` function call.
///
/// Functions already implemented inline in interp.rs (parse/decode,
/// stringify/encode) return None to fall through.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "parse" | "decode" | "stringify" | "encode" => None,
        // json.parse_value — parse a JSON string into a Value tree.
        // Declared in stdlib/json.tl with an empty `// native:` body and previously
        // absent from every dispatcher. Implemented 2026-10-12.
        "parse_value" => Some(do_parse_value(args)),
        // json.to_json_pretty — same serialization as to_string, indented.
        // Declared in stdlib/json.tl with an empty body and unreachable until the
        // 2026-10-22 surface audit.
        "to_json_pretty" => match args.first() {
            Some(val) => {
                let compact = tallow_value_to_json(val);
                match serde_json::from_str::<serde_json::Value>(&compact) {
                    Ok(parsed) => match serde_json::to_string_pretty(&parsed) {
                        Ok(pretty) => Some(Ok(Value::String(pretty))),
                        Err(e) => Some(Err(format!("json.to_json_pretty: {e}"))),
                    },
                    Err(e) => Some(Err(format!("json.to_json_pretty: {e}"))),
                }
            }
            None => Some(Err("json.to_json_pretty requires a value argument".into())),
        },
        // json.to_string — serialize any Value to JSON string
        "to_string" => {
            if let Some(val) = args.first() {
                Some(Ok(Value::String(tallow_value_to_json(val))))
            } else {
                Some(Err("json.to_string() requires a value argument".to_string()))
            }
        }
        _ => None,
    }
}

/// Dispatch a method call on a `tallow.json` object (e.g., JsonValue).
///
/// `json.parse_value` returns plain runtime values (`Nil`, `Bool`, `Int`,
/// `Float`, `String`, `Array`, `Map`), not a tagged `JsonValue` struct, so the
/// accessors declared in `stdlib/json.tl` have to answer those shapes. Before
/// this, the whole accessor surface (`get`, `at`, `as_string`, `as_number`,
/// `as_bool`, `is_null`, `len`) was declared and none of it was reachable:
/// `json.parse_value("123").as_number()` died with "undefined function".
/// Struct receivers are deliberately left alone so a user type keeps its own
/// methods of the same name.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if matches!(object, Value::Struct { .. }) {
        return None;
    }
    match method {
        "is_null" if matches!(object, Value::Nil) => Some(Ok(Value::Bool(true))),
        "is_null" => Some(Ok(Value::Bool(false))),
        "as_number" => Some(Ok(match object {
            Value::Int(n) => Value::Float(*n as f64),
            Value::Float(f) => Value::Float(*f),
            _ => Value::Nil,
        })),
        "as_bool" => Some(Ok(match object {
            Value::Bool(b) => Value::Bool(*b),
            _ => Value::Nil,
        })),
        "as_string" => Some(Ok(match object {
            Value::String(s) => Value::String(s.clone()),
            _ => Value::Nil,
        })),
        "get" => {
            let key = match args.first() {
                Some(Value::String(k)) => k.clone(),
                _ => return Some(Err("json.get: expected a String key".into())),
            };
            // The second argument is the default, matching the map builtin:
            // without it `map.get(k, 0)` returned nil and word-count loops died
            // on "cannot apply Add to nil and int" (measured 2026-10-22).
            let fallback = args.get(1).cloned().unwrap_or(Value::Nil);
            Some(Ok(match object {
                Value::Map(m) => m
                    .iter()
                    .find(|(k, _)| matches!(k, Value::String(s) if *s == key))
                    .map(|(_, v)| v.clone())
                    .unwrap_or(fallback),
                _ => fallback,
            }))
        }
        "at" => {
            let idx = match args.first() {
                Some(Value::Int(i)) => *i,
                _ => return Some(Err("json.at: expected an Int index".into())),
            };
            let fallback = args.get(1).cloned().unwrap_or(Value::Nil);
            Some(Ok(match object {
                Value::Array(items) => usize::try_from(idx)
                    .ok()
                    .and_then(|i| items.get(i).cloned())
                    .unwrap_or(fallback),
                _ => fallback,
            }))
        }
        "len" => Some(Ok(match object {
            Value::Array(items) => Value::Int(items.len() as i128),
            Value::Map(m) => Value::Int(m.len() as i128),
            Value::String(s) => Value::Int(s.chars().count() as i128),
            _ => Value::Int(0),
        })),
        _ => None,
    }
}

/// Serialize a Tallow Value to a JSON string.
///
/// Handles all Value variants including privacy types (redacted in output).
fn tallow_value_to_json(val: &Value) -> String {
    match val {
        Value::Nil => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                "null".to_string()
            } else {
                format!("{f}")
            }
        }
        Value::String(s) => format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t")
        ),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(tallow_value_to_json).collect();
            format!("[{}]", inner.join(","))
        }
        Value::Map(pairs) => {
            let entries: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}:{}", tallow_value_to_json(k), tallow_value_to_json(v)))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Struct { name: _, fields } => {
            let entries: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, tallow_value_to_json(v)))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Ok(inner) => tallow_value_to_json(inner),
        Value::Err(inner) => format!("{{\"error\":{}}}", tallow_value_to_json(inner)),
        Value::Enum {
            variant, fields, ..
        } => {
            if fields.is_empty() {
                format!("\"{}\"", variant)
            } else {
                let f: Vec<String> = fields
                    .iter()
                    .map(|(k, v)| format!("\"{}\":{}", k, tallow_value_to_json(v)))
                    .collect();
                format!("{{\"{}\":{{{}}}}}", variant, f.join(","))
            }
        }
        Value::Private(_) => "\"[REDACTED]\"".to_string(),
        Value::Secret(_) => "\"[REDACTED]\"".to_string(),
        _ => "null".to_string(),
    }
}

/// Parse a JSON string into a Tallow `Value` tree.
///
/// Numbers prefer `Int` when they fit an i64, else `Float`; objects become
/// `Value::Map` (ordered as emitted by serde_json's default BTreeMap ordering).
fn do_parse_value(args: Vec<Value>) -> StdlibResult {
    let input = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("json.parse_value: expected a string argument".into()),
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("json.parse_value: {e}"))?;
    Ok(json_to_value(&parsed))
}

fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i as i128),
            None => Value::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => Value::Map(
            map.iter()
                .map(|(k, val)| (Value::String(k.clone()), json_to_value(val)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_null_and_bool() {
        assert!(matches!(do_parse_value(vec![Value::String("null".into())]).unwrap(), Value::Nil));
        assert!(matches!(
            do_parse_value(vec![Value::String("true".into())]).unwrap(),
            Value::Bool(true)
        ));
    }

    #[test]
    fn parse_value_int_stays_int_but_float_does_not() {
        assert!(matches!(
            do_parse_value(vec![Value::String("42".into())]).unwrap(),
            Value::Int(42)
        ));
        assert!(matches!(
            do_parse_value(vec![Value::String("3.5".into())]).unwrap(),
            Value::Float(_)
        ));
    }

    #[test]
    fn parse_value_array_and_object() {
        let arr = do_parse_value(vec![Value::String("[1,2]".into())]).unwrap();
        match arr {
            Value::Array(v) => assert_eq!(v.len(), 2),
            other => panic!("expected Array, got {other:?}"),
        }
        let obj = do_parse_value(vec![Value::String("{\"a\":1}".into())]).unwrap();
        match obj {
            Value::Map(m) => {
                assert_eq!(m.len(), 1);
                assert!(matches!(&m[0].0, Value::String(k) if k == "a"));
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn parse_value_rejects_invalid_json_and_non_string() {
        assert!(do_parse_value(vec![Value::String("{not json".into())]).is_err());
        assert!(do_parse_value(vec![Value::Int(1)]).is_err());
        assert!(do_parse_value(vec![]).is_err());
    }

    #[test]
    fn to_string_nil() {
        let result = tallow_value_to_json(&Value::Nil);
        assert_eq!(result, "null");
    }

    #[test]
    fn to_string_bool() {
        assert_eq!(tallow_value_to_json(&Value::Bool(true)), "true");
        assert_eq!(tallow_value_to_json(&Value::Bool(false)), "false");
    }

    #[test]
    fn to_string_int() {
        assert_eq!(tallow_value_to_json(&Value::Int(42)), "42");
        assert_eq!(tallow_value_to_json(&Value::Int(-7)), "-7");
    }

    #[test]
    fn to_string_float() {
        assert_eq!(tallow_value_to_json(&Value::Float(3.14)), "3.14");
        assert_eq!(tallow_value_to_json(&Value::Float(f64::NAN)), "null");
        assert_eq!(tallow_value_to_json(&Value::Float(f64::INFINITY)), "null");
    }

    #[test]
    fn to_string_string() {
        assert_eq!(
            tallow_value_to_json(&Value::String("hello".into())),
            "\"hello\""
        );
        assert_eq!(
            tallow_value_to_json(&Value::String("a\"b".into())),
            "\"a\\\"b\""
        );
    }

    #[test]
    fn to_string_array() {
        let arr = Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert_eq!(tallow_value_to_json(&arr), "[1,2,3]");
    }

    #[test]
    fn to_string_map() {
        let map = Value::Map(vec![(
            Value::String("key".into()),
            Value::String("val".into()),
        )]);
        assert_eq!(tallow_value_to_json(&map), "{\"key\":\"val\"}");
    }

    #[test]
    fn to_string_struct() {
        let s = Value::Struct {
            name: "Config".into(),
            fields: vec![("port".into(), Value::Int(8080))],
        };
        assert_eq!(tallow_value_to_json(&s), "{\"port\":8080}");
    }

    #[test]
    fn to_string_privacy_redacted() {
        let p = Value::Private(Box::new(Value::String("secret@mail.com".into())));
        assert_eq!(tallow_value_to_json(&p), "\"[REDACTED]\"");
        let s = Value::Secret(Box::new(Value::String("api-key-123".into())));
        assert_eq!(tallow_value_to_json(&s), "\"[REDACTED]\"");
    }

    #[test]
    fn dispatch_to_string_works() {
        let result = dispatch("to_string", vec![Value::Int(42)]);
        assert!(result.is_some());
        let val = result.unwrap().unwrap();
        match val {
            Value::String(s) => assert_eq!(s, "42"),
            other => panic!("expected String, got: {}", other.as_string()),
        }
    }

    #[test]
    fn dispatch_to_string_no_args() {
        let result = dispatch("to_string", vec![]);
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }
}
