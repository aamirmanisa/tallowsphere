//! Standard library: `tallow.config` — config file parsing.
//!
//! Real runtime implementations for TOML and JSON parsing backed by the
//! `toml` and `serde_json` crates, mirroring the declarations in
//! `stdlib/config.tl`. YAML is not supported by a bundled crate, so
//! `parse_yaml`/`to_yaml` return honest errors rather than fake placeholders.

use super::StdlibResult;
use crate::interp::Value;

/// Contract-level dispatch for `tallow.config.*` functions.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "parse_toml" => {
            let input = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("config.parse_toml: expected a String".into())),
            };
            Some(parse_toml(&input))
        }
        "parse_json" => {
            let input = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("config.parse_json: expected a String".into())),
            };
            Some(parse_json(&input))
        }
        "parse_yaml" => Some(Err(
            "config.parse_yaml: YAML support is not bundled; use parse_toml or \
             parse_json, or pass an already-parsed Map"
                .into(),
        )),
        "load" => {
            let path = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("config.load: expected a String path".into())),
            };
            Some(load(&path))
        }
        "to_toml" => {
            let value = match args.first() {
                Some(v) => v.clone(),
                None => return Some(Err("config.to_toml: expected a value".into())),
            };
            Some(to_toml(&value))
        }
        "to_yaml" => Some(Err(
            "config.to_yaml: YAML support is not bundled; use to_toml instead".into(),
        )),
        _ => None,
    }
}

/// Contract-level dispatch for `tallow.config.*` struct methods.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

/// Parse a TOML string into a Tallow value.
pub fn parse_toml(input: &str) -> StdlibResult {
    let table: toml::Value = toml::from_str(input)
        .map_err(|e| format!("config.parse_toml: {e}"))?;
    Ok(toml_to_tallow(&table))
}

/// Parse a JSON string into a Tallow value.
pub fn parse_json(input: &str) -> StdlibResult {
    let json: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| format!("config.parse_json: {e}"))?;
    Ok(json_to_tallow(&json))
}

/// Load a config file, auto-detecting format by extension
/// (`.toml`, `.json`, `.yaml`/`.yml`).
pub fn load(path: &str) -> StdlibResult {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("config.load: cannot read {path}: {e}"))?;
    let lower = path.to_lowercase();
    if lower.ends_with(".toml") {
        parse_toml(&content)
    } else if lower.ends_with(".json") {
        parse_json(&content)
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        Err("config.load: YAML support is not bundled; convert the file to \
             TOML or JSON"
            .into())
    } else {
        // Fall back to sniffing the first non-whitespace character.
        let trimmed = content.trim_start();
        if trimmed.starts_with('{') {
            parse_json(&content)
        } else {
            parse_toml(&content)
        }
    }
}

/// Serialize a Tallow value to a TOML string.
pub fn to_toml(value: &Value) -> StdlibResult {
    let toml_val = tallow_to_toml(value)?;
    Ok(Value::String(
        toml::to_string(&toml_val).map_err(|e| format!("config.to_toml: {e}"))?,
    ))
}

/// Convert a `toml::Value` into a Tallow `Value`.
fn toml_to_tallow(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::Int(*i as i128),
        toml::Value::Float(f) => Value::Float(*f),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
        toml::Value::Array(items) => {
            Value::Array(items.iter().map(toml_to_tallow).collect())
        }
        toml::Value::Table(table) => {
            let pairs: Vec<(Value, Value)> = table
                .iter()
                .map(|(k, val)| (Value::String(k.clone()), toml_to_tallow(val)))
                .collect();
            Value::Map(pairs)
        }
    }
}

/// Convert a `serde_json::Value` into a Tallow `Value`.
fn json_to_tallow(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(u) = n.as_u64() {
                Value::Int(u as i128)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(json_to_tallow).collect())
        }
        serde_json::Value::Object(obj) => {
            let pairs: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, val)| (Value::String(k.clone()), json_to_tallow(val)))
                .collect();
            Value::Map(pairs)
        }
    }
}

/// Convert a Tallow `Value` into a `toml::Value` for serialization.
fn tallow_to_toml(v: &Value) -> Result<toml::Value, String> {
    match v {
        Value::Nil => Err("config.to_toml: cannot serialize nil to TOML".into()),
        Value::Bool(b) => Ok(toml::Value::Boolean(*b)),
        Value::Int(i) => Ok(toml::Value::Integer(*i as i64)),
        Value::Float(f) => Ok(toml::Value::Float(*f)),
        Value::String(s) => Ok(toml::Value::String(s.clone())),
        Value::Bytes(b) => Ok(toml::Value::String(String::from_utf8_lossy(b).into_owned())),
        Value::Array(items) => {
            let vals: Result<Vec<toml::Value>, String> =
                items.iter().map(tallow_to_toml).collect();
            Ok(toml::Value::Array(vals?))
        }
        Value::Map(pairs) => {
            let mut table = toml::map::Map::new();
            for (k, val) in pairs {
                let key = match k {
                    Value::String(s) => s.clone(),
                    other => format!("{}", other.as_string()),
                };
                table.insert(key, tallow_to_toml(val)?);
            }
            Ok(toml::Value::Table(table))
        }
        other => Err(format!(
            "config.to_toml: unsupported value type {}",
            other.as_string()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_roundtrip() {
        let parsed = parse_toml("name = \"test\"\ncount = 42\nactive = true\n").unwrap();
        match &parsed {
            Value::Map(pairs) => {
                assert_eq!(pairs.len(), 3);
                let name = pairs
                    .iter()
                    .find(|(k, _)| matches!(k, Value::String(s) if s == "name"))
                    .map(|(_, v)| v.clone());
                assert!(matches!(name, Some(Value::String(s)) if s == "test"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn json_parse() {
        let parsed = parse_json("{\"a\": 1, \"b\": [true, \"x\"]}").unwrap();
        match &parsed {
            Value::Map(pairs) => {
                assert_eq!(pairs.len(), 2);
                let a = pairs
                    .iter()
                    .find(|(k, _)| matches!(k, Value::String(s) if s == "a"))
                    .map(|(_, v)| v.clone());
                assert!(matches!(a, Some(Value::Int(1))));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn invalid_json_errors() {
        assert!(parse_json("{ not valid }").is_err());
        assert!(parse_toml("= invalid =").is_err());
    }

    #[test]
    fn to_toml_roundtrip() {
        let value = Value::Map(vec![
            (Value::String("title".into()), Value::String("hi".into())),
            (Value::String("n".into()), Value::Int(7)),
        ]);
        let out = to_toml(&value).unwrap();
        let Value::String(out) = &out else { panic!("expected string") };
        assert!(out.contains("title = \"hi\""));
        assert!(out.contains("n = 7"));
    }

    #[test]
    fn yaml_is_honest_error() {
        assert!(matches!(
            dispatch("parse_yaml", vec![Value::String("a: 1".into())]),
            Some(Err(_))
        ));
    }

    #[test]
    fn dispatch_routing() {
        assert!(dispatch("parse_toml", vec![]).is_some()); // error but recognized
        assert!(dispatch("bogus", vec![]).is_none());
    }
}
