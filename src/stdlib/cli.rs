//! Standard library: `tallow.cli` — CLI argument parsing.
//!
//! Real runtime implementations for the `tallow.cli` structs declared in
//! `stdlib/cli.tl`. Getter methods return the corresponding struct field;
//! `App.run` returns an honest error (argument parsing requires the
//! `std::env::args` of the host process and is handled at the CLI layer,
//! not inside a library stdlib call).

use super::StdlibResult;
use crate::interp::Value;

/// Contract-level dispatch for `tallow.cli.*` functions.
pub fn dispatch(function: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // No free functions are declared in stdlib/cli.tl.
        _ => None,
    }
}

/// Contract-level dispatch for `tallow.cli.*` struct methods.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, fields } = object else {
        return None;
    };
    let getter = |field: &str| -> Option<StdlibResult> {
        fields
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| Ok(v.clone()))
    };
    match name.as_str() {
        "App" => match method {
            "name" | "version" | "description" => getter(method),
            "run" => Some(Err(
                "cli.App.run: not available inside the library stdlib; parse \
                 argv at the host CLI boundary instead"
                    .into(),
            )),
            _ => None,
        },
        "Command" => match method {
            "name" | "description" => getter(method),
            "help" => Some(Ok(Value::String(match getter("description") {
                Some(Ok(Value::String(d))) if !d.is_empty() => d,
                _ => fields
                    .iter()
                    .find(|(k, _)| k == "name")
                    .map(|(_, v)| v.as_string())
                    .unwrap_or_default(),
            }))),
            _ => None,
        },
        "Flag" => match method {
            "name" | "short" | "long" | "description" => getter(method),
            "required" => Some(Ok(fields
                .iter()
                .find(|(k, _)| k == "required")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Bool(false)))),
            "default_value" => Some(Ok(fields
                .iter()
                .find(|(k, _)| k == "default")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Nil))),
            _ => None,
        },
        "Context" => match method {
            "command_name" => getter("command_name").or_else(|| getter("name")),
            "args" => getter("args"),
            "flags" => getter("flags"),
            "flag" => Some(cli_context_flag(fields, &_args)),
            "flag_or" => Some(cli_context_flag_or(fields, &_args)),
            "has_flag" => Some(cli_context_has_flag(fields, &_args)),
            _ => None,
        },
        _ => None,
    }
}

/// `Context.flag(name) -> String?` — look up a flag value by name.
fn cli_context_flag(fields: &[(String, Value)], args: &[Value]) -> StdlibResult {
    let name = expect_string_arg(args, 0, "cli.Context.flag")?;
    let Some((_, Value::Map(flags))) = fields.iter().find(|(k, _)| k == "flags") else {
        return Ok(Value::Nil);
    };
    Ok(flags
        .iter()
        .find(|(k, _)| k.as_string() == name)
        .map(|(_, v)| v.clone())
        .unwrap_or(Value::Nil))
}

/// `Context.flag_or(name, default) -> String` — flag value or a default.
fn cli_context_flag_or(fields: &[(String, Value)], args: &[Value]) -> StdlibResult {
    let name = expect_string_arg(args, 0, "cli.Context.flag_or")?;
    let default = args
        .get(1)
        .map(|v| v.as_string())
        .unwrap_or_default();
    let Some((_, Value::Map(flags))) = fields.iter().find(|(k, _)| k == "flags") else {
        return Ok(Value::String(default));
    };
    let found = flags
        .iter()
        .find(|(k, _)| k.as_string() == name)
        .map(|(_, v)| v.as_string());
    Ok(Value::String(found.unwrap_or(default)))
}

/// `Context.has_flag(name) -> bool` — whether a flag is present.
fn cli_context_has_flag(fields: &[(String, Value)], args: &[Value]) -> StdlibResult {
    let name = expect_string_arg(args, 0, "cli.Context.has_flag")?;
    let Some((_, Value::Map(flags))) = fields.iter().find(|(k, _)| k == "flags") else {
        return Ok(Value::Bool(false));
    };
    Ok(Value::Bool(flags.iter().any(|(k, _)| k.as_string() == name)))
}

fn expect_string_arg(args: &[Value], idx: usize, ctx: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("{ctx}: expected a String at argument {idx}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> Value {
        Value::Struct {
            name: "App".into(),
            fields: vec![
                ("name".into(), Value::String("myapp".into())),
                ("version".into(), Value::String("1.2.3".into())),
                ("description".into(), Value::String("does things".into())),
            ],
        }
    }

    fn ctx() -> Value {
        Value::Struct {
            name: "Context".into(),
            fields: vec![
                ("command_name".into(), Value::String("serve".into())),
                ("args".into(), Value::Array(vec![Value::String("a".into())])),
                (
                    "flags".into(),
                    Value::Map(vec![(
                        Value::String("--verbose".into()),
                        Value::String("true".into()),
                    )]),
                ),
            ],
        }
    }

    #[test]
    fn app_getters() {
        let d = dispatch_method(&app(), "name", vec![]).unwrap().unwrap();
        assert_eq!(d.as_string(), "myapp");
        let v = dispatch_method(&app(), "version", vec![]).unwrap().unwrap();
        assert_eq!(v.as_string(), "1.2.3");
        assert!(dispatch_method(&app(), "run", vec![]).unwrap().is_err());
    }

    #[test]
    fn context_flag() {
        let d = dispatch_method(
            &ctx(),
            "flag",
            vec![Value::String("--verbose".into())],
        )
        .unwrap()
        .unwrap();
        assert_eq!(d.as_string(), "true");
        let miss = dispatch_method(&ctx(), "flag", vec![Value::String("--missing".into())])
            .unwrap()
            .unwrap();
        assert!(matches!(miss, Value::Nil));
    }

    #[test]
    fn context_flag_or() {
        let d = dispatch_method(
            &ctx(),
            "flag_or",
            vec![Value::String("--missing".into()), Value::String("no".into())],
        )
        .unwrap()
        .unwrap();
        assert_eq!(d.as_string(), "no");
    }

    #[test]
    fn context_has_flag() {
        let d = dispatch_method(&ctx(), "has_flag", vec![Value::String("--verbose".into())])
            .unwrap()
            .unwrap();
        assert!(matches!(d, Value::Bool(true)));
    }

    #[test]
    fn unknown_routes_none() {
        assert!(dispatch_method(&app(), "bogus", vec![]).is_none());
        assert!(dispatch("bogus", vec![]).is_none());
    }
}
