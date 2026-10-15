//! Standard library: `tallow.regex` -- Regular expressions.
//!
//! Uses the `regex` crate for linear-time matching (no ReDoS).
//! All functions compile patterns via `regex::Regex::new()`.

use super::StdlibResult;
use crate::interp::Value;

/// Dispatch a `tallow.regex.*` function call.
///
/// All functions are intercepted here -- the broken inline interp.rs
/// implementations (which used string contains, not real regex) are now dead code.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(regex_new(args)),
        "is_match" => Some(regex_is_match(args)),
        // `matches` is the historical native spelling of `is_match`: the
        // compiled path has always lowered both names to the same helper
        // (src/codegen.rs `emit_stdlib_regex`), so a program that built and ran
        // natively died here with "undefined function: regex.matches" whenever
        // `tallow run` fell back to the interpreter (t_96c3ff93). Both engines
        // now resolve the alias to exactly `is_match`, and stdlib/regex.tl
        // declares it.
        "matches" => Some(regex_is_match(args)),
        "find" => Some(regex_find(args)),
        "replace" => Some(regex_replace(args)),
        _ => None,
    }
}

/// Dispatch a method call on a Regex struct.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        if name != "Regex" {
            return None;
        }
        let pattern = fields
            .iter()
            .find(|(k, _)| k == "pattern")
            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
            .unwrap_or_default();

        match method {
            "is_match" => {
                let text = args.first().map(|v| v.as_string()).unwrap_or_default();
                match regex::Regex::new(&pattern) {
                    Ok(re) => Some(Ok(Value::Bool(re.is_match(&text)))),
                    Err(e) => Some(Err(format!("regex error: {e}"))),
                }
            }
            "find" => {
                let text = args.first().map(|v| v.as_string()).unwrap_or_default();
                match regex::Regex::new(&pattern) {
                    Ok(re) => Some(Ok(re.find(&text).map(match_value).unwrap_or(Value::Nil))),
                    Err(e) => Some(Err(format!("regex error: {e}"))),
                }
            }
            // `find_all` is `find` over every non-overlapping match, in order:
            // the same `RegexMatch` value, in a slice. An empty slice (never
            // nil) is the no-match answer — the declaration says `[]RegexMatch`,
            // and `nil` would push a length check onto every caller.
            "find_all" => {
                let text = args.first().map(|v| v.as_string()).unwrap_or_default();
                match regex::Regex::new(&pattern) {
                    Ok(re) => Some(Ok(Value::Array(
                        re.find_iter(&text).map(match_value).collect(),
                    ))),
                    Err(e) => Some(Err(format!("regex error: {e}"))),
                }
            }
            // `captures` returns the capture groups of the FIRST match (group 0
            // = the whole match), or nil when the pattern does not match at all.
            // A group that did not participate (`(a)(b)?` against "a") is nil,
            // not `""`: an empty string is a legitimate capture and the two must
            // not be the same value.
            "captures" => {
                let text = args.first().map(|v| v.as_string()).unwrap_or_default();
                match regex::Regex::new(&pattern) {
                    Ok(re) => match re.captures(&text) {
                        Some(caps) => Some(Ok(Value::Array(
                            (0..caps.len())
                                .map(|i| match caps.get(i) {
                                    Some(g) => Value::String(g.as_str().to_string()),
                                    None => Value::Nil,
                                })
                                .collect(),
                        ))),
                        None => Some(Ok(Value::Nil)),
                    },
                    Err(e) => Some(Err(format!("regex error: {e}"))),
                }
            }
            // `split` splits at every match, keeping empty pieces — the same
            // convention as the String `split` method and `str::split` (a match
            // at either end yields a leading/trailing `""`, adjacent matches
            // yield an interior `""`).
            "split" => {
                let text = args.first().map(|v| v.as_string()).unwrap_or_default();
                match regex::Regex::new(&pattern) {
                    Ok(re) => Some(Ok(Value::Array(
                        re.split(&text)
                            .map(|piece| Value::String(piece.to_string()))
                            .collect(),
                    ))),
                    Err(e) => Some(Err(format!("regex error: {e}"))),
                }
            }
            // `replace_all` is the name for what `replace` already does: replace
            // EVERY match. One arm, two names — the declaration's wording and
            // the flat `regex.replace` both say so (t_96c3ff93 settled it).
            "replace" | "replace_all" => {
                let text = args.first().map(|v| v.as_string()).unwrap_or_default();
                let replacement = args.get(1).map(|v| v.as_string()).unwrap_or_default();
                match regex::Regex::new(&pattern) {
                    Ok(re) => Some(Ok(Value::String(re.replace_all(&text, replacement.as_str()).to_string()))),
                    Err(e) => Some(Err(format!("regex error: {e}"))),
                }
            }
            _ => None,
        }
    } else {
        None
    }
}

/// The `RegexMatch` value this engine hands to `.tl`: `matched`, `start`,
/// `end`. Built in exactly one place so `find`/`find_all` (and the flat
/// `regex.find`) cannot describe the same match two different ways.
///
/// `stdlib/regex.tl` declares this struct — as `RegexMatch`, with these three
/// field names. It used to declare `Match { text, start, end }`, which no
/// engine ever built: `m.text` was a runtime "no field 'text' on struct" and
/// `m.matched` was the real spelling (measured, t_fae7c4db).
fn match_value(m: regex::Match<'_>) -> Value {
    Value::Struct {
        name: "RegexMatch".to_string(),
        fields: vec![
            ("matched".to_string(), Value::String(m.as_str().to_string())),
            ("start".to_string(), Value::Int(m.start() as i128)),
            ("end".to_string(), Value::Int(m.end() as i128)),
        ],
    }
}

fn regex_new(args: Vec<Value>) -> StdlibResult {
    let pattern = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.new expects a pattern string".into()),
    };
    // Validate the pattern compiles
    match regex::Regex::new(&pattern) {
        Ok(_) => Ok(Value::Struct {
            name: "Regex".to_string(),
            fields: vec![("pattern".to_string(), Value::String(pattern))],
        }),
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!("regex error: {e}"))))),
    }
}

fn regex_is_match(args: Vec<Value>) -> StdlibResult {
    let pattern = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.is_match expects (pattern, text)".into()),
    };
    let text = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.is_match expects (pattern, text)".into()),
    };
    match regex::Regex::new(&pattern) {
        Ok(re) => Ok(Value::Bool(re.is_match(&text))),
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!("regex error: {e}"))))),
    }
}

fn regex_find(args: Vec<Value>) -> StdlibResult {
    let pattern = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.find expects (pattern, text)".into()),
    };
    let text = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.find expects (pattern, text)".into()),
    };
    match regex::Regex::new(&pattern) {
        Ok(re) => match re.find(&text) {
            Some(m) => Ok(match_value(m)),
            None => Ok(Value::Nil),
        },
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!("regex error: {e}"))))),
    }
}

fn regex_replace(args: Vec<Value>) -> StdlibResult {
    let pattern = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.replace expects (pattern, text, replacement)".into()),
    };
    let text = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.replace expects (pattern, text, replacement)".into()),
    };
    let replacement = match args.get(2) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("regex.replace expects (pattern, text, replacement)".into()),
    };
    match regex::Regex::new(&pattern) {
        Ok(re) => Ok(Value::String(re.replace_all(&text, replacement.as_str()).to_string())),
        Err(e) => Ok(Value::Err(Box::new(Value::String(format!("regex error: {e}"))))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Value {
        Value::String(v.to_string())
    }

    fn bool_of(function: &str, pattern: &str, text: &str) -> Option<bool> {
        match dispatch(function, vec![s(pattern), s(text)]) {
            Some(Ok(Value::Bool(b))) => Some(b),
            _ => None,
        }
    }

    /// `regex.matches` is the declared alias of `regex.is_match` (the compiled
    /// path always accepted it; before t_96c3ff93 the interpreter raised
    /// "undefined function: regex.matches"). Alias means: resolves, and answers
    /// exactly what `is_match` answers — including through the `regex` crate
    /// language (`\d`, `(?i)`), which a POSIX engine would reject.
    #[test]
    fn matches_alias_resolves_and_equals_is_match() {
        for (pattern, text, want) in [
            ("[0-9a-f]", "f", true),
            ("[0-9a-f]", "z", false),
            ("(?i)abc", "ABC", true),
            ("\\d", "5", true),
            ("(cat|dog)", "dog", true),
            ("[0-9xyz]", "q", false),
        ] {
            assert_eq!(
                bool_of("matches", pattern, text),
                Some(want),
                "regex.matches({pattern:?}, {text:?})"
            );
            assert_eq!(
                bool_of("matches", pattern, text),
                bool_of("is_match", pattern, text),
                "regex.matches must be exactly regex.is_match ({pattern:?}, {text:?})"
            );
        }
    }

    /// Pins the semantics `stdlib/regex.tl` now states for the flat function:
    /// `regex.replace(pattern, text, replacement)` replaces EVERY match
    /// (`Regex::replace_all`), not just the first one.
    #[test]
    fn module_replace_replaces_every_match() {
        match dispatch("replace", vec![s("[0-9a-f]"), s("az1"), s("")]) {
            Some(Ok(Value::String(out))) => assert_eq!(out, "z", "first-match-only would give \"z1\""),
            other => panic!("regex.replace should return a String, got {other:?}"),
        }
    }

    // ── t_fae7c4db: the `Regex` method surface ──────────────────────────────
    //
    // Four declarations in stdlib/regex.tl (`replace_all`, `find_all`,
    // `captures`, `split`) died at runtime with "unknown method" (or, for
    // `split`, fell through to the STRING `split` and died on "split()
    // requires args"). These tests are the interpreter-side pin; the
    // end-to-end one (both legs, pinned stdout) is
    // tests/regex_engine_parity.rs + tests/parity/parity_programs/17_regex_methods.tl.

    fn regex(pattern: &str) -> Value {
        Value::Struct {
            name: "Regex".to_string(),
            fields: vec![("pattern".to_string(), s(pattern))],
        }
    }

    fn call_method(pattern: &str, method: &str, args: Vec<Value>) -> Value {
        match dispatch_method(&regex(pattern), method, args) {
            Some(Ok(v)) => v,
            other => panic!("Regex.{method} should resolve, got {other:?}"),
        }
    }

    fn as_strings(v: &Value) -> Vec<Option<String>> {
        match v {
            Value::Array(items) => items
                .iter()
                .map(|i| match i {
                    Value::String(s) => Some(s.clone()),
                    Value::Nil => None,
                    other => panic!("unexpected array element {other:?}"),
                })
                .collect(),
            other => panic!("expected an Array, got {other:?}"),
        }
    }

    fn as_string(v: &Value) -> String {
        match v {
            Value::String(s) => s.clone(),
            other => panic!("expected a String, got {other:?}"),
        }
    }

    /// `Vec<(field, value-as-string)>` — `Value` has no `PartialEq`, so struct
    /// identity is compared field by field through its `Debug`/string form.
    fn fields_of(v: &Value) -> Vec<(String, String)> {
        match v {
            Value::Struct { fields, .. } => fields
                .iter()
                .map(|(k, val)| (k.clone(), val.as_string()))
                .collect(),
            other => panic!("expected a Struct, got {other:?}"),
        }
    }

    /// `replace_all` is `replace` — both replace every match, and the two names
    /// must not drift apart.
    #[test]
    fn method_replace_all_is_the_same_arm_as_replace() {
        for (pattern, text, repl, want) in [
            ("[0-9]", "a1b2", "-", "a-b-"),
            ("[0-9a-f]", "az1", "", "z"),
            ("cat|dog", "cat dog cat", "x", "x x x"),
        ] {
            let a = as_string(&call_method(pattern, "replace", vec![s(text), s(repl)]));
            let b = as_string(&call_method(pattern, "replace_all", vec![s(text), s(repl)]));
            assert_eq!(a, b, "replace != replace_all for {pattern:?} on {text:?}");
            assert_eq!(a, want, "replace({pattern:?}, {text:?}, {repl:?})");
        }
    }

    /// `find_all` returns every non-overlapping match as the same
    /// `RegexMatch` struct `find` returns, and an EMPTY slice (not nil) when
    /// nothing matches.
    #[test]
    fn method_find_all_collects_every_match() {
        let all = call_method("[0-9]", "find_all", vec![s("a1b2")]);
        let Value::Array(items) = &all else {
            panic!("find_all must return an Array, got {all:?}")
        };
        assert_eq!(items.len(), 2, "got {all:?}");

        let first = call_method("[0-9]", "find", vec![s("a1b2")]);
        assert_eq!(
            fields_of(&items[0]),
            fields_of(&first),
            "find_all's first element must be exactly find's answer"
        );

        let empty = call_method("[0-9]", "find_all", vec![s("abc")]);
        assert_eq!(
            as_strings(&empty),
            Vec::<Option<String>>::new(),
            "no match => empty slice, not nil"
        );
    }

    /// `captures` returns group 0 (the whole match) plus each group, in order;
    /// nil when the pattern does not match; nil (not `""`) for a group that did
    /// not participate.
    #[test]
    fn method_captures_returns_groups_and_nil_on_no_match() {
        // Leftmost match: `[a-z]` at 'a' has no digits after it, so the match
        // starts at 'b' — "b12", groups "b" / "12".
        let c = call_method("([a-z])([0-9]+)", "captures", vec![s("ab12cd345")]);
        assert_eq!(
            as_strings(&c),
            vec![
                Some("b12".to_string()),
                Some("b".to_string()),
                Some("12".to_string())
            ]
        );

        let missing = call_method("(a)(b)?", "captures", vec![s("a")]);
        assert_eq!(
            as_strings(&missing),
            vec![Some("a".to_string()), Some("a".to_string()), None],
            "a non-participating group is nil, not \"\""
        );

        let none = call_method("[0-9]", "captures", vec![s("abc")]);
        assert!(
            matches!(none, Value::Nil),
            "no match => nil, got {none:?}"
        );
    }

    /// `split` splits at every match and keeps empty pieces — the String
    /// `split` convention, so the two spellings cannot surprise each other.
    #[test]
    fn method_split_splits_at_every_match() {
        assert_eq!(
            as_strings(&call_method("[0-9]", "split", vec![s("a1b2")])),
            vec![
                Some("a".to_string()),
                Some("b".to_string()),
                Some("".to_string())
            ]
        );
        assert_eq!(
            as_strings(&call_method("[0-9]", "split", vec![s("a11b")])),
            vec![
                Some("a".to_string()),
                Some("".to_string()),
                Some("b".to_string())
            ],
            "adjacent matches keep the interior empty piece"
        );
    }

    /// The arms answer only for a `Regex` value: another struct's `split` is
    /// not silently answered by this module (the fall-through that used to turn
    /// `re.split(..)` into "split() requires string args").
    #[test]
    fn method_arms_are_scoped_to_the_regex_struct() {
        let not_a_regex = Value::Struct {
            name: "SomethingElse".to_string(),
            fields: vec![("pattern".to_string(), s("[0-9]"))],
        };
        for method in [
            "is_match",
            "find",
            "find_all",
            "captures",
            "split",
            "replace",
            "replace_all",
        ] {
            assert!(
                dispatch_method(&not_a_regex, method, vec![s("a1")]).is_none(),
                "{method} must not resolve on a non-Regex struct"
            );
        }
    }
}
