//! `tallow phone` CLI subcommand — argument parsing + dispatch for the phone
//! OSINT stack (crate::stdlib::osint / crate::stdlib::phone_osint).
//!
//! ============================================================================
//! INTEGRATION POINT (what you must wire in so this module compiles + runs):
//! ============================================================================
//! This file is self-contained and only needs to be *declared*, it does NOT
//! patch any existing file. Two edits are required outside this crate:
//!
//!   1. src/cli/mod.rs  — add `pub mod phone_cmd;` alongside `pub mod daemon;`.
//!   2. src/main.rs      — add a variant to the subcommand enum + a call site.
//!      Concretely (near the existing `Compile` / `Run` / `Schedule` variants
//!      that `fn main()` matches on around line 1992):
//!
//!        // enum variant, e.g. after `Schedule`:
//!        Phone {
//!            #[clap(subcommand)]
//!            command: PhoneArgs,   // or glue the raw Vec<String> below
//!        },
//!
//!        // match arm in the dispatch (return the Result<(),String>):
//!        Sub::Phone { command } => {
//!            // `matches` is the clap v2/v4 `ArgMatches`; grab the trailing "phone"
//!            // args via values_of/indices, or simply pass the Vec<String> of
//!            // everything AFTER the literal `phone` token that your parser
//!            // already split off. Concretely:
//!            let args: Vec<String> = /* tokens after "phone" */;
//!            cli::phone_cmd::run_phone_cmd(&args)?;
//!            Ok(())
//!        }
//!
//! Alternately, if main.rs uses a hand-rolled parser rather than clap, the
//! only requirement is to call `crate::cli::phone_cmd::run_phone_cmd(&args)`
//! where `args` are the tokens following the `phone` keyword (e.g. for
//! `tallow phone lookup 5128501815`, args == ["lookup", "5128501815"]).
//! The first token may also be `phone` itself — run_phone_cmd skips it safely.
//! ============================================================================
//!
//! No other file is modified. Uses the public dispatch entry point
//! `crate::stdlib::osint::dispatch` (`pub fn dispatch(&str, Vec<Value>) ->
//! Option<StdlibResult>`), with `Value` from `crate::interp` and
//! `StdlibResult = Result<Value, String>` from `crate::stdlib`.

use crate::interp::Value;
use crate::stdlib::osint;

/// Grammar implemented by run_phone_cmd:
///
///   tallow phone <SUBCOMMAND> [PHONE] [--evidence <json>] [--signal <json>]
///                          [--before <json>] [--after <json>] [--ties <json>]
///
/// SUBCOMMAND ∈ {lookup, reputation, resolve_owner, linkage, mitigation,
///               lrn_carrier, cnam_name, to_stix, diff}
///
/// * lookup / mitigation / lrn_carrier / cnam_name / to_stix take a PHONE number.
/// * resolve_owner takes `--evidence <json>` (array of owner-evidence maps).
/// * reputation     takes `--signal   <json>` (signal map).
/// * linkage        takes `--ties     <json>` (array of confirmed-tie maps).
/// * diff           takes `--before <json>` and `--after <json>` (two maps).
pub fn run_phone_cmd(args: &[String]) -> Result<(), String> {
    // Allow the caller to pass tokens that include the literal `phone` keyword,
    // or just the tokens after it. Either way we are robust.
    let mut tokens: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if tokens.first().map(|s| *s) == Some("phone") {
        tokens.remove(0);
    }

    let sub = tokens
        .first()
        .ok_or_else(|| {
            "usage: tallow phone <lookup|reputation|resolve_owner|linkage|mitigation|lrn_carrier|cnam_name|to_stix|diff> [PHONE] [--evidence <json>] [--signal <json>] [--before <json>] [--after <json>] [--ties <json>]".to_string()
        })?;

    // --- parse flags (Option<Value>) ---------------------------------------
    let mut number: Option<String> = None;
    let mut evidence: Option<Value> = None; // array of maps (resolve_owner)
    let mut signal: Option<Value> = None; // map (reputation)
    let mut before: Option<Value> = None; // map (diff)
    let mut after: Option<Value> = None; // map (diff)
    let mut ties: Option<Value> = None; // array of maps (linkage)

    let mut i = 1usize;
    while i < tokens.len() {
        match tokens[i] {
            "--evidence" => {
                evidence = Some(parse_json_flag(&tokens, &mut i, "--evidence")?);
            }
            "--signal" => {
                signal = Some(parse_json_flag(&tokens, &mut i, "--signal")?);
            }
            "--before" => {
                before = Some(parse_json_flag(&tokens, &mut i, "--before")?);
            }
            "--after" => {
                after = Some(parse_json_flag(&tokens, &mut i, "--after")?);
            }
            "--ties" => {
                ties = Some(parse_json_flag(&tokens, &mut i, "--ties")?);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            t if t.starts_with("--") => {
                return Err(format!("unknown flag `{t}`;\nusage: tallow phone <SUBCOMMAND> [PHONE] [--evidence <json>] [--signal <json>] [--before <json>] [--after <json>] [--ties <json>]"));
            }
            t if number.is_none() => {
                // First bare token (other than the subcommand) is the PHONE.
                number = Some(t.to_string());
                i += 1;
                continue;
            }
            other => return Err(format!("unexpected token `{other}`")),
        }
        i += 1;
    }

    // --- pick a dispatch key and assemble args ------------------------------
    let (function, mut args): (&str, Vec<Value>) = match *sub {
        "lookup" => ("PhoneNumber.lookup", vec![require_number(number, "lookup")?]),
        "resolve_owner" => {
            let ev = evidence
                .ok_or_else(|| "resolve_owner requires `--evidence <json>` (array of owner-evidence maps)".to_string())?;
            if !matches!(ev, Value::Array(_)) {
                return Err("resolve_owner: `--evidence` must be a JSON array of map objects".to_string());
            }
            ("PhoneNumber.resolve_owner", vec![ev])
        }
        "reputation" => {
            let sig = signal
                .ok_or_else(|| "reputation requires `--signal <json>` (signal map)".to_string())?;
            if !matches!(sig, Value::Map(_)) {
                return Err("reputation: `--signal` must be a JSON object".to_string());
            }
            ("PhoneNumber.reputation", vec![sig])
        }
        "linkage" => {
            let ties_val = ties
                .ok_or_else(|| "linkage requires `--ties <json>` (array of tie maps)".to_string())?;
            if !matches!(ties_val, Value::Array(_)) {
                return Err("linkage: `--ties` must be a JSON array of map objects".to_string());
            }
            ("PhoneNumber.linkage", vec![ties_val])
        }
        "diff" => {
            let b = before
                .ok_or_else(|| "diff requires `--before <json>` (map of field->value)".to_string())?;
            let a = after
                .ok_or_else(|| "diff requires `--after <json>` (map of field->value)".to_string())?;
            if !matches!(b, Value::Map(_)) || !matches!(a, Value::Map(_)) {
                return Err("diff: `--before` and `--after` must be JSON objects".to_string());
            }
            ("PhoneNumber.diff", vec![b, a])
        }
        "mitigation" => ("PhoneNumber.mitigation", vec![require_number(number, "mitigation")?]),
        "lrn_carrier" => ("PhoneNumber.lrn_carrier", vec![require_number(number, "lrn_carrier")?]),
        "cnam_name" => ("PhoneNumber.cnam_name", vec![require_number(number, "cnam_name")?]),
        "to_stix" => ("PhoneNumber.to_stix", vec![require_number(number, "to_stix")?]),
        other => {
            return Err(format!(
                "unknown subcommand `{other}`;\nusage: tallow phone <lookup|reputation|resolve_owner|linkage|mitigation|lrn_carrier|cnam_name|to_stix|diff> [PHONE] [--evidence <json>] [--signal <json>] [--before <json>] [--after <json>] [--ties <json>]"
            ))
        }
    };

    // --- dispatch -----------------------------------------------------------
    let result = osint::dispatch(function, args)
        .ok_or_else(|| format!("tallow phone: dispatch returned None for {function}"))?;

    match result {
        Ok(value) => {
            // to_stix returns a pre-serialized JSON string — print it raw.
            if let Value::String(s) = &value {
                println!("{s}");
            } else {
                println!("{}", pretty_json(&value, 0));
            }
            Ok(())
        }
        Err(msg) => Err(format!("{function}: {msg}")),
    }
}

/// Capture the value token following a `--flag` and parse it as a JSON value.
fn parse_json_flag<'a>(
    tokens: &'a [&str],
    idx: &mut usize,
    flag: &str,
) -> Result<Value, String> {
    let raw = tokens
        .get(*idx + 1)
        .ok_or_else(|| format!("{flag} requires a JSON argument"))?;
    *idx += 1;
    json_string_to_value(raw).map_err(|e| format!("{flag}: {e}"))
}

/// Require a phone number string for the number-driven subcommands.
fn require_number(number: Option<String>, sub: &str) -> Result<Value, String> {
    number
        .map(Value::String)
        .ok_or_else(|| format!("{sub} requires a PHONE number argument"))
}

/// Parse a JSON string into an interpreter `Value`. Preserves string keys in
/// maps as `Value::String`, integers as `Value::Int`, floats as `Value::Float`.
fn json_string_to_value(input: &str) -> Result<Value, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(serde_json_to_interp(&parsed))
}

fn serde_json_to_interp(v: &serde_json::Value) -> Value {
    use serde_json::Value as S;
    match v {
        S::Null => Value::Nil,
        S::Bool(b) => Value::Bool(*b),
        S::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(u) = n.as_u64() {
                Value::Int(u as i128)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        S::String(s) => Value::String(s.clone()),
        S::Array(arr) => Value::Array(arr.iter().map(serde_json_to_interp).collect()),
        S::Object(map) => {
            let fields: Vec<(Value, Value)> = map
                .iter()
                .map(|(k, val)| (Value::String(k.clone()), serde_json_to_interp(val)))
                .collect();
            Value::Map(fields)
        }
    }
}

/// Render an interpreter `Value` as readable, indented JSON for the terminal.
/// Serializes the JSON-ish variants (Struct/Map/Array/Enum/Ok/Err/scalars)
/// that the phone OSINT result values use; opaque handle variants fall back to
/// a quoted type name.
fn pretty_json(v: &Value, depth: usize) -> String {
    let indent = "  ".repeat(depth);
    let child = "  ".repeat(depth + 1);
    match v {
        Value::Nil => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(n) => format!("{n}"),
        Value::String(s) => json_quote(s),
        Value::Array(items) => {
            if items.is_empty() {
                return "[]".to_string();
            }
            let inner: Vec<String> = items
                .iter()
                .map(|it| format!("{child}{}", pretty_json(it, depth + 1)))
                .collect();
            format!("[\n{}\n{}]", inner.join(",\n"), indent)
        }
        Value::Map(pairs) => {
            if pairs.is_empty() {
                return "{}".to_string();
            }
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, val)| {
                    format!("{child}{}: {}", pretty_json(k, depth + 1), pretty_json(val, depth + 1))
                })
                .collect();
            format!("{{\n{}\n{}}}", inner.join(",\n"), indent)
        }
        Value::Struct { fields, .. } => {
            if fields.is_empty() {
                return "{}".to_string();
            }
            let inner: Vec<String> = fields
                .iter()
                .map(|(k, val)| format!("{child}{}: {}", json_quote(k), pretty_json(val, depth + 1)))
                .collect();
            format!("{{\n{}\n{}}}", inner.join(",\n"), indent)
        }
        Value::Enum { variant, fields, .. } => {
            if fields.is_empty() {
                return json_quote(variant);
            }
            let inner: Vec<String> = fields
                .iter()
                .map(|(k, val)| format!("{child}{}: {}", json_quote(k), pretty_json(val, depth + 1)))
                .collect();
            format!("{{\n{}\n{}}}", inner.join(",\n"), indent)
        }
        Value::Ok(inner) => format!("{{\n{child}\"Ok\": {}\n{indent}}}", pretty_json(inner, depth + 1)),
        Value::Err(inner) => format!("{{\n{child}\"Err\": {}\n{indent}}}", pretty_json(inner, depth + 1)),
        Value::Private(inner) => pretty_json(inner, depth),
        Value::Secret(_) => "\"[SECRET]\"".to_string(),
        Value::Boxed(inner) => pretty_json(inner, depth),
        other => json_quote(&format!("<handle:{}>", variant_label(other))),
    }
}

fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn variant_label(v: &Value) -> &'static str {
    match v {
        Value::Range { .. } => "Range",
        Value::Function { .. } => "Function",
        Value::Bytes(_) => "Bytes",
        Value::Provenance(..) => "Provenance",
        Value::Channel(_) => "Channel",
        Value::DbConnection(_) => "DbConnection",
        Value::Consent { .. } => "Consent",
        Value::Erasable { .. } => "Erasable",
        Value::KeyPair { .. } => "KeyPair",
        Value::BrowserObject(..) => "BrowserObject",
        Value::Brain(_) => "Brain",
        Value::Break => "Break",
        Value::Continue => "Continue",
        _ => "Value",
    }
}

fn print_help() {
    println!(
        "{}",
        r#"tallow phone — phone OSINT subcommands

USAGE:
    tallow phone <SUBCOMMAND> [PHONE] [FLAGS]

SUBCOMMANDS:
    lookup         Resolve a NANP number's as-allocated carrier + line type
    resolve_owner  Attribute an owner from evidence (`--evidence <json>`, array of maps)
    reputation     Compute spam reputation (`--signal <json>`, signal map)
    linkage        Build a multi-hop linkage subgraph (`--ties <json>`, array of maps)
    mitigation     Resolve number + FCC Robocall Mitigation DB cert
    lrn_carrier    Tier-C current-carrier / ported LRN dip (authorized only)
    cnam_name      Tier-D displayed caller-id name dip (authorized only)
    to_stix        Emit a STIX 2.1 bundle for the number (printed as JSON)
    diff           Compare two number states (`--before <json>` / `--after <json>`)

FLAGS:
    --evidence <json>   owner-evidence array (resolve_owner)
    --signal <json>     signal map (reputation)
    --before <json>     before-state map (diff)
    --after <json>      after-state map (diff)
    --ties <json>       confirmed-tie array (linkage)
    --help, -h          show this help

EXAMPLES:
    tallow phone lookup 5128501815
    tallow phone mitigation 5128501815
    tallow phone to_stix 5128501815
    tallow phone reputation --signal '{"reports":42,"category":"robocall","source_bits":3}'
    tallow phone diff --before '{"carrier":"ATT"}' --after '{"carrier":"VERIZON"}'
    tallow phone linkage --ties '[{"from":"5128501815","to":"nobody@example.com","relation":"shared"}]'
    tallow phone resolve_owner --evidence '[{"name":"Jane Doe","source":"public-records","source_class":"verified"}]'"#
    );
}
