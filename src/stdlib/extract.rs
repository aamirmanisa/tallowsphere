//! Standard library: `tallow.extract` — structured data extraction from pages.
//!
//! Extracts structured data from HTML/text using regex patterns, CSS selectors
//! (via scraper), and common data schemas (products, articles, profiles, serp).
//!
//! # API
//! - `Extract.schema(html, schema_name)` — extract using predefined schema
//! - `Extract.pattern(html, pattern)` — extract using custom regex pattern
//! - `Extract.jsonld(html)` — extract JSON-LD structured data
//! - `Extract.all(html)` — extract all known schemas at once

use super::StdlibResult;
use crate::interp::{type_name, Value};

use regex::Regex;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

#[derive(Debug, Clone)]
struct ExtractionField {
    name: String,
    pattern: String,        // regex pattern
    attribute: String,      // "text" | "href" | "src" | "content"
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // schema fields kept for future pattern-matching API
struct ExtractionSchema {
    name: String,
    selector: String,       // CSS selector for container
    fields: Vec<ExtractionField>,
}

fn schemas() -> Vec<ExtractionSchema> {
    vec![
        // Product schema
        ExtractionSchema {
            name: "product".into(),
            selector: "".into(),
            fields: vec![
                ExtractionField { name: "title".into(), pattern: r#"<h[1-3][^>]*>(.*?)</h[1-3]>"#.into(), attribute: "text".into() },
                ExtractionField { name: "price".into(), pattern: r#"[\$£€]\s*([0-9,]+\.[0-9]{2})"#.into(), attribute: "text".into() },
                ExtractionField { name: "description".into(), pattern: r#"<p[^>]*>(.*?)</p>"#.into(), attribute: "text".into() },
                ExtractionField { name: "image".into(), pattern: r#"<img[^>]*src="([^"]*)"[^>]*>"#.into(), attribute: "src".into() },
                ExtractionField { name: "sku".into(), pattern: r#"(?:sku|product.?id|item.?number)[\s:]*(?i)([A-Z0-9-]{4,})"#.into(), attribute: "text".into() },
            ],
        },
        // Article schema
        ExtractionSchema {
            name: "article".into(),
            selector: "".into(),
            fields: vec![
                ExtractionField { name: "title".into(), pattern: r#"<h[1-2][^>]*>(.*?)</h[1-2]>"#.into(), attribute: "text".into() },
                ExtractionField { name: "author".into(), pattern: r#"by\s+([A-Z][a-z]+ [A-Z][a-z]+)"#.into(), attribute: "text".into() },
                ExtractionField { name: "date".into(), pattern: r#"(\d{4}-\d{2}-\d{2}|\d{1,2}\s+\w+\s+\d{4})"#.into(), attribute: "text".into() },
                ExtractionField { name: "body".into(), pattern: r#"<article[^>]*>(.*?)</article>"#.into(), attribute: "text".into() },
                ExtractionField { name: "image".into(), pattern: r#"<img[^>]*src="([^"]*)"[^>]*>"#.into(), attribute: "src".into() },
            ],
        },
        // Profile/person schema
        ExtractionSchema {
            name: "profile".into(),
            selector: "".into(),
            fields: vec![
                ExtractionField { name: "name".into(), pattern: r#"<h[1-3][^>]*>(.*?)</h[1-3]>"#.into(), attribute: "text".into() },
                ExtractionField { name: "email".into(), pattern: r#"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"#.into(), attribute: "text".into() },
                ExtractionField { name: "phone".into(), pattern: r#"(\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})"#.into(), attribute: "text".into() },
                ExtractionField { name: "location".into(), pattern: r#"([A-Z][a-z]+,\s*[A-Z]{2})"#.into(), attribute: "text".into() },
                ExtractionField { name: "url".into(), pattern: r#"href="(https?://[^"]*)"#.into(), attribute: "href".into() },
            ],
        },
        // SERP/listing schema
        ExtractionSchema {
            name: "serp".into(),
            selector: "".into(),
            fields: vec![
                ExtractionField { name: "title".into(), pattern: r#"<h3[^>]*><a[^>]*>(.*?)</a></h3>"#.into(), attribute: "text".into() },
                ExtractionField { name: "url".into(), pattern: r#"<h3[^>]*><a[^>]*href="([^"]*)"[^>]*>"#.into(), attribute: "href".into() },
                ExtractionField { name: "snippet".into(), pattern: r#"<div[^>]*class="[^"]*snippet[^"]*"[^>]*>(.*?)</div>"#.into(), attribute: "text".into() },
                ExtractionField { name: "date".into(), pattern: r#"(\d{1,2}\s+\w+\s+\d{4})"#.into(), attribute: "text".into() },
            ],
        },
        // Job listing schema
        ExtractionSchema {
            name: "job".into(),
            selector: "".into(),
            fields: vec![
                ExtractionField { name: "title".into(), pattern: r#"<h[1-3][^>]*>(.*?)</h[1-3]>"#.into(), attribute: "text".into() },
                ExtractionField { name: "company".into(), pattern: r#"(?:company|employer|organization)[\s:]*(?i)([A-Z][A-Za-z &.,()-]{2,50})"#.into(), attribute: "text".into() },
                ExtractionField { name: "location".into(), pattern: r#"([A-Z][a-z]+,\s*[A-Z]{2})"#.into(), attribute: "text".into() },
                ExtractionField { name: "salary".into(), pattern: r#"\$([0-9,]+\s*-\s*[0-9,]+\s*(?:k|K)?)"#.into(), attribute: "text".into() },
            ],
        },
    ]
}

/// A schema field whose regex is compiled once per process.
struct CompiledField {
    name: String,
    attribute: String,
    re: Regex,
}

/// A schema whose field regexes are compiled once per process.
struct CompiledSchema {
    name: String,
    fields: Vec<CompiledField>,
}

/// Schema field regexes, compiled **once per process** instead of on every
/// `Extract.schema` / `Extract.all` call. Previously `Regex::new` ran per field
/// per call (22 compilations per `Extract.all`), and the tag-strip regex was
/// recompiled per match. The `(?s)` prefix lets `.*?` spans cross newlines,
/// which the raw patterns missed on multi-line headings/bodies.
static COMPILED_SCHEMAS: LazyLock<Vec<CompiledSchema>> = LazyLock::new(|| {
    schemas()
        .into_iter()
        .map(|s| CompiledSchema {
            name: s.name,
            fields: s
                .fields
                .into_iter()
                .filter_map(|f| {
                    Regex::new(&format!("(?s){}", f.pattern))
                        .ok()
                        .map(|re| CompiledField {
                            name: f.name,
                            attribute: f.attribute,
                            re,
                        })
                })
                .collect(),
        })
        .collect()
});

/// Matches any HTML tag; used to strip markup from `text` attributes.
static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());

/// Bounded cache of caller-supplied pattern regexes (`Extract.pattern`).
static PATTERN_CACHE: LazyLock<Mutex<HashMap<String, Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Cap on the pattern cache; exceeding it clears rather than growing unbounded
/// (a pipeline typically uses a small fixed set of patterns).
const PATTERN_CACHE_MAX: usize = 256;

fn compiled_pattern(pattern: &str) -> Option<Regex> {
    if let Ok(c) = PATTERN_CACHE.lock() {
        if let Some(re) = c.get(pattern) {
            return Some(re.clone());
        }
    }
    let re = Regex::new(pattern).ok()?;
    if let Ok(mut c) = PATTERN_CACHE.lock() {
        if c.len() >= PATTERN_CACHE_MAX {
            c.clear();
        }
        c.insert(pattern.to_string(), re.clone());
    }
    Some(re)
}

fn extract_schema(html: &str, schema_name: &str) -> Value {
    let schema = COMPILED_SCHEMAS.iter().find(|s| s.name == schema_name);

    match schema {
        Some(s) => {
            let mut results = Vec::new();
            for field in &s.fields {
                let values: Vec<String> = field.re.captures_iter(html)
                    .filter_map(|caps| caps.get(1))
                    .map(|m| {
                        let mut val = m.as_str().to_string();
                        // Strip HTML tags from text attributes
                        if field.attribute == "text" {
                            val = TAG_RE.replace_all(&val, "").to_string();
                        }
                        val.trim().to_string()
                    })
                    .filter(|v| !v.is_empty())
                    .take(10)
                    .collect();
                if values.len() == 1 {
                    results.push((field.name.clone(), Value::String(values[0].clone())));
                } else if values.len() > 1 {
                    let arr: Vec<Value> = values.into_iter()
                        .map(Value::String)
                        .collect();
                    results.push((field.name.clone(), Value::Array(arr)));
                }
            }
            Value::Struct {
                name: "Extraction".into(),
                fields: results,
            }
        }
        None => Value::Struct {
            name: "Extraction".into(),
            fields: vec![("error".into(), Value::String(format!("Unknown schema: {schema_name}. Available: product, article, profile, serp, job")))],
        },
    }
}

/// Raw capture-group matches for a regex `pattern` over `html`, with inner tags
/// stripped and the result trimmed. Shared with the native runtime FFI
/// (`src/runtime/html_ffi.rs::tallow_extract_pattern`) so the compiled path and
/// the interpreter cannot drift apart.
pub fn pattern_matches(html: &str, pattern: &str) -> Vec<String> {
    let mut results = Vec::new();
    if let Some(re) = compiled_pattern(pattern) {
        for caps in re.captures_iter(html) {
            if let Some(m) = caps.get(1) {
                results.push(TAG_RE.replace_all(m.as_str(), "").trim().to_string());
            }
        }
    }
    results
}

fn extract_pattern(html: &str, pattern: &str) -> Value {
    Value::Array(pattern_matches(html, pattern).into_iter().map(Value::String).collect())
}

pub(crate) fn extract_jsonld(html: &str) -> Value {
    let re = Regex::new(r#"(?s)<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>"#).unwrap();
    let mut items = Vec::new();
    for caps in re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            let json_str = m.as_str().trim().to_string();
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(val) => items.push(json_to_value(&val)),
                // Char-boundary-safe preview: byte slicing (`&s[..n]`) panics
                // when `n` lands inside a multi-byte UTF-8 char.
                Err(_) => {
                    let preview: String = json_str.chars().take(80).collect();
                    items.push(Value::String(format!(
                        "(invalid JSON: first 80 chars) {preview}"
                    )));
                }
            }
        }
    }
    Value::Array(items)
}

/// Raw JSON-LD script text, one entry per `application/ld+json` block, trimmed.
///
/// This is the **text** form, and it is what the declared `StructuredData.json_ld`
/// holds (`[]String`, `stdlib/browser.tl:435`). `extract_jsonld` above returns
/// *parsed* values (`Value::Map` per JSON object) and is right for the `Extract.all`
/// map surface, but it cannot satisfy a `[]String` field: the array came back
/// heterogeneous — `Value::String` for malformed blocks, `Value::Map` for valid
/// ones — so a caller doing string work on `sd.json_ld[0]` got a map. Both engines
/// read this one function, so they cannot disagree.
pub(crate) fn jsonld_raw_text(html: &str) -> Vec<String> {
    // Both quote styles: HTML allows `type='application/ld+json'` and
    // `type="application/ld+json"`, and real pages use either. The earlier
    // double-quote-only pattern silently reported `has_json_ld = false` for the
    // single-quoted form — caught by
    // `interp::tests::test_structured_data_extract_json_ld`.
    let re = Regex::new(
        r#"(?s)<script[^>]*type\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>"#,
    )
    .expect("json-ld script regex is a literal");
    re.captures_iter(html)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .collect()
}

fn extract_all(html: &str) -> Value {
    let mut result = Vec::new();
    for schema in schemas() {
        let extraction = extract_schema(html, &schema.name);
        result.push((Value::String(schema.name.clone()), extraction));
    }

    // Also add JSON-LD
    let jsonld = extract_jsonld(html);
    result.push((Value::String("jsonld".into()), jsonld));

    Value::Map(result)
}

fn json_to_value(val: &serde_json::Value) -> Value {
    match val {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() { Value::Int(i as i128) }
            else if let Some(f) = n.as_f64() { Value::Float(f) }
            else { Value::String(n.to_string()) }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(o) => {
            let entries: Vec<(Value, Value)> = o.iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_value(v)))
                .collect();
            Value::Map(entries)
        }
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "schema" => Some(ext_schema(args)),
        "pattern" => Some(ext_pattern(args)),
        "jsonld" => Some(ext_jsonld(args)),
        "all" => Some(ext_all(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "schema" | "pattern" | "jsonld" | "all")
}

fn ext_schema(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Extract.schema: requires (html, schema_name)".into());
    }
    let html = expect_first_str(&args, "html")?;
    let schema = expect_string(&args[1], "schema_name")?;
    Ok(extract_schema(html, schema))
}

fn ext_pattern(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Extract.pattern: requires (html, pattern)".into());
    }
    let html = expect_first_str(&args, "html")?;
    let pattern = expect_string(&args[1], "pattern")?;
    Ok(extract_pattern(html, pattern))
}

fn ext_jsonld(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    Ok(extract_jsonld(html))
}

fn ext_all(args: Vec<Value>) -> StdlibResult {
    let html = expect_first_str(&args, "html")?;
    Ok(extract_all(html))
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

fn expect_string<'a>(val: &'a Value, name: &str) -> Result<&'a String, String> {
    match val {
        Value::String(s) => Ok(s),
        _ => Err(format!("Expected String for {name}, got {}", type_name(val))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extraction_field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
        match v {
            Value::Struct { fields, .. } => fields
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, val)| val),
            _ => None,
        }
    }

    #[test]
    fn schema_extracts_multiline_title() {
        // `(?s)` lets `.*?` cross the newline; without it the title was missed.
        let v = extract_schema("<h1>\n  Widget Pro\n</h1>", "product");
        match extraction_field(&v, "title") {
            Some(Value::String(s)) => assert!(s.contains("Widget Pro"), "got {s:?}"),
            other => panic!("expected title, got {other:?}"),
        }
    }

    #[test]
    fn unknown_schema_reports_error() {
        let v = extract_schema("<h1>x</h1>", "no_such_schema");
        match extraction_field(&v, "error") {
            Some(Value::String(s)) => assert!(s.contains("Unknown schema")),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn jsonld_parses_valid_payload() {
        let html =
            r#"<script type="application/ld+json">{"@type":"Product","name":"Widget"}</script>"#;
        match extract_jsonld(html) {
            Value::Array(items) => assert_eq!(items.len(), 1),
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn jsonld_invalid_multibyte_does_not_panic() {
        // 120 three-byte chars: byte index 80 lands mid-char, so the old
        // `&json_str[..80]` byte slice panicked instead of returning a preview.
        let body = "€".repeat(120);
        let html = format!("<script type=\"application/ld+json\">{{not json {body}}}</script>");
        match extract_jsonld(&html) {
            Value::Array(items) => assert_eq!(items.len(), 1),
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn pattern_cache_reuses_and_matches() {
        let a = pattern_matches("<title>Alpha</title>", r"<title>(.*?)</title>");
        let b = pattern_matches("<title>Beta</title>", r"<title>(.*?)</title>");
        assert_eq!(a, vec!["Alpha".to_string()]);
        assert_eq!(b, vec!["Beta".to_string()]);
    }
}
