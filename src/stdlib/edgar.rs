//! Standard library: `tallow.edgar` — SEC EDGAR API client.
//!
//! Fetches and parses SEC filings: company facts (XBRL-as-JSON),
//! submissions history, and filing documents.
//!
//! # API
//! - `EDGAR.company_facts(cik)` — all XBRL facts for a company
//! - `EDGAR.submissions(cik)` — filing history
//! - `EDGAR.company_concept(cik, taxonomy, concept)` — specific concept data
//! - `EDGAR.search(company_name)` — search by company name
//! - `EDGAR.cik_lookup(ticker)` — CIK lookup by ticker
//!
//! Rate limit: 10 requests/second (SEC requirement). No API key needed.

use super::StdlibResult;
use crate::interp::{type_name, Value};

const EDGAR_BASE: &str = "https://data.sec.gov";
const USER_AGENT: &str = "Tallow/1.0 (operator@example.com)";

fn edgar_get(path: &str) -> Result<String, String> {
    let url = format!("{}{}", EDGAR_BASE, path);
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json")
        .call()
        .map_err(|e| format!("EDGAR request: {e}"))?;
    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("read: {e}"))
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

fn parse_json(body: &str) -> StdlibResult {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("JSON parse: {e}"))?;
    Ok(json_to_value(&json))
}

fn format_cik(cik: &str) -> String {
    format!("{:0>10}", cik.trim())
}

// ── EDGAR.company_facts(cik) ──
fn company_facts(cik: &str) -> StdlibResult {
    let cik_fmt = format_cik(cik);
    let path = format!("/api/xbrl/companyfacts/CIK{}.json", cik_fmt);
    let body = edgar_get(&path)?;
    parse_json(&body)
}

// ── EDGAR.submissions(cik) ──
fn submissions(cik: &str) -> StdlibResult {
    let cik_fmt = format_cik(cik);
    let path = format!("/submissions/CIK{}.json", cik_fmt);
    let body = edgar_get(&path)?;
    parse_json(&body)
}

// ── EDGAR.company_concept(cik, taxonomy, concept) ──
fn company_concept(cik: &str, taxonomy: &str, concept: &str) -> StdlibResult {
    let cik_fmt = format_cik(cik);
    let path = format!("/api/xbrl/companyconcept/CIK{}/{}/{}.json", cik_fmt, taxonomy, concept);
    let body = edgar_get(&path)?;
    parse_json(&body)
}

// ── EDGAR.cik_lookup(ticker) ──
fn cik_lookup(ticker: &str) -> StdlibResult {
    // Send request headers that SEC API expects
    let url = "https://www.sec.gov/files/company_tickers.json";
    let resp = crate::runtime::egress_http::get(url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json")
        .call()
        .map_err(|e| format!("CIK lookup: {e}"))?;
    let body = resp.into_body()
        .read_to_string()
        .map_err(|e| format!("read: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("JSON parse: {e}"))?;

    let ticker_upper = ticker.to_uppercase();
    if let Some(obj) = json.as_object() {
        for (_, val) in obj {
            if val["ticker"].as_str().map(|s| s.to_uppercase()) == Some(ticker_upper.clone()) {
                return Ok(Value::Struct {
                    name: "CIKResult".into(),
                    fields: vec![
                        ("cik".into(), Value::String(format!("{:0>10}", val["cik_str"].as_str().unwrap_or("")))),
                        ("ticker".into(), Value::String(val["ticker"].as_str().unwrap_or("").to_string())),
                        ("title".into(), Value::String(val["title"].as_str().unwrap_or("").to_string())),
                    ],
                });
            }
        }
    }
    Err(format!("Ticker not found: {ticker}"))
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "company_facts" => Some(edgar_facts(args)),
        "submissions" => Some(edgar_subs(args)),
        "company_concept" => Some(edgar_concept(args)),
        "cik_lookup" => Some(edgar_cik(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "company_facts" | "submissions" | "company_concept" | "cik_lookup")
}

fn edgar_facts(args: Vec<Value>) -> StdlibResult {
    let cik = expect_first_str(&args, "cik")?;
    company_facts(cik)
}

fn edgar_subs(args: Vec<Value>) -> StdlibResult {
    let cik = expect_first_str(&args, "cik")?;
    submissions(cik)
}

fn edgar_concept(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("EDGAR.company_concept: requires (cik, taxonomy, concept)".into());
    }
    let cik = expect_first_str(&args, "cik")?;
    let taxonomy = expect_string(&args[1], "taxonomy")?;
    let concept = expect_string(&args[2], "concept")?;
    company_concept(cik, taxonomy, concept)
}

fn edgar_cik(args: Vec<Value>) -> StdlibResult {
    let ticker = expect_first_str(&args, "ticker")?;
    cik_lookup(ticker)
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
