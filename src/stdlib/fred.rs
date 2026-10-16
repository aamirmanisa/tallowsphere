//! Standard library: `tallow.fred` — Federal Reserve Economic Data API.
//!
//! Fetches economic indicators from the St. Louis Fed's FRED database:
//! GDP, CPI, unemployment, interest rates, and 800K+ other series.
//!
//! # API
//! - `Fred.series(series_id)` — get series metadata
//! - `Fred.observations(series_id, limit?)` — get observations
//! - `Fred.search(query, limit?)` — search for series
//! - `Fred.category(category_id)` — get series in a category
//!
//! Requires FRED API key (free at https://fred.stlouisfed.org/docs/api/api_key.html).

use super::StdlibResult;
use crate::interp::{type_name, Value};

const FRED_BASE: &str = "https://api.stlouisfed.org/fred";
const USER_AGENT: &str = "Tallow/1.0";

fn fred_get(endpoint: &str, api_key: &str, params: &[(&str, &str)]) -> Result<String, String> {
    let url = format!("{}{}", FRED_BASE, endpoint);
    let mut param_str = format!("?api_key={}&file_type=json", api_key);
    for (k, v) in params {
        param_str.push_str(&format!("&{}={}", k, v));
    }
    let full_url = format!("{}{}", url, param_str);
    let resp = crate::runtime::egress_http::get(&full_url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("FRED request: {e}"))?;
    resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))
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

fn series_info(api_key: &str, series_id: &str) -> StdlibResult {
    let body = fred_get("/series", api_key, &[("series_id", series_id)])?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;
    if let Some(s) = json["seriess"].as_array().and_then(|a| a.first()) {
        return Ok(json_to_value(s));
    }
    Err(format!("Series not found: {series_id}"))
}

fn observations(api_key: &str, series_id: &str, limit: i64) -> StdlibResult {
    let body = fred_get("/series/observations", api_key, &[
        ("series_id", series_id),
        ("limit", &limit.to_string()),
        ("sort_order", "desc"),
    ])?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;
    if let Some(obs) = json["observations"].as_array() {
        let items: Vec<Value> = obs.iter().take(limit as usize).map(|o| {
            Value::Struct {
                name: "Observation".into(),
                fields: vec![
                    ("date".into(), Value::String(o["date"].as_str().unwrap_or("").to_string())),
                    ("value".into(), Value::String(o["value"].as_str().unwrap_or("").to_string())),
                ],
            }
        }).collect();
        return Ok(Value::Array(items));
    }
    Ok(Value::Array(Vec::new()))
}

fn search_series(api_key: &str, query: &str, limit: i64) -> StdlibResult {
    let body = fred_get("/series/search", api_key, &[
        ("search_text", query),
        ("limit", &limit.to_string()),
    ])?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;
    if let Some(results) = json["seriess"].as_array() {
        let items: Vec<Value> = results.iter().map(|s| {
            Value::Struct {
                name: "FREDSeries".into(),
                fields: vec![
                    ("id".into(), Value::String(s["id"].as_str().unwrap_or("").to_string())),
                    ("title".into(), Value::String(s["title"].as_str().unwrap_or("").to_string())),
                    ("frequency".into(), Value::String(s["frequency"].as_str().unwrap_or("").to_string())),
                    ("units".into(), Value::String(s["units"].as_str().unwrap_or("").to_string())),
                ],
            }
        }).collect();
        return Ok(Value::Array(items));
    }
    Ok(Value::Array(Vec::new()))
}

fn category_series(api_key: &str, category_id: &str) -> StdlibResult {
    let body = fred_get("/category/series", api_key, &[("category_id", category_id)])?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;
    Ok(json_to_value(&json))
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "series" => Some(fred_series(args)),
        "observations" => Some(fred_obs(args)),
        "search" => Some(fred_search(args)),
        "category" => Some(fred_category(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "series" | "observations" | "search" | "category")
}

fn fred_series(args: Vec<Value>) -> StdlibResult {
    let key = expect_first_str(&args, "api_key")?;
    let series_id = expect_str_at(&args, 1, "series_id")?;
    series_info(key, series_id)
}

fn fred_obs(args: Vec<Value>) -> StdlibResult {
    let key = expect_first_str(&args, "api_key")?;
    let series_id = expect_str_at(&args, 1, "series_id")?;
    let limit = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i) } else { None }).unwrap_or(100);
    observations(key, series_id, limit as i64)
}

fn fred_search(args: Vec<Value>) -> StdlibResult {
    let key = expect_first_str(&args, "api_key")?;
    let query = expect_str_at(&args, 1, "query")?;
    let limit = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i) } else { None }).unwrap_or(10);
    search_series(key, query, limit as i64)
}

fn fred_category(args: Vec<Value>) -> StdlibResult {
    let key = expect_first_str(&args, "api_key")?;
    let cat_id = expect_str_at(&args, 1, "category_id")?;
    category_series(key, cat_id)
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}

fn expect_str_at<'a>(args: &'a [Value], idx: usize, name: &str) -> Result<&'a String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}