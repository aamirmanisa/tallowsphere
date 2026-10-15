//! Standard library: `tallow.yahoo` — Yahoo Finance market data.
//!
//! Fetches real-time quotes, historical OHLCV, financial statements,
//! and options chains from Yahoo Finance (via yfinance-compatible endpoints).
//!
//! # API
//! - `Yahoo.quote(ticker)` — real-time quote (price, change, volume, etc.)
//! - `Yahoo.history(ticker, period?, interval?)` — historical OHLCV data
//! - `Yahoo.financials(ticker)` — income statement, balance sheet, cash flow
//! - `Yahoo.options_chain(ticker, expiration?)` — options chain with Greeks
//! - `Yahoo.search(query)` — search for tickers by name

use super::StdlibResult;
use crate::interp::{type_name, Value};

#[allow(dead_code)] // kept for future direct API use
const YAHOO_BASE: &str = "https://query1.finance.yahoo.com/v8/finance";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";


#[allow(dead_code)] // kept for future direct API use
fn yahoo_get(path: &str, _params: &[(&str, &str)]) -> Result<String, String> {
    let url = format!("{}{}", YAHOO_BASE, path);
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json")
        .call()
        .map_err(|e| format!("Yahoo request: {e}"))?;
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

fn parse_json(body: &str) -> StdlibResult {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("JSON parse: {e}"))?;
    Ok(json_to_value(&json))
}

// ── Yahoo.quote(ticker) ──
fn fetch_quote(ticker: &str) -> StdlibResult {
    let url = format!("https://query2.finance.yahoo.com/v7/finance/quote?symbols={}", ticker);
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("Quote request: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;

    if let Some(result) = json["quoteResponse"]["result"].as_array().and_then(|a| a.first()) {
        return Ok(Value::Struct {
            name: "Quote".into(),
            fields: vec![
                ("symbol".into(), Value::String(result["symbol"].as_str().unwrap_or("").to_string())),
                ("name".into(), Value::String(result["shortName"].as_str().unwrap_or("").to_string())),
                ("price".into(), Value::Float(result["regularMarketPrice"].as_f64().unwrap_or(0.0))),
                ("change".into(), Value::Float(result["regularMarketChange"].as_f64().unwrap_or(0.0))),
                ("change_pct".into(), Value::Float(result["regularMarketChangePercent"].as_f64().unwrap_or(0.0))),
                ("volume".into(), Value::Int(result["regularMarketVolume"].as_i64().unwrap_or(0) as i128)),
                ("high".into(), Value::Float(result["regularMarketDayHigh"].as_f64().unwrap_or(0.0))),
                ("low".into(), Value::Float(result["regularMarketDayLow"].as_f64().unwrap_or(0.0))),
                ("open".into(), Value::Float(result["regularMarketOpen"].as_f64().unwrap_or(0.0))),
                ("prev_close".into(), Value::Float(result["regularMarketPreviousClose"].as_f64().unwrap_or(0.0))),
                ("market_cap".into(), Value::Float(result["marketCap"].as_f64().unwrap_or(0.0))),
                ("pe_ratio".into(), Value::Float(result["trailingPE"].as_f64().unwrap_or(0.0))),
                ("currency".into(), Value::String(result["currency"].as_str().unwrap_or("USD").to_string())),
            ],
        });
    }
    Err(format!("Ticker not found: {ticker}"))
}

// ── Yahoo.history(ticker, period, interval) ──
fn fetch_history(ticker: &str, period: &str, interval: &str) -> StdlibResult {
    let url = format!("{}/{ticker}?period1=0&period2=9999999999&interval={interval}&range={period}&events=div%7Csplit",
        "https://query1.finance.yahoo.com/v8/finance/chart");
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("History: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;

    if let Some(timestamps) = json["chart"]["result"][0]["timestamp"].as_array() {
        let quotes = json["chart"]["result"][0]["indicators"]["quote"][0].clone();
        let opens = quotes["open"].as_array().map(|a| a.to_vec()).unwrap_or_default();
        let highs = quotes["high"].as_array().map(|a| a.to_vec()).unwrap_or_default();
        let lows = quotes["low"].as_array().map(|a| a.to_vec()).unwrap_or_default();
        let closes = quotes["close"].as_array().map(|a| a.to_vec()).unwrap_or_default();
        let volumes = quotes["volume"].as_array().map(|a| a.to_vec()).unwrap_or_default();

        let bars: Vec<Value> = timestamps.iter().enumerate().map(|(i, ts)| {
            Value::Struct {
                name: "Bar".into(),
                fields: vec![
                    ("timestamp".into(), Value::Int(ts.as_i64().unwrap_or(0) as i128)),
                    ("open".into(), opens.get(i).and_then(|v| v.as_f64()).map(Value::Float).unwrap_or(Value::Nil)),
                    ("high".into(), highs.get(i).and_then(|v| v.as_f64()).map(Value::Float).unwrap_or(Value::Nil)),
                    ("low".into(), lows.get(i).and_then(|v| v.as_f64()).map(Value::Float).unwrap_or(Value::Nil)),
                    ("close".into(), closes.get(i).and_then(|v| v.as_f64()).map(Value::Float).unwrap_or(Value::Nil)),
                    ("volume".into(), volumes.get(i).and_then(|v| v.as_i64()).map(|v| Value::Int(v as i128)).unwrap_or(Value::Nil)),
                ],
            }
        }).collect();
        return Ok(Value::Array(bars));
    }
    Err(format!("No data for {ticker}"))
}

// ── Yahoo.options_chain(ticker) ──
fn fetch_options(ticker: &str, expiration: Option<&str>) -> StdlibResult {
    let url = if let Some(exp) = expiration {
        format!("https://query2.finance.yahoo.com/v7/finance/options/{ticker}?date={exp}")
    } else {
        format!("https://query2.finance.yahoo.com/v7/finance/options/{ticker}")
    };
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("Options: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
    parse_json(&body)
}

// ── Yahoo.search(query) ──
fn fetch_search(query: &str) -> StdlibResult {
    let url = format!("https://query2.finance.yahoo.com/v1/finance/search?q={}&quotesCount=10", urlencoding::encode(query));
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("Search: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("JSON: {e}"))?;

    if let Some(results) = json["quotes"].as_array() {
        let items: Vec<Value> = results.iter().map(|r| {
            Value::Struct {
                name: "SearchResult".into(),
                fields: vec![
                    ("symbol".into(), Value::String(r["symbol"].as_str().unwrap_or("").to_string())),
                    ("name".into(), Value::String(r["shortname"].as_str().unwrap_or("").to_string())),
                    ("exchange".into(), Value::String(r["exchange"].as_str().unwrap_or("").to_string())),
                    ("type".into(), Value::String(r["quoteType"].as_str().unwrap_or("").to_string())),
                ],
            }
        }).collect();
        return Ok(Value::Array(items));
    }
    Ok(Value::Array(Vec::new()))
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "quote" => Some(yh_quote(args)),
        "history" => Some(yh_history(args)),
        "options_chain" => Some(yh_options(args)),
        "search" => Some(yh_search(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "quote" | "history" | "options_chain" | "search")
}

fn yh_quote(args: Vec<Value>) -> StdlibResult {
    let ticker = expect_first_str(&args, "ticker")?;
    fetch_quote(ticker)
}

fn yh_history(args: Vec<Value>) -> StdlibResult {
    let ticker = expect_first_str(&args, "ticker")?;
    let period = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("1mo");
    let interval = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("1d");
    fetch_history(ticker, period, interval)
}

fn yh_options(args: Vec<Value>) -> StdlibResult {
    let ticker = expect_first_str(&args, "ticker")?;
    let expiration = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None });
    fetch_options(ticker, expiration)
}

fn yh_search(args: Vec<Value>) -> StdlibResult {
    let query = expect_first_str(&args, "query")?;
    fetch_search(query)
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
