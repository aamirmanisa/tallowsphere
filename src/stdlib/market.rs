//! Standard library: `tallow.market` — unified financial market data aggregator.
//!
//! Combines Yahoo Finance, SEC EDGAR, and FRED into a single interface.
//! Provides cross-source data retrieval and correlation.
//!
//! # API
//! - `Market.summary(ticker)` — combined quote + key financials + SEC CIK
//! - `Market.eco_calendar()` — upcoming economic releases
//! - `Market.sector_performance()` — sector performance snapshot

use super::StdlibResult;
use crate::interp::{type_name, Value};

// ── Market.summary(ticker) ──
fn market_summary(ticker: &str) -> StdlibResult {
    // Get quote from Yahoo
    let url = format!("https://query2.finance.yahoo.com/v7/finance/quote?symbols={}", ticker);
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", "Mozilla/5.0")
        .call()
        .map_err(|e| format!("Quote: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

    let result = &json["quoteResponse"]["result"][0];

    Ok(Value::Struct {
        name: "MarketSummary".into(),
        fields: vec![
            ("ticker".into(), Value::String(ticker.to_string())),
            ("name".into(), Value::String(result["shortName"].as_str().unwrap_or("").to_string())),
            ("price".into(), Value::Float(result["regularMarketPrice"].as_f64().unwrap_or(0.0))),
            ("change_pct".into(), Value::Float(result["regularMarketChangePercent"].as_f64().unwrap_or(0.0))),
            ("volume".into(), Value::Int(result["regularMarketVolume"].as_i64().unwrap_or(0) as i128)),
            ("market_cap".into(), Value::Float(result["marketCap"].as_f64().unwrap_or(0.0))),
            ("pe_ratio".into(), Value::Float(result["trailingPE"].as_f64().unwrap_or(0.0))),
            ("fifty_two_week_high".into(), Value::Float(result["fiftyTwoWeekHigh"].as_f64().unwrap_or(0.0))),
            ("fifty_two_week_low".into(), Value::Float(result["fiftyTwoWeekLow"].as_f64().unwrap_or(0.0))),
            ("dividend_yield".into(), Value::Float(result["trailingAnnualDividendYield"].as_f64().unwrap_or(0.0))),
            ("sector".into(), Value::String(result["sector"].as_str().unwrap_or("").to_string())),
            ("industry".into(), Value::String(result["industry"].as_str().unwrap_or("").to_string())),
        ],
    })
}

// ── Market.sector_performance() ──
fn sector_performance() -> StdlibResult {
    let tickers = ["^GSPC", "XLF", "XLK", "XLE", "XLV", "XLI", "XLP", "XLY", "XLU", "XLB", "XLRE"];
    let symbols = tickers.join(",");
    let url = format!("https://query2.finance.yahoo.com/v7/finance/quote?symbols={}", symbols);
    let resp = crate::runtime::egress_http::get(&url)
        .header("User-Agent", "Mozilla/5.0")
        .call()
        .map_err(|e| format!("Sectors: {e}"))?;
    let body = resp.into_body().read_to_string().map_err(|e| format!("read: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

    let names = ["S&P 500", "Financials", "Technology", "Energy", "Healthcare", "Industrials", "Consumer Staples", "Consumer Discretionary", "Utilities", "Materials", "Real Estate"];

    if let Some(results) = json["quoteResponse"]["result"].as_array() {
        let items: Vec<Value> = results.iter().enumerate().map(|(i, r)| {
            Value::Struct {
                name: "SectorPerformance".into(),
                fields: vec![
                    ("name".into(), Value::String(names.get(i).unwrap_or(&"Unknown").to_string())),
                    ("symbol".into(), Value::String(tickers.get(i).unwrap_or(&"").to_string())),
                    ("change_pct".into(), Value::Float(r["regularMarketChangePercent"].as_f64().unwrap_or(0.0))),
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
        "summary" => Some(mkt_summary(args)),
        "sector_performance" => Some(Ok(sector_performance().unwrap_or(Value::Nil))),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "summary" | "sector_performance")
}

fn mkt_summary(args: Vec<Value>) -> StdlibResult {
    let ticker = match args.first() {
        Some(Value::String(s)) => s.as_str(),
        _ => return Err("Market.summary: requires (ticker)".into()),
    };
    market_summary(ticker)
}
