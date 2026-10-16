//! Standard library: `tallow.finance` — financial analysis and ratios.
//!
//! Provides essential financial statement analysis, valuation metrics,
//! and time-value-of-money calculations for investment analysis.
//!
//! # API
//! - `Finance.pv(fv, rate, periods)` — present value
//! - `Finance.fv(pv, rate, periods)` — future value
//! - `Finance.npv(rate, cashflows)` — net present value
//! - `Finance.irr(cashflows)` — internal rate of return (Newton's method)
//! - `Finance.pmt(principal, rate, periods)` — loan payment
//! - `Finance.ratio(name, values)` — compute financial ratios

use super::StdlibResult;
use crate::interp::{type_name, Value};

fn pv(fv: f64, rate: f64, periods: f64) -> f64 {
    fv / (1.0 + rate).powf(periods)
}

fn fv(pv: f64, rate: f64, periods: f64) -> f64 {
    pv * (1.0 + rate).powf(periods)
}

fn npv(rate: f64, cashflows: &[f64]) -> f64 {
    cashflows.iter().enumerate()
        .map(|(t, &cf)| cf / (1.0 + rate).powf(t as f64))
        .sum()
}

fn irr(cashflows: &[f64], guess: f64) -> f64 {
    let mut rate = guess;
    for _ in 0..1000 {
        let npv_val = npv(rate, cashflows);
        let d_npv: f64 = cashflows.iter().enumerate()
            .map(|(t, &cf)| -(t as f64) * cf / (1.0 + rate).powf(t as f64 + 1.0))
            .sum();
        if d_npv.abs() < 1e-10 { break; }
        rate -= npv_val / d_npv;
        if rate.is_nan() || rate.abs() > 100.0 { return f64::NAN; }
    }
    rate
}

fn pmt(principal: f64, rate: f64, periods: f64) -> f64 {
    if rate == 0.0 {
        principal / periods
    } else {
        principal * rate * (1.0 + rate).powf(periods) / ((1.0 + rate).powf(periods) - 1.0)
    }
}

fn compute_ratio(name: &str, values: &[f64]) -> StdlibResult {
    match name {
        // Profitability ratios
        "gross_margin" => {
            if values.len() < 2 { return Err("gross_margin: requires [gross_profit, revenue]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "net_margin" => {
            if values.len() < 2 { return Err("net_margin: requires [net_income, revenue]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "roa" => {
            if values.len() < 2 { return Err("roa: requires [net_income, total_assets]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "roe" => {
            if values.len() < 2 { return Err("roe: requires [net_income, equity]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        // Liquidity ratios
        "current_ratio" => {
            if values.len() < 2 { return Err("current_ratio: requires [current_assets, current_liabilities]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "quick_ratio" => {
            if values.len() < 3 { return Err("quick_ratio: requires [current_assets, inventory, current_liabilities]".into()); }
            Ok(Value::Float((values[0] - values[1]) / values[2]))
        }
        // Valuation ratios
        "pe_ratio" => {
            if values.len() < 2 { return Err("pe_ratio: requires [price_per_share, earnings_per_share]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "pb_ratio" => {
            if values.len() < 2 { return Err("pb_ratio: requires [price_per_share, book_value_per_share]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "ev_ebitda" => {
            if values.len() < 2 { return Err("ev_ebitda: requires [enterprise_value, ebitda]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        // Leverage ratios
        "debt_to_equity" => {
            if values.len() < 2 { return Err("debt_to_equity: requires [total_debt, equity]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "interest_coverage" => {
            if values.len() < 2 { return Err("interest_coverage: requires [ebit, interest_expense]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        // Efficiency ratios
        "asset_turnover" => {
            if values.len() < 2 { return Err("asset_turnover: requires [revenue, total_assets]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        "inventory_turnover" => {
            if values.len() < 2 { return Err("inventory_turnover: requires [cogs, avg_inventory]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        // Growth metrics
        "yoy_growth" => {
            if values.len() < 2 { return Err("yoy_growth: requires [current, previous]".into()); }
            Ok(Value::Float((values[0] - values[1]) / values[1].abs()))
        }
        "cagr" => {
            if values.len() < 3 { return Err("cagr: requires [end_value, start_value, years]".into()); }
            Ok(Value::Float((values[0] / values[1]).powf(1.0 / values[2]) - 1.0))
        }
        // Risk metrics
        "sharpe_ratio" => {
            if values.len() < 3 { return Err("sharpe: requires [returns_mean, risk_free_rate, returns_stddev]".into()); }
            Ok(Value::Float((values[0] - values[1]) / values[2]))
        }
        "beta" => {
            if values.len() < 3 { return Err("beta: requires [stock_returns_variance_with_market, market_returns_variance]]".into()); }
            Ok(Value::Float(values[0] / values[1]))
        }
        _ => Err(format!("Unknown ratio: {name}. Available: gross_margin, net_margin, roa, roe, current_ratio, quick_ratio, pe_ratio, pb_ratio, ev_ebitda, debt_to_equity, interest_coverage, asset_turnover, inventory_turnover, yoy_growth, cagr, sharpe_ratio, beta"))
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "pv" => Some(fin_pv(args)),
        "fv" => Some(fin_fv(args)),
        "npv" => Some(fin_npv(args)),
        "irr" => Some(fin_irr(args)),
        "pmt" => Some(fin_pmt(args)),
        "ratio" => Some(fin_ratio(args)),
        // ── Contract parity with stdlib/finance.tl (2026-08-27) ──
        // The .tl declarations expose flat ratio functions with positional
        // args (current_ratio(current_assets, current_liabilities), etc.).
        // Implement them here so code written against the documented API
        // dispatches for real instead of "undefined function".
        "current_ratio" => Some(fin_flat_ratio("current_ratio", args)),
        "quick_ratio" => Some(fin_flat_ratio("quick_ratio", args)),
        "debt_to_equity" => Some(fin_flat_ratio("debt_to_equity", args)),
        "roe" => Some(fin_flat_ratio("roe", args)),
        "roa" => Some(fin_flat_ratio("roa", args)),
        "gross_margin" => Some(fin_flat_ratio("gross_margin", args)),
        "operating_margin" => Some(fin_flat_ratio("operating_margin", args)),
        "net_margin" => Some(fin_flat_ratio("net_margin", args)),
        "pe_ratio" => Some(fin_flat_ratio("pe_ratio", args)),
        "pb_ratio" => Some(fin_flat_ratio("pb_ratio", args)),
        "dividend_yield" => Some(fin_flat_ratio("dividend_yield", args)),
        "eps" => Some(fin_flat_ratio("eps", args)),
        "free_cash_flow_yield" => Some(fin_flat_ratio("free_cash_flow_yield", args)),
        "interest_coverage" => Some(fin_flat_ratio("interest_coverage", args)),
        "asset_turnover" => Some(fin_flat_ratio("asset_turnover", args)),
        _ => None,
    }
}

/// Flat ratio implementations matching stdlib/finance.tl declarations.
fn fin_flat_ratio(name: &str, args: Vec<Value>) -> StdlibResult {
    let two = |a: usize, b: usize| -> StdlibResult {
        let x = get_f64(&args, a)?;
        let y = get_f64(&args, b)?;
        if y == 0.0 {
            return Err(format!("{name}: division by zero (arg {b})"));
        }
        Ok(Value::Float(x / y))
    };
    match name {
        "current_ratio" => two(0, 1),
        // quick_ratio(cash, receivables, current_liabilities)
        "quick_ratio" => {
            let cash = get_f64(&args, 0)?;
            let receivables = get_f64(&args, 1)?;
            let liabilities = get_f64(&args, 2)?;
            if liabilities == 0.0 {
                return Err("quick_ratio: division by zero (current_liabilities)".into());
            }
            Ok(Value::Float((cash + receivables) / liabilities))
        }
        "debt_to_equity" => two(0, 1),
        "roe" => two(0, 1),
        "roa" => two(0, 1),
        // gross_margin(revenue, cogs) = (revenue - cogs) / revenue
        "gross_margin" => {
            let revenue = get_f64(&args, 0)?;
            let cogs = get_f64(&args, 1)?;
            if revenue == 0.0 {
                return Err("gross_margin: division by zero (revenue)".into());
            }
            Ok(Value::Float((revenue - cogs) / revenue))
        }
        "operating_margin" => two(0, 1),
        "net_margin" => two(0, 1),
        "pe_ratio" => two(0, 1),
        "pb_ratio" => two(0, 1),
        "dividend_yield" => two(0, 1),
        // eps(earnings, shares) — shares may be Int (get_f64 handles Int)
        "eps" => two(0, 1),
        "free_cash_flow_yield" => two(0, 1),
        "interest_coverage" => two(0, 1),
        "asset_turnover" => two(0, 1),
        _ => Err(format!("Unknown ratio: {name}")),
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "pv" | "fv" | "npv" | "irr" | "pmt" | "ratio" | "current_ratio" | "quick_ratio"
            | "debt_to_equity" | "roe" | "roa" | "gross_margin" | "operating_margin"
            | "net_margin" | "pe_ratio" | "pb_ratio" | "dividend_yield" | "eps"
            | "free_cash_flow_yield" | "interest_coverage" | "asset_turnover"
    )
}

fn get_f64(args: &[Value], idx: usize) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        Some(other) => Err(format!("Expected number, got {}", type_name(other))),
        None => Err(format!("Missing argument at index {}", idx)),
    }
}

fn get_f64_slice(args: &[Value], idx: usize) -> Result<Vec<f64>, String> {
    match args.get(idx) {
        Some(Value::Array(arr)) => {
            arr.iter().map(|v| match v {
                Value::Float(f) => Ok(*f),
                Value::Int(i) => Ok(*i as f64),
                _ => Err(format!("Expected number in array")),
            }).collect()
        }
        Some(other) => Err(format!("Expected array, got {}", type_name(other))),
        None => Err(format!("Missing array at index {}", idx)),
    }
}

fn fin_pv(args: Vec<Value>) -> StdlibResult {
    let fv = get_f64(&args, 0)?;
    let rate = get_f64(&args, 1)?;
    let periods = get_f64(&args, 2)?;
    Ok(Value::Float(pv(fv, rate, periods)))
}

fn fin_fv(args: Vec<Value>) -> StdlibResult {
    let pv = get_f64(&args, 0)?;
    let rate = get_f64(&args, 1)?;
    let periods = get_f64(&args, 2)?;
    Ok(Value::Float(fv(pv, rate, periods)))
}

fn fin_npv(args: Vec<Value>) -> StdlibResult {
    let rate = get_f64(&args, 0)?;
    let cashflows = get_f64_slice(&args, 1)?;
    Ok(Value::Float(npv(rate, &cashflows)))
}

fn fin_irr(args: Vec<Value>) -> StdlibResult {
    let cashflows = get_f64_slice(&args, 0)?;
    let guess = if args.len() > 1 { get_f64(&args, 1)? } else { 0.1 };
    Ok(Value::Float(irr(&cashflows, guess)))
}

fn fin_pmt(args: Vec<Value>) -> StdlibResult {
    let principal = get_f64(&args, 0)?;
    let rate = get_f64(&args, 1)?;
    let periods = get_f64(&args, 2)?;
    Ok(Value::Float(pmt(principal, rate, periods)))
}

fn fin_ratio(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Finance.ratio: requires (name, [values])".into());
    }
    let name = match &args[0] {
        Value::String(s) => s.as_str(),
        _ => return Err("Finance.ratio: first argument must be a ratio name string".into()),
    };
    let values = get_f64_slice(&args, 1)?;
    compute_ratio(name, &values)
}
