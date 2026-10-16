//! Standard library: `tallow.algos` — algorithmic trading strategies.
//!
//! Avellaneda-Stoikov market making, statistical arbitrage (pairs trading),
//! momentum/mean-reversion signals, and execution algorithms.
//!
//! # API
//! - `Algos.avellaneda_stoikov(S, sigma, gamma, k, T)` — optimal bid/ask
//! - `Algos.pairs_trading(spread, entry_z, exit_z)` — cointegration signal
//! - `Algos.momentum(prices, lookback)` — time-series momentum
//! - `Algos.twap(quantity, duration, slices)` — TWAP schedule
//! - `Algos.vwap_profile(volume_curve)` — VWAP volume profile
//! - `Algos.backtest(prices, signals)` — simple backtest engine

use super::StdlibResult;
use crate::interp::{type_name, Value};

/// Avellaneda-Stoikov (2008) optimal market making
/// Returns (reservation_price, optimal_bid, optimal_ask, optimal_spread)
pub fn avellaneda_stoikov(s: f64, sigma: f64, gamma: f64, k: f64, t: f64, q: f64) -> Value {
    let reservation = s - q * gamma * sigma.powi(2) * (t);
    let spread = gamma * sigma.powi(2) * (t) + (2.0 / gamma) * (1.0 + (gamma / k)).ln();
    let half_spread = spread / 2.0;
    Value::Struct {
        name: "ASQuote".into(),
        fields: vec![
            ("reservation_price".into(), Value::Float(reservation)),
            ("bid".into(), Value::Float(reservation - half_spread)),
            ("ask".into(), Value::Float(reservation + half_spread)),
            ("spread".into(), Value::Float(spread)),
            ("inventory".into(), Value::Float(q)),
        ],
    }
}

/// Cointegration-based pairs trading signal
pub fn pairs_signal(spread: &[f64], entry_z: f64, exit_z: f64) -> Value {
    let n = spread.len();
    if n < 2 {
        return Value::Struct {
            name: "PairSignal".into(),
            fields: vec![("signal".into(), Value::String("hold".into()))],
        };
    }
    let mean: f64 = spread.iter().sum::<f64>() / n as f64;
    let variance: f64 = spread.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n as f64;
    let std = variance.sqrt();
    let z_score = if std > 0.0 { (spread[n - 1] - mean) / std } else { 0.0 };

    let signal = if z_score > entry_z {
        "short_spread" // asset A overvalued vs B — short A, long B
    } else if z_score < -entry_z {
        "long_spread" // asset A undervalued — long A, short B
    } else if z_score.abs() < exit_z {
        "exit" // close position
    } else {
        "hold"
    };

    Value::Struct {
        name: "PairSignal".into(),
        fields: vec![
            ("signal".into(), Value::String(signal.into())),
            ("z_score".into(), Value::Float(z_score)),
            ("mean".into(), Value::Float(mean)),
            ("std".into(), Value::Float(std)),
        ],
    }
}

/// Time-series momentum (Moskowitz, Ooi, Pedersen 2012)
pub fn momentum_signal(prices: &[f64], lookback: usize) -> Vec<Value> {
    let n = prices.len();
    let mut signals = Vec::new();
    for _ in 0..lookback.min(n) {
        signals.push(Value::Nil);
    }
    for i in lookback..n {
        let ret = prices[i] / prices[i - lookback] - 1.0;
        let signal = if ret > 0.0 { 1.0 } else { -1.0 };
        // Scale by recent volatility
        let slice = &prices[i.saturating_sub(20)..=i];
        let returns: Vec<f64> = slice.windows(2).map(|w| w[1] / w[0] - 1.0).collect();
        let vol = std_dev(&returns);
        let scaled = if vol > 0.0 { signal * 0.20 / vol } else { signal };
        signals.push(Value::Float(scaled));
    }
    signals
}

/// Cross-sectional momentum: rank assets by recent return
pub fn cross_sectional_momentum(returns: &[Vec<f64>], lookback: usize) -> Vec<f64> {
    let n_assets = returns.len();
    let mut scores: Vec<(usize, f64)> = (0..n_assets).map(|i| {
        let start = returns[i].len().saturating_sub(lookback);
        let ret: f64 = returns[i][start..].iter().product::<f64>();
        (i, ret)
    }).collect();
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut weights = vec![0.0; n_assets];
    let top_n = (n_assets as f64 * 0.2).max(1.0) as usize;
    let bottom_n = top_n;
    for j in 0..top_n {
        weights[scores[j].0] = 1.0 / top_n as f64;
    }
    for j in 0..bottom_n {
        weights[scores[n_assets - 1 - j].0] = -1.0 / bottom_n as f64;
    }
    weights
}

/// TWAP execution schedule
pub fn twap_schedule(quantity: f64, duration_secs: f64, slices: usize) -> Vec<Value> {
    let qty_per_slice = quantity / slices as f64;
    let interval = duration_secs / slices as f64;
    (0..slices).map(|i| {
        Value::Struct {
            name: "TWAPSlice".into(),
            fields: vec![
                ("time".into(), Value::Float(interval * i as f64)),
                ("quantity".into(), Value::Float(qty_per_slice)),
                ("cumulative".into(), Value::Float(qty_per_slice * (i + 1) as f64)),
            ],
        }
    }).collect()
}

/// VWAP volume profile from historical volume curve
pub fn vwap_profile(volume_curve: &[f64]) -> Vec<f64> {
    let total: f64 = volume_curve.iter().sum();
    if total <= 0.0 { return vec![1.0 / volume_curve.len() as f64; volume_curve.len()]; }
    volume_curve.iter().map(|v| v / total).collect()
}

/// Simple backtest engine
pub fn backtest(prices: &[f64], signals: &[f64]) -> Value {
    let n = prices.len();
    let mut returns = Vec::new();
    let mut equity = vec![1.0];
    let mut position = 0.0;
    let mut trade_count = 0;

    if n >= 2 {
    for i in 0..n - 1 {
        let signal = signals.get(i).copied().unwrap_or(0.0);
        let prev_pos = position;
        position = signal;
        if (position - prev_pos).abs() > 0.001 { trade_count += 1; }
        let ret = position * (prices[i + 1] / prices[i] - 1.0);
        returns.push(ret);
        equity.push(equity.last().unwrap() * (1.0 + ret));
    }
    }

    let ret_slice: Vec<f64> = returns.clone();
    let mean_ret = ret_slice.iter().sum::<f64>() / ret_slice.len().max(1) as f64;
    let vol = std_dev(&returns) * (252.0_f64).sqrt(); // annualized
    let sharpe = if vol > 0.0 { mean_ret * 252.0 / vol } else { 0.0 };
    let max_dd = max_drawdown(&equity);

    Value::Struct {
        name: "BacktestResult".into(),
        fields: vec![
            ("total_return".into(), Value::Float(equity.last().unwrap_or(&1.0) - 1.0)),
            ("sharpe_ratio".into(), Value::Float(sharpe)),
            ("max_drawdown".into(), Value::Float(max_dd)),
            ("volatility".into(), Value::Float(vol)),
            ("trades".into(), Value::Int(trade_count)),
            ("equity_curve".into(), Value::Array(equity.iter().map(|&e| Value::Float(e)).collect())),
        ],
    }
}

fn std_dev(values: &[f64]) -> f64 {
    let n = values.len();
    if n == 0 { return 0.0; }
    let mean = values.iter().sum::<f64>() / n as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
    variance.sqrt()
}

fn max_drawdown(equity: &[f64]) -> f64 {
    let mut peak = equity[0];
    let mut max_dd = 0.0;
    for &e in &equity[1..] {
        if e > peak { peak = e; }
        let dd = (peak - e) / peak;
        if dd > max_dd { max_dd = dd; }
    }
    max_dd
}

fn parse_signals(value: &Value) -> Vec<f64> {
    match value {
        Value::Array(arr) => arr.iter().filter_map(|v| match v {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            Value::Nil => Some(0.0),
            _ => None,
        }).collect(),
        _ => Vec::new(),
    }
}

fn parse_prices(value: &Value) -> Vec<f64> {
    parse_signals(value) // same logic
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    // Dispatch must never ICE on argument shape: every algos handler needs at
    // least one input argument, and a zero-arg call (e.g. a capability probe)
    // must produce an honest Err instead of an index-out-of-bounds panic.
    if args.is_empty() {
        return Some(Err("algos: requires input".to_string()));
    }
    match function {
        "avellaneda_stoikov" => Some(algo_as(args)),
        "pairs_trading" => Some(algo_pairs(args)),
        "momentum" => Some(algo_momentum(args)),
        "cross_sectional" => Some(algo_cs(args)),
        "twap" => Some(algo_twap(args)),
        "vwap_profile" => Some(algo_vwap(args)),
        "backtest" => Some(algo_bt(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "avellaneda_stoikov" | "pairs_trading" | "momentum" | "cross_sectional" | "twap" | "vwap_profile" | "backtest")
}

fn algo_as(args: Vec<Value>) -> StdlibResult {
    let s = get_f64(&args, 0)?;
    let sigma = get_f64(&args, 1)?;
    let gamma = get_f64(&args, 2)?;
    let k = get_f64(&args, 3)?;
    let t = get_f64(&args, 4)?;
    let q = args.get(5).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None }).unwrap_or(0.0);
    Ok(avellaneda_stoikov(s, sigma, gamma, k, t, q))
}

fn algo_pairs(args: Vec<Value>) -> StdlibResult {
    let spread = parse_prices(first_arg(&args, "pairs_trading")?);
    let entry = get_f64(&args, 1)?;
    let exit = get_f64(&args, 2)?;
    Ok(pairs_signal(&spread, entry, exit))
}

fn algo_momentum(args: Vec<Value>) -> StdlibResult {
    let prices = parse_prices(first_arg(&args, "momentum")?);
    let lookback = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(252);
    Ok(Value::Array(momentum_signal(&prices, lookback)))
}

fn algo_cs(args: Vec<Value>) -> StdlibResult {
    let returns = match first_arg(&args, "cross_sectional")? {
        Value::Array(rows) => {
            let mut mat = Vec::new();
            for row in rows {
                mat.push(parse_prices(row));
            }
            mat
        }
        _ => return Err("Expected matrix of returns".into()),
    };
    let lookback = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(252);
    let w = cross_sectional_momentum(&returns, lookback);
    Ok(Value::Array(w.iter().map(|&x| Value::Float(x)).collect()))
}

fn algo_twap(args: Vec<Value>) -> StdlibResult {
    let qty = get_f64(&args, 0)?;
    let dur = get_f64(&args, 1)?;
    let slices = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(10);
    Ok(Value::Array(twap_schedule(qty, dur, slices)))
}

fn algo_vwap(args: Vec<Value>) -> StdlibResult {
    let vol = parse_prices(first_arg(&args, "vwap_profile")?);
    let profile = vwap_profile(&vol);
    Ok(Value::Array(profile.iter().map(|&x| Value::Float(x)).collect()))
}

fn algo_bt(args: Vec<Value>) -> StdlibResult {
    let prices = parse_prices(first_arg(&args, "backtest")?);
    let signals = parse_signals(args.get(1).ok_or("algos.backtest: requires input (signals)")?);
    let signal_vals: Vec<f64> = signals.iter().copied().collect();
    Ok(backtest(&prices, &signal_vals))
}

/// First positional argument with an honest Err instead of a panic when the
/// argument list is empty — dispatch must never ICE on argument shape.
fn first_arg<'a>(args: &'a [Value], what: &str) -> Result<&'a Value, String> {
    args.first()
        .ok_or_else(|| format!("algos.{what}: requires input"))
}

fn get_f64(args: &[Value], idx: usize) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        _ => Err(format!("Expected number at {}", idx)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backtest_empty_prices_does_not_panic() {
        let r = backtest(&[], &[]);
        if let Value::Struct { fields, .. } = r {
            assert_eq!(fields[0].0, "total_return");
            if let Value::Float(t) = fields[0].1 {
                assert_eq!(t, 0.0);
            } else {
                panic!("expected float total_return");
            }
        } else {
            panic!("expected BacktestResult struct");
        }
    }

    #[test]
    fn backtest_single_price_does_not_panic() {
        let r = backtest(&[100.0], &[]);
        assert!(matches!(r, Value::Struct { .. }));
    }

    #[test]
    fn parse_prices_delegates_to_parse_signals() {
        let v = Value::Array(vec![
            Value::Int(10),
            Value::Float(2.5),
            Value::Nil,
            Value::String("skip".into()),
        ]);
        let p = parse_prices(&v);
        assert_eq!(p, vec![10.0, 2.5, 0.0]);
        assert!(parse_prices(&Value::Nil).is_empty());
    }

    // Every algos dispatch handler requires >=1 input argument. A zero-arg
    // call (e.g. a capability probe) must return an honest Err — never panic
    // with an index-out-of-bounds ICE.
    #[test]
    fn dispatch_zero_arg_returns_honest_err_not_panic() {
        let names = [
            "avellaneda_stoikov",
            "pairs_trading",
            "momentum",
            "cross_sectional",
            "twap",
            "vwap_profile",
            "backtest",
        ];
        for name in names {
            let r = dispatch(name, Vec::new());
            match r {
                Some(Err(msg)) => assert!(
                    msg.contains("requires input"),
                    "{name}: expected 'requires input' Err, got: {msg}"
                ),
                other => panic!("{name}: zero-arg dispatch must Err, got {other:?}"),
            }
        }
        // Sanity: the same handler still works with real input.
        let ok = dispatch(
            "momentum",
            vec![Value::Array(vec![Value::Float(1.0), Value::Float(2.0)])],
        );
        assert!(matches!(ok, Some(Ok(Value::Array(_)))));
    }
}