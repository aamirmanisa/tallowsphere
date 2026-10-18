//! Standard library: `tallow.technical` — technical analysis indicators.
//!
//! Computes common financial technical indicators from price series.
//! Input: arrays of prices (close, high, low, volume). Output: indicator values.
//!
//! # API
//! - `TA.sma(prices, period)` — simple moving average
//! - `TA.ema(prices, period)` — exponential moving average
//! - `TA.rsi(prices, period)` — relative strength index
//! - `TA.macd(prices, fast?, slow?, signal?)` — MACD line, signal, histogram
//! - `TA.bollinger(prices, period?, stddevs?)` — upper, middle, lower bands
//! - `TA.atr(high, low, close, period)` — average true range
//! - `TA.obv(close, volume)` — on-balance volume
//! - `TA.stochastic(high, low, close, k_period?, d_period?)` — %K, %D

use super::StdlibResult;
use crate::interp::{type_name, Value};

fn get_f64_slice(v: &Value) -> Result<Vec<f64>, String> {
    match v {
        Value::Array(arr) => arr.iter().map(|x| to_f64(x)).collect(),
        _ => Err(format!("Expected array, got {}", type_name(v))),
    }
}

fn to_f64(v: &Value) -> Result<f64, String> {
    match v {
        Value::Float(f) => Ok(*f),
        Value::Int(i) => Ok(*i as f64),
        _ => Err(format!("Expected number, got {}", type_name(v))),
    }
}

fn f64_array(values: &[f64]) -> Value {
    Value::Array(values.iter().map(|&v| Value::Float(v)).collect())
}

// ── Simple Moving Average ──
fn sma(prices: &[f64], period: usize) -> Vec<f64> {
    if period == 0 || prices.len() < period {
        return vec![f64::NAN; prices.len()];
    }
    let mut result = vec![f64::NAN; period - 1];
    let mut sum: f64 = prices[..period].iter().sum();
    result.push(sum / period as f64);
    for i in period..prices.len() {
        sum += prices[i] - prices[i - period];
        result.push(sum / period as f64);
    }
    result
}

// ── Exponential Moving Average ──
fn ema(prices: &[f64], period: usize) -> Vec<f64> {
    // `prices[..period]` below panics when the series is shorter than the
    // period. `atr` reaches this with short input (2 bars at period 14), so
    // the guard is not theoretical: it produced an ICE at this line
    // (register #76). Match `sma`'s contract — a series shorter than the
    // period yields NaN of the same length.
    if period == 0 || prices.len() < period {
        return vec![f64::NAN; prices.len()];
    }
    let multiplier = 2.0 / (period as f64 + 1.0);
    let mut result = vec![f64::NAN; period - 1];
    // First EMA value is SMA
    let first: f64 = prices[..period].iter().sum::<f64>() / period as f64;
    result.push(first);
    let mut prev = first;
    for &price in &prices[period..] {
        let val = (price - prev) * multiplier + prev;
        result.push(val);
        prev = val;
    }
    result
}

// ── Relative Strength Index ──
fn rsi(prices: &[f64], period: usize) -> Vec<f64> {
    if period == 0 || prices.len() < period + 1 {
        return vec![f64::NAN; prices.len()];
    }
    let mut result = vec![f64::NAN; period];
    let mut gains = Vec::new();
    let mut losses = Vec::new();
    for i in 1..=period {
        let delta = prices[i] - prices[i - 1];
        gains.push(if delta > 0.0 { delta } else { 0.0 });
        losses.push(if delta < 0.0 { -delta } else { 0.0 });
    }
    let mut avg_gain: f64 = gains.iter().sum::<f64>() / period as f64;
    let mut avg_loss: f64 = losses.iter().sum::<f64>() / period as f64;
    for i in period..prices.len() {
        if avg_loss == 0.0 {
            result.push(100.0);
        } else {
            let rs = avg_gain / avg_loss;
            result.push(100.0 - 100.0 / (1.0 + rs));
        }
        if i + 1 < prices.len() {
            let delta = prices[i + 1] - prices[i];
            let gain = if delta > 0.0 { delta } else { 0.0 };
            let loss = if delta < 0.0 { -delta } else { 0.0 };
            avg_gain = (avg_gain * (period - 1) as f64 + gain) / period as f64;
            avg_loss = (avg_loss * (period - 1) as f64 + loss) / period as f64;
        }
    }
    result
}

// ── MACD ──
fn macd(prices: &[f64], fast: usize, slow: usize, signal: usize) -> Value {
    let ema_fast = ema(prices, fast);
    let ema_slow = ema(prices, slow);
    let mut macd_line = Vec::new();
    for i in 0..prices.len() {
        if ema_fast[i].is_nan() || ema_slow[i].is_nan() {
            macd_line.push(f64::NAN);
        } else {
            macd_line.push(ema_fast[i] - ema_slow[i]);
        }
    }
    let signal_line = ema(&macd_line, signal);
    let mut histogram = Vec::new();
    for i in 0..prices.len() {
        if macd_line[i].is_nan() || signal_line[i].is_nan() {
            histogram.push(f64::NAN);
        } else {
            histogram.push(macd_line[i] - signal_line[i]);
        }
    }
    Value::Struct {
        name: "MACD".into(),
        fields: vec![
            ("macd".into(), f64_array(&macd_line)),
            ("signal".into(), f64_array(&signal_line)),
            ("histogram".into(), f64_array(&histogram)),
        ],
    }
}

// ── Bollinger Bands ──
fn bollinger(prices: &[f64], period: usize, stddevs: f64) -> Value {
    let middle = sma(prices, period);
    let mut upper = vec![f64::NAN; prices.len()];
    let mut lower = vec![f64::NAN; prices.len()];
    for i in period - 1..prices.len() {
        let slice = &prices[i + 1 - period..=i];
        let mean = slice.iter().sum::<f64>() / period as f64;
        let variance = slice.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / period as f64;
        let std = variance.sqrt();
        upper[i] = middle[i] + stddevs * std;
        lower[i] = middle[i] - stddevs * std;
    }
    Value::Struct {
        name: "Bollinger".into(),
        fields: vec![
            ("upper".into(), f64_array(&upper)),
            ("middle".into(), f64_array(&middle)),
            ("lower".into(), f64_array(&lower)),
        ],
    }
}

// ── Average True Range ──
fn atr(high: &[f64], low: &[f64], close: &[f64], period: usize) -> Vec<f64> {
    let n = high.len().min(low.len()).min(close.len());
    if n < 2 {
        return vec![f64::NAN; n];
    }
    let mut tr = Vec::new();
    tr.push(high[0] - low[0]);
    for i in 1..n {
        let h_l = high[i] - low[i];
        let h_pc = (high[i] - close[i - 1]).abs();
        let l_pc = (low[i] - close[i - 1]).abs();
        tr.push(h_l.max(h_pc).max(l_pc));
    }
    // ATR is EMA of TR
    ema(&tr, period)
}

// ── On-Balance Volume ──
fn obv(close: &[f64], volume: &[f64]) -> Vec<f64> {
    let n = close.len().min(volume.len());
    let mut result = vec![0.0; n];
    let mut running = 0.0;
    for i in 0..n {
        if i == 0 || close[i] > close[i - 1] {
            running += volume[i];
        } else if close[i] < close[i - 1] {
            running -= volume[i];
        }
        result[i] = running;
    }
    result
}

// ── Stochastic Oscillator ──
fn stochastic(high: &[f64], low: &[f64], close: &[f64], k_period: usize, d_period: usize) -> Value {
    let n = high.len().min(low.len()).min(close.len());
    let mut k_values = vec![f64::NAN; n];
    for i in k_period - 1..n {
        let start = i + 1 - k_period;
        let h_max = high[start..=i].iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let l_min = low[start..=i].iter().cloned().fold(f64::INFINITY, f64::min);
        if h_max != l_min {
            k_values[i] = 100.0 * (close[i] - l_min) / (h_max - l_min);
        } else {
            k_values[i] = 50.0;
        }
    }
    let d_values = sma(&k_values, d_period);
    Value::Struct {
        name: "Stochastic".into(),
        fields: vec![
            ("k".into(), f64_array(&k_values)),
            ("d".into(), f64_array(&d_values)),
        ],
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "sma" => Some(ta_sma(args)),
        "ema" => Some(ta_ema(args)),
        "rsi" => Some(ta_rsi(args)),
        "macd" => Some(ta_macd(args)),
        "bollinger" => Some(ta_bollinger(args)),
        "atr" => Some(ta_atr(args)),
        "obv" => Some(ta_obv(args)),
        "stochastic" => Some(ta_stochastic(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "sma" | "ema" | "rsi" | "macd" | "bollinger" | "atr" | "obv" | "stochastic")
}

fn ta_sma(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Technical.sma: requires (prices)".into());
    }
    let prices = get_f64_slice(&args[0])?;
    let period = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(20);
    Ok(f64_array(&sma(&prices, period)))
}

fn ta_ema(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Technical.ema: requires (prices)".into());
    }
    let prices = get_f64_slice(&args[0])?;
    let period = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(20);
    Ok(f64_array(&ema(&prices, period)))
}

fn ta_rsi(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Technical.rsi: requires (prices)".into());
    }
    let prices = get_f64_slice(&args[0])?;
    let period = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(14);
    Ok(f64_array(&rsi(&prices, period)))
}

fn ta_macd(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Technical.macd: requires (prices)".into());
    }
    let prices = get_f64_slice(&args[0])?;
    let fast = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(12);
    let slow = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(26);
    let signal = args.get(3).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(9);
    Ok(macd(&prices, fast, slow, signal))
}

fn ta_bollinger(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Technical.bollinger: requires (prices)".into());
    }
    let prices = get_f64_slice(&args[0])?;
    let period = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(20);
    let stddevs = args.get(2).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None }).unwrap_or(2.0);
    Ok(bollinger(&prices, period, stddevs))
}

fn ta_atr(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("Technical.atr: requires (high, low, close)".into());
    }
    let high = get_f64_slice(&args[0])?;
    let low = get_f64_slice(&args[1])?;
    let close = get_f64_slice(&args[2])?;
    let period = args.get(3).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(14);
    Ok(f64_array(&atr(&high, &low, &close, period)))
}

fn ta_obv(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Technical.obv: requires (close, volume)".into());
    }
    let close = get_f64_slice(&args[0])?;
    let volume = get_f64_slice(&args[1])?;
    Ok(f64_array(&obv(&close, &volume)))
}

fn ta_stochastic(args: Vec<Value>) -> StdlibResult {
    if args.len() < 3 {
        return Err("Technical.stochastic: requires (high, low, close)".into());
    }
    let high = get_f64_slice(&args[0])?;
    let low = get_f64_slice(&args[1])?;
    let close = get_f64_slice(&args[2])?;
    let k_period = args.get(3).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(14);
    let d_period = args.get(4).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(3);
    Ok(stochastic(&high, &low, &close, k_period, d_period))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Register #76: `atr` with fewer bars than the period reached `ema` and
    /// panicked on `prices[..period]` — a well-typed call producing an ICE
    /// (rc 8) instead of a value. A short series is NaN of the input length,
    /// the same contract `sma` already had.
    #[test]
    fn ema_shorter_than_period_is_nan_not_a_panic() {
        let out = ema(&[1.0, 2.0], 14);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|v| v.is_nan()));
    }

    #[test]
    fn atr_with_a_short_series_returns_nan() {
        let out = atr(&[1.0, 2.0], &[0.5, 1.5], &[0.8, 1.8], 14);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|v| v.is_nan()));
    }
}
