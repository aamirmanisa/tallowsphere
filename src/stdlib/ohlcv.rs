//! Standard library: `tallow.ohlcv` — OHLCV aggregation and resampling.
//!
//! Converts tick data to OHLCV bars at any resolution.
//! Resamples existing bars to higher timeframes.
//!
//! # API
//! - `OHLCV.from_ticks(ticks, period_secs)` — ticks → OHLCV bars
//! - `OHLCV.resample(bars, period_secs)` — resample bars to new timeframe
//! - `OHLCV.to_array(bars, field)` — extract field as flat array

use super::StdlibResult;
use crate::interp::Value;

fn extract_tick(tick: &Value) -> Option<(i64, f64, f64)> {
    match tick {
        Value::Struct { fields, .. } => {
            let ts = field_i64(fields, "timestamp")?;
            let price = field_f64(fields, "price")?;
            let vol = field_f64(fields, "volume").unwrap_or(0.0);
            Some((ts, price, vol))
        }
        _ => None,
    }
}

fn extract_bar(bar: &Value) -> Option<(i64, f64, f64, f64, f64, f64)> {
    match bar {
        Value::Struct { fields, .. } => {
            let ts = field_i64(fields, "timestamp")?;
            let o = field_f64(fields, "open")?;
            let h = field_f64(fields, "high")?;
            let l = field_f64(fields, "low")?;
            let c = field_f64(fields, "close")?;
            let v = field_f64(fields, "volume").unwrap_or(0.0);
            Some((ts, o, h, l, c, v))
        }
        _ => None,
    }
}

pub fn from_ticks(ticks: &[Value], period_secs: i64) -> Vec<Value> {
    let mut bars = Vec::new();
    if ticks.is_empty() { return bars; }

    let (first_ts, _, _) = match extract_tick(&ticks[0]) {
        Some(t) => t,
        None => return bars,
    };

    let mut bucket_start = (first_ts / period_secs) * period_secs;
    let mut bucket_end = bucket_start + period_secs;
    let mut open = 0.0;
    let mut high = f64::NEG_INFINITY;
    let mut low = f64::INFINITY;
    let mut close = 0.0;
    let mut volume = 0.0;
    let mut has_data = false;

    for tick in ticks {
        if let Some((ts, price, vol)) = extract_tick(tick) {
            if ts >= bucket_end {
                // Flush current bucket
                if has_data {
                    bars.push(make_bar(bucket_start, open, high, low, close, volume));
                }
                // Start new bucket
                while ts >= bucket_end {
                    bucket_start = bucket_end;
                    bucket_end += period_secs;
                }
                open = price;
                high = price;
                low = price;
                close = price;
                volume = vol;
                has_data = true;
            } else {
                if !has_data { open = price; }
                high = high.max(price);
                low = low.min(price);
                close = price;
                volume += vol;
                has_data = true;
            }
        }
    }
    if has_data {
        bars.push(make_bar(bucket_start, open, high, low, close, volume));
    }
    bars
}

pub fn resample(bars: &[Value], period_secs: i64) -> Vec<Value> {
    let mut result = Vec::new();
    if bars.is_empty() { return result; }

    let mut bucket_start = 0i64;
    let mut bucket_end = 0i64;
    let mut open = 0.0;
    let mut high = f64::NEG_INFINITY;
    let mut low = f64::INFINITY;
    let mut close = 0.0;
    let mut volume = 0.0;
    let mut has_data = false;

    for bar in bars {
        if let Some((ts, o, h, l, c, v)) = extract_bar(bar) {
            if bucket_start == 0 { bucket_start = (ts / period_secs) * period_secs; bucket_end = bucket_start + period_secs; }

            if ts >= bucket_end {
                if has_data {
                    result.push(make_bar(bucket_start, open, high, low, close, volume));
                }
                while ts >= bucket_end {
                    bucket_start = bucket_end;
                    bucket_end += period_secs;
                }
                open = o;
                high = h;
                low = l;
                close = c;
                volume = v;
                has_data = true;
            } else {
                if !has_data { open = o; }
                high = high.max(h);
                low = low.min(l);
                close = c;
                volume += v;
                has_data = true;
            }
        }
    }
    if has_data {
        result.push(make_bar(bucket_start, open, high, low, close, volume));
    }
    result
}

fn make_bar(ts: i64, open: f64, high: f64, low: f64, close: f64, volume: f64) -> Value {
    Value::Struct {
        name: "Bar".into(),
        fields: vec![
            ("timestamp".into(), Value::Int(ts as i128)),
            ("open".into(), Value::Float(open)),
            ("high".into(), Value::Float(high)),
            ("low".into(), Value::Float(low)),
            ("close".into(), Value::Float(close)),
            ("volume".into(), Value::Float(volume)),
        ],
    }
}

pub fn to_array(bars: &[Value], field: &str) -> Vec<f64> {
    bars.iter().filter_map(|bar| {
        match bar {
            Value::Struct { fields, .. } => field_f64(fields, field),
            _ => None,
        }
    }).collect()
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "from_ticks" => Some(ohlcv_from_ticks(args)),
        "resample" => Some(ohlcv_resample(args)),
        "to_array" => Some(ohlcv_to_array(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "from_ticks" | "resample" | "to_array")
}

fn ohlcv_from_ticks(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("OHLCV.from_ticks: requires (ticks)".into());
    }
    let ticks = match &args[0] {
        Value::Array(a) => a.clone(),
        _ => return Err("OHLCV.from_ticks: requires array of ticks".into()),
    };
    let period = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as i64) } else { None }).unwrap_or(60);
    Ok(Value::Array(from_ticks(&ticks, period)))
}

fn ohlcv_resample(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("OHLCV.resample: requires (bars)".into());
    }
    let bars = match &args[0] {
        Value::Array(a) => a.clone(),
        _ => return Err("OHLCV.resample: requires array of bars".into()),
    };
    let period = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as i64) } else { None }).unwrap_or(3600);
    Ok(Value::Array(resample(&bars, period)))
}

fn ohlcv_to_array(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("OHLCV.to_array: requires (bars)".into());
    }
    let bars = match &args[0] {
        Value::Array(a) => a.clone(),
        _ => return Err("OHLCV.to_array: requires array of bars".into()),
    };
    let field = args.get(1).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("close");
    let values: Vec<Value> = to_array(&bars, field).into_iter().map(Value::Float).collect();
    Ok(Value::Array(values))
}

fn field_i64(fields: &[(String, Value)], name: &str) -> Option<i64> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::Int(i) = v { Some(*i as i64) } else { None })
}

fn field_f64(fields: &[(String, Value)], name: &str) -> Option<f64> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| match v {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        })
}
