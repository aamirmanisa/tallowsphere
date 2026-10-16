//! Standard library: `tallow.curves` — yield curve construction and interpolation.
//!
//! Builds yield curves from market instruments, interpolates rates at
//! arbitrary maturities, and supports Nelson-Siegel/Svensson parametrization.
//!
//! # API
//! - `Curve.bootstrap(instruments)` — bootstrap zero curve from par instruments
//! - `Curve.nelson_siegel(params, tenors)` — Nelson-Siegel parametrized curve
//! - `Curve.svensson(params, tenors)` — Svensson (extended NS) parametrized curve
//! - `Curve.forward_rate(curve, T1, T2)` — compute forward rate between two dates
//! - `Curve.discount_factor(curve, T)` — get discount factor at tenor

use super::StdlibResult;
use crate::interp::Value;

/// Bootstrap zero curve from par swap/bond instruments (simplified)
pub fn bootstrap_curve(instrument_rates: &[(f64, f64)]) -> Vec<(f64, f64)> {
    // Returns (tenor, zero_rate) pairs
    let mut curve = Vec::new();

    for &(tenor, rate) in instrument_rates {
        if tenor <= 0.0 { continue; }
        // Assume annual compounding for simplicity
        let df = 1.0 / (1.0 + rate).powf(tenor);
        curve.push((tenor, -df.ln() / tenor)); // continuous zero rate
    }
    curve
}

/// Nelson-Siegel (1987) yield curve model
/// y(T) = b0 + b1 * (1-exp(-T/tau))/(T/tau) + b2 * ((1-exp(-T/tau))/(T/tau) - exp(-T/tau))
pub fn nelson_siegel(tenors: &[f64], b0: f64, b1: f64, b2: f64, tau: f64) -> Vec<(f64, f64)> {
    tenors.iter().map(|&t| {
        if t <= 0.0 {
            return (t, b0 + b1);
        }
        let x = t / tau;
        let exp_neg = (-x).exp();
        let level = b0;
        let slope = b1 * (1.0 - exp_neg) / x;
        let curvature = b2 * ((1.0 - exp_neg) / x - exp_neg);
        (t, level + slope + curvature)
    }).collect()
}

/// Svensson (1994) extended Nelson-Siegel
/// Adds a second hump with parameters b3, tau2
pub fn svensson(tenors: &[f64], b0: f64, b1: f64, b2: f64, b3: f64, tau1: f64, tau2: f64) -> Vec<(f64, f64)> {
    tenors.iter().map(|&t| {
        if t <= 0.0 {
            return (t, b0 + b1);
        }
        let x1 = t / tau1;
        let x2 = t / tau2;
        let exp1 = (-x1).exp();
        let exp2 = (-x2).exp();
        let level = b0;
        let slope = b1 * (1.0 - exp1) / x1;
        let curvature1 = b2 * ((1.0 - exp1) / x1 - exp1);
        let curvature2 = b3 * ((1.0 - exp2) / x2 - exp2);
        (t, level + slope + curvature1 + curvature2)
    }).collect()
}

/// Linear interpolation on a sorted (tenor, rate) curve
pub fn interpolate(curve: &[(f64, f64)], t: f64) -> f64 {
    if curve.is_empty() { return 0.0; }
    if t <= curve[0].0 { return curve[0].1; }
    if t >= curve.last().unwrap().0 { return curve.last().unwrap().1; }

    for i in 0..curve.len() - 1 {
        if t >= curve[i].0 && t <= curve[i + 1].0 {
            let t1 = curve[i].0;
            let t2 = curve[i + 1].0;
            let r1 = curve[i].1;
            let r2 = curve[i + 1].1;
            return r1 + (r2 - r1) * (t - t1) / (t2 - t1);
        }
    }
    curve.last().unwrap().1
}

/// Forward rate between T1 and T2 using continuous compounding
pub fn forward_rate(curve: &[(f64, f64)], t1: f64, t2: f64) -> f64 {
    if t2 <= t1 { return 0.0; }
    let r1 = interpolate(curve, t1);
    let r2 = interpolate(curve, t2);
    (r2 * t2 - r1 * t1) / (t2 - t1)
}

/// Discount factor at tenor T from continuous zero rate
pub fn discount_factor(curve: &[(f64, f64)], t: f64) -> f64 {
    (-interpolate(curve, t) * t).exp()
}

/// Convert curve to Tallow Value array
fn curve_to_value(curve: &[(f64, f64)]) -> Value {
    Value::Array(curve.iter().map(|&(t, r)| {
        Value::Struct {
            name: "CurvePoint".into(),
            fields: vec![
                ("tenor".into(), Value::Float(t)),
                ("rate".into(), Value::Float(r)),
            ],
        }
    }).collect())
}

fn parse_instruments(value: &Value) -> Result<Vec<(f64, f64)>, String> {
    match value {
        Value::Array(arr) => arr.iter().map(|v| match v {
            Value::Struct { fields, .. } => {
                let t = field_f64(fields, "tenor").unwrap_or(0.0);
                let r = field_f64(fields, "rate").unwrap_or(0.0);
                Ok((t, r))
            }
            Value::Array(a) if a.len() >= 2 => {
                let t = match &a[0] { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => 0.0 };
                let r = match &a[1] { Value::Float(f) => *f, Value::Int(i) => *i as f64, _ => 0.0 };
                Ok((t, r))
            }
            _ => Err("Invalid instrument format".into()),
        }).collect(),
        _ => Err("Expected array of instruments".into()),
    }
}

fn parse_tenors(value: &Value) -> Vec<f64> {
    match value {
        Value::Array(arr) => arr.iter().filter_map(|v| match v {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        }).collect(),
        _ => vec![0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 20.0, 30.0], // default tenors
    }
}

fn field_f64(fields: &[(String, Value)], name: &str) -> Option<f64> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| match v {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        })
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "bootstrap" => Some(curve_bootstrap(args)),
        "nelson_siegel" => Some(curve_ns(args)),
        "svensson" => Some(curve_sven(args)),
        "interpolate" => Some(curve_interp(args)),
        "forward_rate" => Some(curve_fwd(args)),
        "discount_factor" => Some(curve_df(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "bootstrap" | "nelson_siegel" | "svensson" | "interpolate" | "forward_rate" | "discount_factor")
}

fn curve_bootstrap(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Curves.bootstrap: requires (instruments)".into());
    }
    let instruments = parse_instruments(&args[0])?;
    Ok(curve_to_value(&bootstrap_curve(&instruments)))
}

fn curve_ns(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Curves.nelson_siegel: requires (tenors)".into());
    }
    let tenors = parse_tenors(&args[0]);
    let b0 = get_f64(&args, 1)?;
    let b1 = get_f64(&args, 2)?;
    let b2 = get_f64(&args, 3)?;
    let tau = get_f64(&args, 4)?;
    Ok(curve_to_value(&nelson_siegel(&tenors, b0, b1, b2, tau)))
}

fn curve_sven(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Curves.svensson: requires (tenors)".into());
    }
    let tenors = parse_tenors(&args[0]);
    let b0 = get_f64(&args, 1)?;
    let b1 = get_f64(&args, 2)?;
    let b2 = get_f64(&args, 3)?;
    let b3 = get_f64(&args, 4)?;
    let tau1 = get_f64(&args, 5)?;
    let tau2 = get_f64(&args, 6)?;
    Ok(curve_to_value(&svensson(&tenors, b0, b1, b2, b3, tau1, tau2)))
}

fn curve_interp(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Curves.interpolate: requires (curve)".into());
    }
    let curve = parse_instruments(&args[0])?;
    let t = get_f64(&args, 1)?;
    Ok(Value::Float(interpolate(&curve, t)))
}

fn curve_fwd(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Curves.forward_rate: requires (curve)".into());
    }
    let curve = parse_instruments(&args[0])?;
    let t1 = get_f64(&args, 1)?;
    let t2 = get_f64(&args, 2)?;
    Ok(Value::Float(forward_rate(&curve, t1, t2)))
}

fn curve_df(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Curves.discount_factor: requires (curve)".into());
    }
    let curve = parse_instruments(&args[0])?;
    let t = get_f64(&args, 1)?;
    Ok(Value::Float(discount_factor(&curve, t)))
}

fn get_f64(args: &[Value], idx: usize) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        _ => Err(format!("Expected number at {}", idx)),
    }
}
