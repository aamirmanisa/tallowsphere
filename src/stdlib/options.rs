//! Standard library: `tallow.options` — options pricing and Greeks.
//!
//! Black-Scholes-Merton pricing for European options, plus all
//! first-order Greeks (delta, gamma, vega, theta, rho) computed
//! analytically. Binomial tree for American options.
//!
//! # API
//! - `Options.black_scholes(call_put, S, K, T, r, sigma)` — European pricing
//! - `Options.greeks(call_put, S, K, T, r, sigma)` — all Greeks
//! - `Options.implied_volatility(call_put, market_price, S, K, T, r)` — Newton solver
//! - `Options.binomial_tree(call_put, S, K, T, r, sigma, steps)` — American options
//! - `Options.put_call_parity(call_price, put_price, S, K, T, r)` — parity check

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::f64::consts::{PI};

/// Standard normal CDF using Abramowitz & Stegun approximation
fn norm_cdf(x: f64) -> f64 {
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t) * (-x * x / 2.0).exp();
    0.5 * (1.0 + sign * y)
}

fn norm_pdf(x: f64) -> f64 {
    (-x * x / 2.0).exp() / (2.0 * PI).sqrt()
}

fn d1_d2(s: f64, k: f64, t: f64, r: f64, sigma: f64) -> (f64, f64) {
    if t <= 0.0 { return (f64::NAN, f64::NAN); }
    let d1 = ((s / k).ln() + (r + sigma * sigma / 2.0) * t) / (sigma * t.sqrt());
    let d2 = d1 - sigma * t.sqrt();
    (d1, d2)
}

// ── Black-Scholes European Pricing ──
fn black_scholes_price(call_put: &str, s: f64, k: f64, t: f64, r: f64, sigma: f64) -> f64 {
    if t <= 0.0 {
        // At expiry
        let intrinsic = match call_put {
            "call" => (s - k).max(0.0),
            "put" => (k - s).max(0.0),
            _ => 0.0,
        };
        return intrinsic;
    }
    let (d1, d2) = d1_d2(s, k, t, r, sigma);
    if d1.is_nan() { return 0.0; }
    match call_put {
        "call" => s * norm_cdf(d1) - k * (-r * t).exp() * norm_cdf(d2),
        "put" => k * (-r * t).exp() * norm_cdf(-d2) - s * norm_cdf(-d1),
        _ => 0.0,
    }
}

// ── Greeks ──
fn compute_greeks(call_put: &str, s: f64, k: f64, t: f64, r: f64, sigma: f64) -> Value {
    if t <= 0.0 {
        return Value::Struct {
            name: "Greeks".into(),
            fields: vec![
                ("delta".into(), Value::Float(match call_put { "call" => if s > k { 1.0 } else { 0.0 }, _ => if k > s { -1.0 } else { 0.0 } })),
                ("gamma".into(), Value::Float(0.0)),
                ("vega".into(), Value::Float(0.0)),
                ("theta".into(), Value::Float(0.0)),
                ("rho".into(), Value::Float(0.0)),
                ("price".into(), Value::Float(black_scholes_price(call_put, s, k, t, r, sigma))),
                ("itm_prob".into(), Value::Float(match call_put { "call" => if s > k { 1.0 } else { 0.0 }, _ => if k > s { 1.0 } else { 0.0 } })),
            ],
        };
    }
    let (d1, d2) = d1_d2(s, k, t, r, sigma);
    if d1.is_nan() { return Value::Nil; }
    let discount = (-r * t).exp();

    let delta = match call_put {
        "call" => norm_cdf(d1),
        _ => norm_cdf(d1) - 1.0,
    };

    let gamma = norm_pdf(d1) / (s * sigma * t.sqrt());
    let vega = s * norm_pdf(d1) * t.sqrt() / 100.0; // per 1% vol change

    let theta = match call_put {
        "call" => (-s * norm_pdf(d1) * sigma / (2.0 * t.sqrt()) - r * k * discount * norm_cdf(d2)) / 365.0,
        _ => (-s * norm_pdf(d1) * sigma / (2.0 * t.sqrt()) + r * k * discount * norm_cdf(-d2)) / 365.0,
    };

    let rho = match call_put {
        "call" => k * t * discount * norm_cdf(d2) / 100.0,
        _ => -k * t * discount * norm_cdf(-d2) / 100.0,
    };

    let price = black_scholes_price(call_put, s, k, t, r, sigma);
    let itm_prob = match call_put {
        "call" => norm_cdf(d2),
        _ => norm_cdf(-d2),
    };

    Value::Struct {
        name: "Greeks".into(),
        fields: vec![
            ("delta".into(), Value::Float(delta)),
            ("gamma".into(), Value::Float(gamma)),
            ("vega".into(), Value::Float(vega)),
            ("theta".into(), Value::Float(theta)),
            ("rho".into(), Value::Float(rho)),
            ("price".into(), Value::Float(price)),
            ("itm_prob".into(), Value::Float(itm_prob)),
        ],
    }
}

// ── Implied Volatility (Newton-Raphson) ──
fn implied_vol(call_put: &str, market_price: f64, s: f64, k: f64, t: f64, r: f64) -> f64 {
    let mut sigma = 0.3; // initial guess
    for _ in 0..100 {
        let price = black_scholes_price(call_put, s, k, t, r, sigma);
        let (d1, _) = d1_d2(s, k, t, r, sigma);
        if d1.is_nan() { return f64::NAN; }
        let vega = s * norm_pdf(d1) * t.sqrt(); // raw vega (not per 1%)
        if vega.abs() < 1e-15 { break; }
        let diff = price - market_price;
        sigma -= diff / vega;
        if diff.abs() < 1e-8 { break; }
        if sigma <= 0.0 { sigma = 0.001; }
        if sigma > 10.0 { return f64::NAN; }
    }
    sigma
}

// ── Binomial Tree (Cox-Ross-Rubinstein) for American Options ──
fn binomial_tree(call_put: &str, s: f64, k: f64, t: f64, r: f64, sigma: f64, steps: usize) -> f64 {
    let dt = t / steps as f64;
    let u = (sigma * dt.sqrt()).exp();
    let d = 1.0 / u;
    let p = ((r * dt).exp() - d) / (u - d);
    let discount = (-r * dt).exp();

    let mut prices = vec![0.0; steps + 1];
    // Terminal payoffs
    for i in 0..=steps {
        let spot = s * u.powi(steps as i32 - 2 * i as i32);
        prices[i] = match call_put {
            "call" => (spot - k).max(0.0),
            "put" => (k - spot).max(0.0),
            _ => 0.0,
        };
    }

    // Backward induction
    for j in (0..steps).rev() {
        for i in 0..=j {
            let spot = s * u.powi(j as i32 - 2 * i as i32);
            let hold = discount * (p * prices[i] + (1.0 - p) * prices[i + 1]);
            let exercise = match call_put {
                "call" => (spot - k).max(0.0),
                "put" => (k - spot).max(0.0),
                _ => 0.0,
            };
            prices[i] = hold.max(exercise);
        }
    }
    prices[0]
}

// ── Put-Call Parity ──
fn put_call_parity(call_price: f64, put_price: f64, s: f64, k: f64, t: f64, r: f64) -> Value {
    let lhs = call_price + k * (-r * t).exp();
    let rhs = put_price + s;
    let diff = lhs - rhs;
    Value::Struct {
        name: "ParityCheck".into(),
        fields: vec![
            ("call_plus_pv_strike".into(), Value::Float(lhs)),
            ("put_plus_spot".into(), Value::Float(rhs)),
            ("difference".into(), Value::Float(diff)),
            ("holds".into(), Value::Bool(diff.abs() < 0.01)),
        ],
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "black_scholes" => Some(op_bs(args)),
        "greeks" => Some(op_greeks(args)),
        "implied_volatility" => Some(op_iv(args)),
        "binomial_tree" => Some(op_binomial(args)),
        "put_call_parity" => Some(op_parity(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "black_scholes" | "greeks" | "implied_volatility" | "binomial_tree" | "put_call_parity")
}

fn get_f64(args: &[Value], idx: usize, name: &str) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        Some(other) => Err(format!("{name}: expected number, got {}", type_name(other))),
        None => Err(format!("{name}: missing argument")),
    }
}

fn get_str(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!("{name}: expected string, got {}", type_name(other))),
        None => Err(format!("{name}: missing argument")),
    }
}

fn bs_args(args: &[Value]) -> Result<(String, f64, f64, f64, f64, f64), String> {
    let cp = get_str(args, 0, "call_put")?;
    let s = get_f64(args, 1, "S")?;
    let k = get_f64(args, 2, "K")?;
    let t = get_f64(args, 3, "T")?;
    let r = get_f64(args, 4, "r")?;
    let sigma = get_f64(args, 5, "sigma")?;
    Ok((cp, s, k, t, r, sigma))
}

fn op_bs(args: Vec<Value>) -> StdlibResult {
    let (cp, s, k, t, r, sigma) = bs_args(&args)?;
    Ok(Value::Float(black_scholes_price(&cp, s, k, t, r, sigma)))
}

fn op_greeks(args: Vec<Value>) -> StdlibResult {
    let (cp, s, k, t, r, sigma) = bs_args(&args)?;
    Ok(compute_greeks(&cp, s, k, t, r, sigma))
}

fn op_iv(args: Vec<Value>) -> StdlibResult {
    if args.len() < 6 {
        return Err("Options.implied_volatility: requires (call_put, market_price, S, K, T, r)".into());
    }
    let cp = get_str(&args, 0, "call_put")?;
    let market = get_f64(&args, 1, "market_price")?;
    let s = get_f64(&args, 2, "S")?;
    let k = get_f64(&args, 3, "K")?;
    let t = get_f64(&args, 4, "T")?;
    let r = get_f64(&args, 5, "r")?;
    let iv = implied_vol(&cp, market, s, k, t, r);
    if iv.is_nan() {
        Err("Implied volatility did not converge".into())
    } else {
        Ok(Value::Float(iv))
    }
}

fn op_binomial(args: Vec<Value>) -> StdlibResult {
    let (cp, s, k, t, r, sigma) = bs_args(&args)?;
    let steps = args.get(6).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(100);
    Ok(Value::Float(binomial_tree(&cp, s, k, t, r, sigma, steps)))
}

fn op_parity(args: Vec<Value>) -> StdlibResult {
    if args.len() < 6 {
        return Err("Options.put_call_parity: requires (call_price, put_price, S, K, T, r)".into());
    }
    let call = get_f64(&args, 0, "call_price")?;
    let put = get_f64(&args, 1, "put_price")?;
    let s = get_f64(&args, 2, "S")?;
    let k = get_f64(&args, 3, "K")?;
    let t = get_f64(&args, 4, "T")?;
    let r = get_f64(&args, 5, "r")?;
    Ok(put_call_parity(call, put, s, k, t, r))
}
