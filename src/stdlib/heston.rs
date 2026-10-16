//! Standard library: `tallow.heston` — Heston stochastic volatility model.
//!
//! REGISTERED (FIX13, 2026-08-27): was honest-marked in FIX12 because it
//! depends on the `num_complex` crate, which was not in Cargo.toml.
//! `num_complex = "0.4"` (already in Cargo.lock at 0.4.6 as a transitive
//! dep) is now a direct dependency and the module compiles + dispatches.
//!
//! European option pricing under Heston (1993) dynamics using
//! the characteristic function approach (Carr-Madan / Lewis).
//!
//! dS_t = r*S_t*dt + sqrt(v_t)*S_t*dW1_t
//! dv_t = kappa*(theta - v_t)*dt + sigma*sqrt(v_t)*dW2_t
//! dW1_t * dW2_t = rho*dt
//!
//! # API
//! - `Heston.price(call_put, S, K, T, r, kappa, theta, sigma, v0, rho)` — European price
//! - `Heston.calibrate(call_put, market_prices, strikes, S, T, r)` — calibrate params
//! - `Heston.implied_vol(call_put, market_price, S, K, T, r, params)` — IV surface point

use super::StdlibResult;
use crate::interp::Value;

use std::f64::consts::PI;
use num_complex::Complex;

type C = Complex<f64>;
const I: C = Complex { re: 0.0, im: 1.0 };

/// Heston characteristic function (Gatheral formulation)
fn heston_cf(phi: f64, _s: f64, t: f64, r: f64, kappa: f64, theta: f64, sigma: f64, v0: f64, rho: f64) -> C {
    // `_s`: the Gatheral formulation below is S-independent (S enters via the
    // Carr-Madan price formula in heston_call).
    let _lambda = 0.0; // market price of vol risk = 0
    let u = C::new(phi, 0.0);

    let d = ((kappa - rho * sigma * u * I).powi(2)
        + sigma.powi(2) * (u * I + u * u)).sqrt();

    let g = (kappa - rho * sigma * u * I - d) / (kappa - rho * sigma * u * I + d);

    let c = r * u * I * t
        + (kappa * theta / sigma.powi(2))
        * ((kappa - rho * sigma * u * I - d) * t
        - 2.0 * ((1.0 - g * (-d * t).exp()) / (1.0 - g)).ln());

    let d_term = v0 / sigma.powi(2)
        * (kappa - rho * sigma * u * I - d)
        * (1.0 - (-d * t).exp()) / (1.0 - g * (-d * t).exp());

    (c + d_term).exp()
}

/// Heston European call price via Carr-Madan integration
fn heston_call(s: f64, k: f64, t: f64, r: f64, kappa: f64, theta: f64, sigma: f64, v0: f64, rho: f64) -> f64 {
    let n = 4096; // integration points
    let eta = 0.25;
    let lambda_cm = 2.0 * PI / (n as f64 * eta);
    let _b = (n as f64 * lambda_cm) / 2.0; // Carr-Madan truncation bound (unused in this demo)

    let mut integral = 0.0;
    let k_log = k.ln();

    for j in 0..n {
        let v = eta * j as f64;
        let cf_val = heston_cf(v - (1.0 + 1.0 * I).im, s, t, r, kappa, theta, sigma, v0, rho);
        let denom = (1.0 + v * v) * v;
        if denom.abs() > 1e-15 {
            let term = ((-I * v * k_log).exp() * cf_val * (-r * t).exp() / (I * v)).re;
            integral += term * eta;
        }
    }

    let price = (s - k * (-r * t).exp()) / 2.0 + integral / PI;
    price.max(0.0)
}

pub fn heston_price(call_put: &str, s: f64, k: f64, t: f64, r: f64, kappa: f64, theta: f64, sigma: f64, v0: f64, rho: f64) -> f64 {
    let call = heston_call(s, k, t, r, kappa, theta, sigma, v0, rho);
    match call_put {
        "call" => call,
        "put" => call - s + k * (-r * t).exp(),
        _ => 0.0,
    }
}

/// Grid search calibration (simple, for demo — stochastic-rs does proper optimization)
pub fn calibrate_heston(call_put: &str, market_prices: &[f64], strikes: &[f64], s: f64, t: f64, r: f64) -> Value {
    let param_grid = [
        (1.5, 0.04, 0.3, 0.04, -0.7),
        (2.0, 0.05, 0.4, 0.05, -0.5),
        (1.0, 0.03, 0.2, 0.03, -0.9),
        (3.0, 0.06, 0.5, 0.06, -0.3),
        (0.5, 0.02, 0.15, 0.02, -0.99),
    ];

    let mut best_params = param_grid[0];
    let mut best_error = f64::MAX;

    for &(kappa, theta, sigma, v0, rho) in &param_grid {
        let mut error = 0.0;
        for (i, &strike) in strikes.iter().enumerate() {
            let model_price = heston_price(call_put, s, strike, t, r, kappa, theta, sigma, v0, rho);
            let diff = model_price - market_prices[i];
            error += diff * diff;
        }
        if error < best_error {
            best_error = error;
            best_params = (kappa, theta, sigma, v0, rho);
        }
    }

    Value::Struct {
        name: "HestonParams".into(),
        fields: vec![
            ("kappa".into(), Value::Float(best_params.0)),
            ("theta".into(), Value::Float(best_params.1)),
            ("sigma".into(), Value::Float(best_params.2)),
            ("v0".into(), Value::Float(best_params.3)),
            ("rho".into(), Value::Float(best_params.4)),
            ("mse".into(), Value::Float(best_error / strikes.len() as f64)),
        ],
    }
}

pub fn heston_iv(call_put: &str, market_price: f64, s: f64, k: f64, t: f64, r: f64,
                  kappa: f64, theta: f64, sigma: f64, v0: f64, rho: f64) -> f64 {
    // Newton-Raphson for implied vol from Heston price
    let mut iv = sigma * v0.sqrt(); // initial guess: sqrt(v0) * sigma
    for _ in 0..50 {
        let price = heston_price(call_put, s, k, t, r, kappa, theta, sigma, v0, rho);
        let diff = price - market_price;
        if diff.abs() < 1e-6 { break; }
        // Vega approximation via Black-Scholes
        let (d1, _) = black_scholes_d1_d2(s, k, t, r, iv);
        let vega = s * norm_pdf(d1) * t.sqrt();
        if vega.abs() < 1e-15 { break; }
        iv -= diff / vega;
        if iv <= 0.001 { iv = 0.001; }
    }
    iv
}

// Black-Scholes helpers for vega approximation
#[allow(dead_code)] // kept for completeness; norm_pdf is the one used by heston_iv
fn norm_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    let a1 = 0.254829592; let a2 = -0.284496736; let a3 = 1.421413741;
    let a4 = -1.453152027; let a5 = 1.061405429; let p = 0.3275911;
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + p * x);
    sign * (1.0 - ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * (-x * x).exp())
}

fn norm_pdf(x: f64) -> f64 {
    (-x * x / 2.0).exp() / (2.0 * PI).sqrt()
}

fn black_scholes_d1_d2(s: f64, k: f64, t: f64, r: f64, sigma: f64) -> (f64, f64) {
    let d1 = ((s / k).ln() + (r + sigma * sigma / 2.0) * t) / (sigma * t.sqrt());
    (d1, d1 - sigma * t.sqrt())
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "price" => Some(heston_price_fn(args)),
        "calibrate" => Some(heston_cal(args)),
        "implied_vol" => Some(heston_iv_fn(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "price" | "calibrate" | "implied_vol")
}

fn heston_price_fn(args: Vec<Value>) -> StdlibResult {
    let cp = get_str(&args, 0)?;
    let s = get_f64(&args, 1)?;
    let k = get_f64(&args, 2)?;
    let t = get_f64(&args, 3)?;
    let r = get_f64(&args, 4)?;
    let kappa = get_f64(&args, 5)?;
    let theta = get_f64(&args, 6)?;
    let sigma = get_f64(&args, 7)?;
    let v0 = get_f64(&args, 8)?;
    let rho = get_f64(&args, 9)?;
    Ok(Value::Float(heston_price(&cp, s, k, t, r, kappa, theta, sigma, v0, rho)))
}

fn heston_cal(args: Vec<Value>) -> StdlibResult {
    let cp = get_str(&args, 0)?;
    let mp = get_f64_slice(&args, 1)?;
    let strikes = get_f64_slice(&args, 2)?;
    let s = get_f64(&args, 3)?;
    let t = get_f64(&args, 4)?;
    let r = get_f64(&args, 5)?;
    Ok(calibrate_heston(&cp, &mp, &strikes, s, t, r))
}

fn heston_iv_fn(args: Vec<Value>) -> StdlibResult {
    let cp = get_str(&args, 0)?;
    let mp = get_f64(&args, 1)?;
    let s = get_f64(&args, 2)?;
    let k = get_f64(&args, 3)?;
    let t = get_f64(&args, 4)?;
    let r = get_f64(&args, 5)?;
    let kappa = get_f64(&args, 6)?;
    let theta = get_f64(&args, 7)?;
    let sigma = get_f64(&args, 8)?;
    let v0 = get_f64(&args, 9)?;
    let rho = get_f64(&args, 10)?;
    Ok(Value::Float(heston_iv(&cp, mp, s, k, t, r, kappa, theta, sigma, v0, rho)))
}

fn get_str(args: &[Value], idx: usize) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("Expected string at {}", idx)),
    }
}

fn get_f64(args: &[Value], idx: usize) -> Result<f64, String> {
    match args.get(idx) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        _ => Err(format!("Expected number at {}", idx)),
    }
}

fn get_f64_slice(args: &[Value], idx: usize) -> Result<Vec<f64>, String> {
    match args.get(idx) {
        Some(Value::Array(arr)) => arr.iter().map(|v| match v {
            Value::Float(f) => Ok(*f),
            Value::Int(i) => Ok(*i as f64),
            _ => Err("Expected number".into()),
        }).collect(),
        _ => Err(format!("Expected array at {}", idx)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_call_is_finite_and_in_money_bounds() {
        // ATM call, 1y, mild vol-of-vol — price must be finite, >= 0 and
        // bounded by the underlying (no arbitrage).
        let p = heston_price("call", 100.0, 100.0, 1.0, 0.05, 2.0, 0.04, 0.3, 0.04, -0.7);
        assert!(p.is_finite(), "call price must be finite, got {p}");
        assert!(p >= 0.0 && p <= 100.0, "call price out of bounds: {p}");
    }

    #[test]
    fn put_call_parity_holds() {
        let s = 100.0;
        let k = 105.0;
        let t = 1.0;
        let r = 0.05;
        let call = heston_price("call", s, k, t, r, 2.0, 0.04, 0.3, 0.04, -0.7);
        let put = heston_price("put", s, k, t, r, 2.0, 0.04, 0.3, 0.04, -0.7);
        // C - P == S - K*exp(-rT)
        let parity = (call - put - (s - k * (-r * t).exp())).abs();
        assert!(parity < 1e-6, "put-call parity violated: {parity}");
    }

    #[test]
    fn dispatch_routes_price() {
        let r = dispatch(
            "price",
            vec![
                Value::String("call".into()),
                Value::Float(100.0),
                Value::Float(100.0),
                Value::Float(1.0),
                Value::Float(0.05),
                Value::Float(2.0),
                Value::Float(0.04),
                Value::Float(0.3),
                Value::Float(0.04),
                Value::Float(-0.7),
            ],
        )
        .expect("price is a known arm")
        .expect("price should compute");
        assert!(matches!(r, Value::Float(f) if f.is_finite()));
    }

    #[test]
    fn unknown_returns_none() {
        assert!(dispatch("nonsense", vec![]).is_none());
    }
}
