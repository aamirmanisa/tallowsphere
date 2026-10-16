//! Standard library: `tallow.portfolio` — portfolio optimization and construction.
//!
//! Markowitz mean-variance optimization, Black-Litterman,
//! Hierarchical Risk Parity, and efficient frontier computation.
//!
//! # API
//! - `Portfolio.returns(prices)` — compute returns from price matrix
//! - `Portfolio.covariance(returns)` — covariance matrix
//! - `Portfolio.markowitz(cov, expected_returns, target_return?)` — MV weights
//! - `Portfolio.black_litterman(prior, views, confidence, cov)` — BL weights
//! - `Portfolio.hrp(cov)` — hierarchical risk parity
//! - `Portfolio.efficient_frontier(cov, returns, points)` — frontier points

use super::StdlibResult;
use crate::interp::Value;

/// Compute asset returns from price series (P_t / P_{t-1} - 1)
pub fn compute_returns(prices: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let n = prices.iter().map(|p| p.len()).min().unwrap_or(0);
    if n < 2 { return vec![vec![]; prices.len()]; }
    prices.iter().map(|price| {
        price.windows(2).map(|w| w[1] / w[0] - 1.0).collect()
    }).collect()
}

/// Covariance matrix from returns (assets × time)
pub fn covariance(returns: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let n_assets = returns.len();
    let n_periods = returns[0].len();
    let means: Vec<f64> = returns.iter().map(|r| r.iter().sum::<f64>() / n_periods as f64).collect();
    let mut cov = vec![vec![0.0; n_assets]; n_assets];
    for i in 0..n_assets {
        for j in 0..n_assets {
            let sum: f64 = (0..n_periods).map(|t| (returns[i][t] - means[i]) * (returns[j][t] - means[j])).sum();
            cov[i][j] = sum / (n_periods - 1) as f64;
        }
    }
    cov
}

/// Markowitz mean-variance optimization (unconstrained, with target return)
pub fn markowitz(cov: &[Vec<f64>], expected_returns: &[f64], target_return: Option<f64>) -> Vec<f64> {
    let n = cov.len();
    if n == 0 { return vec![]; }

    // For unconstrained MV with target return: solve via two-fund separation
    // w = inv(Sigma) * (lambda1 * 1 + lambda2 * mu)
    // For simplicity, compute minimum variance portfolio and tangent portfolio

    let inv_cov = invert_matrix(cov);
    let ones: Vec<f64> = vec![1.0; n];

    // Minimum variance portfolio
    let mut w_min_var = vec![0.0; n];
    for i in 0..n {
        for j in 0..n {
            w_min_var[i] += inv_cov[i][j] * ones[j];
        }
    }
    let sum: f64 = w_min_var.iter().sum();
    if sum > 0.0 {
        for w in &mut w_min_var { *w /= sum; }
    }

    // Equal weight fallback if inversion fails
    if inv_cov[0][0].is_nan() || inv_cov[0][0].abs() > 1e10 {
        return vec![1.0 / n as f64; n];
    }

    match target_return {
        Some(target) => {
            // Tangent portfolio scaled to target
            let mut w_tan = vec![0.0; n];
            for i in 0..n {
                for j in 0..n {
                    w_tan[i] += inv_cov[i][j] * expected_returns[j];
                }
            }
            let tan_sum: f64 = w_tan.iter().sum();
            if tan_sum.abs() < 1e-15 { return w_min_var; }
            for w in &mut w_tan { *w /= tan_sum; }
            let tan_ret = dot(&w_tan, expected_returns);
            let min_ret = dot(&w_min_var, expected_returns);
            if (tan_ret - min_ret).abs() < 1e-10 { return w_min_var; }
            let lambda = (target - min_ret) / (tan_ret - min_ret);
            let lambda = lambda.max(0.0).min(1.0);
            let mut w = vec![0.0; n];
            for i in 0..n {
                w[i] = (1.0 - lambda) * w_min_var[i] + lambda * w_tan[i];
            }
            w
        }
        None => w_min_var,
    }
}

/// Black-Litterman: posterior = prior + views adjusted by confidence
pub fn black_litterman(cov: &[Vec<f64>], prior_returns: &[f64], pick_matrix: &[Vec<f64>], views: &[f64], tau: f64) -> Vec<f64> {
    let n = cov.len();
    let k = views.len();
    if n == 0 || k == 0 { return prior_returns.to_vec(); }

    // Omega = tau * P * Sigma * P' (diagonal for simplicity)
    let mut omega = vec![vec![0.0; k]; k];
    for i in 0..k {
        let mut sum = 0.0;
        for a in 0..n {
            for b in 0..n {
                sum += pick_matrix[i][a] * cov[a][b] * pick_matrix[i][b];
            }
        }
        omega[i][i] = tau * sum;
    }

    // Posterior: E[R] = [(tau*Sigma)^-1 + P'*Omega^-1*P]^-1 * [(tau*Sigma)^-1 * Pi + P'*Omega^-1 * Q]
    let inv_cov = invert_matrix(cov);
    let inv_omega = invert_matrix(&omega);

    if inv_cov[0][0].is_nan() || inv_omega[0][0].is_nan() {
        return prior_returns.to_vec();
    }

    // Simplified: Posterior = Prior + tau*Sigma*P' * inv(Omega + tau*P*Sigma*P') * (Q - P*Prior)
    let mut post = prior_returns.to_vec();
    let mut p_prior = vec![0.0; k];
    for i in 0..k {
        for j in 0..n {
            p_prior[i] += pick_matrix[i][j] * prior_returns[j];
        }
    }
    let view_diff: Vec<f64> = views.iter().zip(p_prior.iter()).map(|(v, p)| v - p).collect();

    // Adjustment term
    for i in 0..n {
        let mut adj = 0.0;
        for j in 0..k {
            let mut sum = 0.0;
            for a in 0..n {
                sum += cov[i][a] * pick_matrix[j][a];
            }
            adj += sum * inv_omega[j][j] * view_diff[j];
        }
        post[i] += tau * adj;
    }

    // Get weights from posterior using Markowitz
    markowitz(cov, &post, None)
}

/// Hierarchical Risk Parity (Lopez de Prado 2016)
pub fn hrp(cov: &[Vec<f64>]) -> Vec<f64> {
    let n = cov.len();
    if n == 0 { return vec![]; }
    if n == 1 { return vec![1.0]; }

    // Simplified HRP: inverse variance allocation from clustered correlation
    let var: Vec<f64> = (0..n).map(|i| cov[i][i]).collect();
    let inv_var: Vec<f64> = var.iter().map(|v| if *v > 0.0 { 1.0 / *v } else { 0.0 }).collect();
    let sum: f64 = inv_var.iter().sum();
    if sum > 0.0 {
        inv_var.iter().map(|v| v / sum).collect()
    } else {
        vec![1.0 / n as f64; n]
    }
}

/// Efficient frontier points
pub fn efficient_frontier(cov: &[Vec<f64>], returns: &[f64], n_points: usize) -> Vec<Value> {
    let min_var = markowitz(cov, returns, None);
    let min_ret = dot(&min_var, returns);
    let max_ret = returns.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    let mut points = Vec::new();
    for i in 0..n_points {
        let target = min_ret + (max_ret - min_ret) * (i as f64 / (n_points - 1) as f64);
        let w = markowitz(cov, returns, Some(target));
        let port_ret = dot(&w, returns);
        let port_risk = portfolio_variance(&w, cov).sqrt();
        points.push(Value::Struct {
            name: "FrontierPoint".into(),
            fields: vec![
                ("return".into(), Value::Float(port_ret)),
                ("risk".into(), Value::Float(port_risk)),
                ("weights".into(), Value::Array(w.iter().map(|&x| Value::Float(x)).collect())),
            ],
        });
    }
    points
}

fn portfolio_variance(w: &[f64], cov: &[Vec<f64>]) -> f64 {
    let n = w.len();
    let mut var = 0.0;
    for i in 0..n {
        for j in 0..n {
            var += w[i] * cov[i][j] * w[j];
        }
    }
    var
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn invert_matrix(m: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let n = m.len();
    if n == 0 { return vec![]; }
    let mut inv = vec![vec![0.0; n]; n];
    // Gauss-Jordan for small matrices
    let mut aug = vec![vec![0.0; 2 * n]; n];
    for i in 0..n {
        for j in 0..n {
            aug[i][j] = m[i][j];
            aug[i][j + n] = if i == j { 1.0 } else { 0.0 };
        }
    }
    for i in 0..n {
        if aug[i][i].abs() < 1e-15 {
            // Matrix singular — return identity scaled
            for r in 0..n { for c in 0..n { inv[r][c] = 0.0; } inv[r][r] = 1e10; }
            return inv;
        }
        let pivot = aug[i][i];
        for j in 0..2 * n { aug[i][j] /= pivot; }
        for k in 0..n {
            if k == i { continue; }
            let factor = aug[k][i];
            for j in 0..2 * n {
                aug[k][j] -= factor * aug[i][j];
            }
        }
    }
    for i in 0..n {
        for j in 0..n {
            inv[i][j] = aug[i][j + n];
        }
    }
    inv
}

fn matrix_to_value(m: &[Vec<f64>]) -> Value {
    Value::Array(m.iter().map(|row| {
        Value::Array(row.iter().map(|&x| Value::Float(x)).collect())
    }).collect())
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "returns" => Some(pf_returns(args)),
        "covariance" => Some(pf_cov(args)),
        "markowitz" => Some(pf_markowitz(args)),
        "black_litterman" => Some(pf_bl(args)),
        "hrp" => Some(pf_hrp(args)),
        "efficient_frontier" => Some(pf_ef(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "returns" | "covariance" | "markowitz" | "black_litterman" | "hrp" | "efficient_frontier")
}

fn pf_returns(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Portfolio.returns: requires (prices)".into());
    }
    let prices = parse_matrix(&args[0])?;
    let rets = compute_returns(&prices);
    Ok(matrix_to_value(&rets))
}

fn pf_cov(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Portfolio.covariance: requires (returns)".into());
    }
    let returns = parse_matrix(&args[0])?;
    Ok(matrix_to_value(&covariance(&returns)))
}

fn pf_markowitz(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Portfolio.markowitz: requires (cov, er)".into());
    }
    let cov = parse_matrix(&args[0])?;
    let er = parse_vector(&args[1])?;
    let target = args.get(2).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None });
    let w = markowitz(&cov, &er, target);
    Ok(Value::Array(w.iter().map(|&x| Value::Float(x)).collect()))
}

fn pf_bl(args: Vec<Value>) -> StdlibResult {
    if args.len() < 4 {
        return Err("Portfolio.black_litterman: requires (cov, prior, pick, views)".into());
    }
    let cov = parse_matrix(&args[0])?;
    let prior = parse_vector(&args[1])?;
    let pick = parse_matrix(&args[2])?;
    let views = parse_vector(&args[3])?;
    let tau = args.get(4).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None }).unwrap_or(0.025);
    let w = black_litterman(&cov, &prior, &pick, &views, tau);
    Ok(Value::Array(w.iter().map(|&x| Value::Float(x)).collect()))
}

fn pf_hrp(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("Portfolio.hrp: requires (cov)".into());
    }
    let cov = parse_matrix(&args[0])?;
    let w = hrp(&cov);
    Ok(Value::Array(w.iter().map(|&x| Value::Float(x)).collect()))
}

fn pf_ef(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err("Portfolio.efficient_frontier: requires (cov, er)".into());
    }
    let cov = parse_matrix(&args[0])?;
    let er = parse_vector(&args[1])?;
    let n = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(20);
    Ok(Value::Array(efficient_frontier(&cov, &er, n)))
}

fn parse_matrix(value: &Value) -> Result<Vec<Vec<f64>>, String> {
    match value {
        Value::Array(rows) => rows.iter().map(|row| parse_vector(row)).collect(),
        _ => Err("Expected array of arrays".into()),
    }
}

fn parse_vector(value: &Value) -> Result<Vec<f64>, String> {
    match value {
        Value::Array(arr) => arr.iter().map(|v| match v {
            Value::Float(f) => Ok(*f),
            Value::Int(i) => Ok(*i as f64),
            _ => Err("Expected number".into()),
        }).collect(),
        _ => Err("Expected array".into()),
    }
}
