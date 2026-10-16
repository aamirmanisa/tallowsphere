/// Black-Scholes-Merton options pricing and Greeks.
module tallow.options

/// European option price via Black-Scholes
native fn black_scholes(call_put: String, S: Float, K: Float, T: Float, r: Float, sigma: Float) -> Float
/// All first-order Greeks: delta, gamma, vega, theta, rho + price + ITM probability
native fn greeks(call_put: String, S: Float, K: Float, T: Float, r: Float, sigma: Float) -> GreeksResult
/// Implied volatility via Newton-Raphson solver
native fn implied_volatility(call_put: String, market_price: Float, S: Float, K: Float, T: Float, r: Float) -> Float
/// American option pricing via binomial tree
native fn binomial_tree(call_put: String, S: Float, K: Float, T: Float, r: Float, sigma: Float, steps: Int) -> Float
/// Put-Call Parity check
native fn put_call_parity(call_price: Float, put_price: Float, S: Float, K: Float, T: Float, r: Float) -> ParityCheck

struct GreeksResult {
    delta: Float,
    gamma: Float,
    vega: Float,
    theta: Float,
    rho: Float,
    price: Float,
    itm_prob: Float,
}

struct ParityCheck {
    call_plus_pv_strike: Float,
    put_plus_spot: Float,
    difference: Float,
    holds: Bool,
}
