/// Heston stochastic volatility model for options pricing.
///
/// Registered + dispatched (FIX13, 2026-08-27): src/stdlib/heston.rs now
/// compiles (num_complex dependency added) and routes
/// price / calibrate / implied_vol.
module tallow.heston

/// Heston European option price via Carr-Madan integration
native fn price(call_put: String, S: Float, K: Float, T: Float, r: Float, kappa: Float, theta: Float, sigma: Float, v0: Float, rho: Float) -> Float
/// Grid-search calibration of Heston parameters
native fn calibrate(call_put: String, market_prices: [Float], strikes: [Float], S: Float, T: Float, r: Float) -> HestonParams
/// Implied volatility surface point from Heston
native fn implied_vol(call_put: String, market_price: Float, S: Float, K: Float, T: Float, r: Float, kappa: Float, theta: Float, sigma: Float, v0: Float, rho: Float) -> Float

struct HestonParams {
    kappa: Float,
    theta: Float,
    sigma: Float,
    v0: Float,
    rho: Float,
    mse: Float,
}
