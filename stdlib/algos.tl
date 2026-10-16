/// Algorithmic trading strategies and execution.
module tallow.algos

/// Avellaneda-Stoikov optimal market making
native fn avellaneda_stoikov(S: Float, sigma: Float, gamma: Float, k: Float, T: Float, q: Float) -> ASQuote
/// Cointegration-based pairs trading signal
native fn pairs_trading(spread: [Float], entry_z: Float, exit_z: Float) -> PairSignal
/// Time-series momentum signals
native fn momentum(prices: [Float], lookback: Int) -> [Float]
/// Cross-sectional momentum weights
native fn cross_sectional(returns: [[Float]], lookback: Int) -> [Float]
/// TWAP execution schedule
native fn twap(quantity: Float, duration_secs: Float, slices: Int) -> [TWAPSlice]
/// VWAP volume profile
native fn vwap_profile(volume_curve: [Float]) -> [Float]
/// Simple backtest engine
native fn backtest(prices: [Float], signals: [Float]) -> BacktestResult

struct ASQuote {
    reservation_price: Float,
    bid: Float,
    ask: Float,
    spread: Float,
    inventory: Float,
}

struct PairSignal {
    signal: String,
    z_score: Float,
    mean: Float,
    std: Float,
}

struct TWAPSlice {
    time: Float,
    quantity: Float,
    cumulative: Float,
}

struct BacktestResult {
    total_return: Float,
    sharpe_ratio: Float,
    max_drawdown: Float,
    volatility: Float,
    trades: Int,
    equity_curve: [Float],
}
