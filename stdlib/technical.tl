/// Technical analysis indicators for financial time series.
module tallow.technical

/// Simple Moving Average
native fn sma(prices: [Float], period: Int) -> [Float]
/// Exponential Moving Average
native fn ema(prices: [Float], period: Int) -> [Float]
/// Relative Strength Index
native fn rsi(prices: [Float], period: Int) -> Float
/// MACD: returns (macd_line, signal_line, histogram)
native fn macd(prices: [Float], fast: Int, slow: Int, signal: Int) -> {Float, Float, Float}
/// Bollinger Bands: returns (middle, upper, lower)
native fn bollinger(prices: [Float], period: Int, std_dev: Float) -> {Float, Float, Float}
/// Average True Range
native fn atr(high: [Float], low: [Float], close: [Float], period: Int) -> Float
/// On-Balance Volume
native fn obv(close: [Float], volume: [Float]) -> [Float]
/// Stochastic Oscillator
native fn stochastic(close: [Float], high: [Float], low: [Float], period: Int) -> Float
