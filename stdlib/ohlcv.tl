/// OHLCV aggregation: ticks to bars, resampling, field extraction.
module tallow.ohlcv

/// Convert ticks to OHLCV bars at periodic intervals
native fn from_ticks(ticks: [{timestamp: Int, price: Float, volume: Float}], period_secs: Int) -> [Bar]
/// Resample bars to a new timeframe
native fn resample(bars: [Bar], period_secs: Int) -> [Bar]
/// Extract a single field (open, high, low, close, volume) as flat array
native fn to_array(bars: [Bar], field: String) -> [Float]
