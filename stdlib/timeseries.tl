/// SQLite-backed time-series database for tick and bar data.
module tallow.timeseries

/// Create or open a time-series database
native fn new(path: String) -> TimeSeries

struct TimeSeries {
    path: String,
}

/// Insert a tick (timestamp, price, volume)
method insert(symbol: String, timestamp: Int, price: Float, volume: Float) -> Bool on TimeSeries
/// Insert an OHLCV bar
method insert_bar(symbol: String, timestamp: Int, open: Float, high: Float, low: Float, close: Float, volume: Float) -> Bool on TimeSeries
/// Query ticks in range
method range(symbol: String, from: Int, to: Int) -> []Tick on TimeSeries
/// Query bars in range
method bars(symbol: String, from: Int, to: Int) -> []Bar on TimeSeries
/// Latest tick for symbol
method latest(symbol: String) -> Tick on TimeSeries
/// List all symbols
method symbols() -> []String on TimeSeries

struct Tick {
    timestamp: Int,
    price: Float,
    volume: Float,
}
