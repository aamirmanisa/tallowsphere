/// SQLite-backed time-series database for tick and bar data.
module tallow.timeseries

/// Create or open a time-series database
native fn new(path: String) -> TimeSeries

struct TimeSeries {
    path: String,
}

/// Insert a tick (timestamp, price, volume)
/// Insert an OHLCV bar
/// Query ticks in range
/// Query bars in range
/// Latest tick for symbol
/// List all symbols

struct Tick {
    timestamp: Int,
    price: Float,
    volume: Float,
}


impl TimeSeries {
    native fn insert(symbol: String, timestamp: Int, price: Float, volume: Float) -> Bool
    native fn insert_bar(symbol: String, timestamp: Int, open: Float, high: Float, low: Float, close: Float, volume: Float) -> Bool
    native fn range(symbol: String, from: Int, to: Int) -> []Tick
    native fn bars(symbol: String, from: Int, to: Int) -> []Bar
    native fn latest(symbol: String) -> Tick
    native fn symbols() -> []String
}
