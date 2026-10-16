/// Yahoo Finance market data: quotes, history, options chains.
module tallow.yahoo

/// Real-time quote: price, change, volume, PE, market cap
native fn quote(ticker: String) -> Quote
/// Historical OHLCV data
native fn history(ticker: String, period: String, interval: String) -> [Bar]
/// Options chain for a ticker
native fn options_chain(ticker: String, expiration: String) -> Map
/// Search for tickers by name
native fn search(query: String) -> [SearchResult]

struct Quote {
    symbol: String,
    name: String,
    price: Float,
    change: Float,
    change_pct: Float,
    volume: Int,
    high: Float,
    low: Float,
    open: Float,
    prev_close: Float,
    market_cap: Float,
    pe_ratio: Float,
    currency: String,
}

struct Bar {
    timestamp: Int,
    open: Float,
    high: Float,
    low: Float,
    close: Float,
    volume: Float,
}

struct SearchResult {
    symbol: String,
    name: String,
    exchange: String,
    type: String,
}
