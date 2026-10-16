/// Unified market data aggregator: Yahoo + SEC + FRED.
module tallow.market

/// Combined quote + key financials
native fn summary(ticker: String) -> MarketSummary
/// Sector performance snapshot (SPY + XLF/XLK/XLE/XLV/XLI/XLP/XLY/XLU/XLB/XLRE)
native fn sector_performance() -> [SectorPerformance]

struct MarketSummary {
    ticker: String,
    name: String,
    price: Float,
    change_pct: Float,
    volume: Int,
    market_cap: Float,
    pe_ratio: Float,
    fifty_two_week_high: Float,
    fifty_two_week_low: Float,
    dividend_yield: Float,
    sector: String,
    industry: String,
}

struct SectorPerformance {
    name: String,
    symbol: String,
    change_pct: Float,
}
