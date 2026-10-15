/// Position tracking: P&L, cost basis, realized/unrealized.
module tallow.positions

/// Create a new empty position book
native fn new() -> PositionBook
/// Add or update a position (averages cost basis)
native fn add(book: PositionBook, symbol: String, qty: Float, price: Float) -> PositionBook
/// Close a position, realize P&L
native fn close(book: PositionBook, symbol: String, price: Float) -> PositionBook
/// Compute total P&L (realized + unrealized) given market prices
native fn pnl(book: PositionBook, market_prices: {String: Float}) -> Float
/// Position summary
native fn summary(book: PositionBook) -> PositionSummary

struct PositionBook {
    positions: [Position],
    realized_pnl: Float,
    cost_basis: Float,
}

struct Position {
    symbol: String,
    quantity: Float,
    avg_cost: Float,
}

struct PositionSummary {
    count: Int,
    gross_exposure: Float,
    realized_pnl: Float,
}
