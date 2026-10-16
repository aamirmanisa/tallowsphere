/// Order management: limit, market, stop, OCO, fill simulation.
module tallow.orders

/// Create a limit order
native fn limit(side: String, qty: Float, price: Float, symbol: String) -> Order
/// Create a market order
native fn market(side: String, qty: Float, symbol: String) -> Order
/// Create a stop order
native fn stop(side: String, qty: Float, stop_price: Float, symbol: String) -> Order
/// Create an OCO (One-Cancels-Other) bracket
native fn oco(side: String, qty: Float, price: Float, stop: Float, symbol: String) -> Order
/// Simulate a fill on an order
native fn fill(order: Order, fill_price: Float, fill_qty: Float) -> Order

struct Order {
    type: String,       // "limit", "market", "stop", "oco"
    side: String,        // "buy", "sell"
    quantity: Float,
    price: Float,
    stop_price: Float,
    symbol: String,
    status: String,      // "pending", "partial", "filled"
    filled_qty: Float,
    avg_fill_price: Float,
}
