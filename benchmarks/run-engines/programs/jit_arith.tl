// jit_arith.tl — the shape the Cranelift tier CAN actually run today: straight-line
// arithmetic in main, no calls, no control flow, `var` (not the older `let mut`).
fn main() -> i64 {
    var a = 2
    var b = 3
    return a * b + 1
}
