/// Fixed-point decimal arithmetic for financial applications.
/// Uses i128 with configurable scale for exact decimal math.
module tallow.decimal

native fn decimal_add(a: String, b: String, scale: Int) -> String
native fn decimal_sub(a: String, b: String, scale: Int) -> String
native fn decimal_mul(a: String, b: String, scale: Int) -> String
native fn decimal_div(a: String, b: String, scale: Int) -> String
native fn decimal_round(value: String, scale: Int, new_scale: Int) -> String
native fn decimal_cmp(a: String, b: String, scale: Int) -> Int
