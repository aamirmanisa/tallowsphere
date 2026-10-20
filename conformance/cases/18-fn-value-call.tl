fn add(a: i64, b: i64) -> i64 { a + b }
fn apply(f: fn(i64, i64) -> i64, a: i64, b: i64) -> i64 { f(a, b) }
fn main() { print(apply(add, 2, 40)) }
