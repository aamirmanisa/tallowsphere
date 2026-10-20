fn apply(f: fn(i64) -> i64, x: i64) -> i64 {
    f(x)
}

fn main() {
    let base = 100
    let compute = { x: i64 -> x + base }
    print(apply(compute, 8))
    print(apply({ x: i64 -> x * 2 }, 21))
}
