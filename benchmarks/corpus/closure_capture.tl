fn apply(f: fn(i64) -> i64, x: i64) -> i64 {
    f(x)
}

fn main() {
    // Simple closure (no capture)
    let double = { x: i64 -> x * 2 }
    print(apply(double, 5))

    // Closure with capture
    let multiplier = 3
    let triple = { x: i64 -> x * multiplier }
    print(apply(triple, 7))
}
