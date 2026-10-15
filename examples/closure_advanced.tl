fn apply(f: fn(i64) -> i64, x: i64) -> i64 {
    f(x)
}

fn main() {
    // 1. Simple closure (no capture)
    let double = { x: i64 -> x * 2 }
    print(apply(double, 5))

    // 2. Single capture
    let multiplier = 3
    let triple = { x: i64 -> x * multiplier }
    print(apply(triple, 7))

    // 3. Multiple captures
    let base = 100
    let offset = 42
    let compute = { x: i64 -> x + base + offset }
    print(apply(compute, 8))

    // 4. Closure capturing a different value
    let scale = 10
    let scaled = { x: i64 -> x * scale }
    print(apply(scaled, 6))

    // 5. Two closures sharing a capture
    let factor = 5
    let mul_fn = { x: i64 -> x * factor }
    let add_fn = { x: i64 -> x + factor }
    print(apply(mul_fn, 4))
    print(apply(add_fn, 4))
}
