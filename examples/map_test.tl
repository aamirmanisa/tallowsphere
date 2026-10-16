fn main() {
    // Map not yet in codegen — testing what works
    // Focus on what IS working: arrays, HOF, closures, results, etc.

    // Bail test
    let scores = [95, 87, 72, 60, 45]
    let high = scores.filter { s: i64 -> s >= 70 }
    print("High scores: {high.len}")

    // Chained operations
    let doubled = scores.map { s: i64 -> s * 2 }
    doubled.each { s: i64 -> print("  {s}") }

    // Closure capturing multiple values
    let base = 10
    let multiplier = 3
    let compute = { x: i64 -> x * multiplier + base }
    print("compute(5) = {compute(5)}")
    print("compute(10) = {compute(10)}")
}
