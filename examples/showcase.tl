// Tallow Language Showcase
// Demonstrates all major compiled features

struct Product {
    name: String,
    price: i64,
    category: String
}

fn apply(f: fn(i64) -> i64, x: i64) -> i64 {
    f(x)
}

fn grade(score: i64) -> String {
    match score {
        100 -> "perfect"
        90  -> "excellent"
        80  -> "great"
        70  -> "good"
        _   -> "ok"
    }
}

fn main() {
    print("=== Tallow Language Showcase ===")

    // 1. Variables and types
    let name = "Tallow"
    let version = 1
    var counter = 0
    print("Language: {name} v{version}")

    // 2. Arithmetic
    let a = 15
    let b = 4
    print("  {a} + {b} = {a + b}")
    print("  {a} * {b} = {a * b}")
    print("  {a} % {b} = {a % b}")

    // 3. String operations
    let greeting = "Hello, World!"
    print("  upper: {greeting.upper()}")
    print("  contains 'World': {greeting.contains("World")}")
    print("  replace: {greeting.replace("World", "Tallow")}")
    let line = "-".repeat(30)
    print(line)

    // 4. Arrays + HOF
    let scores = [100, 90, 80, 70, 60]
    let high = scores.filter { s: i64 -> s >= 80 }
    print("High scores ({high.len}):")
    high.each { s: i64 -> print("  {grade(s)}") }

    let doubled = scores.map { s: i64 -> s * 2 }
    doubled.each { s: i64 -> print("  doubled: {s}") }

    // 5. Closures with capture
    let tax_rate = 20
    let add_tax = { price: i64 -> price + price * tax_rate / 100 }
    print("Price 100 + tax: {apply(add_tax, 100)}")
    print("Price 250 + tax: {apply(add_tax, 250)}")

    // 6. Match expressions
    let status = 200
    let status_msg = match status {
        200 -> "OK"
        404 -> "Not Found"
        500 -> "Server Error"
        _   -> "Unknown"
    }
    print("HTTP {status}: {status_msg}")

    // 7. Control flow
    for i in 0..5 {
        counter = counter + 1
    }
    print("Counter: {counter}")

    // 8. Conditionals
    let temp = 72
    if temp > 80 {
        print("Hot")
    } else if temp > 60 {
        print("Nice weather ({temp}F)")
    } else {
        print("Cold")
    }

    // 9. String parsing
    let data = "42"
    let parsed = data.to_int()
    print("Parsed '{data}' + 8 = {parsed + 8}")

    // 10. Split and slice
    let csv = "alpha,beta,gamma"
    let parts = csv.split(",")
    print("CSV parts: {parts.len}")
    let sub = csv.slice(0, 5)
    print("First 5 chars: {sub}")

    print(line)
    print("Showcase complete!")
}
