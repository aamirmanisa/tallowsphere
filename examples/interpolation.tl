fn main() {
    let name = "Tallow"
    let version = 1

    // Simple string interpolation
    print("Hello, {name}!")

    // Interpolation with integer expression
    print("Version: {version}")

    // Multiple interpolations
    print("{name} v{version} is ready")

    // Expression in interpolation
    let a = 10
    let b = 20
    print("Sum: {a + b}")

    // Nested expressions
    let items = 42
    print("Found {items} items")
}
