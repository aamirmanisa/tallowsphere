// full_demo.tl — Comprehensive Tallow language demo

struct Product {
    name: String,
    price: f64,
}

impl Product {
    fn display(self) -> String {
        "{self.name}: ${self.price}"
    }
}

fn find_cheapest(products: []Product) -> String {
    var best_name = "none"
    var best_price = 999999.0
    for p in products {
        if p.price < best_price {
            best_price = p.price
            best_name = p.name
        }
    }
    best_name
}

fn grade(score: i64) -> String {
    match score {
        90 -> "A"
        80 -> "B"
        70 -> "C"
        _  -> "F"
    }
}

fn divide(a: f64, b: f64) -> Result<f64> {
    if b == 0.0 {
        return Err("division by zero")
    }
    Ok(a / b)
}

const VERSION = "0.1.0"

fn main() {
    print("=== Tallow Demo v{VERSION} ===")
    print("")

    // Structs and methods
    let apple = Product { name: "Apple", price: 1.50 }
    let banana = Product { name: "Banana", price: 0.75 }
    let cherry = Product { name: "Cherry", price: 3.00 }
    print(apple.display())
    print(banana.display())
    print(cherry.display())
    print("")

    // Arrays of structs with for loop
    let products = [apple, banana, cherry]
    print("Products: {products.len}")
    for p in products {
        print("  {p.name} at {p.price}")
    }
    print("")

    // Function with struct array parameter
    let cheapest = find_cheapest(products)
    print("Cheapest: {cheapest}")
    print("")

    // Match expression
    print("Score 90: {grade(90)}")
    print("Score 70: {grade(70)}")
    print("Score 50: {grade(50)}")
    print("")

    // Result type
    let ok = divide(10.0, 3.0)
    print(ok)
    let err = divide(5.0, 0.0)
    print(err)
    print("")

    // Loops and control flow
    var sum = 0
    for i in 0..5 {
        sum = sum + i
    }
    print("Sum 0..5: {sum}")

    // String operations
    let msg = "hello world"
    print("Upper: {msg.upper()}")
    print("Length: {msg.len}")
    print("")

    // Array operations
    let nums = [10, 20, 30, 40, 50]
    print("Array: {nums.len} items, sum = {nums.sum()}")

    print("")
    print("=== Demo Complete ===")
}
