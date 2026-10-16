// Comprehensive Tallow test: exercises multiple language features together

const APP_NAME = "TallowTest"
const MAX_ITEMS = 5

fn fibonacci(n: i32) -> i32 {
    if n <= 1 {
        return n
    }
    fibonacci(n - 1) + fibonacci(n - 2)
}

fn process_items(items: []i32) -> []i32 {
    items.filter({ x -> x > 2 }).map({ x -> x * 10 })
}

fn greet(name: String) -> String {
    "{APP_NAME} says hello to {name}!"
}

fn main() {
    // Constants
    print(APP_NAME)

    // Fibonacci
    let fib8 = fibonacci(8)
    print("fib(8) = {fib8}")

    // Array operations with closures
    let nums = [1, 2, 3, 4, 5]
    let processed = process_items(nums)
    print(processed)

    // String interpolation
    print(greet("World"))

    // Match expression
    let status = 200
    match status {
        200 -> print("ok")
        404 -> print("not found")
        _   -> print("other")
    }

    // Result handling
    let result = Ok(42)
    let value = result match {
        Ok(v)    -> v
        Err(msg) -> 0
    }
    print("value = {value}")

    // String methods
    let text = "  hello tallow  "
    print(text.trim())
    print("tallow".upper())

    // Array methods
    let words = ["hello", "world"]
    print(words.join(", "))
    print(words.first())
}
