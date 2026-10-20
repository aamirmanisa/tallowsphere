fn factorial(n: i64) -> i64 {
    if n <= 1 {
        return 1
    }
    return n * factorial(n - 1)
}

fn add(a: i64, b: i64) -> i64 {
    a + b
}

fn main() {
    print(factorial(5))
    print(add(2, 40))
}
