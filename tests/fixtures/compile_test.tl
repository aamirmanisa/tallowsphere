// Basic compilation test: arithmetic, functions, control flow, strings

fn square(n: i64) -> i64 {
    n * n
}

fn fibonacci(n: i64) -> i64 {
    if n < 2 {
        n
    } else {
        fibonacci(n - 1) + fibonacci(n - 2)
    }
}

fn main() {
    print("=== Tallow Compiled Binary ===")
    print(42)
    print(square(7))
    print(true)

    var sum = 0
    for i in 0..10 {
        sum = sum + i
    }
    print(sum)

    print(fibonacci(10))

    let x = 100
    if x > 50 {
        print("x is big")
    } else {
        print("x is small")
    }

    match x {
        42 -> print("answer")
        100 -> print("century")
        _ -> print("other")
    }

    print("done!")
}
