// Contract programming test

@requires(n > 0)
fn factorial(n: i32) -> i32 {
    if n == 1 { 1 } else { n * factorial(n - 1) }
}

@ensures(result >= 0)
fn absolute(x: i32) -> i32 {
    if x < 0 { 0 - x } else { x }
}

@property
fn prop_absolute_non_negative(x: i32) {
    let r = absolute(x)
    assert(r >= 0)
}

fn main() {
    let f = factorial(5)
    assert(f == 120)
    print("factorial(5) = {f}")

    let a = absolute(-7)
    assert(a == 7)
    print("absolute(-7) = {a}")
}
