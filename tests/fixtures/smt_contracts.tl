@requires(x > 0)
@ensures(result >= 0)
fn sqrt_approx(x: f64) -> f64 {
    x / 2.0
}

@requires(a > 0)
@requires(b > 0)
@ensures(result > 0)
fn multiply_positive(a: i32, b: i32) -> i32 {
    a * b
}

fn no_contracts(x: i32) -> i32 {
    x + 1
}
