fn divide(a: i64, b: i64) -> Result<i64> {
    if b == 0 {
        return Err("division by zero")
    }
    Ok(a / b)
}

fn compute(x: i64, y: i64) -> Result<i64> {
    let a = divide(x, y)?
    let b = a + 10
    Ok(b)
}

fn main() {
    // Ok path: 60 / 3 = 20, 20 + 10 = 30
    let r1 = compute(60, 3)
    print(r1)

    // Err path: division by zero propagated via ?
    let r2 = compute(10, 0)
    print(r2)
}
