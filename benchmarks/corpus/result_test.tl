fn divide(a: i64, b: i64) -> Result<i64> {
    if b == 0 {
        return Err("division by zero")
    }
    Ok(a / b)
}

fn main() {
    // Ok case
    let r1 = divide(10, 2)
    print(r1)

    // Err case
    let r2 = divide(10, 0)
    print(r2)

    // Match on Result
    let result = divide(42, 7) match {
        Ok(v) -> v
        Err(msg) -> 0
    }
    print(result)

    // Match on Err
    let err_result = divide(1, 0) match {
        Ok(v) -> v
        Err(msg) -> -1
    }
    print(err_result)
}
