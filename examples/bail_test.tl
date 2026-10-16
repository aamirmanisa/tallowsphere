fn validate(n: i64) -> Result<i64> {
    if n < 0 {
        bail "negative number"
    }
    if n > 100 {
        bail "too large"
    }
    Ok(n * 2)
}

fn main() {
    let r1 = validate(25)
    print(r1)

    let r2 = validate(0 - 5)
    print(r2)

    let r3 = validate(200)
    print(r3)

    // Use with match
    let v = validate(50) match {
        Ok(x) -> x
        Err(msg) -> 0
    }
    print("validated: {v}")
}
