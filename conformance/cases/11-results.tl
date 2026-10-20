fn validate(n: i64) -> Result<i64> {
    if n < 0 {
        bail "negative"
    }
    Ok(n * 2)
}

fn main() {
    print(validate(3))
    print(validate(0 - 1))
    let v = validate(21) match {
        Ok(x) -> x
        Err(e) -> 0
    }
    print(v)
}
