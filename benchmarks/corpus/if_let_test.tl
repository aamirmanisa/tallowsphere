fn divide(a: i64, b: i64) -> Result<i64> {
    if b == 0 {
        return Err("division by zero")
    }
    Ok(a / b)
}

fn main() {
    // if let Ok(v) = success case
    if let Ok(v) = divide(10, 2) {
        print("got value: {v}")
    } else {
        print("failed")
    }

    // if let Ok(v) = error case
    if let Ok(v) = divide(10, 0) {
        print("got value: {v}")
    } else {
        print("got error as expected")
    }

    // if let Err(e) = error case
    if let Err(e) = divide(10, 0) {
        print("error: {e}")
    } else {
        print("no error")
    }
}
