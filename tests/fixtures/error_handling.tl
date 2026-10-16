// Error handling: Result, bail, match, unwrap_or

fn divide(a: i32, b: i32) -> i32 {
    if b == 0 { bail "division by zero" }
    Ok(a / b)
}

fn parse_port(s: String) -> i32 {
    let n = s.parse()
    if n < 0 { bail "port must be positive" }
    if n > 65535 { bail "port too large" }
    Ok(n)
}

fn main() {
    // Successful result
    let r1 = divide(10, 2)
    match r1 {
        Ok(v) -> print("10/2 = " + to_string(v))
        Err(e) -> print("error: " + e)
    }

    // Error result
    let r2 = divide(10, 0)
    match r2 {
        Ok(v) -> print("10/0 = " + to_string(v))
        Err(e) -> print("error: " + e)
    }

    // unwrap_or
    let safe = divide(10, 0).unwrap_or(-1)
    print("safe = " + to_string(safe))

    // Port parsing
    let p1 = parse_port("8080")
    match p1 {
        Ok(v) -> print("port: " + to_string(v))
        Err(e) -> print("bad port: " + e)
    }
}
