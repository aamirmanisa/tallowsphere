// Error handling in Tallow: Result, the ? operator, bail, and match.
//
// A function that can fail returns Result<T>: the caller either handles the
// Err case itself (match / unwrap_or) or propagates it upward with `?`.
//
// Run: tallow run examples/error_handling.tl

// Result<T> is either Ok(value) or Err(message).
fn divide(a: i64, b: i64) -> Result<i64> {
    if b == 0 {
        return Err("division by zero")
    }
    Ok(a / b)
}

// `bail "message"` is an early Err return; the two error paths below are
// reported with the same message vocabulary as any other Result.
fn parse_port(s: String) -> Result<i64> {
    let n = s.parse()
    if n < 0 {
        bail "port must be positive"
    }
    if n > 65535 {
        bail "port too large"
    }
    Ok(n)
}

// `?` unwraps Ok and returns early with the Err, so a chain of fallible calls
// reads like straight-line code.
fn divide_twice(a: i64, b: i64) -> Result<i64> {
    let q = divide(a, b)?
    let r = divide(q, 2)?
    Ok(r)
}

fn main() {
    print("=== Result values ===")

    // Ok and Err print in their constructor form.
    let ok = divide(10, 2)
    print(ok)

    let bad = divide(10, 0)
    print(bad)

    print("=== match on a Result ===")

    let label = divide(10, 2) match {
        Ok(v) -> "10 / 2 ok: {v}"
        Err(e) -> "10 / 2 error: {e}"
    }
    print(label)

    let failed = divide(10, 0) match {
        Ok(v) -> "ok: {v}"
        Err(e) -> "handled error: {e}"
    }
    print(failed)

    print("=== ? operator propagation ===")

    // 100 / 5 = 20, then 20 / 2 = 10.
    let chained = divide_twice(100, 5)
    print(chained)

    // The first division fails, so the Err travels back out of divide_twice.
    let chained_err = divide_twice(100, 0)
    print(chained_err)

    print("=== if let on a Result ===")

    // `if let` narrows a Result to its Ok arm (the value is bound to `v`;
    // examples/if_let_test.tl shows the same form with the bound value used).
    if let Ok(v) = divide(20, 4) {
        print("if let matched the Ok arm")
    } else {
        print("if let hit the Err arm")
    }

    print("=== unwrap_or default ===")

    let safe = divide(10, 0).unwrap_or(-1)
    print("unwrap_or -> {safe}")

    print("=== bail ===")

    let p_ok = parse_port("8080")
    print(p_ok)

    let p_bad = parse_port("99999")
    print(p_bad)
}
