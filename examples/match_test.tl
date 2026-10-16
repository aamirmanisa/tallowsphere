fn classify(n: i64) -> i64 {
    match n {
        1 -> 10
        2 -> 20
        3 -> 30
        _ -> 0
    }
}

fn main() {
    // Integer match
    print(classify(1))
    print(classify(2))
    print(classify(3))
    print(classify(99))

    // Match as expression
    let status = 200
    let msg = match status {
        200 -> "ok"
        404 -> "not found"
        500 -> "error"
        _   -> "unknown"
    }
    print(msg)

    // Match in if context
    let code = 404
    let response = match code {
        200 -> "success"
        404 -> "missing"
        _   -> "other"
    }
    print(response)
}
