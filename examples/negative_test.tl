fn abs(n: i64) -> i64 {
    if n < 0 {
        0 - n
    } else {
        n
    }
}

fn main() {
    let x = 0 - 42
    print(x)
    print(abs(x))
    print(abs(10))

    // Negative in match
    let y = 0 - 1
    let r = match y {
        1 -> "positive"
        _ -> "not one"
    }
    print(r)
}
