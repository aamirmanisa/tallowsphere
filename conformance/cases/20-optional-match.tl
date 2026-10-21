// Unwrapping an optional with `match` (#134): Some binds the payload, None the
// absent branch. Both planes must agree.
fn div(a: i64, b: i64) -> i64? {
    if b == 0 { return nil }
    return a / b
}

fn main() {
    let hit = div(8, 2) match {
        Some(x) -> x
        None -> 0 - 1
    }
    print(hit)

    let miss = div(8, 0) match {
        Some(x) -> x
        None -> 0 - 1
    }
    print(miss)
}
