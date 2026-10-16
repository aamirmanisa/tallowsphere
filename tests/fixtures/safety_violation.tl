@safety_critical(level: .asil_d)
fn critical_fn(x: i32) -> i32 {
    medium_fn(x)
}

@safety_critical(level: .asil_b)
fn medium_fn(x: i32) -> i32 {
    x + 1
}
