@safety_critical(level: .asil_d)
fn critical_calc(x: i32) -> i32 {
    x * 2
}

@safety_critical(level: .asil_b)
fn medium_calc(x: i32) -> i32 {
    critical_calc(x)
}

fn unchecked(x: i32) -> i32 {
    x + 1
}
