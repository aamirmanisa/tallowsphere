@requires(x > 0)
@ensures(result >= x)
fn double(x: i32) -> i32 {
    x * 2
}

@requires(n > 0)
@ensures(result >= n)
fn double_then_add(n: i32) -> i32 {
    let d = double(n)
    d + 1
}

fn main() {
    let r = double_then_add(5)
    print("Result: {r}")
}
