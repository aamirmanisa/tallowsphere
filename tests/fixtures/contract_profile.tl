@requires(x > 0)
@ensures(result > 0)
fn positive_only(x: i32) -> i32 {
    x * 2
}

fn main() {
    let a = positive_only(5)
    print(a)
    let b = positive_only(-1)
    print(b)
}
