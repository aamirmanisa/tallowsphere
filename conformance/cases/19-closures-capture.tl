// A closure that captures a variable can cross a call boundary (#127).
fn apply(f: fn(i64) -> i64, x: i64) -> i64 { f(x) }

fn main() {
    let triple = 3
    print(apply({ y -> y * triple }, 14))
}
