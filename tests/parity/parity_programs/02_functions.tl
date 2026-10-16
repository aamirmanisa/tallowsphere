// 02_functions.tl — deterministic function/call probe.
// Exercises named functions (recursion, accumulation), closures, and
// higher-order functions (map / filter / each) over arrays.
// Both the tree-walker and the CodeGen/native path must print EXACTLY this output.

fn fib(n: i64) -> i64 {
    if n <= 1 {
        n
    } else {
        fib(n - 1) + fib(n - 2)
    }
}

fn range_sum(lo: i64, hi: i64) -> i64 {
    var s = 0
    var x = lo
    while x <= hi {
        s = s + x
        x = x + 1
    }
    s
}

fn main() {
    print("fib(10) = {fib(10)}")
    print("range_sum(1,100) = {range_sum(1, 100)}")

    // closure capturing a variable from the enclosing scope
    let base = 5
    let mul = { x: i64 -> x * 2 + base }
    print("closure(3) = {mul(3)}")
    print("closure(10) = {mul(10)}")

    // higher-order functions over an array
    let scores = [90, 85, 70, 60]
    let high = scores.filter { s: i64 -> s >= 70 }
    print("high count {high.len()}")

    let doubled = scores.map { s: i64 -> s * 2 }
    print("doubled count {doubled.len()}")
    doubled.each { v: i64 -> print("  {v}") }
}
