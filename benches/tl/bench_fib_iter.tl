// bench_fib_iter.tl
// Compute-bound benchmark: iterative fibonacci (bounded via modulo) plus a
// nested numeric loop with a modulus to keep the accumulator in range.
// Category: compute.
//
// Run:
//   tallow run benches/tl/bench_fib_iter.tl

fn fib_iter(n: i64) -> i64 {
    var a = 0
    var b = 1
    var i = 0
    while i < n {
        let next = (a + b) % 1000000007
        a = b
        b = next
        i = i + 1
    }
    return a
}

fn nested_loop(n: i64) -> i64 {
    var acc = 0
    var i = 0
    while i < n {
        var j = 0
        while j < n {
            if (i + j) % 3 == 0 {
                acc = (acc + i * j) % 1000000007
            }
            j = j + 1
        }
        i = i + 1
    }
    return acc
}

fn main() {
    let fib_n = 40000
    let fib_last = fib_iter(fib_n)
    let nest_n = 140
    let acc = nested_loop(nest_n)

    print("fib_iter({fib_n}) last = {fib_last}")
    print("nested_loop({nest_n}) acc = {acc}")
    print("COMPUTE_ITER_OK")
}
