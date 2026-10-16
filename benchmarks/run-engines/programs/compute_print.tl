// compute_print.tl — the SAME computation as compute.tl, but with a print, so the engines
// that support stdout can be checked against the independently computed value
// 4499998500000. The Cranelift tier is expected to REJECT this file (builtin call), and
// that rejection is a result worth recording: a tier that silently mis-executed a builtin
// would be worse than one that refuses.
fn sum_to(n: i64) -> i64 {
    var i = 0
    var acc = 0
    while i < n {
        acc = acc + i
        i = i + 1
    }
    return acc
}

fn main() {
    print("sum {sum_to(3000000)}")
}
