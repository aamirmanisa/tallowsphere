// bench_recursive.tl
// Compute-bound benchmark: recursive traversal of a full binary tree. The
// recursive call DEPTH is small (the interpreter's call frame is large, so deep
// recursion overflows the stack), while the repeat count makes the total number
// of recursive calls large. This gives a realistic recursive workload.
// Category: compute (recursion).
//
// Run:
//   RUST_MIN_STACK=67108864 tallow run benches/tl/bench_recursive.tl

fn tree_nodes(depth: i64) -> i64 {
    if depth <= 0 {
        return 1
    }
    return tree_nodes(depth - 1) + tree_nodes(depth - 1) + 1
}

fn main() {
    let depth = 6
    let repeats = 150
    var total = 0
    var i = 0
    while i < repeats {
        total = total + tree_nodes(depth)
        i = i + 1
    }
    print("tree_nodes(depth={depth}) x {repeats} total = {total}")
    print("COMPUTE_REC_OK")
}
