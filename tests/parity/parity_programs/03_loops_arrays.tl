// 03_loops_arrays.tl — deterministic loop/array probe.
// Exercises arrays (indexing, length, iterate, map/sum) and for-loops.
// Both the tree-walker and the CodeGen/native path must print EXACTLY this output.

fn main() {
    let nums = [3, 7, 1, 9, 4, 2]
    let n = nums.len()

    var sum = 0
    var i = 0
    while i < n {
        sum = sum + nums[i]
        i = i + 1
    }
    print("sum {sum}")
    print("len {n}")
    print("first {nums[0]}")
    print("last {nums[n - 1]}")

    // for-in over an array
    for num in nums {
        print("item {num}")
    }

    // map to squares
    let squares = nums.map { x: i64 -> x * x }
    print("squares count {squares.len()}")
    squares.each { v: i64 -> print("square {v}") }
}
