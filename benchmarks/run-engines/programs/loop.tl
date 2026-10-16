// loop.tl — compute-bound. Exposes the tree-walker's throughput deficit, which a trivial
// program cannot show: with no work to do, the interpreter wins simply by not compiling.
fn main() {
    var sum = 0
    var i = 0
    while i < 200000 {
        sum = sum + i
        i = i + 1
    }
    print("sum {sum}")
}
