// bench_alloc.tl
// Allocation-heavy benchmark: build many strings by concatenation, grow large
// arrays via push, and build/index maps in a loop.
// Category: alloc.
//
// Run:
//   tallow run benches/tl/bench_alloc.tl

fn string_build(n: i64) -> i64 {
    var s = ""
    var i = 0
    while i < n {
        s = s + "chunk-" + "x"
        i = i + 1
    }
    return s.len()
}

fn array_grow(n: i64) -> i64 {
    var arr = []
    var i = 0
    while i < n {
        arr = arr.push(i)
        i = i + 1
    }
    var sum = 0
    for x in arr {
        sum = sum + x
    }
    return sum
}

fn map_build(n: i64) -> i64 {
    var m = {}
    var i = 0
    while i < n {
        m = m.set("k" + "{i}", i)
        i = i + 1
    }
    return m.len()
}

fn main() {
    let s_len = string_build(2000)
    let arr_sum = array_grow(6000)
    let m_len = map_build(500)

    print("string_build len = {s_len}")
    print("array_grow sum = {arr_sum}")
    print("map_build len = {m_len}")
    print("ALLOC_OK")
}
