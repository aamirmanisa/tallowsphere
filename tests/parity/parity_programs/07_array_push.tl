// parity: expect-build-fallback
// 07_array_push.tl — ARRAY .push() GROWTH canary.
//
// Interpreter: grows an array via .push() in a loop, then iterates it; prints
// the real sum (sum 1225 for n=50), rc=0.
//
// Native: `.push()` growth has no lowering in the compiled plane, and `tallow
// build` REFUSES it by name ("the native backend has no lowering for
// Array.push"), so no binary is produced and `tallow run` falls back to the
// interpreter. That is the improvement this canary now records: the lowering
// used to SEGFAULT instead — a signal death with no error text and no exit
// code, which the run-path fallback swallowed, so only `tallow build` plus a
// direct binary run surfaced it. A named refusal replaces a silent crash; the
// lowering itself is still unimplemented.
//
// NOT covered by 03_loops_arrays.tl (which reads a fixed literal array and
// iterates; it never mutates via push in a loop).

fn main() {
    var arr = []
    var i = 0
    while i < 50 {
        arr = arr.push(i)
        i = i + 1
    }
    var sum = 0
    for x in arr {
        sum = sum + x
    }
    print("sum {sum}")
    print("ARRAY_PUSH_OK")
}
