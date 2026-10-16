// 07_array_push.tl — ARRAY .push() GROWTH canary.
//
// Interpreter: grows an array via .push() in a loop, then iterates it; prints
// the real sum (sum=1225 for n=50), rc=0.
//
// Native: the .push() growth lowering SEGFAULTs (signal, rc=139) even at a
// small n. There is no error text and no exit code, so `tallow run`'s
// run-path fallback silently re-runs the interpreter — which is why the
// benchmark harness never saw a failure. Only `tallow build` + direct binary
// execution surfaces it (it is a signal death, so the "native crashed" branch
// fires). This canary makes the array-push regression a first-class condition.
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
