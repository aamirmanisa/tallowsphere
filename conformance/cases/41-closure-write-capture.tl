// Closure capture is a SNAPSHOT, by design, on both planes.
//
// This case was originally added as a pin for a defect I believed existed: that
// `n = n + 1` inside a closure was silently discarded because the enclosing
// frame still read 0. That reading was wrong. The interpreter documents the
// behaviour explicitly (src/interp.rs, `Env::from_captures`): each call seeds
// the frame from the closure's shared cell and flushes mutations back, so the
// CLOSURE accumulates state (1, then 2) while the enclosing frame "keeps its
// creation-time value: capture is a snapshot taken where the closure literal is
// evaluated". The native plane implements the same semantics.
//
// What this case pins: (1) the closure's own state accumulates across calls,
// and (2) the defining frame is unaffected. If capture ever became
// by-reference, this case would fail — which is the point.
fn main() {
    var n = 0
    let inc = { ->
        n = n + 1
        print(n)
    }
    inc()
    inc()
    print(n)
}
