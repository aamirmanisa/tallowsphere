// parity: expect-build-fallback
// 08_closure_return.tl — closure RETURNED from a function.
//
// Tree-walker: `make_adder(5)` returns a closure; calling it gives 15. Native:
// the backend cannot lift a closure across a function boundary yet (env is a
// per-function side-table), so `tallow build` REJECTS it loudly (fail-loud) and
// `tallow run` falls back to the interpreter. This fixture documents that
// contract: the parity runner reports ERROR(build) for native (expected —
// native correctly refuses rather than silently miscompiling), and the
// interpreter is the correct reference that MUST still produce 15.
//
// This is a "known expected divergence" fixture, not a regression: the native
// path must FAIL LOUDLY here, never silently return a wrong value.

fn make_adder(x: i64) {
    return { y -> y + x }
}

fn main() {
    let add5 = make_adder(5)
    let r = add5(10)
    print("add5(10) = {r}")
    print("CLOSURE_RETURN_OK")
}
