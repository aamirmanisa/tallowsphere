// compute.tl — numeric core, NO print. This is the shape the Cranelift JIT tier accepts:
// `main() -> i64` returning a value. The JIT reports that return on stderr, so the answer
// is checkable without stdout: sum_to(3000000) = 3000000*2999999/2 = 4499998500000.
//
// Kept print-free on purpose — `print` is a builtin call, and the JIT rejects builtin calls
// LOUDLY rather than mis-executing them (see codegen_cranelift.rs), so a printed variant
// would measure the rejection path, not the tier.
fn sum_to(n: i64) -> i64 {
    var i = 0
    var acc = 0
    while i < n {
        acc = acc + i
        i = i + 1
    }
    return acc
}

fn main() -> i64 {
    return sum_to(3000000)
}
