// jit_fncall.tl — a top-level function call. Pinned because the Cranelift tier does not
// merely refuse this: it ICEs (internal compiler error, with a bug-report URL). An ICE is a
// crash, and a crash is a different and worse event than a refusal, so this case exists to
// make it visible rather than to be tolerated.
fn add(a: i64, b: i64) -> i64 {
    return a + b
}

fn main() -> i64 {
    return add(2, 3)
}
