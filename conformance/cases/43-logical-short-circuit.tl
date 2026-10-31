// `&&` and `||` must short-circuit.
//
// The native plane lowered both as bitwise and/or on i64, which did two wrong
// things: it evaluated the right operand even when the left had decided the
// answer (so `false && side()` ran `side()`), and it produced 0/1 instead of a
// Bool. The corpus had no case for either operator, so the miscompile went
// unnoticed. Fixed by lowering `&&`/`||` as a branch plus `phi` emitted BEFORE
// the right operand, so short-circuiting is structural, not incidental.
fn side(label: String) -> bool {
    print(label)
    return true
}

fn main() {
    // false && x  -> the right operand must not run
    print(false && side("AND-RAN"))
    // true || x   -> the right operand must not run
    print(true || side("OR-RAN"))
    // true && x   -> it must run, and the result is true
    print(true && side("AND-OK"))
    // false || x  -> it must run, and the result is true
    print(false || side("OR-OK"))
}
