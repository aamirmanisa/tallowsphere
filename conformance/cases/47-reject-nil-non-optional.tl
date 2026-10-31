// `nil` cannot initialise a non-optional binding. This is a reject case: the
// checker must refuse it rather than let the two planes disagree about what the
// binding holds (interpreter: nil, native: 0). Fixed in the checker:
// `check_optional_binding` now refuses `nil` for a non-optional destination.
fn main() {
    let x: i64 = nil
    print(x)
}
