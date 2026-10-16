// 22_for_range_continue.tl — `continue` inside a range-for.
// Regression guard for a range arm whose `continue` skipped the loop's own increment, so the
// interpreter never advanced and the loop ran forever. Both legs must produce the same output.
fn main() {
    for i in 0..6 {
        if i == 3 { continue }
        print(i)
    }
}
