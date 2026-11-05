// A closure passed to an array higher-order method writes an enclosing binding.
//
// The native backend inlines these bodies, so `sum = sum + n` lands on the
// caller's `sum`. The interpreter used to run every closure in its own capture
// frame, where that write hit a private snapshot and vanished: this program
// printed 0 on `--interpret` and 6 compiled. Both planes now print 6 6 3.
//
// The array is bound to a name first: `[1, 2, 3].each { … }` (literal receiver)
// does not parse yet, which is a separate parser gap, not a plane difference.

fn main() {
    let nums = [1, 2, 3]
    var sum = 0
    nums.each { n: i64 -> sum = sum + n }
    print(sum)

    var acc = 0
    let out = nums.map { n: i64 -> acc = acc + n }
    print(acc)
    print(out.len())
}
