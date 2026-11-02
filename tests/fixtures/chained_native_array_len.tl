// Minimal, browser-free reproduction of the v1.7.0 cookie-array split.
//
// A native array is `[count: i64][slot: i64]...`, so `strlen` over that buffer
// reads the count's low byte and stops at the NUL of its second byte: 0 -> 0,
// and every count in 1..=255 -> 1. That is the whole defect:
//
//   tallow run --require-native tests/fixtures/chained_native_array_len.tl -- a b c
//   tallow run --interpret     tests/fixtures/chained_native_array_len.tl -- a b c
//
// Before the fix the first line printed 1 and the second printed 3.
fn main() {
    print(env.args().len)   // chained native-array call: the broken form
    let argv = env.args()
    print(argv.len)         // bound form: was already correct on both planes
}
