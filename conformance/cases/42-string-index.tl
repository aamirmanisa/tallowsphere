// String indexing must return a one-character String, not a numeric slot.
//
// A String and a length-prefixed array share the LLVM type i8*, so the native
// index lowering treated every i8* receiver as an array: it read the string's
// first bytes as an element count and then loaded character data as if it were
// an i64 slot. `"hello"[0]` printed a pointer-shaped integer instead of `h`.
//
// Fixed on the native plane by a string-vs-array dispatch in the index
// lowering plus `tallow_string_index` in the runtime: a string is indexed by
// Unicode scalar (same as the interpreter), nil-checked first, and an
// out-of-bounds read exits 1 with `runtime error: index N out of bounds`.
// This case pins the in-bounds ASCII read, which is the ordinary path.
fn main() {
    let s = "hello"
    print(s[0])
    print(s[4])
    print(s[0] + s[4])
}
