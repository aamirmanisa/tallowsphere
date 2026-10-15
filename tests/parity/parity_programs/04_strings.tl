// 04_strings.tl — deterministic string probe.
// Exercises interpolation, string concatenation with '+', and length.
// Both the tree-walker and the CodeGen/native path must print EXACTLY this output.

fn main() {
    let name = "Tallow"
    let version = 2

    print("Hello, {name}!")
    print("v{version} ready")
    print("{name} v{version} is here")

    // concatenation with '+'
    let first = "foo"
    let second = "bar"
    let joined = first + second
    print("joined {joined}")
    let long = first + " " + second + "!"
    print(long)

    // interpolation with an expression
    let a = 6
    let b = 7
    print("sum {a + b}")

    // length
    let word = "tallow"
    print("len {word.len()}")

    // interpolation of a repeated value
    let cnt = 3
    print("Found {cnt} items")
}
