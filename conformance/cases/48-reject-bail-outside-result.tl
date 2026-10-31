// `bail` is only legal in a function whose return type is Result (spec 03-types).
// The parser desugars `bail expr` to `return Err(expr)`; typeck must still refuse
// it when the declared return is not Result (E0126).
fn f() -> i64 {
    bail "no"
}
fn main() {
    print(f())
}
