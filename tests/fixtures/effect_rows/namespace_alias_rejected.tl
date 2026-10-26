// G01 P0.1 (audit F-1): a module namespace is a dispatch path, not a value.
//
// `let n = net` used to compile and *run*: the effect table matches the syntax
// of a dotted callee (`net.connect`), while the interpreter dispatches on the
// module tag the value carries — so an aliased namespace reached a real socket
// from a body with no row and no grant. The binding itself is now E0146.
//
// `@legal` is present so E0100 (the pre-existing @legal gate) can never be what
// the assertion is reading.
@legal(basis: .public_data, purpose: "namespace alias fixture")
fn helper(h: String) {
    let n = net
    n.connect(h)
}

@legal(basis: .public_data, purpose: "namespace alias fixture")
fn main() {
    print("no network here")
}
