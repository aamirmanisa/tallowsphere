// G01: a different callee shape — a static method on a type name — must be
// gated the same way as the module-qualified call in no_row.tl.
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(host: String) {
    let conn = Tcp.connect(host, 443)
    print("connected")
}
