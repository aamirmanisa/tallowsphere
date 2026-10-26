// G01: two-entry row — the syntax `with Net(connect), Net(read)` must parse and
// the declared `connect` entry must satisfy the call.
@legal(basis: .public_data, purpose: "effect row fixture")
fn multi(host: String) with Net(connect), Net(read) {
    net.connect(host)
}
