// G01: two-entry row — the syntax `with Net(connect), Net(read)` must parse and
// the declared `connect` entry must satisfy the call. G01 P0.2: the row is
// backed by a `Grant<Net>` parameter, so the call has an authority as well as a
// declaration.
@legal(basis: .public_data, purpose: "effect row fixture")
fn multi(g: Grant<Net>, host: String) with Net(connect), Net(read) {
    net.connect(host)
}
