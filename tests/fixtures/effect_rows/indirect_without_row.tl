// G01 interprocedural negative fixture: `probe` declares `Net(connect)` and
// reaches a socket. `outer` calls `probe` and declares nothing — its body
// therefore reaches a socket too, so the refusal must land on the call in
// `outer` (line 14), not on `probe`'s declaration.
//
// `@legal` is present so E0100 (the pre-existing @legal gate) can never be what
// the assertion is reading.
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(host: String) with Net(connect) {
    net.connect(host)
}

fn outer(host: String) {
    probe(host)
}
