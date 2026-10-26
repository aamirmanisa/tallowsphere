// G01 positive fixture: the identical body, with the row the gate asks for.
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(host: String) with Net(connect) {
    net.connect(host)
}
