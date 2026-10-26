// G01 P0.2 positive fixture: the row is satisfied by a *value*, not by the
// declaration alone. `g: Grant<Net>` is the capability the call consumes; the
// row says what the body does, the parameter says where the authority came
// from. This is the shape every network helper is meant to have.
@legal(basis: .public_data, purpose: "effect row fixture")
fn scan(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}
