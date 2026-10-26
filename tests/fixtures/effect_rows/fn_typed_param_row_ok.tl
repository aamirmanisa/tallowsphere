// G01 P0.3 positive half of the parameter channel: the identical parameter
// type with the forwarded row declared on `apply`. This is the shape the
// checker says to write (`add: with Net(connect)`).
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn apply(
    f: fn(Grant<Net>, String) with Net(connect),
    g: Grant<Net>,
    host: String
) with Net(connect) {
    f(g, host)
}
