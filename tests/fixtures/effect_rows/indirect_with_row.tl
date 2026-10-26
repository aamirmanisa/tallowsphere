// G01 interprocedural positive fixture: the identical call chain, with the
// forwarded row declared on the caller. `outer` reaches a socket through
// `probe`, so `outer` must declare `Net(connect)` — and once it does, the
// program compiles. G01 P0.2: the capability travels as a value, so both
// frames take the `Grant<Net>` explicitly; there is no implicit forwarding.
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

fn outer(g: Grant<Net>, host: String) with Net(connect) {
    probe(g, host)
}
