// G01 interprocedural positive fixture: the identical call chain, with the
// forwarded row declared on the caller. `outer` reaches a socket through
// `probe`, so `outer` must declare `Net(connect)` — and once it does, the
// program compiles.
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(host: String) with Net(connect) {
    net.connect(host)
}

fn outer(host: String) with Net(connect) {
    probe(host)
}
