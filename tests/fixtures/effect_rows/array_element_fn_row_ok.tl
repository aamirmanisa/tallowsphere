// G01 P0.3 positive half of the array channel.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) with Net(connect) {
    let fs = [worker, worker]
    let f = fs[0]
    f(g, host)
}
