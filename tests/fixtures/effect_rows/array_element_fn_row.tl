// G01 P0.3 (audit N-5): an array of function values. `[worker, worker]` is
// `[fn(..) with Net(connect)]` because that is `worker`'s type, `fs[0]` is that
// element type, and the call through it is a `Net(connect)` requirement.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) {
    let fs = [worker, worker]
    let f = fs[0]
    f(g, host)
}
