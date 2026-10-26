// G01 P0.3 (audit N-4): a function *returned* from a function. The row lives
// on `get`'s return type, travels into `f`, and the call through `f` in
// `outer` requires it — `outer` declares nothing, so it is refused at the call.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn get() -> fn(Grant<Net>, String) with Net(connect) {
    worker
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) {
    let f = get()
    f(g, host)
}
