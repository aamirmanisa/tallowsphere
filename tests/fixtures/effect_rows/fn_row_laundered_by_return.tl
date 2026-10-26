// G01 P0.3: the type must declare what the value can do. `get` promises a
// rowless `fn(..)` and returns `worker`, whose row is `Net(connect)`; the
// laundering is refused at the return.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn get() -> fn(Grant<Net>, String) {
    worker
}
