// G01 P0.3 (audit N-6): a function-typed struct field. The row is on the field
// type, so a call through `b.f` requires it however the value got there.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

struct Box3 {
    f: fn(Grant<Net>, String) with Net(connect),
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) {
    let b = Box3 { f: worker }
    b.f(g, host)
}
