// G01 P0.3: the same laundering in argument position — a rowwed function
// stored into a parameter type that declares no row.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn apply(f: fn(Grant<Net>, String), g: Grant<Net>, host: String) with Net(connect) {
    f(g, host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) with Net(connect) {
    apply(worker, g, host)
}
