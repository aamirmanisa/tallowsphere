// G01 P0.3 positive half of the struct-field channel.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

struct Box3 {
    f: fn(Grant<Net>, String) with Net(connect),
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) with Net(connect) {
    let b = Box3 { f: worker }
    b.f(g, host)
}
