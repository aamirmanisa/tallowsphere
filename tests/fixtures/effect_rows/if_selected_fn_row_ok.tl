// G01 P0.3 positive half of the `if`-selection channel.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}
@legal(basis: .public_data, purpose: "effect row on a function type")
fn nop(g: Grant<Net>, host: String) {
    print("no network here")
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) with Net(connect) {
    let f = if true { worker } else { nop }
    f(g, host)
}
