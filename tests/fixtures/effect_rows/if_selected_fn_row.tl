// G01 P0.3 (audit N-8): `if` selects the function value. The joined type
// carries the union of the arms' rows, so the rowless arm does not make the
// call safe.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}
@legal(basis: .public_data, purpose: "effect row on a function type")
fn nop(g: Grant<Net>, host: String) {
    print("no network here")
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn outer(g: Grant<Net>, host: String) {
    let f = if true { worker } else { nop }
    f(g, host)
}
