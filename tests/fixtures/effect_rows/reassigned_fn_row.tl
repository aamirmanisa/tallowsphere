// G01 P0.3 (audit N-7): the row recorded on a binding follows the value it
// holds. `f` starts rowless (`nop`) and is reassigned to `worker`, so the call
// after the assignment reaches a socket even though the initialiser did not.
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
    var f = nop
    f = worker
    f(g, host)
}
