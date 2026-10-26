// G01 P0.3 (audit N-3): a row travels with a function value through its
// *type*. `apply` takes a `fn(..) with Net(connect)` and calls it, so `apply`
// reaches a socket through the parameter and must declare the row itself. A
// parameter used to carry nothing: `VarInfo::effects` was only ever populated
// from an initialiser, so this body inherited no requirement.
@legal(basis: .public_data, purpose: "effect row on a function type")
fn worker(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "effect row on a function type")
fn apply(f: fn(Grant<Net>, String) with Net(connect), g: Grant<Net>, host: String) {
    f(g, host)
}
