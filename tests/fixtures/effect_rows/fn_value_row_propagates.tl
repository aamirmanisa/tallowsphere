// G01 (audit F-8): a row survives being stored in a value.
//
// `scan` declares `Net(connect)`. `outer` binds it to `f` and calls `f(g, h)` —
// which used to match nothing in the effect table, so the caller inherited no
// requirement and no E0141 fired. The row now travels with the binding, so the
// refusal lands on the call in `outer`, exactly as for a direct call.
@legal(basis: .public_data, purpose: "function value row fixture")
fn scan(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}

@legal(basis: .public_data, purpose: "function value row fixture")
fn outer(g: Grant<Net>, h: String) {
    let f = scan
    f(g, h)
}

@legal(basis: .public_data, purpose: "function value row fixture")
fn main() {
    print("no network here")
}
