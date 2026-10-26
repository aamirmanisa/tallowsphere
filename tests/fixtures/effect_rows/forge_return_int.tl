// G01 P0.2 / audit F-2: a declared return type is not a mint.
//
// `check_return_coverage` used to ask only whether *some* return existed, so
// `fn mk() -> Grant<Net> { 0 }` typechecked and `helper` could bind the result
// into a real capability. The tail expression is now compared to the declared
// return type; producing a `Grant<Net>` from an `int` is E0117.
@legal(basis: .public_data, purpose: "effect row fixture: return-position forgery")
fn mk() -> Grant<Net> {
    0
}

@legal(basis: .public_data, purpose: "effect row fixture: return-position forgery")
fn helper(h: String) with Net(connect) {
    let g = mk()
    net.connect(h)
}

@legal(basis: .public_data, purpose: "effect row fixture: return-position forgery")
fn main() {
    print("no network here")
}
