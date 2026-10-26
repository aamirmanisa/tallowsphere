// G01 P0.2 / audit F-3: same forgery through an explicit `return`.
//
// The explicit-`return` form is checked separately from the tail expression,
// because a body may have any number of returns and none of them is the tail.
// Returning a string where `Grant<Net>` was declared is E0117.
@legal(basis: .public_data, purpose: "effect row fixture: explicit return forgery")
fn mk() -> Grant<Net> {
    return "not a grant"
}

@legal(basis: .public_data, purpose: "effect row fixture: explicit return forgery")
fn helper(h: String) with Net(connect) {
    let g = mk()
    net.connect(h)
}

@legal(basis: .public_data, purpose: "effect row fixture: explicit return forgery")
fn main() {
    print("no network here")
}
