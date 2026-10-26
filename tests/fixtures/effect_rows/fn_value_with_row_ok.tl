// Positive half of the function-value row: the identical indirection with the
// forwarded row declared on the caller compiles. Without this the refusal above
// could be "indirection is forbidden" rather than "the row was not declared".
@legal(basis: .public_data, purpose: "function value row fixture")
fn scan(g: Grant<Net>, h: String) with Net(connect) {
    net.connect(h)
}

@legal(basis: .public_data, purpose: "function value row fixture")
fn outer(g: Grant<Net>, h: String) with Net(connect) {
    let f = scan
    f(g, h)
}

@legal(basis: .public_data, purpose: "function value row fixture")
fn main() {
    print("no network here")
}
