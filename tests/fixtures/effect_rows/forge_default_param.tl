// G01 P0.2 / audit F-6: a default parameter value is a producer position.
//
// `fn scan(g: Grant<Net> = 7, ..)` typechecked because defaults were parsed and
// never compared to the parameter's declared type. The default expression is
// now checked against that type, so this is E0117 at the default's span.
@legal(basis: .public_data, purpose: "effect row fixture: default-parameter forgery")
fn scan(g: Grant<Net> = 7, h: String = "example.com") with Net(connect) {
    net.connect(h)
}

@legal(basis: .public_data, purpose: "effect row fixture: default-parameter forgery")
fn main() {
    print("no network here")
}
