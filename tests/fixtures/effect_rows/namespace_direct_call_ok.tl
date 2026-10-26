// Positive half of the E0146 rule: the module namespace is legal exactly where
// it names a dispatch path — as the receiver of a method call. The call itself
// is still governed by the row and the capability, so this body declares
// `Net(connect)` and takes a `Grant<Net>`; nothing about E0146 loosens that.
@legal(basis: .public_data, purpose: "namespace alias fixture")
fn probe(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}

@legal(basis: .public_data, purpose: "namespace alias fixture")
fn main() {
    print("no network here")
}
