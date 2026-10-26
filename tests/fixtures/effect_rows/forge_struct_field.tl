// G01 P0.2 / audit F-4: a struct field is a slot for a capability.
//
// `Holder { g: 7 }` stored an int in a `Grant<Net>` field and `let g = box.g`
// read authority back out. The field initialiser is now checked against the
// declared field type, so the write is E0117 — the forgery is refused at the
// point it is manufactured, not only where it is read.
struct Holder {
    g: Grant<Net>,
}

@legal(basis: .public_data, purpose: "effect row fixture: struct-field forgery")
fn helper(h: String) with Net(connect) {
    let box = Holder { g: 7 }
    let g = box.g
    net.connect(h)
}

@legal(basis: .public_data, purpose: "effect row fixture: struct-field forgery")
fn main() {
    print("no network here")
}
