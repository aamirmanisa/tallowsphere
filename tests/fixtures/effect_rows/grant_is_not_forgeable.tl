// G01 P0.2: a capability cannot be forged. `Grant` is a lattice type, not a
// struct, so there is no literal, no constructor and no default: binding a
// struct value or an `int` into a `Grant<Net>` slot is an assignability error
// (E0117). `main` is used so the fixture's failure is the forgery, and the
// program performs no network operation, so E0141/E0142 cannot be what the
// assertion reads.
struct Forged {
    x: int,
}

@legal(basis: .public_data, purpose: "effect row fixture")
fn main() {
    let from_struct: Grant<Net> = Forged { x: 1 }
    let from_int: Grant<Net> = 7
    print("unreachable")
}
