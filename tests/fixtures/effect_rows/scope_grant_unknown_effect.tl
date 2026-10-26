// The runtime path must not let an effect name the checker never heard of
// through: E0143 is the checker's answer and the interpreter's binding is not a
// second, weaker door.
@legal(basis: .public_data, purpose: "effect row fixture: unknown grant effect")
fn main() {
    let g = scope.grant(Bogus)
    print(g)
}
