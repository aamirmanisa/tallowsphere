// G01 P0.2 negative fixture: the argument of a capability type is an *effect
// name the checker can enforce*, so `Grant<Bogus>` is E0143 — not an unknown
// type that quietly becomes a promise nothing verifies. No network call is
// made, so E0141/E0142 cannot be what the assertion reads.
@legal(basis: .public_data, purpose: "effect row fixture")
fn scan(g: Grant<Bogus>) {
    print("no network operation in this body")
}
