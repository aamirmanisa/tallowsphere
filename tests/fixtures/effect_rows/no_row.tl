// G01 negative fixture: `net.connect` opens a socket, and `probe` declares no
// effect row. `@legal` is present so E0100 (the pre-existing @legal gate) cannot
// be confused with E0141 (the effect-row gate).
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(host: String) {
    net.connect(host)
}
