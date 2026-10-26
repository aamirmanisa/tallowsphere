// G01 positive fixture: the identical body, with the row the gate asks for.
// G01 P0.2 adds the second half of the rule — the row must be backed by a
// capability — so the parameter list carries the `Grant<Net>` that authorises
// the call. `with Net(connect)` alone is a promise; the grant is the authority.
@legal(basis: .public_data, purpose: "effect row fixture")
fn probe(g: Grant<Net>, host: String) with Net(connect) {
    net.connect(host)
}
