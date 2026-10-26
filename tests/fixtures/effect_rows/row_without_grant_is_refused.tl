// G01 P0.2 negative fixture: the identical body and the identical row, with
// the capability parameter removed. The row is still declared, so E0141 must
// NOT fire — the refusal is E0142: a declared row with no `Grant<Net>` in
// scope is a promise, not an authority.
@legal(basis: .public_data, purpose: "effect row fixture")
fn scan(h: String) with Net(connect) {
    net.connect(h)
}
