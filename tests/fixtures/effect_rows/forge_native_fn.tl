// G01 P0.2 / audit F-5: a `native fn` has no body, so it cannot be a producer.
//
// There is nothing for the return-position check to walk, which used to make a
// `-> Grant<Net>` declaration a mint: the symbol is supplied at link time and
// no `scope.grant` call backs it. `scope.grant` is the only declared producer,
// so a native capability result is E0145.
native fn get_grant() -> Grant<Net>

@legal(basis: .public_data, purpose: "effect row fixture: native producer")
fn helper(h: String) with Net(connect) {
    let g = get_grant()
    net.connect(h)
}

@legal(basis: .public_data, purpose: "effect row fixture: native producer")
fn main() {
    print("no network here")
}
