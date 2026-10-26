// N-12: a user function named like a stdlib module is a function value, not a
// namespace. `db` is registered in the stdlib module table, so `let f = db`
// used to be refused as E0146 even though the program declares `fn db`.
@legal(basis: .public_data, purpose: "checker fixture: user fn shadows a module name")
fn db(x: i64) -> i64 {
    x + 1
}

@legal(basis: .public_data, purpose: "checker fixture: user fn shadows a module name")
fn main() {
    let f = db
    print(f(1))
}
