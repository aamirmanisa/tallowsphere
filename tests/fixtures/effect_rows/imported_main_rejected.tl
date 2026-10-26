// G01 (audit F-11): the trust root is an item, not a spelling.
//
// This entry file imports a module that declares its own fully annotated `main`
// with `scope.grant`. Before E0147 that library function inherited `main`'s
// exemption from E0144 and could originate authority. A program's entry point is
// never a library item, so the imported `main` is refused.
import imported_main_lib

@legal(basis: .public_data, purpose: "trust root fixture")
fn main() {
    library_helper()
}
