// N-9: the refusal is correct (an imported `main` is E0147), but the caret used
// to be drawn against this file's text instead of the imported module's.
import n9_imported_main_lib

@legal(basis: .public_data, purpose: "checker fixture: imported main span")
fn main() {
    print("entry")
}
