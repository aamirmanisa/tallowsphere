// N-10: an import that resolves to no file used to be dropped silently, so the
// program compiled against a module it never loaded.
import nosuchmodule

@legal(basis: .public_data, purpose: "checker fixture: missing import")
fn main() {
    print("compiled anyway")
}
