// G01 (audit F-12): a second `main` in the entry file is a second trust root.
//
// Both bodies were exempt from E0144 and both were checked as the entry point,
// while codegen would keep only one of them. A program has exactly one entry
// point: the duplicate is E0147.
@legal(basis: .public_data, purpose: "trust root fixture")
fn main() {
    print("first")
}

@legal(basis: .public_data, purpose: "trust root fixture")
fn main() {
    print("second")
}
