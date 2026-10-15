// parity: expect-refusal
// Refusal-parity fixture: a non-string argument to `StructuredData.extract`.
//
// P2.T4 asks for the SAME refusal from both engines, not merely "both fail" — so the
// test compares the cause each engine names, not just the exit codes.

fn main() {
    let sd = StructuredData.extract(42)
    print(sd.has_json_ld)
}
