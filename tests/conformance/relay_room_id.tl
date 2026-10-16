// tests/conformance/relay_room_id.tl — the Tallow-source side of the wire-conformance check.
//
// One code per invocation, because the surface's refusal is part of the contract: a code that is
// not the accepted 8-symbol shape raises "unsupported code" and stops the program (operator
// directive 2026-10-12: strict 8 only). A single program looping over all vectors would abort at
// the first refused code and never exercise the rest, which is how a refusal gets mistaken for a
// harness failure.
//
//   usage: tallow run tests/conformance/relay_room_id.tl [--target <t> | --require-native] -- <code>
//
// Prints "<code>\t<room id hex>" on success. Driven by scripts/relay_room_id_conformance.sh, which
// compares that against tests/vectors/relay_room_id.v1.txt — the values the Rust crate computes —
// and separately asserts that the codes the crate does *not* accept are refused here too.
//
// Pure function, no network, no relay contact.

fn main() {
    let args = env.args()
    if args.len >= 1 {
        let code = args[0]
        print("{code}\t{RelayRoom.room_id(code)}")
    } else {
        print("usage: relay_room_id.tl <code>")
    }
}
