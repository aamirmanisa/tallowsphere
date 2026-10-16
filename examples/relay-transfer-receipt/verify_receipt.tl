// examples/relay-transfer-receipt/verify_receipt.tl
// Stage 3 / Slice 1 — flagship demo: verify a TallowTransfer relay receipt,
// entirely in Tallow (env.args + fs + Transfer.hash/chunk/tree_hash + process).
//
// The transfer itself rides `tallow send/receive --relay` (relay-v1 live
// pairing over the shared `tallow_protocol::transfer::relay` crate); this
// program is the independent, language-side receipt verifier.
//
// Checks:
//   1. source and received files exist
//   2. BLAKE3(source) == BLAKE3(received)              (Transfer.hash)
//   3. chunk-tree root hash equality                   (Transfer.chunk + Transfer.tree_hash)
//   4. chunk-count equality
//   5. recomputed hash == caller-supplied expected     (optional 3rd arg)
//
// Usage:
//   tallow run examples/relay-transfer-receipt/verify_receipt.tl -- <source> <received> [expected-blake3]
//
// Exits: 0 = receipt verified · 2 = mismatch · 64 = usage error.

@cra_class(.default)
fn main() {
    let args = env.args()
    if args.len < 2 {
        print("usage: tallow run verify_receipt.tl -- <source> <received> [expected-blake3]")
        process.exit(64)
    }

    let source = args[0]
    let received = args[1]
    let expected = if args.len >= 3 { args[2] } else { "" }

    if !fs.is_file(source) || !fs.is_file(received) {
        print("receipt FAIL: source or received file missing")
        process.exit(2)
    }

    let source_hash = Transfer.hash(source)
    let received_hash = Transfer.hash(received)

    let source_chunks = Transfer.chunk(source)
    let received_chunks = Transfer.chunk(received)
    let source_tree = Transfer.tree_hash(source_chunks)
    let received_tree = Transfer.tree_hash(received_chunks)

    let hash_match = source_hash == received_hash
    let tree_match = source_tree == received_tree
    let chunks_match = source_chunks.len == received_chunks.len
    let expected_match = if expected == "" { true } else { source_hash == expected }
    let ok = hash_match && tree_match && chunks_match && expected_match

    print("== TallowTransfer receipt ==============================")
    print("source     : {source}")
    print("received   : {received}")
    print("blake3     : {source_hash}")
    print("chunks     : {source_chunks.len}")
    print("tree root  : {source_tree}")
    print("checks     : hash={hash_match} tree={tree_match} chunks={chunks_match} expected={expected_match}")

    if ok {
        print("RECEIPT VERIFIED")
        process.exit(0)
    } else {
        print("RECEIPT MISMATCH")
        if !expected_match { print("  expected        : {expected}") }
        if !hash_match { print("  received blake3 : {received_hash}") }
        if !tree_match { print("  received tree   : {received_tree}") }
        process.exit(2)
    }
}
