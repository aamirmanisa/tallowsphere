// Fixture: field access through an array of structs.
//
// `xs[0].size` has an Index receiver, so the native backend cannot type it
// from the binding alone. Before the element-struct tracking landed it fell
// through to a literal 0 — a silent wrong answer, not an error. Both engines
// must agree with the source.

struct ChunkInfo {
    index: i64,
    offset: i64,
    size: i64,
    hash: String,
}

fn main() {
    let a = ChunkInfo { index: 0, offset: 0, size: 16, hash: "aa" }
    let b = ChunkInfo { index: 1, offset: 16, size: 5, hash: "bb" }
    let xs = [a, b]
    print(xs.len().to_string())
    print(xs[0].size.to_string())
    print(xs[1].offset.to_string())
    print(xs[1].hash)

    // Direct field access must keep working.
    print(a.size.to_string())
    print(b.hash)
}
