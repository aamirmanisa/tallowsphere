// Parity fixture: `StructuredData.extract` — the P2.T1 native binding.
//
// One value per line with a literal tag, deliberately: interpolating `{sd.json_ld.len}`
// would test the interpolation rules rather than the binding, and braces inside the HTML
// string literals are read as interpolation too (which is how this fixture's first draft
// broke the native build).
//
// Four documents, chosen so the two engines cannot agree by accident:
//   A  JSON-LD present (one block) + an og tag
//   B  nothing structured at all
//   C  two JSON-LD blocks, so "only the first survives" predicts a different count
//   D  og tag with content BEFORE property, so an order-sensitive reader yields nothing

fn main() {
    let a = "<html><head><meta property='og:title' content='Hello'><script type='application/ld+json'>[1]</script></head><body>hi</body></html>"
    let sd = StructuredData.extract(a)
    print("A_has")
    print(sd.has_json_ld)
    print("A_len")
    print(sd.json_ld.len)
    print("A_og_len")
    print(sd.open_graph.len)
    print("A_og_title")
    print(sd.open_graph["title"])

    let b = "<html><body>no structured data</body></html>"
    let empty = StructuredData.extract(b)
    print("B_has")
    print(empty.has_json_ld)
    print("B_len")
    print(empty.json_ld.len)
    print("B_og_len")
    print(empty.open_graph.len)

    let c = "<html><head><script type='application/ld+json'>[2]</script><script type='application/ld+json'>[3]</script></head></html>"
    let pair = StructuredData.extract(c)
    print("C_has")
    print(pair.has_json_ld)
    print("C_len")
    print(pair.json_ld.len)

    let d = "<html><head><meta content='Hello' property='og:title'></head></html>"
    let rev = StructuredData.extract(d)
    print("D_has")
    print(rev.has_json_ld)
    print("D_len")
    print(rev.json_ld.len)
    print("D_og_len")
    print(rev.open_graph.len)
    print("D_og_title")
    print(rev.open_graph["title"])
}
