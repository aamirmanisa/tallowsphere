// End-to-end smoke for the tallow.ip surface (N33 + N37): the table path is an
// explicit local fixture, and no socket is opened anywhere in this program.
fn main() {
    let t = ip.load("tests/fixtures/intel_ip/asn-fixture.tsv")
    print("load: rows=" + t.rows + " source=" + t.source)

    let m = ip.lookup(t, "10.1.2.7")
    print("longest-prefix: asn=" + m.asn + " prefix_len=" + m.prefix_len + " country=" + m.country)
    let wide = ip.lookup(t, "10.9.9.9")
    print("wider-row: asn=" + wide.asn + " prefix_len=" + wide.prefix_len)

    let c = ip.cache_new()
    let w = ip.cache_put(c, "asn", "10.1.2.7", "AS64501 DE", 1000, 5000)
    print("put: hash=" + w.content_hash + " stored_at_ms=" + w.stored_at_ms)

    let fresh = ip.cache_get(c, "asn", "10.1.2.7", 5500)
    print("get-fresh: body=" + fresh.body + " age_ms=" + fresh.age_ms)
    print("get-fresh-stale: " + fresh.stale)

    let old = ip.cache_get(c, "asn", "10.1.2.7", 8500)
    print("get-stale: age_ms=" + old.age_ms)
    print("get-stale-flag: " + old.stale)

    let s = ip.cache_stats(c)
    print("stats: entries=" + s.entries + " sources=" + s.sources + " stale_entries=" + s.stale_entries)
}
