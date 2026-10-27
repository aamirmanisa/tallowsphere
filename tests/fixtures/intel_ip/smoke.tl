// End-to-end smoke for the tallow.ip N33 surface: the table path is an explicit
// local fixture, and no socket is opened anywhere in this program.
fn main() {
    let t = ip.load("tests/fixtures/intel_ip/asn-fixture.tsv")
    print("load: rows=" + t.rows + " source=" + t.source)

    let m = ip.lookup(t, "10.1.2.7")
    print("longest-prefix: asn=" + m.asn + " prefix_len=" + m.prefix_len + " country=" + m.country)
    let wide = ip.lookup(t, "10.9.9.9")
    print("wider-row: asn=" + wide.asn + " prefix_len=" + wide.prefix_len)
}
