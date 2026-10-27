// N33 refusal, end to end: an address no row covers. Must exit non-zero with
// ip:not-in-table, not with asn=0.
fn main() {
    let t = ip.load("tests/fixtures/intel_ip/asn-fixture.tsv")
    let m = ip.lookup(t, "203.0.113.9")
    print("unreachable: asn=" + m.asn)
}
