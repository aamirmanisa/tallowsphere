// N33 refusal, end to end: a table path that does not exist. Must exit non-zero
// with ip:table-missing naming the path, never with an empty table.
fn main() {
    let t = ip.load("/nonexistent/intel-ip/ip2asn-v4.tsv")
    print("unreachable: rows=" + t.rows)
}
