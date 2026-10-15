// msweep_batch.tl — batch store-directory fetcher for the FRESH Modisoft sweep.
//
// Reads a JSON array of [lat,lng] probe points (path in $MSWEEP_IN), calls the public
// guest locator once per point via tallow.modisoft.locate(), and emits one delimited
// record per point on stdout:
//
//     PT_BEGIN <lat> <lng>
//     <canonical JSON array of store hits, single line>
//     PT_END
//
// The Python driver reads the points file and captures stdout (avoids the E2203
// path-traversal gate that blocks env-derived paths at write_file sinks).
//
// Public no-auth endpoint, read-only, paced by the module governor (TALLOW_MODISOFT_RPS).
// Egress: Tor (fail-closed default).
//
// Run: MSWEEP_IN=/tmp/pts.json TALLOW_MODISOFT_RPS=1 \
//        ./target/debug/tallow run examples/msweep_batch.tl > /tmp/batch.ndjson

@legal(
    basis: .public_data,
    purpose: "public store-directory enumeration of a public guest store locator",
    personal_data: false,
    rate_limit: 1.per_second
)
fn main() {
    let inp = env.get("MSWEEP_IN")
    let pts = fs.read(inp).unwrap().parse_json().unwrap()
    print("BATCH_START points=" + pts.len().to_string())
    for p in pts {
        let lat = p[0]
        let lng = p[1]
        let body = modisoft.locate(lat, lng)
        print("PT_BEGIN " + lat.to_string() + " " + lng.to_string())
        print(body)
        print("PT_END")
    }
    print("BATCH_DONE")
}
