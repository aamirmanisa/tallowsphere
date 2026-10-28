// Phase 23: Stealth & Advanced Networking integration test
//
// Covers only the constructs that are actually implemented. The WireGuard
// tunnel, gRPC server/client and obfs4/meek/snowflake transports have no
// backend in this build: each entry point refuses with "… is not supported in
// this build (…)" instead of returning a fake success. Those refusals are
// pinned by the unit tests in src/stdlib/net.rs and by `tallow run` on
// tests/fixtures/unsupported_net.tl.

fn main() with Net(tor_pool_create), Net(onion_addr), Net(proxy_chain_create), Net(traffic_shape_create) {
    // Test TorPool type construction
    let tor = net.tor_pool_create(3)
    print("TorPool size: {tor.size}")

    // Test OnionAddr
    let addr = net.onion_addr("example.onion")
    print("OnionAddr: {addr.address}")

    // Test ProxyChain
    let chain = net.proxy_chain_create(["socks5://127.0.0.1:1080", "http://proxy.example.com:8080"])
    print("ProxyChain hops: {chain.hop_count}")

    // Test TrafficShape
    let shaper = net.traffic_shape_create(256, 100, false)
    print("TrafficShape padding: {shaper.padding}")

    print("All implemented Phase 23 types constructed successfully")
}
