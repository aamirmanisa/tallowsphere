fn main() {
    print("=== Single Tor Test ===")
    let tor_res = TorPool.new(1, "per_request")
    let torpool = match tor_res {
        Ok(tp) -> tp
        Err(e) -> {
            print("FAIL: " + e)
            return
        }
    }
    print("TorPool spawned with 1 instance")

    let ip_res = torpool.exit_ip(0)
    let ip = match ip_res {
        Ok(addr) -> addr
        Err(e) -> "error: " + e
    }
    print("Exit IP: " + ip)

    torpool.stop()
    print("=== PASS ===")
}
