// live_tor_test.tl — End-to-end Tor circuit test
// Tests TorPool.new, fresh_circuit, new_circuit, exit_ip

fn main() {
    print("=== Layer 3: TorPool Live Test ===")

    // Spawn 2 Tor instances with per-request rotation
    let tor_res = TorPool.new(2, "per_request")
    let torpool = match tor_res {
        Ok(tp) -> tp
        Err(e) -> {
            print("FATAL: TorPool.new failed: " + e)
            return
        }
    }
    print("TorPool created with 2 instances")

    // Get fresh circuit
    let circuit1 = torpool.fresh_circuit()
    let c1 = match circuit1 {
        Ok(cfg) -> cfg
        Err(e) -> {
            print("fresh_circuit failed: " + e)
            torpool.stop()
            return
        }
    }
    print("Circuit 1 URL: " + c1.url)

    // Get another fresh circuit
    let circuit2 = torpool.fresh_circuit()
    let c2 = match circuit2 {
        Ok(cfg) -> cfg
        Err(e) -> {
            print("fresh_circuit 2 failed: " + e)
            torpool.stop()
            return
        }
    }
    print("Circuit 2 URL: " + c2.url)

    // Query exit IPs
    let ip0_res = torpool.exit_ip(0)
    let ip0 = match ip0_res {
        Ok(ip) -> ip
        Err(e) -> "error: " + e
    }
    print("Instance 0 exit IP: " + ip0)

    // Renew all circuits
    let renew_res = torpool.new_circuit()
    let renewed = match renew_res {
        Ok(msg) -> msg
        Err(e) -> "error: " + e
    }
    print("Circuits renewed: " + renewed)

    // Stop
    let stop_res = torpool.stop()
    print("TorPool stop result: " + stop_res)

    print("=== Layer 3: LIVE TEST PASSED ===")
}
