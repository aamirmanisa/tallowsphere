// Tallow IPPool Demo
// Demonstrates connection pooling with proxy rotation

fn main() {
    print("═══════════════════════════════════════════")
    print("  Tallow IPPool — Connection Pool Demo")
    print("═══════════════════════════════════════════")
    print("")

    // Create pool from proxy list
    let proxies = [
        "socks5://proxy1.example.com:1080",
        "socks5://proxy2.example.com:1080",
        "http://proxy3.example.com:8080",
        "http://proxy4.example.com:8080"
    ]
    let pool = IPPool.from_list(proxies)

    print("Pool size:    {pool.size} proxies")
    print("Rotation:     {pool.rotation}")
    print("Proxy count:  {pool.proxies.len}")
    print("")

    // Show each proxy
    print("Configured proxies:")
    var i = 0
    pool.proxies.each { proxy: String ->
        i = i + 1
        print("  [{i}] {proxy}")
    }

    print("")
    print("── Pool Map (closure processing) ─────────")

    // Use pool.map with a closure to process URLs
    let urls = [
        "https://api.example.com/data/1",
        "https://api.example.com/data/2",
        "https://api.example.com/data/3"
    ]

    // In interpreter: runs sequentially with proxy rotation
    // In compiled code: runs concurrently with real proxy SOCKS5 connections
    let results = pool.pool_map(urls, { url: String ->
        // Transform each URL (simulating processing)
        let parts = url.split("/")
        let id = parts[parts.len - 1]
        "processed item {id}"
    })

    results.each { result: String ->
        print("  {result}")
    }

    print("")
    print("── Empty Pool (direct connection) ────────")

    // Pool without proxies — direct connections
    let direct_pool = IPPool.from_list([])
    print("Direct pool size: {direct_pool.size}")

    print("")
    print("═══════════════════════════════════════════")
    print("  IPPool demo complete")
    print("═══════════════════════════════════════════")
}
