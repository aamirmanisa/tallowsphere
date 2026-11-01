# W12 surface census — the primitives the egress gate's predicate cannot see

Lane: quarry. Tree: `/home/aamir/tallow-worktrees/w12/quarry`, branch `rel/w12-quarry`,
HEAD `758e5bc`. Read-only: no source edited, no `cargo` run, nothing gated.

## 1. What I measured, and what the meter measures

The coverage gate is `tests/egress_gate_coverage.rs`. Its predicate is a set of
substrings applied line-by-line to every `.rs` file under `src/`:

- HTTP: `egress_http::` / `ureq::` / `reqwest::` followed by one of
  `get( post( put( delete( head( patch( request(`, plus `egress_http::agent(`,
  `egress_http::agent_with_timeouts(`, `egress_http::Agent::config_builder(`;
- reqwest client constructors (`reqwest::Client::new`, `.builder`, `blocking::` variants);
- raw: `TcpStream::connect(`, `UdpSocket::connect(`, `connect_timeout(`.

Gating is then decided **per file**, not per site: a file is "gated" if its
production region contains the substring `scope::require` anywhere.

I ported that predicate to Python (`gate_sim.py`) and ran it over the same tree.
It reproduces the shape the brief describes — 10 debt files, 0 ungated files —
but gives **47 gated files, not 48**, over **595 `.rs` files, not ~596**. Two
premises in the brief are therefore off by one; I could not reproduce 48 by any
reading of the predicate and I am not going to round. The 0-ungated result is
robust and reproduces exactly.

A second, wider meter exists and the brief does not mention it:
`tests/egress_census.rs` classifies **files** against `ureq::`, `reqwest`,
`hickory_resolver`, `TcpStream::connect`, `UdpSocket::bind`, `UdpSocket::connect`
plus a resolver census over `lookup_host(` / `to_socket_addrs(`. It is a file
allowlist with written reasons. It is wider than the coverage gate on DNS and
`UdpSocket::bind`, and it is still blind to everything in sections 4.1, 4.2,
4.5, 4.6, 4.7 and 4.10 below.

### Counting rule (disagree with this, not with the reality)

1. **Population.** Every `src/**/*.rs` file: 595 files.
2. **Production region.** The bytes before the first `#[cfg(test)]`. This cut
   applied to **474 of 595 files**; the other 121 have no test module. Every
   site below is in a production region. Test-only occurrences were dropped, not
   counted — e.g. `src/stdlib/net.rs:3130` `TcpStream::connect(&addr_clone)` and
   `src/browser/observability.rs:576`'s test client are out.
3. **Site.** One *line* that **invokes** a network-capable primitive (call form:
   `connect(`, `bind(`, `send_to(`, `send_to`, `connect_async(`, `libc::socket(`,
   `Command::new(`, `Endpoint::client/server`, `.connect(addr`). Imports (`use
   tokio::net::TcpStream;`), type positions (`, conn: quinn::Connection`),
   return types and doc comments are **not** sites. One row per line, first
   matching class wins.
4. **Gated.** A `crate::scope::require` call appears **earlier in the same
   enclosing function body** than the site. This is deliberately stricter than
   the gate, which asks only whether the string appears anywhere in the file.
   "Gated" here means the connect has an authorization decision in its own
   function, above it.
5. **Predicate-visible.** The site's line matches one of the gate's needles
   (`has_http(line) or has_raw(line)` from the port).
6. **Predicate-classifies-gated.** Predicate-visible *and* the site's file
   contains `scope::require` (the gate's actual rule). Debt files are excluded
   from that bucket, exactly as the gate excludes them.

Consequences a reader should be able to attack: a `require` that runs *after*
the connect counts as ungated under rule 4 (there are none — I checked the 12
gated rows by hand); a `require` in a caller three frames up counts as ungated
(several of the DEBT justifications are exactly that claim, and section 5 tests
it). A wrapper that gates and is called by an ungated function is counted once,
at the socket.

## 2. Headline numbers

| measure | count |
|---|---|
| network-capable **sites** in production regions (rule 3) | **176** |
| sites with `scope::require` earlier in the **same fn** (rule 4) | **12** |
| sites with no such require — **genuinely ungated** | **164** |
| sites the current predicate can **see** (rule 5) | **41** |
| …of those, in files the gate reports **gated** (rule 6) | **26** |
| …of those, in **DEBT** files | **15** |
| sites the predicate **cannot see** (blind) | **135** |
| …blind, in files the gate reports **gated** — false credit | **61** |
| …blind, in DEBT files | **34** |
| …blind, in files the gate never examines (no predicate line at all) | **40** |
| sites the gate would classify as gated | **26** |
| difference: 26 classified gated − 12 actually gated | **14** |
| difference: 164 genuinely ungated − 0 the gate reports | **164** |

Read the last two rows together: the gate reports **zero** ungated files and is
right about that, because it never asked about 135 of the 176 sites. Its
"gated" bucket credits 26 sites; 9 of those have a require in their own
function, 3 more are truly gated but invisible to it (section 4), and the rest
are covered by a `require` somewhere else in the file. The 164 genuinely ungated
sites are not a regression the gate missed — they are primitives the predicate
has no word for.

One more number that matters: of the 87 sites that live in files the gate calls gated,
**75 have no require in their enclosing function**. The file-level rule
turns one `require` into a blanket pass for the whole file.

## 3. Where the numbers come from (reproduction)

```
python3 <scratch>/census2.py   # writes census2.json: 595 files, 225 rows, 176 call sites
python3 <scratch>/gate_sim.py  # 595 files, gated 47, debt 10, ungated 0
```

No `cargo` invocation was made in this lane, so there is no `test result:` line
to quote: the brief's box rule says at most one cargo call, and a read-only
census that edits nothing has nothing to test. The gate port is a faithful
transcription of the Rust source cited above (same needle lists, same
`production_region`, same `is_comment`, same DEBT skip order) and its output is
stated above as a **port result, not a test run**.


### 4.1 quinn / QUIC endpoints and handshakes — 11 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/browser/distributed/relay.rs:48` | `start` | no | src/main.rs:7667, src/main.rs:8361 | `let endpoint = quinn::Endpoint::server(config, self.addr)` |
| `src/stdlib/net.rs:343` | `quic_connect_async` | no | src/stdlib/net.rs:294 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:1466` | `quic_send_file_resume` | no | src/stdlib/transfer_net.rs:1530, src/stdlib/transfer_net.rs:5122 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:1687` | `quic_listen` | no | src/stdlib/transfer_net.rs:4990, src/stdlib/transfer_net.rs:1516 | `quinn::Endpoint::server(server_config, addr)` |
| `src/stdlib/transfer_net.rs:1766` | `quic_connect` | no | src/stdlib/net.rs:211, src/stdlib/net.rs:211 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:1835` | `quic_send_file` | no | src/stdlib/transfer_net.rs:1518, src/stdlib/transfer_net.rs:1518 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:1940` | `quic_receive_file` | no | src/stdlib/transfer_net.rs:1519, src/stdlib/transfer_net.rs:1519 | `let endpoint = quinn::Endpoint::server(server_config, addr)` |
| `src/stdlib/transfer_net.rs:2072` | `quic_send_bytes` | no | src/stdlib/transfer_net.rs:1520, src/stdlib/transfer_net.rs:1520 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:3316` | `quic_send_file_streaming` | no | src/stdlib/transfer_net.rs:1556 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:3927` | `quic_send_dir_structured` | no | src/main.rs:5518, src/stdlib/transfer_net.rs:1563 | `let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())` |
| `src/stdlib/transfer_net.rs:4003` | `quic_receive_dir` | no | src/stdlib/transfer_net.rs:1564, src/stdlib/transfer_net.rs:1564 | `let endpoint = quinn::Endpoint::server(server_config, addr)` |


### 4.2 quinn handshake: `endpoint.connect(addr, ..)` (method form) — 7 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/stdlib/net.rs:360` | `quic_connect_async` | no | src/stdlib/net.rs:294 | `.connect(addr, host)` |
| `src/stdlib/transfer_net.rs:1472` | `quic_send_file_resume` | no | src/stdlib/transfer_net.rs:1530, src/stdlib/transfer_net.rs:5122 | `.connect(addr, "tallow-transfer")` |
| `src/stdlib/transfer_net.rs:1771` | `quic_connect` | no | src/stdlib/net.rs:211, src/stdlib/net.rs:211 | `.connect(addr, &server_name)` |
| `src/stdlib/transfer_net.rs:1844` | `quic_send_file` | no | src/stdlib/transfer_net.rs:1518, src/stdlib/transfer_net.rs:1518 | `.connect(addr, "tallow-transfer")` |
| `src/stdlib/transfer_net.rs:2080` | `quic_send_bytes` | no | src/stdlib/transfer_net.rs:1520, src/stdlib/transfer_net.rs:1520 | `.connect(addr, "tallow-transfer")` |
| `src/stdlib/transfer_net.rs:3321` | `quic_send_file_streaming` | no | src/stdlib/transfer_net.rs:1556 | `let conn = endpoint.connect(addr, "tallow-transfer")` |
| `src/stdlib/transfer_net.rs:3934` | `quic_send_dir_structured` | no | src/main.rs:5518, src/stdlib/transfer_net.rs:1563 | `.connect(addr, "tallow-transfer")` |


### 4.3 std::net TcpStream / TcpListener — 55 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/browser/ipv6_pool.rs:650` | `rotate_via_http` | **yes** | src/browser/ipv6_pool.rs:394 | `let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&add` |
| `src/browser/network_stealth.rs:271` | `happy_eyeballs_connect_family` | **yes** | src/browser/network_stealth.rs:190, src/browser/network_stealth.rs:206 | `return tokio::time::timeout(timeout, TcpStream::connect(v4[0]))` |
| `src/browser/network_stealth.rs:276` | `happy_eyeballs_connect_family` | **yes** | src/browser/network_stealth.rs:190, src/browser/network_stealth.rs:206 | `return tokio::time::timeout(timeout, TcpStream::connect(v6[0]))` |
| `src/browser/network_stealth.rs:284` | `happy_eyeballs_connect_family` | **yes** | src/browser/network_stealth.rs:190, src/browser/network_stealth.rs:206 | `result = TcpStream::connect(v6[0]) => result,` |
| `src/browser/network_stealth.rs:287` | `happy_eyeballs_connect_family` | **yes** | src/browser/network_stealth.rs:190, src/browser/network_stealth.rs:206 | `TcpStream::connect(v4[0]).await` |
| `src/browser/observability.rs:428` | `serve_metrics` | no | src/browser/observability.rs:576, src/browser/observability.rs:604 | `let listener = TcpListener::bind(("127.0.0.1", port))?;` |
| `src/browser/process.rs:936` | `discover_ws_url_via_http` | no | src/browser/process.rs:696 | `match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {` |
| `src/browser/process.rs:1063` | `find_available_port` | no | src/browser/process.rs:371, src/browser/process.rs:1765 | `let listener = TcpListener::bind("127.0.0.1:0")?;` |
| `src/browser/proxy.rs:653` | `check_proxy_health` | **yes** | src/browser/proxy.rs:820 | `let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))` |
| `src/browser/socks_shim.rs:108` | `spawn_for_credentials` | no | src/browser/process.rs:510, src/browser/socks_shim.rs:316 | `TcpListener::bind("127.0.0.1:0").map_err(\|e\| format!("bind loopback relay: {e}"))?;` |
| `src/browser/socks_shim.rs:196` | `handle_conn` | no | src/browser/socks_shim.rs:140 | `let mut up = match TcpStream::connect_timeout(&upstream, UPSTREAM_CONNECT_TIMEOUT) {` |
| `src/cli/fingerprint_audit_cmd.rs:1516` | `build_egress` | no | src/cli/fingerprint_audit_cmd.rs:1607 | `Ok(addr) => match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {` |
| `src/cli/request_plan_cmd.rs:972` | `loopback_get` | no | src/cli/request_plan_cmd.rs:1029 | `let mut stream = match std::net::TcpStream::connect_timeout(` |
| `src/cli/veil_cmd.rs:195` | `connect_tor` | no | src/cli/veil_cmd.rs:148 | `let mut s = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {` |
| `src/cli/veil_cmd.rs:273` | `connect_mesh` | no | src/cli/veil_cmd.rs:149 | `TcpStream::connect_timeout(&a, CONNECT_TIMEOUT)` |
| `src/cli/veil_cmd.rs:289` | `connect_mesh` | no | src/cli/veil_cmd.rs:149 | `TcpStream::connect_timeout(&a, CONNECT_TIMEOUT)` |
| `src/cli/veil_cmd.rs:485` | `bridge_serve` | no | src/cli/veil_cmd.rs:475 | `let listener = match TcpListener::bind((bind, port)) {` |
| `src/cli/veil_cmd.rs:589` | `bridge_conn` | no | src/cli/veil_cmd.rs:502 | `let up = match TcpStream::connect_timeout(&SocketAddr::from((ip, target.1)), CONNECT_T` |
| `src/main.rs:2321` | `detect_public_ip` | no | src/main.rs:2463, src/main.rs:22007 | `match std::net::TcpStream::connect("8.8.8.8:80") {` |
| `src/main.rs:2455` | `run_signal_server` | no | src/main.rs:6399 | `let listener = match std::net::TcpListener::bind(&bind_addr) {` |
| `src/main.rs:2542` | `run_relay_chat` | no | src/main.rs:7084, src/main.rs:7198 | `if let Ok(mut s) = TcpStream::connect(&relay_owned) {` |
| `src/main.rs:2570` | `run_relay_chat` | no | src/main.rs:7084, src/main.rs:7198 | `let _ = TcpStream::connect(&relay_owned).and_then(\|mut s\| {` |
| `src/main.rs:2622` | `run_relay_chat` | no | src/main.rs:7084, src/main.rs:7198 | `match TcpStream::connect(relay_addr) {` |
| `src/main.rs:5764` | `real_main` | no | src/main.rs:2794 | `match std::net::TcpStream::connect(sig_addr.as_str()) {` |
| `src/main.rs:6043` | `real_main` | no | src/main.rs:2794 | `match std::net::TcpStream::connect(sig_addr.as_str()) {` |
| `src/main.rs:8403` | `real_main` | no | src/main.rs:2794 | `std::net::TcpStream::connect_timeout(` |
| `src/mesh/remote.rs:88` | `bind` | no | src/interp.rs:36386, src/main.rs:2455 | `let listener = TcpListener::bind(addr).map_err(\|e\| format!("bind {addr}: {e}"))?;` |
| `src/mesh/remote.rs:617` | `run_worker` | **yes** | src/main.rs:22108, src/mesh/remote.rs:751 | `let mut stream = TcpStream::connect(addr).map_err(\|e\| format!("connect {addr}: {e}"))?` |
| `src/net/ip_pool.rs:129` | `acquire_connection` | no | src/net/ip_pool.rs:305, src/net/ip_pool.rs:342 | `let listener = std::net::TcpListener::bind(("127.0.0.1", 0u16))` |
| `src/runtime/net_ffi.rs:37` | `tallow_net_connect` | **yes** | src/codegen.rs:2487, src/codegen.rs:30465 | `match TcpStream::connect(addr_str) {` |
| `src/runtime/net_ffi.rs:57` | `tallow_net_listen` | no | src/codegen.rs:2488, src/codegen.rs:30498 | `match TcpListener::bind(addr_str) {` |
| `src/stdlib/email.rs:44` | `connect` | no | src/interp.rs:11971, src/interp.rs:36411 | `let stream = TcpStream::connect_timeout(` |
| `src/stdlib/http.rs:1112` | `http_listen` | no | src/stdlib/http.rs:31, src/stdlib/http.rs:34 | `let listener = TcpListener::bind(&addr).map_err(\|e\| format!("http.listen: {e}"))?;` |
| `src/stdlib/mesh.rs:271` | `bind_with_retry` | no | src/stdlib/mesh.rs:222 | `match TcpListener::bind(("127.0.0.1", port)) {` |
| `src/stdlib/mesh.rs:482` | `mesh_node_join` | no | src/stdlib/mesh.rs:431, src/stdlib/mesh.rs:725 | `let stream = match TcpStream::connect(&addr) {` |
| `src/stdlib/net.rs:980` | `tcp_endpoint_reachable` | no | src/stdlib/net.rs:1063, src/stdlib/net.rs:1064 | `std::net::TcpStream::connect_timeout(&sa, Duration::from_millis(200)).is_ok()` |
| `src/stdlib/net.rs:1739` | `net_connect` | **yes** | src/stdlib/net.rs:227 | `match TcpStream::connect(&addr) {` |
| `src/stdlib/net.rs:1782` | `net_listen` | no | src/stdlib/net.rs:3109, src/stdlib/net.rs:3156 | `let listener = TcpListener::bind(&addr)` |
| `src/stdlib/osint.rs:1108` | `whois_stream` | no | src/stdlib/osint.rs:1146, src/stdlib/osint.rs:6622 | `return TcpStream::connect_timeout(` |
| `src/stdlib/osint.rs:3132` | `scanner_scan` | no | src/stdlib/osint.rs:123 | `std::net::TcpStream::connect_timeout(` |
| `src/stdlib/topology.rs:407` | `connect_probe` | no | src/stdlib/topology.rs:3096 | `match TcpStream::connect_timeout(&SocketAddr::from((target, port)), timeout) {` |
| `src/stdlib/topology.rs:499` | `connect_probe_v6` | no | src/stdlib/topology.rs:1277 | `match TcpStream::connect_timeout(&sock, timeout) {` |
| `src/stdlib/topology.rs:1613` | `tls_posture_fn` | no | src/stdlib/topology.rs:2673 | `let mut sock = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), ti` |
| `src/stdlib/topology.rs:1783` | `banner_fn` | no | src/stdlib/topology.rs:2674 | `let mut sock = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), ti` |
| `src/stdlib/topology.rs:2110` | `ja4_fn` | no | src/stdlib/topology.rs:2675 | `let mut sock = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), ti` |
| `src/stdlib/transfer_net.rs:264` | `relay_start` | no | src/stdlib/transfer_net.rs:5097, src/stdlib/transfer_net.rs:1525 | `let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))` |
| `src/stdlib/transfer_net.rs:1003` | `relay_direct_connect` | no | src/stdlib/transfer_net.rs:974 | `return std::net::TcpStream::connect(addr)` |
| `src/stdlib/transfer_net.rs:1193` | `relay_send_v0` | no | src/stdlib/transfer_net.rs:1092 | `let mut stream = tokio::net::TcpStream::connect(relay_addr).await` |
| `src/stdlib/transfer_net.rs:1365` | `relay_receive_v0` | no | src/stdlib/transfer_net.rs:1253 | `let mut stream = tokio::net::TcpStream::connect(relay_addr).await` |
| `src/stdlib/transfer_net.rs:3170` | `send_text` | no | src/stdlib/transfer_net.rs:6099, src/stdlib/transfer_net.rs:6118 | `let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))` |
| `src/stdlib/transfer_net.rs:3521` | `broadcast_send` | no | src/stdlib/transfer_net.rs:1560, src/stdlib/transfer_net.rs:1560 | `match std::net::TcpStream::connect_timeout(` |
| `src/stdlib/transfer_net.rs:3575` | `speed_test` | no | src/stdlib/transfer_net.rs:1561, src/stdlib/transfer_net.rs:1561 | `let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))` |
| `src/stdlib/transfer_net.rs:4248` | `share_by_link` | no | src/stdlib/transfer_net.rs:7040, src/stdlib/transfer_net.rs:1568 | `let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))` |
| `src/stdlib/transfer_net.rs:4444` | `browser_live_share` | no | src/stdlib/transfer_net.rs:1570, src/stdlib/transfer_net.rs:1570 | `let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))` |
| `src/stdlib/ws.rs:108` | `connect` | no | src/interp.rs:11971, src/interp.rs:36411 | `let tcp = TcpStream::connect_timeout(` |


### 4.4 std::net UdpSocket (bind / send_to) — 23 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/cli/veil_cmd.rs:635` | `mesh_resolve` | no | src/cli/veil_cmd.rs:574 | `let sock = UdpSocket::bind("0.0.0.0:0").map_err(\|e\| e.to_string())?;` |
| `src/cli/veil_cmd.rs:638` | `mesh_resolve` | no | src/cli/veil_cmd.rs:574 | `sock.send_to(&q, dns).map_err(\|e\| e.to_string())?;` |
| `src/stdlib/net.rs:1802` | `net_listen` | no | src/stdlib/net.rs:3109, src/stdlib/net.rs:3156 | `let socket = UdpSocket::bind(&addr)` |
| `src/stdlib/net.rs:1967` | `net_udp_send` | no | src/stdlib/net.rs:234, src/stdlib/net.rs:2037 | `let sent = socket.send_to(data.as_bytes(), &addr)` |
| `src/stdlib/topology.rs:701` | `udp_source_v6` | no | src/stdlib/topology.rs:611 | `let sock = std::net::UdpSocket::bind("[::]:0")?;` |
| `src/stdlib/topology.rs:743` | `source_for` | no | src/stdlib/topology.rs:1145, src/stdlib/topology.rs:3117 | `let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;` |
| `src/stdlib/topology.rs:2286` | `udp_scan_fn` | no | src/stdlib/topology.rs:2676, src/stdlib/topology.rs:2939 | `let sock = match UdpSocket::bind("0.0.0.0:0") {` |
| `src/stdlib/topology.rs:2547` | `traceroute_fn` | no | src/stdlib/topology.rs:2679 | `let sock = match UdpSocket::bind("0.0.0.0:0") {` |
| `src/stdlib/transfer.rs:1037` | `dht_create` | no | src/stdlib/transfer.rs:94, src/stdlib/transfer.rs:94 | `let socket_bound = match std::net::UdpSocket::bind(&bind_addr) {` |
| `src/stdlib/transfer.rs:1071` | `dht_announce` | no | src/stdlib/transfer.rs:95, src/stdlib/transfer.rs:95 | `if sock.send_to(msg.as_bytes(), peer_addr).is_ok() {` |
| `src/stdlib/transfer.rs:1107` | `dht_lookup` | no | src/stdlib/transfer.rs:96, src/stdlib/transfer.rs:96 | `let _ = sock.send_to(msg.as_bytes(), peer_addr);` |
| `src/stdlib/transfer.rs:1113` | `dht_lookup` | no | src/stdlib/transfer.rs:96, src/stdlib/transfer.rs:96 | `if let Ok((n, _src)) = std::net::UdpSocket::bind("0.0.0.0:0")` |
| `src/stdlib/transfer.rs:1433` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `let local_ip: Option<std::net::IpAddr> = UdpSocket::bind("0.0.0.0:0")` |
| `src/stdlib/transfer.rs:1459` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `let probe = UdpSocket::bind("0.0.0.0:6881")` |
| `src/stdlib/transfer.rs:1460` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `.or_else(\|_\| UdpSocket::bind("0.0.0.0:0"))` |
| `src/stdlib/transfer.rs:1472` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `let _ = probe.send_to(announce.as_bytes(), "255.255.255.255:6881");` |
| `src/stdlib/transfer.rs:1473` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `let _ = probe.send_to(announce.as_bytes(), "127.0.0.1:6881");` |
| `src/stdlib/transfer.rs:1484` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `let _ = probe.send_to(reply.as_bytes(), src);` |
| `src/stdlib/transfer_net.rs:3223` | `stun_discover` | no | src/stdlib/transfer_net.rs:1553, src/stdlib/transfer_net.rs:1553 | `let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();` |
| `src/stdlib/transfer_net.rs:3257` | `hole_punch` | no | src/stdlib/transfer_net.rs:6184, src/stdlib/transfer_net.rs:6243 | `let result = std::net::UdpSocket::bind(format!("0.0.0.0:{}", local_port));` |
| `src/stdlib/transfer_net.rs:3262` | `hole_punch` | no | src/stdlib/transfer_net.rs:6184, src/stdlib/transfer_net.rs:6243 | `let _ = socket.send_to(b"TALLOW-PUNCH", &peer_addr);` |
| `src/stdlib/transfer_net.rs:4255` | `share_by_link` | no | src/stdlib/transfer_net.rs:7040, src/stdlib/transfer_net.rs:1568 | `let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();` |
| `src/stdlib/transfer_net.rs:4449` | `browser_live_share` | no | src/stdlib/transfer_net.rs:1570, src/stdlib/transfer_net.rs:1570 | `let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();` |


### 4.5 UdpSocket connect-by-method (`sock.connect("8.8.8.8:80")`) — 4 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/stdlib/transfer.rs:1435` | `lan_discover` | no | src/stdlib/transfer.rs:76, src/stdlib/transfer.rs:76 | `.and_then(\|sock\| sock.connect("8.8.8.8:80").ok().map(\|_\| sock))` |
| `src/stdlib/transfer_net.rs:3226` | `stun_discover` | no | src/stdlib/transfer_net.rs:1553, src/stdlib/transfer_net.rs:1553 | `s.connect("8.8.8.8:80").ok()?;` |
| `src/stdlib/transfer_net.rs:4258` | `share_by_link` | no | src/stdlib/transfer_net.rs:7040, src/stdlib/transfer_net.rs:1568 | `s.connect("8.8.8.8:80").ok()?;` |
| `src/stdlib/transfer_net.rs:4452` | `browser_live_share` | no | src/stdlib/transfer_net.rs:1570, src/stdlib/transfer_net.rs:1570 | `s.connect("8.8.8.8:80").ok()?;` |


### 4.6 WebSocket connect (`tokio_tungstenite::connect_async`) — 3 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/browser/cdp.rs:409` | `connect` | no | src/interp.rs:11971, src/interp.rs:36411 | `let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)` |
| `src/stdlib/net.rs:574` | `ws_connect` | no | src/stdlib/net.rs:212, src/stdlib/net.rs:212 | `let (ws_stream, _response) = tokio_tungstenite::connect_async(&url_for_async)` |
| `src/stdlib/relay_room.rs:134` | `(none: top-level item)` | no | — | `let (mut ws, _response) = tokio_tungstenite::connect_async(url)` |


### 4.7 Raw sockets (`libc::socket`, AF_INET/AF_INET6) — 4 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/stdlib/topology.rs:593` | `icmpv6_echo` | no | src/stdlib/topology.rs:1345 | `let fd = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6);` |
| `src/stdlib/topology.rs:714` | `open` | no | src/agent_ledger.rs:538, src/agent_ledger.rs:545 | `let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);` |
| `src/stdlib/topology.rs:832` | `icmp_echo` | no | src/stdlib/topology.rs:1125 | `let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);` |
| `src/stdlib/topology.rs:2514` | `traceroute_fn` | no | src/stdlib/topology.rs:2679 | `let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };` |


### 4.8 tokio::net (lookup_host) — 3 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/browser/network_stealth.rs:250` | `happy_eyeballs_connect_family` | **yes** | src/browser/network_stealth.rs:190, src/browser/network_stealth.rs:206 | `let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))` |
| `src/browser/network_stealth.rs:324` | `prefetch` | no | — | `match tokio::net::lookup_host(format!("{}:443", domain)).await {` |
| `src/stdlib/net.rs:353` | `quic_connect_async` | no | src/stdlib/net.rs:294 | `let addr = tokio::net::lookup_host(format!("{host}:{port}"))` |


### 4.9 DNS resolution that implies a socket — 3 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/stdlib/net.rs:845` | `resolve_doh` | no | src/stdlib/net.rs:819, src/stdlib/net.rs:822 | `.lookup_ip(&host)` |
| `src/stdlib/osint.rs:477` | `enumerate_dns_brute` | no | src/stdlib/osint.rs:375, src/stdlib/osint.rs:6104 | `if std::net::ToSocketAddrs::to_socket_addrs(&addr.as_str()).is_ok() {` |
| `src/stdlib/osint.rs:1237` | `domain_intel_dns_history` | no | src/stdlib/osint.rs:114 | `if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!("{domain}:80").as` |


### 4.10 Browser CDP endpoints — 0 sites

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|


### 4.11 Child-process launch (`Command::new`) — 63 sites

Every one of these launches an external binary; a launched browser is
network-capable by construction. The brief names `curl`/`wget`/`tallow`
and `sh -c` with a URL as the class to look for — **there are zero
`curl` or `wget` launches in this tree.** The two `sh -c` sites carry no
URL (section 6).

| site | enclosing fn | require before | caller | line |
|---|---|---|---|---|
| `src/bin/pm.rs:55` | `run_tallow` | no | src/bin/pm.rs:164, src/bin/pm.rs:184 | `let status = process::Command::new(&binary)` |
| `src/browser/ipv6_pool.rs:689` | `rotate_via_at_command` | no | src/browser/ipv6_pool.rs:399 | `let off = Command::new("sh")` |
| `src/browser/ipv6_pool.rs:707` | `rotate_via_at_command` | no | src/browser/ipv6_pool.rs:399 | `let on = Command::new("sh")` |
| `src/browser/ipv6_pool.rs:729` | `rotate_via_adb` | no | src/browser/ipv6_pool.rs:404 | `let on = Command::new("adb")` |
| `src/browser/ipv6_pool.rs:753` | `rotate_via_adb` | no | src/browser/ipv6_pool.rs:404 | `let off = Command::new("adb")` |
| `src/browser/juggler.rs:91` | `launch` | no | src/interp.rs:11969, src/main.rs:7726 | `let mut cmd = Command::new(&config.chrome_path);` |
| `src/browser/process.rs:400` | `launch` | no | src/interp.rs:11969, src/main.rs:7726 | `let mut cmd = Command::new(&config.chrome_path);` |
| `src/browser/process.rs:1397` | `process_is_alive` | no | src/browser/process.rs:1265, src/browser/process.rs:1364 | `match Command::new("tasklist")` |
| `src/browser/recording.rs:175` | `find_ffmpeg` | no | src/browser/recording.rs:191, src/browser/recording.rs:223 | `let ok = Command::new(candidate)` |
| `src/browser/recording.rs:226` | `encode_with_ffmpeg` | no | src/browser/recording.rs:488 | `let status = Command::new(ffmpeg_bin)` |
| `src/browser/scheduler.rs:889` | `execute_scheduled_script` | no | src/browser/scheduler.rs:859 | `let mut cmd = std::process::Command::new(&exe);` |
| `src/browser/trace.rs:449` | `open_trace_viewer` | no | — | `let _ = std::process::Command::new("cmd")` |
| `src/browser/trace.rs:455` | `open_trace_viewer` | no | — | `let _ = std::process::Command::new("open")` |
| `src/browser/trace.rs:461` | `open_trace_viewer` | no | — | `let _ = std::process::Command::new("xdg-open")` |
| `src/cli/doctest_cmd.rs:188` | `run_leg` | no | src/cli/doctest_cmd.rs:334, src/cli/doctest_cmd.rs:335 | `let mut child = Command::new(bin)` |
| `src/cli/never_probe.rs:49` | `run_never_probe` | no | src/main.rs:2905 | `let output = match Command::new("bash")` |
| `src/cli/sandbox_cmd.rs:57` | `run_confined_self` | no | src/main.rs:10939 | `let mut cmd = Command::new(&exe);` |
| `src/codegen.rs:1332` | `compile_with_target_and_source_dir` | no | src/main.rs:10823, src/main.rs:10991 | `let mut cmd = std::process::Command::new(&clang);` |
| `src/gate/docs_examples.rs:219` | `run_with_timeout` | no | src/gate/docs_examples.rs:311 | `let mut child = Command::new(binary)` |
| `src/gate/sbom.rs:69` | `cargo_metadata` | no | src/gate/sbom.rs:109 | `let offline = Command::new("cargo")` |
| `src/gate/sbom.rs:87` | `cargo_metadata` | no | src/gate/sbom.rs:109 | `let online = Command::new("cargo")` |
| `src/interp.rs:12406` | `call_function` | **yes** | src/interp.rs:2057, src/interp.rs:3397 | `let mut cmd = std::process::Command::new(&exe);` |
| `src/interp.rs:13014` | `call_function` | **yes** | src/interp.rs:2057, src/interp.rs:3397 | `return match std::process::Command::new(&cmd).args(&args_list).output() {` |
| `src/main.rs:2110` | `which_ffmpeg` | no | src/main.rs:2149, src/main.rs:2258 | `let ok = std::process::Command::new(candidate)` |
| `src/main.rs:2150` | `ffmpeg_install` | no | src/main.rs:8453 | `let version_out = std::process::Command::new(&path)` |
| `src/main.rs:2167` | `ffmpeg_install` | no | src/main.rs:8453 | `let winget_ok = std::process::Command::new("winget")` |
| `src/main.rs:2183` | `ffmpeg_install` | no | src/main.rs:8453 | `let choco_ok = std::process::Command::new("choco")` |
| `src/main.rs:2203` | `ffmpeg_install` | no | src/main.rs:8453 | `let brew_ok = std::process::Command::new("brew")` |
| `src/main.rs:2220` | `ffmpeg_install` | no | src/main.rs:8453 | `let apt_ok = std::process::Command::new("sudo")` |
| `src/main.rs:2230` | `ffmpeg_install` | no | src/main.rs:8453 | `let dnf_ok = std::process::Command::new("sudo")` |
| `src/main.rs:2240` | `ffmpeg_install` | no | src/main.rs:8453 | `let pacman_ok = std::process::Command::new("sudo")` |
| `src/main.rs:2269` | `ffmpeg_version` | no | src/main.rs:8455 | `match std::process::Command::new("ffmpeg")` |
| `src/main.rs:2645` | `cargo_metadata_ok` | no | src/main.rs:6715 | `std::process::Command::new("cargo")` |
| `src/main.rs:4813` | `real_main` | no | src/main.rs:2794 | `let _ = std::process::Command::new("chown")` |
| `src/main.rs:4973` | `real_main` | no | src/main.rs:2794 | `let icacls_check = SysCommand::new("icacls").arg("/?").output();` |
| `src/main.rs:4984` | `real_main` | no | src/main.rs:2794 | `let save_ok = SysCommand::new("icacls")` |
| `src/main.rs:4992` | `real_main` | no | src/main.rs:2794 | `let restore_ok = SysCommand::new("icacls")` |
| `src/main.rs:8048` | `real_main` | no | src/main.rs:2794 | `let mut cmd = std::process::Command::new(&exe);` |
| `src/main.rs:8275` | `real_main` | no | src/main.rs:2794 | `let status = std::process::Command::new(&editor).arg(&path).status();` |
| `src/main.rs:10999` | `real_main` | no | src/main.rs:2794 | `let run = std::process::Command::new(&native_out)` |
| `src/mcp/client.rs:60` | `connect` | no | src/interp.rs:11971, src/interp.rs:36411 | `let mut child = Command::new(program)` |
| `src/pkg/cache.rs:575` | `link_all_batch_junction` | no | src/pkg/cache.rs:260 | `let status = std::process::Command::new("cmd")` |
| `src/pkg/cache.rs:618` | `create_dir_link` | no | src/pkg/cache.rs:225 | `let status = std::process::Command::new("cmd")` |
| `src/pkg/enterprise.rs:751` | `workspace_run` | no | src/main.rs:10166 | `let status = std::process::Command::new(&tallow_exe)` |
| `src/runtime/io_uring_runtime.rs:123` | `check_kernel_version` | no | src/runtime/io_uring_runtime.rs:113 | `let output = std::process::Command::new("uname")` |
| `src/runtime/process_ffi.rs:134` | `run_with_args` | no | src/runtime/process_ffi.rs:80, src/runtime/process_ffi.rs:129 | `match std::process::Command::new(cmd).args(args).output() {` |
| `src/stdlib/ocr.rs:54` | `ocr_extract` | no | src/stdlib/ocr.rs:13, src/stdlib/ocr.rs:13 | `let output = Command::new("tesseract")` |
| `src/stdlib/pdf.rs:59` | `pdf_extract_text` | no | src/stdlib/pdf.rs:13, src/stdlib/pdf.rs:13 | `let output = Command::new("pdftotext")` |
| `src/stdlib/pdf.rs:144` | `get_page_count_inner` | no | src/stdlib/pdf.rs:54, src/stdlib/pdf.rs:134 | `if let Ok(output) = Command::new("pdfinfo")` |
| `src/stdlib/process.rs:115` | `process_exec` | no | src/stdlib/process.rs:20 | `match Command::new(&cmd).args(&args_list).output() {` |
| `src/stdlib/process.rs:140` | `process_spawn` | no | src/stdlib/process.rs:21 | `match Command::new(&cmd)` |
| `src/stdlib/spotify.rs:46` | `spotify_mod_apk` | no | src/stdlib/spotify.rs:22 | `let status = Command::new(java)` |
| `src/stdlib/spotify.rs:78` | `spotify_mod_apk` | no | src/stdlib/spotify.rs:22 | `let status = Command::new(java)` |
| `src/stdlib/spotify.rs:89` | `spotify_decompile` | no | src/stdlib/spotify.rs:18 | `let status = Command::new(java)` |
| `src/stdlib/spotify.rs:97` | `spotify_patch` | no | src/stdlib/spotify.rs:19 | `let status = Command::new("python3").arg(py).status().map_err(\|e\| format!("Patch: {e}"` |
| `src/stdlib/spotify.rs:103` | `spotify_rebuild` | no | src/stdlib/spotify.rs:20 | `let status = Command::new(java)` |
| `src/stdlib/transfer.rs:718` | `copy_via_vss_subprocess` | no | src/stdlib/transfer.rs:686 | `let output = std::process::Command::new("powershell")` |
| `src/stdlib/transfer.rs:2694` | `av_scan` | no | src/stdlib/transfer.rs:6127, src/stdlib/transfer.rs:6143 | `let result = std::process::Command::new("clamscan")` |
| `src/stdlib/transfer.rs:2750` | `yara_scan` | no | src/stdlib/transfer.rs:6152, src/stdlib/transfer.rs:127 | `let result = std::process::Command::new("yara")` |
| `src/tor/manager.rs:148` | `start` | no | src/main.rs:7667, src/main.rs:8361 | `let child = Command::new(&tor_bin)` |
| `src/tor/manager.rs:260` | `find_tor_binary` | no | src/tor/manager.rs:114 | `if let Ok(output) = Command::new("tor").arg("--version").output() {` |
| `src/vault/autotype.rs:572` | `run` | no | src/interp.rs:1920, src/interp.rs:2060 | `let out = std::process::Command::new(program).args(args).output()?;` |
| `src/vault/autotype.rs:580` | `run` | no | src/interp.rs:1920, src/interp.rs:2060 | `let mut child = std::process::Command::new(program)` |

## 5. The four DEBT claims that do not survive reading

DEBT entries are one-line justifications. Four of them rest on a gate located in
a *caller*, which is exactly the claim my per-function rule tests. I read each:

- `src/stdlib/mesh.rs` — "mesh bootstrap handshake to operator-supplied overlay
  addrs (named plane: mesh)". `mesh_node_join` (`src/stdlib/mesh.rs:482`,
  `TcpStream::connect(&addr)`) has **no** `scope::require` in its body, and
  `mesh_node_method` (`:431`) does not supply one either. The named plane is a
  declaration, not a check. (`src/mesh/remote.rs:617` in `run_worker` *does*
  gate, but only when the peer is not loopback — that is the other mesh path.)
- `src/browser/process.rs` — "Chrome CDP control socket". `discover_ws_url_via_http`
  (`:936`) and `find_available_port` (`:1063`) hold no require. CDP is loopback,
  so this may be the right decision, but the DEBT reason does not say "loopback";
  it says "CDP socket", and the file-level pattern would hide a non-loopback CDP
  host if one were ever configured.
- `src/stdlib/sync.rs` — "loopback-only tallow-daemon HTTP". True today, but the
  loopback-ness is enforced by the URL builder, not by a gate; the census rule
  cannot see that and neither can the predicate.
- `src/cli/veil_cmd.rs` — "plane-assertion probes". `bridge_conn` (`:589`) dials
  `SocketAddr::from((ip, target.1))` where `ip` comes from `mesh_resolve`, a
  DNS query the file itself sends over UDP (`:638`). That is a *resolved remote*
  dial, not a fixed plane assertion.

These are observations, not change requests. This lane gates nothing.

## 6. Premises in the brief that turned out wrong

1. **"48 gated"** — the port gives 47 (section 1). Not reproducible at `758e5bc`.
2. **"~596 files"** — 595 `.rs` files under `src/`.
3. **"child-process egress: `Command::new` for curl/wget/tallow"** — there is no
   `curl` or `wget` launch anywhere in `src/`. `Command::new("tallow")`-style
   self-invocation does not exist either; `src/pkg/enterprise.rs:751` launches a
   `tallow_exe` path variable. The 63 child-process sites are browsers, package
   managers, media tools, `sh -c` AT-command writers and a `bash <script>`.
4. **"any `sh -c` that passes a URL"** — the only `sh -c` sites
   (`src/browser/ipv6_pool.rs:689,707`) write `AT+CFUN=0/1` to a serial device
   path. No URL. `src/cli/never_probe.rs:49` runs `bash scripts/never_check.sh`.
5. **`Endpoint::connect`** — the literal form does not exist. The handshakes are
   method-form, `endpoint.connect(addr, server_name)`, split across two lines at
   five sites, so a one-line grep for `connect(` finds the *line after* the
   endpoint creation and a grep for `Endpoint::connect` finds nothing. Section
   4.2 is the list the brief actually wanted.
6. **"std::net … `send_to`"** — `self.send_to(` at `src/mesh/remote.rs:242,351`
   is a mesh frame write, not a socket call. Rejected and excluded from the 176.

## 7. Re-check of five rows (acceptance)

Five rows drawn from the table were re-read from disk with `sed -n` and the
enclosing fn confirmed by opening the function, not by trusting the scanner. See
the tail of this report for the transcript.

