// tallow.topology — host and port discovery.
//
// Every entry point consults the scope register before a packet is built: a
// target absent from configs/tallow/scope/authorized-hosts.toml is refused with
// the register's own code (scope:not-listed). The scanners are not a second,
// weaker door than `tallow scope check`.
//
// Every result says how it was obtained. A port is open, closed, filtered or
// open|filtered, and the technique that produced the verdict travels with it —
// a SYN verdict and a connect verdict are not interchangeable.
//
// The IPv4 entry points below cover every technique. IPv6 is served by the two
// unprivileged paths, v6_connect_scan and v6_discover; a raw technique asked
// for an IPv6 literal is refused with a message naming v6_connect_scan rather
// than returning an empty scan.

// Port specification parsing helper: "22", "22,80,443", "1-1024", or a mix.
// Returned ascending and de-duplicated; an empty spec is an error, not an
// empty scan.
native fn parse_ports(spec: String) -> []Int

// Estimate a scan without sending anything:
// {ports_count, packets, estimated_ms, worst_case_ms}. worst_case_ms assumes
// every probe times out, which is the honest number on a filtered host.
native fn plan(target: String, ports: String, technique: String?, rps: Int?, timeout_ms: Int?) -> Plan

// Half-open scan: a real IPv4+TCP SYN, with the pseudo-header checksum computed
// from the routed source address. Reports open (SYN-ACK), closed (RST) and
// filtered (silence) as distinct verdicts.
native fn syn_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> ScanResult

// Unprivileged connect scan. Same verdicts as syn_scan, different evidence:
// the kernel's connect() either completed, was refused, or timed out.
native fn connect_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> ScanResult

// FIN / NULL / Xmas probes. A segment with no SYN draws no reply from an
// RFC 793 host on an open port, so silence is reported as open|filtered and
// never as open; a RST remains decisive.
native fn fin_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> ScanResult
native fn null_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> ScanResult
native fn xmas_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> ScanResult

// IPv6 connect scan (N09) — the unprivileged path, and the only port-scan
// technique this build can send over IPv6: connect() needs no raw socket.
// Accepts ::1, 2001:db8::1, [::1], and a link-local literal with a zone
// (fe80::1%eth0), whose scope id is resolved to an interface index. Verdicts
// are the same as the IPv4 connect scan, from the same evidence.
native fn v6_connect_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> ScanResult

// UDP scan with protocol-appropriate payloads (DNS, NTP, SNMP, IKE). A
// connected socket turns an ICMP port-unreachable into ECONNREFUSED, which is
// the only reliable "closed" verdict without CAP_NET_RAW; silence stays
// open|filtered because a live daemon and a firewall look the same.
native fn udp_scan(target: String, ports: String, timeout_ms: Int?, rps: Int?) -> UDPScanResult

// Host discovery union: ICMP echo and TCP SYN, with per-method confidence.
// A reply proves presence; silence proves little, so the report carries a
// confidence and the list of methods that spoke. ARP (the only method that
// sees an on-link host blocking IP) is reported as unsupported, not as "down".
native fn discover(target: String, methods: String?, ports: String?, timeout_ms: Int?, rps: Int?) -> DiscoveryResult

// IPv6 host discovery (N09): one ICMPv6 echo request (type 128), matched on its
// echo reply (type 129) by id, sequence and payload marker. Reports alive,
// rtt_ms and the same confidence scale as discover (a reply = 0.9, silence =
// 0.2); a denied raw socket is reported in `unsupported`, never as "down".
native fn v6_discover(target: String, timeout_ms: Int?) -> DiscoveryResult

// Read the banner a service offers and identify the product/version only when
// the banner defines it (SSH identification string, HTTP Server header).
// `auto` speaks HTTP only on ports that expect it: a stray probe can make a
// daemon log a protocol error and close, losing the greeting.
native fn banner(target: String, port: Int?, timeout_ms: Int?, probe: String?) -> BannerResult

// TLS posture: negotiated version, cipher, ALPN, chain length, leaf SHA-256,
// certificate dNSName SANs, and trust as data (trusted=false + trust_error).
// An expired or self-signed certificate is a posture to report, not a reason to
// refuse to look.
native fn tls_posture(target: String, port: Int?, timeout_ms: Int?, sni: String?) -> TLSReport

// JA4 client fingerprint computed from the ClientHello recorded off the
// socket, not from the client configuration. JA4H (HTTP headers) is a
// different measurement and is not returned.
native fn ja4(target: String, port: Int?, timeout_ms: Int?, sni: String?) -> JA4Result

// Merge several techniques into one host record. Precedence, not averaging:
// a positive observation outranks silence. Disagreements are recorded and cost
// confidence; an open-vs-closed conflict names the middlebox hypothesis.
native fn reconcile(target: String, ports: String, techniques: String?, timeout_ms: Int?, rps: Int?) -> HostRecord
