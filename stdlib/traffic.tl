// tallow.traffic — offline traffic observation (N27/N28/N29/N30).
//
// Everything here was handed to the module: a capture file on local disk, or a
// record list the caller built. No socket is opened, no capture is started, no
// DNS query is sent and no clock is read. `started_ms`/`ended_ms` are whatever
// the capture or the caller says; nothing here stamps "now". Acquiring traffic
// belongs to a caller holding a Grant — this is the reading, not the collecting.
//
// The record, shared by every item in the lane:
//
//   flow := {src, dst, src_port, dst_port, proto, bytes_out, bytes_in,
//            packets_out, packets_in, started_ms, ended_ms, plane?, exit?,
//            payload_sig?}
//
// A flow with zero packets is refused (`traffic:empty-flow`), not recorded: a row
// with no packets has no duration, no direction and no bytes, and every
// statistic downstream would be computed over a fiction.
//
// `payload_sig` is the one field the brief's shape does not list, and it is here
// because N28 cannot be done without it. "https, because 443" and "https,
// because a TLS ClientHello" differ by exactly one fact — whether a signature was
// observed — and a record that does not carry that observation forces the
// attributor to guess which of the two it is holding. `pcap_load` fills it from
// the payload; the `flow` constructor lets a caller state it.

// One observed flow. `src` is the *initiating* endpoint (the sender of the first
// packet on the tuple), so `bytes_out` is what the initiator sent. Byte counts are
// layer-3 lengths (IPv4 total_length / IPv6 40 + payload_length), not frame
// lengths. `plane` and `exit` are nil when the record did not say — and an absent
// plane is `unknown`, never `direct`.
struct TrafficFlow {
    src:         String,
    dst:         String,
    src_port:    Int,
    dst_port:    Int,
    proto:       String,
    bytes_out:   Int,
    bytes_in:    Int,
    packets_out: Int,
    packets_in:  Int,
    started_ms:  Int,
    ended_ms:    Int,
    plane:       String?,
    exit:        String?,
    payload_sig: String?,
}

// Build one flow by hand — the only way to write a struct from a `.tl` program
// (a struct literal is E0115). Refuses `traffic:empty-flow` when
// `packets_out + packets_in == 0`.
native fn traffic.flow(src: String, dst: String, src_port: Int, dst_port: Int, proto: String, bytes_out: Int, bytes_in: Int, packets_out: Int, packets_in: Int, started_ms: Int, ended_ms: Int, plane: String?, exit: String?, payload_sig: String?) -> TrafficFlow

// One DNS query as observed. `response_bytes` is nil when the response size was
// not recorded — a different fact from zero, and the difference decides whether
// N29 is allowed to use the ratio at all.
struct TrafficQuery {
    qname:          String,
    dst:            String,
    ts_ms:          Int,
    query_bytes:    Int,
    response_bytes: Int?,
}

// Build one DNS query by hand.
native fn traffic.query(qname: String, dst: String, ts_ms: Int, query_bytes: Int, response_bytes: Int?) -> TrafficQuery

// ── N27: capture import ───────────────────────────────────────────────────
//
// Classic PCAP only, both endiannesses and both timestamp resolutions, read from
// the magic rather than assumed: d4c3b2a1 / a1b2c3d4 are the little- and big-
// endian microsecond writers, 4d3cb2a1 / a1b23c4d the nanosecond ones. A record
// whose `incl_len` runs past the end of the file is a refusal naming the offset
// of that record — never a partial flow list presented as a complete capture.
//
// PCAPNG is not parsed: a Section Header Block at offset 0 is refused
// (`traffic:pcapng-unsupported`). Link layer is Ethernet with up to one VLAN tag;
// anything else is refused (`traffic:pcap-linktype-unsupported`) rather than
// guessed at. Frames carrying no IPv4/IPv6 are counted in `frames` and produce no
// flow, so `frames` is the number of records read and the per-flow packet counts
// sum to at most that.
//
// One row per unordered 4-tuple per capture. A capture that reuses a 4-tuple
// twice (a second connection from the same source port) yields one row spanning
// both: splitting per connection needs TCP state this module does not keep. That
// affects durations, not per-destination byte or packet totals.
struct TrafficCapture {
    path:          String,
    format:        String,
    // "microsecond" or "nanosecond", read from the magic.
    ts_resolution: String,
    // In words: the stored `*_ms` are milliseconds truncated from
    // `ts_resolution`, so sub-millisecond ordering is lost. A microsecond capture
    // is never silently reported as millisecond-precision.
    ts_note:       String,
    link_type:     Int,
    // Records read from the file, including frames that produced no flow.
    frames:        Int,
    flow_count:    Int,
    flows:         []TrafficFlow,
}

// Parse a classic PCAP file from local disk. Refuses `traffic:io`,
// `traffic:pcap-bad-magic` (quoting the bytes seen), `traffic:pcap-truncated`
// (naming the offset), `traffic:pcap-linktype-unsupported` and
// `traffic:pcapng-unsupported`.
native fn traffic.pcap_load(path: String) -> TrafficCapture

// The flow list from a capture, when only the flows are wanted.
native fn traffic.flows(capture: TrafficCapture) -> []TrafficFlow

// ── N28: protocol attribution ─────────────────────────────────────────────
//
// A signature is a measurement, a port is a guess, and the two do not carry the
// same confidence:
//
//   payload signature on the protocol's conventional port   0.95  measured
//   payload signature on some other port                    0.90  measured
//   well-known port, no signature                           0.40  a guess
//   nothing                                                 0.00  unknown
//
// Signatures recognised: TLS ClientHello (distinguished from the rest of the TLS
// handshake), TLS application data, TLS ChangeCipherSpec, an HTTP request line, an
// HTTP response line, an SSH identification banner, and a DNS message whose header
// actually parses (one question, query/response bit read).
//
// `http` is never reported from a port. Ports 80 and 8080 are signature-required:
// without a request or response line the row is `unknown` and the reason says the
// port is conventionally http but no signature was seen. Port 80 carries proxies,
// tunnels and non-HTTP on purpose, and a plaintext request line is cheap to
// observe when it is really there.
struct TrafficAttribution {
    // Position in the input list.
    index:      Int,
    protocol:   String,
    // Which signature matched, or nil when none did.
    signature:  String?,
    // "payload" (measured), "port" (guessed) or "none".
    evidence:   String,
    port:       Int,
    confidence: Float,
    reason:     String,
}

// Attribute a protocol to each flow, from its payload signature where one was
// observed and its port otherwise. Every row names its evidence and why.
native fn traffic.attribute(flows: []TrafficFlow) -> []TrafficAttribution

// ── N29: DNS tunnelling signal ────────────────────────────────────────────
//
// Per destination: the mean Shannon entropy (bits/char) of each query's first
// label, the query rate over the observed window, and the response-size ratio
// (sum of response bytes / sum of query bytes). Each component is nil when it was
// not measurable, and `*_measured` says which — a missing component is absent from
// `score` (the weights renormalise) rather than defaulted to zero.
//
// The thresholds, and why:
//
//   ENTROPY_MIN 3.9 bits/char on the mean first label. Uniform hex measures
//   ~3.7-4.0 over 16-character labels and base64 payloads ~4.5-5.0; ordinary
//   words sit below 2.6 ("www" 0, "static" 2.58). 3.9 is deliberately above the
//   hex band, because hex is also the shape of a CDN shard name.
//
//   RATE_MIN 30 queries/min. A tunnel is a throughput mechanism; a handful of
//   lookups a minute is a resolver doing its job.
//
//   RATIO_LOW 0.6 / RATIO_HIGH 4.0. Exfiltration sends long qnames and gets short
//   answers; a download tunnel pulls large answers. Ordinary A/AAAA lookups sit
//   near 1.
//
//   ENTROPY_HIGH 4.4 with RATE_HIGH 120/min, the alternative only when response
//   sizes were never recorded: high entropy at a very high rate, and a higher bar
//   to clear because one component is missing.
//
// High entropy alone cannot fire. A destination fires only when the rate clears
// RATE_MIN and the entropy clears ENTROPY_MIN and (the ratio is abnormal, or both
// the rate and the entropy are extreme). The case that matters is a hex-shaped
// CDN shard name at 60 queries/min: it clears
// the entropy bar and must still not fire, because its answers are ordinary sizes
// (regression test `n29_a_benign_high_entropy_cdn_name_does_not_fire`).
//
// The output always says `signal: "dns-tunnelling"`; it never says tunnel,
// detected or malicious. `fires` means the documented thresholds were met.
// `score` is 0.40*entropy + 0.35*rate + 0.25*ratio over the measured components —
// a shape for ranking, not a probability.
struct DnsTunnelSignal {
    // Always "dns-tunnelling". A description, never a verdict.
    signal:           String,
    dst:              String,
    queries:          Int,
    window_ms:        Int,
    entropy:          Float?,
    queries_per_min:  Float?,
    response_ratio:   Float?,
    mean_label_len:   Float?,
    entropy_measured: Bool,
    rate_measured:    Bool,
    ratio_measured:   Bool,
    score:            Float,
    fires:            Bool,
    reason:           String,
}

// One signal per destination, sorted by destination so two runs over the same
// input render identically.
//
// `items` is `any` because two record shapes are accepted — []TrafficQuery, or
// []TrafficFlow for a capture-derived list. A flow carries no qname, so entropy
// comes back nil and the row says so.
native fn traffic.dns_tunnel_signal(items: any) -> []DnsTunnelSignal
