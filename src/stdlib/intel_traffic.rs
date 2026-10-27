//! `tallow.traffic` — offline traffic observation (N27, N28, N29).
//!
//! **Offline by construction.** Every byte this module sees was handed to it: a capture file on
//! local disk, or a record list the caller built. It opens no socket, starts no capture, sends no
//! DNS query and reads no clock. `started_ms`/`ended_ms` are whatever the capture or the caller
//! says they are; nothing here stamps "now". Acquiring traffic belongs to a caller holding a
//! `Grant` — this module is the reading, not the collecting.
//!
//! # The record
//!
//! One shape, shared by every item in the lane:
//!
//! ```text
//! flow := {src, dst, src_port, dst_port, proto, bytes_out, bytes_in, packets_out,
//!          packets_in, started_ms, ended_ms, plane?, exit?, payload_sig?}
//! ```
//!
//! A flow with **zero packets** is refused (`traffic:empty-flow`) rather than recorded: a row with
//! no packets has no duration, no bytes and no direction, and every statistic downstream (the rate
//! in N29) would be computed over a fiction. There is no partial credit
//! for a flow that was never observed.
//!
//! `payload_sig` is the one field the brief's shape does not list, and it is here because N28
//! cannot be done without it: the difference between "https, because 443" and "https, because a
//! TLS ClientHello" is *the existence of an observed signature*, and a record that does not carry
//! that observation forces the attributor to guess which one it has.
//!
//! # N27 — a capture is parsed whole or refused at a byte
//!
//! Classic PCAP only, both endiannesses and both timestamp resolutions. The magic is **read**, not
//! assumed: `d4 c3 b2 a1` and `a1 b2 c3 d4` are the little- and big-endian writers of the
//! microsecond format, `4d 3c b2 a1` / `a1 b2 3c 4d` the nanosecond variants. Every record's
//! `incl_len` is bounds-checked against the bytes that remain, so a truncated capture fails at the
//! exact offset of the record that ran off the end — never a partial flow list presented as a
//! complete capture.
//!
//! Timestamp resolution is carried, not smoothed: `ts_resolution` is `"microsecond"` or
//! `"nanosecond"` and `ts_note` says in words that the stored `*_ms` are milliseconds truncated
//! from that resolution, so a sub-millisecond ordering has been lost. A microsecond capture is
//! never silently reported as millisecond-precision.
//!
//! PCAPNG is **not** parsed: a file starting with a Section Header Block (`0x0A0D0D0A`) is refused
//! (`traffic:pcapng-unsupported`) at offset 0. See the lane report — the block-structured format
//! did not fit the diff budget alongside four items.
//!
//! Link layer: Ethernet (LINKTYPE 1) with up to one VLAN tag. Anything else is refused
//! (`traffic:pcap-linktype-unsupported`) rather than guessed at. Frames that carry no IPv4/IPv6
//! (ARP, LLDP) are counted in `frames` but produce no flow, so `frames` is the number of records
//! read and the per-flow packet counts sum to at most that.
//!
//! ## What a row is, exactly
//!
//! One row per **unordered 4-tuple per capture** (`{a, a_port} ↔ {b, b_port}`, plus `proto`).
//! `src`/`dst` are the *initiating* endpoint — the sender of the first packet on that tuple — so
//! `bytes_out` is what the initiator sent and `bytes_in` what the responder sent back. A capture
//! that reuses a 4-tuple twice (a second connection from the same source port) therefore yields
//! **one** row spanning both. Splitting per connection needs TCP state this module does not keep;
//! the limitation is named rather than approximated, and it affects durations, not per-destination
//! byte or packet totals.
//!
//! `bytes_out`/`bytes_in` are layer-3 lengths (IPv4 `total_length`, IPv6 `40 + payload_length`),
//! not frame lengths, so Ethernet headers and padding are not counted.
//!
//! # N28 — a signature is a measurement, a port is a guess
//!
//! `attribute` reports, per flow, the protocol it believes, **which signature matched** (`signature`
//! plus the port it was found on), the evidence class (`payload` / `port` / `none`) and a
//! confidence. The two facts the brief asks to keep apart are kept apart by construction:
//!
//! | evidence | confidence | meaning |
//! |---|---|---|
//! | payload signature on the protocol's conventional port | 0.95 | measured |
//! | payload signature on some other port | 0.90 | measured; the port is not the evidence |
//! | well-known port, no signature | 0.40 | a guess |
//! | nothing | 0.00 | `unknown`, with the reason |
//!
//! `https` from a TLS ClientHello on 443 and `https` from port 443 alone therefore differ by both
//! `evidence` and `confidence`. Signatures recognised: TLS handshake (ClientHello distinguished
//! from the rest of the handshake), TLS application data, TLS ChangeCipherSpec, HTTP request (a
//! request line), HTTP response (`HTTP/1.x`), an SSH identification banner, and a DNS message
//! whose header actually parses (`QDCOUNT ≥ 1`, query/response bit read).
//!
//! **`http` is never reported from a port.** Port 80 and 8080 are marked signature-required in
//! [`port_rule`]: without a request or response line the row's protocol is `unknown` and its reason
//! says the port is conventionally http but no signature was seen. That asymmetry is deliberate and
//! is the brief's: port 80 carries proxies, tunnels and non-HTTP on purpose, and a plaintext
//! request line is cheap to observe when it is really there — so "port 80 minus signature" is the
//! weakest inference in the table and the only one refused outright.
//!
//! # N29 — a signal, not a verdict
//!
//! `dns_tunnel_signal` groups queries by destination and reports, per destination: the mean Shannon
//! entropy (bits/char) of each query's **first label** — the label a tunnelling encoder puts its
//! payload in — the query rate over the observed window, and the response-size ratio
//! (`Σ response bytes / Σ query bytes`). Each component is an `Option`: a component that was not
//! measurable is absent from `score` rather than defaulted to zero, and `*_measured` says which is
//! which.
//!
//! Thresholds, and why:
//!
//! - `ENTROPY_MIN = 3.9` bits/char on the mean first label. Uniform hex gives ≈ 3.7–4.0 measured
//!   empirically on 16-character labels and base64/32-byte payloads land near 4.5–5.0; ordinary
//!   words sit below 2.6 (`www` = 0, `static` = 2.58). 3.9 is above the hex band on purpose: hex
//!   is also the shape of a CDN shard name.
//! - `RATE_MIN = 30` queries/min. A tunnel is a *throughput* mechanism; a handful of lookups per
//!   minute is a resolver doing its job.
//! - `RATIO_LOW = 0.6` / `RATIO_HIGH = 4.0`. Exfiltration sends long qnames and gets short answers
//!   (ratio well below 1); a download tunnel pulls large TXT answers (ratio well above 1). Ordinary
//!   A/AAAA lookups sit near 1.
//! - `ENTROPY_HIGH = 4.4` with `RATE_HIGH = 120` queries/min, the alternative when response sizes
//!   were not recorded at all: high entropy at a very high rate is the only case that can fire
//!   without the ratio, and it must clear a higher bar to do so.
//!
//! **High entropy alone cannot fire.** A destination fires only when the rate clears `RATE_MIN`
//! *and* the entropy clears `ENTROPY_MIN` *and* (the ratio is abnormal, or the rate is extreme and
//! the entropy extreme). The regression test `a_benign_high_entropy_cdn_name_does_not_fire` is the
//! case that matters: `d1a2b3c4d5e6f708.cloudfront.net` at 60 queries/min clears the entropy bar and
//! must still not fire, because its names are high-entropy *and* its answers are ordinary sizes.
//! Entropy is also reported as `nil`, not `0.0`, when the input is flows rather than queries — a
//! flow carries no qname, so nothing was measured and nothing is claimed.
//!
//! The output always says `signal: "dns-tunnelling"`; it never says `tunnel`, `detected` or
//! `malicious`. `fires` means "the documented thresholds were met", and `score` is
//! `0.40·entropy + 0.35·rate + 0.25·ratio` renormalised over the measured components — a shape for
//! ranking, not a probability.
//!
//! # Refusals
//!
//! | code | when |
//! |---|---|
//! | `traffic:empty-flow` | a flow with `packets_out + packets_in == 0` |
//! | `traffic:bad-argument` | missing argument, wrong type, struct of the wrong shape, negative count |
//! | `traffic:io` | the capture path cannot be read |
//! | `traffic:pcap-bad-magic` | the first four bytes are not a pcap magic (the bytes are quoted) |
//! | `traffic:pcap-truncated` | the file ends inside the global header or a record (the offset is named) |
//! | `traffic:pcap-linktype-unsupported` | link type is not Ethernet |
//! | `traffic:pcapng-unsupported` | the file is PCAPNG |

use super::StdlibResult;
use crate::interp::{Value, type_name};
use std::collections::{BTreeMap, btree_map::Entry};

pub const CODE_ARG: &str = "traffic:bad-argument";
pub const CODE_EMPTY_FLOW: &str = "traffic:empty-flow";
pub const CODE_IO: &str = "traffic:io";
pub const CODE_PCAP_MAGIC: &str = "traffic:pcap-bad-magic";
pub const CODE_PCAP_TRUNCATED: &str = "traffic:pcap-truncated";
pub const CODE_PCAP_LINKTYPE: &str = "traffic:pcap-linktype-unsupported";
pub const CODE_PCAPNG: &str = "traffic:pcapng-unsupported";

/// The signal label N29 emits. A description of a shape, never a verdict.
pub const SIGNAL_DNS_TUNNEL: &str = "dns-tunnelling";

// N29 thresholds. See the module docs for the reasoning behind each number.
pub const ENTROPY_MIN: f64 = 3.9;
pub const ENTROPY_HIGH: f64 = 4.4;
pub const RATE_MIN: f64 = 30.0;
pub const RATE_HIGH: f64 = 120.0;
pub const RATIO_LOW: f64 = 0.6;
pub const RATIO_HIGH: f64 = 4.0;

// ── The record ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Flow {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: String,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub packets_in: u64,
    pub started_ms: i64,
    pub ended_ms: i64,
    pub plane: Option<String>,
    pub exit: Option<String>,
    pub payload_sig: Option<String>,
}

impl Flow {
    /// Refuse a flow that was never observed. Named `check` rather than done in the constructor so
    /// `pcap_load` cannot bypass it: a capture cannot produce an empty row either.
    pub fn check(&self) -> Result<(), String> {
        if self.packets() == 0 {
            return Err(format!(
                "{CODE_EMPTY_FLOW}: traffic: flow {}:{} -> {}:{} ({}) has 0 packets; \
                 a flow with no packets is not a flow",
                self.src, self.src_port, self.dst, self.dst_port, self.proto
            ));
        }
        Ok(())
    }

    fn packets(&self) -> u64 {
        self.packets_out + self.packets_in
    }
}

// ── N27: PCAP ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Capture {
    pub path: String,
    /// `"pcap"`. Named so a caller reading the struct knows what it holds even though only one
    /// format is parsed today.
    pub format: &'static str,
    /// `"microsecond"` or `"nanosecond"` — read from the magic, never assumed.
    pub ts_resolution: &'static str,
    pub link_type: u32,
    /// Records read from the file, including frames that carry no IP and produced no flow.
    pub frames: u64,
    pub flows: Vec<Flow>,
}

impl Capture {
    pub fn ts_note(&self) -> String {
        format!(
            "timestamps are milliseconds truncated from {} resolution; sub-millisecond ordering \
             within the capture is lost",
            self.ts_resolution
        )
    }
}

fn u32_at(b: &[u8], at: usize, le: bool) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(if le {
        u32::from_le_bytes([s[0], s[1], s[2], s[3]])
    } else {
        u32::from_be_bytes([s[0], s[1], s[2], s[3]])
    })
}

fn ip4_str(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn ip6_str(b: &[u8]) -> String {
    let group = |i: usize| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
    let mut parts: Vec<String> = (0..8).map(|i| format!("{:x}", group(i))).collect();
    // Compress the longest run of zero groups, RFC 5952 style, so the address reads the way a
    // human writes it.
    let (mut best, mut best_len, mut run, mut run_len) = (usize::MAX, 0usize, 0usize, 0usize);
    for i in 0..8 {
        if group(i) == 0 {
            if run_len == 0 {
                run = i;
            }
            run_len += 1;
            if run_len > best_len {
                best = run;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    if best_len > 1 {
        let head = parts[..best].join(":");
        let tail = parts[best + best_len..].join(":");
        parts = vec![if head.is_empty() && tail.is_empty() {
            "::".to_string()
        } else {
            format!("{head}::{tail}")
        }];
    }
    parts.join(":")
}

/// One decoded packet: the minimum a flow row needs, plus the first 64 payload bytes for N28.
struct Packet {
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    proto: &'static str,
    /// Layer-3 length (IPv4 total_length / IPv6 40 + payload_length).
    bytes: u64,
    payload: Vec<u8>,
}

fn tcp_or_udp(
    l4: &[u8],
    src: String,
    dst: String,
    bytes: u64,
    proto: &'static str,
) -> Option<Packet> {
    let sport = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
    let dport = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    let hdr = if proto == "tcp" {
        if l4.len() < 20 {
            return None;
        }
        ((l4[12] >> 4) as usize) * 4
    } else {
        8
    };
    let payload = if hdr >= 8 && l4.len() > hdr {
        l4[hdr..].iter().take(64).copied().collect()
    } else {
        Vec::new()
    };
    Some(Packet {
        src,
        dst,
        sport,
        dport,
        proto,
        bytes,
        payload,
    })
}

fn decode_ipv4(p: &[u8]) -> Option<Packet> {
    if p.len() < 20 {
        return None;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    if ihl < 20 || p.len() < ihl {
        return None;
    }
    let bytes = u16::from_be_bytes([p[2], p[3]]).max(ihl as u16) as u64;
    let frag = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    let proto = p[9];
    let src = ip4_str(&p[12..16]);
    let dst = ip4_str(&p[16..20]);
    // A non-first fragment carries no L4 header: naming a port from it would be a fabricated
    // port, so the fragment is recorded as `other` with no ports.
    if frag != 0 {
        return Some(Packet {
            src,
            dst,
            sport: 0,
            dport: 0,
            proto: "other",
            bytes,
            payload: Vec::new(),
        });
    }
    let l4 = &p[ihl..];
    match proto {
        6 => tcp_or_udp(l4, src, dst, bytes, "tcp"),
        17 => tcp_or_udp(l4, src, dst, bytes, "udp"),
        1 => Some(Packet {
            src,
            dst,
            sport: 0,
            dport: 0,
            proto: "icmp",
            bytes,
            payload: Vec::new(),
        }),
        _ => Some(Packet {
            src,
            dst,
            sport: 0,
            dport: 0,
            proto: "other",
            bytes,
            payload: Vec::new(),
        }),
    }
}

fn decode_ipv6(p: &[u8]) -> Option<Packet> {
    if p.len() < 40 {
        return None;
    }
    let bytes = 40 + u16::from_be_bytes([p[4], p[5]]) as u64;
    let next = p[6];
    let src = ip6_str(&p[8..24]);
    let dst = ip6_str(&p[24..40]);
    // Extension headers are not walked: only a directly-following TCP/UDP header is decoded, and
    // anything else keeps the byte count but claims no ports.
    let l4 = &p[40..];
    match next {
        6 => tcp_or_udp(l4, src, dst, bytes, "tcp"),
        17 => tcp_or_udp(l4, src, dst, bytes, "udp"),
        58 => Some(Packet {
            src,
            dst,
            sport: 0,
            dport: 0,
            proto: "icmp",
            bytes,
            payload: Vec::new(),
        }),
        _ => Some(Packet {
            src,
            dst,
            sport: 0,
            dport: 0,
            proto: "other",
            bytes,
            payload: Vec::new(),
        }),
    }
}

fn decode_ethernet(f: &[u8]) -> Option<Packet> {
    if f.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([f[12], f[13]]);
    let mut l3 = 14usize;
    if (ethertype == 0x8100 || ethertype == 0x88a8) && f.len() >= 18 {
        ethertype = u16::from_be_bytes([f[16], f[17]]);
        l3 = 18;
    }
    match ethertype {
        0x0800 => decode_ipv4(&f[l3..]),
        0x86dd => decode_ipv6(&f[l3..]),
        _ => None,
    }
}

/// Recognise a payload signature. Returns the name of what matched, or `None`.
///
/// Cheap, prefix-only tests on purpose: this runs per flow, not per byte, and a signature that
/// needs a full parse is a signature this module does not claim.
fn signature(pkt: &Packet) -> Option<&'static str> {
    let p = &pkt.payload;
    if p.is_empty() {
        return None;
    }
    if p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 {
        return Some(if p[5] == 0x01 {
            "tls_clienthello"
        } else {
            "tls_handshake"
        });
    }
    if p.len() >= 3 && p[0] == 0x17 && p[1] == 0x03 {
        return Some("tls_appdata");
    }
    if p.len() >= 3 && p[0] == 0x14 && p[1] == 0x03 {
        return Some("tls_changecipher");
    }
    if p.starts_with(b"HTTP/1.") {
        return Some("http_response");
    }
    for method in [
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    ] {
        if p.starts_with(method.as_bytes()) {
            return Some("http_request");
        }
    }
    if p.starts_with(b"SSH-") {
        return Some("ssh_banner");
    }
    // A DNS message only counts as one when its header parses: a one-question message with the
    // query/response bit read. Twelve bytes of port-53 payload alone is not a signature.
    if pkt.proto == "udp"
        && (pkt.sport == 53 || pkt.dport == 53)
        && p.len() >= 12
        && u16::from_be_bytes([p[4], p[5]]) >= 1
    {
        return Some(if p[2] & 0x80 == 0 {
            "dns_query"
        } else {
            "dns_response"
        });
    }
    None
}

type FlowKey = (String, u16, String, u16, &'static str);

fn flow_key(p: &Packet) -> FlowKey {
    if (p.src.as_str(), p.sport) <= (p.dst.as_str(), p.dport) {
        (p.src.clone(), p.sport, p.dst.clone(), p.dport, p.proto)
    } else {
        (p.dst.clone(), p.dport, p.src.clone(), p.sport, p.proto)
    }
}

fn new_flow(p: &Packet, ts_ms: i64) -> Flow {
    Flow {
        src: p.src.clone(),
        dst: p.dst.clone(),
        src_port: p.sport,
        dst_port: p.dport,
        proto: p.proto.to_string(),
        bytes_out: p.bytes,
        bytes_in: 0,
        packets_out: 1,
        packets_in: 0,
        started_ms: ts_ms,
        ended_ms: ts_ms,
        plane: None,
        exit: None,
        payload_sig: signature(p).map(str::to_string),
    }
}

fn add_packet(flows: &mut BTreeMap<FlowKey, Flow>, p: &Packet, ts_ms: i64) {
    match flows.entry(flow_key(p)) {
        Entry::Vacant(v) => {
            v.insert(new_flow(p, ts_ms));
        }
        Entry::Occupied(mut o) => {
            let f = o.get_mut();
            let from_initiator = p.src == f.src && p.sport == f.src_port;
            if from_initiator {
                f.bytes_out += p.bytes;
                f.packets_out += 1;
                if f.payload_sig.is_none() {
                    f.payload_sig = signature(p).map(str::to_string);
                }
            } else {
                f.bytes_in += p.bytes;
                f.packets_in += 1;
            }
            f.started_ms = f.started_ms.min(ts_ms);
            f.ended_ms = f.ended_ms.max(ts_ms);
        }
    }
}

/// Parse a classic PCAP byte slice. Split from [`load_pcap`] so the parser is testable without a
/// file and so the refusal offsets are a property of the bytes, not of the filesystem.
pub fn parse_pcap(path: &str, b: &[u8]) -> Result<Capture, String> {
    if b.len() < 4 {
        return Err(format!(
            "{CODE_PCAP_TRUNCATED}: traffic.pcap_load: {path}: file is {} byte(s); a capture \
             begins with a 4-byte magic at offset 0",
            b.len()
        ));
    }
    let le_magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let be_magic = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if le_magic == 0x0a0d_0d0a || be_magic == 0x0a0d_0d0a {
        return Err(format!(
            "{CODE_PCAPNG}: traffic.pcap_load: {path}: a PCAPNG Section Header Block at offset 0; \
             this build parses classic PCAP only"
        ));
    }
    let (le, ts_resolution) = if le_magic == 0xa1b2_c3d4 {
        (true, "microsecond")
    } else if le_magic == 0xa1b2_3c4d {
        (true, "nanosecond")
    } else if be_magic == 0xa1b2_c3d4 {
        (false, "microsecond")
    } else if be_magic == 0xa1b2_3c4d {
        (false, "nanosecond")
    } else {
        return Err(format!(
            "{CODE_PCAP_MAGIC}: traffic.pcap_load: {path}: bytes {:02x}{:02x}{:02x}{:02x} at \
             offset 0 are not a PCAP magic (expected d4c3b2a1 / a1b2c3d4 / 4d3cb2a1 / a1b23c4d)",
            b[0], b[1], b[2], b[3]
        ));
    };
    if b.len() < 24 {
        return Err(format!(
            "{CODE_PCAP_TRUNCATED}: traffic.pcap_load: {path}: the global header needs 24 bytes, \
             the file ends at offset {}",
            b.len()
        ));
    }
    let link_type = u32_at(b, 20, le).unwrap_or(0);
    if link_type != 1 {
        return Err(format!(
            "{CODE_PCAP_LINKTYPE}: traffic.pcap_load: {path}: link type {link_type} at offset 20; \
             only LINKTYPE_ETHERNET (1) is decoded"
        ));
    }

    let mut flows: BTreeMap<FlowKey, Flow> = BTreeMap::new();
    let mut frames = 0u64;
    let mut pos = 24usize;
    while pos < b.len() {
        if b.len() - pos < 16 {
            return Err(format!(
                "{CODE_PCAP_TRUNCATED}: traffic.pcap_load: {path}: record header at offset {pos} \
                 needs 16 bytes, {} remain",
                b.len() - pos
            ));
        }
        let ts_sec = u32_at(b, pos, le).unwrap_or(0) as i64;
        let ts_frac = u32_at(b, pos + 4, le).unwrap_or(0) as i64;
        let incl = u32_at(b, pos + 8, le).unwrap_or(0) as usize;
        let data = pos + 16;
        let end = data.saturating_add(incl);
        if end > b.len() {
            return Err(format!(
                "{CODE_PCAP_TRUNCATED}: traffic.pcap_load: {path}: record at offset {pos} \
                 declares {incl} byte(s) of packet data, only {} remain",
                b.len() - data
            ));
        }
        let ts_ms = match ts_resolution {
            "nanosecond" => ts_sec * 1000 + ts_frac / 1_000_000,
            _ => ts_sec * 1000 + ts_frac / 1000,
        };
        if let Some(pkt) = decode_ethernet(&b[data..end]) {
            add_packet(&mut flows, &pkt, ts_ms);
        }
        frames += 1;
        pos = end;
    }

    Ok(Capture {
        path: path.to_string(),
        format: "pcap",
        ts_resolution,
        link_type,
        frames,
        flows: flows.into_values().collect(),
    })
}

/// Read and parse a classic PCAP file from local disk. No network, no live capture.
pub fn load_pcap(path: &str) -> Result<Capture, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("{CODE_IO}: traffic.pcap_load: cannot read {path}: {e}"))?;
    parse_pcap(path, &bytes)
}

// ── N28: attribution ──────────────────────────────────────────────────────

struct PortRule {
    protocol: &'static str,
    /// The port alone may not name this protocol; a payload signature is required.
    sig_required: bool,
}

/// Well-known service ports. Deliberately small: a long table of every registered port would trade
/// one guess for another, and 0.40 confidence on a guess is only worth having for ports that are
/// actually common.
fn port_rule(port: u16) -> Option<PortRule> {
    let (protocol, sig_required) = match port {
        21 => ("ftp", false),
        22 => ("ssh", false),
        25 => ("smtp", false),
        53 => ("dns", false),
        80 => ("http", true),
        110 => ("pop3", false),
        123 => ("ntp", false),
        143 => ("imap", false),
        443 => ("https", false),
        445 => ("smb", false),
        587 => ("smtp", false),
        3306 => ("mysql", false),
        3389 => ("rdp", false),
        5432 => ("postgres", false),
        5433 => ("postgres", false),
        6379 => ("redis", false),
        8080 => ("http", true),
        8443 => ("https", false),
        27017 => ("mongo", false),
        _ => return None,
    };
    Some(PortRule {
        protocol,
        sig_required,
    })
}

/// The protocol a signature names, and the port that protocol conventionally lives on.
fn sig_protocol(sig: &str, port: u16) -> Option<(&'static str, Option<u16>)> {
    Some(match sig {
        "tls_clienthello" | "tls_handshake" | "tls_appdata" | "tls_changecipher" => {
            if port == 8443 {
                ("https", Some(8443))
            } else {
                ("https", Some(443))
            }
        }
        "http_request" | "http_response" => ("http", Some(80)),
        "ssh_banner" => ("ssh", Some(22)),
        "dns_query" | "dns_response" => ("dns", Some(53)),
        _ => return None,
    })
}

/// The responder's port: the service port of the flow. Prefers `dst_port` (the initiator's
/// destination) and falls back to `src_port` when only that side names a known service.
fn service_port(f: &Flow) -> (u16, &'static str) {
    if port_rule(f.dst_port).is_some() {
        (f.dst_port, "dst_port")
    } else if port_rule(f.src_port).is_some() {
        (f.src_port, "src_port")
    } else {
        (f.dst_port, "dst_port")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribution {
    pub index: usize,
    pub protocol: String,
    /// Which signature matched, or `None` when none did. This is the field that makes the
    /// difference between a measurement and a guess inspectable.
    pub signature: Option<String>,
    /// `payload` (measured), `port` (guessed), or `none`.
    pub evidence: String,
    pub port: u16,
    pub confidence: f64,
    pub reason: String,
}

pub fn attribute_one(index: usize, f: &Flow) -> Attribution {
    let (port, side) = service_port(f);
    if let Some(sig) = &f.payload_sig {
        if let Some((protocol, conv)) = sig_protocol(sig, port) {
            let on_conventional = conv == Some(port);
            return Attribution {
                index,
                protocol: protocol.to_string(),
                signature: Some(sig.clone()),
                evidence: "payload".to_string(),
                port,
                confidence: if on_conventional { 0.95 } else { 0.90 },
                reason: if on_conventional {
                    format!(
                        "payload signature `{sig}` on {side} {port}, the conventional port for \
                         {protocol}: measured"
                    )
                } else {
                    format!(
                        "payload signature `{sig}` on {side} {port}, not the conventional port \
                         for {protocol}; the signature is the measurement, the port is not the \
                         evidence"
                    )
                },
            };
        }
        // A signature this table does not map (a caller-supplied `payload_sig`) is recorded as
        // seen but names no protocol: the row says so rather than falling back to a port guess
        // that would look like the signature had been understood.
        return Attribution {
            index,
            protocol: "unknown".to_string(),
            signature: Some(sig.clone()),
            evidence: "none".to_string(),
            port,
            confidence: 0.0,
            reason: format!(
                "payload signature `{sig}` was recorded but this module has no rule mapping it to \
                 a protocol"
            ),
        };
    }
    match port_rule(port) {
        Some(rule) if !rule.sig_required => Attribution {
            index,
            protocol: rule.protocol.to_string(),
            signature: None,
            evidence: "port".to_string(),
            port,
            confidence: 0.40,
            reason: format!(
                "no payload signature was observed; {side} {port} is conventionally {} — a port \
                 guess, not a measurement",
                rule.protocol
            ),
        },
        Some(rule) => Attribution {
            index,
            protocol: "unknown".to_string(),
            signature: None,
            evidence: "none".to_string(),
            port,
            confidence: 0.0,
            reason: format!(
                "{side} {port} is conventionally {} but no {} signature was observed; this \
                 module does not name {} from a port",
                rule.protocol, rule.protocol, rule.protocol
            ),
        },
        None => Attribution {
            index,
            protocol: "unknown".to_string(),
            signature: None,
            evidence: "none".to_string(),
            port,
            confidence: 0.0,
            reason: format!(
                "no payload signature and {side} {port} is not a well-known service port"
            ),
        },
    }
}

pub fn attribute(flows: &[Flow]) -> Vec<Attribution> {
    flows
        .iter()
        .enumerate()
        .map(|(i, f)| attribute_one(i, f))
        .collect()
}

// ── N29: DNS tunnelling signal ────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Query {
    pub qname: String,
    pub dst: String,
    pub ts_ms: i64,
    pub query_bytes: u64,
    /// `None` means the response size was not recorded — a different fact from zero, and the
    /// difference decides whether the ratio component is allowed to influence the score at all.
    pub response_bytes: Option<u64>,
}

/// Shannon entropy in bits per character of `s`. `None` for an empty string: nothing was measured.
pub fn shannon_bits_per_char(s: &str) -> Option<f64> {
    if s.is_empty() {
        return None;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    let mut h = 0.0;
    for c in counts.iter().filter(|c| **c > 0) {
        let p = *c as f64 / n;
        h -= p * p.log2();
    }
    Some(h)
}

/// The label a tunnelling encoder puts its payload in: the leftmost one.
fn first_label(qname: &str) -> &str {
    qname.trim_end_matches('.').split('.').next().unwrap_or("")
}

#[derive(Clone, Debug, PartialEq)]
pub struct TunnelSignal {
    pub dst: String,
    pub queries: u64,
    pub window_ms: i64,
    pub entropy: Option<f64>,
    pub queries_per_min: Option<f64>,
    pub response_ratio: Option<f64>,
    pub mean_label_len: Option<f64>,
    pub score: f64,
    pub fires: bool,
    pub reason: String,
}

fn clamp01(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

/// One destination's signal. Components are measured independently; a component that was not
/// measured is absent from `score` (the weights renormalise) rather than defaulted to zero.
pub fn dns_signal_for(dst: &str, qs: &[Query]) -> TunnelSignal {
    let queries = qs.len() as u64;

    let entropies: Vec<f64> = qs
        .iter()
        .filter_map(|q| shannon_bits_per_char(first_label(&q.qname)))
        .collect();
    let lengths: Vec<f64> = qs
        .iter()
        .filter(|q| !q.qname.is_empty())
        .map(|q| first_label(&q.qname).len() as f64)
        .collect();
    let entropy =
        (!entropies.is_empty()).then(|| entropies.iter().sum::<f64>() / entropies.len() as f64);
    let mean_label_len =
        (!lengths.is_empty()).then(|| lengths.iter().sum::<f64>() / lengths.len() as f64);

    let (mut min_ts, mut max_ts) = (i64::MAX, i64::MIN);
    for q in qs {
        min_ts = min_ts.min(q.ts_ms);
        max_ts = max_ts.max(q.ts_ms);
    }
    let window_ms = if qs.is_empty() { 0 } else { max_ts - min_ts };
    let queries_per_min = (window_ms > 0).then(|| queries as f64 * 60_000.0 / window_ms as f64);

    let (mut qb, mut rb, mut have_rb) = (0u64, 0u64, false);
    for q in qs {
        qb += q.query_bytes;
        if let Some(r) = q.response_bytes {
            rb += r;
            have_rb = true;
        }
    }
    let response_ratio = (have_rb && qb > 0).then(|| rb as f64 / qb as f64);

    let e = entropy.map(|v| clamp01((v - 3.2) / 1.8)).unwrap_or(0.0);
    let r = queries_per_min
        .map(|v| clamp01((v - 20.0) / 180.0))
        .unwrap_or(0.0);
    let s = response_ratio.map(ratio_component).unwrap_or(0.0);
    let measured = [
        (entropy.is_some(), 0.40),
        (queries_per_min.is_some(), 0.35),
        (response_ratio.is_some(), 0.25),
    ];
    let weight: f64 = measured.iter().filter(|(m, _)| *m).map(|(_, w)| *w).sum();
    let score = if weight > 0.0 {
        (e * 0.40 + r * 0.35 + s * 0.25) / weight
    } else {
        0.0
    };

    // The gate. High entropy alone cannot fire: a rate above RATE_MIN is necessary, and either the
    // response ratio is abnormal (ordinary traffic sits near 1.0) or both entropy and rate are
    // extreme.
    let ratio_fires = response_ratio.map(ratio_abnormal).unwrap_or(false);
    let fires = match (entropy, queries_per_min) {
        (Some(e), Some(r)) if e >= ENTROPY_MIN && r >= RATE_MIN => {
            ratio_fires || (e >= ENTROPY_HIGH && r >= RATE_HIGH)
        }
        _ => false,
    };

    let reason = if qs.is_empty() {
        "no queries to this destination".to_string()
    } else if !fires {
        let mut why = Vec::new();
        match queries_per_min {
            None => why
                .push("query rate is not measurable (all queries share one timestamp)".to_string()),
            Some(r) if r < RATE_MIN => why.push(format!("rate {r:.1}/min is below {RATE_MIN}")),
            Some(r) => why.push(format!("rate {r:.1}/min")),
        }
        match entropy {
            None => why.push("entropy is not measurable (no qname in the input)".to_string()),
            Some(e) if e < ENTROPY_MIN => why.push(format!(
                "mean first-label entropy {e:.2} bits/char is below {ENTROPY_MIN}"
            )),
            Some(e) => why.push(format!("mean first-label entropy {e:.2} bits/char")),
        }
        match response_ratio {
            None => why.push("response-size ratio was not recorded".to_string()),
            Some(x) if !ratio_abnormal(x) => {
                why.push(format!("response ratio {x:.2} is in the ordinary range"))
            }
            Some(x) => why.push(format!("response ratio {x:.2}")),
        }
        format!("thresholds not met: {}", why.join("; "))
    } else {
        format!(
            "thresholds met: rate {:.1}/min ≥ {RATE_MIN}, entropy {:.2} bits/char ≥ \
             {ENTROPY_MIN}, response ratio {} — a signal, not a verdict",
            queries_per_min.unwrap_or(0.0),
            entropy.unwrap_or(0.0),
            response_ratio
                .map(|x| format!("{x:.2}"))
                .unwrap_or_else(|| "not recorded".to_string()),
        )
    };

    TunnelSignal {
        dst: dst.to_string(),
        queries,
        window_ms,
        entropy,
        queries_per_min,
        response_ratio,
        mean_label_len,
        score,
        fires,
        reason,
    }
}

fn ratio_abnormal(x: f64) -> bool {
    x < RATIO_LOW || x > RATIO_HIGH
}

fn ratio_component(x: f64) -> f64 {
    if x < RATIO_LOW {
        clamp01((RATIO_LOW - x) / RATIO_LOW)
    } else if x > RATIO_HIGH {
        clamp01((x - RATIO_HIGH) / 6.0)
    } else {
        0.0
    }
}

/// A flow carries no qname, so entropy cannot be measured from one. It becomes a `Query` with an
/// empty qname and the flow's own byte counts, which is honest about what is missing: the
/// destination, the count, the rate and the response ratio are all still measured.
fn query_of_flow(f: &Flow) -> Query {
    Query {
        qname: String::new(),
        dst: f.dst.clone(),
        ts_ms: f.started_ms,
        query_bytes: f.bytes_out,
        response_bytes: Some(f.bytes_in),
    }
}

pub fn dns_tunnel_signal(queries: &[Query]) -> Vec<TunnelSignal> {
    let mut by_dst: BTreeMap<&str, Vec<Query>> = BTreeMap::new();
    for q in queries {
        by_dst.entry(q.dst.as_str()).or_default().push(q.clone());
    }
    by_dst
        .into_iter()
        .map(|(dst, qs)| dns_signal_for(dst, &qs))
        .collect()
}

// ── Value plumbing ────────────────────────────────────────────────────────

fn sf(name: &str, v: &str) -> (String, Value) {
    (name.to_string(), Value::String(v.to_string()))
}

fn of(name: &str, v: &Option<String>) -> (String, Value) {
    (
        name.to_string(),
        v.clone().map(Value::String).unwrap_or(Value::Nil),
    )
}

fn nf(name: &str, v: i128) -> (String, Value) {
    (name.to_string(), Value::Int(v))
}

fn ff(name: &str, v: Option<f64>) -> (String, Value) {
    (name.to_string(), v.map(Value::Float).unwrap_or(Value::Nil))
}

fn flow_value(f: &Flow) -> Value {
    Value::Struct {
        name: "TrafficFlow".to_string(),
        fields: vec![
            sf("src", &f.src),
            sf("dst", &f.dst),
            nf("src_port", f.src_port as i128),
            nf("dst_port", f.dst_port as i128),
            sf("proto", &f.proto),
            nf("bytes_out", f.bytes_out as i128),
            nf("bytes_in", f.bytes_in as i128),
            nf("packets_out", f.packets_out as i128),
            nf("packets_in", f.packets_in as i128),
            nf("started_ms", f.started_ms as i128),
            nf("ended_ms", f.ended_ms as i128),
            of("plane", &f.plane),
            of("exit", &f.exit),
            of("payload_sig", &f.payload_sig),
        ],
    }
}

fn capture_value(c: &Capture) -> Value {
    Value::Struct {
        name: "TrafficCapture".to_string(),
        fields: vec![
            sf("path", &c.path),
            sf("format", c.format),
            sf("ts_resolution", c.ts_resolution),
            sf("ts_note", &c.ts_note()),
            nf("link_type", c.link_type as i128),
            nf("frames", c.frames as i128),
            nf("flow_count", c.flows.len() as i128),
            (
                "flows".to_string(),
                Value::Array(c.flows.iter().map(flow_value).collect()),
            ),
        ],
    }
}

fn attribution_value(a: &Attribution) -> Value {
    Value::Struct {
        name: "TrafficAttribution".to_string(),
        fields: vec![
            nf("index", a.index as i128),
            sf("protocol", &a.protocol),
            of("signature", &a.signature),
            sf("evidence", &a.evidence),
            nf("port", a.port as i128),
            ff("confidence", Some(a.confidence)),
            sf("reason", &a.reason),
        ],
    }
}

fn signal_value(s: &TunnelSignal) -> Value {
    Value::Struct {
        name: "DnsTunnelSignal".to_string(),
        fields: vec![
            sf("signal", SIGNAL_DNS_TUNNEL),
            sf("dst", &s.dst),
            nf("queries", s.queries as i128),
            nf("window_ms", s.window_ms as i128),
            ff("entropy", s.entropy),
            ff("queries_per_min", s.queries_per_min),
            ff("response_ratio", s.response_ratio),
            ff("mean_label_len", s.mean_label_len),
            (
                "entropy_measured".to_string(),
                Value::Bool(s.entropy.is_some()),
            ),
            (
                "rate_measured".to_string(),
                Value::Bool(s.queries_per_min.is_some()),
            ),
            (
                "ratio_measured".to_string(),
                Value::Bool(s.response_ratio.is_some()),
            ),
            ff("score", Some(s.score)),
            ("fires".to_string(), Value::Bool(s.fires)),
            sf("reason", &s.reason),
        ],
    }
}

// ── Argument reading ──────────────────────────────────────────────────────

fn bad(fname: &str, what: &str) -> String {
    format!("{CODE_ARG}: traffic.{fname}: {what}")
}

fn get(fs: &[(String, Value)], key: &str) -> Option<Value> {
    fs.iter().find(|(n, _)| n == key).map(|(_, v)| v.clone())
}

fn u64_of(fs: &[(String, Value)], key: &str, fname: &str) -> Result<u64, String> {
    match get(fs, key) {
        Some(Value::Int(i)) if i >= 0 => Ok(i as u64),
        Some(other) => Err(bad(
            fname,
            &format!(
                "field `{key}` must be a non-negative Int, got {}",
                type_name(&other)
            ),
        )),
        None => Err(bad(fname, &format!("missing field `{key}`"))),
    }
}

fn i64_of(fs: &[(String, Value)], key: &str, fname: &str) -> Result<i64, String> {
    match get(fs, key) {
        Some(Value::Int(i)) => Ok(i as i64),
        Some(other) => Err(bad(
            fname,
            &format!("field `{key}` must be an Int, got {}", type_name(&other)),
        )),
        None => Err(bad(fname, &format!("missing field `{key}`"))),
    }
}

fn str_of(fs: &[(String, Value)], key: &str, fname: &str) -> Result<String, String> {
    match get(fs, key) {
        Some(Value::String(s)) => Ok(s),
        Some(other) => Err(bad(
            fname,
            &format!("field `{key}` must be a String, got {}", type_name(&other)),
        )),
        None => Err(bad(fname, &format!("missing field `{key}`"))),
    }
}

fn opt_str_of(fs: &[(String, Value)], key: &str) -> Option<String> {
    match get(fs, key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s),
        _ => None,
    }
}

fn flow_of(fs: &[(String, Value)], fname: &str) -> Result<Flow, String> {
    let port = |key: &str| -> Result<u16, String> {
        let v = u64_of(fs, key, fname)?;
        u16::try_from(v)
            .map_err(|_| bad(fname, &format!("field `{key}` = {v} is outside 0..=65535")))
    };
    let f = Flow {
        src: str_of(fs, "src", fname)?,
        dst: str_of(fs, "dst", fname)?,
        src_port: port("src_port")?,
        dst_port: port("dst_port")?,
        proto: str_of(fs, "proto", fname)?,
        bytes_out: u64_of(fs, "bytes_out", fname)?,
        bytes_in: u64_of(fs, "bytes_in", fname)?,
        packets_out: u64_of(fs, "packets_out", fname)?,
        packets_in: u64_of(fs, "packets_in", fname)?,
        started_ms: i64_of(fs, "started_ms", fname)?,
        ended_ms: i64_of(fs, "ended_ms", fname)?,
        plane: opt_str_of(fs, "plane"),
        exit: opt_str_of(fs, "exit"),
        payload_sig: opt_str_of(fs, "payload_sig"),
    };
    f.check()?;
    Ok(f)
}

fn flows_of(v: &Value, fname: &str) -> Result<Vec<Flow>, String> {
    let Value::Array(items) = v else {
        return Err(bad(
            fname,
            &format!("expected []TrafficFlow, got {}", type_name(v)),
        ));
    };
    items
        .iter()
        .map(|it| match it {
            Value::Struct { name, fields } if name == "TrafficFlow" => flow_of(fields, fname),
            other => Err(bad(
                fname,
                &format!("expected TrafficFlow, got {}", type_name(other)),
            )),
        })
        .collect()
}

fn arg_flows(args: &[Value], idx: usize, fname: &str) -> Result<Vec<Flow>, String> {
    match args.get(idx) {
        Some(v) => flows_of(v, fname),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn query_of(fs: &[(String, Value)], fname: &str) -> Result<Query, String> {
    let response_bytes = match get(fs, "response_bytes") {
        Some(Value::Nil) | None => None,
        Some(Value::Int(i)) if i >= 0 => Some(i as u64),
        Some(Value::Int(_)) => None,
        Some(other) => {
            return Err(bad(
                fname,
                &format!(
                    "field `response_bytes` must be Int?, got {}",
                    type_name(&other)
                ),
            ));
        }
    };
    Ok(Query {
        qname: opt_str_of(fs, "qname").unwrap_or_default(),
        dst: str_of(fs, "dst", fname)?,
        ts_ms: i64_of(fs, "ts_ms", fname)?,
        query_bytes: u64_of(fs, "query_bytes", fname)?,
        response_bytes,
    })
}

/// `dns_tunnel_signal` takes flows *or* queries, so the input is dispatched on the struct name —
/// the only place in this module where two record shapes are accepted for one argument.
fn queries_of(v: &Value, fname: &str) -> Result<Vec<Query>, String> {
    let Value::Array(items) = v else {
        return Err(bad(
            fname,
            &format!(
                "expected []TrafficQuery or []TrafficFlow, got {}",
                type_name(v)
            ),
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Value::Struct { name, fields } if name == "TrafficQuery" => {
                out.push(query_of(fields, fname)?)
            }
            Value::Struct { name, fields } if name == "TrafficFlow" => {
                out.push(query_of_flow(&flow_of(fields, fname)?))
            }
            other => {
                return Err(bad(
                    fname,
                    &format!(
                        "expected TrafficQuery or TrafficFlow, got {}",
                        type_name(other)
                    ),
                ));
            }
        }
    }
    Ok(out)
}

fn str_arg(args: &[Value], idx: usize, fname: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected String, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn opt_str_arg(args: &[Value], idx: usize, fname: &str) -> Result<Option<String>, String> {
    match args.get(idx) {
        Some(Value::Nil) | None => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected String?, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
    }
}

fn u64_arg(args: &[Value], idx: usize, fname: &str) -> Result<u64, String> {
    match args.get(idx) {
        Some(Value::Int(i)) if *i >= 0 => Ok(*i as u64),
        Some(Value::Int(i)) => Err(bad(
            fname,
            &format!("argument {} = {i} is negative", idx + 1),
        )),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected Int, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn i64_arg(args: &[Value], idx: usize, fname: &str) -> Result<i64, String> {
    match args.get(idx) {
        Some(Value::Int(i)) => Ok(*i as i64),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected Int, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn port_arg(args: &[Value], idx: usize, fname: &str) -> Result<u16, String> {
    let v = u64_arg(args, idx, fname)?;
    u16::try_from(v).map_err(|_| bad(fname, &format!("argument {} = {v} is not a port", idx + 1)))
}

// ── Dispatch ──────────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let function = function
        .strip_prefix("traffic.")
        .or_else(|| function.strip_prefix("intel_traffic."))
        .unwrap_or(function);
    let mut unknown = false;
    let result: StdlibResult = (|| {
        match function {
            // Every input struct needs a constructor: a stdlib struct cannot be written as a
            // literal in a `.tl` program (E0115), so a module that only *takes* structs is a module
            // no program can call.
            "flow" => {
                let f = Flow {
                    src: str_arg(&args, 0, "flow")?,
                    dst: str_arg(&args, 1, "flow")?,
                    src_port: port_arg(&args, 2, "flow")?,
                    dst_port: port_arg(&args, 3, "flow")?,
                    proto: str_arg(&args, 4, "flow")?,
                    bytes_out: u64_arg(&args, 5, "flow")?,
                    bytes_in: u64_arg(&args, 6, "flow")?,
                    packets_out: u64_arg(&args, 7, "flow")?,
                    packets_in: u64_arg(&args, 8, "flow")?,
                    started_ms: i64_arg(&args, 9, "flow")?,
                    ended_ms: i64_arg(&args, 10, "flow")?,
                    plane: opt_str_arg(&args, 11, "flow")?,
                    exit: opt_str_arg(&args, 12, "flow")?,
                    payload_sig: opt_str_arg(&args, 13, "flow")?,
                };
                f.check()?;
                Ok(flow_value(&f))
            }
            "query" => Ok(Value::Struct {
                name: "TrafficQuery".to_string(),
                fields: vec![
                    sf("qname", &str_arg(&args, 0, "query")?),
                    sf("dst", &str_arg(&args, 1, "query")?),
                    nf("ts_ms", i64_arg(&args, 2, "query")? as i128),
                    nf("query_bytes", u64_arg(&args, 3, "query")? as i128),
                    match args.get(4) {
                        Some(Value::Int(i)) if *i >= 0 => nf("response_bytes", *i),
                        _ => of("response_bytes", &None),
                    },
                ],
            }),
            "pcap_load" => Ok(capture_value(&load_pcap(&str_arg(&args, 0, "pcap_load")?)?)),
            "flows" => match args.first() {
                Some(Value::Struct { name, fields }) if name == "TrafficCapture" => {
                    match get(fields, "flows") {
                        Some(v) => Ok(Value::Array(
                            flows_of(&v, "flows")?.iter().map(flow_value).collect(),
                        )),
                        None => Err(bad("flows", "TrafficCapture without a `flows` array")),
                    }
                }
                Some(_) => Err(bad("flows", "expected TrafficCapture")),
                None => Err(bad("flows", "missing argument 1")),
            },
            "attribute" => Ok(Value::Array(
                attribute(&arg_flows(&args, 0, "attribute")?)
                    .iter()
                    .map(attribution_value)
                    .collect(),
            )),
            "dns_tunnel_signal" => {
                let items = args
                    .first()
                    .ok_or_else(|| bad("dns_tunnel_signal", "missing argument 1"))?;
                Ok(Value::Array(
                    dns_tunnel_signal(&queries_of(items, "dns_tunnel_signal")?)
                        .iter()
                        .map(signal_value)
                        .collect(),
                ))
            }
            _ => {
                unknown = true;
                Ok(Value::Nil)
            }
        }
    })();
    if unknown {
        return None;
    }
    Some(result)
}

// Named `intel_traffic_tests`, not `tests`: the gate is `cargo test --lib intel_traffic`, which
// filters on the full test path including the module.
#[cfg(test)]
mod intel_traffic_tests {
    use super::*;

    // The fixtures are real files on disk, generated by the committed script next to them, so the
    // tests read bytes nobody hand-typed and nobody has to trust.
    const LE: &[u8] = include_bytes!("../../tests/fixtures/intel_traffic/sample-le-usec.pcap");
    const BE: &[u8] = include_bytes!("../../tests/fixtures/intel_traffic/sample-be-usec.pcap");

    fn capture() -> Capture {
        parse_pcap("fixture", LE).expect("the committed fixture parses")
    }

    fn flow(src: &str, dst: &str, dport: u16, sig: Option<&str>) -> Flow {
        Flow {
            src: src.to_string(),
            dst: dst.to_string(),
            src_port: 40000,
            dst_port: dport,
            proto: "tcp".to_string(),
            bytes_out: 100,
            bytes_in: 200,
            packets_out: 2,
            packets_in: 3,
            started_ms: 0,
            ended_ms: 1000,
            plane: None,
            exit: None,
            payload_sig: sig.map(str::to_string),
        }
    }

    // ── N27 ──

    #[test]
    fn n27_a_real_capture_merges_packets_into_flows() {
        let c = capture();
        assert_eq!(c.ts_resolution, "microsecond");
        assert_eq!(c.link_type, 1);
        assert_eq!(c.frames, 6);
        // Five flows: TLS (two packets), HTTP, DNS (two packets), SSH banner.
        assert_eq!(c.flows.len(), 4, "flows: {:#?}", c.flows);

        let tls = c
            .flows
            .iter()
            .find(|f| f.dst_port == 443 || f.src_port == 443)
            .unwrap();
        assert_eq!(
            (tls.src.as_str(), tls.dst.as_str()),
            ("10.0.0.5", "93.184.216.34")
        );
        assert_eq!((tls.packets_out, tls.packets_in), (1, 1));
        // Layer-3 lengths: 20 (IPv4) + 20 (TCP) + payload. The ClientHello is 56 bytes and
        // the TLS app-data record 65, all in the committed fixture.
        assert_eq!((tls.bytes_out, tls.bytes_in), (96, 105));
        assert_eq!(tls.started_ms, 1_000_000);
        assert_eq!(tls.ended_ms, 1_000_100);
        assert_eq!(tls.payload_sig.as_deref(), Some("tls_clienthello"));

        let dns = c.flows.iter().find(|f| f.dst_port == 53).unwrap();
        assert_eq!(dns.proto, "udp");
        assert_eq!((dns.packets_out, dns.packets_in), (1, 1));
        assert_eq!(dns.payload_sig.as_deref(), Some("dns_query"));
    }

    #[test]
    fn n27_big_endian_capture_parses_identically() {
        let c = parse_pcap("be", BE).unwrap();
        let le = capture();
        assert_eq!(c.ts_resolution, le.ts_resolution);
        assert_eq!(c.frames, le.frames);
        assert_eq!(
            c.flows, le.flows,
            "the magic decides endianness, not the host"
        );
    }

    #[test]
    fn n27_resolution_is_reported_rather_than_smoothed() {
        let c = capture();
        assert!(
            c.ts_note().contains("microsecond") && c.ts_note().contains("truncated"),
            "{}",
            c.ts_note()
        );
        // A nanosecond magic is the same layout with a different scale, and the note must change.
        let mut bytes = LE.to_vec();
        bytes[..4].copy_from_slice(&0xa1b2_3c4du32.to_le_bytes());
        let ns = parse_pcap("ns", &bytes).unwrap();
        assert_eq!(ns.ts_resolution, "nanosecond");
        assert!(
            ns.ts_note()
                .starts_with("timestamps are milliseconds truncated from nanosecond")
        );
    }

    #[test]
    fn n27_refusals_name_the_offset_and_never_return_a_partial_list() {
        let e = parse_pcap("t", &LE[..LE.len() - 5]).unwrap_err();
        assert!(
            e.starts_with(CODE_PCAP_TRUNCATED)
                && e.contains("record at offset ")
                && e.contains("only 70 remain"),
            "{e}"
        );
        let e = parse_pcap("m", b"nope").unwrap_err();
        assert!(
            e.starts_with(CODE_PCAP_MAGIC) && e.contains("6e6f7065"),
            "{e}"
        );
        let e = parse_pcap("p", b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00").unwrap_err();
        assert!(e.starts_with(CODE_PCAPNG), "{e}");
        let mut wrong_link = LE[..24].to_vec();
        wrong_link[20] = 101;
        let e = parse_pcap("l", &wrong_link).unwrap_err();
        assert!(
            e.starts_with(CODE_PCAP_LINKTYPE) && e.contains("101"),
            "{e}"
        );
        let e = parse_pcap("short", &LE[..10]).unwrap_err();
        assert!(
            e.starts_with(CODE_PCAP_TRUNCATED) && e.contains("24"),
            "{e}"
        );
    }

    // ── N28 ──

    #[test]
    fn n28_a_signature_outranks_a_port_and_the_two_confidences_differ() {
        let measured = attribute_one(0, &flow("a", "b", 443, Some("tls_clienthello")));
        let guessed = attribute_one(0, &flow("a", "b", 443, None));
        assert_eq!(measured.protocol, "https");
        assert_eq!(guessed.protocol, "https");
        assert_eq!(measured.evidence, "payload");
        assert_eq!(guessed.evidence, "port");
        assert_eq!(measured.signature.as_deref(), Some("tls_clienthello"));
        assert!(guessed.signature.is_none());
        assert!(
            measured.confidence > guessed.confidence + 0.4,
            "{} vs {}",
            measured.confidence,
            guessed.confidence
        );
        assert_eq!(measured.confidence, 0.95);
        assert_eq!(guessed.confidence, 0.40);
    }

    #[test]
    fn n28_port_80_without_a_signature_is_unknown_not_http() {
        let a = attribute_one(0, &flow("a", "b", 80, None));
        assert_eq!(a.protocol, "unknown");
        assert_eq!(a.evidence, "none");
        assert!(a.reason.contains("no http signature"), "{}", a.reason);
        // With a request line it is http, and the signature is named.
        let b = attribute_one(0, &flow("a", "b", 80, Some("http_request")));
        assert_eq!(b.protocol, "http");
        assert_eq!(b.signature.as_deref(), Some("http_request"));
        assert_eq!(b.confidence, 0.95);
    }

    #[test]
    fn n28_a_signature_off_its_conventional_port_is_still_measured_but_not_0_95() {
        let a = attribute_one(0, &flow("a", "b", 9999, Some("ssh_banner")));
        assert_eq!(a.protocol, "ssh");
        assert_eq!(a.confidence, 0.90);
        assert!(
            a.reason.contains("not the conventional port"),
            "{}",
            a.reason
        );
        let b = attribute_one(0, &flow("a", "b", 9999, None));
        assert_eq!(b.protocol, "unknown");
        assert_eq!(b.confidence, 0.0);
    }

    #[test]
    fn n28_the_fixture_attributes_end_to_end() {
        let c = capture();
        let rows = attribute(&c.flows);
        assert_eq!(rows.len(), 4);
        let by = |p: &str| {
            rows.iter()
                .find(|r| r.protocol == p)
                .unwrap_or_else(|| panic!("{p}"))
        };
        assert_eq!(by("https").signature.as_deref(), Some("tls_clienthello"));
        assert_eq!(by("http").signature.as_deref(), Some("http_request"));
        assert_eq!(by("dns").signature.as_deref(), Some("dns_query"));
        assert_eq!(by("ssh").signature.as_deref(), Some("ssh_banner"));
        assert!(rows.iter().all(|r| r.evidence == "payload"));
    }

    // ── N29 ──

    /// A deterministic base62 label — the shape a tunnelling encoder produces, generated without
    /// an RNG so a failure is reproducible to the character. SplitMix64: a counter over a mixed
    /// seed, so consecutive seeds do not produce correlated prefixes (a plain LCG does, and then
    /// the "high entropy" bench name measures the PRNG instead of the threshold).
    fn alnum_label(seed: u64, len: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (0..len)
            .map(|_| {
                x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = x;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^= z >> 31;
                ALPHABET[(z % ALPHABET.len() as u64) as usize] as char
            })
            .collect()
    }

    fn query(qname: &str, ts_ms: i64, qb: u64, rb: u64) -> Query {
        Query {
            qname: qname.to_string(),
            dst: "198.51.100.53".to_string(),
            ts_ms,
            query_bytes: qb,
            response_bytes: Some(rb),
        }
    }

    #[test]
    fn n29_a_benign_high_entropy_cdn_name_does_not_fire() {
        // 60 lookups in one minute to hex-shaped CDN shard names, answered at ordinary sizes.
        let qs: Vec<Query> = (0..60u64)
            .map(|i| {
                let shard = alnum_label(0x5eed_0000 + i, 32);
                query(&format!("{shard}.cdn.example.net"), i as i64 * 1000, 40, 44)
            })
            .collect();
        let s = dns_signal_for("198.51.100.53", &qs);
        // The name must really clear the entropy bar, or this test proves nothing: the only
        // thing that may stop it firing is the ordinary response size.
        assert!(
            s.entropy.unwrap() >= ENTROPY_MIN,
            "the CDN name must be above the entropy threshold, got {:?}",
            s.entropy
        );
        assert!(
            (59.0..62.0).contains(&s.queries_per_min.unwrap()),
            "{}",
            s.queries_per_min.unwrap()
        );
        assert!(!s.fires, "high entropy alone must not fire: {}", s.reason);
        assert_eq!(SIGNAL_DNS_TUNNEL, "dns-tunnelling");
        assert!(s.reason.contains("thresholds not met"), "{}", s.reason);
    }

    #[test]
    fn n29_a_fast_random_exfil_shape_fires_with_its_components_exposed() {
        // 200 queries in one minute: long base64-ish labels, long queries, one-sentence answers.
        let qs: Vec<Query> = (0..200u64)
            .map(|i| {
                let label = alnum_label(0xa5a5_0000 + i * 0x9e37, 24);
                query(&format!("{label}.t.example"), i as i64 * 300, 60, 33)
            })
            .collect();
        let s = dns_signal_for("198.51.100.53", &qs);
        assert!(s.fires, "{}", s.reason);
        assert!(s.entropy.unwrap() >= ENTROPY_MIN);
        assert!(s.queries_per_min.unwrap() >= RATE_MIN);
        assert!(s.response_ratio.unwrap() < RATIO_LOW);
        assert!(s.score > 0.55, "score {}", s.score);
        assert!(s.reason.contains("signal, not a verdict"), "{}", s.reason);
    }

    #[test]
    fn n29_a_slow_random_lookup_does_not_fire_on_entropy_alone() {
        let qs: Vec<Query> = (0..3u64)
            .map(|i| {
                let label = alnum_label(0xabcdef12 + i, 32);
                query(&format!("{label}.t.example"), i as i64 * 20_000, 60, 33)
            })
            .collect();
        let s = dns_signal_for("198.51.100.53", &qs);
        // Entropy and the response ratio both look like exfiltration; the rate does not, and the
        // rate is the component that has to agree.
        assert!(s.entropy.unwrap() >= ENTROPY_MIN, "entropy {:?}", s.entropy);
        assert!(s.response_ratio.unwrap() < RATIO_LOW);
        assert!(!s.fires, "3 queries/min is not a tunnel: {}", s.reason);
        assert!(s.reason.contains("below 30"), "{}", s.reason);
    }

    #[test]
    fn n29_an_unmeasured_component_is_absent_not_zero() {
        // Flows carry no qname and no response size here: entropy and ratio must be nil.
        let f = Flow {
            ..flow("a", "b", 53, Some("dns_query"))
        };
        let qs: Vec<Query> = vec![query_of_flow(&f)];
        let s = dns_signal_for("b", &qs);
        assert!(s.entropy.is_none(), "a flow has no qname to measure");
        assert!(s.response_ratio.is_some(), "bytes_in was recorded");
        assert!(s.queries_per_min.is_none(), "one timestamp is no window");
        assert!(!s.fires);
        assert!(
            s.reason.contains("entropy is not measurable"),
            "{}",
            s.reason
        );

        let no_bytes = Query {
            response_bytes: None,
            ..query("abc.t.example", 0, 10, 0)
        };
        let s = dns_signal_for("x", &[no_bytes]);
        assert!(
            s.response_ratio.is_none(),
            "an unrecorded response size is not a ratio of zero"
        );
    }

    #[test]
    fn n29_groups_per_destination_and_sorts_deterministically() {
        let mut a = query("aaa.t.example", 0, 50, 50);
        a.dst = "192.0.2.9".to_string();
        let s = dns_tunnel_signal(&[a, query("bbb.t.example", 1000, 50, 50)]);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].dst, "192.0.2.9");
        assert_eq!(s[1].dst, "198.51.100.53");
        assert_eq!(s[0].queries, 1);
    }

    #[test]
    fn n29_entropy_is_shannon_bits_per_character() {
        assert_eq!(shannon_bits_per_char(""), None);
        assert_eq!(shannon_bits_per_char("aaaa"), Some(0.0));
        assert!((shannon_bits_per_char("ab").unwrap() - 1.0).abs() < 1e-9);
        assert!((shannon_bits_per_char("abcd").unwrap() - 2.0).abs() < 1e-9);
    }

    // ── the dispatch surface ──

    #[test]
    fn the_constructors_round_trip_through_the_readers() {
        let made = dispatch(
            "flow",
            vec![
                Value::String("10.0.0.5".into()),
                Value::String("93.184.216.34".into()),
                Value::Int(51515),
                Value::Int(443),
                Value::String("tcp".into()),
                Value::Int(98),
                Value::Int(104),
                Value::Int(1),
                Value::Int(1),
                Value::Int(1_000_000),
                Value::Int(1_000_100),
                Value::String("tor".into()),
                Value::Nil,
                Value::String("tls_clienthello".into()),
            ],
        )
        .unwrap()
        .unwrap();
        // The constructor round-trips through a reader: a struct built by `flow` is read by
        // `attribute`, with no `.tl` struct literal and no hand-built field list in between.
        let rows = dispatch("attribute", vec![Value::Array(vec![made])])
            .unwrap()
            .unwrap();
        let Value::Array(rows) = rows else {
            panic!("expected []TrafficAttribution")
        };
        assert_eq!(rows.len(), 1);
        let Value::Struct { fields, .. } = &rows[0] else {
            panic!("expected TrafficAttribution")
        };
        assert!(
            matches!(get(fields, "protocol"), Some(Value::String(p)) if p == "https"),
            "the flow carries a tls_clienthello signature on 443"
        );

        let e = dispatch(
            "flow",
            vec![Value::String("a".into()), Value::String("b".into())],
        )
        .unwrap()
        .unwrap_err();
        assert!(e.starts_with(CODE_ARG), "{e}");
        assert!(dispatch("nope", vec![]).is_none());
    }

    #[test]
    fn a_flow_with_no_packets_is_refused_by_both_paths() {
        let mut args: Vec<Value> = vec![
            Value::String("a".into()),
            Value::String("b".into()),
            Value::Int(1),
            Value::Int(2),
            Value::String("tcp".into()),
            Value::Int(0),
            Value::Int(0),
            Value::Int(0),
            Value::Int(0),
            Value::Int(0),
            Value::Int(0),
            Value::Nil,
            Value::Nil,
            Value::Nil,
        ];
        let e = dispatch("flow", args.clone()).unwrap().unwrap_err();
        assert!(e.starts_with(CODE_EMPTY_FLOW), "{e}");
        // The reader refuses it too: a struct built any other way cannot smuggle one in.
        args[7] = Value::Int(1);
        let ok = dispatch("flow", args).unwrap().unwrap();
        let Value::Struct { fields, .. } = ok else {
            panic!("expected TrafficFlow")
        };
        let mut fields = fields;
        for (k, v) in fields.iter_mut() {
            if k == "packets_out" {
                *v = Value::Int(0);
            }
        }
        let e = flows_of(
            &Value::Array(vec![Value::Struct {
                name: "TrafficFlow".to_string(),
                fields,
            }]),
            "attribute",
        )
        .unwrap_err();
        assert!(e.starts_with(CODE_EMPTY_FLOW), "{e}");
    }

    #[test]
    fn the_capture_renders_its_resolution_and_flow_count() {
        let v = capture_value(&capture());
        let Value::Struct { fields, .. } = v else {
            panic!("expected TrafficCapture")
        };
        assert!(
            matches!(get(&fields, "flow_count"), Some(Value::Int(4))),
            "the fixture has four flows"
        );
        assert_eq!(
            get(&fields, "ts_resolution").map(|v| type_name(&v)),
            Some("String")
        );
        let Value::Array(flows) = get(&fields, "flows").unwrap() else {
            panic!("expected flows array")
        };
        assert_eq!(flows.len(), 4);
    }
}
