//! `tallow.traffic` — offline traffic observation (N27).
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
//! in N29, the plane counts in N30) would be computed over a fiction. There is no partial credit
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

pub const SIGNAL_DNS_TUNNEL: &str = "dns-tunnelling";

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

    /// A deterministic base62 label — the shape a tunnelling encoder produces, generated without
    /// an RNG so a failure is reproducible to the character. SplitMix64: a counter over a mixed
    /// seed, so consecutive seeds do not produce correlated prefixes (a plain LCG does, and then
    /// the "high entropy" bench name measures the PRNG instead of the threshold).
    // ── the dispatch surface ──

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
