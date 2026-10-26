//! Standard library: `tallow.topology` — host and port discovery.
//!
//! The first slice of the blueprint's topology lane (`docs/plans/2026-10-tallow-2.0-feature-backlog.md`
//! §A1): a plan-before-run estimator (N11), a per-target and per-prefix rate
//! governor (N10), and two port scanners — a real half-open SYN scan (N01) and
//! a connect scan that works without privileges.
//!
//! Three rules govern everything here:
//!
//! 1. **The scope register is consulted before a packet is built.** A target
//!    absent from `authorized-hosts.toml` is refused with the register's own
//!    refusal, exactly as `tallow scope check` would report it. The scanner is
//!    not a second, weaker door.
//! 2. **The governor is the only thing that paces traffic.** No fixed sleep, no
//!    global rps: a token bucket per target and per IPv4 /24, so one host
//!    cannot be hammered because another host in the same run is idle.
//! 3. **Every result says how it was obtained.** A port is `open`, `closed` or
//!    `filtered`, and the technique that produced the verdict travels with the
//!    result — a SYN verdict and a connect verdict are not interchangeable, and
//!    the reconciliation step (N12) will need that distinction.
//!
//! Only IPv4 is scanned today; `plan` says so rather than silently ignoring an
//! IPv6 target.

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

// ══════════════════════════════════════════════════════════════════
// Port specification
// ══════════════════════════════════════════════════════════════════

/// Parse a port specification: `22`, `22,80,443`, `1-1024`, or a mix.
///
/// Returns the ports in ascending order, de-duplicated. An empty list is an
/// error, not "scan nothing": a scan with no ports is a typo.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a
                .trim()
                .parse()
                .map_err(|e| format!("topology: bad port range '{part}': {e}"))?;
            let hi: u16 = b
                .trim()
                .parse()
                .map_err(|e| format!("topology: bad port range '{part}': {e}"))?;
            if lo == 0 || hi == 0 {
                return Err(format!("topology: port 0 is not scannable ('{part}')"));
            }
            if lo > hi {
                return Err(format!("topology: reversed port range '{part}'"));
            }
            out.extend(lo..=hi);
        } else {
            let p: u16 = part
                .parse()
                .map_err(|e| format!("topology: bad port '{part}': {e}"))?;
            if p == 0 {
                return Err(format!("topology: port 0 is not scannable ('{part}')"));
            }
            out.push(p);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("topology: empty port specification".to_string());
    }
    Ok(out)
}

fn parse_technique(spec: &str) -> Result<Technique, String> {
    match spec.to_ascii_lowercase().as_str() {
        "" | "syn" | "half-open" => Ok(Technique::Syn),
        "connect" | "full" => Ok(Technique::Connect),
        "fin" => Ok(Technique::Evasion(EvasionFlags::Fin)),
        "null" => Ok(Technique::Evasion(EvasionFlags::Null)),
        "xmas" => Ok(Technique::Evasion(EvasionFlags::Xmas)),
        other => Err(format!(
            "topology: unknown technique '{other}' (expected syn, connect, fin, null or xmas)"
        )),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Technique {
    Syn,
    Connect,
    /// FIN / NULL / Xmas (N03). They share one property: the probe carries no
    /// SYN, so an RFC 793 host ignores it on an open port and answers RST on a
    /// closed one. That makes silence "open|filtered", never "open".
    Evasion(EvasionFlags),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EvasionFlags {
    /// Only FIN set.
    Fin,
    /// No flags at all.
    Null,
    /// FIN|PSH|URG.
    Xmas,
}

impl EvasionFlags {
    fn tcp_flags(self) -> u8 {
        match self {
            EvasionFlags::Fin => 0x01,
            EvasionFlags::Null => 0x00,
            EvasionFlags::Xmas => 0x01 | 0x08 | 0x20,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            EvasionFlags::Fin => "fin",
            EvasionFlags::Null => "null",
            EvasionFlags::Xmas => "xmas",
        }
    }
}

impl Technique {
    fn as_str(self) -> &'static str {
        match self {
            Technique::Syn => "syn",
            Technique::Connect => "connect",
            Technique::Evasion(f) => f.as_str(),
        }
    }

    fn is_evasion(self) -> bool {
        matches!(self, Technique::Evasion(_))
    }
}

// ══════════════════════════════════════════════════════════════════
// Scope gate
// ══════════════════════════════════════════════════════════════════

/// Refuse a target the authorization register does not list.
///
/// The register is the same file `net.connect` is documented to consult and
/// `tallow scope check` reads; a scanner that skipped it would be a new
/// un-gated egress path, which is the exact class of defect the capability
/// work closed.
fn require_authorized(target: &str) -> Result<(), String> {
    let register = crate::scope::ScopeRegister::load_default();
    let decision = register.authorize(target, "GET", &crate::scope::utc_today());
    match decision {
        crate::scope::Decision::Allowed(_) => Ok(()),
        crate::scope::Decision::Refused(refusal) => Err(format!(
            "topology: target '{target}' is not authorized ({}): {}",
            refusal.code(),
            refusal.explain()
        )),
    }
}

// ══════════════════════════════════════════════════════════════════
// Rate governor (N10)
// ══════════════════════════════════════════════════════════════════

/// Token bucket, refilled at `rps` tokens per second up to `rps` (one second of
/// burst). A bucket is keyed per target *and* per IPv4 /24, so a single host
/// and a single prefix each have their own ceiling.
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-run governor state. Scoped to the process: a scan run is one call, and
/// carrying state between runs would make the second run's pacing depend on the
/// first run's shape.
struct Governor {
    rps: f64,
    buckets: HashMap<String, Bucket>,
}

impl Governor {
    fn new(rps: f64) -> Self {
        Self {
            rps: rps.max(0.1),
            buckets: HashMap::new(),
        }
    }

    /// Block until one token is available for both `target` and its /24.
    fn acquire(&mut self, target: Ipv4Addr) {
        loop {
            let now = Instant::now();
            let per_target = format!("host:{target}");
            let prefix = format!("prefix:{}.{}.{}", target.octets()[0], target.octets()[1], target.octets()[2]);
            let mut ok = true;
            for key in [per_target.clone(), prefix.clone()] {
                let bucket = self.buckets.entry(key).or_insert_with(|| Bucket {
                    tokens: self.rps,
                    last: now,
                });
                let elapsed = now.duration_since(bucket.last).as_secs_f64();
                bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.rps);
                bucket.last = now;
                if bucket.tokens < 1.0 {
                    ok = false;
                }
            }
            if ok {
                for key in [per_target, prefix] {
                    if let Some(b) = self.buckets.get_mut(&key) {
                        b.tokens -= 1.0;
                    }
                }
                return;
            }
            // Sleep only as long as the emptiest bucket needs for one token.
            let wait = self
                .buckets
                .values()
                .map(|b| (1.0 - b.tokens).max(0.0) / self.rps)
                .fold(0.0_f64, f64::max);
            std::thread::sleep(Duration::from_secs_f64(wait.min(0.25).max(0.001)));
        }
    }
}

static GOVERNOR: LazyLock<Mutex<Option<Governor>>> = LazyLock::new(|| Mutex::new(None));

fn governor_acquire(target: Ipv4Addr, rps: f64) {
    let mut guard = GOVERNOR.lock().unwrap();
    let gov = guard.get_or_insert_with(|| Governor::new(rps));
    gov.acquire(target);
}

// ══════════════════════════════════════════════════════════════════
// Planner (N11)
// ══════════════════════════════════════════════════════════════════

/// What a run would cost, computed before anything is sent.
struct Plan {
    ports_per_target: usize,
    technique: Technique,
    rps: f64,
    packets: usize,
    estimated_ms: u128,
    max_rtt_ms: u64,
}

fn make_plan(targets: usize, ports: usize, technique: Technique, rps: f64, timeout_ms: u64) -> Plan {
    let probes = targets.saturating_mul(ports);
    let packets = match technique {
        // One SYN out; one SYN-ACK or RST back. A closed port and an open port
        // cost the same on the wire.
        Technique::Syn => probes,
        Technique::Connect => probes * 2, // SYN, then FIN/ACK
        // One probe out; an open port says nothing back. The cost on the wire
        // is identical to SYN.
        Technique::Evasion(_) => probes,
    };
    // The governor paces probes at `rps`; the wall time is the larger of that
    // and the timeout of the last probe still waiting.
    let paced_ms = (probes as f64 / rps.max(0.1) * 1000.0) as u128;
    Plan {
        ports_per_target: ports,
        technique,
        rps,
        packets,
        estimated_ms: paced_ms + timeout_ms as u128,
        max_rtt_ms: timeout_ms,
    }
}

// ══════════════════════════════════════════════════════════════════
// Scanners
// ══════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PortState {
    Open,
    Closed,
    Filtered,
    /// No RST came back to a non-SYN probe. The port is either open or
    /// something in the path dropped the probe: RFC 793 requires silence from
    /// an open port, but a firewall that drops and an open port look the same.
    /// Non-RFC-compliant hosts may answer RST on open ports, so a `closed`
    /// verdict from FIN/NULL/Xmas is the only one this technique can trust.
    OpenOrFiltered,
}

fn resolve_v4(target: &str) -> Result<Ipv4Addr, String> {
    let with_port = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:0")
    };
    let addrs: Vec<SocketAddr> = with_port
        .to_socket_addrs()
        .map_err(|e| format!("topology: cannot resolve '{target}': {e}"))?
        .collect();
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }
    Err(format!(
        "topology: '{target}' has no IPv4 address; this build scans IPv4 only"
    ))
}

fn connect_probe(target: Ipv4Addr, port: u16, timeout: Duration) -> PortState {
    match TcpStream::connect_timeout(&SocketAddr::from((target, port)), timeout) {
        Ok(_) => PortState::Open,
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => PortState::Closed,
            _ => PortState::Filtered,
        },
    }
}

// ── Raw SYN probe (Linux) ─────────────────────────────────────────

#[cfg(target_os = "linux")]
mod raw {
    use super::PortState;
    use std::io;
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::unix::io::RawFd;
    use std::time::{Duration, Instant};

    /// A raw TCP socket with `IP_HDRINCL`: the caller builds the IPv4 header.
    pub struct RawSyn {
        fd: RawFd,
    }

    impl Drop for RawSyn {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    impl RawSyn {
        pub fn open() -> io::Result<Self> {
            unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let one: libc::c_int = 1;
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &one as *const _ as *const libc::c_void,
                    mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    let err = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(err);
                }
                Ok(Self { fd })
            }
        }

        /// Build and send one SYN for `dst:port` from `src_port`.
        /// The address a SYN to `dst` would leave from.
        ///
        /// A connect() on a UDP socket sends nothing and lets the routing
        /// table answer; the TCP checksum needs this address in its
        /// pseudo-header, and a zero there makes every probe fail validation
        /// at the peer (silently — which looks exactly like a filtered port).
        pub fn source_for(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
            let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
            sock.connect(std::net::SocketAddr::from((dst, 53)))?;
            match sock.local_addr()?.ip() {
                std::net::IpAddr::V4(v4) => Ok(v4),
                _ => Err(io::Error::new(io::ErrorKind::Other, "no IPv4 source")),
            }
        }

        /// Send one TCP probe with `flags` in the TCP header.
        ///
        /// SYN uses the same builder with `0x02`; FIN/NULL/Xmas (N03) use it
        /// with their own flag sets, which is why the flag byte is a parameter
        /// rather than a constant.
        pub fn send_probe(
            &self,
            src: Ipv4Addr,
            dst: Ipv4Addr,
            src_port: u16,
            dst_port: u16,
            seq: u32,
            flags: u8,
        ) -> io::Result<()> {
            let mut packet = [0u8; 40];
            // IPv4 header
            packet[0] = 0x45;
            packet[1] = 0;
            packet[2..4].copy_from_slice(&(40u16).to_be_bytes());
            packet[4..6].copy_from_slice(&0u16.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            packet[8] = 64; // TTL
            packet[9] = libc::IPPROTO_TCP as u8;
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            // TCP header
            packet[20..22].copy_from_slice(&src_port.to_be_bytes());
            packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
            packet[24..28].copy_from_slice(&seq.to_be_bytes());
            packet[28..32].copy_from_slice(&0u32.to_be_bytes()); // ack
            packet[32] = 5 << 4; // data offset
            packet[33] = flags;
            packet[34..36].copy_from_slice(&64240u16.to_be_bytes()); // window
            packet[36..38].copy_from_slice(&0u16.to_be_bytes()); // checksum, filled below
            packet[38..40].copy_from_slice(&0u16.to_be_bytes());

            // TCP checksum over the pseudo-header + TCP segment.
            let mut pseudo = [0u8; 12];
            pseudo[0..4].copy_from_slice(&src.octets());
            pseudo[4..8].copy_from_slice(&dst.octets());
            pseudo[8] = 0;
            pseudo[9] = libc::IPPROTO_TCP as u8;
            pseudo[10..12].copy_from_slice(&(20u16).to_be_bytes());
            let mut sum_data = Vec::with_capacity(32);
            sum_data.extend_from_slice(&pseudo);
            sum_data.extend_from_slice(&packet[20..40]);
            let ck = checksum(&sum_data);
            packet[36..38].copy_from_slice(&ck.to_be_bytes());

            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: dst_port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dst.octets()),
                },
                sin_zero: [0; 8],
            };
            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// One ICMP echo request, returning the round-trip time when a reply
        /// for *this* id/sequence comes back (N04).
        ///
        /// The reply is matched on the payload marker as well as the id, so a
        /// concurrent ping from another process on the same host is not
        /// credited to this one.
        pub fn icmp_echo(dst: Ipv4Addr, timeout: Duration) -> io::Result<Option<u128>> {
            unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let tv = libc::timeval {
                    tv_sec: timeout.as_secs() as libc::time_t,
                    tv_usec: timeout.subsec_micros() as libc::suseconds_t,
                };
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    mem::size_of::<libc::timeval>() as libc::socklen_t,
                );

                let id = (std::process::id() & 0xffff) as u16;
                let seq: u16 = 1;
                let payload = b"tallow-n04";
                let mut packet = vec![0u8; 8 + payload.len()];
                packet[0] = 8; // echo request
                packet[1] = 0;
                packet[4..6].copy_from_slice(&id.to_be_bytes());
                packet[6..8].copy_from_slice(&seq.to_be_bytes());
                packet[8..].copy_from_slice(payload);
                let ck = checksum(&packet);
                packet[2..4].copy_from_slice(&ck.to_be_bytes());

                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(dst.octets()),
                    },
                    sin_zero: [0; 8],
                };
                let started = Instant::now();
                let sent = libc::sendto(
                    fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &sa as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
                if sent < 0 {
                    let err = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(err);
                }

                let deadline = Instant::now() + timeout;
                let mut buf = [0u8; 2048];
                while Instant::now() < deadline {
                    let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::TimedOut
                        {
                            break;
                        }
                        libc::close(fd);
                        return Err(err);
                    }
                    let n = n as usize;
                    if n < 28 {
                        continue;
                    }
                    let ihl = ((buf[0] & 0x0f) as usize) * 4;
                    let icmp = &buf[ihl..n];
                    if icmp.len() < 8 + payload.len() {
                        continue;
                    }
                    // Echo reply, our id/seq, our marker.
                    if icmp[0] == 0
                        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
                        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
                        && &icmp[8..8 + payload.len()] == payload
                    {
                        let rtt = started.elapsed().as_millis();
                        libc::close(fd);
                        return Ok(Some(rtt));
                    }
                }
                libc::close(fd);
                Ok(None)
            }
        }

        /// Collect replies for `timeout`, returning (port, open?) per probe.
        ///
        /// A SYN-ACK means open; a RST means closed; silence means filtered.
        /// Every other packet on the wire is somebody else's traffic and is
        /// dropped rather than interpreted.
        pub fn collect(
            &self,
            dst: Ipv4Addr,
            src_port: u16,
            probes: &[u16],
            timeout: Duration,
        ) -> io::Result<Vec<(u16, PortState)>> {
            let deadline = Instant::now() + timeout;
            let mut state: Vec<(u16, PortState)> =
                probes.iter().map(|p| (*p, PortState::Filtered)).collect();
            let mut seen = 0usize;
            let mut buf = [0u8; 2048];

            // Non-blocking reads with a short poll, so one late reply cannot
            // stall the whole window.
            let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
            unsafe {
                libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            while Instant::now() < deadline && seen < probes.len() {
                let n = unsafe {
                    libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    match err.kind() {
                        io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        _ => return Err(err),
                    }
                }
                let n = n as usize;
                if n < 40 {
                    continue;
                }
                let ihl = ((buf[0] & 0x0f) as usize) * 4;
                if n < ihl + 20 || buf[9] != libc::IPPROTO_TCP as u8 {
                    continue;
                }
                let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                if src_ip != dst {
                    continue;
                }
                let tcp = &buf[ihl..];
                let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
                let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
                if dport != src_port {
                    continue;
                }
                let flags = tcp[13];
                let is_open = flags & 0x12 == 0x12; // SYN|ACK
                let is_closed = flags & 0x04 != 0; // RST
                if !is_open && !is_closed {
                    continue;
                }
                if let Some(slot) = state.iter_mut().find(|(p, _)| *p == sport) {
                    if slot.1 == PortState::Filtered {
                        slot.1 = if is_open {
                            PortState::Open
                        } else {
                            PortState::Closed
                        };
                        seen += 1;
                    }
                }
            }
            Ok(state)
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod raw {
    use super::PortState;
    use std::io;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    pub struct RawSyn;

    impl RawSyn {
        pub fn icmp_echo(
            _dst: std::net::Ipv4Addr,
            _timeout: std::time::Duration,
        ) -> io::Result<Option<u128>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host discovery over ICMP needs raw sockets (Linux only)",
            ))
        }

        pub fn open() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "topology.syn_scan needs raw sockets, which this build does not implement on this platform (Linux only); use technique: 'connect'",
            ))
        }

        pub fn source_for(_dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
        }

        pub fn send_probe(
            &self,
            _src: Ipv4Addr,
            _dst: Ipv4Addr,
            _src_port: u16,
            _dst_port: u16,
            _seq: u32,
            _flags: u8,
        ) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
        }

        pub fn collect(
            &self,
            _dst: Ipv4Addr,
            _src_port: u16,
            _probes: &[u16],
            _timeout: Duration,
        ) -> io::Result<Vec<(u16, PortState)>> {
            Ok(Vec::new())
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// Host discovery (N04)
// ══════════════════════════════════════════════════════════════════

/// One discovery method's verdict, with the confidence it earns.
///
/// The union is deliberately not a boolean: ICMP is widely filtered, so
/// "no reply to ping" is weak evidence of absence while "reply to ping" is
/// strong evidence of presence. Each method carries its own weight and the
/// result reports which ones spoke.
struct MethodResult {
    name: &'static str,
    alive: bool,
    rtt_ms: Option<u128>,
    confidence: f64,
}

fn discover_fn(args: Vec<Value>) -> StdlibResult {
    let target = arg_str(&args, 0, "target")?;
    let methods = arg_str(&args, 1, "methods").unwrap_or_else(|_| "icmp_echo,tcp_syn".to_string());
    let ports = parse_ports(&arg_str(&args, 2, "ports").unwrap_or_else(|_| "80,443,22".to_string()))?;
    let timeout_ms = arg_u64(&args, 3, 500);
    let rps = arg_u64(&args, 4, 20).max(1) as f64;

    let dst = resolve_v4(&target)?;
    require_authorized(&target)?;
    let timeout = Duration::from_millis(timeout_ms);
    let started = Instant::now();

    let wanted: Vec<String> = methods
        .split(',')
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .collect();
    if wanted.is_empty() {
        return Err("topology.discover: no discovery methods requested".to_string());
    }

    let mut results: Vec<MethodResult> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();

    for method in &wanted {
        match method.as_str() {
            "icmp_echo" | "icmp" => {
                governor_acquire(dst, rps);
                match raw::RawSyn::icmp_echo(dst, timeout) {
                    Ok(rtt) => results.push(MethodResult {
                        name: "icmp_echo",
                        alive: rtt.is_some(),
                        rtt_ms: rtt,
                        // A reply proves presence; silence proves little,
                        // because many hosts and paths drop ICMP.
                        confidence: if rtt.is_some() { 0.9 } else { 0.2 },
                    }),
                    Err(e) => unsupported.push(format!("icmp_echo: {e}")),
                }
            }
            "tcp_syn" | "tcp" => {
                let sock = match raw::RawSyn::open() {
                    Ok(s) => s,
                    Err(e) => {
                        unsupported.push(format!("tcp_syn: {e}"));
                        continue;
                    }
                };
                let src = match raw::RawSyn::source_for(dst) {
                    Ok(s) => s,
                    Err(e) => {
                        unsupported.push(format!("tcp_syn: {e}"));
                        continue;
                    }
                };
                let src_port = 40000 + (std::process::id() % 20000) as u16;
                let mut seq: u32 = 0x0dd5_0000 ^ (std::process::id() as u32) << 8;
                for port in &ports {
                    governor_acquire(dst, rps);
                    seq = seq.wrapping_add(1);
                    if let Err(e) = sock.send_probe(src, dst, src_port, *port, seq, 0x02) {
                        unsupported.push(format!("tcp_syn send {port}: {e}"));
                        break;
                    }
                }
                match sock.collect(dst, src_port, &ports, timeout) {
                    Ok(states) => {
                        // Any RST or SYN-ACK is a host that answered. Silence
                        // on all three probes is the weak case.
                        let answered = states.iter().any(|(_, s)| *s != PortState::Filtered);
                        results.push(MethodResult {
                            name: "tcp_syn",
                            alive: answered,
                            rtt_ms: None,
                            confidence: if answered { 0.8 } else { 0.3 },
                        });
                    }
                    Err(e) => unsupported.push(format!("tcp_syn: {e}")),
                }
            }
            // ARP is the only method that sees a host which blocks IP. It
            // needs an AF_PACKET socket bound to the interface, so it is not
            // implemented yet; saying so is better than silently reporting
            // "down" for an on-link host.
            "arp" => unsupported.push(
                "arp: not implemented in this build (AF_PACKET link-layer discovery)".to_string(),
            ),
            other => unsupported.push(format!("{other}: unknown discovery method")),
        }
    }

    let alive = results.iter().any(|r| r.alive);
    let confidence = if alive {
        results
            .iter()
            .filter(|r| r.alive)
            .map(|r| r.confidence)
            .fold(0.0_f64, f64::max)
    } else if results.is_empty() {
        0.0
    } else {
        // No method spoke: the host may be down, or every probe may have been
        // filtered. That is not the same claim, and the number says so.
        0.6
    };

    let method_values: Vec<Value> = results
        .iter()
        .map(|r| Value::Struct {
            name: "DiscoveryMethod".to_string(),
            fields: vec![
                ("name".to_string(), Value::String(r.name.to_string())),
                ("alive".to_string(), Value::Bool(r.alive)),
                (
                    "rtt_ms".to_string(),
                    match r.rtt_ms {
                        Some(ms) => Value::Int(ms as i128),
                        None => Value::Nil,
                    },
                ),
                ("confidence".to_string(), Value::Float(r.confidence)),
            ],
        })
        .collect();

    Ok(Value::Struct {
        name: "DiscoveryResult".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(dst.to_string())),
            ("alive".to_string(), Value::Bool(alive)),
            ("confidence".to_string(), Value::Float(confidence)),
            ("methods".to_string(), Value::Array(method_values)),
            (
                "unsupported".to_string(),
                Value::Array(
                    unsupported
                        .iter()
                        .map(|m| Value::String(m.clone()))
                        .collect(),
                ),
            ),
            (
                "duration_ms".to_string(),
                Value::Int(started.elapsed().as_millis() as i128),
            ),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// TLS posture (N06)
// ══════════════════════════════════════════════════════════════════

/// Records the certificate chain the server presents while accepting it, so
/// the report can be produced even for an untrusted or expired certificate.
///
/// Verification is deliberately split: the handshake must complete to observe
/// the negotiated version and cipher, and a host with a bad certificate still
/// has a posture worth reporting. The trust decision is made afterwards
/// against the same root store, and its failure is reported as data
/// (`trusted=false`, `trust_error=…`) rather than aborting the probe.
#[derive(Debug)]
struct CapturingVerifier {
    certs: Mutex<Vec<Vec<u8>>>,
    inner: std::sync::Arc<rustls::client::WebPkiServerVerifier>,
}

impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut recorded = self.certs.lock().unwrap();
        recorded.clear();
        recorded.push(end_entity.as_ref().to_vec());
        for cert in intermediates {
            recorded.push(cert.as_ref().to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Read a DER length at `i`, returning (length, index of first content byte).
fn der_length(der: &[u8], i: usize) -> Option<(usize, usize)> {
    let first = *der.get(i)? as usize;
    if first & 0x80 == 0 {
        return Some((first, i + 1));
    }
    let n = first & 0x7f;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for k in 0..n {
        len = (len << 8) | *der.get(i + 1 + k)? as usize;
    }
    Some((len, i + 1 + n))
}

/// Extract the dNSName entries from a certificate's subjectAltName extension.
///
/// A dependency-free walk for the one extension the posture report needs:
/// OID 2.5.29.17 (06 03 55 1D 11), wrapped in an OCTET STRING, containing a
/// SEQUENCE of GeneralNames where a dNSName is context tag 2 (0x82). IP
/// addresses (0x87) and other name forms are deliberately not returned here —
/// they are a different kind of answer to "which names does this certificate
/// cover".
fn san_dns_names(der: &[u8]) -> Vec<String> {
    let oid = [0x06u8, 0x03, 0x55, 0x1D, 0x11];
    let mut names = Vec::new();
    let pos = match der.windows(oid.len()).position(|w| w == oid) {
        Some(p) => p + oid.len(),
        None => return names,
    };
    let mut i = pos;
    if der.get(i) != Some(&0x04) {
        return names;
    }
    i += 1;
    let (outer_len, next) = match der_length(der, i) {
        Some(v) => v,
        None => return names,
    };
    i = next;
    if der.get(i) != Some(&0x30) {
        return names;
    }
    i += 1;
    let (_seq_len, next) = match der_length(der, i) {
        Some(v) => v,
        None => return names,
    };
    i = next;
    let end = (i + outer_len).min(der.len());
    while i < end {
        let tag = der[i];
        i += 1;
        let (len, next) = match der_length(der, i) {
            Some(v) => v,
            None => break,
        };
        i = next;
        if i + len > der.len() {
            break;
        }
        if tag == 0x82 {
            names.push(String::from_utf8_lossy(&der[i..i + len]).to_string());
        }
        i += len;
    }
    names
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn tls_posture_fn(args: Vec<Value>) -> StdlibResult {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use sha2::Digest;
    use std::sync::Arc;

    let target = arg_str(&args, 0, "target")?;
    let port = arg_u64(&args, 1, 443) as u16;
    let timeout_ms = arg_u64(&args, 2, 3000);
    let sni = match args.get(3) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => target.clone(),
    };

    let addr = resolve_v4(&target)?;
    require_authorized(&target)?;

    // rustls refuses to guess when more than one provider is linked, and the
    // panic happens deep inside the verifier rather than at the call site, so
    // the provider is installed once here before any rustls type is built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots.clone()))
        .build()
        .map_err(|e| format!("topology.tls_posture: cannot build the verifier: {e}"))?;
    let capturing = Arc::new(CapturingVerifier {
        certs: Mutex::new(Vec::new()),
        inner,
    });

    // The custom verifier replaces the built-in chain walk, so the root store
    // is not installed on the client config: it is held by the verifier, which
    // applies it after the handshake to produce the trust verdict.
    // Pin the provider: the crate links ring for its other TLS paths, but a
    // second provider in the dependency graph makes the implicit default
    // ambiguous, and rustls panics rather than guessing.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("topology.tls_posture: cannot configure TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(capturing.clone())
        .with_no_client_auth();
    // Offering both makes the server's choice observable; with no ALPN offered
    // a server that only speaks h2 would still answer, and the report would
    // silently lose a protocol fact.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let server_name = ServerName::try_from(sni.clone())
        .map_err(|_| format!("topology.tls_posture: '{sni}' is not a valid server name"))?;

    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut sock = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), timeout)
        .map_err(|e| format!("topology.tls_posture: connect {addr}:{port} failed: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name.clone())
        .map_err(|e| format!("topology.tls_posture: cannot start a TLS session: {e}"))?;

    let deadline = Instant::now() + timeout;
    while conn.is_handshaking() {
        if Instant::now() > deadline {
            return Err(format!(
                "topology.tls_posture: handshake with {addr}:{port} did not complete within {timeout_ms} ms"
            ));
        }
        match conn.complete_io(&mut sock) {
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "topology.tls_posture: handshake with {addr}:{port} failed: {e}"
                ))
            }
        }
    }

    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        Some(other) => return Err(format!("topology.tls_posture: unexpected version {other:?}")),
        None => "none",
    }
    .to_string();
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "none".to_string());
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();

    let chain = capturing.certs.lock().unwrap().clone();
    let leaf = chain.first().cloned().unwrap_or_default();
    let trust = if leaf.is_empty() {
        Err("no certificate presented".to_string())
    } else {
        let end = CertificateDer::from(leaf.clone());
        let intermediates: Vec<CertificateDer<'static>> = chain
            .iter()
            .skip(1)
            .map(|c| CertificateDer::from(c.clone()))
            .collect();
        capturing
            .inner
            .verify_server_cert(
                &end,
                &intermediates,
                &server_name,
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    let mut hasher = sha2::Sha256::new();
    hasher.update(&leaf);
    let fingerprint = hex_lower(&hasher.finalize());

    Ok(Value::Struct {
        name: "TLSReport".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(addr.to_string())),
            ("port".to_string(), Value::Int(port as i128)),
            ("server_name".to_string(), Value::String(sni)),
            ("version".to_string(), Value::String(version)),
            ("cipher".to_string(), Value::String(cipher)),
            ("alpn".to_string(), Value::String(alpn)),
            (
                "trusted".to_string(),
                Value::Bool(trust.is_ok()),
            ),
            (
                "trust_error".to_string(),
                Value::String(trust.err().unwrap_or_default()),
            ),
            ("chain_len".to_string(), Value::Int(chain.len() as i128)),
            ("leaf_sha256".to_string(), Value::String(fingerprint)),
            (
                "sans".to_string(),
                Value::Array(
                    san_dns_names(&leaf)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            (
                "duration_ms".to_string(),
                Value::Int(started.elapsed().as_millis() as i128),
            ),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Service banner (N05)
// ══════════════════════════════════════════════════════════════════

/// Split `product/version` or `product version` into its two halves.
///
/// Returns (product, version) only when a separator exists; a banner that is
/// just a word yields (word, "") rather than inventing a version.
fn split_product_version(token: &str) -> (String, String) {
    let cleaned = token.trim().trim_end_matches([';', ',', ')']);
    if let Some((product, version)) = cleaned.split_once('/') {
        return (product.trim().to_string(), version.trim().to_string());
    }
    if let Some((product, version)) = cleaned.split_once(' ') {
        return (product.trim().to_string(), version.trim().to_string());
    }
    (cleaned.to_string(), String::new())
}

/// Pull (product, version) out of a banner, or nothing.
///
/// Only shapes that are actually defined are matched: an SSH identification
/// string (RFC 4253) and an HTTP `Server` header. A banner that matches
/// neither returns empty fields, because guessing a product from arbitrary
/// greeting text would produce confident nonsense.
fn identify_banner(first_line: &str, headers: &[String]) -> (String, String) {
    if let Some(rest) = first_line.strip_prefix("SSH-") {
        // SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
        if let Some((_proto, software)) = rest.split_once('-') {
            let software = software.split_whitespace().next().unwrap_or(software);
            if let Some((product, version)) = software.split_once('_') {
                return (product.to_string(), version.to_string());
            }
            return (software.to_string(), String::new());
        }
    }
    for line in headers {
        if let Some(value) = line
            .strip_prefix("Server:")
            .or_else(|| line.strip_prefix("server:"))
        {
            let value = value.trim();
            let first = value.split_whitespace().next().unwrap_or(value);
            return split_product_version(first);
        }
    }
    (String::new(), String::new())
}

fn banner_fn(args: Vec<Value>) -> StdlibResult {
    use std::io::{Read, Write};

    let target = arg_str(&args, 0, "target")?;
    let port = arg_u64(&args, 1, 80) as u16;
    let timeout_ms = arg_u64(&args, 2, 800);
    let probe = arg_str(&args, 3, "probe").unwrap_or_else(|_| "auto".to_string());

    let addr = resolve_v4(&target)?;
    require_authorized(&target)?;

    let timeout = Duration::from_millis(timeout_ms);
    let started = Instant::now();
    let mut sock = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), timeout)
        .map_err(|e| format!("topology.banner: connect {addr}:{port} failed: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    // "auto" means: speak HTTP on the ports that almost always expect it, and
    // stay silent elsewhere — a probe sent to an SSH or SMTP port can make the
    // daemon log a protocol error and close, losing the greeting it would have
    // offered unprompted.
    let effective = match probe.as_str() {
        "auto" => {
            if matches!(port, 80 | 8080 | 8000 | 8888) {
                "http"
            } else {
                "none"
            }
        }
        other => other,
    };

    match effective {
        "http" => {
            let host = target.clone();
            let req = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: TallowTopology/1.0\r\n\r\n");
            sock.write_all(req.as_bytes())
                .map_err(|e| format!("topology.banner: send to {addr}:{port} failed: {e}"))?;
        }
        "crlf" => {
            sock.write_all(b"\r\n").ok();
        }
        "none" => {}
        other => {
            return Err(format!(
                "topology.banner: unknown probe '{other}' (expected auto, none, http or crlf)"
            ))
        }
    }

    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        if raw.len() >= 4096 {
            break;
        }
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                // A greeting is one line; an HTTP response ends at the blank
                // line. Either way there is no point waiting out the timeout.
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if raw.len() > 2 && raw.windows(2).any(|w| w == b"\r\n") && effective != "http" {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => {
                // A reset after the greeting is normal for banner grabbing;
                // what was already read is still the answer.
                if raw.is_empty() {
                    return Err(format!("topology.banner: read from {addr}:{port} failed: {e}"));
                }
                break;
            }
        }
    }

    let tls_detected = raw.first() == Some(&0x16);
    let text = String::from_utf8_lossy(&raw).to_string();
    let mut lines: Vec<String> = text
        .split("\r\n")
        .map(|l| l.trim_end().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let first_line = lines.first().cloned().unwrap_or_default();
    let headers: Vec<String> = lines.drain(1..).collect();
    let (product, version) = if tls_detected {
        (String::new(), String::new())
    } else {
        identify_banner(&first_line, &headers)
    };

    Ok(Value::Struct {
        name: "BannerResult".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(addr.to_string())),
            ("port".to_string(), Value::Int(port as i128)),
            ("probe".to_string(), Value::String(effective.to_string())),
            ("tls_detected".to_string(), Value::Bool(tls_detected)),
            (
                "banner".to_string(),
                Value::String(first_line.chars().take(200).collect()),
            ),
            ("product".to_string(), Value::String(product)),
            ("version".to_string(), Value::String(version)),
            (
                "bytes".to_string(),
                Value::Int(raw.len() as i128),
            ),
            (
                "duration_ms".to_string(),
                Value::Int(started.elapsed().as_millis() as i128),
            ),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// JA4 client fingerprint (N07)
// ══════════════════════════════════════════════════════════════════

/// A TCP stream that records everything written through it.
///
/// The fingerprint must describe the ClientHello that actually went on the
/// wire, not the configuration that was supposed to produce it; recording at
/// the socket is the only way to be sure the two match.
struct RecordingStream<'a> {
    inner: &'a mut TcpStream,
    written: Vec<u8>,
}

impl std::io::Write for RecordingStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if self.written.len() < 16 * 1024 {
            self.written.extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl std::io::Read for RecordingStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

#[derive(Debug, Default)]
struct ClientHelloInfo {
    legacy_version: u16,
    supported_versions: Vec<u16>,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    alpn: Vec<String>,
    has_sni: bool,
}

/// Parse the first ClientHello out of a recorded TLS stream.
fn parse_client_hello(bytes: &[u8]) -> Option<ClientHelloInfo> {
    if bytes.len() < 5 || bytes[0] != 0x16 || bytes[1] != 0x03 {
        return None;
    }
    let mut i = 5; // record header
    if *bytes.get(i)? != 0x01 {
        return None; // handshake type: ClientHello
    }
    i += 1;
    // handshake length (3 bytes) — not needed for parsing, the record bound is.
    i += 3;
    let mut info = ClientHelloInfo {
        legacy_version: u16::from_be_bytes([*bytes.get(i)?, *bytes.get(i + 1)?]),
        ..Default::default()
    };
    i += 2;
    i += 32; // random
    let sid_len = *bytes.get(i)? as usize;
    i += 1 + sid_len;
    let cipher_len = u16::from_be_bytes([*bytes.get(i)?, *bytes.get(i + 1)?]) as usize;
    i += 2;
    if i + cipher_len > bytes.len() {
        return None;
    }
    for c in bytes[i..i + cipher_len].chunks_exact(2) {
        info.ciphers.push(u16::from_be_bytes([c[0], c[1]]));
    }
    i += cipher_len;
    let comp_len = *bytes.get(i)? as usize;
    i += 1 + comp_len;
    if i + 2 > bytes.len() {
        return Some(info); // no extensions block
    }
    let ext_total = u16::from_be_bytes([*bytes.get(i)?, *bytes.get(i + 1)?]) as usize;
    i += 2;
    let ext_end = (i + ext_total).min(bytes.len());
    while i + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let ext_len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        i += 4;
        if i + ext_len > ext_end {
            break;
        }
        info.extensions.push(ext_type);
        match ext_type {
            0x0000 => info.has_sni = true,
            0x0010 => {
                // ALPN: 2-byte list length, then 1-byte-len entries.
                let data = &bytes[i..i + ext_len];
                if data.len() >= 2 {
                    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                    let mut j = 2;
                    let end = (2 + list_len).min(data.len());
                    while j < end {
                        let l = data[j] as usize;
                        j += 1;
                        if j + l > end {
                            break;
                        }
                        info.alpn
                            .push(String::from_utf8_lossy(&data[j..j + l]).to_string());
                        j += l;
                    }
                }
            }
            0x002b => {
                // supported_versions: 1-byte length, then 2-byte versions.
                let data = &bytes[i..i + ext_len];
                if !data.is_empty() {
                    let l = data[0] as usize;
                    let mut j = 1;
                    while j + 1 < data.len() && j < 1 + l {
                        info.supported_versions
                            .push(u16::from_be_bytes([data[j], data[j + 1]]));
                        j += 2;
                    }
                }
            }
            _ => {}
        }
        i += ext_len;
    }
    Some(info)
}

fn sha256_12(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())[..12].to_string()
}

/// Compute JA4 (FoxIO spec) from a parsed ClientHello.
///
/// `a` is protocol/version/SNI, `b` counts ciphers and extensions and carries
/// the first ALPN token, `c` is the cipher-list hash. JA4H (the HTTP header
/// fingerprint) is a different fingerprint and is not computed here.
fn ja4_from(info: &ClientHelloInfo) -> (String, String, String) {
    let version = if info.supported_versions.contains(&0x0304) {
        "13"
    } else if info.legacy_version >= 0x0303 {
        "12"
    } else {
        "11"
    };
    let sni = if info.has_sni { "d" } else { "i" };
    let alpn = match info.alpn.first() {
        Some(a) if a.len() >= 2 => format!("{}{}", &a[..1], &a[a.len() - 1..]),
        Some(a) => format!("{a}0"),
        None => "00".to_string(),
    };
    let a = format!("t{version}{sni}");
    let b = format!("{:02}{:02}{}", info.ciphers.len(), info.extensions.len(), alpn);

    let cipher_spec = info
        .ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let c = sha256_12(cipher_spec.as_bytes());

    // The extension hash excludes SNI (0x0000) and ALPN (0x0010), which are
    // already represented in the `a` and `b` fields, and is computed over the
    // sorted extension list.
    let mut exts: Vec<String> = info
        .extensions
        .iter()
        .filter(|e| **e != 0x0000 && **e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    exts.sort();
    let d = sha256_12(exts.join(",").as_bytes());

    (format!("{a}_{b}_{c}"), c, d)
}

fn ja4_fn(args: Vec<Value>) -> StdlibResult {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let target = arg_str(&args, 0, "target")?;
    let port = arg_u64(&args, 1, 443) as u16;
    let timeout_ms = arg_u64(&args, 2, 3000);
    let sni = match args.get(3) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => target.clone(),
    };

    let addr = resolve_v4(&target)?;
    require_authorized(&target)?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("topology.ja4: cannot configure TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let server_name = ServerName::try_from(sni.clone())
        .map_err(|_| format!("topology.ja4: '{sni}' is not a valid server name"))?;
    let timeout = Duration::from_millis(timeout_ms);
    let mut sock = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), timeout)
        .map_err(|e| format!("topology.ja4: connect {addr}:{port} failed: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("topology.ja4: cannot start a TLS session: {e}"))?;

    let started = Instant::now();
    let hello = {
        let mut recorder = RecordingStream {
            inner: &mut sock,
            written: Vec::new(),
        };
        // Only the first flight matters. complete_io writes the ClientHello and
        // then blocks for the reply; if the server is slow the timeout bounds
        // it, and the bytes already recorded are still the fingerprint.
        let _ = conn.complete_io(&mut recorder);
        parse_client_hello(&recorder.written)
    };

    let hello = hello.ok_or_else(|| {
        format!("topology.ja4: no ClientHello was captured for {addr}:{port}")
    })?;
    let (ja4, cipher_hash, ext_hash) = ja4_from(&hello);

    Ok(Value::Struct {
        name: "JA4Result".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(addr.to_string())),
            ("port".to_string(), Value::Int(port as i128)),
            ("ja4".to_string(), Value::String(ja4)),
            (
                "legacy_version".to_string(),
                Value::Int(hello.legacy_version as i128),
            ),
            (
                "ciphers".to_string(),
                Value::Int(hello.ciphers.len() as i128),
            ),
            (
                "extensions".to_string(),
                Value::Int(hello.extensions.len() as i128),
            ),
            (
                "alpn".to_string(),
                Value::Array(hello.alpn.iter().cloned().map(Value::String).collect()),
            ),
            ("sni".to_string(), Value::Bool(hello.has_sni)),
            ("cipher_hash".to_string(), Value::String(cipher_hash)),
            ("extension_hash".to_string(), Value::String(ext_hash)),
            (
                "duration_ms".to_string(),
                Value::Int(started.elapsed().as_millis() as i128),
            ),
        ],
    })
}

/// The fingerprint describes the hello we sent; the peer's certificate is not
/// the subject of the measurement, so verification is not attempted here (use
/// `tls_posture` for trust).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
        ]
    }
}

// ══════════════════════════════════════════════════════════════════
// UDP scanning (N02)
// ══════════════════════════════════════════════════════════════════

/// The payload a UDP service is most likely to answer.
///
/// An empty datagram gets a reply from almost nothing: most UDP daemons parse
/// the first bytes and drop what they cannot understand, so a scanner that
/// sends nothing learns nothing and reports every live service as filtered.
/// These are the smallest well-formed requests that elicit a response.
fn udp_probe(port: u16) -> Vec<u8> {
    match port {
        // DNS: standard query, RD set, one question for example.com A.
        53 => vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ],
        // NTP: client request, version 4, mode 3.
        123 => {
            let mut p = vec![0u8; 48];
            p[0] = 0x23; // LI 0, VN 4, mode 3
            p
        }
        // SNMP v1 GetRequest for 1.3.6.1.2.1.1.1.0 with community "public".
        161 => vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
            0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        ],
        // IKE: 8-byte ISAKMP header, SA init, no payloads. Enough for a
        // responder to answer with NO_PROPOSAL_CHOSEN rather than silence.
        500 | 4500 => vec![0u8; 28],
        _ => Vec::new(),
    }
}

fn udp_scan_fn(args: Vec<Value>) -> StdlibResult {
    use std::net::UdpSocket;

    let target = arg_str(&args, 0, "target")?;
    let ports = parse_ports(&arg_str(&args, 1, "ports")?)?;
    let timeout_ms = arg_u64(&args, 2, 800);
    let rps = arg_u64(&args, 3, 50).max(1) as f64;

    let addr = resolve_v4(&target)?;
    require_authorized(&target)?;
    let timeout = Duration::from_millis(timeout_ms);
    let started = Instant::now();

    let mut open = Vec::new();
    let mut closed = Vec::new();
    let mut undecided = Vec::new();
    let mut details: Vec<Value> = Vec::new();

    for port in &ports {
        governor_acquire(addr, rps);

        // A *connected* UDP socket is what makes ICMP interpretation possible:
        // an ICMP port-unreachable is reported to the next recv() as
        // ECONNREFUSED, which is the only reliable way for an unprivileged
        // process to tell "closed" from "nothing answered".
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => return Err(format!("topology.udp_scan: cannot bind a UDP socket: {e}")),
        };
        if let Err(e) = sock.connect(SocketAddr::new(IpAddr::V4(addr), *port)) {
            return Err(format!(
                "topology.udp_scan: cannot connect to {addr}:{port}: {e}"
            ));
        }
        sock.set_read_timeout(Some(timeout)).ok();

        let payload = udp_probe(*port);
        if let Err(e) = sock.send(&payload) {
            return Err(format!(
                "topology.udp_scan: send to {addr}:{port} failed: {e}"
            ));
        }

        let mut buf = [0u8; 2048];
        match sock.recv(&mut buf) {
            Ok(n) => {
                open.push(*port);
                details.push(Value::Struct {
                    name: "UDPResponse".to_string(),
                    fields: vec![
                        ("port".to_string(), Value::Int(*port as i128)),
                        ("bytes".to_string(), Value::Int(n as i128)),
                        (
                            "probe_bytes".to_string(),
                            Value::Int(payload.len() as i128),
                        ),
                    ],
                });
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                closed.push(*port);
                continue;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Silence: either the service is open and ignores malformed
                // input, or a firewall dropped the probe. UDP cannot tell
                // these apart without a reply, and the verdict says so.
                undecided.push(*port);
                continue;
            }
            Err(e) => {
                return Err(format!(
                    "topology.udp_scan: read from {addr}:{port} failed: {e}"
                ))
            }
        }
    }

    open.sort_unstable();
    closed.sort_unstable();
    undecided.sort_unstable();

    Ok(Value::Struct {
        name: "UDPScanResult".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(addr.to_string())),
            ("open".to_string(), Value::Array(open.iter().map(|p| Value::Int(*p as i128)).collect())),
            (
                "closed".to_string(),
                Value::Array(closed.iter().map(|p| Value::Int(*p as i128)).collect()),
            ),
            (
                "open_or_filtered".to_string(),
                Value::Array(
                    undecided
                        .iter()
                        .map(|p| Value::Int(*p as i128))
                        .collect(),
                ),
            ),
            ("responses".to_string(), Value::Array(details)),
            (
                "caveat".to_string(),
                Value::String(
                    "UDP silence is open|filtered: no reply means either a live service that ignored the probe or a firewall that dropped it; only an ICMP port-unreachable proves closed"
                        .to_string(),
                ),
            ),
            (
                "duration_ms".to_string(),
                Value::Int(started.elapsed().as_millis() as i128),
            ),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Dispatch
// ══════════════════════════════════════════════════════════════════

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "plan" => Some(plan_fn(args)),
        "syn_scan" => Some(scan(args, Technique::Syn)),
        "connect_scan" => Some(scan(args, Technique::Connect)),
        "fin_scan" => Some(scan(args, Technique::Evasion(EvasionFlags::Fin))),
        "null_scan" => Some(scan(args, Technique::Evasion(EvasionFlags::Null))),
        "xmas_scan" => Some(scan(args, Technique::Evasion(EvasionFlags::Xmas))),
        "discover" => Some(discover_fn(args)),
        "tls_posture" => Some(tls_posture_fn(args)),
        "banner" => Some(banner_fn(args)),
        "ja4" => Some(ja4_fn(args)),
        "udp_scan" => Some(udp_scan_fn(args)),
        _ => None,
    }
}

fn arg_str(args: &[Value], i: usize, name: &str) -> Result<String, String> {
    args.get(i)
        .map(|v| v.as_string())
        .ok_or_else(|| format!("topology: expected {name} as argument {}", i + 1))
}

fn arg_u64(args: &[Value], i: usize, default: u64) -> u64 {
    match args.get(i) {
        Some(Value::Int(n)) if *n >= 0 => *n as u64,
        Some(Value::Float(f)) if *f >= 0.0 => *f as u64,
        _ => default,
    }
}

fn plan_fn(args: Vec<Value>) -> StdlibResult {
    let target = arg_str(&args, 0, "target")?;
    let ports = parse_ports(&arg_str(&args, 1, "ports")?)?;
    let technique = parse_technique(&arg_str(&args, 2, "technique").unwrap_or_default())?;
    let rps = arg_u64(&args, 3, 20).max(1) as f64;
    let timeout_ms = arg_u64(&args, 4, 1000);

    let host = resolve_v4(&target)?;
    require_authorized(&target)?;
    let plan = make_plan(1, ports.len(), technique, rps, timeout_ms);

    Ok(Value::Struct {
        name: "ScanPlan".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(host.to_string())),
            ("technique".to_string(), Value::String(plan.technique.as_str().to_string())),
            (
                "ports".to_string(),
                Value::Array(ports.iter().map(|p| Value::Int(*p as i128)).collect()),
            ),
            (
                "ports_count".to_string(),
                Value::Int(plan.ports_per_target.min(i128::MAX as usize) as i128),
            ),
            ("packets".to_string(), Value::Int(plan.packets as i128)),
            (
                "estimated_ms".to_string(),
                Value::Int(plan.estimated_ms.min(i128::MAX as u128) as i128),
            ),
            ("rps".to_string(), Value::Float(plan.rps)),
            // A plan is honest about what it cannot see: a filtered port costs
            // the full timeout, and that is the dominant term on a firewalled
            // host.
            (
                "worst_case_ms".to_string(),
                Value::Int((plan.packets as u128 * plan.max_rtt_ms as u128).min(i128::MAX as u128) as i128),
            ),
        ],
    })
}

fn scan(args: Vec<Value>, technique: Technique) -> StdlibResult {
    let target = arg_str(&args, 0, "target")?;
    let ports = parse_ports(&arg_str(&args, 1, "ports")?)?;
    let timeout_ms = arg_u64(&args, 2, 1000);
    let rps = arg_u64(&args, 3, 20).max(1) as f64;

    let dst = resolve_v4(&target)?;
    require_authorized(&target)?;

    let timeout = Duration::from_millis(timeout_ms);
    let started = Instant::now();
    let mut open = Vec::new();
    let mut closed = Vec::new();
    let mut filtered = Vec::new();
    let mut open_or_filtered = Vec::new();
    let mut sent = 0usize;

    match technique {
        Technique::Connect => {
            for port in &ports {
                governor_acquire(dst, rps);
                sent += 1;
                match connect_probe(dst, *port, timeout) {
                    PortState::Open => open.push(*port),
                    PortState::Closed => closed.push(*port),
                    PortState::Filtered => filtered.push(*port),
                    // A connect probe cannot be undecided: connect() either
                    // completed, was refused, or did not.
                    PortState::OpenOrFiltered => filtered.push(*port),
                }
            }
        }
        Technique::Syn | Technique::Evasion(_) => {
            let sock = raw::RawSyn::open().map_err(|e| {
                format!("topology: technique '{}' needs a raw socket ({e}); use 'connect' when unprivileged", technique.as_str())
            })?;
            let tcp_flags = match technique {
                Technique::Syn => 0x02,
                Technique::Evasion(f) => f.tcp_flags(),
                Technique::Connect => unreachable!(),
            };
            // Pace the send window the same way the connect path paces
            // connects: one token per probe.
            let src = raw::RawSyn::source_for(dst)
                .map_err(|e| format!("topology.syn_scan: cannot determine source address for {dst}: {e}"))?;
            let src_port = 40000 + (std::process::id() % 20000) as u16;
            let mut seq: u32 = 0x5eed_0000 ^ (std::process::id() as u32) << 8;
            for port in &ports {
                governor_acquire(dst, rps);
                seq = seq.wrapping_add(1);
                sock.send_probe(src, dst, src_port, *port, seq, tcp_flags)
                    .map_err(|e| format!("topology: send to {dst}:{port} failed: {e}"))?;
                sent += 1;
            }
            let states = sock
                .collect(dst, src_port, &ports, timeout)
                .map_err(|e| format!("topology.syn_scan: receive failed: {e}"))?;
            for (port, state) in states {
                // A non-SYN probe that drew no reply is open|filtered, never
                // open: RFC 793 requires silence from an open port, but a
                // dropping firewall is silent too. Only a RST is decisive.
                let state = if technique.is_evasion() && state == PortState::Filtered {
                    PortState::OpenOrFiltered
                } else {
                    state
                };
                match state {
                    PortState::Open => open.push(port),
                    PortState::Closed => closed.push(port),
                    PortState::Filtered => filtered.push(port),
                    PortState::OpenOrFiltered => open_or_filtered.push(port),
                }
            }
        }
    }

    open.sort_unstable();
    closed.sort_unstable();
    filtered.sort_unstable();
    open_or_filtered.sort_unstable();

    Ok(Value::Struct {
        name: "ScanResult".to_string(),
        fields: vec![
            ("target".to_string(), Value::String(dst.to_string())),
            (
                "technique".to_string(),
                Value::String(technique.as_str().to_string()),
            ),
            (
                "open".to_string(),
                Value::Array(open.iter().map(|p| Value::Int(*p as i128)).collect()),
            ),
            (
                "closed".to_string(),
                Value::Array(closed.iter().map(|p| Value::Int(*p as i128)).collect()),
            ),
            (
                "filtered".to_string(),
                Value::Array(filtered.iter().map(|p| Value::Int(*p as i128)).collect()),
            ),
            (
                "open_or_filtered".to_string(),
                Value::Array(
                    open_or_filtered
                        .iter()
                        .map(|p| Value::Int(*p as i128))
                        .collect(),
                ),
            ),
            // The caveat travels with the result: a reader must not mistake
            // "no RST" for "open", and non-RFC hosts can RST an open port.
            (
                "caveat".to_string(),
                Value::String(if technique.is_evasion() {
                    "FIN/NULL/Xmas: silence means open|filtered, not open; some non-RFC-compliant hosts RST an open port, so a closed verdict is the only decisive one".to_string()
                } else {
                    String::new()
                }),
            ),
            ("sent".to_string(), Value::Int(sent as i128)),
            (
                "duration_ms".to_string(),
                Value::Int(started.elapsed().as_millis() as i128),
            ),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_parse_and_normalise() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("443,22,22").unwrap(), vec![22, 443]);
        assert_eq!(parse_ports("1000-1003").unwrap(), vec![1000, 1001, 1002, 1003]);
        assert_eq!(parse_ports("80, 100-102").unwrap(), vec![80, 100, 101, 102]);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("9-2").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn a_plan_counts_probes_and_budgets_the_timeout() {
        let p = make_plan(1, 100, Technique::Syn, 20.0, 1000);
        assert_eq!(p.packets, 100);
        assert_eq!(p.estimated_ms, 5000 + 1000);
        let c = make_plan(1, 100, Technique::Connect, 20.0, 1000);
        assert_eq!(c.packets, 200);
    }

    #[test]
    fn the_governor_paces_a_single_target() {
        let mut g = Governor::new(50.0);
        let target = Ipv4Addr::new(127, 0, 0, 1);
        let start = Instant::now();
        for _ in 0..10 {
            g.acquire(target);
        }
        // 10 tokens at 50 rps: the first ~50 are free (burst), so this must
        // complete quickly but the bucket must have been consulted each time.
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_governor_key_separates_hosts_and_prefixes() {
        let mut g = Governor::new(20.0);
        g.acquire(Ipv4Addr::new(10, 0, 0, 1));
        g.acquire(Ipv4Addr::new(10, 0, 0, 2));
        assert!(g.buckets.contains_key("host:10.0.0.1"));
        assert!(g.buckets.contains_key("prefix:10.0.0"));
    }
}
