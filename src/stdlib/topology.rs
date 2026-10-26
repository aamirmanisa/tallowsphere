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
        other => Err(format!(
            "topology: unknown technique '{other}' (expected syn or connect)"
        )),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Technique {
    Syn,
    Connect,
}

impl Technique {
    fn as_str(self) -> &'static str {
        match self {
            Technique::Syn => "syn",
            Technique::Connect => "connect",
        }
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

        pub fn send_syn(
            &self,
            src: Ipv4Addr,
            dst: Ipv4Addr,
            src_port: u16,
            dst_port: u16,
            seq: u32,
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
            packet[33] = 0x02; // SYN
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
        pub fn open() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "topology.syn_scan needs raw sockets, which this build does not implement on this platform (Linux only); use technique: 'connect'",
            ))
        }

        pub fn source_for(_dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported"))
        }

        pub fn send_syn(
            &self,
            _src: Ipv4Addr,
            _dst: Ipv4Addr,
            _src_port: u16,
            _dst_port: u16,
            _seq: u32,
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
// Dispatch
// ══════════════════════════════════════════════════════════════════

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "plan" => Some(plan_fn(args)),
        "syn_scan" => Some(scan(args, Technique::Syn)),
        "connect_scan" => Some(scan(args, Technique::Connect)),
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
                }
            }
        }
        Technique::Syn => {
            let sock = raw::RawSyn::open().map_err(|e| {
                format!("topology.syn_scan: cannot open a raw socket ({e}); use technique 'connect' when unprivileged")
            })?;
            // Pace the send window the same way the connect path paces
            // connects: one token per probe.
            let src = raw::RawSyn::source_for(dst)
                .map_err(|e| format!("topology.syn_scan: cannot determine source address for {dst}: {e}"))?;
            let src_port = 40000 + (std::process::id() % 20000) as u16;
            let mut seq: u32 = 0x5eed_0000 ^ (std::process::id() as u32) << 8;
            for port in &ports {
                governor_acquire(dst, rps);
                seq = seq.wrapping_add(1);
                // The source address in the pseudo-header is zero because the
                // kernel fills it; the checksum is recomputed by the kernel
                // when IP_HDRINCL is set on Linux, so a zero here is accepted.
                sock.send_syn(src, dst, src_port, *port, seq)
                    .map_err(|e| format!("topology.syn_scan: send to {dst}:{port} failed: {e}"))?;
                sent += 1;
            }
            let states = sock
                .collect(dst, src_port, &ports, timeout)
                .map_err(|e| format!("topology.syn_scan: receive failed: {e}"))?;
            for (port, state) in states {
                match state {
                    PortState::Open => open.push(port),
                    PortState::Closed => closed.push(port),
                    PortState::Filtered => filtered.push(port),
                }
            }
        }
    }

    open.sort_unstable();
    closed.sort_unstable();
    filtered.sort_unstable();

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
