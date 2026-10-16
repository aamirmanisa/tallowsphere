//! `tallow veil connect` — managed egress rung for the runtime (RFC-8.1, S3).
//!
//! Asserts that a chosen transport is actually up, announces the rung, and
//! hands off env for child runs. It never carries traffic itself and it never
//! falls through: if the transport is down the verb fails closed (stdout
//! empty, exit 1) and children refuse — there is no silent downgrade.
//!
//! Rungs:
//! - `tor`    — asserts the box's SOCKS5 contract: proxy reachability, the
//!   no-auth greeting, and a circuit test through the proxy (to our own onion
//!   when a target is known — no third party in the check path). Hands off
//!   `TALLOW_PROXY=socks5h://…`.
//! - `mesh`   — asserts the wg overlay (interface + hub reachability) and the
//!   local mesh bridge, then hands off `TALLOW_PROXY` pointing at the bridge.
//!   Mesh v1 targets mesh-hosted endpoints behind doors only; it is not
//!   transit and gives no outbound anonymity gain.
//! - `direct` — no anonymity; prints a loud warning and hands off
//!   `TALLOW_ALLOW_DIRECT=1` (the opt-out stays visible).
//!
//! Announce line (stderr) matches the `tallow-mesh` client convention:
//! `egress: <tor|mesh|direct> rung=<name> id=<stream-id|null>`
//!
//! Hand-off lines (stdout) are shell-eval-able:
//! `eval "$(tallow veil connect tor)"`
//!
//! The mesh bridge (`tallow veil bridge serve`) is a minimal SOCKS5 bridge,
//! loopback-bound by default, that resolves names against the mesh resolver
//! and allows only `10.77.0.0/24` targets — it cannot become a generic proxy.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

/// Default Tor SOCKS5 endpoint (the egress contract's default path).
const DEFAULT_TOR_PROXY: &str = "127.0.0.1:9050";
/// Default mesh admission hub — a cover-safe liveness anchor on the overlay.
const DEFAULT_MESH_HUB: &str = "10.77.0.1:9410";
/// Default mesh bridge listen endpoint (loopback only).
const DEFAULT_BRIDGE: &str = "127.0.0.1:11085";
/// Default mesh resolver.
const DEFAULT_MESH_DNS: &str = "10.77.0.1:53";
/// The only network the bridge will dial (mesh-hosted endpoints).
const MESH_PREFIX: [u8; 3] = [10, 77, 0];
/// Box convention: onion file used for the tor circuit test when no explicit
/// target is configured (the box's own console door — first-party only).
const ONION_FILE: &str = "/opt/tallow-portal/console-onion.txt";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(20);

const DNS_QUERY_ID: [u8; 2] = [0x54, 0x41]; // "TA"

// ---------------------------------------------------------------------------
// Entry point (called from main.rs dispatch; returns the process exit code)
// ---------------------------------------------------------------------------

/// Run `tallow veil <args…>`. Exit codes: 0 ok · 1 rung unavailable/refused ·
/// 2 usage. stdout carries only hand-off lines (empty on refusal).
pub fn run_veil_args(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("connect") => run_connect(&args[1..]),
        Some("bridge") => run_bridge(&args[1..]),
        _ => {
            eprintln!("{}", usage());
            2
        }
    }
}

fn usage() -> String {
    [
        "usage:",
        "  tallow veil connect <tor|mesh|direct> [--proxy H:P] [--circuit-target H:P]",
        "        [--hub H:P] [--bridge H:P] [--wg IFACE]",
        "  tallow veil bridge serve [--bind ADDR] [--port N] [--dns H:P]",
        "",
        "Announce (stderr): egress: <mode> rung=<name> id=<stream-id|null>",
        "Hand-off (stdout, eval-able): eval \"$(tallow veil connect tor)\"",
    ]
    .join("\n")
}

// ---------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Tor,
    Mesh,
    Direct,
}

#[derive(Default, Debug, PartialEq)]
struct ConnectOpts {
    proxy: Option<String>,
    circuit_target: Option<String>,
    hub: Option<String>,
    bridge: Option<String>,
    wg_iface: Option<String>,
}

/// Pure parser: `[mode] [flags…]`, any order, first positional wins as mode.
fn parse_connect_args(rest: &[String]) -> Result<(Mode, ConnectOpts), String> {
    let mut mode: Option<Mode> = None;
    let mut o = ConnectOpts::default();
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "tor" if mode.is_none() => mode = Some(Mode::Tor),
            "mesh" if mode.is_none() => mode = Some(Mode::Mesh),
            "direct" if mode.is_none() => mode = Some(Mode::Direct),
            "--proxy" => o.proxy = Some(take_value(rest, &mut i, a)?),
            "--circuit-target" => o.circuit_target = Some(take_value(rest, &mut i, a)?),
            "--hub" => o.hub = Some(take_value(rest, &mut i, a)?),
            "--bridge" => o.bridge = Some(take_value(rest, &mut i, a)?),
            "--wg" => o.wg_iface = Some(take_value(rest, &mut i, a)?),
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }
    let mode = mode.ok_or_else(|| "missing mode (tor | mesh | direct)".to_string())?;
    Ok((mode, o))
}

fn take_value(rest: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let v = rest
        .get(*i + 1)
        .ok_or_else(|| format!("{flag} requires a value"))?
        .clone();
    *i += 1;
    Ok(v)
}

fn run_connect(rest: &[String]) -> i32 {
    let (mode, o) = match parse_connect_args(rest) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("veil connect: {e}");
            eprintln!("{}", usage());
            return 2;
        }
    };
    match mode {
        Mode::Tor => connect_tor(&o),
        Mode::Mesh => connect_mesh(&o),
        Mode::Direct => connect_direct(),
    }
}

/// Refusal shape used for pre-request failures (no bytes attempted at any
/// target): stdout stays empty and no fallback exists. N3: the word
/// "refusing" only ever appears on a path that attempts no request.
fn refuse(msg: &str) -> i32 {
    eprintln!("refusing: {msg}; no fallback");
    1
}

fn announce(mode: &str, rung: &str, id: Option<&str>) {
    eprintln!("egress: {mode} rung={rung} id={}", id.unwrap_or("null"));
}

fn handoff_lines(unsets: &[&str], sets: &[(&str, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for u in unsets {
        out.push(format!("unset {u}"));
    }
    for (k, v) in sets {
        out.push(format!("export {k}={v}"));
    }
    out
}

fn emit(lines: &[String]) {
    for l in lines {
        println!("{l}");
    }
}

fn connect_tor(o: &ConnectOpts) -> i32 {
    let proxy = o
        .proxy
        .clone()
        .unwrap_or_else(|| DEFAULT_TOR_PROXY.to_string());
    let addr = match resolve_addr(&proxy) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("veil connect: bad proxy '{proxy}': {e}");
            return 2;
        }
    };
    let mut s = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            return refuse(&format!(
                "tor rung unavailable — SOCKS5 proxy {proxy} unreachable ({e})"
            ));
        }
    };
    let _ = s.set_read_timeout(Some(CONNECT_TIMEOUT));

    if let Err(e) = socks5_greeting(&mut s) {
        return refuse(&format!(
            "tor rung unavailable — greeting refused by {proxy} ({e})"
        ));
    }

    // Circuit test: a real CONNECT through the proxy. First-party target by
    // default (our own onion door), never a third party.
    match resolve_circuit_target(o) {
        Some(target) => match socks5_connect(&mut s, &target) {
            Ok(()) => eprintln!("circuit: ok through {target}"),
            Err(e) => {
                // A request was attempted here — say so without "refusing".
                eprintln!("circuit test failed: {e}; no fallback");
                return 1;
            }
        },
        None => eprintln!(
            "circuit: skipped (no target; pass --circuit-target or set TALLOW_VEIL_CIRCUIT_TARGET)"
        ),
    }

    let pinned = std::env::var("TALLOW_TOR_STREAM_ID")
        .ok()
        .filter(|v| !v.is_empty());
    if std::env::var("TALLOW_TOR_ISOLATE")
        .map(|v| matches!(v.as_str(), "0" | "false" | "no"))
        .unwrap_or(false)
    {
        eprintln!("note: TALLOW_TOR_ISOLATE=0 is set — shared circuit; per-run isolation disabled");
    }

    announce("tor", "tor-socks5h", pinned.as_deref());
    emit(&handoff_lines(
        &["TALLOW_ALLOW_DIRECT"],
        &[("TALLOW_PROXY", format!("socks5h://{proxy}"))],
    ));
    0
}

fn resolve_circuit_target(o: &ConnectOpts) -> Option<String> {
    if let Some(t) = &o.circuit_target {
        return Some(t.clone());
    }
    if let Ok(t) = std::env::var("TALLOW_VEIL_CIRCUIT_TARGET") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    let onion = std::fs::read_to_string(ONION_FILE).ok()?;
    let onion = onion.trim();
    if onion.is_empty() {
        return None;
    }
    Some(format!("{onion}:80"))
}

fn connect_mesh(o: &ConnectOpts) -> i32 {
    let wg = o.wg_iface.clone().unwrap_or_else(|| "wg0".to_string());
    if !Path::new(&format!("/sys/class/net/{wg}")).exists() {
        return refuse(&format!("mesh rung unavailable — interface {wg} is not up"));
    }
    let hub = o
        .hub
        .clone()
        .unwrap_or_else(|| DEFAULT_MESH_HUB.to_string());
    match resolve_addr(&hub).and_then(|a| {
        TcpStream::connect_timeout(&a, CONNECT_TIMEOUT)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }) {
        Ok(()) => {}
        Err(e) => {
            return refuse(&format!(
                "mesh rung unavailable — hub {hub} unreachable ({e})"
            ));
        }
    }
    let bridge = o
        .bridge
        .clone()
        .unwrap_or_else(|| DEFAULT_BRIDGE.to_string());
    match resolve_addr(&bridge).and_then(|a| {
        TcpStream::connect_timeout(&a, CONNECT_TIMEOUT)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }) {
        Ok(()) => {}
        Err(e) => {
            return refuse(&format!(
                "mesh rung unavailable — mesh bridge not running at {bridge} ({e}); start it: tallow veil bridge serve"
            ));
        }
    }
    announce("mesh", "wg-bridge", None);
    emit(&handoff_lines(
        &["TALLOW_ALLOW_DIRECT"],
        &[("TALLOW_PROXY", format!("socks5h://{bridge}"))],
    ));
    0
}

fn connect_direct() -> i32 {
    eprintln!(
        "warning: direct mode — traffic leaves from this machine's own IP; no anonymity; \
         the opt-out is visible in logs and receipts"
    );
    announce("direct", "direct-warned", None);
    emit(&handoff_lines(
        &["TALLOW_PROXY"],
        &[("TALLOW_ALLOW_DIRECT", "1".to_string())],
    ));
    0
}

// ---------------------------------------------------------------------------
// SOCKS5 client helpers (used by the tor circuit test)
// ---------------------------------------------------------------------------

fn resolve_addr(host_port: &str) -> Result<SocketAddr, String> {
    host_port
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no addresses resolved".to_string())
}

fn socks5_greeting(s: &mut TcpStream) -> Result<(), String> {
    s.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| e.to_string())?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).map_err(|e| e.to_string())?;
    match r {
        [0x05, 0x00] => Ok(()),
        [0x05, 0xFF] => Err("no acceptable auth method (proxy demands auth)".to_string()),
        other => Err(format!("unexpected greeting reply {other:02x?}")),
    }
}

fn sock_addr_reply_skip_len(atyp: u8, first: &[u8]) -> Result<usize, String> {
    // returns bytes remaining in the reply's BND.ADDR+BND.PORT after `first`
    let _ = first;
    match atyp {
        0x01 => Ok(4 + 2),
        0x04 => Ok(16 + 2),
        0x03 => Err("domain bound-addr needs length read".to_string()),
        other => Err(format!("unsupported ATYP {other:#04x}")),
    }
}

fn socks5_connect(s: &mut TcpStream, target: &str) -> Result<(), String> {
    let (host, port) = split_host_port(target)?;
    let mut req = vec![0x05, 0x01, 0x00];
    match host.parse::<Ipv4Addr>() {
        Ok(ip) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let h = host.as_bytes();
            if h.len() > 255 {
                return Err("host too long for SOCKS5".to_string());
            }
            req.push(0x03);
            req.push(h.len() as u8);
            req.extend_from_slice(h);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).map_err(|e| e.to_string())?;

    let mut h = [0u8; 4];
    s.read_exact(&mut h).map_err(|e| e.to_string())?;
    if h[0] != 0x05 {
        return Err(format!("unexpected reply version {:#04x}", h[0]));
    }
    if h[1] != 0x00 {
        return Err(format!("socks5 reply {} ({})", h[1], socks5_rep_name(h[1])));
    }
    match h[3] {
        0x01 | 0x04 => {
            let n = sock_addr_reply_skip_len(h[3], &h)?;
            let mut rest = vec![0u8; n];
            s.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).map_err(|e| e.to_string())?;
            let mut rest = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unsupported ATYP {other:#04x} in reply")),
    }
    Ok(())
}

fn socks5_rep_name(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    }
}

fn split_host_port(s: &str) -> Result<(String, u16), String> {
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("'{s}' is not HOST:PORT"))?;
    if h.is_empty() {
        return Err(format!("'{s}' has an empty host"));
    }
    let port: u16 = p
        .parse()
        .map_err(|_| format!("'{p}' is not a valid port"))?;
    Ok((h.to_string(), port))
}

// ---------------------------------------------------------------------------
// bridge serve — the mesh CONNECT/SOCKS5 bridge
// ---------------------------------------------------------------------------

fn run_bridge(rest: &[String]) -> i32 {
    match rest.first().map(String::as_str) {
        Some("serve") => {
            let mut bind = "127.0.0.1".to_string();
            let mut port: u16 = 11085;
            let mut dns = DEFAULT_MESH_DNS.to_string();
            let mut i = 1;
            while i < rest.len() {
                let a = rest[i].as_str();
                match a {
                    "--bind" => match take_value(rest, &mut i, a) {
                        Ok(v) => bind = v,
                        Err(e) => {
                            eprintln!("veil bridge: {e}");
                            return 2;
                        }
                    },
                    "--port" => match take_value(rest, &mut i, a).and_then(|v| {
                        v.parse::<u16>()
                            .map_err(|_| format!("'{v}' is not a valid port"))
                    }) {
                        Ok(v) => port = v,
                        Err(e) => {
                            eprintln!("veil bridge: {e}");
                            return 2;
                        }
                    },
                    "--dns" => match take_value(rest, &mut i, a) {
                        Ok(v) => dns = v,
                        Err(e) => {
                            eprintln!("veil bridge: {e}");
                            return 2;
                        }
                    },
                    other => {
                        eprintln!("veil bridge: unknown argument '{other}'");
                        eprintln!("{}", usage());
                        return 2;
                    }
                }
                i += 1;
            }
            bridge_serve(&bind, port, &dns)
        }
        _ => {
            eprintln!("{}", usage());
            2
        }
    }
}

fn bridge_serve(bind: &str, port: u16, dns: &str) -> i32 {
    let listener = match TcpListener::bind((bind, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("veil bridge: cannot bind {bind}:{port}: {e}");
            return 1;
        }
    };
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("{bind}:{port}"));
    eprintln!("mesh bridge: listening on {actual} (resolver {dns}; allow 10.77.0.0/24)");
    for conn in listener.incoming() {
        match conn {
            Ok(cli) => {
                let dns = dns.to_string();
                std::thread::spawn(move || {
                    let _ = bridge_conn(cli, &dns);
                });
            }
            Err(_) => continue,
        }
    }
    0
}

fn bridge_conn(mut cli: TcpStream, dns: &str) -> Result<(), String> {
    let _ = cli.set_read_timeout(Some(IO_TIMEOUT));
    let _ = cli.set_write_timeout(Some(IO_TIMEOUT));

    // greeting
    let mut h = [0u8; 2];
    cli.read_exact(&mut h).map_err(|e| e.to_string())?;
    if h[0] != 0x05 {
        return Err(format!("not SOCKS5 (version {:#04x})", h[0]));
    }
    let mut methods = vec![0u8; h[1] as usize];
    cli.read_exact(&mut methods).map_err(|e| e.to_string())?;
    if !methods.contains(&0x00) {
        let _ = cli.write_all(&[0x05, 0xFF]);
        return Err("client offered no no-auth method".to_string());
    }
    cli.write_all(&[0x05, 0x00]).map_err(|e| e.to_string())?;

    // request
    let mut rh = [0u8; 4];
    cli.read_exact(&mut rh).map_err(|e| e.to_string())?;
    if rh[0] != 0x05 {
        return Err(format!("request version {:#04x}", rh[0]));
    }
    let cmd = rh[1];
    let target: (String, u16) = match rh[3] {
        0x01 => {
            let mut a = [0u8; 4];
            cli.read_exact(&mut a).map_err(|e| e.to_string())?;
            let mut p = [0u8; 2];
            cli.read_exact(&mut p).map_err(|e| e.to_string())?;
            (Ipv4Addr::from(a).to_string(), u16::from_be_bytes(p))
        }
        0x03 => {
            let mut l = [0u8; 1];
            cli.read_exact(&mut l).map_err(|e| e.to_string())?;
            let mut name = vec![0u8; l[0] as usize];
            cli.read_exact(&mut name).map_err(|e| e.to_string())?;
            let mut p = [0u8; 2];
            cli.read_exact(&mut p).map_err(|e| e.to_string())?;
            (
                String::from_utf8_lossy(&name).to_string(),
                u16::from_be_bytes(p),
            )
        }
        0x04 => {
            let _ = reply(&mut cli, 0x08); // address type not supported (IPv6)
            return Err("IPv6 targets are not supported".to_string());
        }
        other => {
            let _ = reply(&mut cli, 0x08);
            return Err(format!("bad ATYP {other:#04x}"));
        }
    };
    if cmd != 0x01 {
        let _ = reply(&mut cli, 0x07); // command not supported
        return Err(format!("unsupported command {cmd:#04x}"));
    }

    // resolve + policy: mesh-only dial. Domains resolve through the mesh
    // resolver; the RESOLVED address is checked too (no rebind around it).
    let ip: Ipv4Addr = match target.0.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => match mesh_resolve(dns, &target.0) {
            Ok(ip) => ip,
            Err(e) => {
                let _ = reply(&mut cli, 0x04); // host unreachable
                return Err(format!("resolve '{}': {e}", target.0));
            }
        },
    };
    if !is_mesh_ip(ip) {
        let _ = reply(&mut cli, 0x02); // not allowed by ruleset
        return Err(format!(
            "target {ip} outside 10.77.0.0/24 (mesh bridge is not a generic proxy)"
        ));
    }

    let up = match TcpStream::connect_timeout(&SocketAddr::from((ip, target.1)), CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            let rep = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => 0x05,
                std::io::ErrorKind::TimedOut => 0x04,
                _ => 0x01,
            };
            let _ = reply(&mut cli, rep);
            return Err(format!("dial {ip}:{}: {e}", target.1));
        }
    };
    if reply(&mut cli, 0x00).is_err() {
        return Err("client closed before dial reply".to_string());
    }

    // byte pump
    let mut c2 = cli.try_clone().map_err(|e| e.to_string())?;
    let mut u2 = up.try_clone().map_err(|e| e.to_string())?;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut u2);
        let _ = u2.shutdown(std::net::Shutdown::Write);
    });
    let mut up = up;
    let _ = std::io::copy(&mut up, &mut cli);
    let _ = cli.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    Ok(())
}

fn reply(cli: &mut TcpStream, rep: u8) -> Result<(), String> {
    cli.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| e.to_string())
}

fn is_mesh_ip(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == MESH_PREFIX[0] && o[1] == MESH_PREFIX[1] && o[2] == MESH_PREFIX[2]
}

// ---------------------------------------------------------------------------
// Minimal mesh-DNS A-query client (domains resolve via the mesh resolver)
// ---------------------------------------------------------------------------

fn mesh_resolve(dns: &str, name: &str) -> Result<Ipv4Addr, String> {
    let q = build_a_query(name)?;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(DNS_TIMEOUT))
        .map_err(|e| e.to_string())?;
    sock.send_to(&q, dns).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1232];
    let (n, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
    parse_a_response(&buf[..n])
}

fn build_a_query(name: &str) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&DNS_QUERY_ID);
    q.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("bad DNS label in '{name}'"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    Ok(q)
}

fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        let b = *buf.get(pos).ok_or("truncated name")?;
        if b == 0 {
            return Ok(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + b as usize;
    }
}

fn parse_a_response(buf: &[u8]) -> Result<Ipv4Addr, String> {
    if buf.len() < 12 {
        return Err("short DNS header".to_string());
    }
    if buf[0..2] != DNS_QUERY_ID {
        return Err("DNS reply id mismatch".to_string());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4).ok_or("truncated question")?;
    }
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        let g = |p: usize| -> Result<u8, String> {
            buf.get(p)
                .copied()
                .ok_or_else(|| "truncated answer".to_string())
        };
        let rtype = u16::from_be_bytes([g(pos)?, g(pos + 1)?]);
        let rclass = u16::from_be_bytes([g(pos + 2)?, g(pos + 3)?]);
        let rdlen = u16::from_be_bytes([g(pos + 8)?, g(pos + 9)?]) as usize;
        let rd_start = pos + 10;
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let mut a = [0u8; 4];
            for (k, item) in a.iter_mut().enumerate() {
                *item = g(rd_start + k)?;
            }
            return Ok(Ipv4Addr::from(a));
        }
        pos = rd_start.checked_add(rdlen).ok_or("truncated answer")?;
    }
    Err("no A record in DNS reply".to_string())
}

// ---------------------------------------------------------------------------
// tests (pure helpers only — live legs live in tests/veil_connect_cli.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn mesh_allowlist_shape() {
        assert!(is_mesh_ip(Ipv4Addr::new(10, 77, 0, 1)));
        assert!(is_mesh_ip(Ipv4Addr::new(10, 77, 0, 255)));
        assert!(!is_mesh_ip(Ipv4Addr::new(10, 77, 1, 0)));
        assert!(!is_mesh_ip(Ipv4Addr::new(10, 78, 0, 1)));
        assert!(!is_mesh_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_mesh_ip(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn host_port_split_rules() {
        assert_eq!(
            split_host_port("console.wg:443").unwrap(),
            ("console.wg".to_string(), 443)
        );
        assert_eq!(
            split_host_port("10.77.0.1:80").unwrap(),
            ("10.77.0.1".to_string(), 80)
        );
        assert!(split_host_port("nohost").is_err());
        assert!(split_host_port(":443").is_err());
        assert!(split_host_port("host:notaport").is_err());
    }

    #[test]
    fn connect_args_parse() {
        let (m, o) = parse_connect_args(&s(&["tor", "--proxy", "127.0.0.1:9"])).unwrap();
        assert_eq!(m, Mode::Tor);
        assert_eq!(o.proxy.as_deref(), Some("127.0.0.1:9"));

        let (m, o) = parse_connect_args(&s(&["--hub", "10.77.0.1:9410", "mesh"])).unwrap();
        assert_eq!(m, Mode::Mesh);
        assert_eq!(o.hub.as_deref(), Some("10.77.0.1:9410"));

        let (m, _) = parse_connect_args(&s(&["direct"])).unwrap();
        assert_eq!(m, Mode::Direct);
    }

    #[test]
    fn connect_args_reject() {
        assert!(parse_connect_args(&s(&["tor", "mesh"])).is_err()); // two positionals
        assert!(parse_connect_args(&s(&["bogus"])).is_err());
        assert!(parse_connect_args(&s(&[])).is_err());
        assert!(parse_connect_args(&s(&["tor", "--proxy"])).is_err()); // missing value
        assert!(parse_connect_args(&s(&["tor", "--frobnicate"])).is_err());
    }

    #[test]
    fn handoff_lines_exact() {
        let lines = handoff_lines(
            &["TALLOW_ALLOW_DIRECT"],
            &[("TALLOW_PROXY", "socks5h://127.0.0.1:9050".to_string())],
        );
        assert_eq!(
            lines,
            vec![
                "unset TALLOW_ALLOW_DIRECT".to_string(),
                "export TALLOW_PROXY=socks5h://127.0.0.1:9050".to_string()
            ]
        );
        let lines = handoff_lines(
            &["TALLOW_PROXY"],
            &[("TALLOW_ALLOW_DIRECT", "1".to_string())],
        );
        assert_eq!(
            lines,
            vec![
                "unset TALLOW_PROXY".to_string(),
                "export TALLOW_ALLOW_DIRECT=1".to_string()
            ]
        );
    }

    #[test]
    fn dns_query_shape() {
        let q = build_a_query("console.wg").unwrap();
        assert_eq!(&q[0..2], &DNS_QUERY_ID);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // QDCOUNT
        assert_eq!(q[12], 7); // label len "console"
        assert_eq!(&q[13..20], b"console");
        assert_eq!(q[20], 2); // label len "wg"
        assert_eq!(&q[21..23], b"wg");
        assert_eq!(q[23], 0); // root
        assert_eq!(&q[24..26], &[0x00, 0x01]); // QTYPE A
        assert!(build_a_query("bad..name").is_err());
    }

    #[test]
    fn dns_answer_parse_ok_and_miss() {
        // Header + question(console.wg A IN) + one answer A 10.77.0.1
        let mut r = Vec::new();
        r.extend_from_slice(&DNS_QUERY_ID);
        r.extend_from_slice(&[0x81, 0x80]); // QR=1 RD RA
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        r.push(7);
        r.extend_from_slice(b"console");
        r.push(2);
        r.extend_from_slice(b"wg");
        r.push(0);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        r.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
        r.extend_from_slice(&[0x00, 0x04]); // rdlen
        r.extend_from_slice(&[0x0A, 0x4D, 0x00, 0x01]); // 10.77.0.1
        assert_eq!(parse_a_response(&r).unwrap(), Ipv4Addr::new(10, 77, 0, 1));

        // same but AAAA only -> miss
        let mut r2 = r.clone();
        let l = r2.len();
        r2[l - 14] = 0x00;
        r2[l - 13] = 0x1C; // answer rtype → AAAA
        assert!(parse_a_response(&r2).is_err());
    }

    #[test]
    fn dns_skip_name_forms() {
        let plain = [2u8, b'w', b'g', 0];
        assert_eq!(skip_name(&plain, 0).unwrap(), 4);
        let ptr = [0xC0u8, 0x0C];
        assert_eq!(skip_name(&ptr, 0).unwrap(), 2);
        assert!(skip_name(&[3u8, b'w'], 0).is_err());
    }

    #[test]
    fn parse_addr_general() {
        assert!(resolve_addr("127.0.0.1:9050").is_ok());
        assert!(resolve_addr("not a host:port").is_err());
    }
}
