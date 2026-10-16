//! `tallow-mesh` — operator client MVP (task 1.5, local half).
//!
//! A one-shot authenticated call over the admission protocol, with the
//! **failover rungs announced** (checked rule: zero silent fallback):
//!
//! - `direct` — plain TCP to host:port (loopback/staging today; mesh `P1` shape)
//! - `ssh`    — the LOCAL end of an operator-created `ssh -L` forward (interim
//!   rung `P4`; the tunnel itself is set up out-of-band)
//! - `tor`    — dial through a SOCKS5 proxy (default `127.0.0.1:9050`; rung `P3`
//!   family — with a real Tor proxy the target must be the onion door)
//!
//! If the selected rung is unavailable the client **stops and names the rung**;
//! it never silently retries another one.
//!
//! ```text
//! tallow-mesh keygen --out <file.json>     mint a device key (chmod 600) + print pubkey
//! tallow-mesh call --act echo [--data JSON] [--rung direct|ssh|tor]
//!                  [--host H] [--port P] [--device ID] [--device-key FILE]
//!                  [--pin FILE] [--proxy HOST:PORT]
//! ```
//!
//! DEV defaults (loud warning): device `operator-1` from deterministic dev
//! seeds; server pinned to the dev identity. `--device-key` / `--pin` load
//! real material (`{"seed_hex"}` / `{"ed_pub_hex","x_pub_hex"}`).

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use x25519_dalek::PublicKey;

use tallow_admission::client::ClientConfig;
use tallow_admission::devkeys::{device_identity, server_identity, DeviceIdentity};
use tallow_admission::io::dial_call_on;

fn die(msg: &str) -> ! {
    eprintln!("tallow-mesh: {msg}");
    std::process::exit(1);
}

/// Usage-class errors (bad flags/verbs/arguments) exit 2; runtime errors
/// (rung unavailable, call refused, key material) exit 1.
fn usage_die(msg: &str) -> ! {
    eprintln!("tallow-mesh: {msg}");
    usage();
}

fn usage() -> ! {
    eprintln!(
        "tallow-mesh {}\n\
         Usage: tallow-mesh keygen --out <file.json>\n\
         \x20      tallow-mesh call --act ACT [--data JSON] [--rung direct|ssh|tor]\n\
         \x20                       [--host H] [--port P] [--device ID] [--device-key FILE]\n\
         \x20                       [--pin FILE] [--proxy HOST:PORT]\n",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}

fn err(msg: String) -> io::Error {
    io::Error::other(msg)
}

fn parse_hex32(s: &str, what: &str) -> [u8; 32] {
    let raw = hex::decode(s).unwrap_or_else(|e| die(&format!("{what}: bad hex: {e}")));
    raw.try_into()
        .unwrap_or_else(|v: Vec<u8>| die(&format!("{what}: expected 32 bytes, got {}", v.len())))
}

fn load_seed_key(path: &str) -> SigningKey {
    #[derive(serde::Deserialize)]
    struct KeyFile {
        seed_hex: String,
    }
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(&format!("device-key: read {path}: {e}")));
    let f: KeyFile =
        serde_json::from_str(&data).unwrap_or_else(|e| die(&format!("device-key: bad JSON: {e}")));
    SigningKey::from_bytes(&parse_hex32(&f.seed_hex, "device-key.seed_hex"))
}

fn load_pin(path: &str) -> (VerifyingKey, PublicKey) {
    #[derive(serde::Deserialize)]
    struct PinFile {
        ed_pub_hex: String,
        x_pub_hex: String,
    }
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("pin: read {path}: {e}")));
    let f: PinFile =
        serde_json::from_str(&data).unwrap_or_else(|e| die(&format!("pin: bad JSON: {e}")));
    let ed = VerifyingKey::from_bytes(&parse_hex32(&f.ed_pub_hex, "pin.ed_pub_hex"))
        .unwrap_or_else(|e| die(&format!("pin: invalid Ed25519 key: {e}")));
    let x = PublicKey::from(parse_hex32(&f.x_pub_hex, "pin.x_pub_hex"));
    (ed, x)
}

/// Dial a TCP stream per rung. Unavailable rungs return an error that names
/// the rung — the caller must NOT fall back.
fn dial(rung: &str, host: &str, port: u16, proxy: &str) -> io::Result<TcpStream> {
    match rung {
        "direct" => TcpStream::connect((host, port)),
        "ssh" => {
            let is_loopback = matches!(host, "127.0.0.1" | "::1" | "localhost");
            if !is_loopback {
                return Err(err(format!(
                    "ssh rung must target the LOCAL end of the tunnel (loopback host); got {host}. \
                     Create the forward out-of-band: ssh -L <port>:<target> <host>"
                )));
            }
            TcpStream::connect((host, port))
        }
        "tor" => socks5_connect(proxy, host, port),
        other => Err(err(format!("unknown rung {other:?} (direct|ssh|tor)"))),
    }
}

/// Minimal SOCKS5 CONNECT (no auth) — enough for a Tor SocksPort.
fn socks5_connect(proxy: &str, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut s =
        TcpStream::connect(proxy).map_err(|e| err(format!("cannot reach proxy {proxy}: {e}")))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    // greeting: version 5, one method, no-auth
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    if greet != [0x05, 0x00] {
        return Err(err(format!("socks5: proxy rejected no-auth: {greet:?}")));
    }

    // CONNECT request
    let mut req = vec![0x05, 0x01, 0x00];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(err("socks5: hostname too long".into()));
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    // reply
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(err(format!("socks5: bad reply version {}", head[0])));
    }
    if head[1] != 0x00 {
        return Err(err(format!(
            "socks5: connect refused, code {:#04x}",
            head[1]
        )));
    }
    match head[3] {
        0x01 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a)?;
        }
        0x04 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a)?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            let mut a = vec![0u8; l[0] as usize];
            s.read_exact(&mut a)?;
        }
        other => return Err(err(format!("socks5: bad address type {other:#04x}"))),
    }
    let mut p = [0u8; 2];
    s.read_exact(&mut p)?;

    s.set_read_timeout(None)?;
    s.set_write_timeout(None)?;
    Ok(s)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        usage();
    }
    if argv.iter().any(|a| a == "--version") {
        println!("tallow-mesh {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let known = [
        "out",
        "rung",
        "host",
        "port",
        "device",
        "device-key",
        "pin",
        "proxy",
        "act",
        "data",
    ];
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(name) = a.strip_prefix("--") {
            if !known.contains(&name) {
                usage_die(&format!("unknown flag --{name}"));
            }
            let val = argv
                .get(i + 1)
                .unwrap_or_else(|| usage_die(&format!("--{name} needs a value")));
            map.insert(name.into(), val.clone());
            i += 2;
        } else {
            pos.push(a.clone());
            i += 1;
        }
    }

    let verb = pos.first().cloned().unwrap_or_else(|| usage());

    match verb.as_str() {
        "keygen" => {
            let out = map
                .get("out")
                .cloned()
                .unwrap_or_else(|| die("keygen needs --out"));
            if std::path::Path::new(&out).exists() {
                die("refusing to overwrite an existing key file");
            }
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let doc = json!({ "seed_hex": hex::encode(sk.to_bytes()) });
            std::fs::write(&out, format!("{doc}\n"))
                .unwrap_or_else(|e| die(&format!("write {out}: {e}")));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
            }
            println!(
                "wrote {out} (chmod 600)\ndevice pubkey (mint into the registry): {}",
                hex::encode(sk.verifying_key().to_bytes())
            );
        }

        "call" => {
            let rung = map.get("rung").cloned().unwrap_or_else(|| "direct".into());
            let host = map
                .get("host")
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".into());
            let port: u16 = map
                .get("port")
                .map(|p| {
                    p.parse()
                        .unwrap_or_else(|_| usage_die("--port must be a number"))
                })
                .unwrap_or(9410);
            let device_id = map
                .get("device")
                .cloned()
                .unwrap_or_else(|| "operator-1".into());
            let act = map.get("act").cloned().unwrap_or_else(|| "echo".into());
            let data = map.get("data").map(|d| {
                serde_json::from_str::<Value>(d)
                    .unwrap_or_else(|e| usage_die(&format!("--data: bad JSON: {e}")))
            });
            let proxy = map
                .get("proxy")
                .cloned()
                .unwrap_or_else(|| "127.0.0.1:9050".into());

            let (dev_key, dev_is_dev) = match map.get("device-key") {
                Some(p) => (load_seed_key(p), false),
                None => (device_identity(&device_id).ed, true),
            };
            let (server_ed, server_x, pin_is_dev) = match map.get("pin") {
                Some(p) => {
                    let (ed, x) = load_pin(p);
                    (ed, x, false)
                }
                None => {
                    let si = server_identity();
                    (si.ed.verifying_key(), PublicKey::from(&si.x), true)
                }
            };
            if dev_is_dev || pin_is_dev {
                eprintln!(
                    "tallow-mesh: WARNING: DEV key material in use (device={dev_is_dev}, server-pin={pin_is_dev}) — staging/rehearsal only"
                );
            }

            let cfg = ClientConfig {
                device: DeviceIdentity {
                    id: device_id.clone(),
                    ed: dev_key,
                },
                server_ed,
                server_x,
                ts_override: None,
                tamper_sig: false,
            };

            let mut stream = dial(&rung, &host, port, &proxy).unwrap_or_else(|e| {
                die(&format!(
                    "rung={rung} UNAVAILABLE: {e} — stopping; announced rungs only, no silent fallback"
                ))
            });
            eprintln!("tallow-mesh: rung={rung} target={host}:{port} device={device_id}");

            let resp = dial_call_on(&mut stream, cfg, &act, data)
                .unwrap_or_else(|e| die(&format!("rung={rung}: call failed: {e}")));
            println!(
                "{}",
                serde_json::to_string(&resp).expect("response serialize")
            );
        }

        other => usage_die(&format!("unknown verb {other:?}")),
    }
}
