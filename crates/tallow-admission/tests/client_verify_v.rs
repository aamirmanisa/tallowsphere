//! VERITY V-pass — `tallow-mesh` client edges (V-series). Adversarial
//! black-box pass over the operator client: SOCKS5 protocol edges, CLI exit
//! classification, the keygen→mint→admit→revoke ceremony path, pin
//! handling, and the audit line's device fingerprint (v1 ruling N-1).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

static TMP_N: AtomicUsize = AtomicUsize::new(0);

fn mesh_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow-mesh")
}

fn daemon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow-admissiond")
}

fn tmp(tag: &str) -> PathBuf {
    let n = TMP_N.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!("tallow-client-v-{}-{n}-{tag}", std::process::id()));
    p
}

struct Daemon {
    child: Child,
    addr: String,
}

impl Daemon {
    fn spawn_with(registry: &Path, audit: &Path) -> Daemon {
        // Reserve→drop→bind can lose the port to an unrelated ephemeral
        // connection; retry on early child exit / readiness timeout.
        for _attempt in 0..10 {
            let port = {
                let l = TcpListener::bind("127.0.0.1:0").expect("reserve");
                l.local_addr().expect("addr").port()
            };
            let addr = format!("127.0.0.1:{port}");
            let mut child = Command::new(daemon_bin())
                .args([
                    "--listen",
                    &addr,
                    "--registry",
                    registry.to_str().expect("utf8"),
                    "--audit",
                    audit.to_str().expect("utf8"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn daemon");

            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if TcpStream::connect(&addr).is_ok() {
                    return Daemon { child, addr };
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break; // daemon died (port stolen) — retry on a fresh port
                }
                if Instant::now() > deadline {
                    break; // stuck — retry on a fresh port
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("daemon never became ready after retries");
    }

    fn spawn_dev() -> (Daemon, PathBuf) {
        let reg = tmp("dev-registry.json");
        let out = Command::new(daemon_bin())
            .arg("--print-dev-registry")
            .output()
            .expect("print-dev-registry");
        std::fs::write(&reg, &out.stdout).expect("write registry");
        let audit = tmp("audit.jsonl");
        (Self::spawn_with(&reg, &audit), audit)
    }

    fn port(&self) -> String {
        self.addr.rsplit(':').next().expect("port").to_string()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_mesh(args: &[&str]) -> Output {
    Command::new(mesh_bin())
        .args(args)
        .output()
        .expect("run mesh")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

// ------------------------------------------------------------ SOCKS mock bits

fn socks_greeting_ok(c: &mut TcpStream) {
    let mut g = [0u8; 3];
    c.read_exact(&mut g).expect("greeting");
    assert_eq!(g, [0x05, 0x01, 0x00], "greeting shape");
    c.write_all(&[0x05, 0x00]).expect("greeting reply");
}

fn consume_socks_request(c: &mut TcpStream) {
    let mut head = [0u8; 4];
    c.read_exact(&mut head).expect("request head");
    assert_eq!(head[0], 0x05, "version");
    assert_eq!(head[1], 0x01, "CONNECT");
    match head[3] {
        0x01 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).expect("ipv4");
        }
        0x03 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).expect("len");
            let mut a = vec![0u8; l[0] as usize];
            c.read_exact(&mut a).expect("domain");
        }
        0x04 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).expect("ipv6");
        }
        other => panic!("unexpected ATYP {other:#04x}"),
    }
    let mut p = [0u8; 2];
    c.read_exact(&mut p).expect("port");
}

fn pump_keygen(out: &Output) -> String {
    let s = stdout_of(out);
    s.lines()
        .find(|l| l.contains("device pubkey"))
        .and_then(|l| l.split_whitespace().last())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no pubkey line in:\n{s}"))
}

// ------------------------------------------------------------------- V-series

#[test]
fn v1_socks_greeting_rejected() {
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = proxy.local_addr().expect("addr").port();
    let h = std::thread::spawn(move || {
        let (mut c, _) = proxy.accept().expect("accept");
        let mut g = [0u8; 3];
        c.read_exact(&mut g).expect("greeting");
        c.write_all(&[0x05, 0xFF]).expect("reject");
    });
    let out = run_mesh(&[
        "call",
        "--rung",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{port}"),
        "--act",
        "echo",
    ]);
    let e = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "{e}");
    assert!(e.contains("rejected no-auth"), "{e}");
    let _ = h.join();
}

#[test]
fn v2_socks_connect_refused_code_named() {
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = proxy.local_addr().expect("addr").port();
    let h = std::thread::spawn(move || {
        let (mut c, _) = proxy.accept().expect("accept");
        socks_greeting_ok(&mut c);
        consume_socks_request(&mut c);
        c.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("refuse");
    });
    let out = run_mesh(&[
        "call",
        "--rung",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{port}"),
        "--act",
        "echo",
    ]);
    let e = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "{e}");
    assert!(e.contains("connect refused, code 0x05"), "{e}");
    let _ = h.join();
}

#[test]
fn v3_socks_domain_reply_accepted_and_spliced() {
    let (d, _audit) = Daemon::spawn_dev();
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind");
    let pp = proxy.local_addr().expect("addr").port();
    let target = d.addr.clone();
    let h = std::thread::spawn(move || {
        let (mut c, _) = proxy.accept().expect("accept");
        socks_greeting_ok(&mut c);
        consume_socks_request(&mut c);
        let mut up = TcpStream::connect(&target).expect("upstream");
        // reply with a DOMAIN address type (len 1, "x") — some proxies do this
        c.write_all(&[0x05, 0x00, 0x00, 0x03, 0x01, b'x', 0x00, 0x00])
            .expect("reply");
        let mut c2 = c.try_clone().expect("clone c");
        let mut u2 = up.try_clone().expect("clone u");
        let t = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c2, &mut u2);
            let _ = u2.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut up, &mut c);
        let _ = t.join();
    });
    let out = run_mesh(&[
        "call",
        "--rung",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{pp}"),
        "--port",
        &d.port(),
        "--act",
        "echo",
        "--data",
        "\"domain-reply\"",
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    let resp: Value = serde_json::from_slice(&out.stdout).expect("response json");
    assert_eq!(resp["result"], json!("domain-reply"));
    let _ = h.join();
}

#[test]
fn v4_socks_bad_reply_version() {
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = proxy.local_addr().expect("addr").port();
    let h = std::thread::spawn(move || {
        let (mut c, _) = proxy.accept().expect("accept");
        socks_greeting_ok(&mut c);
        consume_socks_request(&mut c);
        c.write_all(&[0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("bad version");
    });
    let out = run_mesh(&[
        "call",
        "--rung",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{port}"),
        "--act",
        "echo",
    ]);
    let e = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "{e}");
    assert!(e.contains("bad reply version"), "{e}");
    let _ = h.join();
}

#[test]
fn v5_usage_errors_exit_2() {
    let cases: [(&[&str], &str); 4] = [
        (&["call", "--nope", "x"], "unknown flag"),
        (&["frobnicate"], "unknown verb"),
        (&["call", "--port", "abc"], "port"),
        (&["call", "--data", "{oops"], "bad JSON"),
    ];
    for (args, want) in cases {
        let out = run_mesh(args);
        let e = stderr_of(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {e}");
        assert!(e.contains(want), "{args:?}: {e}");
    }
}

#[test]
fn v6_ceremony_keygen_mint_admit_revoke() {
    let key = tmp("ceremony-key.json");
    let _ = std::fs::remove_file(&key);
    let out = run_mesh(&["keygen", "--out", key.to_str().expect("utf8")]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    let pub_hex = pump_keygen(&out);
    assert_eq!(pub_hex.len(), 64);

    // registry: the dev devices + the freshly minted one
    let reg = tmp("ceremony-registry.json");
    let devreg = Command::new(daemon_bin())
        .arg("--print-dev-registry")
        .output()
        .expect("print");
    let mut v: Value = serde_json::from_slice(&devreg.stdout).expect("dev registry json");
    v["devices"].as_array_mut().expect("devices").push(json!({
        "id": "ceremony-device",
        "role": "owner",
        "status": "active",
        "ed_pub_hex": pub_hex,
    }));
    std::fs::write(&reg, serde_json::to_string_pretty(&v).expect("pretty")).expect("write reg");

    let audit = tmp("audit.jsonl");
    let d = Daemon::spawn_with(&reg, &audit);
    let out = run_mesh(&[
        "call",
        "--rung",
        "direct",
        "--port",
        &d.port(),
        "--device",
        "ceremony-device",
        "--device-key",
        key.to_str().expect("utf8"),
        "--act",
        "echo",
    ]);
    assert!(out.status.success(), "admit failed: {}", stderr_of(&out));
    let resp: Value = serde_json::from_slice(&out.stdout).expect("response json");
    assert_eq!(resp["ok"], json!(true));
    drop(d);

    // revoke → the same device is refused
    for dev in v["devices"].as_array_mut().expect("devices") {
        if dev["id"] == json!("ceremony-device") {
            dev["status"] = json!("revoked");
        }
    }
    std::fs::write(&reg, serde_json::to_string_pretty(&v).expect("pretty")).expect("write reg");
    let audit2 = tmp("audit2.jsonl");
    let d2 = Daemon::spawn_with(&reg, &audit2);
    let out = run_mesh(&[
        "call",
        "--rung",
        "direct",
        "--port",
        &d2.port(),
        "--device",
        "ceremony-device",
        "--device-key",
        key.to_str().expect("utf8"),
        "--act",
        "echo",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "revoked must be refused: {}",
        stderr_of(&out)
    );
    assert!(
        out.stdout.is_empty(),
        "no response may leak for a revoked device"
    );

    let _ = std::fs::remove_file(&key);
}

#[test]
fn v7_wrong_server_pin_rejected() {
    let (d, _audit) = Daemon::spawn_dev();

    // a valid but unrelated Ed25519 key in the pin (from keygen)
    let key = tmp("pin-key.json");
    let _ = std::fs::remove_file(&key);
    let kg = run_mesh(&["keygen", "--out", key.to_str().expect("utf8")]);
    assert!(kg.status.success());
    let pub_hex = pump_keygen(&kg);

    let pin = tmp("pin.json");
    std::fs::write(
        &pin,
        format!(
            "{{\"ed_pub_hex\":\"{pub_hex}\",\"x_pub_hex\":\"{}\"}}",
            "11".repeat(32)
        ),
    )
    .expect("write pin");

    let out = run_mesh(&[
        "call",
        "--rung",
        "direct",
        "--port",
        &d.port(),
        "--pin",
        pin.to_str().expect("utf8"),
        "--act",
        "echo",
    ]);
    let e = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "{e}");
    assert!(out.stdout.is_empty(), "no output for a rejected server");
    assert!(e.contains("server-auth-failed"), "{e}");
    let _ = std::fs::remove_file(&key);
}

#[test]
fn v8_malformed_pin_rejected() {
    let pin = tmp("pin-bad.json");
    std::fs::write(&pin, "{\"ed_pub_hex\":\"zz\",\"x_pub_hex\":\"11\"}").expect("write pin");
    let out = run_mesh(&[
        "call",
        "--rung",
        "direct",
        "--pin",
        pin.to_str().expect("utf8"),
        "--act",
        "echo",
    ]);
    let e = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "{e}");
    assert!(e.contains("pin"), "{e}");
}

#[test]
fn v9_audit_carries_stable_device_fp() {
    let (d, audit) = Daemon::spawn_dev();
    for _ in 0..2 {
        let out = run_mesh(&[
            "call",
            "--rung",
            "direct",
            "--port",
            &d.port(),
            "--act",
            "echo",
        ]);
        assert!(out.status.success(), "{}", stderr_of(&out));
    }
    drop(d);

    let text = std::fs::read_to_string(&audit).expect("audit readable");
    let auths: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("AUTH ok device=operator-1"))
        .collect();
    assert_eq!(auths.len(), 2, "audit:\n{text}");

    let tok = |l: &str, k: &str| {
        l.split_whitespace()
            .find(|t| t.starts_with(&format!("{k}=")))
            .map(|t| t[k.len() + 1..].to_string())
            .unwrap_or_else(|| panic!("no {k}= in {l}"))
    };
    let fp1 = tok(auths[0], "fp");
    let fp2 = tok(auths[1], "fp");
    let dfp1 = tok(auths[0], "dev_fp");
    let dfp2 = tok(auths[1], "dev_fp");

    assert_eq!(dfp1, dfp2, "device fp must be stable across sessions");
    assert_ne!(fp1, fp2, "session fp must vary per connection");
    assert_ne!(dfp1, fp1, "device and session fps must be distinct fields");
    assert_eq!(dfp1.len(), 16);
}
