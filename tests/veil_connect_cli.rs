//! CLI acceptance tests for `tallow veil connect` / `veil bridge serve`
//! (RFC-8.1 S3). These spawn the real built binary. Hermetic: mock SOCKS5
//! proxy + mock mesh DNS; the only environmental assumption is that this
//! test runs on the box (wg0 present) — the mesh legs inject `--hub` /
//! `--bridge` so no live overlay state is required for refusal legs.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove("TALLOW_PROXY")
        .env_remove("TALLOW_ALLOW_DIRECT")
        .env_remove("TALLOW_TOR_STREAM_ID")
        .env_remove("TALLOW_TOR_ISOLATE")
        .env_remove("TALLOW_VEIL_CIRCUIT_TARGET")
        .output()
        .expect("spawn tallow")
}

fn stdout_lines(o: &Output) -> Vec<String> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn stderr_s(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn dead_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve")
        .local_addr()
        .expect("addr")
        .port()
}

/// Mock SOCKS5 proxy (no-auth): performs the greeting, records the CONNECT
/// target, replies with `rep` (0x00 = success).
fn spawn_mock_socks(rep: u8) -> (u16, std::sync::mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = l.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut c, _) = l.accept().expect("accept");
        let mut g = [0u8; 2];
        c.read_exact(&mut g).expect("greeting head");
        let mut m = vec![0u8; g[1] as usize];
        c.read_exact(&mut m).expect("methods");
        assert!(m.contains(&0x00), "client should offer no-auth");
        c.write_all(&[0x05, 0x00]).expect("greeting reply");
        let mut h = [0u8; 4];
        c.read_exact(&mut h).expect("req head");
        assert_eq!(h[1], 0x01, "CONNECT");
        let target = match h[3] {
            0x01 => {
                let mut a = [0u8; 4];
                c.read_exact(&mut a).expect("ipv4");
                let mut p = [0u8; 2];
                c.read_exact(&mut p).expect("port");
                format!(
                    "{}.{}.{}.{}:{}",
                    a[0],
                    a[1],
                    a[2],
                    a[3],
                    u16::from_be_bytes(p)
                )
            }
            0x03 => {
                let mut len = [0u8; 1];
                c.read_exact(&mut len).expect("len");
                let mut n = vec![0u8; len[0] as usize];
                c.read_exact(&mut n).expect("name");
                let mut p = [0u8; 2];
                c.read_exact(&mut p).expect("port");
                format!("{}:{}", String::from_utf8_lossy(&n), u16::from_be_bytes(p))
            }
            other => panic!("unexpected ATYP {other:#04x}"),
        };
        let _ = tx.send(target);
        c.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("reply");
    });
    (port, rx)
}

#[test]
fn tor_ok_mock_socks_circuit() {
    let (port, rx) = spawn_mock_socks(0x00);
    let proxy = format!("127.0.0.1:{port}");
    let o = run(&[
        "veil",
        "connect",
        "tor",
        "--proxy",
        &proxy,
        "--circuit-target",
        "meshtest.onion:80",
    ]);
    let err = stderr_s(&o);
    assert!(o.status.success(), "rc={:?} stderr={err}", o.status.code());
    assert!(
        err.contains("egress: tor rung=tor-socks5h id=null"),
        "announce: {err}"
    );
    assert!(
        err.contains("circuit: ok through meshtest.onion:80"),
        "circuit: {err}"
    );
    assert_eq!(
        stdout_lines(&o),
        vec![
            "unset TALLOW_ALLOW_DIRECT".to_string(),
            format!("export TALLOW_PROXY=socks5h://{proxy}"),
        ]
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).expect("target"),
        "meshtest.onion:80"
    );
}

#[test]
fn tor_dead_proxy_refuses_stdout_empty() {
    let port = dead_port();
    let o = run(&[
        "veil",
        "connect",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{port}"),
    ]);
    let err = stderr_s(&o);
    assert_eq!(o.status.code(), Some(1), "stderr={err}");
    assert!(o.stdout.is_empty(), "stdout must be empty on refusal");
    assert!(
        err.contains("refusing: tor rung unavailable"),
        "stderr={err}"
    );
    assert!(err.contains("no fallback"), "stderr={err}");
    assert!(!err.contains("egress:"), "no announce on refusal: {err}");
}

#[test]
fn tor_circuit_test_failure_is_not_refusal_wording() {
    let (port, _rx) = spawn_mock_socks(0x05); // connection refused at target
    let o = run(&[
        "veil",
        "connect",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{port}"),
        "--circuit-target",
        "meshtest.onion:80",
    ]);
    let err = stderr_s(&o);
    assert_eq!(o.status.code(), Some(1), "stderr={err}");
    assert!(o.stdout.is_empty());
    assert!(err.contains("circuit test failed"), "stderr={err}");
    assert!(err.contains("connection refused"), "stderr={err}");
    assert!(
        !err.contains("refusing"),
        "N3: word 'refusing' only pre-request: {err}"
    );
}

#[test]
fn mesh_bridge_down_refuses() {
    let hub = TcpListener::bind("127.0.0.1:0").expect("hub");
    let hub_addr = hub.local_addr().expect("addr").to_string();
    let dead = dead_port();
    let o = run(&[
        "veil",
        "connect",
        "mesh",
        "--hub",
        &hub_addr,
        "--bridge",
        &format!("127.0.0.1:{dead}"),
    ]);
    let err = stderr_s(&o);
    assert_eq!(o.status.code(), Some(1), "stderr={err}");
    assert!(o.stdout.is_empty());
    assert!(err.contains("mesh bridge not running"), "stderr={err}");
    assert!(!err.contains("egress:"), "no announce on refusal: {err}");
}

#[test]
fn direct_warns_and_hands_off_optout() {
    let o = run(&["veil", "connect", "direct"]);
    let err = stderr_s(&o);
    assert!(o.status.success(), "stderr={err}");
    assert!(err.contains("warning: direct mode"), "stderr={err}");
    assert!(
        err.contains("egress: direct rung=direct-warned id=null"),
        "stderr={err}"
    );
    assert_eq!(
        stdout_lines(&o),
        vec![
            "unset TALLOW_PROXY".to_string(),
            "export TALLOW_ALLOW_DIRECT=1".to_string(),
        ]
    );
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &["veil"][..],
        &["veil", "connect"][..],
        &["veil", "connect", "bogus"][..],
        &["veil", "bridge"][..],
        &["veil", "bridge", "nope"][..],
    ] {
        let o = run(args);
        assert_eq!(o.status.code(), Some(2), "args={args:?}");
        assert!(o.stdout.is_empty(), "args={args:?}");
    }
}

/// Full mesh path: mock DNS (A → 10.77.0.1) + bridge serve + a target
/// listener on the mesh address. Proves: connect assertion, hand-off env,
/// SOCKS CONNECT through the bridge by mesh name, byte pump, policy denials.
#[test]
fn mesh_rung_end_to_end_through_bridge() {
    // 1. mock mesh DNS: any A query → 10.77.0.1
    let dns_sock = UdpSocket::bind("127.0.0.1:0").expect("dns");
    let dns_port = dns_sock.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (n, from) = dns_sock.recv_from(&mut buf).expect("dns recv");
        assert!(n >= 12, "dns query too short");
        let mut r = Vec::new();
        r.extend_from_slice(&buf[0..2]); // id
        r.extend_from_slice(&[0x81, 0x80]); // response, RD RA
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        r.extend_from_slice(&buf[12..n]); // echo the question
        r.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
        ]);
        r.extend_from_slice(&[10, 77, 0, 1]);
        let _ = dns_sock.send_to(&r, from);
    });

    // 2. target listener on the mesh address (root); replies "pong" to "ping"
    let target = TcpListener::bind("10.77.0.1:0").expect("bind 10.77.0.1");
    let target_port = target.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = target.accept() {
            let mut b = [0u8; 4];
            if s.read_exact(&mut b).is_ok() {
                let _ = s.write_all(b"pong");
            }
        }
    });

    // 3. live hub stand-in
    let hub = TcpListener::bind("127.0.0.1:0").expect("hub");
    let hub_addr = hub.local_addr().expect("addr").to_string();

    // 4. bridge serve child (port 0 → learn the real port from stderr)
    let mut bridge: Child = Command::new(bin())
        .args([
            "veil",
            "bridge",
            "serve",
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--dns",
            &format!("127.0.0.1:{dns_port}"),
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bridge");
    let stderr = bridge.stderr.take().expect("stderr");
    let mut rdr = BufReader::new(stderr);
    let mut bridge_port = 0u16;
    for _ in 0..10 {
        let mut line = String::new();
        if rdr.read_line(&mut line).expect("read") == 0 {
            break;
        }
        if let Some(rest) = line.split("listening on ").nth(1) {
            if let Some(addr) = rest.trim().split_whitespace().next() {
                if let Some(p) = addr.rsplit(':').next() {
                    bridge_port = p.parse().expect("bridge port");
                    break;
                }
            }
        }
    }
    assert!(bridge_port > 0, "did not learn bridge port");
    let bridge_addr = format!("127.0.0.1:{bridge_port}");

    // 5. connect assertion + hand-off env
    let o = run(&[
        "veil",
        "connect",
        "mesh",
        "--hub",
        &hub_addr,
        "--bridge",
        &bridge_addr,
    ]);
    let err = stderr_s(&o);
    assert!(o.status.success(), "stderr={err}");
    assert!(
        err.contains("egress: mesh rung=wg-bridge id=null"),
        "stderr={err}"
    );
    assert_eq!(
        stdout_lines(&o),
        vec![
            "unset TALLOW_ALLOW_DIRECT".to_string(),
            format!("export TALLOW_PROXY=socks5h://{bridge_addr}"),
        ]
    );

    // 6. through the bridge: CONNECT by mesh name → byte pump
    let mut c = TcpStream::connect(&bridge_addr).expect("bridge connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("t");
    c.write_all(&[0x05, 0x01, 0x00]).expect("greet");
    let mut g = [0u8; 2];
    c.read_exact(&mut g).expect("greet reply");
    assert_eq!(g, [0x05, 0x00]);
    let name = b"mesh-test.wg";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&target_port.to_be_bytes());
    c.write_all(&req).expect("connect req");
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).expect("connect reply");
    assert_eq!(rep[1], 0x00, "expected success, got {:#04x}", rep[1]);
    c.write_all(b"ping").expect("pump");
    let mut pong = [0u8; 4];
    c.read_exact(&mut pong).expect("pong");
    assert_eq!(&pong, b"pong");

    // 7. policy: public targets are refused (not allowed by ruleset)
    let mut c2 = TcpStream::connect(&bridge_addr).expect("bridge connect 2");
    c2.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("t");
    c2.write_all(&[0x05, 0x01, 0x00]).expect("greet");
    let mut g2 = [0u8; 2];
    c2.read_exact(&mut g2).expect("greet reply 2");
    c2.write_all(&[0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0, 80])
        .expect("connect req 2");
    let mut rep2 = [0u8; 10];
    c2.read_exact(&mut rep2).expect("connect reply 2");
    assert_eq!(
        rep2[1], 0x02,
        "expected ruleset denial, got {:#04x}",
        rep2[1]
    );

    let _ = bridge.kill();
    let _ = bridge.wait();
}
