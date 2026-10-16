//! `tallow-mesh` client MVP end-to-end tests: the three rungs (direct / ssh /
//! tor-via-mock-SOCKS) against a locally spawned `tallow-admissiond`, the
//! no-silent-fallback rule, unknown-device refusal, and `keygen`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn mesh_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow-mesh")
}

fn daemon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow-admissiond")
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("tallow-mesh-test-{}-{tag}", std::process::id()));
    p
}

struct Daemon {
    child: Child,
    addr: String,
}

impl Daemon {
    fn spawn() -> Daemon {
        let reg = tmp("registry.json");
        let out = Command::new(daemon_bin())
            .arg("--print-dev-registry")
            .output()
            .expect("print-dev-registry");
        std::fs::write(&reg, &out.stdout).expect("write registry");

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
                    reg.to_str().expect("utf8"),
                    "--audit",
                    "-",
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

fn run_mesh(args: &[&str]) -> std::process::Output {
    Command::new(mesh_bin())
        .args(args)
        .output()
        .expect("run mesh")
}

#[test]
fn direct_rung_echo() {
    let d = Daemon::spawn();
    let out = run_mesh(&[
        "call",
        "--rung",
        "direct",
        "--port",
        &d.port(),
        "--act",
        "echo",
        "--data",
        "\"hi\"",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("rung=direct"), "announce missing: {stderr}");
    let resp: serde_json::Value = serde_json::from_slice(&out.stdout).expect("response json");
    assert_eq!(resp["ok"], serde_json::json!(true), "resp: {resp}");
    assert_eq!(resp["result"], serde_json::json!("hi"));
}

#[test]
fn ssh_rung_guard_and_loopback_end() {
    let d = Daemon::spawn();

    // non-loopback host → refused with the tunnel explanation, rung named
    let out = run_mesh(&[
        "call",
        "--rung",
        "ssh",
        "--host",
        "10.9.9.9",
        "--port",
        &d.port(),
        "--act",
        "echo",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ssh rung"), "rung named: {stderr}");
    assert!(
        stderr.contains("no silent fallback"),
        "rule stated: {stderr}"
    );

    // loopback (the local end of a hypothetical tunnel) works
    let out = run_mesh(&[
        "call",
        "--rung",
        "ssh",
        "--host",
        "127.0.0.1",
        "--port",
        &d.port(),
        "--act",
        "echo",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn tor_rung_via_mock_socks5() {
    let d = Daemon::spawn();

    // mock SOCKS5 proxy (no-auth) forwarding to the daemon
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_port = proxy.local_addr().expect("addr").port();
    let target = d.addr.clone();
    let handle = std::thread::spawn(move || {
        let (mut cli, _) = proxy.accept().expect("accept");
        let mut greet = [0u8; 3];
        cli.read_exact(&mut greet).expect("greeting");
        assert_eq!(greet, [0x05, 0x01, 0x00], "greeting shape");
        cli.write_all(&[0x05, 0x00]).expect("greeting reply");

        let mut head = [0u8; 4];
        cli.read_exact(&mut head).expect("request head");
        assert_eq!(head[0], 0x05, "version");
        assert_eq!(head[1], 0x01, "CONNECT");
        match head[3] {
            0x01 => {
                let mut a = [0u8; 4];
                cli.read_exact(&mut a).expect("ipv4");
            }
            0x03 => {
                let mut l = [0u8; 1];
                cli.read_exact(&mut l).expect("len");
                let mut a = vec![0u8; l[0] as usize];
                cli.read_exact(&mut a).expect("domain");
            }
            0x04 => {
                let mut a = [0u8; 16];
                cli.read_exact(&mut a).expect("ipv6");
            }
            other => panic!("unexpected ATYP {other:#04x}"),
        }
        let mut p = [0u8; 2];
        cli.read_exact(&mut p).expect("port");

        let mut upstream = TcpStream::connect(&target).expect("upstream connect");
        cli.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("reply");

        let mut c2 = cli.try_clone().expect("clone cli");
        let mut u2 = upstream.try_clone().expect("clone up");
        let t = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c2, &mut u2);
            let _ = u2.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut upstream, &mut cli);
        let _ = t.join();
    });

    let out = run_mesh(&[
        "call",
        "--rung",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{proxy_port}"),
        "--host",
        "127.0.0.1",
        "--port",
        &d.port(),
        "--act",
        "echo",
        "--data",
        "\"via-socks\"",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("rung=tor"), "announce: {stderr}");
    let resp: serde_json::Value = serde_json::from_slice(&out.stdout).expect("response json");
    assert_eq!(resp["result"], serde_json::json!("via-socks"));
    let _ = handle.join();
}

#[test]
fn tor_rung_unavailable_stops_announced() {
    // nothing listening on this port
    let dead_port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("reserve");
        l.local_addr().expect("addr").port()
    };
    let out = run_mesh(&[
        "call",
        "--rung",
        "tor",
        "--proxy",
        &format!("127.0.0.1:{dead_port}"),
        "--act",
        "echo",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("rung=tor UNAVAILABLE"), "{stderr}");
    assert!(stderr.contains("no silent fallback"), "{stderr}");
}

#[test]
fn keygen_secure_parseable_and_no_overwrite() {
    let path = tmp("device-key.json");
    let _ = std::fs::remove_file(&path);

    let out = run_mesh(&["keygen", "--out", path.to_str().expect("utf8")]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&path).expect("read key file");
    let v: serde_json::Value = serde_json::from_str(&text).expect("key json");
    assert_eq!(v["seed_hex"].as_str().map(str::len), Some(64));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be 0600");
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("device pubkey"), "{stdout}");

    // refuses to clobber an existing key
    let out2 = run_mesh(&["keygen", "--out", path.to_str().expect("utf8")]);
    assert_eq!(out2.status.code(), Some(1));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn unknown_device_refused() {
    let d = Daemon::spawn();
    let out = run_mesh(&[
        "call",
        "--rung",
        "direct",
        "--port",
        &d.port(),
        "--device",
        "intruder-7",
        "--act",
        "echo",
    ]);
    assert_eq!(out.status.code(), Some(1), "unknown device must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("call failed"), "{stderr}");
    assert!(out.stdout.is_empty(), "no response may leak on cover");
}
