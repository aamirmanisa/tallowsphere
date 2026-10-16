//! W2-08 — `--bwlimit` enforcement + `--vss` removal gates (design cycle-02/09
//! §W1: D-C2 parse+enforce, V1 timing band, V2 rejection).
//!
//! These tests spawn the real compiled binary (`CARGO_BIN_EXE_tallow`) and run
//! end-to-end loopback transfers:
//!   1. relay-v1 pair: `tallow relay` + `receive --relay` + `send --relay`,
//!   2. QUIC direct: `receive --listen` + `send --to` — gated to the
//!      non-default `dangerous_skip_verify` feature (the hardened default
//!      rejects the self-signed lab cert; W5-D, commit ebe54604),
//!   3. `--vss` is rejected by clap (removed flag, D-C1).
//!
//! Timing band (design V1): 1 MiB @ `1M` bits/sec = 8,388,608 / 1,000,000 =
//! 8.388608 s nominal; assert ±20% => [6.71, 10.07] s. The band is wide by
//! design; measured values are logged in the W2-08 exec log.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "dangerous_skip_verify")]
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_tallow");
const SEND_BYTES: usize = 1024 * 1024; // 1 MiB
const BAND_LOW: f64 = 6.71;
const BAND_HIGH: f64 = 10.07;

/// Deterministic 1 MiB payload (not compressible to trivial size).
fn write_test_file(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let mut data = Vec::with_capacity(SEND_BYTES);
    let mut x: u32 = 0x9e37_79b9;
    while data.len() < SEND_BYTES {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.extend_from_slice(&x.to_le_bytes());
    }
    data.truncate(SEND_BYTES);
    std::fs::write(&path, &data).expect("write test file");
    path
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("addr")
        .port()
}

#[cfg(feature = "dangerous_skip_verify")]
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("udp bind probe")
        .local_addr()
        .expect("addr")
        .port()
}

fn wait_tcp_listen(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Kill-on-drop process guard.
struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(args: &[&str]) -> Proc {
    Proc(
        Command::new(BIN)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tallow"),
    )
}

/// Wait for child exit up to `timeout`; returns (exit_ok, stdout, stderr).
fn wait_with_output(mut proc: Proc, timeout: Duration) -> (bool, String, String) {
    let deadline = Instant::now() + timeout;
    loop {
        match proc.0.try_wait().expect("try_wait") {
            Some(status) => {
                let mut out = String::new();
                let mut err = String::new();
                if let Some(mut s) = proc.0.stdout.take() {
                    let _ = s.read_to_string(&mut out);
                }
                if let Some(mut s) = proc.0.stderr.take() {
                    let _ = s.read_to_string(&mut err);
                }
                return (status.success(), out, err);
            }
            None if Instant::now() >= deadline => {
                let _ = proc.0.kill();
                let _ = proc.0.wait();
                return (false, String::new(), "timeout waiting for process exit".into());
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn assert_band(elapsed: Duration, what: &str, stdout: &str) {
    let secs = elapsed.as_secs_f64();
    println!("[W2-08] {what}: {secs:.3}s (band {BAND_LOW}–{BAND_HIGH}s)\n{stdout}");
    assert!(
        (BAND_LOW..=BAND_HIGH).contains(&secs),
        "{what} elapsed {secs:.3}s outside V1 band {BAND_LOW}–{BAND_HIGH}s"
    );
}

fn assert_received(src: &Path, out_dir: &Path) {
    let name = src.file_name().unwrap();
    let got = out_dir.join(name);
    let want = std::fs::read(src).expect("read source");
    let have = std::fs::read(&got).unwrap_or_else(|e| panic!("missing {}: {e}", got.display()));
    assert_eq!(have.len(), want.len(), "received size mismatch");
    assert_eq!(have, want, "received bytes differ from source");
}

/// V1 / relay-v1: `send --relay --bwlimit 1M` of 1 MiB must land inside the band.
#[test]
fn bwlimit_paces_relay_send_within_band() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = write_test_file(tmp.path(), "payload.bin");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).expect("mkdir out");

    let port = free_tcp_port();
    let relay_addr = format!("127.0.0.1:{port}");
    let code = "123-alpha-beta-gamma";

    let relay = spawn(&["relay", "--port", &port.to_string()]);
    assert!(
        wait_tcp_listen(&relay_addr, Duration::from_secs(5)),
        "relay did not start listening on {relay_addr}"
    );

    let recv = spawn(&[
        "receive",
        "--code",
        code,
        "--relay",
        &relay_addr,
        "--output",
        out_dir.to_str().unwrap(),
        "--timeout",
        "60",
    ]);
    // Give the receiver time to join the relay room before the sender pairs.
    std::thread::sleep(Duration::from_millis(700));

    let t0 = Instant::now();
    let send = Command::new(BIN)
        .args([
            "send",
            src.to_str().unwrap(),
            "--relay",
            &relay_addr,
            "--code",
            code,
            "--bwlimit",
            "1M",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run sender");
    let elapsed = t0.elapsed();
    let stdout = String::from_utf8_lossy(&send.stdout).to_string();
    assert!(
        send.status.success(),
        "sender rc={:?}\nstdout:{stdout}\nstderr:{}",
        send.status.code(),
        String::from_utf8_lossy(&send.stderr)
    );
    assert!(
        stdout.contains("125000"),
        "sender stdout must show parsed 1M = 125000 B/s (D-C2), got:\n{stdout}"
    );
    assert_band(elapsed, "relay send 1 MiB @ 1M", &stdout);

    let (recv_ok, recv_out, recv_err) = wait_with_output(recv, Duration::from_secs(30));
    assert!(
        recv_ok,
        "receiver failed\nstdout:{recv_out}\nstderr:{recv_err}"
    );
    assert_received(&src, &out_dir);
    drop(relay);
}

/// V1 / QUIC direct: `send --to --bwlimit 1M` of 1 MiB must land inside the band.
///
/// W5-D (2026-09-27): the receiver serves a runtime self-signed lab cert; the
/// hardened default (webpki roots) rejects it with `UnknownIssuer`, so this test
/// is only valid with the non-default `dangerous_skip_verify` feature — the same
/// gate as the in-file QUIC roundtrip tests in src/stdlib/transfer_net.rs.
/// Run it with: `cargo test --features dangerous_skip_verify --test transfer_bwlimit`
#[cfg(feature = "dangerous_skip_verify")]
#[test]
fn bwlimit_paces_quic_direct_send_within_band() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = write_test_file(tmp.path(), "payload.bin");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir(&out_dir).expect("mkdir out");

    let port = free_udp_port();
    let listen = format!("127.0.0.1:{port}");

    let recv = spawn(&[
        "receive",
        "--listen",
        &listen,
        "--output",
        out_dir.to_str().unwrap(),
        "--timeout",
        "60",
    ]);
    // No portable probe for the QUIC (UDP) listener; startup is <1 s on a warm
    // build. The sender retries the handshake if the receiver is not up yet.
    std::thread::sleep(Duration::from_millis(900));

    let t0 = Instant::now();
    let send = Command::new(BIN)
        .args([
            "send",
            src.to_str().unwrap(),
            "--to",
            &listen,
            "--bwlimit",
            "1M",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run sender");
    let elapsed = t0.elapsed();
    let stdout = String::from_utf8_lossy(&send.stdout).to_string();
    assert!(
        send.status.success(),
        "sender rc={:?}\nstdout:{stdout}\nstderr:{}",
        send.status.code(),
        String::from_utf8_lossy(&send.stderr)
    );
    assert!(
        stdout.contains("125000"),
        "sender stdout must show parsed 1M = 125000 B/s (D-C2), got:\n{stdout}"
    );
    assert_band(elapsed, "QUIC direct send 1 MiB @ 1M", &stdout);

    let (recv_ok, recv_out, recv_err) = wait_with_output(recv, Duration::from_secs(30));
    assert!(
        recv_ok,
        "receiver failed\nstdout:{recv_out}\nstderr:{recv_err}"
    );
    assert_received(&src, &out_dir);
}

/// V2: `--vss` is gone — clap must reject it with a clean unknown-argument error.
#[test]
fn vss_flag_is_rejected_by_clap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();

    let out = Command::new(BIN)
        .args([
            "delta-sync",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--vss",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run delta-sync --vss");
    assert!(!out.status.success(), "--vss must be rejected after D-C1 removal");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--vss") && stderr.to_lowercase().contains("unexpected"),
        "expected clap unknown-argument error for --vss, got:\n{stderr}"
    );
}
