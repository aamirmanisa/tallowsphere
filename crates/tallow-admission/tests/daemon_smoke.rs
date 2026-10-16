//! Daemon packaging smoke — exercises the actual `tallow-admissiond` binary
//! over loopback: dev-registry minting via `--print-dev-registry`, admission
//! and echo, RBAC deny, byte-identical cover for an unknown device, and the
//! audit file contents.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use tallow_admission::server::Action;
use tallow_admission::{
    cover, device_identity, io as adm_io, server_identity, ClientConfig, ClientSession,
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow-admissiond")
}

fn tmp_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "tallow-admissiond-smoke-{}-{tag}",
        std::process::id()
    ));
    p
}

fn cfg_for(name: &str) -> ClientConfig {
    let si = server_identity();
    ClientConfig {
        device: device_identity(name),
        server_ed: si.ed.verifying_key(),
        server_x: x25519_dalek::PublicKey::from(&si.x),
        ts_override: None,
        tamper_sig: false,
    }
}

#[test]
fn daemon_smoke_end_to_end() {
    // 1) mint the dev registry via the binary itself
    let out = Command::new(bin())
        .arg("--print-dev-registry")
        .output()
        .expect("run --print-dev-registry");
    assert!(out.status.success(), "print-dev-registry exit");
    let reg_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("registry is JSON");
    assert_eq!(
        reg_json["devices"].as_array().map(Vec::len),
        Some(3),
        "three dev devices"
    );

    let out_srv = Command::new(bin())
        .arg("--print-dev-server")
        .output()
        .expect("run --print-dev-server");
    assert!(out_srv.status.success(), "print-dev-server exit");
    let srv_json: serde_json::Value =
        serde_json::from_slice(&out_srv.stdout).expect("server keys are JSON");
    assert_eq!(
        srv_json["ed_pub_hex"].as_str().map(str::len),
        Some(64),
        "server ed25519 pubkey hex"
    );
    assert_eq!(
        srv_json["x_pub_hex"].as_str().map(str::len),
        Some(64),
        "server x25519 pubkey hex"
    );

    // 2) materialize registry + audit paths; reserve a port, release it for the daemon
    let registry_path = tmp_path("registry.json");
    std::fs::write(&registry_path, &out.stdout).expect("write registry");
    let audit_path = tmp_path("audit.log");
    let _ = std::fs::remove_file(&audit_path);

    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("reserve port");
        l.local_addr().expect("addr").port()
    };
    let addr = format!("127.0.0.1:{port}");

    // 3) spawn the daemon; wait for readiness
    let mut child = Command::new(bin())
        .args([
            "--listen",
            &addr,
            "--registry",
            registry_path.to_str().expect("utf8 path"),
            "--audit",
            audit_path.to_str().expect("utf8 path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("daemon never became ready on {addr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // 4) happy path — operator echo via the one-shot client
    let resp = adm_io::dial_call(&addr, cfg_for("operator-1"), "echo", Some(json!("hi")))
        .expect("operator echo");
    assert_eq!(resp["ok"], json!(true), "echo ok: {resp}");
    assert_eq!(resp["act"], json!("echo"));
    assert_eq!(resp["result"], json!("hi"));

    // 5) RBAC — guest denied on an owner action
    let resp = adm_io::dial_call(&addr, cfg_for("guest-1"), "hermes.config.read", None)
        .expect("guest call");
    assert_eq!(resp["ok"], json!(false), "denied response: {resp}");
    assert_eq!(resp["code"], json!("denied"));

    // 6) unknown device over the real daemon → byte-identical cover
    {
        let mut c = ClientSession::new(cfg_for("intruder-9"));
        let mut s = TcpStream::connect(&addr).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        s.write_all(&c.start()).expect("write msg1");
        let mut buf = [0u8; 4096];
        let n = s.read(&mut buf).expect("read msg2");
        let acts = c.feed(&buf[..n]).expect("feed msg2");
        let m3 = match acts.into_iter().next() {
            Some(Action::Write(b)) => b,
            other => panic!("expected msg3 write, got {other:?}"),
        };
        s.write_all(&m3).expect("write msg3");
        let mut rest = Vec::new();
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => rest.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        assert_eq!(
            rest,
            cover(),
            "unknown device over the daemon gets byte-identical cover"
        );
    }

    // 7) audit file landed the events
    let _ = child.kill();
    let _ = child.wait();
    let audit = std::fs::read_to_string(&audit_path).expect("audit file readable");
    assert!(
        audit.contains("AUTH ok device=operator-1 role=owner"),
        "auth line missing; audit:\n{audit}"
    );
    assert!(
        audit.contains("ALLOW device=operator-1 role=owner act=echo"),
        "allow line missing; audit:\n{audit}"
    );
    assert!(
        audit.contains("DENY device=guest-1 role=guest act=hermes.config.read"),
        "deny line missing; audit:\n{audit}"
    );

    let _ = std::fs::remove_file(&registry_path);
    let _ = std::fs::remove_file(&audit_path);
}
