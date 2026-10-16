//! Loopback TCP test — proves the blocking I/O layer wires the state
//! machines over a real socket: a happy-path echo and two cover scenarios
//! (garbage probe + silent linger, mirroring the battery's S8 classes).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use tallow_admission::io::dial_call;
use tallow_admission::{
    cover, device_identity, frame, server_identity, ClientConfig, DeviceEntry, DeviceStatus,
    ServerCore, StaticRegistry,
};

fn core_for_tests() -> Arc<ServerCore> {
    let mut reg = StaticRegistry::new();
    let d = device_identity("operator-1");
    reg.insert(DeviceEntry {
        id: "operator-1".to_string(),
        ed: d.ed.verifying_key(),
        role: "owner".to_string(),
        status: DeviceStatus::Active,
    });
    ServerCore::new(server_identity(), Arc::new(reg), None)
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
fn loopback_happy_path_and_cover_scenarios() {
    let core = core_for_tests();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _serve = tallow_admission::io::serve(listener, Arc::clone(&core));

    // happy path over TCP
    let resp = dial_call(
        &addr.to_string(),
        cfg_for("operator-1"),
        "echo",
        Some(json!("tcp-hello")),
    )
    .expect("dial_call");
    assert_eq!(resp["ok"], json!(true));
    assert_eq!(resp["result"], json!("tcp-hello"));

    // garbage probe over raw TCP → cover bytes
    let mut s = TcpStream::connect(addr).expect("probe connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.write_all(&frame(b"nope")).expect("probe write");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("probe read");
    assert_eq!(out, cover(), "probe must receive cover bytes");

    // silent linger over raw TCP → cover bytes after the deadline
    let mut s = TcpStream::connect(addr).expect("linger connect");
    s.set_read_timeout(Some(Duration::from_secs(6)))
        .expect("timeout");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("linger read");
    assert_eq!(out, cover(), "linger must receive cover bytes");
}
