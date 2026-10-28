//! The three network capabilities with no backend must refuse *in their value*.
//!
//! `docs/quality/stub-audit.md` §9 records A1–A3 as resolved by refusal rather than
//! by implementation. A fixture nobody executes is documentation, so this test runs
//! the user path: a `.tl` program that calls each entry point, executed through the
//! real binary, must exit non-zero and name the missing backend on stderr.
//!
//! The assertion is deliberately threefold: (1) it fails, (2) it says what is
//! missing, and (3) it does not claim success — the defect being closed was a
//! `success: true` with no backend behind it.

use std::process::Command;

fn run(src: &str, name: &str) -> (Option<i32>, String, String) {
    let dir = std::env::temp_dir().join(format!("tallow-unsupported-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let path = dir.join(name);
    std::fs::write(&path, src).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["run", "--interpret"])
        .arg(&path)
        .output()
        .expect("run tallow");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn assert_refusal(src: &str, name: &str, backend: &str) {
    let (code, stdout, stderr) = run(src, name);
    assert!(
        code.is_some() && code != Some(0),
        "{name}: expected a failing exit, got {code:?}\nstdout:{stdout}\nstderr:{stderr}"
    );
    let all = format!("{stdout}\n{stderr}");
    assert!(
        all.contains("is not supported in this build"),
        "{name}: the refusal must name the absent backend, got:\n{all}"
    );
    assert!(
        all.contains(backend),
        "{name}: the refusal must name `{backend}` specifically, got:\n{all}"
    );
    assert!(
        !stdout.contains("success: true") && !stdout.contains("status: connected"),
        "{name}: a capability that does not exist must not report success:\n{stdout}"
    );
}

#[test]
fn wireguard_refuses_and_names_the_missing_backend() {
    assert_refusal(
        "fn main() with Net(tunnel_wireguard) {\n    let t = net.tunnel_wireguard(\"vpn.example.com:51820\", \"base64pubkey==\")\n    print(\"{t.status}\")\n}\n",
        "wireguard.tl",
        "WireGuard",
    );
}

#[test]
fn grpc_refuses_and_names_the_missing_backend() {
    assert_refusal(
        "fn main() with Net(grpc_server_create) {\n    let s = net.grpc_server_create(50051)\n    print(\"{s.port}\")\n}\n",
        "grpc.tl",
        "gRPC",
    );
}

#[test]
fn pluggable_transport_refuses_and_names_the_missing_backend() {
    assert_refusal(
        "fn main() with Net(transport_obfs4) {\n    let t = net.transport_obfs4(\"bridge.example.com:443\")\n    print(\"{t.kind}\")\n}\n",
        "obfs4.tl",
        "obfs4",
    );
}
