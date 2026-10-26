//! N01/N10/N11 — the topology slice, measured against a real loopback
//! listener.
//!
//! A SYN scan is a real packet exchange: the listener's port must come back
//! `open`, and a closed port must come back `closed` (RST) rather than being
//! swept into `filtered`. The connect scan is the unprivileged path and must
//! reach the same verdicts. The SYN test needs CAP_NET_RAW and skips loudly if
//! the environment denies it — a skipped test that says why is evidence; a
//! silently passing one is not.

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::thread;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/topology/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(name: &str) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(fixture(name))
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_connect_scan_separates_open_from_closed() {
    let listener = TcpListener::bind("127.0.0.1:45992").expect("bind 45992");
    let _accepted = thread::spawn(move || {
        let _ = listener.accept();
    });

    let (ok, stdout, stderr) = run("scan_connect.tl");
    assert!(ok, "connect scan must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("open=[45992]"),
        "the listening port must be open and the closed ones must not:\n{stdout}"
    );
    assert!(
        stdout.contains("closed=[45993, 45994]"),
        "closed ports must be reported closed, not filtered:\n{stdout}"
    );
}

#[test]
fn a_syn_scan_separates_open_from_closed() {
    // Raw sockets need CAP_NET_RAW. Root has it; a sandbox may not. Skip with
    // the measured reason rather than pretending the scan ran.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: raw SYN scan needs CAP_NET_RAW (not root)");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:45995").expect("bind 45995");
    let _accepted = thread::spawn(move || {
        let _ = listener.accept();
    });

    let (ok, stdout, stderr) = run("scan_loopback.tl");
    assert!(ok, "syn scan must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("plan packets=3"),
        "the planner must count one probe per port:\n{stdout}"
    );
    assert!(
        stdout.contains("syn open=[45995]"),
        "the listener must be seen open by a half-open scan:\n{stdout}"
    );
    assert!(
        stdout.contains("closed=[45996, 45997]"),
        "CLOSED means a RST came back; silence is filtered:\n{stdout}"
    );
}

#[test]
fn an_unauthorized_target_is_refused_before_a_packet_is_sent() {
    // The scanner must not be a second, weaker door than the register. A host
    // that is not listed cannot be planned or scanned at all.
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(fixture("unauthorized_target.tl"))
        .output()
        .expect("run tallow");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "an unlisted target must not scan:\n{stderr}"
    );
    assert!(
        stderr.contains("not authorized"),
        "the refusal must come from the scope register:\n{stderr}"
    );
    assert!(
        stderr.contains("scope:not-listed"),
        "the register's own refusal code must be carried through:\n{stderr}"
    );
}

#[test]
fn a_fin_scan_never_claims_open() {
    // N03: silence from a non-SYN probe is open|filtered. A closed port must
    // still be decisive (RST), and the caveat must travel with the result so a
    // reader cannot mistake "no RST" for "open".
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: FIN scan needs CAP_NET_RAW (not root)");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:45998").expect("bind 45998");
    let _accepted = thread::spawn(move || {
        let _ = listener.accept();
    });

    let (ok, stdout, stderr) = run("evasion_fin.tl");
    assert!(ok, "fin scan must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("open_or_filtered=[45998]"),
        "a listening port must be undecidable under FIN, never 'open':\n{stdout}"
    );
    assert!(
        stdout.contains("closed=[45999, 46000]"),
        "a RST is decisive even for FIN:\n{stdout}"
    );
    assert!(
        stdout.contains("silence means open|filtered"),
        "the caveat must be carried in the result:\n{stdout}"
    );
}

#[test]
fn discovery_unions_icmp_and_tcp() {
    // N04: loopback answers both. The assertion is about presence and the
    // confidence being non-zero, not about which method won.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: raw ICMP discovery needs CAP_NET_RAW (not root)");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:46001").expect("bind 46001");
    let _accepted = thread::spawn(move || {
        let _ = listener.accept();
    });

    let (ok, stdout, stderr) = run("discover_loopback.tl");
    assert!(ok, "discovery must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("alive=true"),
        "loopback must be discovered alive:\n{stdout}"
    );
    assert!(
        stdout.contains("confidence=0.9"),
        "a positive ICMP discovery carries 0.9 (a reply proves presence):\n{stdout}"
    );
}

#[test]
fn tls_posture_reports_the_handshake_it_saw() {
    // N06: a self-signed server still has a reportable posture. The assertions
    // are the facts a posture report exists to carry: negotiated version,
    // cipher, the certificate's own SAN, and the trust verdict as data.
    let key = rcgen::KeyPair::generate().expect("keygen");
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    let cert = params.self_signed(&key).expect("self-sign");

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let server_config = std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
                ),
            )
            .expect("server config"),
    );

    let listener = TcpListener::bind("127.0.0.1:46003").expect("bind 46003");
    let _server = thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut conn = rustls::ServerConnection::new(server_config).expect("server conn");
            let mut buf = [0u8; 16];
            // Drive the handshake only; the client closes after reading posture.
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
            // Read anything the client sends so it does not see an early RST.
            let _ = sock.read(&mut buf);
        }
    });

    let (ok, stdout, stderr) = run("tls_posture.tl");
    assert!(ok, "posture probe must run:\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("version=TLSv1.3"),
        "the negotiated version must be reported:\n{stdout}"
    );
    assert!(
        stdout.contains("trusted=false"),
        "a self-signed certificate is untrusted and must be reported as such:\n{stdout}"
    );
    assert!(
        stdout.contains("\"localhost\"") || stdout.contains("localhost"),
        "the certificate's own SAN must be reported:\n{stdout}"
    );
    assert!(
        stdout.contains("chain_len=1"),
        "the presented chain length must be reported:\n{stdout}"
    );
}
