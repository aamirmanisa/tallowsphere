//! Conformance: the TLS stack can actually negotiate the post-quantum hybrid
//! group, and does not pretend to when it cannot.
//!
//! These run a real TLS 1.3 handshake over a loopback socket — no external
//! network, no mocks. The assertion is on `negotiated_key_exchange_group()`,
//! i.e. the group the two stacks agreed on, not on the list they advertise.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

struct Cert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn self_signed() -> Cert {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed certificate");
    Cert {
        cert: ck.cert.der().clone(),
        key: PrivateKeyDer::try_from(ck.key_pair.serialize_der()).expect("private key"),
    }
}

/// Run one handshake and return the negotiated group name as rustls reports it.
fn negotiated_group(pq: bool) -> String {
    let cert = self_signed();
    let provider: Arc<rustls::crypto::CryptoProvider> = if pq {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    } else {
        Arc::new(rustls::crypto::ring::default_provider())
    };

    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.clone()], cert.key)
        .expect("server config");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert.cert.clone())
        .expect("trust the self-signed certificate");
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");

    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let conn = rustls::ServerConnection::new(Arc::new(server_config)).expect("server conn");
        let mut stream = rustls::StreamOwned::new(conn, sock);
        // Complete the handshake by writing a byte.
        let _ = stream.write_all(b"x");
        stream
            .conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()))
            .unwrap_or_else(|| "<none>".to_string())
    });

    let sock = TcpStream::connect(addr).expect("connect");
    let conn = rustls::ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .expect("client conn");
    let mut stream = rustls::StreamOwned::new(conn, sock);
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);
    // Drive the handshake to completion if the read did not.
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .expect("handshake io");
    }
    let group = stream
        .conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_else(|| "<none>".to_string());

    let server_group = server.join().expect("server thread");
    assert_eq!(
        server_group, group,
        "both ends must report the same group (server={server_group}, client={group})"
    );
    group
}

#[test]
fn the_pq_provider_negotiates_x25519mlkem768() {
    let group = negotiated_group(true);
    assert!(
        group.contains("MLKEM"),
        "aws-lc-rs must negotiate a post-quantum hybrid group, got {group}"
    );
    assert_eq!(
        group, "X25519MLKEM768",
        "the standard codepoint name is what a peer will report"
    );
}

#[test]
fn the_classical_provider_does_not_claim_a_pq_group() {
    let group = negotiated_group(false);
    assert!(
        !group.contains("MLKEM"),
        "the default provider must stay classical, got {group}"
    );
    assert!(
        group.contains("X25519") || group.contains("P256") || group.contains("P384"),
        "expected a named classical group, got {group}"
    );
}
