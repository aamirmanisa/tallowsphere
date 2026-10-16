//! SPKI pin probe — connect to a TLS server pinning `sha256(SPKI DER)`, or
//! hash a certificate's SPKI for out-of-band pin provisioning.
//!
//! ```text
//! Usage:
//!   spki_pin_probe --hash-cert <cert.der>          print sha256(SPKI DER) hex
//!   spki_pin_probe --addr HOST:PORT --pin <hex64> [--server-name N] [--http]
//! ```
//!
//! Exit codes: 0 = handshake OK (and HTTP leg if `--http`), 3 = pin rejected,
//! 4 = usage/config/other error. Lab tool for the pin + registry-verify arc
//! (D7 acceptance: the substituted-certificate scenario must be rejected while
//! the matching pin is accepted).

use std::process::ExitCode;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use tallow_net::transport::spki_pin::spki_sha256;
use tallow_net::transport::tls_config::client_config_pinned;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         spki_pin_probe --hash-cert <cert.der>\n  \
         spki_pin_probe --addr HOST:PORT --pin <hex64> [--server-name N] [--http]"
    );
    ExitCode::from(4)
}

fn decode_pin(hex_str: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_str).map_err(|e| format!("pin hex: {e}"))?;
    raw.try_into()
        .map_err(|v: Vec<u8>| format!("pin must be 32 bytes, got {}", v.len()))
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let mut addr: Option<String> = None;
    let mut pin_hex: Option<String> = None;
    let mut server_name = "localhost".to_string();
    let mut http = false;
    let mut hash_cert: Option<String> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--addr" => {
                i += 1;
                addr = Some(argv.get(i).cloned().unwrap_or_default());
            }
            "--pin" => {
                i += 1;
                pin_hex = Some(argv.get(i).cloned().unwrap_or_default());
            }
            "--server-name" => {
                i += 1;
                server_name = argv.get(i).cloned().unwrap_or_default();
            }
            "--http" => http = true,
            "--hash-cert" => {
                i += 1;
                hash_cert = Some(argv.get(i).cloned().unwrap_or_default());
            }
            other => {
                eprintln!("unknown argument: {other}");
                return usage();
            }
        }
        i += 1;
    }

    // Mode 1: hash a DER certificate's SPKI (pin provisioning helper).
    if let Some(path) = hash_cert {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("read {path}: {e}");
                return ExitCode::from(4);
            }
        };
        let cert = CertificateDer::from(bytes);
        match spki_sha256(&cert) {
            Ok(h) => {
                println!("SPKI_SHA256={}", hex::encode(h));
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("spki parse: {e}");
                return ExitCode::from(4);
            }
        }
    }

    // Mode 2: pinned connect.
    let (Some(addr), Some(pin_hex)) = (addr, pin_hex) else {
        return usage();
    };
    let pin = match decode_pin(&pin_hex) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(4);
        }
    };

    let cfg = match client_config_pinned(&[], pin) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("client config: {e}");
            return ExitCode::from(4);
        }
    };
    let connector = TlsConnector::from(Arc::new(cfg));
    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tcp connect {addr}: {e}");
            return ExitCode::from(4);
        }
    };
    let name = match ServerName::try_from(server_name.clone()) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("server name: {e}");
            return ExitCode::from(4);
        }
    };

    let mut tls = match connector.connect(name, stream).await {
        Ok(t) => t,
        Err(e) => {
            println!("PIN_REJECTED: {e}");
            return ExitCode::from(3);
        }
    };
    println!("PIN_OK: handshake verified against pinned SPKI");

    if http {
        let req = format!("GET / HTTP/1.0\r\nHost: {server_name}\r\n\r\n");
        if let Err(e) = tls.write_all(req.as_bytes()).await {
            eprintln!("write: {e}");
            return ExitCode::from(4);
        }
        let mut buf = vec![0u8; 4096];
        match tls.read(&mut buf).await {
            Ok(0) => {
                eprintln!("read: connection closed without data");
                return ExitCode::from(4);
            }
            Ok(n) => {
                let head = String::from_utf8_lossy(&buf[..n]);
                let first = head.lines().next().unwrap_or("").to_string();
                println!("HTTP_OK: {first}");
            }
            Err(e) => {
                eprintln!("read: {e}");
                return ExitCode::from(4);
            }
        }
    }

    ExitCode::SUCCESS
}
