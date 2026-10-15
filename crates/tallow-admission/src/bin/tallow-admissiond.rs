//! `tallow-admissiond` — loopback-first daemon wrapping the admission core.
//!
//! Packaging shape for task 1.4: the same [`tallow_admission::server::ServerCore`]
//! behind a blocking TCP listener ([`tallow_admission::io::serve`]). Loopback
//! only by default — it refuses non-loopback binds without
//! `--allow-non-loopback` (admin surfaces never public). Production sits
//! behind Caddy (TLS terminated there) with real key material loaded via
//! `--server-key`; without it the daemon runs on the deterministic DEV keys
//! with a loud warning (staging/rehearsal only).
//!
//! ```text
//! Modes:
//!   --print-dev-registry   print the deterministic dev device registry (JSON), exit
//!   --print-dev-server     print the deterministic dev server public keys (JSON), exit
//!   --help                 usage
//!
//! Server:
//!   --listen <addr>        bind address (default 127.0.0.1:9410)
//!   --registry <path>      device registry JSON (required)
//!   --server-key <path>    server key material JSON {ed_seed_hex, x_seed_hex}
//!   --audit <path|->       audit destination (default: - = stdout)
//!   --allow-non-loopback   permit a non-loopback bind (default: refuse)
//! ```

use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use x25519_dalek::StaticSecret;

use tallow_admission::devkeys::{device_identity, server_identity, ServerIdentity};
use tallow_admission::server::{
    AuditEvent, AuditSink, DeviceEntry, DeviceRegistry, DeviceStatus, ServerCore, StaticRegistry,
};
use tallow_admission::{cover, io as adm_io};

fn die(msg: &str) -> ! {
    eprintln!("tallow-admissiond: {msg}");
    std::process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "tallow-admissiond {}\n\
         Usage: tallow-admissiond --registry <path> [--listen ADDR] [--server-key <path>]\n\
         \x20                        [--audit <path|->] [--allow-non-loopback]\n\
         \x20      tallow-admissiond --print-dev-registry | --print-dev-server | --help\n\
         \x20      tallow-admissiond --print-pubkeys [--server-key <path>]\n",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}

fn parse_hex32(s: &str, what: &str) -> [u8; 32] {
    let v = match hex::decode(s) {
        Ok(v) => v,
        Err(e) => die(&format!("{what}: bad hex: {e}")),
    };
    match <[u8; 32]>::try_from(v) {
        Ok(a) => a,
        Err(v) => die(&format!("{what}: expected 32 bytes, got {}", v.len())),
    }
}

// ------------------------------------------------------------- registry file

#[derive(Deserialize)]
struct RegistryFile {
    devices: Vec<RegistryRow>,
}

#[derive(Deserialize)]
struct RegistryRow {
    id: String,
    role: String,
    status: String,
    ed_pub_hex: String,
}

fn load_registry(path: &str) -> StaticRegistry {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => die(&format!("registry: cannot read {path}: {e}")),
    };
    let file: RegistryFile = match serde_json::from_str(&data) {
        Ok(f) => f,
        Err(e) => die(&format!("registry: bad JSON in {path}: {e}")),
    };
    let mut reg = StaticRegistry::new();
    for row in file.devices {
        let pub32 = parse_hex32(&row.ed_pub_hex, &format!("registry[{}].ed_pub_hex", row.id));
        let key = match ed25519_dalek::VerifyingKey::from_bytes(&pub32) {
            Ok(k) => k,
            Err(e) => die(&format!("registry[{}]: invalid Ed25519 key: {e}", row.id)),
        };
        let status = match row.status.as_str() {
            "active" => DeviceStatus::Active,
            "revoked" => DeviceStatus::Revoked,
            other => die(&format!(
                "registry[{}]: unknown status {other:?} (active|revoked)",
                row.id
            )),
        };
        reg.insert(DeviceEntry {
            id: row.id,
            ed: key,
            role: row.role,
            status,
        });
    }
    reg
}

// ------------------------------------------------------------- server keys

#[derive(Deserialize)]
struct ServerKeyFile {
    ed_seed_hex: String,
    x_seed_hex: String,
}

fn load_identity(path: Option<&str>) -> (ServerIdentity, bool) {
    match path {
        None => (server_identity(), true),
        Some(p) => {
            let data = match std::fs::read_to_string(p) {
                Ok(d) => d,
                Err(e) => die(&format!("server-key: cannot read {p}: {e}")),
            };
            let f: ServerKeyFile = match serde_json::from_str(&data) {
                Ok(f) => f,
                Err(e) => die(&format!("server-key: bad JSON in {p}: {e}")),
            };
            (
                ServerIdentity {
                    ed: SigningKey::from_bytes(&parse_hex32(&f.ed_seed_hex, "ed_seed_hex")),
                    x: StaticSecret::from(parse_hex32(&f.x_seed_hex, "x_seed_hex")),
                },
                false,
            )
        }
    }
}

// -------------------------------------------------------------------- print

fn print_dev_registry() {
    let devices: Vec<serde_json::Value> = [
        ("operator-1", "owner", "active"),
        ("guest-1", "guest", "active"),
        ("revoked-1", "owner", "revoked"),
    ]
    .iter()
    .map(|(name, role, status)| {
        let pk = device_identity(name).ed.verifying_key();
        serde_json::json!({
            "id": name,
            "role": role,
            "status": status,
            "ed_pub_hex": hex::encode(pk.to_bytes()),
        })
    })
    .collect();
    let doc = serde_json::json!({ "devices": devices });
    println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
}

fn print_dev_server() {
    let si = server_identity();
    let x_pub = x25519_dalek::PublicKey::from(&si.x);
    let doc = serde_json::json!({
        "ed_pub_hex": hex::encode(si.ed.verifying_key().to_bytes()),
        "x_pub_hex": hex::encode(x_pub.to_bytes()),
    });
    println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
}

// --------------------------------------------------------------------- main

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen = "127.0.0.1:9410".to_string();
    let mut registry_path: Option<String> = None;
    let mut server_key_path: Option<String> = None;
    let mut audit = "-".to_string();
    let mut allow_non_loopback = false;
    let mut print_pubkeys = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--print-dev-registry" => {
                print_dev_registry();
                return;
            }
            "--print-dev-server" => {
                print_dev_server();
                return;
            }
            "--print-pubkeys" => print_pubkeys = true,
            "--help" | "-h" => usage(),
            "--listen" => {
                i += 1;
                listen = match args.get(i) {
                    Some(v) => v.clone(),
                    None => die("--listen needs a value"),
                };
            }
            "--registry" => {
                i += 1;
                registry_path = Some(match args.get(i) {
                    Some(v) => v.clone(),
                    None => die("--registry needs a value"),
                });
            }
            "--server-key" => {
                i += 1;
                server_key_path = Some(match args.get(i) {
                    Some(v) => v.clone(),
                    None => die("--server-key needs a value"),
                });
            }
            "--audit" => {
                i += 1;
                audit = match args.get(i) {
                    Some(v) => v.clone(),
                    None => die("--audit needs a value"),
                };
            }
            "--allow-non-loopback" => allow_non_loopback = true,
            other => die(&format!("unknown argument {other:?} (try --help)")),
        }
        i += 1;
    }

    if print_pubkeys {
        let (si, dev) = load_identity(server_key_path.as_deref());
        if dev {
            eprintln!(
                "tallow-admissiond: WARNING: printing DEV server keys (no --server-key given)"
            );
        }
        let x_pub = x25519_dalek::PublicKey::from(&si.x);
        let doc = serde_json::json!({
            "ed_pub_hex": hex::encode(si.ed.verifying_key().to_bytes()),
            "x_pub_hex": hex::encode(x_pub.to_bytes()),
        });
        println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
        return;
    }

    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => die(&format!("--listen: bad address {listen:?}: {e}")),
    };
    if !addr.ip().is_loopback() && !allow_non_loopback {
        die("refusing a non-loopback bind without --allow-non-loopback (admin surfaces never public)");
    }

    let registry_path = match registry_path {
        Some(p) => p,
        None => usage(),
    };
    let registry = load_registry(&registry_path);
    let (identity, is_dev) = load_identity(server_key_path.as_deref());
    if is_dev {
        eprintln!(
            "tallow-admissiond: WARNING: DEV SERVER KEYS in use (deterministic test material) — staging/rehearsal only; pass --server-key for production"
        );
    }

    let sink: AuditSink = if audit == "-" {
        Arc::new(|ev: AuditEvent| println!("{}", ev.line()))
    } else {
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit)
        {
            Ok(f) => f,
            Err(e) => die(&format!("audit: cannot open {audit}: {e}")),
        };
        let file = Mutex::new(file);
        Arc::new(move |ev: AuditEvent| {
            let mut f = match file.lock() {
                Ok(f) => f,
                Err(p) => p.into_inner(),
            };
            use std::io::Write;
            let _ = writeln!(f, "{}", ev.line());
            let _ = f.flush();
        })
    };

    let registry: Arc<dyn DeviceRegistry> = Arc::new(registry);
    let core = ServerCore::new(identity, registry, Some(sink));

    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => die(&format!("bind {addr}: {e}")),
    };
    let local = listener.local_addr().expect("local addr");
    println!(
        "tallow-admissiond {} listening on {local} (loopback-first; behind-Caddy shape; cover={} B)",
        env!("CARGO_PKG_VERSION"),
        cover().len()
    );

    let handle = adm_io::serve(listener, core);
    let _ = handle.join();
}
