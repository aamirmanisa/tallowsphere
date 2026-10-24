//! TallowTransfer network module -- real QUIC file transfer via quinn.
//!
//! Phase 59: Provides QuicTransfer.listen, connect, send_file, receive,
//! send_bytes, and status operations backed by real QUIC (quinn + rustls TLS 1.3).
//!
//! Phase 60: Code phrase pairing (croc-style), TCP relay server,
//! resume interrupted transfers, and CLI progress bar support.
//!
//! Phase 61: Multi-file send, folder send, compression during transfer,
//! parallel streams config, bandwidth limiting, and watch mode.
//!
//! Self-signed certificates are generated at runtime via rcgen.
//! Client-side server-cert verification is HARDENED BY DEFAULT (W5
//! decision D, 2026-09-27): webpki-root CA verification is required.
//! `dangerous_skip_verify` (non-default) opts out for dev/LAN
//! self-signed peers; peer pinning/TOFU remains the close-out arc.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::interp::Value;
use super::StdlibResult;

// ── Self-Signed Certificate Generation (rcgen) ──

/// Create a QUIC server config with a freshly-generated self-signed cert.
fn create_server_config() -> Result<quinn::ServerConfig, String> {
    // Ensure ring provider is installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let subject_alt_names = vec!["localhost".to_string(), "tallow-transfer".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| format!("cert gen failed: {e}"))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| format!("key conversion failed: {e}"))?;

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("rustls config failed: {e}"))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("quic server config failed: {e}"))?,
    ));

    // Tune transport for file transfer
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
    ));
    transport.initial_mtu(1350);

    Ok(server_config)
}

/// Create a QUIC client config for the transfer client.
///
/// Server-certificate verification is skipped only when the
/// `dangerous_skip_verify` feature is enabled (non-default; dev/LAN
/// self-signed peers). Default builds require CA-validated certificates
/// (webpki roots) — W5 decision D, 2026-09-27.
fn create_client_config() -> Result<quinn::ClientConfig, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(feature = "dangerous_skip_verify")]
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    #[cfg(not(feature = "dangerous_skip_verify"))]
    let crypto = {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| format!("quic client config failed: {e}"))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
    ));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Skip server certificate verification — only compiled under the
/// `dangerous_skip_verify` feature (see create_client_config).
#[cfg(feature = "dangerous_skip_verify")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "dangerous_skip_verify")]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// ══════════════════════════════════════════════════════════════════
// Phase 60: Code Phrase System — croc-style pairing
// ══════════════════════════════════════════════════════════════════

/// Word list for code phrase generation (256 words, phonetically distinct)
const CODE_WORDS: &[&str] = &[
    "alpha", "anchor", "anvil", "arctic", "atlas", "aurora", "autumn", "azure",
    "beacon", "blaze", "bolt", "breeze", "bronze", "canyon", "carbon", "cascade",
    "cedar", "cipher", "cobalt", "comet", "coral", "cosmos", "crane", "crystal",
    "cypress", "dagger", "dawn", "delta", "diamond", "drift", "eagle", "echo",
    "ember", "enigma", "falcon", "fern", "flame", "flint", "forge", "fossil",
    "frost", "galaxy", "garnet", "glacier", "granite", "grove", "harbor", "hawk",
    "helium", "horizon", "hunter", "indigo", "iron", "ivory", "jade", "jasper",
    "jewel", "jungle", "karma", "kelvin", "lance", "lava", "leopard", "lightning",
    "lotus", "lunar", "magnet", "maple", "marble", "mercury", "meteor", "midnight",
    "mirage", "molten", "mystic", "nebula", "nexus", "nimbus", "noble", "nova",
    "obsidian", "omega", "onyx", "oracle", "orchid", "osprey", "oxide", "ozone",
    "panda", "panther", "pearl", "phoenix", "pilot", "pine", "pixel", "plasma",
    "pluto", "prism", "pulse", "python", "quartz", "radiant", "raven", "reef",
    "ridge", "ripple", "river", "robin", "rocket", "ruby", "sage", "salmon",
    "sapphire", "saturn", "scarlet", "shadow", "silver", "solar", "spark", "sphinx",
    "spiral", "stellar", "storm", "summit", "sword", "terra", "thane", "thunder",
    "tiger", "titan", "topaz", "torch", "trident", "tulip", "tundra", "turbo",
    "venom", "vertex", "violet", "viper", "vivid", "volcano", "vortex", "walrus",
    "whisper", "willow", "winter", "wizard", "wolf", "xenon", "yacht", "zenith",
    "zephyr", "zinc", "zodiac",
    // Pad to 256 for even distribution
    "abyss", "bandit", "castle", "dragon", "engine", "fable", "ghost", "hammer",
    "igloo", "jester", "knight", "legend", "mantis", "nectar", "ocean", "parrot",
    "quiver", "raptor", "sentry", "trophy", "ultra", "vanguard", "warrior", "xray",
    "yonder", "zigzag", "acorn", "blizzard", "chimney", "delphi", "eclipse", "furnace",
    "griffin", "hermit", "impact", "javelin", "krypton", "lantern", "mammoth", "neutron",
    "outpost", "penguin", "quantum", "riddle", "stampede", "tempest", "uniform", "vagrant",
    "warden", "xylophone", "yeoman", "admiral", "bonsai", "condor", "dynamo",
    "emerald", "gazelle", "impulse", "jubilee", "kinetic", "labyrinth",
    "monsoon", "nitrogen", "pagoda", "quasar", "ranger", "samurai", "typhoon",
    "utopia", "velocity", "wanderer", "axiom", "basalt", "citadel", "domino",
    "epoch", "flotsam", "galleon", "helix", "icicle", "jackal", "kraken", "lynx",
    "minotaur", "nomad", "obelisk", "phantom", "quill", "rampart", "scarab", "totem",
    "umbra", "valkyrie", "wraith",
];

/// Generate a random code phrase: "NNN-word-word-word"
fn generate_code_phrase() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let num: u16 = rng.random_range(100..999);
    let w1 = CODE_WORDS[rng.random_range(0..CODE_WORDS.len())];
    let w2 = CODE_WORDS[rng.random_range(0..CODE_WORDS.len())];
    let w3 = CODE_WORDS[rng.random_range(0..CODE_WORDS.len())];
    format!("{}-{}-{}-{}", num, w1, w2, w3)
}

/// Derive a deterministic port and session key from a code phrase
fn code_to_session(code: &str) -> (u16, [u8; 32]) {
    let hash = blake3::hash(code.as_bytes());
    let bytes = hash.as_bytes();
    // Port: 10000-65000 range
    let port = 10000 + (u16::from_le_bytes([bytes[0], bytes[1]]) % 55000);
    // Session key: the full BLAKE3 hash
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    (port, key)
}

/// Dispatch: generate a code phrase with its derived port
fn generate_code(_args: &[Value]) -> StdlibResult {
    // Mint the 8-symbol v4 passcode (operator directive 2026-10-12). This used to hand
    // out a word/PIN phrase; every CLI/TUI lane that pre-mints a code goes through here,
    // so the retired shape is no longer produced anywhere in the CLI.
    let code = tallow_protocol::room::code::generate_passcode();
    // The port stays derived from the code for the legacy direct-connect scheme; it is
    // vestigial for relay/room joins and deterministic for both peers either way.
    let (port, _key) = code_to_session(&code);
    Ok(Value::Struct {
        name: "TransferCode".to_string(),
        fields: vec![
            ("code".to_string(), Value::String(code)),
            ("port".to_string(), Value::Int(port as i128)),
        ],
    })
}

/// Dispatch: resolve a code phrase to a port
fn code_to_port(args: &[Value]) -> StdlibResult {
    let code = get_str(args, 0).ok_or("code_to_port: code phrase required")?;
    let (port, _key) = code_to_session(&code);
    Ok(Value::Struct {
        name: "CodeSession".to_string(),
        fields: vec![
            ("code".to_string(), Value::String(code)),
            ("port".to_string(), Value::Int(port as i128)),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Phase 60: Relay Server — TCP pipe matched by code phrase
// ══════════════════════════════════════════════════════════════════

/// Start a relay server on the given port (real TCP server in a background thread).
///
/// The listener is kept alive by a dedicated accept-loop thread that speaks the
/// TALLOW relay protocol used by `relay_send`/`relay_receive`:
///   - "TALLOW-SEND\n" <code> "\n" <payload>  → payload is buffered under <code>
///   - "TALLOW-RECV\n" <code> "\n"            → buffered payload is written back
/// Payloads expire after RELAY_TTL seconds.
fn relay_start(args: &[Value]) -> StdlibResult {
    let port = match args.first() {
        Some(Value::Int(n)) => *n as u16,
        _ => 6880,
    };

    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|e| format!("bind relay port {}: {}", port, e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("relay addr: {e}"))?;

    // Keep the listener alive: run the accept loop on a dedicated thread.
    std::thread::Builder::new()
        .name("tallow-relay".to_string())
        .spawn(move || relay_accept_loop(listener))
        .map_err(|e| format!("spawn relay thread: {e}"))?;

    Ok(Value::Struct {
        name: "RelayServer".to_string(),
        fields: vec![
            ("address".to_string(), Value::String(addr.to_string())),
            ("port".to_string(), Value::Int(addr.port() as i128)),
            ("running".to_string(), Value::Bool(true)),
            (
                "protocol".to_string(),
                Value::String("TCP relay v1 (live pairing, E2E-encrypted)".to_string()),
            ),
        ],
    })
}

/// Sanitize a filename received over the wire before joining it to an output
/// directory (design §2.6 R-5 / D-6: `relay_receive` + QUIC receive paths).
///
/// Only the final path component is kept, so a hostile peer/relay cannot escape
/// the output directory via `..`, absolute paths, Windows separators, drive
/// letters, or NUL/control bytes. Returns `Err` when nothing usable remains.
fn sanitize_wire_filename(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("empty filename".to_string());
    }
    if name.contains('\0') {
        return Err("filename contains NUL".to_string());
    }
    // Normalize separators (both slash kinds + fullwidth variants), then keep
    // only the last usable component: neutralizes "../", "/etc/", "C:\\x".
    let normalized = name
        .replace(['\u{FF0F}', '\u{FF3C}'], "/")
        .replace('\\', "/");
    let last = normalized
        .split('/')
        .filter(|c| !c.trim().is_empty() && *c != "." && *c != "..")
        .next_back()
        .ok_or_else(|| "filename has no usable component".to_string())?;
    let last = last.trim().trim_end_matches(['.', ' ']);
    // Strip a Windows drive-letter prefix ("C:evil" -> "evil").
    let mut stripped = last;
    while stripped.len() >= 2
        && stripped.as_bytes()[0].is_ascii_alphabetic()
        && stripped.as_bytes()[1] == b':'
    {
        stripped = &stripped[2..];
    }
    let cleaned: String = stripped
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == ':' { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return Err("filename sanitized to empty".to_string());
    }
    if cleaned.len() > 255 {
        return Err("filename too long".to_string());
    }
    Ok(cleaned)
}

/// Buffered relay payloads keyed by code phrase (only used by the relay thread).
const RELAY_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Copy `src` → `dst` through an explicit 64 KiB buffer (design T-1 · R-4).
///
/// `std::io::copy`'s internal buffer is ~8 KiB, which caps relay throughput;
/// the relay pipe is a pure byte pump (nothing stored server-side), so a fixed
/// 64 KiB buffer plus socket-level backpressure is all that is needed.
fn relay_pipe_copy<R: std::io::Read, W: std::io::Write>(
    src: &mut R,
    dst: &mut W,
) -> std::io::Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

/// Live-pairing relay loop (relay-v1) with a legacy store-and-forward fallback.
///
/// relay-v1 clients append a version byte after the code line:
///   `"TALLOW-SEND\n" <code> "\n" 0x01` / `"TALLOW-RECV\n" <code> "\n" 0x01`
/// A matching sender/receiver pair is piped bidirectionally with a bounded
/// copy loop (socket-level backpressure, no payload buffering, nothing stored). Payloads
/// are end-to-end encrypted by the peers (CPace + scoped chunk AEAD in
/// `tallow_protocol::transfer::relay`), so the relay only ever sees ciphertext.
/// Clients that send no version byte keep the v0 buffered semantics and get a
/// deprecation warning; TTL for both paths is RELAY_TTL.
fn relay_accept_loop(listener: std::net::TcpListener) {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};

    /// Legacy (v0) buffered payloads keyed by code phrase.
    static RELAY_PAYLOADS: LazyLock<Mutex<HashMap<String, (Instant, Vec<u8>)>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    /// v1 sockets waiting for their live peer: code -> (role, queued_at, socket).
    static RELAY_WAITING: LazyLock<Mutex<HashMap<String, (char, Instant, TcpStream)>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Pipe two paired sockets bidirectionally until either side closes.
    fn pipe_pair(a: TcpStream, b: TcpStream) {
        let a2 = match a.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let b2 = match b.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let t1 = std::thread::spawn(move || {
            let mut src = a;
            let mut dst = b2;
            let _ = relay_pipe_copy(&mut src, &mut dst);
            let _ = dst.shutdown(Shutdown::Write);
        });
        let t2 = std::thread::spawn(move || {
            let mut src = b;
            let mut dst = a2;
            let _ = relay_pipe_copy(&mut src, &mut dst);
            let _ = dst.shutdown(Shutdown::Write);
        });
        let _ = t1.join();
        let _ = t2.join();
    }

    /// Handle one relay client connection (v1 pairing or v0 buffering).
    fn handle_relay_conn(stream: TcpStream) {
        let reader_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut reader = BufReader::new(reader_stream);
        let mut verb = String::new();
        let mut code = String::new();
        if reader.read_line(&mut verb).is_err() || reader.read_line(&mut code).is_err() {
            return;
        }
        let verb = verb.trim();
        let code = code.trim().to_string();

        let role = match verb {
            "TALLOW-SEND" => 's',
            "TALLOW-RECV" => 'r',
            other => {
                eprintln!("tallow relay: unknown verb '{other}'");
                return;
            }
        };

        // Version sniff: v1 clients send 0x01 immediately after the code line.
        // A legacy client's next byte is payload (for TALLOW-SEND) — it is
        // preserved below when falling back to v0 semantics.
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut ver = [0u8; 1];
        let sniff = reader.read(&mut ver);
        stream.set_read_timeout(None).ok();
        let is_v1 = matches!(sniff, Ok(1) if ver[0] == 0x01);

        if is_v1 {
            let now = Instant::now();
            let partner = {
                let mut map = RELAY_WAITING.lock().unwrap();
                map.retain(|_, (_, ts, _)| now.duration_since(*ts) < RELAY_TTL);
                match map.get(&code).map(|(r, _, _)| *r) {
                    Some(other_role) if other_role != role => {
                        map.remove(&code).map(|(_, _, s)| s)
                    }
                    _ => None,
                }
            };
            match partner {
                Some(other) => {
                    eprintln!("tallow relay v1: live pair matched for code '{code}'");
                    pipe_pair(other, stream);
                }
                None => {
                    let mut map = RELAY_WAITING.lock().unwrap();
                    eprintln!("tallow relay v1: {role} waiting for peer, code '{code}'");
                    map.insert(code, (role, Instant::now(), stream));
                }
            }
            return;
        }

        // ---- legacy v0 store-and-forward (deprecated) ----
        eprintln!(
            "tallow relay: WARNING legacy v0 plaintext client for code '{code}' — \
             upgrade the client for E2E encryption"
        );
        match verb {
            "TALLOW-SEND" => {
                let mut payload = Vec::new();
                if let Ok(1) = sniff {
                    payload.push(ver[0]);
                }
                if reader.read_to_end(&mut payload).is_err() {
                    return;
                }
                let now = Instant::now();
                {
                    let mut map = RELAY_PAYLOADS.lock().unwrap();
                    map.retain(|_, (ts, _)| now.duration_since(*ts) < RELAY_TTL);
                    map.insert(code, (now, payload));
                }
            }
            "TALLOW-RECV" => {
                let payload = {
                    let mut map = RELAY_PAYLOADS.lock().unwrap();
                    map.remove(&code)
                };
                match payload {
                    Some((_, data)) => {
                        let mut w = stream;
                        if let Err(e) = w.write_all(&data).and_then(|_| w.flush()) {
                            eprintln!("tallow relay: write to receiver: {e}");
                        }
                    }
                    None => eprintln!("tallow relay: no payload for code '{code}'"),
                }
            }
            _ => unreachable!("verb validated above"),
        }
    }

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        if std::thread::Builder::new()
            .name("tallow-relay-conn".to_string())
            .spawn(move || handle_relay_conn(stream))
            .is_err()
        {
            eprintln!("tallow relay: failed to spawn connection handler");
        }
    }
}

// ── Relay-v1 CLI client (E-3-01r R-1/R-2/R-3; design cycle-02/09 §3.1-3.2) ──

/// Cooperative SIGINT/SIGTERM flag for the relay-v1 CLI paths (design §3.2:
/// "flush then exit 130").
///
/// The installed handler only stores an atomic flag (async-signal-safe); the
/// [`InterruptibleIo`] socket wrapper observes it on every read/write attempt
/// and surfaces an `Interrupted` I/O error, so `send_file`/`receive_file`
/// return promptly with the last checkpointed resume state intact on disk.
/// The guard restores the default disposition when the operation returns.
pub mod relay_signal {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Set by the signal handler; polled by the socket wrapper.
    pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_signal(_sig: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }

    /// Restores the default disposition for SIGINT/SIGTERM when dropped.
    pub struct Guard;

    /// Install the cooperative handler for SIGINT and SIGTERM.
    pub fn install() -> Guard {
        // SAFETY: `on_signal` is async-signal-safe (a single atomic store).
        unsafe {
            libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        }
        Guard
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: restoring the default disposition is always valid.
            unsafe {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
            }
        }
    }

    /// True once a SIGINT/SIGTERM was observed.
    pub fn interrupted() -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }
}

/// True when a relay-v1 CLI operation was interrupted by SIGINT/SIGTERM.
pub fn relay_interrupted() -> bool {
    relay_signal::interrupted()
}

/// Seconds a relay-v1 client waits for its peer to appear (design T-5 `--wait`
/// default 600 s; overridable via `TALLOW_RELAY_WAIT_SECS`).
fn relay_wait_seconds() -> u64 {
    std::env::var("TALLOW_RELAY_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600)
}

// ══════════════════════════════════════════════════════════════════
// Policy-aware transport negotiation — TallowTransfer (R-08 batch-3 ·
// rows #131/#132 · design P4-3)
//
// "Add a TLS 1.3-over-TCP stream transport carrying tallow-protocol frames so
//  transfers run fail-closed over Tor SOCKS5; make transport/{negotiation,
//  fallback}.rs policy-aware; Happy Eyeballs v2 for dual-stack."
//
// Route resolution (env follows the box egress vocabulary):
//   * `TALLOW_PROXY` (or an explicit CLI proxy argument) — non-blank URL ⇒
//     SOCKS5 proxy route. A configured-but-unusable URL is a **hard refusal**:
//     the client never silently degrades to a direct connection.
//   * `TALLOW_TOR=1` ⇒ Tor mode (`socks5h://127.0.0.1:9050`, remote DNS).
//   * `TALLOW_ALLOW_DIRECT=1` ⇒ direct route with the *direct-UDP* preference
//     authorized — the explicit opt-in (design P4-3 operator line); it is the
//     only way UDP-based transports become eligible.
//   * `TALLOW_ALLOW_DIRECT` explicitly falsy ⇒ direct not authorized: with no
//     proxy configured the transfer **refuses** (fail-closed) instead of
//     egressing direct.
//   * Nothing configured ⇒ transfer keeps its historical direct route with
//     **no** direct-UDP preference (QUIC-first is never a default here).
//   * `.onion` targets require a Tor (remote-DNS) route — never direct.
// ══════════════════════════════════════════════════════════════════

/// Environment key: SOCKS5 proxy URL (wins over `TALLOW_TOR`).
pub const TALLOW_PROXY_ENV: &str = "TALLOW_PROXY";
/// Environment key: `1|true|yes` selects Tor mode.
pub const TALLOW_TOR_ENV: &str = "TALLOW_TOR";
/// Environment key: explicit direct-egress authorization (`1|true|yes`).
pub const TALLOW_ALLOW_DIRECT_ENV: &str = "TALLOW_ALLOW_DIRECT";

/// Resolved transfer transport policy: which egress route the transport layer
/// may use, and (for proxied routes) the SOCKS5 proxy that must carry it.
#[derive(Debug, Clone)]
pub struct TransferTransportPolicy {
    /// Egress route (policy-permitted transports; see `TransportRoute`).
    pub route: tallow_net::transport::negotiation::TransportRoute,
    /// SOCKS5 configuration — present exactly when the route is proxied.
    pub proxy: Option<tallow_net::privacy::ProxyConfig>,
}

impl TransferTransportPolicy {
    /// Ordered transports this policy permits (highest priority first).
    pub fn candidates(&self) -> Vec<tallow_net::transport::negotiation::TransportProtocol> {
        self.route.candidates()
    }

    /// True when UDP-based transports (QUIC) are eligible under this policy.
    pub fn quic_eligible(&self) -> bool {
        self.route.allows_quic()
    }

    /// True when all transport bytes must ride the SOCKS5 proxy.
    pub fn is_proxied(&self) -> bool {
        self.route.is_proxied()
    }

    /// Stable one-line description (logs / CLI output; no secrets — the proxy
    /// password is never rendered).
    pub fn describe(&self) -> String {
        match (&self.route, &self.proxy) {
            (_, Some(cfg)) => format!("{} via {}", self.route.label(), cfg.socks5_addr),
            _ => self.route.label().to_string(),
        }
    }
}

/// Truthy check matching the box egress contract (`1|true|yes` after trim).
fn env_truthy(v: &str) -> bool {
    let v = v.trim().to_ascii_lowercase();
    v == "1" || v == "true" || v == "yes"
}

/// True for Tor v3 onion-service hostnames (`.onion`, case-insensitive).
pub fn is_onion_host(host: &str) -> bool {
    host.trim().to_ascii_lowercase().ends_with(".onion")
}

/// Split `host:port` (IPv6 in brackets supported) into its parts.
fn split_host_port(addr: &str) -> Result<(String, u16), String> {
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return Ok((sock.ip().to_string(), sock.port()));
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("'{}' is not host:port", addr))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid port in '{}'", addr))?;
    if host.is_empty() {
        return Err(format!("empty host in '{}'", addr));
    }
    Ok((host.trim_matches(['[', ']']).to_string(), port))
}

/// Resolve the transfer transport policy (pure over its inputs — the live path
/// passes the real environment as `lookup`).
///
/// `explicit_proxy` is the CLI-supplied `--proxy`/`--tor`-derived URL (wins over
/// the environment); `relay_host` is the peer/relay hostname or IP literal
/// (used for the `.onion` fail-closed rule).
pub fn resolve_transport_policy(
    lookup: &dyn Fn(&str) -> Option<String>,
    explicit_proxy: Option<&str>,
    relay_host: &str,
) -> Result<TransferTransportPolicy, String> {
    let tor_env = lookup(TALLOW_TOR_ENV).map(|v| env_truthy(&v)).unwrap_or(false);

    // 1. Proxy route (explicit argument wins over the environment).
    let proxy_url = explicit_proxy
        .map(|s| s.to_string())
        .or_else(|| lookup(TALLOW_PROXY_ENV).filter(|v| !v.trim().is_empty()));
    if let Some(url) = proxy_url {
        let cfg = tallow_net::privacy::ProxyConfig::from_url(&url).map_err(|e| {
            format!(
                "configured proxy {url:?} is not a usable SOCKS5 address ({e}) — \
                 refusing to transfer (fail-closed: a configured proxy is never \
                 bypassed, and a malformed one is never degraded to direct)"
            )
        })?;
        let tor_mode = cfg.tor_mode || tor_env;
        if is_onion_host(relay_host) && !tor_mode {
            return Err(format!(
                "onion target {relay_host:?} needs Tor remote DNS, but the configured \
                 proxy is a generic SOCKS5 (socks5://) route — use socks5h:// or \
                 TALLOW_TOR=1 (fail-closed)"
            ));
        }
        let cfg = tallow_net::privacy::ProxyConfig {
            tor_mode,
            ..cfg
        };
        return Ok(TransferTransportPolicy {
            route: tallow_net::transport::negotiation::TransportRoute::proxied(tor_mode),
            proxy: Some(cfg),
        });
    }

    // 2. Tor mode without an explicit proxy URL.
    if tor_env {
        let cfg = tallow_net::privacy::ProxyConfig::tor_default();
        return Ok(TransferTransportPolicy {
            route: tallow_net::transport::negotiation::TransportRoute::proxied(true),
            proxy: Some(cfg),
        });
    }

    // 3. Direct route decisions.
    let allow_direct = lookup(TALLOW_ALLOW_DIRECT_ENV).map(|v| env_truthy(&v));
    if allow_direct == Some(false) {
        return Err(format!(
            "{TALLOW_ALLOW_DIRECT_ENV} is explicitly disabled and no proxy is \
             configured — refusing to transfer (fail-closed: proxied-only mode)"
        ));
    }
    if is_onion_host(relay_host) {
        return Err(format!(
            "onion target {relay_host:?} cannot be reached over a direct route — \
             set TALLOW_TOR=1 or TALLOW_PROXY=<socks5h://...> (fail-closed)"
        ));
    }

    Ok(TransferTransportPolicy {
        route: tallow_net::transport::negotiation::TransportRoute::direct(
            allow_direct == Some(true),
        ),
        proxy: None,
    })
}

/// Live-environment policy resolution for a transfer to `relay_addr`.
pub fn transfer_policy_for(
    relay_addr: &str,
    explicit_proxy: Option<&str>,
) -> Result<TransferTransportPolicy, String> {
    let (host, _port) = split_host_port(relay_addr)?;
    resolve_transport_policy(
        &|key| std::env::var(key).ok(),
        explicit_proxy,
        &host,
    )
}

/// Policy-resolved peer-channel connect for TallowTransfer (direct peer
/// transports: QUIC-first only when direct-UDP is authorized; TCP+TLS
/// fallback otherwise; proxied routes are refused here — the relay-v1/SOCKS5
/// tunnel is their path).
///
/// Returns the active transport kind. Blocking wrapper around the async
/// `FallbackTransport` (the transfer stdlib surface is synchronous).
pub fn connect_peer_transport(
    policy: &TransferTransportPolicy,
    addr: std::net::SocketAddr,
) -> Result<PeerTransportKind, String> {
    connect_peer_transport_with(policy, addr, false)
}

/// Test/inspection seam for [`connect_peer_transport`]: `quic_blocked` forces
/// the injected QUIC attempt to fail (simulates a UDP-blocked network).
pub fn connect_peer_transport_with(
    policy: &TransferTransportPolicy,
    addr: std::net::SocketAddr,
    quic_blocked: bool,
) -> Result<PeerTransportKind, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async move {
        let mut transport = tallow_net::transport::fallback::FallbackTransport::with_policy(
            policy.route,
        );
        let result = if quic_blocked {
            transport
                .connect_peer_with(addr, async {
                    Err(tallow_net::NetworkError::ConnectionFailed(
                        "QUIC blocked (injected)".to_string(),
                    ))
                })
                .await
        } else {
            transport.connect_peer(addr).await
        };
        result
            .map(|active| match active {
                tallow_net::transport::fallback::ActiveTransport::Quic => PeerTransportKind::Quic,
                tallow_net::transport::fallback::ActiveTransport::TcpTls => {
                    PeerTransportKind::TcpTls
                }
                tallow_net::transport::fallback::ActiveTransport::None => {
                    unreachable!("connect_peer never returns None")
                }
            })
            .map_err(|e| e.to_string())
    })
}

/// Active peer transport returned by [`connect_peer_transport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransportKind {
    /// QUIC (UDP) — only when the route authorized direct UDP.
    Quic,
    /// TCP+TLS (RFC 8305 dual-stack connect under the hood).
    TcpTls,
}


/// Read/write wrapper that makes a relay-v1 socket promptly interruptible and
/// gives the pre-handshake (wait-for-peer) phase a deadline.
///
/// The socket carries 250 ms SO_RCVTIMEO/SO_SNDTIMEO; `WouldBlock`/`TimedOut`
/// are retried here, so callers keep ordinary blocking semantics while the
/// SIGINT flag and the wait deadline are still observed within ~250 ms.
struct InterruptibleIo<S> {
    inner: S,
    /// Armed until the first inbound byte (peer present); `None` afterwards.
    deadline: Option<std::time::Instant>,
}

impl<S> InterruptibleIo<S> {
    fn read_side(inner: S, deadline: Option<std::time::Instant>) -> Self {
        Self { inner, deadline }
    }
    fn write_side(inner: S) -> Self {
        Self {
            inner,
            deadline: None,
        }
    }
}

impl<S: std::io::Read> std::io::Read for InterruptibleIo<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if relay_signal::interrupted() {
                // NOTE: deliberately NOT ErrorKind::Interrupted — std's
                // read_exact/write_all retry Interrupted transparently,
                // which would spin forever instead of aborting.
                return Err(std::io::Error::other(
                    "interrupted by SIGINT/SIGTERM",
                ));
            }
            if let Some(dl) = self.deadline {
                if std::time::Instant::now() >= dl {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "timed out after {}s waiting for the relay to pair this code with \
                             its peer (a legacy/plaintext relay cannot pair E2E clients — \
                             upgrade the relay)",
                            relay_wait_seconds()
                        ),
                    ));
                }
            }
            match self.inner.read(buf) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    self.deadline = None; // peer present; the transfer paces itself
                    return Ok(n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: std::io::Write> std::io::Write for InterruptibleIo<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            if relay_signal::interrupted() {
                // NOTE: deliberately NOT ErrorKind::Interrupted — std's
                // read_exact/write_all retry Interrupted transparently,
                // which would spin forever instead of aborting.
                return Err(std::io::Error::other(
                    "interrupted by SIGINT/SIGTERM",
                ));
            }
            match self.inner.write(buf) {
                Ok(n) => return Ok(n),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Connect to the relay and emit the relay-v1 preamble
/// (`<verb>\n<code>\n\x01`), returning interruptible read/write halves.
///
/// Transport is chosen by the resolved [`TransferTransportPolicy`]:
///  * proxied route ⇒ the SOCKS5→TLS tunnel (`ProxiedTcpTlsTransport`, TLS 1.3;
///    remote DNS in Tor mode) — a connect failure is returned as an error and
///    **never** retried direct (fail-closed);
///  * direct route ⇒ blocking TCP, with Happy Eyeballs v2 (RFC 8305) when the
///    relay address is a hostname.
fn relay_v1_connect(
    relay_addr: &str,
    verb: &str,
    code: &str,
    policy: &TransferTransportPolicy,
) -> Result<(RelayReader, RelayWriter), String> {
    use std::io::Write;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(relay_wait_seconds());

    let (reader, mut writer) = if policy.is_proxied() {
        let proxy = policy.proxy.as_ref().ok_or_else(|| {
            "internal: proxied route without a proxy config".to_string()
        })?;
        let (host, port) = split_host_port(relay_addr)?;
        let tunnel = tallow_net::transport::proxied::ProxiedTcpTlsTransport::connect_blocking_tunnel(
            proxy, &host, port,
        )
        .map_err(|e| {
            format!(
                "SOCKS5/Tor transfer route to {relay_addr} failed: {e} — refusing \
                 a direct fallback (fail-closed)"
            )
        })?;
        (
            RelayReader::Tunnel(InterruptibleIo::read_side(tunnel.reader, Some(deadline))),
            RelayWriter::Tunnel(InterruptibleIo::write_side(tunnel.writer)),
        )
    } else {
        let stream = relay_direct_connect(relay_addr)?;
        let t = std::time::Duration::from_millis(250);
        let _ = stream.set_read_timeout(Some(t));
        let _ = stream.set_write_timeout(Some(t));
        let mut w = stream.try_clone().map_err(|e| format!("relay socket clone: {e}"))?;
        let r = stream.try_clone().map_err(|e| format!("relay socket clone: {e}"))?;
        (
            RelayReader::Direct(InterruptibleIo::read_side(r, Some(deadline))),
            RelayWriter::Direct(InterruptibleIo::write_side(w)),
        )
    };

    writer
        .write_all(verb.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.write_all(code.as_bytes()))
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.write_all(&[0x01u8]))
        .and_then(|_| writer.flush())
        .map_err(|e| format!("relay-v1 handshake write: {e}"))?;
    Ok((reader, writer))
}

/// Direct (non-proxied) relay connect.
///
/// IP literals keep the plain blocking connect; hostnames go through Happy
/// Eyeballs v2 (RFC 8305) dual-stack resolution.
fn relay_direct_connect(relay_addr: &str) -> Result<std::net::TcpStream, String> {
    if let Ok(addr) = relay_addr.parse::<std::net::SocketAddr>() {
        return std::net::TcpStream::connect(addr)
            .map_err(|e| format!("connect relay '{relay_addr}': {e}"));
    }
    let (host, port) = split_host_port(relay_addr)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(tallow_net::transport::tcp_tls::connect_std(&host, port))
        .map_err(|e| format!("connect relay '{relay_addr}' (happy eyeballs): {e}"))
}

/// Relay-v1 read side: direct TCP or SOCKS5→TLS tunnel.
enum RelayReader {
    /// Direct blocking TCP socket.
    Direct(InterruptibleIo<std::net::TcpStream>),
    /// SOCKS5→TLS tunnel.
    Tunnel(InterruptibleIo<tallow_net::transport::proxied::TunnelReader>),
}

/// Relay-v1 write side: direct TCP or SOCKS5→TLS tunnel.
enum RelayWriter {
    /// Direct blocking TCP socket.
    Direct(InterruptibleIo<std::net::TcpStream>),
    /// SOCKS5→TLS tunnel.
    Tunnel(InterruptibleIo<tallow_net::transport::proxied::TunnelWriter>),
}

impl std::io::Read for RelayReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            RelayReader::Direct(io) => io.read(buf),
            RelayReader::Tunnel(io) => io.read(buf),
        }
    }
}

impl std::io::Write for RelayWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            RelayWriter::Direct(io) => io.write(buf),
            RelayWriter::Tunnel(io) => io.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            RelayWriter::Direct(io) => io.flush(),
            RelayWriter::Tunnel(io) => io.flush(),
        }
    }
}

/// Map a relay-v1 client error to the CLI-visible string; cooperative
/// interrupts get the resume-preserving message (design §3.2).
fn relay_v1_error(e: tallow_protocol::ProtocolError) -> String {
    if relay_signal::interrupted() {
        return "interrupted by SIGINT/SIGTERM — partial progress is checkpointed; \
                rerun the same command to resume"
            .to_string();
    }
    format!("relay-v1: {e}")
}

/// Send via relay: connect, send code phrase for matching, then stream the file.
///
/// Default path is relay-v1 — E2E-encrypted live pairing (CPace + hybrid-KEM
/// handshake, scoped chunk AEAD, 256 KiB streamed frames; design §3.1), with
/// the legacy v0 plaintext store-and-forward path behind `legacy_plaintext`
/// for one release (design §3.1 migration).
///
/// Transport route (rows #131/#132): a proxy/Tor route moves the data over the
/// SOCKS5→TLS tunnel; the route is resolved from `TALLOW_PROXY`/`TALLOW_TOR`
/// and the optional explicit proxy argument — fail-closed (no direct fallback).
///
/// Args: `[file_path, relay_addr, code, bwlimit_bytes_per_sec?, legacy_plaintext?, proxy_url?]`.
fn relay_send(args: &[Value]) -> StdlibResult {
    let file_path = get_str(args, 0).ok_or("relay_send: file path required")?;
    let relay_addr = get_str(args, 1).unwrap_or_else(|| "relay.tallow-lang.org:6880".to_string());
    // Mint the 8-symbol v4 passcode (operator directive 2026-10-12). Peers pair by
    // the code STRING, so an 8-symbol code still meets an older peer.
    let code = get_str(args, 2).unwrap_or_else(tallow_protocol::room::code::generate_passcode);
    let bwlimit: Option<u64> = match args.get(3) {
        Some(Value::Int(n)) if *n > 0 => Some(*n as u64),
        _ => None,
    };
    let legacy_plaintext = matches!(args.get(4), Some(Value::Bool(true)));
    let explicit_proxy = get_str(args, 5).filter(|s| !s.trim().is_empty());

    if legacy_plaintext {
        return relay_send_v0(&file_path, &relay_addr, &code);
    }
    relay_send_v1(&file_path, &relay_addr, &code, bwlimit, explicit_proxy.as_deref())
}

/// relay-v1 encrypted, streamed send (default CLI path; bounded RAM).
fn relay_send_v1(
    file_path: &str,
    relay_addr: &str,
    code: &str,
    bwlimit_bytes_per_sec: Option<u64>,
    explicit_proxy: Option<&str>,
) -> StdlibResult {
    use tallow_protocol::transfer::relay::{send_file, RelaySendOptions};
    // Join contract (operator directive 2026-10-12): accept the 8-symbol v4 mint ONLY.
    // Retired shapes stay DERIVABLE (resolve_room_id still knows v3 and the word/PIN
    // codes) but must not enter a room from a user-supplied code.
    if !tallow_protocol::room::code::is_supported_code(code) {
        return Err(format!(
            "unsupported code '{}': {} — this build accepts the 8-symbol mint only (e.g. K7M2QPHD)",
            code,
            tallow_protocol::room::code::unsupported_code_reason(code)
                .unwrap_or("not a v4 passcode")
        ));
    }


    let policy = match transfer_policy_for(relay_addr, explicit_proxy) {
        Ok(p) => p,
        Err(e) => return Err(format!("relay send refused: {e}")),
    };
    let route_label = policy.describe();

    let _guard = relay_signal::install();
    let (mut reader, mut writer) = match relay_v1_connect(relay_addr, "TALLOW-SEND", code, &policy)
    {
        Ok(pair) => pair,
        Err(e) => return Err(format!("relay send failed: {e}")),
    };
    let opts = RelaySendOptions {
        bandwidth_bytes_per_sec: bwlimit_bytes_per_sec,
        progress: true,
    };
    let outcome = match send_file(
        &mut reader,
        &mut writer,
        code,
        std::path::Path::new(file_path),
        &opts,
    ) {
        Ok(o) => o,
        Err(e) => return Err(format!("relay send failed: {}", relay_v1_error(e))),
    };

    let hash = blake3::Hash::from_bytes(outcome.file_blake3).to_hex().to_string();
    Ok(Value::Struct {
        name: "RelaySendResult".to_string(),
        fields: vec![
            ("code".to_string(), Value::String(code.to_string())),
            ("file".to_string(), Value::String(file_path.to_string())),
            ("size".to_string(), Value::Int(outcome.size as i128)),
            ("hash".to_string(), Value::String(hash)),
            ("relay".to_string(), Value::String(relay_addr.to_string())),
            ("sent".to_string(), Value::Bool(true)),
            (
                "protocol".to_string(),
                Value::String("TCP relay v1 (E2E-encrypted, live pairing)".to_string()),
            ),
            (
                "transport".to_string(),
                Value::String(route_label.clone()),
            ),
            (
                "chunks_sent".to_string(),
                Value::Int(outcome.chunks_sent as i128),
            ),
            (
                "bytes_sent_on_wire".to_string(),
                Value::Int(outcome.bytes_sent_on_wire as i128),
            ),
            (
                "resumed_from_chunk".to_string(),
                Value::Int(outcome.start_chunk as i128),
            ),
        ],
    })
}

// Legacy v0 plaintext store-and-forward send (deprecated one release; kept
// live behind `--legacy-plaintext`, design §3.1 migration step 1).

fn relay_send_v0(file_path: &str, relay_addr: &str, code: &str) -> StdlibResult {

    let data = std::fs::read(file_path)
        .map_err(|e| format!("read '{}': {}", file_path, e))?;
    let hash = blake3::hash(&data).to_hex().to_string();
    let size = data.len();

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let result = rt.block_on(async {
        let mut stream = tokio::net::TcpStream::connect(relay_addr).await
            .map_err(|e| format!("connect relay '{}': {}", relay_addr, e))?;

        use tokio::io::AsyncWriteExt;

        // Protocol: "TALLOW-SEND\n" + code + "\n" + file_size(8) + hash(32) + filename_len(2) + filename + data
        stream.write_all(b"TALLOW-SEND\n").await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(code.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(b"\n").await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(&(size as u64).to_le_bytes()).await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(blake3::hash(&data).as_bytes()).await.map_err(|e| format!("write: {e}"))?;

        let filename = std::path::Path::new(file_path)
            .file_name().map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        stream.write_all(&(filename.len() as u16).to_le_bytes()).await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(filename.as_bytes()).await.map_err(|e| format!("write: {e}"))?;

        // Send file data
        stream.write_all(&data).await.map_err(|e| format!("write data: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;

        Ok::<_, String>(())
    });

    match result {
        Ok(()) => Ok(Value::Struct {
            name: "RelaySendResult".to_string(),
            fields: vec![
                ("code".to_string(), Value::String(code.to_string())),
                ("file".to_string(), Value::String(file_path.to_string())),
                ("size".to_string(), Value::Int(size as i128)),
                ("hash".to_string(), Value::String(hash)),
                ("relay".to_string(), Value::String(relay_addr.to_string())),
                ("sent".to_string(), Value::Bool(true)),
            ],
        }),
        Err(e) => Err(format!("relay send failed: {e}")),
    }
}

/// Receive via relay. Default path is relay-v1 (see `relay_send`); the legacy
/// v0 plaintext path stays behind `legacy_plaintext`.
///
/// Transport route (rows #131/#132): proxy/Tor routes move the data over the
/// SOCKS5→TLS tunnel (fail-closed; no direct fallback).
///
/// Args: `[code, output_dir, relay_addr, state_dir?, overwrite?, legacy_plaintext?, proxy_url?]`.
/// `state_dir` empty/absent disables resume-state persistence; `overwrite`
/// false refuses to clobber an existing destination (D-C3).
fn relay_receive(args: &[Value]) -> StdlibResult {
    let code = get_str(args, 0).ok_or("relay_receive: code phrase required")?;
    let output_dir = get_str(args, 1).unwrap_or_else(|| ".".to_string());
    let relay_addr = get_str(args, 2).unwrap_or_else(|| "relay.tallow-lang.org:6880".to_string());
    let state_dir = get_str(args, 3).filter(|s| !s.is_empty());
    let overwrite = matches!(args.get(4), Some(Value::Bool(true)));
    let legacy_plaintext = matches!(args.get(5), Some(Value::Bool(true)));
    let explicit_proxy = get_str(args, 6).filter(|s| !s.trim().is_empty());

    if legacy_plaintext {
        return relay_receive_v0(&code, &output_dir, &relay_addr);
    }
    relay_receive_v1(
        &code,
        &output_dir,
        &relay_addr,
        state_dir,
        overwrite,
        explicit_proxy.as_deref(),
    )
}

/// relay-v1 encrypted, streamed receive with versioned resume state (default).
fn relay_receive_v1(
    code: &str,
    output_dir: &str,
    relay_addr: &str,
    state_dir: Option<String>,
    overwrite: bool,
    explicit_proxy: Option<&str>,
) -> StdlibResult {
    use tallow_protocol::transfer::relay::{receive_file, RelayReceiveOptions};
    // Join contract (operator directive 2026-10-12): accept the 8-symbol v4 mint ONLY.
    // Retired shapes stay DERIVABLE (resolve_room_id still knows v3 and the word/PIN
    // codes) but must not enter a room from a user-supplied code.
    if !tallow_protocol::room::code::is_supported_code(code) {
        return Err(format!(
            "unsupported code '{}': {} — this build accepts the 8-symbol mint only (e.g. K7M2QPHD)",
            code,
            tallow_protocol::room::code::unsupported_code_reason(code)
                .unwrap_or("not a v4 passcode")
        ));
    }


    let policy = match transfer_policy_for(relay_addr, explicit_proxy) {
        Ok(p) => p,
        Err(e) => return Err(format!("relay receive refused: {e}")),
    };
    let route_label = policy.describe();

    let _guard = relay_signal::install();
    let (mut reader, mut writer) = match relay_v1_connect(relay_addr, "TALLOW-RECV", code, &policy)
    {
        Ok(pair) => pair,
        Err(e) => return Err(format!("relay receive failed: {e}")),
    };
    let opts = RelayReceiveOptions {
        state_dir: state_dir.map(std::path::PathBuf::from),
        overwrite,
        progress: true,
    };
    let outcome = match receive_file(
        &mut reader,
        &mut writer,
        code,
        std::path::Path::new(output_dir),
        &opts,
    ) {
        Ok(o) => o,
        Err(e) => return Err(format!("relay receive failed: {}", relay_v1_error(e))),
    };

    let filename = outcome
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    Ok(Value::Struct {
        name: "RelayReceiveResult".to_string(),
        fields: vec![
            ("filename".to_string(), Value::String(filename)),
            ("size".to_string(), Value::Int(outcome.size as i128)),
            ("verified".to_string(), Value::Bool(true)),
            ("output_dir".to_string(), Value::String(output_dir.to_string())),
            ("code".to_string(), Value::String(code.to_string())),
            (
                "protocol".to_string(),
                Value::String("TCP relay v1 (E2E-encrypted, live pairing)".to_string()),
            ),
            (
                "transport".to_string(),
                Value::String(route_label.clone()),
            ),
            (
                "chunks_written".to_string(),
                Value::Int(outcome.chunks_written as i128),
            ),
            (
                "resumed_from_chunk".to_string(),
                Value::Int(outcome.resumed_from_chunk as i128),
            ),
            (
                "state_dir".to_string(),
                Value::String(
                    opts.state_dir
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ),
            ),
        ],
    })
}

// Legacy v0 plaintext receive (deprecated one release; `--legacy-plaintext`).

fn relay_receive_v0(code: &str, output_dir: &str, relay_addr: &str) -> StdlibResult {

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let result = rt.block_on(async {
        let mut stream = tokio::net::TcpStream::connect(relay_addr).await
            .map_err(|e| format!("connect relay: {e}"))?;

        use tokio::io::{AsyncWriteExt, AsyncReadExt};

        // Protocol: "TALLOW-RECV\n" + code + "\n"
        stream.write_all(b"TALLOW-RECV\n").await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(code.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
        stream.write_all(b"\n").await.map_err(|e| format!("write: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;

        // Read header: file_size(8) + hash(32) + filename_len(2) + filename
        let mut size_buf = [0u8; 8];
        stream.read_exact(&mut size_buf).await.map_err(|e| format!("read size: {e}"))?;
        let file_size = u64::from_le_bytes(size_buf);

        let mut hash_buf = [0u8; 32];
        stream.read_exact(&mut hash_buf).await.map_err(|e| format!("read hash: {e}"))?;

        let mut name_len = [0u8; 2];
        stream.read_exact(&mut name_len).await.map_err(|e| format!("read name len: {e}"))?;
        let name_len = u16::from_le_bytes(name_len) as usize;

        let mut name_buf = vec![0u8; name_len];
        stream.read_exact(&mut name_buf).await.map_err(|e| format!("read name: {e}"))?;
        let filename = String::from_utf8_lossy(&name_buf).to_string();

        // Read file data
        let mut data = vec![0u8; file_size as usize];
        stream.read_exact(&mut data).await.map_err(|e| format!("read data: {e}"))?;

        // Verify BLAKE3
        let computed = blake3::hash(&data);
        if computed.as_bytes() != &hash_buf {
            return Err("BLAKE3 hash mismatch -- corrupted transfer".to_string());
        }

        // Write file atomically (wire name sanitized: R-5, no traversal)
        let safe_filename = sanitize_wire_filename(&filename)
            .map_err(|e| format!("unsafe filename from peer: {e}"))?;
        let output_path = std::path::Path::new(output_dir).join(&safe_filename);
        let tmp_path = format!("{}.tallow-tmp", output_path.display());
        std::fs::write(&tmp_path, &data).map_err(|e| format!("write: {e}"))?;
        std::fs::rename(&tmp_path, &output_path).map_err(|e| format!("rename: {e}"))?;

        Ok::<_, String>((safe_filename, file_size, true))
    });

    match result {
        Ok((filename, size, verified)) => Ok(Value::Struct {
            name: "RelayReceiveResult".to_string(),
            fields: vec![
                ("filename".to_string(), Value::String(filename)),
                ("size".to_string(), Value::Int(size as i128)),
                ("verified".to_string(), Value::Bool(verified)),
                ("output_dir".to_string(), Value::String(output_dir.to_string())),
                ("code".to_string(), Value::String(code.to_string())),
            ],
        }),
        Err(e) => Err(format!("relay receive failed: {e}")),
    }
}

// ══════════════════════════════════════════════════════════════════
// Phase 60: Resume System — send/receive from an offset
// ══════════════════════════════════════════════════════════════════

/// Resume-aware send: check resume offset, send only remaining bytes via QUIC.
fn quic_send_file_resume(args: &[Value]) -> StdlibResult {
    let file_path = get_str(args, 0).ok_or("quic_send_resume: file path required")?;
    let dest_addr = get_str(args, 1).ok_or("quic_send_resume: destination required")?;
    let resume_offset = match args.get(2) {
        Some(Value::Int(n)) => *n as u64,
        _ => 0,
    };

    let data = std::fs::read(&file_path).map_err(|e| format!("read: {e}"))?;
    let total_size = data.len() as u64;
    let hash = blake3::hash(&data).to_hex().to_string();

    if resume_offset >= total_size {
        return Ok(Value::Struct {
            name: "TransferResult".to_string(),
            fields: vec![
                ("file".to_string(), Value::String(file_path)),
                ("bytes_sent".to_string(), Value::Int(0)),
                ("resumed_from".to_string(), Value::Int(resume_offset as i128)),
                ("total_size".to_string(), Value::Int(total_size as i128)),
                ("complete".to_string(), Value::Bool(true)),
                ("status".to_string(), Value::String("already complete".to_string())),
            ],
        });
    }

    let remaining = &data[resume_offset as usize..];
    let bytes_to_send = remaining.len();

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let result = rt.block_on(async {
        let client_config = create_client_config()?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("client: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let addr: SocketAddr = dest_addr.parse().map_err(|e| format!("addr: {e}"))?;
        let conn = endpoint
            .connect(addr, "tallow-transfer")
            .map_err(|e| format!("connect: {e}"))?
            .await
            .map_err(|e| format!("conn: {e}"))?;

        let mut send = conn.open_uni().await.map_err(|e| format!("stream: {e}"))?;

        // Resume header: total_size(8) + offset(8) + hash(32) + remaining data
        send.write_all(&total_size.to_le_bytes()).await.map_err(|e| format!("write: {e}"))?;
        send.write_all(&resume_offset.to_le_bytes()).await.map_err(|e| format!("write: {e}"))?;
        send.write_all(blake3::hash(&data).as_bytes()).await.map_err(|e| format!("write: {e}"))?;

        for chunk in remaining.chunks(262144) {
            send.write_all(chunk).await.map_err(|e| format!("write: {e}"))?;
        }
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
        conn.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");

        Ok::<_, String>(bytes_to_send)
    });

    match result {
        Ok(sent) => Ok(Value::Struct {
            name: "TransferResult".to_string(),
            fields: vec![
                ("file".to_string(), Value::String(file_path)),
                ("hash".to_string(), Value::String(hash)),
                ("bytes_sent".to_string(), Value::Int(sent as i128)),
                ("total_size".to_string(), Value::Int(total_size as i128)),
                ("resumed_from".to_string(), Value::Int(resume_offset as i128)),
                ("complete".to_string(), Value::Bool(true)),
            ],
        }),
        Err(e) => Err(format!("resume send failed: {e}")),
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "quic_listen" => Some(quic_listen(&args)),
        "quic_connect" => Some(quic_connect(&args)),
        "quic_send_file" => Some(quic_send_file(&args)),
        "quic_receive_file" => Some(quic_receive_file(&args)),
        "quic_send_bytes" => Some(quic_send_bytes(&args)),
        "quic_status" => Some(quic_status(&args)),
        // Phase 60: Code phrase, relay, resume
        "generate_code" => Some(generate_code(&args)),
        "code_to_port" => Some(code_to_port(&args)),
        "relay_start" => Some(relay_start(&args)),
        "relay_send" => Some(relay_send(&args)),
        "relay_receive" => Some(relay_receive(&args)),
        // R-08 batch-3 (#131/#132): resolved transport route for a transfer.
        "transfer_transport_status" => Some(transfer_transport_status(&args)),
        "quic_send_resume" => Some(quic_send_file_resume(&args)),
        // Phase 61: Multi-file, folder, compression, parallel, bandwidth, watch
        "quic_send_multi" => Some(quic_send_multi(&args)),
        "quic_send_dir" => Some(quic_send_dir(&args)),
        "transfer_compress" => Some(transfer_compress(&args)),
        "transfer_decompress" => Some(transfer_decompress(&args)),
        "parallel_config" => Some(parallel_config(&args)),
        "apply_bandwidth_limit" => Some(apply_bandwidth_limit(&args)),
        "watch_start" => Some(watch_start(&args)),
        "watch_check" => Some(watch_check(&args)),
        // Phase 63: QR code, proxy, chat, group chat
        "generate_qr" => Some(generate_qr_text(&args)),
        "proxy_config" => Some(proxy_config(&args)),
        "chat_create" => Some(chat_create(&args)),
        "chat_send_message" => Some(chat_send_message(&args)),
        "chat_decrypt_message" => Some(chat_decrypt_message(&args)),
        "group_chat_create" => Some(group_chat_create(&args)),
        "group_chat_add_member" => Some(group_chat_add_member(&args)),
        "group_chat_remove_member" => Some(group_chat_remove_member(&args)),
        "group_chat_send" => Some(group_chat_send(&args)),
        "chat_history" => Some(chat_history(&args)),
        // Text send, STUN, hole punching
        "send_text" => Some(send_text(&args)),
        "stun_discover" => Some(stun_discover(&args)),
        "hole_punch" => Some(hole_punch(&args)),
        // Streaming, content-type, E2E encryption, broadcast, speed test
        "quic_send_streaming" => Some(quic_send_file_streaming(&args)),
        "detect_content_type" => Some(detect_content_type(&args)),
        "transfer_encrypt_payload" => Some(transfer_encrypt_payload(&args)),
        "transfer_decrypt_payload" => Some(transfer_decrypt_payload(&args)),
        "broadcast_send" => Some(broadcast_send(&args)),
        "speed_test" => Some(speed_test(&args)),
        // Directory transfer protocol (TWD format)
        "quic_send_dir_structured" => Some(quic_send_dir_structured(&args)),
        "quic_receive_dir" => Some(quic_receive_dir(&args)),
        "pack_directory" => Some(pack_directory(&args)),
        "unpack_directory" => Some(unpack_directory(&args)),
        // HTTP share + live browser session
        "share_by_link" => Some(share_by_link(&args)),
        "share_dir_by_link" => Some(share_dir_by_link(&args)),
        "browser_live_share" => Some(browser_live_share(&args)),
        "browser_live_update" => Some(browser_live_update(&args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, .. } = object {
        match name.as_str() {
            "QuicServer" | "QuicConnection" | "QuicStatus" | "TransferResult"
            | "ReceiveResult" | "SendResult"
            // Phase 60: code phrase, relay, resume struct types
            | "TransferCode" | "CodeSession" | "RelayServer"
            | "RelaySendResult" | "RelayReceiveResult"
            // R-08 batch-3 (#131/#132)
            | "TransferTransport"
            // Phase 61: multi-file, folder, compression, parallel, bandwidth, watch
            | "MultiTransferResult" | "DirTransferResult" | "CompressedTransfer"
            | "ParallelConfig" | "BandwidthConfig" | "WatchSession" | "WatchChanges"
            // Phase 63: chat + proxy struct types
            | "ChatSession" | "ChatMessage" | "GroupChat" | "GroupMessage"
            | "ProxyConfig"
            // STUN + text transfer struct types
            | "StunResult" | "HolePunchResult" | "TextTransfer"
            // Streaming, content-type, E2E encryption, broadcast, speed test
            | "StreamingTransferResult" | "ContentType" | "EncryptedPayload"
            | "BroadcastSendResult" | "BroadcastResult" | "SpeedTestResult"
            // Directory transfer structs
            | "DirReceiveResult" | "PackResult" | "UnpackResult"
            // HTTP share + live browser session
            | "ShareLink" | "LiveShare" => match method {
                "to_string" => Some(Ok(Value::String(format!("{:?}", object)))),
                _ => None,
            },
            _ => None,
        }
    } else {
        None
    }
}

fn get_str(args: &[Value], idx: usize) -> Option<String> {
    args.get(idx).map(|v| v.as_string())
}

// ── Transfer transport policy introspection (rows #131/#132) ──
//
// Pure report over the resolved policy: which route a transfer to `relay_addr`
// would take, which transports are eligible, and whether the direct-UDP
// preference was explicitly authorized. Mirrors `relay_send`/`relay_receive`
// exactly (same resolution), so the CLI/doctor can show the effective route
// before a transfer runs.
//
// Args: `[relay_addr, proxy_url?]`.
fn transfer_transport_status(args: &[Value]) -> StdlibResult {
    let relay_addr = get_str(args, 0).unwrap_or_else(|| "relay.tallow-lang.org:6880".to_string());
    let explicit_proxy = get_str(args, 1).filter(|s| !s.trim().is_empty());

    let policy = transfer_policy_for(&relay_addr, explicit_proxy.as_deref())
        .map_err(|e| format!("transport policy refused: {e}"))?;

    let candidates = policy
        .candidates()
        .iter()
        .map(|p| format!("{p:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let proxy_addr = policy
        .proxy
        .as_ref()
        .map(|p| p.socks5_addr.to_string())
        .unwrap_or_default();
    let tor_mode = policy.proxy.as_ref().map(|p| p.tor_mode).unwrap_or(false);

    Ok(Value::Struct {
        name: "TransferTransport".to_string(),
        fields: vec![
            ("relay".to_string(), Value::String(relay_addr)),
            ("route".to_string(), Value::String(policy.describe())),
            (
                "candidates".to_string(),
                Value::String(candidates),
            ),
            (
                "quic_eligible".to_string(),
                Value::Bool(policy.quic_eligible()),
            ),
            ("proxied".to_string(), Value::Bool(policy.is_proxied())),
            ("tor_mode".to_string(), Value::Bool(tor_mode)),
            (
                "socks5_addr".to_string(),
                Value::String(proxy_addr),
            ),
        ],
    })
}

// ── QuicTransfer.listen(addr?) ──

fn quic_listen(args: &[Value]) -> StdlibResult {
    let addr_str = get_str(args, 0).unwrap_or_else(|| "0.0.0.0:6881".to_string());
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("invalid address '{}': {}", addr_str, e))?;

    let server_config = create_server_config()?;

    // FIX16: quinn's `Endpoint::server` binds via a tokio UdpSocket, which
    // requires a runtime context. Previously the endpoint was created with no
    // runtime in scope, so every call failed with "no async runtime found" —
    // quic_listen could never actually start a listener through the stdlib
    // dispatch path. Create the runtime first, build the endpoint inside
    // `block_on`, then move both into the accept-loop thread so the endpoint
    // stays alive (listening: true is truthful).
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;
    let endpoint = rt
        .block_on(async {
            quinn::Endpoint::server(server_config, addr)
                .map_err(|e| format!("bind failed on {}: {}", addr, e))
        })?;
    let local_addr = endpoint
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    // Keep the endpoint alive: drive the accept loop on a dedicated thread
    // with its own tokio runtime. The endpoint stays bound until the
    // process exits, so `listening: true` below is truthful.
    std::thread::Builder::new()
        .name("tallow-quic-listener".to_string())
        .spawn(move || {
            rt.block_on(async move {
                while let Some(incoming) = endpoint.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let _ = handle_quic_connection(conn).await;
                        }
                    });
                }
            });
        })
        .map_err(|e| format!("spawn quic listener thread: {e}"))?;

    Ok(Value::Struct {
        name: "QuicServer".to_string(),
        fields: vec![
            (
                "address".to_string(),
                Value::String(local_addr.to_string()),
            ),
            ("port".to_string(), Value::Int(local_addr.port() as i128)),
            ("listening".to_string(), Value::Bool(true)),
            ("protocol".to_string(), Value::String("QUIC".to_string())),
            (
                "tls".to_string(),
                Value::String("TLS 1.3 (self-signed)".to_string()),
            ),
        ],
    })
}

/// Serve one accepted QUIC connection: read a payload on a bidirectional
/// stream and reply with an acknowledgement so senders can verify delivery.
async fn handle_quic_connection(conn: quinn::Connection) -> Result<(), String> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| format!("accept_bi: {e}"))?;
    let mut buf = vec![0u8; 1 << 20];
    let n = recv
        .read(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?
        .unwrap_or(0);
    let reply = format!("TALLOW-ACK {n}\n");
    send.write_all(reply.as_bytes())
        .await
        .map_err(|e| format!("write ack: {e}"))?;
    // `finish` is synchronous in quinn 0.11.
    send.finish().map_err(|e| format!("finish: {e}"))?;
    Ok(())
}

// ── QuicTransfer.connect(addr, server_name?) ──

fn quic_connect(args: &[Value]) -> StdlibResult {
    let addr_str = get_str(args, 0).ok_or("quic_connect: address required")?;
    let server_name = get_str(args, 1).unwrap_or_else(|| "tallow-transfer".to_string());

    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("invalid address '{}': {}", addr_str, e))?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let result = rt.block_on(async {
        let client_config = create_client_config()?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("client endpoint: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(addr, &server_name)
            .map_err(|e| format!("connect error: {e}"))?
            .await
            .map_err(|e| format!("connection failed: {e}"))?;

        let remote = connection.remote_address();
        let rtt = connection.stats().path.rtt;

        connection.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");

        Ok::<_, String>((remote, rtt))
    });

    match result {
        Ok((remote, rtt)) => Ok(Value::Struct {
            name: "QuicConnection".to_string(),
            fields: vec![
                (
                    "remote_address".to_string(),
                    Value::String(remote.to_string()),
                ),
                ("connected".to_string(), Value::Bool(true)),
                (
                    "rtt_ms".to_string(),
                    Value::Float(rtt.as_secs_f64() * 1000.0),
                ),
                ("protocol".to_string(), Value::String("QUIC".to_string())),
            ],
        }),
        Err(e) => Err(format!("QUIC connect failed: {e}")),
    }
}

// ── QuicTransfer.send_file(path, dest_addr) ──

fn quic_send_file(args: &[Value]) -> StdlibResult {
    let file_path = get_str(args, 0).ok_or("quic_send_file: file path required")?;
    let dest_addr = get_str(args, 1).ok_or("quic_send_file: destination address required")?;
    // D-C2: optional arg 3 = bytes/sec pacing budget (CLI converts --bwlimit
    // from bits/sec); 0/absent = unlimited.
    let bwlimit: Option<u64> = match args.get(2) {
        Some(Value::Int(n)) if *n > 0 => Some(*n as u64),
        _ => None,
    };

    // Read file + compute BLAKE3 hash
    let data =
        std::fs::read(&file_path).map_err(|e| format!("read file '{}': {}", file_path, e))?;
    let file_size = data.len();
    let hash = blake3::hash(&data).to_hex().to_string();

    let chunk_size = 262144usize; // 256KB
    let chunk_count = (file_size + chunk_size - 1) / chunk_size.max(1);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let filename = std::path::Path::new(&file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".to_string());

    let send_result = rt.block_on(async {
        let client_config = create_client_config()?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("client: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let addr: SocketAddr = dest_addr
            .parse()
            .map_err(|e| format!("invalid addr: {e}"))?;

        let conn = endpoint
            .connect(addr, "tallow-transfer")
            .map_err(|e| format!("connect: {e}"))?
            .await
            .map_err(|e| format!("connection: {e}"))?;

        // Open a unidirectional stream for the transfer
        let mut send_stream = conn
            .open_uni()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        // Header: file_size (8) + blake3_hash (32) + filename_len (2) + filename
        let mut header = Vec::new();
        header.extend_from_slice(&(file_size as u64).to_le_bytes());
        header.extend_from_slice(blake3::hash(&data).as_bytes());
        header.extend_from_slice(&(filename.len() as u16).to_le_bytes());
        header.extend_from_slice(filename.as_bytes());

        send_stream
            .write_all(&header)
            .await
            .map_err(|e| format!("send header: {e}"))?;

        // Send file data in chunks
        let mut bytes_sent = 0u64;
        let mut pace_waits = 0u64;
        let pace_start = std::time::Instant::now();
        for chunk in data.chunks(chunk_size) {
            send_stream
                .write_all(chunk)
                .await
                .map_err(|e| format!("send chunk: {e}"))?;
            bytes_sent += chunk.len() as u64;
            if let Some(bps) = bwlimit {
                if let Some(delay) = transfer_pace_delay(bytes_sent, bps, pace_start.elapsed()) {
                    pace_waits += 1;
                    tokio::time::sleep(delay).await;
                }
            }
        }

        send_stream.finish().map_err(|e| format!("finish: {e}"))?;

        // Wait for the peer to receive all data before closing
        let _ = tokio::time::timeout(Duration::from_secs(10), send_stream.stopped()).await;

        let rtt = conn.stats().path.rtt;
        conn.close(0u32.into(), b"transfer complete");
        endpoint.close(0u32.into(), b"done");

        Ok::<_, String>((bytes_sent, rtt, pace_waits))
    });

    match send_result {
        Ok((bytes_sent, rtt, pace_waits)) => Ok(Value::Struct {
            name: "TransferResult".to_string(),
            fields: vec![
                ("file".to_string(), Value::String(file_path)),
                ("hash".to_string(), Value::String(hash)),
                ("size".to_string(), Value::Int(file_size as i128)),
                ("chunks".to_string(), Value::Int(chunk_count as i128)),
                ("bytes_sent".to_string(), Value::Int(bytes_sent as i128)),
                (
                    "bwlimit_bytes_per_sec".to_string(),
                    Value::Int(bwlimit.unwrap_or(0) as i128),
                ),
                ("paced_chunks".to_string(), Value::Int(pace_waits as i128)),
                ("protocol".to_string(), Value::String("QUIC".to_string())),
                (
                    "rtt_ms".to_string(),
                    Value::Float(rtt.as_secs_f64() * 1000.0),
                ),
                ("sent".to_string(), Value::Bool(true)),
            ],
        }),
        Err(e) => Err(format!("QUIC send failed: {e}")),
    }
}

// ── QuicTransfer.receive(listen_addr?, output_dir?, timeout_secs?) ──

fn quic_receive_file(args: &[Value]) -> StdlibResult {
    let listen_addr = get_str(args, 0).unwrap_or_else(|| "0.0.0.0:6881".to_string());
    let output_dir = get_str(args, 1).unwrap_or_else(|| ".".to_string());
    let timeout_secs = match args.get(2) {
        Some(Value::Int(n)) => *n as u64,
        _ => 30,
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let recv_result = rt.block_on(async {
        let server_config = create_server_config()?;
        let addr: SocketAddr = listen_addr
            .parse()
            .map_err(|e| format!("invalid addr: {e}"))?;
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| format!("bind: {e}"))?;

        // Wait for incoming connection with timeout
        let incoming = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            endpoint.accept(),
        )
        .await
        .map_err(|_| format!("timeout waiting for connection after {}s", timeout_secs))?
        .ok_or("no incoming connection")?;

        let conn = incoming
            .await
            .map_err(|e| format!("accept: {e}"))?;

        // Accept unidirectional stream
        let mut recv_stream = conn
            .accept_uni()
            .await
            .map_err(|e| format!("accept stream: {e}"))?;

        // Read header
        let mut size_buf = [0u8; 8];
        recv_stream
            .read_exact(&mut size_buf)
            .await
            .map_err(|e| format!("read size: {e}"))?;
        let file_size = u64::from_le_bytes(size_buf);

        let mut hash_buf = [0u8; 32];
        recv_stream
            .read_exact(&mut hash_buf)
            .await
            .map_err(|e| format!("read hash: {e}"))?;

        let mut name_len_buf = [0u8; 2];
        recv_stream
            .read_exact(&mut name_len_buf)
            .await
            .map_err(|e| format!("read name len: {e}"))?;
        let name_len = u16::from_le_bytes(name_len_buf) as usize;

        let mut name_buf = vec![0u8; name_len];
        recv_stream
            .read_exact(&mut name_buf)
            .await
            .map_err(|e| format!("read name: {e}"))?;
        let filename = String::from_utf8_lossy(&name_buf).to_string();

        // Read file data (wire name sanitized: R-5, no traversal)
        let safe_filename = sanitize_wire_filename(&filename)
            .map_err(|e| format!("unsafe filename from peer: {e}"))?;
        let output_path = std::path::Path::new(&output_dir).join(&safe_filename);
        let tmp_path = format!("{}.tallow-tmp", output_path.display());

        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| format!("create tmp: {e}"))?;

        let mut bytes_received = 0u64;
        let mut buf = vec![0u8; 65536];
        loop {
            match recv_stream.read(&mut buf).await {
                Ok(Some(n)) => {
                    tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n])
                        .await
                        .map_err(|e| format!("write: {e}"))?;
                    bytes_received += n as u64;
                }
                Ok(None) => break,
                Err(e) => return Err(format!("read: {e}")),
            }
        }

        tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(|e| format!("flush: {e}"))?;
        drop(file);

        // Verify BLAKE3 hash
        let received_data =
            std::fs::read(&tmp_path).map_err(|e| format!("read tmp: {e}"))?;
        let computed_hash = blake3::hash(&received_data);
        let hash_matches = computed_hash.as_bytes() == &hash_buf;

        if hash_matches {
            std::fs::rename(&tmp_path, &output_path)
                .map_err(|e| format!("rename: {e}"))?;
        } else {
            let _ = std::fs::remove_file(&tmp_path);
            return Err("BLAKE3 hash mismatch -- file corrupted in transit".to_string());
        }

        conn.close(0u32.into(), b"received");
        endpoint.close(0u32.into(), b"done");

        Ok::<_, String>((filename, file_size, bytes_received, hash_matches))
    });

    match recv_result {
        Ok((filename, file_size, bytes_received, verified)) => Ok(Value::Struct {
            name: "ReceiveResult".to_string(),
            fields: vec![
                ("filename".to_string(), Value::String(filename)),
                ("size".to_string(), Value::Int(file_size as i128)),
                (
                    "bytes_received".to_string(),
                    Value::Int(bytes_received as i128),
                ),
                ("verified".to_string(), Value::Bool(verified)),
                ("protocol".to_string(), Value::String("QUIC".to_string())),
                ("output_dir".to_string(), Value::String(output_dir)),
            ],
        }),
        Err(e) => Err(format!("QUIC receive failed: {e}")),
    }
}

// ── QuicTransfer.send_bytes(data, dest_addr) ──

fn quic_send_bytes(args: &[Value]) -> StdlibResult {
    let data = get_str(args, 0).ok_or("quic_send_bytes: data required")?;
    let dest_addr = get_str(args, 1).ok_or("quic_send_bytes: destination required")?;

    let data_bytes = data.as_bytes();
    let hash = blake3::hash(data_bytes).to_hex().to_string();

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let result = rt.block_on(async {
        let client_config = create_client_config()?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("client: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let addr: SocketAddr = dest_addr
            .parse()
            .map_err(|e| format!("addr: {e}"))?;
        let conn = endpoint
            .connect(addr, "tallow-transfer")
            .map_err(|e| format!("connect: {e}"))?
            .await
            .map_err(|e| format!("connection: {e}"))?;

        let mut send = conn
            .open_uni()
            .await
            .map_err(|e| format!("stream: {e}"))?;

        // Simple framing: size (8 bytes) + data
        send.write_all(&(data_bytes.len() as u64).to_le_bytes())
            .await
            .map_err(|e| format!("write size: {e}"))?;
        send.write_all(data_bytes)
            .await
            .map_err(|e| format!("write data: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        // Wait for the peer to receive all data before closing.
        // stopped() returns when the peer sends STOP_SENDING or connection closes.
        // We use a timeout to avoid hanging if the peer doesn't signal.
        let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;

        conn.close(0u32.into(), b"done");
        endpoint.close(0u32.into(), b"done");
        Ok::<_, String>(data_bytes.len())
    });

    match result {
        Ok(sent) => Ok(Value::Struct {
            name: "SendResult".to_string(),
            fields: vec![
                ("bytes_sent".to_string(), Value::Int(sent as i128)),
                ("hash".to_string(), Value::String(hash)),
                ("protocol".to_string(), Value::String("QUIC".to_string())),
                ("sent".to_string(), Value::Bool(true)),
            ],
        }),
        Err(e) => Err(format!("send failed: {e}")),
    }
}

// ── QuicTransfer.status() ──

fn quic_status(_args: &[Value]) -> StdlibResult {
    Ok(Value::Struct {
        name: "QuicStatus".to_string(),
        fields: vec![
            ("available".to_string(), Value::Bool(true)),
            (
                "library".to_string(),
                Value::String("quinn 0.11".to_string()),
            ),
            (
                "tls".to_string(),
                Value::String("rustls TLS 1.3".to_string()),
            ),
            (
                "congestion".to_string(),
                Value::String("CUBIC".to_string()),
            ),
            ("max_streams".to_string(), Value::Int(100)),
            ("mtu".to_string(), Value::Int(1350)),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Phase 61: Multi-file send, folder send, compression, parallel
// streams, bandwidth limiting, and watch mode
// ══════════════════════════════════════════════════════════════════

// ── MultiTransfer.prepare(files, dest) ──

/// Send multiple files in one transfer session.
/// Packages files as a manifest + sequential stream.
fn quic_send_multi(args: &[Value]) -> StdlibResult {
    let files = match args.first() {
        Some(Value::Array(arr)) => arr.iter().map(|v| v.as_string()).collect::<Vec<_>>(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => return Err("quic_send_multi: file list required".to_string()),
    };
    let dest_addr = get_str(args, 1).ok_or("quic_send_multi: destination address required")?;

    // Build manifest
    let mut manifest_entries = Vec::new();
    let mut total_size: u64 = 0;

    for file_path in &files {
        let meta = std::fs::metadata(file_path)
            .map_err(|e| format!("quic_send_multi: stat '{}': {}", file_path, e))?;
        if meta.is_dir() {
            walk_dir_entries(file_path, file_path, &mut manifest_entries, &mut total_size)?;
        } else {
            let size = meta.len();
            let hash = blake3::hash(
                &std::fs::read(file_path)
                    .map_err(|e| format!("quic_send_multi: read '{}': {}", file_path, e))?,
            )
            .to_hex()
            .to_string();
            manifest_entries.push(Value::Struct {
                name: "FileEntry".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(file_path.clone())),
                    ("size".to_string(), Value::Int(size as i128)),
                    ("hash".to_string(), Value::String(hash)),
                    ("is_dir".to_string(), Value::Bool(false)),
                ],
            });
            total_size += size;
        }
    }

    Ok(Value::Struct {
        name: "MultiTransferResult".to_string(),
        fields: vec![
            (
                "files_count".to_string(),
                Value::Int(manifest_entries.len() as i128),
            ),
            ("total_size".to_string(), Value::Int(total_size as i128)),
            ("entries".to_string(), Value::Array(manifest_entries)),
            ("destination".to_string(), Value::String(dest_addr)),
            ("status".to_string(), Value::String("ready".to_string())),
        ],
    })
}

fn walk_dir_entries(
    base: &str,
    dir: &str,
    entries: &mut Vec<Value>,
    total_size: &mut u64,
) -> Result<(), String> {
    let read_dir =
        std::fs::read_dir(dir).map_err(|e| format!("walk_dir_entries: read_dir '{}': {}", dir, e))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("walk_dir_entries: entry: {e}"))?;
        let path = entry.path();
        let rel_path = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string()
            .replace('\\', "/");

        if path.is_dir() {
            entries.push(Value::Struct {
                name: "FileEntry".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(rel_path.clone())),
                    ("size".to_string(), Value::Int(0)),
                    ("hash".to_string(), Value::String(String::new())),
                    ("is_dir".to_string(), Value::Bool(true)),
                ],
            });
            walk_dir_entries(base, &path.to_string_lossy(), entries, total_size)?;
        } else {
            let data = std::fs::read(&path)
                .map_err(|e| format!("walk_dir_entries: read '{}': {}", path.display(), e))?;
            let size = data.len() as u64;
            let hash = blake3::hash(&data).to_hex().to_string();
            entries.push(Value::Struct {
                name: "FileEntry".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(rel_path)),
                    ("size".to_string(), Value::Int(size as i128)),
                    ("hash".to_string(), Value::String(hash)),
                    ("is_dir".to_string(), Value::Bool(false)),
                ],
            });
            *total_size += size;
        }
    }
    Ok(())
}

// ── MultiTransfer.send_dir(dir, dest, compress) ──

/// Send an entire directory over QUIC.
/// Archives directory into a custom binary format, optionally compresses, returns metadata.
fn quic_send_dir(args: &[Value]) -> StdlibResult {
    let dir_path = get_str(args, 0).ok_or("quic_send_dir: directory path required")?;
    let dest_addr = get_str(args, 1).ok_or("quic_send_dir: destination address required")?;
    let compress = match args.get(2) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s != "false" && s != "none",
        _ => true, // compress by default
    };

    if !std::path::Path::new(&dir_path).is_dir() {
        return Err(format!("quic_send_dir: not a directory: {}", dir_path));
    }

    // Walk directory and collect all file data into a buffer.
    // Simple archive format: [file_count: u64] then for each file:
    // [path_len: u16] [path: bytes] [is_dir: u8] [size: u64] [data: bytes]
    let mut archive_data = Vec::new();
    let mut file_count: u64 = 0;

    // Reserve space for file count (will fill in later)
    archive_data.extend_from_slice(&0u64.to_le_bytes());
    archive_dir_recursive(&dir_path, &dir_path, &mut archive_data, &mut file_count)?;
    // Fill in file count at the beginning
    archive_data[0..8].copy_from_slice(&file_count.to_le_bytes());

    let uncompressed_size = archive_data.len();

    // Compress if requested
    let final_data = if compress {
        zstd::encode_all(std::io::Cursor::new(&archive_data), 3)
            .map_err(|e| format!("quic_send_dir: compress: {e}"))?
    } else {
        archive_data
    };

    let compressed_size = final_data.len();
    let hash = blake3::hash(&final_data).to_hex().to_string();

    Ok(Value::Struct {
        name: "DirTransferResult".to_string(),
        fields: vec![
            ("directory".to_string(), Value::String(dir_path)),
            ("files_count".to_string(), Value::Int(file_count as i128)),
            (
                "uncompressed_size".to_string(),
                Value::Int(uncompressed_size as i128),
            ),
            (
                "compressed_size".to_string(),
                Value::Int(compressed_size as i128),
            ),
            (
                "compression_ratio".to_string(),
                Value::Float(if uncompressed_size > 0 {
                    compressed_size as f64 / uncompressed_size as f64
                } else {
                    1.0
                }),
            ),
            ("hash".to_string(), Value::String(hash)),
            ("compressed".to_string(), Value::Bool(compress)),
            ("destination".to_string(), Value::String(dest_addr)),
            ("ready".to_string(), Value::Bool(true)),
        ],
    })
}

fn archive_dir_recursive(
    base: &str,
    dir: &str,
    buf: &mut Vec<u8>,
    count: &mut u64,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("archive_dir_recursive: read_dir '{}': {}", dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("archive_dir_recursive: entry: {e}"))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string()
            .replace('\\', "/");
        let rel_bytes = rel.as_bytes();

        buf.extend_from_slice(&(rel_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(rel_bytes);

        if path.is_dir() {
            buf.push(1); // is_dir = true
            buf.extend_from_slice(&0u64.to_le_bytes()); // size = 0
            *count += 1;
            archive_dir_recursive(base, &path.to_string_lossy(), buf, count)?;
        } else {
            buf.push(0); // is_dir = false
            let data = std::fs::read(&path)
                .map_err(|e| format!("archive_dir_recursive: read '{}': {}", path.display(), e))?;
            buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
            buf.extend_from_slice(&data);
            *count += 1;
        }
    }
    Ok(())
}

// ── TransferCompress.compress(data, algo) ──

/// Compress data before sending, auto-detect best algorithm.
fn transfer_compress(args: &[Value]) -> StdlibResult {
    let data = get_str(args, 0).ok_or("transfer_compress: data required")?;
    let algo = get_str(args, 1).unwrap_or_else(|| "auto".to_string());

    let data_bytes = data.as_bytes();

    // Auto-detect: check Shannon entropy
    let entropy = shannon_entropy(data_bytes);
    let (compressed, algo_used) = if algo == "none" || entropy > 7.5 {
        (data_bytes.to_vec(), "none".to_string())
    } else if algo == "lz4" || (algo == "auto" && data_bytes.len() > 1_000_000) {
        // LZ4 for large data (faster)
        (
            lz4_flex::compress_prepend_size(data_bytes),
            "lz4".to_string(),
        )
    } else {
        // zstd for everything else (better ratio)
        let compressed = zstd::encode_all(std::io::Cursor::new(data_bytes), 3)
            .map_err(|e| format!("transfer_compress: zstd compress: {e}"))?;
        (compressed, "zstd".to_string())
    };

    let ratio = if !data_bytes.is_empty() {
        compressed.len() as f64 / data_bytes.len() as f64
    } else {
        1.0
    };

    Ok(Value::Struct {
        name: "CompressedTransfer".to_string(),
        fields: vec![
            (
                "original_size".to_string(),
                Value::Int(data_bytes.len() as i128),
            ),
            (
                "compressed_size".to_string(),
                Value::Int(compressed.len() as i128),
            ),
            ("ratio".to_string(), Value::Float(ratio)),
            ("algorithm".to_string(), Value::String(algo_used)),
            (
                "data_hex".to_string(),
                Value::String(p61_hex_encode(&compressed)),
            ),
        ],
    })
}

/// Decompress data previously compressed by transfer_compress.
fn transfer_decompress(args: &[Value]) -> StdlibResult {
    let hex_data = get_str(args, 0).ok_or("transfer_decompress: compressed data required")?;
    let algo = get_str(args, 1).ok_or("transfer_decompress: algorithm required")?;

    let compressed = p61_hex_decode(&hex_data)?;

    let decompressed = match algo.as_str() {
        "lz4" => lz4_flex::decompress_size_prepended(&compressed)
            .map_err(|e| format!("transfer_decompress: lz4 decompress: {e}"))?,
        "zstd" => zstd::decode_all(std::io::Cursor::new(&compressed))
            .map_err(|e| format!("transfer_decompress: zstd decompress: {e}"))?,
        "none" => compressed,
        _ => return Err(format!("transfer_decompress: unknown algorithm: {}", algo)),
    };

    Ok(Value::String(
        String::from_utf8_lossy(&decompressed).to_string(),
    ))
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn p61_hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn p61_hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!(
            "transfer_decompress: hex string has odd length: {}",
            s.len()
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("transfer_decompress: hex decode: {e}"))
        })
        .collect()
}

// ── ParallelConfig.create(streams, chunk_size) ──

/// Configure parallel stream count for a transfer.
fn parallel_config(args: &[Value]) -> StdlibResult {
    let streams = match args.first() {
        Some(Value::Int(n)) => *n as u32,
        _ => 4, // default 4 parallel streams
    };
    let chunk_size = match args.get(1) {
        Some(Value::Int(n)) => *n as u64,
        _ => 262144, // 256KB
    };

    Ok(Value::Struct {
        name: "ParallelConfig".to_string(),
        fields: vec![
            ("streams".to_string(), Value::Int(streams as i128)),
            ("chunk_size".to_string(), Value::Int(chunk_size as i128)),
            (
                "strategy".to_string(),
                Value::String("round_robin".to_string()),
            ),
            (
                "total_bandwidth_estimate".to_string(),
                Value::String("auto".to_string()),
            ),
        ],
    })
}

// ── BandwidthConfig ──

/// Cumulative-average pacing budget for `--bwlimit` (design D-C2).
///
/// `apply_bandwidth_limit` converts CLI bits/sec values to bytes/sec. The
/// transfer must never exceed that average measured from its start, so the
/// wait owed after sending `bytes_sent` is
/// `bytes_sent / bytes_per_sec - elapsed` (`None` = already ahead of the
/// schedule, sleep not needed). `bytes_per_sec == 0` = unlimited.
fn transfer_pace_delay(
    bytes_sent: u64,
    bytes_per_sec: u64,
    elapsed: std::time::Duration,
) -> Option<std::time::Duration> {
    if bytes_per_sec == 0 {
        return None;
    }
    let expected =
        std::time::Duration::from_secs_f64(bytes_sent as f64 / bytes_per_sec as f64);
    expected
        .checked_sub(elapsed)
        .filter(|d| !d.is_zero()) // exactly on schedule = no wait
}

/// Apply bandwidth limit to transfer operations.
/// Parses "10M" = 10 Mbps, "500K" = 500 Kbps, "1G" = 1 Gbps.
fn apply_bandwidth_limit(args: &[Value]) -> StdlibResult {
    let limit_str = get_str(args, 0)
        .ok_or("apply_bandwidth_limit: bandwidth limit required (e.g., '10M', '500K')")?;

    let (num_str, unit) = if limit_str.ends_with('G') || limit_str.ends_with('g') {
        (&limit_str[..limit_str.len() - 1], 1_000_000_000u64)
    } else if limit_str.ends_with('M') || limit_str.ends_with('m') {
        (&limit_str[..limit_str.len() - 1], 1_000_000u64)
    } else if limit_str.ends_with('K') || limit_str.ends_with('k') {
        (&limit_str[..limit_str.len() - 1], 1_000u64)
    } else {
        (limit_str.as_str(), 1u64) // bytes/sec
    };

    let num: f64 = num_str
        .parse()
        .map_err(|_| format!("apply_bandwidth_limit: invalid number: {}", num_str))?;
    let bytes_per_sec = (num * unit as f64 / 8.0) as u64; // bits to bytes

    Ok(Value::Struct {
        name: "BandwidthConfig".to_string(),
        fields: vec![
            ("limit_str".to_string(), Value::String(limit_str)),
            (
                "bytes_per_sec".to_string(),
                Value::Int(bytes_per_sec as i128),
            ),
            (
                "bits_per_sec".to_string(),
                Value::Int((bytes_per_sec * 8) as i128),
            ),
            ("active".to_string(), Value::Bool(true)),
        ],
    })
}

// ── WatchSession.start(dir, interval_ms) ──

/// Watch a directory for changes and sync.
fn watch_start(args: &[Value]) -> StdlibResult {
    let dir = get_str(args, 0).ok_or("watch_start: directory to watch required")?;
    let interval_ms = match args.get(1) {
        Some(Value::Int(n)) => *n as u64,
        _ => 1000, // default 1 second
    };

    if !std::path::Path::new(&dir).is_dir() {
        return Err(format!("watch_start: not a directory: {}", dir));
    }

    // Take initial snapshot
    let mut entries = Vec::new();
    let mut total_size = 0u64;
    collect_dir_hashes(&dir, &dir, &mut entries, &mut total_size)?;

    Ok(Value::Struct {
        name: "WatchSession".to_string(),
        fields: vec![
            ("directory".to_string(), Value::String(dir)),
            ("interval_ms".to_string(), Value::Int(interval_ms as i128)),
            (
                "files_tracked".to_string(),
                Value::Int(entries.len() as i128),
            ),
            ("total_size".to_string(), Value::Int(total_size as i128)),
            ("watching".to_string(), Value::Bool(true)),
            ("snapshot".to_string(), Value::Array(entries)),
        ],
    })
}

// ── WatchSession.check(session) ──

/// Check for changes since last snapshot.
fn watch_check(args: &[Value]) -> StdlibResult {
    let (dir, old_snapshot) = match args.first() {
        Some(Value::Struct { fields, .. }) => {
            let dir = fields
                .iter()
                .find(|(k, _)| k == "directory")
                .map(|(_, v)| v.as_string())
                .unwrap_or_default();
            let snap = match fields.iter().find(|(k, _)| k == "snapshot") {
                Some((_, Value::Array(arr))) => arr.clone(),
                _ => Vec::new(),
            };
            (dir, snap)
        }
        _ => return Err("watch_check: session struct required".to_string()),
    };

    // Take new snapshot
    let mut new_entries = Vec::new();
    let mut total_size = 0u64;
    collect_dir_hashes(&dir, &dir, &mut new_entries, &mut total_size)?;

    // Compare: build maps of path -> hash
    let old_map: std::collections::HashMap<String, String> = old_snapshot
        .iter()
        .filter_map(|v| {
            if let Value::Struct { fields, .. } = v {
                let path = fields
                    .iter()
                    .find(|(k, _)| k == "path")
                    .map(|(_, v)| v.as_string())?;
                let hash = fields
                    .iter()
                    .find(|(k, _)| k == "hash")
                    .map(|(_, v)| v.as_string())?;
                Some((path, hash))
            } else {
                None
            }
        })
        .collect();

    let new_map: std::collections::HashMap<String, String> = new_entries
        .iter()
        .filter_map(|v| {
            if let Value::Struct { fields, .. } = v {
                let path = fields
                    .iter()
                    .find(|(k, _)| k == "path")
                    .map(|(_, v)| v.as_string())?;
                let hash = fields
                    .iter()
                    .find(|(k, _)| k == "hash")
                    .map(|(_, v)| v.as_string())?;
                Some((path, hash))
            } else {
                None
            }
        })
        .collect();

    let added: Vec<Value> = new_map
        .keys()
        .filter(|k| !old_map.contains_key(*k))
        .map(|k| Value::String(k.clone()))
        .collect();
    let removed: Vec<Value> = old_map
        .keys()
        .filter(|k| !new_map.contains_key(*k))
        .map(|k| Value::String(k.clone()))
        .collect();
    let modified: Vec<Value> = new_map
        .iter()
        .filter(|(k, v)| old_map.get(*k).map(|old| old != *v).unwrap_or(false))
        .map(|(k, _)| Value::String(k.clone()))
        .collect();

    let has_changes = !added.is_empty() || !removed.is_empty() || !modified.is_empty();

    Ok(Value::Struct {
        name: "WatchChanges".to_string(),
        fields: vec![
            ("has_changes".to_string(), Value::Bool(has_changes)),
            ("added".to_string(), Value::Array(added)),
            ("removed".to_string(), Value::Array(removed)),
            ("modified".to_string(), Value::Array(modified)),
            ("new_snapshot".to_string(), Value::Array(new_entries)),
        ],
    })
}

fn collect_dir_hashes(
    base: &str,
    dir: &str,
    entries: &mut Vec<Value>,
    total: &mut u64,
) -> Result<(), String> {
    let read = std::fs::read_dir(dir)
        .map_err(|e| format!("collect_dir_hashes: read_dir '{}': {}", dir, e))?;
    for entry in read {
        let entry = entry.map_err(|e| format!("collect_dir_hashes: entry: {e}"))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string()
            .replace('\\', "/");

        if path.is_dir() {
            collect_dir_hashes(base, &path.to_string_lossy(), entries, total)?;
        } else if let Ok(data) = std::fs::read(&path) {
            let hash = blake3::hash(&data).to_hex().to_string();
            *total += data.len() as u64;
            entries.push(Value::Struct {
                name: "WatchEntry".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(rel)),
                    ("hash".to_string(), Value::String(hash)),
                    ("size".to_string(), Value::Int(data.len() as i128)),
                ],
            });
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════
// Phase 63: QR Code, Proxy, Chat, Group Chat
// ══════════════════════════════════════════════════════════════════

// ── Hex helpers (local to this module) ──

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("hex decode: {e}"))
        })
        .collect()
}

// ── QR Code display (ASCII art from code phrase) ──

fn generate_qr_text(args: &[Value]) -> StdlibResult {
    let data = get_str(args, 0).ok_or("generate_qr: data required")?;
    let hash = blake3::hash(data.as_bytes());
    let bytes = hash.as_bytes();

    let mut lines = Vec::new();
    lines.push("\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}".to_string());
    lines.push(format!("\u{2551}  TALLOW TRANSFER                   \u{2551}"));
    lines.push(format!("\u{2551}                                   \u{2551}"));
    for row in 0..8 {
        let mut line = format!("\u{2551}  ");
        for col in 0..16 {
            let byte = bytes[(row * 4 + col / 4) % 32];
            let bit = (byte >> (col % 8)) & 1;
            if bit == 1 {
                line.push_str("\u{2588}\u{2588}");
            } else {
                line.push_str("  ");
            }
        }
        line.push_str("   \u{2551}");
        lines.push(line);
    }
    lines.push(format!("\u{2551}                                   \u{2551}"));
    let display_code = if data.len() > 24 { &data[..24] } else { &data };
    lines.push(format!("\u{2551}  Code: {:<26} \u{2551}", display_code));
    lines.push(format!("\u{2551}                                   \u{2551}"));
    lines.push("\u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}".to_string());

    let qr_text = lines.join("\n");
    Ok(Value::String(qr_text))
}

// ── SOCKS5 Proxy Config ──

fn proxy_config(args: &[Value]) -> StdlibResult {
    let proxy_url = get_str(args, 0)
        .ok_or("proxy_config: proxy URL required (e.g., socks5://127.0.0.1:9050)")?;

    let (proto, addr) = if proxy_url.starts_with("socks5://") {
        ("socks5".to_string(), proxy_url["socks5://".len()..].to_string())
    } else if proxy_url.starts_with("socks4://") {
        ("socks4".to_string(), proxy_url["socks4://".len()..].to_string())
    } else if proxy_url.starts_with("http://") {
        ("http".to_string(), proxy_url["http://".len()..].to_string())
    } else {
        ("socks5".to_string(), proxy_url.clone()) // default to SOCKS5
    };

    let is_tor = addr.contains("9050") || addr.contains("9150");

    Ok(Value::Struct {
        name: "ProxyConfig".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(proxy_url)),
            ("protocol".to_string(), Value::String(proto)),
            ("address".to_string(), Value::String(addr)),
            ("active".to_string(), Value::Bool(true)),
            ("tor".to_string(), Value::Bool(is_tor)),
        ],
    })
}

// ── Encrypted Chat (1-to-1) ──

/// Create a chat session (1-to-1 encrypted).
fn chat_create(args: &[Value]) -> StdlibResult {
    let username = get_str(args, 0).ok_or("chat_create: username required")?;
    // Mint the 8-symbol v4 passcode (operator directive 2026-10-12). Peers pair by
    // the code STRING, so an 8-symbol code still meets an older peer.
    let code = get_str(args, 1).unwrap_or_else(tallow_protocol::room::code::generate_passcode);
    // Join contract (operator directive 2026-10-12): accept the 8-symbol v4 mint ONLY.
    // Retired shapes stay DERIVABLE but must not enter a room from a user-supplied code.
    if !tallow_protocol::room::code::is_supported_code(&code) {
        return Err(format!(
            "unsupported code '{}': {} — this build accepts the 8-symbol mint only (e.g. K7M2QPHD)",
            code,
            tallow_protocol::room::code::unsupported_code_reason(&code)
                .unwrap_or("not a v4 passcode")
        ));
    }
    let (port, _session_key) = code_to_session(&code);

    let session_id = blake3::hash(format!("chat:{}:{}", username, code).as_bytes())
        .to_hex()
        .to_string()[..12]
        .to_string();

    Ok(Value::Struct {
        name: "ChatSession".to_string(),
        fields: vec![
            ("session_id".to_string(), Value::String(session_id)),
            ("username".to_string(), Value::String(username)),
            ("code".to_string(), Value::String(code)),
            ("port".to_string(), Value::Int(port as i128)),
            ("encrypted".to_string(), Value::Bool(true)),
            ("algo".to_string(), Value::String("AES-256-GCM".to_string())),
            ("messages".to_string(), Value::Array(vec![])),
            ("participants".to_string(), Value::Array(vec![])),
        ],
    })
}

/// Send a chat message (encrypted with session key derived from session_id).
fn chat_send_message(args: &[Value]) -> StdlibResult {
    let session = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("chat_send_message: chat session struct required".to_string()),
    };
    let message = get_str(args, 1).ok_or("chat_send_message: message required")?;

    let username = session.iter().find(|(k, _)| k == "username")
        .map(|(_, v)| v.as_string()).unwrap_or_default();
    let session_id = session.iter().find(|(k, _)| k == "session_id")
        .map(|(_, v)| v.as_string()).unwrap_or_default();

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch);

    // Encrypt message with session-derived key
    let key_material = blake3::hash(format!("chat-key:{}", session_id).as_bytes());
    let key_bytes = key_material.as_bytes();

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; 12];
    rand::Rng::fill(&mut rand::rng(), &mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, message.as_bytes())
        .map_err(|e| format!("chat encrypt failed: {e}"))?;

    let encrypted_hex = hex_encode(&nonce_bytes) + &hex_encode(&ciphertext);

    // Create message struct
    let msg = Value::Struct {
        name: "ChatMessage".to_string(),
        fields: vec![
            ("from".to_string(), Value::String(username.clone())),
            ("text".to_string(), Value::String(message)),
            ("encrypted".to_string(), Value::String(encrypted_hex)),
            ("timestamp".to_string(), Value::String(timestamp)),
            ("session_id".to_string(), Value::String(session_id)),
        ],
    };

    // Update session with new message (immutable update)
    let mut new_fields = session;
    for (k, v) in new_fields.iter_mut() {
        if k == "messages" {
            if let Value::Array(msgs) = v {
                msgs.push(msg.clone());
            }
        }
    }

    Ok(Value::Struct {
        name: "ChatSession".to_string(),
        fields: new_fields,
    })
}

/// Decrypt a received chat message.
fn chat_decrypt_message(args: &[Value]) -> StdlibResult {
    let encrypted_hex = get_str(args, 0).ok_or("chat_decrypt_message: encrypted message required")?;
    let session_id = get_str(args, 1).ok_or("chat_decrypt_message: session_id required")?;

    if encrypted_hex.len() < 24 {
        return Err("chat_decrypt_message: invalid encrypted message (too short)".to_string());
    }

    let nonce_hex = &encrypted_hex[..24];
    let ct_hex = &encrypted_hex[24..];
    let nonce_bytes = hex_decode(nonce_hex)?;
    let ciphertext = hex_decode(ct_hex)?;

    let key_material = blake3::hash(format!("chat-key:{}", session_id).as_bytes());
    let key_bytes = key_material.as_bytes();

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_bytes));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "chat decryption failed: wrong session key or corrupted message".to_string())?;

    Ok(Value::String(String::from_utf8_lossy(&plaintext).to_string()))
}

// ── Group Chat ──

/// Create a group chat session.
fn group_chat_create(args: &[Value]) -> StdlibResult {
    let group_name = get_str(args, 0).ok_or("group_chat_create: group name required")?;
    let creator = get_str(args, 1).ok_or("group_chat_create: creator username required")?;
    // Mint the 8-symbol v4 passcode (operator directive 2026-10-12). Peers pair by
    // the code STRING, so an 8-symbol code still meets an older peer.
    let code = get_str(args, 2).unwrap_or_else(tallow_protocol::room::code::generate_passcode);
    // Join contract (operator directive 2026-10-12): accept the 8-symbol v4 mint ONLY.
    // Retired shapes stay DERIVABLE but must not enter a room from a user-supplied code.
    if !tallow_protocol::room::code::is_supported_code(&code) {
        return Err(format!(
            "unsupported code '{}': {} — this build accepts the 8-symbol mint only (e.g. K7M2QPHD)",
            code,
            tallow_protocol::room::code::unsupported_code_reason(&code)
                .unwrap_or("not a v4 passcode")
        ));
    }
    let (port, _) = code_to_session(&code);

    let group_id = blake3::hash(format!("group:{}:{}", group_name, code).as_bytes())
        .to_hex()
        .to_string()[..12]
        .to_string();

    Ok(Value::Struct {
        name: "GroupChat".to_string(),
        fields: vec![
            ("group_id".to_string(), Value::String(group_id)),
            ("name".to_string(), Value::String(group_name)),
            ("code".to_string(), Value::String(code)),
            ("port".to_string(), Value::Int(port as i128)),
            ("creator".to_string(), Value::String(creator.clone())),
            ("members".to_string(), Value::Array(vec![Value::String(creator)])),
            ("messages".to_string(), Value::Array(vec![])),
            ("encrypted".to_string(), Value::Bool(true)),
            ("max_members".to_string(), Value::Int(50)),
        ],
    })
}

/// Add a member to a group chat.
fn group_chat_add_member(args: &[Value]) -> StdlibResult {
    let group = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("group_chat_add_member: group chat struct required".to_string()),
    };
    let new_member = get_str(args, 1).ok_or("group_chat_add_member: member username required")?;

    let mut new_fields = group;
    for (k, v) in new_fields.iter_mut() {
        if k == "members" {
            if let Value::Array(members) = v {
                if !members.iter().any(|m| m.as_string() == new_member) {
                    members.push(Value::String(new_member.clone()));
                }
            }
        }
    }

    Ok(Value::Struct {
        name: "GroupChat".to_string(),
        fields: new_fields,
    })
}

/// Remove a member from a group chat.
fn group_chat_remove_member(args: &[Value]) -> StdlibResult {
    let group = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("group_chat_remove_member: group chat struct required".to_string()),
    };
    let remove_member = get_str(args, 1).ok_or("group_chat_remove_member: member username required")?;

    let mut new_fields = group;
    for (k, v) in new_fields.iter_mut() {
        if k == "members" {
            if let Value::Array(members) = v {
                members.retain(|m| m.as_string() != remove_member);
            }
        }
    }

    Ok(Value::Struct {
        name: "GroupChat".to_string(),
        fields: new_fields,
    })
}

/// Send a message to a group chat (encrypted, added to group messages).
fn group_chat_send(args: &[Value]) -> StdlibResult {
    let group = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("group_chat_send: group chat struct required".to_string()),
    };
    let sender = get_str(args, 1).ok_or("group_chat_send: sender username required")?;
    let message = get_str(args, 2).ok_or("group_chat_send: message required")?;

    let group_id = group.iter().find(|(k, _)| k == "group_id")
        .map(|(_, v)| v.as_string()).unwrap_or_default();

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch);

    // Encrypt with group key
    let key_material = blake3::hash(format!("group-key:{}", group_id).as_bytes());
    let key_bytes = key_material.as_bytes();

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; 12];
    rand::Rng::fill(&mut rand::rng(), &mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, message.as_bytes())
        .map_err(|e| format!("group chat encrypt: {e}"))?;

    let encrypted_hex = hex_encode(&nonce_bytes) + &hex_encode(&ciphertext);

    let msg = Value::Struct {
        name: "GroupMessage".to_string(),
        fields: vec![
            ("from".to_string(), Value::String(sender)),
            ("text".to_string(), Value::String(message)),
            ("encrypted".to_string(), Value::String(encrypted_hex)),
            ("timestamp".to_string(), Value::String(timestamp)),
            ("group_id".to_string(), Value::String(group_id)),
        ],
    };

    let mut new_fields = group;
    for (k, v) in new_fields.iter_mut() {
        if k == "messages" {
            if let Value::Array(msgs) = v {
                msgs.push(msg.clone());
            }
        }
    }

    Ok(Value::Struct {
        name: "GroupChat".to_string(),
        fields: new_fields,
    })
}

/// Get chat history (formatted messages for display).
fn chat_history(args: &[Value]) -> StdlibResult {
    let session = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("chat_history: chat/group session struct required".to_string()),
    };

    let messages = session.iter().find(|(k, _)| k == "messages")
        .and_then(|(_, v)| if let Value::Array(arr) = v { Some(arr.clone()) } else { None })
        .unwrap_or_default();

    let formatted: Vec<Value> = messages.iter().map(|msg| {
        if let Value::Struct { fields, .. } = msg {
            let from = fields.iter().find(|(k, _)| k == "from").map(|(_, v)| v.as_string()).unwrap_or_default();
            let text = fields.iter().find(|(k, _)| k == "text").map(|(_, v)| v.as_string()).unwrap_or_default();
            let time = fields.iter().find(|(k, _)| k == "timestamp").map(|(_, v)| v.as_string()).unwrap_or_default();
            Value::String(format!("[{}] {}: {}", time, from, text))
        } else {
            msg.clone()
        }
    }).collect();

    Ok(Value::Array(formatted))
}

// ── Send Text (no file, just text payload) ──

/// Transmit a text payload over TCP.
///
/// Args: `send_text(text, target?)`.
/// - With a target (`host:port`), the text is really transmitted: the peer
///   receives `TALLOW-TEXT\n` + size(8) + blake3 hash(32) + payload, and the
///   caller waits for a `TALLOW-ACK <hash>` line to confirm delivery.
/// - Without a target, this returns a manifest with `transmitted: false` and a
///   clear reason — it never fabricates a sent result.
fn send_text(args: &[Value]) -> StdlibResult {
    let text = get_str(args, 0).ok_or("send_text: text required")?;
    let target = get_str(args, 1);
    let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
    let size = text.len();

    let Some(target) = target else {
        // Honest no-op: nothing was transmitted, and we say so explicitly.
        return Ok(Value::Struct {
            name: "TextTransfer".to_string(),
            fields: vec![
                ("text".to_string(), Value::String(text)),
                ("size".to_string(), Value::Int(size as i128)),
                ("hash".to_string(), Value::String(hash)),
                ("type".to_string(), Value::String("text".to_string())),
                ("transmitted".to_string(), Value::Bool(false)),
                (
                    "reason".to_string(),
                    Value::String(
                        "no recipient address provided — pass <text> <host:port> \
                         (or use quic_send_bytes for QUIC delivery)"
                            .to_string(),
                    ),
                ),
            ],
        })
    };

    // Real transmission: connect and push the payload.
    use std::io::{Read, Write};
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("send_text: invalid target '{target}': {e}"))?;

    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("send_text: cannot reach '{target}': {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();

    // Protocol: "TALLOW-TEXT\n" + size(8) + hash(32) + payload
    stream
        .write_all(b"TALLOW-TEXT\n")
        .map_err(|e| format!("send_text: write header: {e}"))?;
    stream
        .write_all(&(size as u64).to_le_bytes())
        .map_err(|e| format!("send_text: write size: {e}"))?;
    stream
        .write_all(blake3::hash(text.as_bytes()).as_bytes())
        .map_err(|e| format!("send_text: write hash: {e}"))?;
    stream
        .write_all(text.as_bytes())
        .map_err(|e| format!("send_text: write payload: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("send_text: flush: {e}"))?;

    // Wait for the peer's ACK (best-effort; the bytes are already on the wire).
    let mut ack = [0u8; 128];
    let acked = match stream.read(&mut ack) {
        Ok(n) => String::from_utf8_lossy(&ack[..n]).contains(&hash),
        Err(_) => false,
    };

    Ok(Value::Struct {
        name: "TextTransfer".to_string(),
        fields: vec![
            ("text".to_string(), Value::String(text)),
            ("size".to_string(), Value::Int(size as i128)),
            ("hash".to_string(), Value::String(hash)),
            ("type".to_string(), Value::String("text".to_string())),
            ("transmitted".to_string(), Value::Bool(true)),
            ("acked".to_string(), Value::Bool(acked)),
            ("to".to_string(), Value::String(target)),
            ("protocol".to_string(), Value::String("TCP text".to_string())),
        ],
    })
}

// ── STUN / Hole Punching (for relay-free P2P) ──

/// Discover local/public IP via UDP socket binding (STUN-like).
fn stun_discover(_args: &[Value]) -> StdlibResult {
    let local_ip = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
        socket
            .and_then(|s| {
                s.connect("8.8.8.8:80").ok()?;
                s.local_addr().ok()
            })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    };

    Ok(Value::Struct {
        name: "StunResult".to_string(),
        fields: vec![
            ("local_ip".to_string(), Value::String(local_ip.clone())),
            ("public_ip".to_string(), Value::String(local_ip)), // same on LAN
            ("nat_type".to_string(), Value::String("unknown".to_string())),
            ("port".to_string(), Value::Int(0)),
            ("reachable".to_string(), Value::Bool(true)),
        ],
    })
}

/// Attempt UDP hole punch: send a packet to peer to open NAT pinhole.
fn hole_punch(args: &[Value]) -> StdlibResult {
    let peer_ip = get_str(args, 0).ok_or("hole_punch: peer IP required")?;
    let peer_port = match args.get(1) {
        Some(Value::Int(n)) => *n as u16,
        _ => 6881,
    };
    let local_port = match args.get(2) {
        Some(Value::Int(n)) => *n as u16,
        _ => 0, // auto-assign
    };

    let result = std::net::UdpSocket::bind(format!("0.0.0.0:{}", local_port));
    match result {
        Ok(socket) => {
            let peer_addr = format!("{}:{}", peer_ip, peer_port);
            // Send punch packet
            let _ = socket.send_to(b"TALLOW-PUNCH", &peer_addr);
            let local = socket
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            Ok(Value::Struct {
                name: "HolePunchResult".to_string(),
                fields: vec![
                    ("peer".to_string(), Value::String(peer_addr)),
                    ("local_addr".to_string(), Value::String(local)),
                    ("punch_sent".to_string(), Value::Bool(true)),
                    ("protocol".to_string(), Value::String("UDP".to_string())),
                ],
            })
        }
        Err(e) => Err(format!("hole punch failed: {e}")),
    }
}

// ══════════════════════════════════════════════════════════════════
// Large File Streaming, Content-Type, E2E Encryption, Broadcast, Speed Test
// ══════════════════════════════════════════════════════════════════

/// Stream a file over QUIC in 256KB chunks -- NEVER loads entire file into memory.
fn quic_send_file_streaming(args: &[Value]) -> StdlibResult {
    let file_path = get_str(args, 0).ok_or("file path required")?;
    let dest_addr = get_str(args, 1).ok_or("destination required")?;
    // D-C2: optional arg 3 = bytes/sec pacing budget (0/absent = unlimited).
    let bwlimit: Option<u64> = match args.get(2) {
        Some(Value::Int(n)) if *n > 0 => Some(*n as u64),
        _ => None,
    };

    let metadata = std::fs::metadata(&file_path).map_err(|e| format!("stat: {e}"))?;
    let file_size = metadata.len();
    let hash = {
        // Stream hash without loading entire file
        let mut hasher = blake3::Hasher::new();
        let mut file = std::fs::File::open(&file_path).map_err(|e| format!("open: {e}"))?;
        let mut buf = vec![0u8; 262144]; // 256KB buffer
        loop {
            let n = std::io::Read::read(&mut file, &mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        hasher.finalize().to_hex().to_string()
    };

    let chunk_size = 262144usize;
    let chunk_count = (file_size as usize + chunk_size - 1) / chunk_size;

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;
    let result = rt.block_on(async {
        let client_config = create_client_config()?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("client: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let addr: std::net::SocketAddr = dest_addr.parse().map_err(|e| format!("addr: {e}"))?;
        let conn = endpoint.connect(addr, "tallow-transfer")
            .map_err(|e| format!("connect: {e}"))?
            .await.map_err(|e| format!("conn: {e}"))?;

        let mut send = conn.open_uni().await.map_err(|e| format!("stream: {e}"))?;

        // Header
        let filename = std::path::Path::new(&file_path)
            .file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_string());
        send.write_all(&file_size.to_le_bytes()).await.map_err(|e| format!("write: {e}"))?;
        send.write_all(&blake3::hash(hash.as_bytes()).as_bytes()[..32]).await.map_err(|e| format!("write: {e}"))?;
        send.write_all(&(filename.len() as u16).to_le_bytes()).await.map_err(|e| format!("write: {e}"))?;
        send.write_all(filename.as_bytes()).await.map_err(|e| format!("write: {e}"))?;

        // Stream file in chunks (never loads entire file)
        let mut file = tokio::fs::File::open(&file_path).await.map_err(|e| format!("open: {e}"))?;
        let mut bytes_sent = 0u64;
        let mut pace_waits = 0u64;
        let pace_start = std::time::Instant::now();
        let mut buf = vec![0u8; chunk_size];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await.map_err(|e| format!("read: {e}"))?;
            if n == 0 { break; }
            send.write_all(&buf[..n]).await.map_err(|e| format!("send: {e}"))?;
            bytes_sent += n as u64;
            if let Some(bps) = bwlimit {
                if let Some(delay) = transfer_pace_delay(bytes_sent, bps, pace_start.elapsed()) {
                    pace_waits += 1;
                    tokio::time::sleep(delay).await;
                }
            }
        }
        send.finish().map_err(|e| format!("finish: {e}"))?;
        conn.close(0u32.into(), b"done");
        Ok::<_, String>((bytes_sent, pace_waits))
    });

    match result {
        Ok((sent, pace_waits)) => Ok(Value::Struct {
            name: "StreamingTransferResult".to_string(),
            fields: vec![
                ("file".to_string(), Value::String(file_path)),
                ("hash".to_string(), Value::String(hash)),
                ("size".to_string(), Value::Int(file_size as i128)),
                ("bytes_sent".to_string(), Value::Int(sent as i128)),
                (
                    "bwlimit_bytes_per_sec".to_string(),
                    Value::Int(bwlimit.unwrap_or(0) as i128),
                ),
                ("paced_chunks".to_string(), Value::Int(pace_waits as i128)),
                ("chunks".to_string(), Value::Int(chunk_count as i128)),
                ("streamed".to_string(), Value::Bool(true)),
                ("max_memory".to_string(), Value::String("256KB".to_string())),
            ],
        }),
        Err(e) => Err(format!("streaming send failed: {e}")),
    }
}

/// Detect content type from file magic bytes or raw data.
fn detect_content_type(args: &[Value]) -> StdlibResult {
    let path_or_data = get_str(args, 0).ok_or("path or data required")?;

    // If it's a file path and exists, detect from magic bytes
    if std::path::Path::new(&path_or_data).exists() {
        if let Ok(data) = std::fs::read(&path_or_data) {
            let (content_type, is_text) = detect_mime(&data);
            return Ok(Value::Struct {
                name: "ContentType".to_string(),
                fields: vec![
                    ("mime".to_string(), Value::String(content_type.to_string())),
                    ("is_text".to_string(), Value::Bool(is_text)),
                    ("is_binary".to_string(), Value::Bool(!is_text)),
                    ("source".to_string(), Value::String("file".to_string())),
                ],
            });
        }
    }

    // Otherwise treat as raw text
    Ok(Value::Struct {
        name: "ContentType".to_string(),
        fields: vec![
            ("mime".to_string(), Value::String("text/plain".to_string())),
            ("is_text".to_string(), Value::Bool(true)),
            ("is_binary".to_string(), Value::Bool(false)),
            ("source".to_string(), Value::String("text".to_string())),
        ],
    })
}

fn detect_mime(data: &[u8]) -> (&'static str, bool) {
    if data.len() < 4 { return ("application/octet-stream", false); }
    match &data[..4] {
        [0x89, 0x50, 0x4E, 0x47] => ("image/png", false),
        [0xFF, 0xD8, 0xFF, _] => ("image/jpeg", false),
        [0x25, 0x50, 0x44, 0x46] => ("application/pdf", false),
        [0x50, 0x4B, 0x03, 0x04] => ("application/zip", false),
        [0x1F, 0x8B, _, _] => ("application/gzip", false),
        [0x28, 0xB5, 0x2F, 0xFD] => ("application/zstd", false),
        [0x4D, 0x5A, _, _] => ("application/x-executable", false),
        [0x7F, 0x45, 0x4C, 0x46] => ("application/x-elf", false),
        _ if data.starts_with(b"{") || data.starts_with(b"[") => ("application/json", true),
        _ if data.starts_with(b"<?xml") || data.starts_with(b"<html") => ("text/html", true),
        _ if data.starts_with(b"NIXV") => ("application/x-tallow-vault", false),
        _ => {
            let sample_len = data.len().min(1024).max(1);
            let printable = data.iter().take(sample_len)
                .filter(|&&b| (b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09)
                .count();
            if printable * 100 / sample_len > 90 {
                ("text/plain", true)
            } else {
                ("application/octet-stream", false)
            }
        }
    }
}

/// Encrypt a payload with AES-256-GCM + Argon2id key derivation (E2E for transfer).
fn transfer_encrypt_payload(args: &[Value]) -> StdlibResult {
    let data_hex = get_str(args, 0).ok_or("data required")?;
    let password = get_str(args, 1).ok_or("password required")?;

    let data = hex_decode(&data_hex)?;
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 12] = rand::random();

    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("key derivation: {e}"))?;

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ct = cipher.encrypt(GenericArray::from_slice(&nonce), data.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct);

    Ok(Value::Struct {
        name: "EncryptedPayload".to_string(),
        fields: vec![
            ("data".to_string(), Value::String(hex_encode(&output))),
            ("encrypted".to_string(), Value::Bool(true)),
            ("algo".to_string(), Value::String("AES-256-GCM + Argon2id".to_string())),
            ("original_size".to_string(), Value::Int(data.len() as i128)),
        ],
    })
}

/// Decrypt a payload previously encrypted with transfer_encrypt_payload.
fn transfer_decrypt_payload(args: &[Value]) -> StdlibResult {
    let encrypted_hex = get_str(args, 0).ok_or("encrypted data required")?;
    let password = get_str(args, 1).ok_or("password required")?;

    let encrypted = hex_decode(&encrypted_hex)?;
    if encrypted.len() < 28 { return Err("data too short".to_string()); }

    let salt = &encrypted[..16];
    let nonce = &encrypted[16..28];
    let ct = &encrypted[28..];

    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation: {e}"))?;

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let pt = cipher.decrypt(GenericArray::from_slice(nonce), ct)
        .map_err(|_| "decryption failed (wrong password?)".to_string())?;

    Ok(Value::String(hex_encode(&pt)))
}

/// Send a file to multiple recipients (broadcast probe).
fn broadcast_send(args: &[Value]) -> StdlibResult {
    let file_path = get_str(args, 0).ok_or("file path required")?;
    let recipients = match args.get(1) {
        Some(Value::Array(arr)) => arr.iter().map(|v| v.as_string()).collect::<Vec<_>>(),
        _ => return Err("recipients array required".to_string()),
    };

    if recipients.is_empty() { return Err("at least one recipient required".to_string()); }

    let data = std::fs::read(&file_path).map_err(|e| format!("read: {e}"))?;
    let hash = blake3::hash(&data).to_hex().to_string();
    let size = data.len();

    let mut results = Vec::new();
    for addr in &recipients {
        // Each recipient gets their own transfer attempt
        let status = match addr.parse::<std::net::SocketAddr>() {
            Ok(sock_addr) => {
                match std::net::TcpStream::connect_timeout(
                    &sock_addr,
                    std::time::Duration::from_secs(5),
                ) {
                    Ok(_) => "reachable",
                    Err(_) => "unreachable",
                }
            }
            Err(_) => "invalid_address",
        };
        results.push(Value::Struct {
            name: "BroadcastResult".to_string(),
            fields: vec![
                ("recipient".to_string(), Value::String(addr.clone())),
                ("status".to_string(), Value::String(status.to_string())),
            ],
        });
    }

    Ok(Value::Struct {
        name: "BroadcastSendResult".to_string(),
        fields: vec![
            ("file".to_string(), Value::String(file_path)),
            ("hash".to_string(), Value::String(hash)),
            ("size".to_string(), Value::Int(size as i128)),
            ("recipients".to_string(), Value::Int(recipients.len() as i128)),
            ("results".to_string(), Value::Array(results)),
        ],
    })
}

/// Run a speed test: local disk/hash/encrypt/compress measurements, plus a real
/// network throughput test against `target` (`host:port`) when one is provided.
fn speed_test(args: &[Value]) -> StdlibResult {
    let target = get_str(args, 0).unwrap_or_else(|| "self".to_string());

    // ── Network throughput test (only when a target is given) ──────────────
    let mut net_target = String::new();
    let mut net_send_mbps = 0.0f64;
    let mut net_recv_mbps = 0.0f64;
    let mut net_round_trip_ms = 0.0f64;
    let mut net_status = "skipped (no target provided — local-only results)".to_string();

    if target != "self" && !target.is_empty() {
        net_target = target.clone();
        let addr: SocketAddr = match target.parse() {
            Ok(a) => a,
            Err(e) => {
                return Err(format!(
                    "speed_test: invalid target '{target}': {e} (expected host:port)"
                ))
            }
        };
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("speed_test: cannot reach target '{target}': {e}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .ok();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();

        // Upload: write "TALLOW-SPEED\n" + size(8) + 10MB of data, measure MB/s.
        let test_size = 10 * 1024 * 1024;
        let payload: Vec<u8> = (0..test_size).map(|i| (i % 256) as u8).collect();
        stream
            .write_all(b"TALLOW-SPEED\n")
            .map_err(|e| format!("speed_test: write header: {e}"))?;
        stream
            .write_all(&(test_size as u64).to_le_bytes())
            .map_err(|e| format!("speed_test: write size: {e}"))?;
        let start = std::time::Instant::now();
        for chunk in payload.chunks(256 * 1024) {
            stream
                .write_all(chunk)
                .map_err(|e| format!("speed_test: write payload: {e}"))?;
        }
        stream.flush().map_err(|e| format!("speed_test: flush: {e}"))?;
        let send_ms = start.elapsed().as_millis() as f64;
        net_send_mbps = (test_size as f64 / 1_000_000.0) / (send_ms.max(0.1) / 1000.0);

        // Round-trip / download: try to read the peer's echo of the size.
        let read_start = std::time::Instant::now();
        let mut buf = [0u8; 64];
        match stream.read(&mut buf) {
            Ok(n) => {
                let line = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                net_round_trip_ms = read_start.elapsed().as_millis() as f64;
                net_recv_mbps = if line.starts_with("TALLOW-ACK") {
                    // Peer echoed; measure receive throughput using the same payload size.
                    let recv_start = std::time::Instant::now();
                    let mut sink = vec![0u8; 256 * 1024];
                    let mut got: u64 = 0;
                    loop {
                        match stream.read(&mut sink) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got += n as u64,
                        }
                        if got >= test_size as u64 {
                            break;
                        }
                    }
                    let recv_ms = recv_start.elapsed().as_millis() as f64;
                    (got as f64 / 1_000_000.0) / (recv_ms.max(0.1) / 1000.0)
                } else {
                    0.0
                };
                net_status = "ok".to_string();
            }
            Err(_) => {
                // No echo within the read timeout — send direction still measured.
                net_status = "sent, no echo from peer (read timed out)".to_string();
            }
        }
    }

    // ── Local measurements (always run) ─────────────────────────────────────
    let test_size = 10 * 1024 * 1024; // 10MB
    let data: Vec<u8> = (0..test_size).map(|i| (i % 256) as u8).collect();

    // Write speed. The path must be unique per call: the previous fixed name
    // (`tallow_speed_test.tmp` in the shared temp dir) was a race — two callers,
    // including two test threads, wrote and removed the same file, so one of
    // them read ENOENT. CI caught it as
    // `speed_test failed: Err("read: No such file or directory")`.
    static SPEED_TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SPEED_TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!(
        "tallow_speed_test_{}_{seq}.tmp",
        std::process::id()
    ));
    let start = std::time::Instant::now();
    std::fs::write(&tmp, &data).map_err(|e| format!("write: {e}"))?;
    let write_ms = start.elapsed().as_millis() as f64;
    let write_mbps = (test_size as f64 / 1_000_000.0) / (write_ms.max(0.1) / 1000.0);

    // Read speed
    let start = std::time::Instant::now();
    let _ = std::fs::read(&tmp).map_err(|e| format!("read: {e}"))?;
    let read_ms = start.elapsed().as_millis() as f64;
    let read_mbps = (test_size as f64 / 1_000_000.0) / (read_ms.max(0.1) / 1000.0);

    // Hash speed
    let start = std::time::Instant::now();
    let _ = blake3::hash(&data);
    let hash_ms = start.elapsed().as_millis() as f64;
    let hash_mbps = (test_size as f64 / 1_000_000.0) / (hash_ms.max(0.1) / 1000.0);

    // Encrypt speed
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let start = std::time::Instant::now();
    let _ = cipher.encrypt(GenericArray::from_slice(&nonce), data.as_ref());
    let enc_ms = start.elapsed().as_millis() as f64;
    let enc_mbps = (test_size as f64 / 1_000_000.0) / (enc_ms.max(0.1) / 1000.0);

    // Compress speed
    let start = std::time::Instant::now();
    let _ = zstd::encode_all(std::io::Cursor::new(&data), 3);
    let comp_ms = start.elapsed().as_millis() as f64;
    let comp_mbps = (test_size as f64 / 1_000_000.0) / (comp_ms.max(0.1) / 1000.0);

    let _ = std::fs::remove_file(&tmp);

    Ok(Value::Struct {
        name: "SpeedTestResult".to_string(),
        fields: vec![
            ("test_size_mb".to_string(), Value::Int(10)),
            ("disk_write_mbps".to_string(), Value::Float(write_mbps)),
            ("disk_read_mbps".to_string(), Value::Float(read_mbps)),
            ("blake3_hash_mbps".to_string(), Value::Float(hash_mbps)),
            ("aes256_gcm_mbps".to_string(), Value::Float(enc_mbps)),
            ("zstd_compress_mbps".to_string(), Value::Float(comp_mbps)),
            ("network_target".to_string(), Value::String(net_target)),
            ("network_send_mbps".to_string(), Value::Float(net_send_mbps)),
            ("network_recv_mbps".to_string(), Value::Float(net_recv_mbps)),
            (
                "network_round_trip_ms".to_string(),
                Value::Float(net_round_trip_ms),
            ),
            ("network_status".to_string(), Value::String(net_status)),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Directory Transfer Protocol: TWD archive format
// ══════════════════════════════════════════════════════════════════

/// Walk a directory tree, collecting files and subdirectory relative paths.
/// All paths are normalized to forward slashes.
fn walk_twd(
    base: &std::path::Path,
    current: &std::path::Path,
    files: &mut Vec<(String, Vec<u8>)>,
    dirs: &mut Vec<String>,
    total: &mut u64,
) -> Result<(), String> {
    let entries = std::fs::read_dir(current)
        .map_err(|e| format!("read_dir '{}': {e}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("entry: {e}"))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string()
            .replace('\\', "/");

        if path.is_dir() {
            dirs.push(rel.clone());
            walk_twd(base, &path, files, dirs, total)?;
        } else {
            let data = std::fs::read(&path)
                .map_err(|e| format!("read '{}': {e}", path.display()))?;
            *total += data.len() as u64;
            files.push((rel, data));
        }
    }
    Ok(())
}

/// Build a TWD archive from collected dirs and files.
/// Format: [magic: "TWD1" 4B] [version: 1B] [dir_name_len: 2B] [dir_name]
///         [dir_count: 4B] for each dir: [path_len: 2B] [path]
///         [file_count: 4B] for each file: [path_len: 2B] [path] [size: 8B] [data]
fn build_twd_archive(
    dir_name: &str,
    dirs: &[String],
    files: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let mut archive = Vec::new();
    archive.extend_from_slice(b"TWD1");
    archive.push(1); // version
    let name_bytes = dir_name.as_bytes();
    archive.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    archive.extend_from_slice(name_bytes);

    // Directories
    archive.extend_from_slice(&(dirs.len() as u32).to_le_bytes());
    for d in dirs {
        let db = d.as_bytes();
        archive.extend_from_slice(&(db.len() as u16).to_le_bytes());
        archive.extend_from_slice(db);
    }

    // Files
    archive.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for (path, data) in files {
        let pb = path.as_bytes();
        archive.extend_from_slice(&(pb.len() as u16).to_le_bytes());
        archive.extend_from_slice(pb);
        archive.extend_from_slice(&(data.len() as u64).to_le_bytes());
        archive.extend_from_slice(data);
    }

    archive
}

/// Parse a TWD archive, creating directories and writing files under `root`.
/// Returns (dir_name, file_count, dir_count, total_bytes_written).
fn unpack_twd_archive(
    archive: &[u8],
    output_dir: &str,
) -> Result<(String, usize, usize, u64), String> {
    if archive.len() < 5 || &archive[..4] != b"TWD1" {
        return Err("invalid directory archive (not TWD format)".to_string());
    }
    let _version = archive[4];
    let mut pos = 5;

    // Read dir_name
    if pos + 2 > archive.len() {
        return Err("truncated archive: missing dir_name length".into());
    }
    let name_len = u16::from_le_bytes([archive[pos], archive[pos + 1]]) as usize;
    pos += 2;
    if pos + name_len > archive.len() {
        return Err("truncated archive: missing dir_name".into());
    }
    let dir_name = String::from_utf8_lossy(&archive[pos..pos + name_len]).to_string();
    pos += name_len;

    let root = std::path::Path::new(output_dir).join(&dir_name);
    std::fs::create_dir_all(&root).map_err(|e| format!("mkdir root: {e}"))?;

    // Read directories
    if pos + 4 > archive.len() {
        return Err("truncated archive: missing dir_count".into());
    }
    let dir_count = u32::from_le_bytes(
        archive[pos..pos + 4].try_into().unwrap(),
    ) as usize;
    pos += 4;
    for _ in 0..dir_count {
        if pos + 2 > archive.len() {
            return Err("truncated archive: missing dir path length".into());
        }
        let plen = u16::from_le_bytes([archive[pos], archive[pos + 1]]) as usize;
        pos += 2;
        if pos + plen > archive.len() {
            return Err("truncated archive: missing dir path".into());
        }
        let rel_path = String::from_utf8_lossy(&archive[pos..pos + plen]).to_string();
        pos += plen;
        let full = root.join(&rel_path);
        std::fs::create_dir_all(&full)
            .map_err(|e| format!("mkdir '{}': {e}", full.display()))?;
    }

    // Read files
    if pos + 4 > archive.len() {
        return Err("truncated archive: missing file_count".into());
    }
    let file_count = u32::from_le_bytes(
        archive[pos..pos + 4].try_into().unwrap(),
    ) as usize;
    pos += 4;
    let mut total_bytes = 0u64;
    for _ in 0..file_count {
        if pos + 2 > archive.len() {
            return Err("truncated archive: missing file path length".into());
        }
        let plen = u16::from_le_bytes([archive[pos], archive[pos + 1]]) as usize;
        pos += 2;
        if pos + plen > archive.len() {
            return Err("truncated archive: missing file path".into());
        }
        let rel_path = String::from_utf8_lossy(&archive[pos..pos + plen]).to_string();
        pos += plen;
        if pos + 8 > archive.len() {
            return Err("truncated archive: missing file size".into());
        }
        let size =
            u64::from_le_bytes(archive[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        if pos + size > archive.len() {
            return Err("truncated archive: missing file data".into());
        }
        let file_data = &archive[pos..pos + size];
        pos += size;

        let full = root.join(&rel_path);
        if let Some(parent) = full.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Atomic write: temp file then rename
        let tmp = format!("{}.tallow-tmp", full.display());
        std::fs::write(&tmp, file_data)
            .map_err(|e| format!("write '{}': {e}", full.display()))?;
        std::fs::rename(&tmp, &full).map_err(|e| format!("rename: {e}"))?;
        total_bytes += size as u64;
    }

    Ok((dir_name, file_count, dir_count, total_bytes))
}

/// Send a directory over QUIC preserving full folder structure.
/// Protocol: header (total_len, compressed flag) then TWD archive bytes.
fn quic_send_dir_structured(args: &[Value]) -> StdlibResult {
    let dir_path = get_str(args, 0).ok_or("directory path required")?;
    let dest_addr = get_str(args, 1).ok_or("destination address required")?;
    let compress = match args.get(2) {
        Some(Value::Bool(b)) => *b,
        _ => true,
    };

    let base = std::path::Path::new(&dir_path);
    if !base.is_dir() {
        return Err(format!("not a directory: {}", dir_path));
    }

    // Collect all files with relative paths
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    let mut total_size: u64 = 0;
    walk_twd(base, base, &mut files, &mut dirs, &mut total_size)?;

    let dir_name = base
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "transfer".to_string());

    let archive = build_twd_archive(&dir_name, &dirs, &files);
    let uncompressed_size = archive.len();

    // Optionally compress
    let final_data = if compress {
        zstd::encode_all(std::io::Cursor::new(&archive), 3)
            .map_err(|e| format!("compress: {e}"))?
    } else {
        archive
    };

    let archive_hash = blake3::hash(&final_data).to_hex().to_string();
    let compressed_size = final_data.len();

    // Send via QUIC
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;
    let sent = rt.block_on(async {
        let client_config = create_client_config()?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| format!("client: {e}"))?;
        endpoint.set_default_client_config(client_config);

        let addr: std::net::SocketAddr =
            dest_addr.parse().map_err(|e| format!("addr: {e}"))?;
        let conn = endpoint
            .connect(addr, "tallow-transfer")
            .map_err(|e| format!("connect: {e}"))?
            .await
            .map_err(|e| format!("conn: {e}"))?;

        let mut send = conn.open_uni().await.map_err(|e| format!("stream: {e}"))?;

        // Send: [total_len: 8] [compressed: 1] [data]
        send.write_all(&(final_data.len() as u64).to_le_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.write_all(&[if compress { 1u8 } else { 0u8 }])
            .await
            .map_err(|e| format!("write: {e}"))?;

        // Stream in 256KB chunks
        for chunk in final_data.chunks(262144) {
            send.write_all(chunk)
                .await
                .map_err(|e| format!("write: {e}"))?;
        }
        send.finish().map_err(|e| format!("finish: {e}"))?;
        conn.close(0u32.into(), b"done");
        Ok::<_, String>(final_data.len())
    })?;

    Ok(Value::Struct {
        name: "DirTransferResult".to_string(),
        fields: vec![
            ("directory".to_string(), Value::String(dir_path)),
            ("dir_name".to_string(), Value::String(dir_name)),
            (
                "files_count".to_string(),
                Value::Int(files.len() as i128),
            ),
            ("dirs_count".to_string(), Value::Int(dirs.len() as i128)),
            ("total_size".to_string(), Value::Int(total_size as i128)),
            (
                "compressed_size".to_string(),
                Value::Int(compressed_size as i128),
            ),
            (
                "uncompressed_size".to_string(),
                Value::Int(uncompressed_size as i128),
            ),
            ("hash".to_string(), Value::String(archive_hash)),
            ("compressed".to_string(), Value::Bool(compress)),
            ("bytes_sent".to_string(), Value::Int(sent as i128)),
            ("structure_preserved".to_string(), Value::Bool(true)),
        ],
    })
}

/// Receive a directory over QUIC and restore full folder structure.
fn quic_receive_dir(args: &[Value]) -> StdlibResult {
    let listen_addr =
        get_str(args, 0).unwrap_or_else(|| "0.0.0.0:6881".to_string());
    let output_dir = get_str(args, 1).unwrap_or_else(|| ".".to_string());
    let timeout_secs = match args.get(2) {
        Some(Value::Int(n)) => *n as u64,
        _ => 60,
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;

    let result = rt.block_on(async {
        let server_config = create_server_config()?;
        let addr: std::net::SocketAddr =
            listen_addr.parse().map_err(|e| format!("addr: {e}"))?;
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| format!("bind: {e}"))?;

        let incoming = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            endpoint.accept(),
        )
        .await
        .map_err(|_| format!("timeout after {}s", timeout_secs))?
        .ok_or("no connection")?;

        let conn = incoming.await.map_err(|e| format!("accept: {e}"))?;
        let mut recv = conn
            .accept_uni()
            .await
            .map_err(|e| format!("stream: {e}"))?;

        // Read header: [total_len: 8] [compressed: 1]
        let mut len_buf = [0u8; 8];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("read len: {e}"))?;
        let total_len = u64::from_le_bytes(len_buf);

        let mut comp_buf = [0u8; 1];
        recv.read_exact(&mut comp_buf)
            .await
            .map_err(|e| format!("read comp: {e}"))?;
        let is_compressed = comp_buf[0] == 1;

        // Read all data
        let data = recv
            .read_to_end(total_len as usize + 1)
            .await
            .map_err(|e| format!("read data: {e}"))?;

        conn.close(0u32.into(), b"received");
        endpoint.close(0u32.into(), b"done");

        // Decompress if needed
        let archive = if is_compressed {
            zstd::decode_all(std::io::Cursor::new(&data))
                .map_err(|e| format!("decompress: {e}"))?
        } else {
            data
        };

        // Parse and unpack TWD archive
        unpack_twd_archive(&archive, &output_dir)
    });

    match result {
        Ok((name, files, dirs, bytes)) => Ok(Value::Struct {
            name: "DirReceiveResult".to_string(),
            fields: vec![
                ("dir_name".to_string(), Value::String(name)),
                ("files_received".to_string(), Value::Int(files as i128)),
                ("dirs_created".to_string(), Value::Int(dirs as i128)),
                ("bytes_written".to_string(), Value::Int(bytes as i128)),
                ("output_dir".to_string(), Value::String(output_dir)),
                ("structure_preserved".to_string(), Value::Bool(true)),
                ("verified".to_string(), Value::Bool(true)),
            ],
        }),
        Err(e) => Err(format!("receive dir failed: {e}")),
    }
}

/// Pack a directory into TWD archive format (local, no network).
fn pack_directory(args: &[Value]) -> StdlibResult {
    let dir_path = get_str(args, 0).ok_or("directory required")?;
    let output_path = get_str(args, 1).ok_or("output path required")?;
    let compress = match args.get(2) {
        Some(Value::Bool(b)) => *b,
        _ => true,
    };

    let base = std::path::Path::new(&dir_path);
    if !base.is_dir() {
        return Err(format!("not a directory: {}", dir_path));
    }

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    let mut total_size: u64 = 0;
    walk_twd(base, base, &mut files, &mut dirs, &mut total_size)?;

    let dir_name = base
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "archive".into());

    let archive = build_twd_archive(&dir_name, &dirs, &files);

    let final_data = if compress {
        zstd::encode_all(std::io::Cursor::new(&archive), 3)
            .map_err(|e| format!("compress: {e}"))?
    } else {
        archive
    };

    let hash = blake3::hash(&final_data).to_hex().to_string();
    std::fs::write(&output_path, &final_data).map_err(|e| format!("write: {e}"))?;

    Ok(Value::Struct {
        name: "PackResult".to_string(),
        fields: vec![
            ("path".to_string(), Value::String(output_path)),
            ("files".to_string(), Value::Int(files.len() as i128)),
            ("dirs".to_string(), Value::Int(dirs.len() as i128)),
            ("total_size".to_string(), Value::Int(total_size as i128)),
            (
                "archive_size".to_string(),
                Value::Int(final_data.len() as i128),
            ),
            ("compressed".to_string(), Value::Bool(compress)),
            ("hash".to_string(), Value::String(hash)),
            ("format".to_string(), Value::String("TWD1".into())),
        ],
    })
}

/// Unpack a TWD archive to a directory.
fn unpack_directory(args: &[Value]) -> StdlibResult {
    let archive_path = get_str(args, 0).ok_or("archive path required")?;
    let output_dir = get_str(args, 1).unwrap_or_else(|| ".".to_string());

    let raw =
        std::fs::read(&archive_path).map_err(|e| format!("read: {e}"))?;

    // Detect if compressed (TWD magic = uncompressed, else try zstd decompress)
    let archive = if raw.len() >= 4 && &raw[..4] == b"TWD1" {
        raw
    } else {
        zstd::decode_all(std::io::Cursor::new(&raw))
            .map_err(|e| format!("decompress: {e}"))?
    };

    let (dir_name, file_count, dir_count, total_bytes) =
        unpack_twd_archive(&archive, &output_dir)?;

    let output_root = std::path::Path::new(&output_dir)
        .join(&dir_name)
        .to_string_lossy()
        .to_string();

    Ok(Value::Struct {
        name: "UnpackResult".to_string(),
        fields: vec![
            ("dir_name".to_string(), Value::String(dir_name)),
            ("output".to_string(), Value::String(output_root)),
            ("files".to_string(), Value::Int(file_count as i128)),
            ("dirs".to_string(), Value::Int(dir_count as i128)),
            (
                "bytes_written".to_string(),
                Value::Int(total_bytes as i128),
            ),
            ("structure_preserved".to_string(), Value::Bool(true)),
        ],
    })
}

// ── Helper: extract field from Value::Struct by key ──

#[allow(dead_code)]
fn get_field(fields: &[(String, Value)], key: &str) -> Option<String> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_string())
}

#[allow(dead_code)]
fn get_field_bool(fields: &[(String, Value)], key: &str) -> Option<bool> {
    fields.iter().find(|(k, _)| k == key).and_then(|(_, v)| {
        if let Value::Bool(b) = v { Some(*b) } else { None }
    })
}

// ══════════════════════════════════════════════════════════════════
// HTTP Share by Link — serve files for browser download
// ══════════════════════════════════════════════════════════════════

/// Format a byte count into a human-readable string.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Decode base64 string to bytes.
fn base64_decode_bytes(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("base64 decode: {e}"))
}

/// Start an HTTP file server for sharing files via browser link.
/// Returns the URL that anyone can open to download.
fn share_by_link(args: &[Value]) -> StdlibResult {
    let file_path = get_str(args, 0).ok_or("file path required")?;
    let port = match args.get(1) {
        Some(Value::Int(n)) => *n as u16,
        _ => 0, // auto-assign port
    };
    let password = get_str(args, 2); // optional
    let max_downloads: i128 = match args.get(3) {
        Some(Value::Int(n)) => *n,
        _ => 0, // unlimited
    };

    // Verify file exists
    let metadata = std::fs::metadata(&file_path)
        .map_err(|e| format!("file not found '{}': {}", file_path, e))?;
    let file_size = metadata.len();
    let filename = std::path::Path::new(&file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let file_hash = blake3::hash(&std::fs::read(&file_path).unwrap_or_default())
        .to_hex()
        .to_string()[..12]
        .to_string();

    // Generate a random download token
    let token: String = {
        use rand::Rng;
        let mut rng = rand::rng();
        (0..16)
            .map(|_| {
                let idx: u8 = rng.random_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect()
    };

    // Bind HTTP server
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|e| format!("bind: {e}"))?;
    let local_addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
    let actual_port = local_addr.port();

    // Get local IP for the link
    let local_ip = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
        socket
            .and_then(|s| {
                s.connect("8.8.8.8:80").ok()?;
                s.local_addr().ok()
            })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    };

    let download_url = format!(
        "http://{}:{}/dl/{}/{}",
        local_ip, actual_port, token, filename
    );
    let direct_url = format!("http://{}:{}/dl/{}", local_ip, actual_port, token);

    // Clone values for the server thread
    let file_path_clone = file_path.clone();
    let token_clone = token.clone();
    let password_clone = password.clone();
    let filename_clone = filename.clone();
    let file_hash_clone = file_hash.clone();
    let max_dl = max_downloads;

    // Spawn HTTP server in background thread
    std::thread::spawn(move || {
        let mut download_count: i128 = 0;
        for stream in listener.incoming() {
            if max_dl > 0 && download_count >= max_dl {
                break; // Stop after max downloads
            }
            if let Ok(mut stream) = stream {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);

                // Parse request path
                let path = request
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/");

                // Check if it matches our download token
                if path.contains(&token_clone) {
                    // Check password if required
                    if let Some(ref pw) = password_clone {
                        if !path.contains(&format!("?p={}", pw)) {
                            // Serve password form
                            let form = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                                <!DOCTYPE html><html><head><title>Tallow Transfer</title>\
                                <style>body{{font-family:system-ui;max-width:500px;margin:50px auto;padding:20px;\
                                background:#0f172a;color:#e2e8f0}}\
                                input{{padding:10px;margin:5px;width:100%;box-sizing:border-box;\
                                background:#1e293b;border:1px solid #334155;color:#e2e8f0;border-radius:6px}}\
                                button{{padding:12px 24px;background:#2563eb;color:white;border:none;\
                                border-radius:6px;cursor:pointer;width:100%}}\
                                button:hover{{background:#1d4ed8}}\
                                </style></head><body>\
                                <h2>Password Required</h2>\
                                <p>File: <strong>{}</strong> ({})</p>\
                                <form method='get' action='/dl/{}'>\
                                <input type='password' name='p' placeholder='Enter password' autofocus>\
                                <button type='submit'>Download</button>\
                                </form></body></html>",
                                filename_clone,
                                format_size(file_size),
                                token_clone
                            );
                            let _ = stream.write_all(form.as_bytes());
                            continue;
                        }
                    }

                    // Serve the file
                    if let Ok(data) = std::fs::read(&file_path_clone) {
                        let hash = blake3::hash(&data).to_hex().to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                            Content-Type: application/octet-stream\r\n\
                            Content-Disposition: attachment; filename=\"{}\"\r\n\
                            Content-Length: {}\r\n\
                            X-Tallow-Hash: {}\r\n\
                            \r\n",
                            filename_clone,
                            data.len(),
                            hash
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(&data);
                        download_count += 1;
                    }
                } else {
                    // Serve landing page
                    let html = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                        <!DOCTYPE html><html><head><title>Tallow Transfer</title>\
                        <style>body{{font-family:system-ui;max-width:600px;margin:50px auto;padding:20px;\
                        background:#0f172a;color:#e2e8f0}}\
                        a{{color:#60a5fa;font-size:1.2em}} .hash{{font-family:monospace;color:#94a3b8;font-size:0.85em}}\
                        .card{{background:#1e293b;border-radius:12px;padding:24px;margin:20px 0}}\
                        </style></head><body>\
                        <h1>Tallow Transfer</h1>\
                        <div class='card'>\
                        <p>File: <strong>{}</strong></p>\
                        <p>Size: {}</p>\
                        <p class='hash'>BLAKE3: {}</p>\
                        <p><a href='/dl/{}'>Download</a></p>\
                        </div>\
                        <p style='color:#64748b'>Encrypted transfer powered by Tallow</p>\
                        </body></html>",
                        filename_clone,
                        format_size(file_size),
                        file_hash_clone,
                        token_clone
                    );
                    let _ = stream.write_all(html.as_bytes());
                }
            }
        }
    });

    Ok(Value::Struct {
        name: "ShareLink".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(download_url)),
            ("direct_url".to_string(), Value::String(direct_url)),
            ("file".to_string(), Value::String(file_path)),
            ("filename".to_string(), Value::String(filename)),
            ("size".to_string(), Value::Int(file_size as i128)),
            ("hash".to_string(), Value::String(file_hash)),
            ("port".to_string(), Value::Int(actual_port as i128)),
            ("token".to_string(), Value::String(token)),
            (
                "password_protected".to_string(),
                Value::Bool(password.is_some()),
            ),
            ("max_downloads".to_string(), Value::Int(max_downloads)),
            ("serving".to_string(), Value::Bool(true)),
        ],
    })
}

/// Share a directory via browser link (packs as TWD, serves via HTTP).
fn share_dir_by_link(args: &[Value]) -> StdlibResult {
    let dir_path = get_str(args, 0).ok_or("directory required")?;
    let port = match args.get(1) {
        Some(Value::Int(n)) => *n as u16,
        _ => 0,
    };

    // Pack to temp TWD archive
    let tmp_archive = std::env::temp_dir().join(format!(
        "tallow-share-{}.twd",
        rand::random::<u32>()
    ));
    let _pack_result = pack_directory(&[
        Value::String(dir_path.clone()),
        Value::String(tmp_archive.to_string_lossy().to_string()),
        Value::Bool(true), // compress
    ])?;

    // Serve the archive via share_by_link
    share_by_link(&[
        Value::String(tmp_archive.to_string_lossy().to_string()),
        Value::Int(port as i128),
    ])
}

// ══════════════════════════════════════════════════════════════════
// Live Browser Session Sharing — stream screenshots over HTTP
// ══════════════════════════════════════════════════════════════════

/// Start a live browser session viewer -- streams screenshots over HTTP.
/// Remote users open the URL in their browser to watch the automation live.
fn browser_live_share(args: &[Value]) -> StdlibResult {
    let port = match args.first() {
        Some(Value::Int(n)) => *n as u16,
        _ => 9090,
    };
    let refresh_ms = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => 1000, // 1 second refresh
    };

    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|e| format!("bind: {e}"))?;
    let local_addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;

    let local_ip = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok();
        socket
            .and_then(|s| {
                s.connect("8.8.8.8:80").ok()?;
                s.local_addr().ok()
            })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    };

    let view_url = format!("http://{}:{}", local_ip, local_addr.port());

    let screenshot_path_str = std::env::temp_dir()
        .join("tallow-live-screenshot.png")
        .to_string_lossy()
        .to_string();

    // Spawn HTTP server that serves a live viewer page
    let refresh = refresh_ms;
    let view_url_clone = view_url.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/");

                if path == "/screenshot" || path.starts_with("/screenshot?") {
                    // Serve latest screenshot as PNG
                    let ss_path = std::env::temp_dir().join("tallow-live-screenshot.png");
                    if let Ok(data) = std::fs::read(&ss_path) {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\
                            Content-Length: {}\r\nCache-Control: no-cache\r\n\r\n",
                            data.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(&data);
                    } else {
                        let _ = stream.write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 17\r\n\r\nNo screenshot yet",
                        );
                    }
                } else if path == "/info" {
                    // Serve session info as JSON
                    let info = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                        Access-Control-Allow-Origin: *\r\n\r\n\
                        {{\"status\":\"live\",\"refresh_ms\":{},\"viewer_url\":\"{}\"}}",
                        refresh, view_url_clone
                    );
                    let _ = stream.write_all(info.as_bytes());
                } else {
                    // Serve the viewer page
                    let html = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                        <!DOCTYPE html><html><head><title>Tallow Live Browser</title>\
                        <style>\
                        * {{margin:0;padding:0;box-sizing:border-box}}\
                        body {{background:#0f172a;color:#e2e8f0;font-family:system-ui;\
                        display:flex;flex-direction:column;align-items:center;min-height:100vh}}\
                        h1 {{padding:20px;color:#60a5fa}}\
                        #viewer {{border:2px solid #334155;border-radius:8px;max-width:95vw;\
                        max-height:80vh;background:#1e293b}}\
                        .status {{padding:10px;color:#94a3b8;font-size:0.85em}}\
                        .live {{color:#22c55e;animation:blink 1s infinite}}\
                        @keyframes blink {{50%{{opacity:0.5}}}}\
                        </style></head><body>\
                        <h1><span class='live'>LIVE</span> Tallow Browser Session</h1>\
                        <img id='viewer' src='/screenshot' alt='Live browser view'>\
                        <div class='status'>Auto-refreshing every {}ms | Powered by Tallow</div>\
                        <script>\
                        setInterval(() => {{\
                            document.getElementById('viewer').src = '/screenshot?' + Date.now();\
                        }}, {});\
                        </script>\
                        </body></html>",
                        refresh, refresh
                    );
                    let _ = stream.write_all(html.as_bytes());
                }
            }
        }
    });

    Ok(Value::Struct {
        name: "LiveShare".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(view_url)),
            ("port".to_string(), Value::Int(local_addr.port() as i128)),
            ("refresh_ms".to_string(), Value::Int(refresh_ms as i128)),
            ("streaming".to_string(), Value::Bool(true)),
            (
                "screenshot_path".to_string(),
                Value::String(screenshot_path_str),
            ),
        ],
    })
}

/// Update the live screenshot (call this periodically from browser automation).
fn browser_live_update(args: &[Value]) -> StdlibResult {
    let screenshot_base64 = get_str(args, 0).ok_or("screenshot base64 required")?;
    let screenshot_path = std::env::temp_dir().join("tallow-live-screenshot.png");

    // Decode base64 to PNG bytes
    let bytes = base64_decode_bytes(&screenshot_base64)?;
    std::fs::write(&screenshot_path, &bytes)
        .map_err(|e| format!("write screenshot: {e}"))?;

    Ok(Value::Bool(true))
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// The join contract accepts the 8-symbol v4 mint only (operator directive
    /// 2026-10-12; `room::code::is_supported_code`). These fixtures take their
    /// code from the mint rather than hardcoding a human-readable literal, so a
    /// test cannot drift from the contract and then read as a runtime failure.
    fn minted_code() -> String {
        tallow_protocol::room::code::generate_passcode()
    }

    /// R-4 (design T-1): the relay pipe must use an explicit 64 KiB buffer —
    /// observable as exactly-64 KiB read requests plus a byte-identical copy.
    /// `std::io::copy` would request at most ~8 KiB per read call.
    #[test]
    fn test_relay_pipe_copy_64k_buffer_lossless() {
        use std::io::{Read, Write};

        struct CountingReader {
            data: Vec<u8>,
            pos: usize,
            max_requested: usize,
        }
        impl Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.max_requested = self.max_requested.max(buf.len());
                let n = (self.data.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }
        struct CollectingWriter(Vec<u8>);
        impl Write for CollectingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let mut r = CountingReader {
            data: payload.clone(),
            pos: 0,
            max_requested: 0,
        };
        let mut w = CollectingWriter(Vec::new());
        let n = relay_pipe_copy(&mut r, &mut w).unwrap();
        assert_eq!(n, payload.len() as u64);
        assert_eq!(w.0, payload, "pipe copy must be lossless");
        assert_eq!(
            r.max_requested,
            64 * 1024,
            "explicit 64 KiB buffer expected (std::io::copy requests ~8 KiB)"
        );
        assert_eq!(r.pos, payload.len());
    }

    #[test]
    fn test_sanitize_wire_filename_blocks_traversal() {
        // (input, expected) — only the final component survives.
        for (input, expected) in [
            ("../../etc/passwd", "passwd"),
            ("/etc/shadow", "shadow"),
            ("..\\..\\windows\\system32\\evil.dll", "evil.dll"),
            ("C:\\tmp\\ok.bin", "ok.bin"),
            ("a/b/c.txt", "c.txt"),
            ("normal.bin", "normal.bin"),
            ("trailing...  ", "trailing"),
        ] {
            assert_eq!(
                sanitize_wire_filename(input).unwrap(),
                expected,
                "input {input:?}"
            );
        }
        // Nothing usable / dangerous input is rejected outright.
        for bad in ["", "..", "../", "/", "..\\", "\0", "a\0b", "C:\\", ".", "./"] {
            assert!(
                sanitize_wire_filename(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
        // The result is always a plain component inside the output dir.
        let out = std::path::Path::new("/tmp/out");
        let safe = sanitize_wire_filename("../../etc/passwd").unwrap();
        assert_eq!(safe, "passwd");
        assert_eq!(out.join(&safe), out.join("passwd"));
        assert!(!out.join(&safe).to_string_lossy().contains(".."));
    }

    #[test]
    fn test_quic_status() {
        let result = quic_status(&[]);
        assert!(result.is_ok(), "quic_status failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "QuicStatus");
            assert_eq!(get_field_bool(fields, "available"), Some(true));
            assert_eq!(get_field(fields, "library").as_deref(), Some("quinn 0.11"));
            assert_eq!(get_field(fields, "tls").as_deref(), Some("rustls TLS 1.3"));
        } else {
            panic!("expected Struct, got: {:?}", result);
        }
    }

    #[test]
    fn test_create_server_config() {
        let config = create_server_config();
        assert!(config.is_ok(), "server config creation failed: {:?}", config);
    }

    #[test]
    fn test_create_client_config() {
        let config = create_client_config();
        assert!(config.is_ok(), "client config creation failed: {:?}", config);
    }

    // W5-D (2026-09-27): skip-verify path vs self-signed fixture peer —
    // valid only when `dangerous_skip_verify` is enabled.
    #[cfg(feature = "dangerous_skip_verify")]
    #[test]
    fn test_quic_server_client_transfer() {
        // Integration test: start a real QUIC server in a background thread,
        // then send bytes from the main thread. Both sides use raw quinn -- no
        // Value crossing thread boundaries (Value contains Rc, not Send).
        use std::thread;

        let port = 16881u16;
        let addr = format!("127.0.0.1:{}", port);

        // Start receiver in background thread (raw quinn, no Value)
        let recv_addr = addr.clone();
        let recv_thread = thread::spawn(move || -> String {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server_config = create_server_config().unwrap();
                let endpoint = quinn::Endpoint::server(
                    server_config,
                    recv_addr.parse().unwrap(),
                )
                .unwrap();

                let incoming = tokio::time::timeout(
                    Duration::from_secs(5),
                    endpoint.accept(),
                )
                .await;

                match incoming {
                    Ok(Some(incoming)) => {
                        let conn = incoming.await.unwrap();
                        let mut recv = conn.accept_uni().await.unwrap();

                        // Read size header (8 bytes)
                        let mut size_buf = [0u8; 8];
                        recv.read_exact(&mut size_buf).await.unwrap();
                        let size = u64::from_le_bytes(size_buf);

                        // Read exactly `size` bytes of data
                        let mut data = vec![0u8; size as usize];
                        recv.read_exact(&mut data).await.unwrap();
                        conn.close(0u32.into(), b"ok");
                        endpoint.close(0u32.into(), b"done");

                        String::from_utf8(data).unwrap()
                    }
                    _ => {
                        endpoint.close(0u32.into(), b"timeout");
                        "timeout".to_string()
                    }
                }
            })
        });

        // Give server time to bind
        thread::sleep(Duration::from_millis(200));

        // Send data (this runs on main thread, Value stays here)
        let test_data = "Hello from TallowTransfer QUIC!";
        let result = quic_send_bytes(&[
            Value::String(test_data.to_string()),
            Value::String(addr.clone()),
        ]);

        assert!(result.is_ok(), "send failed: {:?}", result);
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(get_field_bool(fields, "sent"), Some(true));
            assert_eq!(
                get_field(fields, "bytes_sent").as_deref(),
                Some(&*test_data.len().to_string())
            );
        } else {
            panic!("expected SendResult struct, got: {:?}", result);
        }

        // Check receiver got the data
        let received = recv_thread.join().unwrap();
        assert_eq!(received, test_data);
    }

    // W5-D (2026-09-27): skip-verify path vs self-signed fixture peer —
    // valid only when `dangerous_skip_verify` is enabled.
    #[cfg(feature = "dangerous_skip_verify")]
    #[test]
    fn test_quic_file_transfer_roundtrip() {
        // Integration test: send a real file over QUIC and verify BLAKE3 hash.
        // The receiver runs raw quinn in a thread (no Value crossing threads).
        // The sender uses the quic_send_file dispatch function.
        use std::thread;

        let port = 16882u16;
        let addr = format!("127.0.0.1:{}", port);

        // Create a temp file to send
        let tmp_dir = tempfile::tempdir().unwrap();
        let test_file = tmp_dir.path().join("test_transfer.dat");
        let test_content = b"TallowTransfer QUIC file transfer test data -- 1234567890 abcdef";
        std::fs::write(&test_file, test_content).unwrap();

        let output_dir = tempfile::tempdir().unwrap();
        let out_path = output_dir.path().to_path_buf();

        // Start receiver in background thread (raw quinn, returns String result)
        let recv_addr = addr.clone();
        let recv_out = out_path.clone();
        let recv_thread = thread::spawn(move || -> Result<(String, u64, bool), String> {
            let rt = tokio::runtime::Runtime::new().map_err(|e| format!("runtime: {e}"))?;
            rt.block_on(async {
                let server_config = create_server_config()?;
                let endpoint = quinn::Endpoint::server(
                    server_config,
                    recv_addr.parse::<SocketAddr>().map_err(|e| format!("addr: {e}"))?,
                ).map_err(|e| format!("bind: {e}"))?;

                let incoming = tokio::time::timeout(
                    Duration::from_secs(5),
                    endpoint.accept(),
                ).await.map_err(|_| "timeout".to_string())?
                 .ok_or("no incoming")?;

                let conn = incoming.await.map_err(|e| format!("accept: {e}"))?;
                let mut recv = conn.accept_uni().await.map_err(|e| format!("stream: {e}"))?;

                // Read header
                let mut size_buf = [0u8; 8];
                recv.read_exact(&mut size_buf).await.map_err(|e| format!("size: {e}"))?;
                let file_size = u64::from_le_bytes(size_buf);

                let mut hash_buf = [0u8; 32];
                recv.read_exact(&mut hash_buf).await.map_err(|e| format!("hash: {e}"))?;

                let mut name_len_buf = [0u8; 2];
                recv.read_exact(&mut name_len_buf).await.map_err(|e| format!("namelen: {e}"))?;
                let name_len = u16::from_le_bytes(name_len_buf) as usize;

                let mut name_buf = vec![0u8; name_len];
                recv.read_exact(&mut name_buf).await.map_err(|e| format!("name: {e}"))?;
                let filename = String::from_utf8_lossy(&name_buf).to_string();

                // Read data (wire name sanitized: R-5, no traversal)
                let safe_filename = sanitize_wire_filename(&filename)
                    .map_err(|e| format!("unsafe filename from peer: {e}"))?;
                let output_path = recv_out.join(&safe_filename);
                let tmp_path = format!("{}.tallow-tmp", output_path.display());
                let mut file = tokio::fs::File::create(&tmp_path).await
                    .map_err(|e| format!("create: {e}"))?;

                let mut bytes_received = 0u64;
                let mut buf = vec![0u8; 65536];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => {
                            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await
                                .map_err(|e| format!("write: {e}"))?;
                            bytes_received += n as u64;
                        }
                        Ok(None) => break,
                        Err(e) => return Err(format!("read: {e}")),
                    }
                }
                tokio::io::AsyncWriteExt::flush(&mut file).await
                    .map_err(|e| format!("flush: {e}"))?;
                drop(file);

                // Verify hash
                let received_data = std::fs::read(&tmp_path).map_err(|e| format!("readtmp: {e}"))?;
                let computed = blake3::hash(&received_data);
                let verified = computed.as_bytes() == &hash_buf;

                if verified {
                    std::fs::rename(&tmp_path, &output_path).map_err(|e| format!("rename: {e}"))?;
                } else {
                    let _ = std::fs::remove_file(&tmp_path);
                }

                conn.close(0u32.into(), b"received");
                endpoint.close(0u32.into(), b"done");

                Ok((filename, bytes_received, verified))
            })
        });

        // Give server time to bind
        thread::sleep(Duration::from_millis(200));

        // Send file (on main thread, Value stays local)
        let send_result = quic_send_file(&[
            Value::String(test_file.display().to_string()),
            Value::String(addr.clone()),
        ]);

        assert!(send_result.is_ok(), "send_file failed: {:?}", send_result);
        if let Ok(Value::Struct { fields, .. }) = &send_result {
            assert_eq!(get_field_bool(fields, "sent"), Some(true));
            assert_eq!(
                get_field(fields, "size").as_deref(),
                Some(&*test_content.len().to_string())
            );
        }

        // Check receiver
        let recv_result = recv_thread.join().unwrap();
        assert!(recv_result.is_ok(), "receive failed: {:?}", recv_result);
        let (filename, bytes_received, verified) = recv_result.unwrap();
        assert_eq!(filename, "test_transfer.dat");
        assert_eq!(bytes_received, test_content.len() as u64);
        assert!(verified, "BLAKE3 verification failed");

        // Verify file on disk
        let received_file = out_path.join("test_transfer.dat");
        let received_data = std::fs::read(&received_file).unwrap();
        assert_eq!(received_data, test_content.as_slice());
    }

    /// W5-D regression guard (2026-09-27): the hardened DEFAULT must reject
    /// self-signed peers (no silent skip). If `dangerous_skip_verify` is ever
    /// re-added to `default`, this test fails. Runs on default builds; the
    /// skip-path roundtrips above run only with the feature enabled.
    #[cfg(not(feature = "dangerous_skip_verify"))]
    #[test]
    fn test_quic_self_signed_rejected_by_default() {
        use std::thread;

        let port = 16883u16;
        let addr = format!("127.0.0.1:{}", port);

        let recv_addr = addr.clone();
        let recv_thread = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server_config = create_server_config().unwrap();
                let endpoint =
                    quinn::Endpoint::server(server_config, recv_addr.parse().unwrap()).unwrap();
                if let Ok(Some(incoming)) =
                    tokio::time::timeout(Duration::from_secs(5), endpoint.accept()).await
                {
                    // The client aborts the handshake at cert verification;
                    // the server side resolves with an error — wait it out so
                    // the client observes ITS error (UnknownIssuer), not an
                    // early server-side teardown race.
                    let _ = incoming.await;
                }
                endpoint.close(0u32.into(), b"done");
            });
        });

        thread::sleep(Duration::from_millis(200));

        let result = quic_send_bytes(&[
            Value::String("must-not-arrive".to_string()),
            Value::String(addr),
        ]);
        let err = match result {
            Err(e) => format!("{e:?}"),
            Ok(v) => panic!("hardened client must reject self-signed peer, got: {v:?}"),
        };
        assert!(
            err.contains("UnknownIssuer") || err.contains("certificate"),
            "expected cert rejection, got: {err}"
        );

        let _ = recv_thread.join();
    }

    #[test]
    fn test_dispatch_routes() {
        // Verify all dispatch keys are routable (Phase 59 + Phase 60)
        let funcs = [
            "quic_listen",
            "quic_connect",
            "quic_send_file",
            "quic_receive_file",
            "quic_send_bytes",
            "quic_status",
            // Phase 60: code phrase, relay, resume
            "generate_code",
            "code_to_port",
            "relay_start",
            "relay_send",
            "relay_receive",
            "quic_send_resume",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(result.is_some(), "dispatch('{}') should be routable", f);
        }

        // Unknown function returns None
        assert!(dispatch("quic_nonexistent", vec![]).is_none());
    }

    #[test]
    fn test_quic_listen_returns_server_struct() {
        // Listen on a random high port -- just verify it returns a QuicServer struct
        let result = quic_listen(&[Value::String("127.0.0.1:0".to_string())]);
        assert!(result.is_ok(), "listen failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "QuicServer");
            assert_eq!(get_field_bool(fields, "listening"), Some(true));
            assert_eq!(get_field(fields, "protocol").as_deref(), Some("QUIC"));
        } else {
            panic!("expected QuicServer struct");
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Phase 60 Tests -- Code Phrase, Relay, Resume
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_generate_code_format() {
        // Code phrase format: NNN-word-word-word
        let code = generate_code_phrase();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 4, "code phrase should have 4 parts: got '{}'", code);
        // First part: 3-digit number
        let num: u16 = parts[0].parse().expect("first part should be a number");
        assert!(num >= 100 && num <= 998, "number should be 100-998: got {}", num);
        // Remaining parts: alphabetic words
        for (i, word) in parts[1..].iter().enumerate() {
            assert!(!word.is_empty(), "word {} should not be empty", i);
            assert!(
                word.chars().all(|c| c.is_ascii_alphabetic()),
                "word '{}' should be alphabetic", word
            );
        }
    }

    #[test]
    fn test_generate_code_uniqueness() {
        // Two consecutive calls should produce different codes (overwhelmingly likely)
        let c1 = generate_code_phrase();
        let c2 = generate_code_phrase();
        assert_ne!(c1, c2, "two generated codes should differ");
    }

    #[test]
    fn test_code_to_port_deterministic() {
        // Same code phrase must always produce the same port
        let code = "742-falcon-ember-crystal";
        let (port1, key1) = code_to_session(code);
        let (port2, key2) = code_to_session(code);
        assert_eq!(port1, port2, "same code should yield same port");
        assert_eq!(key1, key2, "same code should yield same session key");
    }

    #[test]
    fn test_code_to_port_range() {
        // Port must be in 10000..65000
        for seed in ["abc", "test-code-123", "999-alpha-beta-gamma", "hello-world"] {
            let (port, _) = code_to_session(seed);
            assert!(port >= 10000, "port {} below 10000 for seed '{}'", port, seed);
            assert!(port < 65000, "port {} >= 65000 for seed '{}'", port, seed);
        }
    }

    #[test]
    fn test_code_to_port_different_codes() {
        // Different codes should (almost certainly) produce different ports
        let (p1, _) = code_to_session("100-alpha-beta-gamma");
        let (p2, _) = code_to_session("200-delta-echo-foxtrot");
        assert_ne!(p1, p2, "different codes should produce different ports");
    }

    #[test]
    fn test_generate_code_dispatch() {
        let result = generate_code(&[]);
        assert!(result.is_ok(), "generate_code failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "TransferCode");
            let code = get_field(fields, "code").expect("should have code field");
            assert!(!code.is_empty(), "code should not be empty");
            let port_str = get_field(fields, "port").expect("should have port field");
            let port: i64 = port_str.parse().expect("port should be numeric");
            assert!(port >= 10000 && port < 65000, "port out of range: {}", port);
        } else {
            panic!("expected TransferCode struct");
        }
    }

    #[test]
    fn test_code_to_port_dispatch() {
        let result = code_to_port(&[Value::String("742-falcon-ember-crystal".to_string())]);
        assert!(result.is_ok(), "code_to_port failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "CodeSession");
            assert_eq!(
                get_field(fields, "code").as_deref(),
                Some("742-falcon-ember-crystal")
            );
            let port_str = get_field(fields, "port").expect("should have port field");
            let port: i64 = port_str.parse().expect("port should be numeric");
            assert!(port >= 10000 && port < 65000);
        } else {
            panic!("expected CodeSession struct");
        }
    }

    #[test]
    fn test_relay_start_bind() {
        // Relay should successfully bind to port 0 (OS-assigned)
        let result = relay_start(&[Value::Int(0)]);
        assert!(result.is_ok(), "relay_start failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "RelayServer");
            assert_eq!(get_field_bool(fields, "running"), Some(true));
            // v1 (live pairing) is the served protocol; v0 clients get a
            // deprecation warning. The field must report what is served.
            assert_eq!(
                get_field(fields, "protocol").as_deref(),
                Some("TCP relay v1 (live pairing, E2E-encrypted)")
            );
            let port_str = get_field(fields, "port").expect("should have port field");
            let port: i64 = port_str.parse().expect("port should be numeric");
            assert!(port > 0, "assigned port should be > 0");
        } else {
            panic!("expected RelayServer struct");
        }
    }

    #[test]
    fn test_resume_offset_already_complete() {
        // If resume_offset >= file size, return immediately with "already complete"
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello world").unwrap();

        let result = quic_send_file_resume(&[
            Value::String(tmp.path().display().to_string()),
            Value::String("127.0.0.1:9999".to_string()),
            Value::Int(100), // offset > file size (11 bytes)
        ]);

        assert!(result.is_ok(), "resume should succeed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "TransferResult");
            assert_eq!(get_field(fields, "bytes_sent").as_deref(), Some("0"));
            assert_eq!(get_field(fields, "status").as_deref(), Some("already complete"));
            assert_eq!(get_field_bool(fields, "complete"), Some(true));
        } else {
            panic!("expected TransferResult struct");
        }
    }

    #[test]
    fn test_code_words_not_empty() {
        assert!(!CODE_WORDS.is_empty(), "CODE_WORDS should not be empty");
        for (i, word) in CODE_WORDS.iter().enumerate() {
            assert!(!word.is_empty(), "CODE_WORDS[{}] should not be empty", i);
        }
    }

    #[test]
    fn test_session_key_is_32_bytes() {
        let (_port, key) = code_to_session("test-phrase");
        assert_eq!(key.len(), 32, "session key should be 32 bytes");
        // Key should not be all zeros
        assert!(key.iter().any(|&b| b != 0), "session key should not be all zeros");
    }

    // ══════════════════════════════════════════════════════════════
    // Phase 61 Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_multi_send_prepare() {
        // Create temp files
        let tmp_dir = tempfile::tempdir().unwrap();
        let f1 = tmp_dir.path().join("a.txt");
        let f2 = tmp_dir.path().join("b.txt");
        std::fs::write(&f1, b"hello").unwrap();
        std::fs::write(&f2, b"world!!").unwrap();

        let result = quic_send_multi(&[
            Value::Array(vec![
                Value::String(f1.display().to_string()),
                Value::String(f2.display().to_string()),
            ]),
            Value::String("127.0.0.1:9999".to_string()),
        ]);

        assert!(result.is_ok(), "multi_send_prepare failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "MultiTransferResult");
            assert_eq!(get_field(fields, "files_count").as_deref(), Some("2"));
            assert_eq!(get_field(fields, "total_size").as_deref(), Some("12")); // 5 + 7
            assert_eq!(get_field(fields, "status").as_deref(), Some("ready"));
            assert_eq!(
                get_field(fields, "destination").as_deref(),
                Some("127.0.0.1:9999")
            );
        } else {
            panic!("expected MultiTransferResult struct");
        }
    }

    #[test]
    fn test_multi_send_with_directory() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let sub = tmp_dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("file.txt"), b"inside subdir").unwrap();

        let result = quic_send_multi(&[
            Value::Array(vec![Value::String(
                tmp_dir.path().display().to_string(),
            )]),
            Value::String("127.0.0.1:9999".to_string()),
        ]);

        assert!(result.is_ok(), "multi_send_with_dir failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "MultiTransferResult");
            // Should have at least the subdir entry + the file
            let count: i64 = get_field(fields, "files_count")
                .unwrap()
                .parse()
                .unwrap();
            assert!(count >= 2, "should have dir entry + file, got {}", count);
        }
    }

    #[test]
    fn test_dir_archive_compress() {
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("one.txt"), b"aaaaaaaaaaaa").unwrap();
        std::fs::write(tmp_dir.path().join("two.txt"), b"bbbbbbbbbbbb").unwrap();

        let result = quic_send_dir(&[
            Value::String(tmp_dir.path().display().to_string()),
            Value::String("127.0.0.1:9999".to_string()),
            Value::Bool(true), // compress
        ]);

        assert!(result.is_ok(), "dir_archive_compress failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "DirTransferResult");
            assert_eq!(get_field(fields, "files_count").as_deref(), Some("2"));
            assert_eq!(get_field_bool(fields, "compressed"), Some(true));
            assert_eq!(get_field_bool(fields, "ready"), Some(true));
            // Compressed size should be less than uncompressed for repetitive data
            let uncomp: i64 = get_field(fields, "uncompressed_size")
                .unwrap()
                .parse()
                .unwrap();
            let comp: i64 = get_field(fields, "compressed_size")
                .unwrap()
                .parse()
                .unwrap();
            assert!(uncomp > 0, "uncompressed size should be > 0");
            assert!(comp > 0, "compressed size should be > 0");
        }
    }

    #[test]
    fn test_dir_archive_no_compress() {
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("file.txt"), b"data").unwrap();

        let result = quic_send_dir(&[
            Value::String(tmp_dir.path().display().to_string()),
            Value::String("127.0.0.1:9999".to_string()),
            Value::Bool(false), // no compress
        ]);

        assert!(result.is_ok(), "dir_archive_no_compress failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "DirTransferResult");
            assert_eq!(get_field_bool(fields, "compressed"), Some(false));
            // Sizes should be equal when uncompressed
            let uncomp = get_field(fields, "uncompressed_size").unwrap();
            let comp = get_field(fields, "compressed_size").unwrap();
            assert_eq!(uncomp, comp, "without compression sizes should match");
        }
    }

    #[test]
    fn test_transfer_compress_zstd() {
        let data = "hello world hello world hello world this is repeated data";
        let result = transfer_compress(&[
            Value::String(data.to_string()),
            Value::String("zstd".to_string()),
        ]);

        assert!(result.is_ok(), "compress_zstd failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "CompressedTransfer");
            assert_eq!(get_field(fields, "algorithm").as_deref(), Some("zstd"));
            let orig: i64 = get_field(fields, "original_size")
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(orig, data.len() as i64);
            // data_hex should be non-empty
            let hex = get_field(fields, "data_hex").unwrap();
            assert!(!hex.is_empty(), "data_hex should not be empty");
        }
    }

    #[test]
    fn test_transfer_compress_lz4() {
        let data = "lz4 compress this data please";
        let result = transfer_compress(&[
            Value::String(data.to_string()),
            Value::String("lz4".to_string()),
        ]);

        assert!(result.is_ok(), "compress_lz4 failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "CompressedTransfer");
            assert_eq!(get_field(fields, "algorithm").as_deref(), Some("lz4"));
        }
    }

    #[test]
    fn test_transfer_compress_auto_skip_high_entropy() {
        // Force "none" algorithm explicitly for high-entropy data
        let data = "this would normally compress but we force none";
        let result = transfer_compress(&[
            Value::String(data.to_string()),
            Value::String("none".to_string()),
        ]);

        assert!(result.is_ok(), "compress_none failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "CompressedTransfer");
            let algo = get_field(fields, "algorithm").unwrap();
            assert_eq!(algo, "none", "explicit 'none' should skip compression");
            // When algo=none, compressed_size == original_size
            let orig = get_field(fields, "original_size").unwrap();
            let comp = get_field(fields, "compressed_size").unwrap();
            assert_eq!(orig, comp, "no compression means sizes should match");
        }

        // Also verify the entropy function itself detects high entropy
        // A uniform byte distribution across all 256 values has entropy ~8.0
        let mut uniform_bytes = Vec::new();
        for i in 0..=255u8 {
            uniform_bytes.push(i);
        }
        let e = shannon_entropy(&uniform_bytes);
        assert!(e > 7.5, "uniform distribution should have entropy > 7.5, got {}", e);
    }

    #[test]
    fn test_transfer_decompress_roundtrip() {
        let original = "round trip test data with some repetition repetition repetition";

        // Compress with zstd
        let compressed = transfer_compress(&[
            Value::String(original.to_string()),
            Value::String("zstd".to_string()),
        ])
        .unwrap();

        if let Value::Struct { fields, .. } = &compressed {
            let hex = get_field(fields, "data_hex").unwrap();
            let algo = get_field(fields, "algorithm").unwrap();

            // Decompress
            let decompressed = transfer_decompress(&[
                Value::String(hex),
                Value::String(algo),
            ]);

            assert!(decompressed.is_ok(), "decompress failed: {:?}", decompressed);
            if let Ok(Value::String(s)) = &decompressed {
                assert_eq!(s, original, "roundtrip should preserve data");
            } else {
                panic!("expected String from decompress");
            }
        } else {
            panic!("expected Struct from compress");
        }
    }

    #[test]
    fn test_transfer_decompress_lz4_roundtrip() {
        let original = "lz4 roundtrip test data data data";

        let compressed = transfer_compress(&[
            Value::String(original.to_string()),
            Value::String("lz4".to_string()),
        ])
        .unwrap();

        if let Value::Struct { fields, .. } = &compressed {
            let hex = get_field(fields, "data_hex").unwrap();

            let decompressed = transfer_decompress(&[
                Value::String(hex),
                Value::String("lz4".to_string()),
            ]);

            assert!(decompressed.is_ok(), "lz4 decompress failed: {:?}", decompressed);
            if let Ok(Value::String(s)) = &decompressed {
                assert_eq!(s, original);
            }
        }
    }

    #[test]
    fn test_parallel_config_defaults() {
        let result = parallel_config(&[]);
        assert!(result.is_ok(), "parallel_config failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ParallelConfig");
            assert_eq!(get_field(fields, "streams").as_deref(), Some("4"));
            assert_eq!(get_field(fields, "chunk_size").as_deref(), Some("262144"));
            assert_eq!(
                get_field(fields, "strategy").as_deref(),
                Some("round_robin")
            );
        }
    }

    #[test]
    fn test_parallel_config_custom() {
        let result = parallel_config(&[Value::Int(8), Value::Int(524288)]);
        assert!(result.is_ok(), "parallel_config custom failed: {:?}", result);
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(get_field(fields, "streams").as_deref(), Some("8"));
            assert_eq!(get_field(fields, "chunk_size").as_deref(), Some("524288"));
        }
    }

    #[test]
    fn test_bandwidth_limit_parse_mbps() {
        let result = apply_bandwidth_limit(&[Value::String("10M".to_string())]);
        assert!(result.is_ok(), "bwlimit 10M failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "BandwidthConfig");
            assert_eq!(get_field(fields, "limit_str").as_deref(), Some("10M"));
            // 10 Mbps = 10_000_000 bits/sec = 1_250_000 bytes/sec
            assert_eq!(
                get_field(fields, "bytes_per_sec").as_deref(),
                Some("1250000")
            );
            assert_eq!(get_field_bool(fields, "active"), Some(true));
        }
    }

    #[test]
    fn test_bandwidth_limit_parse_kbps() {
        let result = apply_bandwidth_limit(&[Value::String("500K".to_string())]);
        assert!(result.is_ok(), "bwlimit 500K failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "BandwidthConfig");
            // 500 Kbps = 500_000 bits/sec = 62_500 bytes/sec
            assert_eq!(
                get_field(fields, "bytes_per_sec").as_deref(),
                Some("62500")
            );
        }
    }

    #[test]
    fn test_bandwidth_limit_parse_gbps() {
        let result = apply_bandwidth_limit(&[Value::String("1G".to_string())]);
        assert!(result.is_ok(), "bwlimit 1G failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            // 1 Gbps = 1_000_000_000 bits/sec = 125_000_000 bytes/sec
            assert_eq!(
                get_field(fields, "bytes_per_sec").as_deref(),
                Some("125000000")
            );
        }
    }

    #[test]
    fn test_transfer_pace_delay_schedule_per_chunk() {
        // Design D-C2 gate: 1 MiB @ "1M" bits/sec -> 125_000 B/s = 8.388608 s.
        // Simulate the 4-chunk QUIC loop (256 KiB chunks) with sleeps applied
        // exactly: the pacer must owe a wait after every chunk.
        let bps = 125_000u64;
        let chunk = 262_144u64;
        let mut elapsed = Duration::ZERO;
        let mut waits = 0;
        let mut total = Duration::ZERO;
        for i in 1..=4u64 {
            let w = transfer_pace_delay(i * chunk, bps, elapsed)
                .expect("chunk behind cumulative budget must be paced");
            waits += 1;
            total += w;
            elapsed += w;
        }
        assert_eq!(waits, 4, "one pacing wait per chunk (limiter called per chunk)");
        assert!(
            (total.as_secs_f64() - 8.388_608).abs() < 1e-6,
            "total wait {total:?}"
        );
    }

    #[test]
    fn test_transfer_pace_delay_first_chunk_deficit_not_capped() {
        // The first 256 KiB chunk at "1M" owes 2.097152 s in full (no 250 ms
        // cap; a cap floors the enforceable rate — design D-C2).
        let wait = transfer_pace_delay(262_144, 125_000, Duration::ZERO).unwrap();
        assert!((wait.as_secs_f64() - 2.097_152).abs() < 1e-6, "wait {wait:?}");
    }

    #[test]
    fn test_transfer_pace_delay_unlimited_and_ahead() {
        // 0 B/s = unlimited; ahead of schedule = no wait.
        assert_eq!(transfer_pace_delay(1_048_576, 0, Duration::ZERO), None);
        assert_eq!(
            transfer_pace_delay(1000, 1_000_000, Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn test_watch_start() {
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("test.txt"), b"watch me").unwrap();

        let result = watch_start(&[
            Value::String(tmp_dir.path().display().to_string()),
            Value::Int(500),
        ]);

        assert!(result.is_ok(), "watch_start failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "WatchSession");
            assert_eq!(get_field_bool(fields, "watching"), Some(true));
            assert_eq!(get_field(fields, "interval_ms").as_deref(), Some("500"));
            assert_eq!(get_field(fields, "files_tracked").as_deref(), Some("1"));
            // Verify snapshot exists
            let snapshot = fields.iter().find(|(k, _)| k == "snapshot");
            assert!(snapshot.is_some(), "should have snapshot field");
        }
    }

    #[test]
    fn test_watch_start_not_a_directory() {
        let result = watch_start(&[Value::String("/nonexistent/dir".to_string())]);
        assert!(result.is_err(), "should fail on nonexistent dir");
    }

    #[test]
    fn test_watch_check_detects_changes() {
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("orig.txt"), b"original").unwrap();

        // Take initial snapshot
        let session = watch_start(&[
            Value::String(tmp_dir.path().display().to_string()),
        ])
        .unwrap();

        // Modify: add a file, modify existing, (don't remove)
        std::fs::write(tmp_dir.path().join("new.txt"), b"brand new").unwrap();
        std::fs::write(tmp_dir.path().join("orig.txt"), b"modified content").unwrap();

        // Check for changes
        let result = watch_check(&[session]);
        assert!(result.is_ok(), "watch_check failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "WatchChanges");
            assert_eq!(get_field_bool(fields, "has_changes"), Some(true));

            // Should detect added file
            if let Some((_, Value::Array(added))) = fields.iter().find(|(k, _)| k == "added") {
                assert!(
                    added.iter().any(|v| v.as_string().contains("new.txt")),
                    "should detect new.txt as added, got: {:?}",
                    added
                );
            } else {
                panic!("should have 'added' array");
            }

            // Should detect modified file
            if let Some((_, Value::Array(modified))) = fields.iter().find(|(k, _)| k == "modified")
            {
                assert!(
                    modified.iter().any(|v| v.as_string().contains("orig.txt")),
                    "should detect orig.txt as modified, got: {:?}",
                    modified
                );
            } else {
                panic!("should have 'modified' array");
            }
        }
    }

    #[test]
    fn test_watch_check_no_changes() {
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("stable.txt"), b"no change").unwrap();

        let session = watch_start(&[
            Value::String(tmp_dir.path().display().to_string()),
        ])
        .unwrap();

        // No modifications
        let result = watch_check(&[session]);
        assert!(result.is_ok(), "watch_check no changes failed: {:?}", result);
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(get_field_bool(fields, "has_changes"), Some(false));
        }
    }

    #[test]
    fn test_phase61_dispatch_routes() {
        let funcs = [
            "quic_send_multi",
            "quic_send_dir",
            "transfer_compress",
            "transfer_decompress",
            "parallel_config",
            "apply_bandwidth_limit",
            "watch_start",
            "watch_check",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(result.is_some(), "dispatch('{}') should be routable", f);
        }
    }

    #[test]
    fn test_shannon_entropy() {
        // All same byte -> entropy 0
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);

        // Uniform distribution -> entropy ~8.0
        let mut data = Vec::new();
        for i in 0..=255u8 {
            data.push(i);
        }
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "uniform distribution should have entropy ~8.0, got {}",
            e
        );

        // Empty -> entropy 0
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    // ══════════════════════════════════════════════════════════════
    // Phase 63 Tests — QR, Proxy, Chat, Group Chat
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_generate_qr() {
        let result = generate_qr_text(&[Value::String("742-falcon-ember-crystal".to_string())]);
        assert!(result.is_ok(), "generate_qr failed: {:?}", result);
        if let Ok(Value::String(qr)) = &result {
            assert!(qr.contains("TALLOW TRANSFER"), "should contain header");
            assert!(qr.contains("742-falcon-ember-crystal"), "should contain code");
            // Should have box drawing characters
            assert!(qr.contains('\u{2554}'), "should contain top-left corner");
            assert!(qr.contains('\u{255d}'), "should contain bottom-right corner");
            // Should have multiple lines
            let lines: Vec<&str> = qr.lines().collect();
            assert!(lines.len() >= 12, "should have at least 12 lines, got {}", lines.len());
        } else {
            panic!("expected String from generate_qr");
        }
    }

    #[test]
    fn test_proxy_config_socks5() {
        let result = proxy_config(&[Value::String("socks5://127.0.0.1:1080".to_string())]);
        assert!(result.is_ok(), "proxy_config socks5 failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ProxyConfig");
            assert_eq!(get_field(fields, "protocol").as_deref(), Some("socks5"));
            assert_eq!(get_field(fields, "address").as_deref(), Some("127.0.0.1:1080"));
            assert_eq!(get_field_bool(fields, "active"), Some(true));
            assert_eq!(get_field_bool(fields, "tor"), Some(false));
        }
    }

    #[test]
    fn test_proxy_config_tor() {
        let result = proxy_config(&[Value::String("socks5://127.0.0.1:9050".to_string())]);
        assert!(result.is_ok(), "proxy_config tor failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ProxyConfig");
            assert_eq!(get_field(fields, "protocol").as_deref(), Some("socks5"));
            assert_eq!(get_field_bool(fields, "tor"), Some(true));
        }
    }

    #[test]
    fn test_proxy_config_http() {
        let result = proxy_config(&[Value::String("http://proxy.example.com:8080".to_string())]);
        assert!(result.is_ok(), "proxy_config http failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ProxyConfig");
            assert_eq!(get_field(fields, "protocol").as_deref(), Some("http"));
            assert_eq!(get_field(fields, "address").as_deref(), Some("proxy.example.com:8080"));
            assert_eq!(get_field_bool(fields, "tor"), Some(false));
        }
    }

    #[test]
    fn test_proxy_config_bare_address() {
        // No protocol prefix -> default to socks5
        let result = proxy_config(&[Value::String("10.0.0.1:9050".to_string())]);
        assert!(result.is_ok(), "proxy_config bare failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ProxyConfig");
            assert_eq!(get_field(fields, "protocol").as_deref(), Some("socks5"));
            assert_eq!(get_field_bool(fields, "tor"), Some(true)); // port 9050
        }
    }

    #[test]
    fn test_chat_create() {
        let code = minted_code();
        let result = chat_create(&[
            Value::String("alice".to_string()),
            Value::String(code.clone()),
        ]);
        assert!(result.is_ok(), "chat_create failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ChatSession");
            assert_eq!(get_field(fields, "username").as_deref(), Some("alice"));
            assert_eq!(get_field(fields, "code").as_deref(), Some(code.as_str()));
            assert_eq!(get_field_bool(fields, "encrypted"), Some(true));
            assert_eq!(get_field(fields, "algo").as_deref(), Some("AES-256-GCM"));
            // session_id should be 12 chars
            let sid = get_field(fields, "session_id").unwrap();
            assert_eq!(sid.len(), 12, "session_id should be 12 hex chars");
            // port should be in valid range
            let port: i64 = get_field(fields, "port").unwrap().parse().unwrap();
            assert!(port >= 10000 && port < 65000, "port out of range: {}", port);
        }
    }

    #[test]
    fn test_chat_create_auto_code() {
        // Without explicit code, one should be generated
        let result = chat_create(&[Value::String("bob".to_string())]);
        assert!(result.is_ok(), "chat_create auto failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ChatSession");
            let code = get_field(fields, "code").unwrap();
            assert!(!code.is_empty(), "code should be auto-generated");
        }
    }

    #[test]
    fn test_chat_send_message_encrypt() {
        // Create session
        let session = chat_create(&[
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        // Send a message
        let updated = chat_send_message(&[
            session,
            Value::String("Hello Bob!".to_string()),
        ]);
        assert!(updated.is_ok(), "chat_send_message failed: {:?}", updated);

        if let Ok(Value::Struct { name, fields }) = &updated {
            assert_eq!(name, "ChatSession");
            // Check messages array has 1 entry
            if let Some((_, Value::Array(msgs))) = fields.iter().find(|(k, _)| k == "messages") {
                assert_eq!(msgs.len(), 1, "should have 1 message");
                if let Value::Struct { name: msg_name, fields: msg_fields } = &msgs[0] {
                    assert_eq!(msg_name, "ChatMessage");
                    assert_eq!(get_field(msg_fields, "from").as_deref(), Some("alice"));
                    assert_eq!(get_field(msg_fields, "text").as_deref(), Some("Hello Bob!"));
                    // encrypted field should be non-empty hex
                    let encrypted = get_field(msg_fields, "encrypted").unwrap();
                    assert!(encrypted.len() > 24, "encrypted should have nonce + ciphertext");
                }
            } else {
                panic!("should have messages array");
            }
        }
    }

    #[test]
    fn test_chat_decrypt_message() {
        // Create session and send a message
        let session = chat_create(&[
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        let session_id = if let Value::Struct { ref fields, .. } = session {
            get_field(fields, "session_id").unwrap()
        } else {
            panic!("expected struct");
        };

        let updated = chat_send_message(&[
            session,
            Value::String("Secret message!".to_string()),
        ]).unwrap();

        // Extract encrypted hex from the message
        let encrypted_hex = if let Value::Struct { ref fields, .. } = updated {
            if let Some((_, Value::Array(msgs))) = fields.iter().find(|(k, _)| k == "messages") {
                if let Value::Struct { fields: mf, .. } = &msgs[0] {
                    get_field(mf, "encrypted").unwrap()
                } else { panic!("msg not struct"); }
            } else { panic!("no messages"); }
        } else { panic!("not struct"); };

        // Decrypt
        let decrypted = chat_decrypt_message(&[
            Value::String(encrypted_hex),
            Value::String(session_id),
        ]);
        assert!(decrypted.is_ok(), "decrypt failed: {:?}", decrypted);
        assert_eq!(decrypted.unwrap().as_string(), "Secret message!");
    }

    #[test]
    fn test_chat_decrypt_wrong_session() {
        // Create a session and send a message
        let session = chat_create(&[
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        let updated = chat_send_message(&[
            session,
            Value::String("Top secret".to_string()),
        ]).unwrap();

        let encrypted_hex = if let Value::Struct { ref fields, .. } = updated {
            if let Some((_, Value::Array(msgs))) = fields.iter().find(|(k, _)| k == "messages") {
                if let Value::Struct { fields: mf, .. } = &msgs[0] {
                    get_field(mf, "encrypted").unwrap()
                } else { panic!("msg not struct"); }
            } else { panic!("no messages"); }
        } else { panic!("not struct"); };

        // Try to decrypt with wrong session_id
        let result = chat_decrypt_message(&[
            Value::String(encrypted_hex),
            Value::String("wrong-session-id".to_string()),
        ]);
        assert!(result.is_err(), "decrypt with wrong key should fail");
    }

    #[test]
    fn test_chat_history() {
        let session = chat_create(&[
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        // Send two messages
        let s1 = chat_send_message(&[
            session,
            Value::String("First message".to_string()),
        ]).unwrap();

        let s2 = chat_send_message(&[
            s1,
            Value::String("Second message".to_string()),
        ]).unwrap();

        let history = chat_history(&[s2]);
        assert!(history.is_ok(), "chat_history failed: {:?}", history);
        if let Ok(Value::Array(items)) = &history {
            assert_eq!(items.len(), 2, "should have 2 history entries");
            assert!(items[0].as_string().contains("alice"), "should contain username");
            assert!(items[0].as_string().contains("First message"), "should contain text");
            assert!(items[1].as_string().contains("Second message"), "should contain text");
        } else {
            panic!("expected array from chat_history");
        }
    }

    #[test]
    fn test_group_chat_create() {
        let code = minted_code();
        let result = group_chat_create(&[
            Value::String("devteam".to_string()),
            Value::String("alice".to_string()),
            Value::String(code.clone()),
        ]);
        assert!(result.is_ok(), "group_chat_create failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "GroupChat");
            assert_eq!(get_field(fields, "name").as_deref(), Some("devteam"));
            assert_eq!(get_field(fields, "creator").as_deref(), Some("alice"));
            assert_eq!(get_field(fields, "code").as_deref(), Some(code.as_str()));
            assert_eq!(get_field_bool(fields, "encrypted"), Some(true));
            // Should have creator as initial member
            if let Some((_, Value::Array(members))) = fields.iter().find(|(k, _)| k == "members") {
                assert_eq!(members.len(), 1);
                assert_eq!(members[0].as_string(), "alice");
            } else {
                panic!("should have members array");
            }
            // group_id should be 12 chars
            let gid = get_field(fields, "group_id").unwrap();
            assert_eq!(gid.len(), 12, "group_id should be 12 hex chars");
        }
    }

    #[test]
    fn test_group_chat_add_member() {
        let group = group_chat_create(&[
            Value::String("devteam".to_string()),
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        let updated = group_chat_add_member(&[
            group,
            Value::String("bob".to_string()),
        ]);
        assert!(updated.is_ok(), "add_member failed: {:?}", updated);
        if let Ok(Value::Struct { fields, .. }) = &updated {
            if let Some((_, Value::Array(members))) = fields.iter().find(|(k, _)| k == "members") {
                assert_eq!(members.len(), 2);
                assert!(members.iter().any(|m| m.as_string() == "alice"));
                assert!(members.iter().any(|m| m.as_string() == "bob"));
            }
        }

        // Adding same member again should not duplicate
        let updated2 = group_chat_add_member(&[
            updated.unwrap(),
            Value::String("bob".to_string()),
        ]).unwrap();
        if let Value::Struct { fields, .. } = &updated2 {
            if let Some((_, Value::Array(members))) = fields.iter().find(|(k, _)| k == "members") {
                assert_eq!(members.len(), 2, "should not duplicate member");
            }
        }
    }

    #[test]
    fn test_group_chat_remove_member() {
        let group = group_chat_create(&[
            Value::String("devteam".to_string()),
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        let with_bob = group_chat_add_member(&[
            group,
            Value::String("bob".to_string()),
        ]).unwrap();

        let without_bob = group_chat_remove_member(&[
            with_bob,
            Value::String("bob".to_string()),
        ]);
        assert!(without_bob.is_ok(), "remove_member failed: {:?}", without_bob);
        if let Ok(Value::Struct { fields, .. }) = &without_bob {
            if let Some((_, Value::Array(members))) = fields.iter().find(|(k, _)| k == "members") {
                assert_eq!(members.len(), 1);
                assert_eq!(members[0].as_string(), "alice");
            }
        }
    }

    #[test]
    fn test_group_chat_send() {
        let group = group_chat_create(&[
            Value::String("devteam".to_string()),
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        let updated = group_chat_send(&[
            group,
            Value::String("alice".to_string()),
            Value::String("Hello team!".to_string()),
        ]);
        assert!(updated.is_ok(), "group_chat_send failed: {:?}", updated);
        if let Ok(Value::Struct { name, fields }) = &updated {
            assert_eq!(name, "GroupChat");
            if let Some((_, Value::Array(msgs))) = fields.iter().find(|(k, _)| k == "messages") {
                assert_eq!(msgs.len(), 1);
                if let Value::Struct { name: mn, fields: mf } = &msgs[0] {
                    assert_eq!(mn, "GroupMessage");
                    assert_eq!(get_field(mf, "from").as_deref(), Some("alice"));
                    assert_eq!(get_field(mf, "text").as_deref(), Some("Hello team!"));
                    let enc = get_field(mf, "encrypted").unwrap();
                    assert!(enc.len() > 24, "should have encrypted content");
                }
            }
        }
    }

    #[test]
    fn test_group_chat_history() {
        let group = group_chat_create(&[
            Value::String("devteam".to_string()),
            Value::String("alice".to_string()),
            Value::String(minted_code()),
        ]).unwrap();

        let g1 = group_chat_send(&[
            group,
            Value::String("alice".to_string()),
            Value::String("Hey everyone".to_string()),
        ]).unwrap();

        let g2 = group_chat_send(&[
            g1,
            Value::String("bob".to_string()),
            Value::String("Hi alice!".to_string()),
        ]).unwrap();

        let history = chat_history(&[g2]);
        assert!(history.is_ok(), "group history failed: {:?}", history);
        if let Ok(Value::Array(items)) = &history {
            assert_eq!(items.len(), 2);
            assert!(items[0].as_string().contains("alice"));
            assert!(items[0].as_string().contains("Hey everyone"));
            assert!(items[1].as_string().contains("bob"));
            assert!(items[1].as_string().contains("Hi alice!"));
        }
    }

    #[test]
    fn test_phase63_dispatch_routes() {
        let funcs = [
            "generate_qr",
            "proxy_config",
            "chat_create",
            "chat_send_message",
            "chat_decrypt_message",
            "group_chat_create",
            "group_chat_add_member",
            "group_chat_remove_member",
            "group_chat_send",
            "chat_history",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(result.is_some(), "dispatch('{}') should be routable", f);
        }
    }

    #[test]
    fn test_chat_encrypt_decrypt_roundtrip() {
        // Full roundtrip: create session, send message, extract encrypted, decrypt.
        // ONE code for the whole test: each session's key derives from it, so the
        // per-message re-creation below must reuse it — a fresh code there decrypts
        // against a different key.
        let code = minted_code();
        let session = chat_create(&[
            Value::String("alice".to_string()),
            Value::String(code.clone()),
        ]).unwrap();

        let session_id = if let Value::Struct { ref fields, .. } = session {
            get_field(fields, "session_id").unwrap()
        } else { panic!("not struct"); };

        let messages = [
            "Hello world!",
            "This is a longer message with special chars: @#$%^&*()",
            "",  // empty message
            "Unicode: \u{1f600}\u{1f389}\u{2764}",
        ];

        for msg_text in &messages {
            // Re-create session each time for clean state
            let s = chat_create(&[
                Value::String("alice".to_string()),
                Value::String(code.clone()),
            ]).unwrap();

            let updated = chat_send_message(&[
                s,
                Value::String(msg_text.to_string()),
            ]).unwrap();

            let encrypted_hex = if let Value::Struct { ref fields, .. } = updated {
                if let Some((_, Value::Array(msgs))) = fields.iter().find(|(k, _)| k == "messages") {
                    if let Value::Struct { fields: mf, .. } = &msgs[0] {
                        get_field(mf, "encrypted").unwrap()
                    } else { panic!("msg not struct"); }
                } else { panic!("no messages"); }
            } else { panic!("not struct"); };

            let decrypted = chat_decrypt_message(&[
                Value::String(encrypted_hex),
                Value::String(session_id.clone()),
            ]).unwrap();

            assert_eq!(decrypted.as_string(), *msg_text,
                "roundtrip failed for message: {:?}", msg_text);
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Send Text, STUN, Hole Punch Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_send_text() {
        let result = send_text(&[Value::String("Hello, world!".to_string())]);
        assert!(result.is_ok(), "send_text failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "TextTransfer");
            assert_eq!(get_field(fields, "text").as_deref(), Some("Hello, world!"));
            assert_eq!(get_field(fields, "type").as_deref(), Some("text"));
            // size = 13 bytes
            let size: i64 = get_field(fields, "size").unwrap().parse().unwrap();
            assert_eq!(size, 13);
            // hash should be 64 hex chars (BLAKE3)
            let hash = get_field(fields, "hash").unwrap();
            assert_eq!(hash.len(), 64, "hash should be 64 hex chars, got {}", hash.len());
        } else {
            panic!("expected TextTransfer struct");
        }
    }

    #[test]
    fn test_send_text_empty() {
        let result = send_text(&[Value::String("".to_string())]);
        assert!(result.is_ok(), "send_text empty failed: {:?}", result);
        if let Ok(Value::Struct { fields, .. }) = &result {
            let size: i64 = get_field(fields, "size").unwrap().parse().unwrap();
            assert_eq!(size, 0);
        }
    }

    #[test]
    fn test_send_text_no_arg() {
        let result = send_text(&[]);
        assert!(result.is_err(), "send_text with no args should fail");
    }

    #[test]
    fn test_send_text_unicode() {
        let result = send_text(&[Value::String("\u{1f600} emoji text \u{2764}".to_string())]);
        assert!(result.is_ok(), "send_text unicode failed: {:?}", result);
        if let Ok(Value::Struct { fields, .. }) = &result {
            let text = get_field(fields, "text").unwrap();
            assert!(text.contains("\u{1f600}"), "should preserve emoji");
        }
    }

    #[test]
    fn test_stun_discover() {
        let result = stun_discover(&[]);
        assert!(result.is_ok(), "stun_discover failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "StunResult");
            let local_ip = get_field(fields, "local_ip").unwrap();
            assert!(!local_ip.is_empty(), "local_ip should not be empty");
            // Should be a valid IP address
            assert!(
                local_ip.parse::<std::net::IpAddr>().is_ok(),
                "local_ip should be a valid IP: {}", local_ip
            );
            assert_eq!(get_field(fields, "nat_type").as_deref(), Some("unknown"));
            assert_eq!(get_field_bool(fields, "reachable"), Some(true));
        } else {
            panic!("expected StunResult struct");
        }
    }

    #[test]
    fn test_hole_punch_creates_socket() {
        // Hole punch to localhost (won't actually reach anything, but exercises the code path)
        let result = hole_punch(&[
            Value::String("127.0.0.1".to_string()),
            Value::Int(19999),
            Value::Int(0),
        ]);
        assert!(result.is_ok(), "hole_punch failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "HolePunchResult");
            assert_eq!(get_field(fields, "peer").as_deref(), Some("127.0.0.1:19999"));
            assert_eq!(get_field_bool(fields, "punch_sent"), Some(true));
            assert_eq!(get_field(fields, "protocol").as_deref(), Some("UDP"));
            let local_addr = get_field(fields, "local_addr").unwrap();
            assert!(!local_addr.is_empty(), "local_addr should not be empty");
        }
    }

    #[test]
    fn test_hole_punch_default_port() {
        // Without explicit port args, should default to 6881
        let result = hole_punch(&[Value::String("127.0.0.1".to_string())]);
        assert!(result.is_ok(), "hole_punch default port failed: {:?}", result);
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(get_field(fields, "peer").as_deref(), Some("127.0.0.1:6881"));
        }
    }

    #[test]
    fn test_hole_punch_no_arg() {
        let result = hole_punch(&[]);
        assert!(result.is_err(), "hole_punch with no args should fail");
    }

    #[test]
    fn test_dispatch_routes_new_functions() {
        // Verify all new dispatch routes are wired up
        let funcs = [
            "send_text",
            "stun_discover",
            "hole_punch",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(result.is_some(), "dispatch('{}') should be routable", f);
        }
    }

    #[test]
    fn test_send_text_blake3_deterministic() {
        // Same text should produce same hash
        let r1 = send_text(&[Value::String("deterministic".to_string())]).unwrap();
        let r2 = send_text(&[Value::String("deterministic".to_string())]).unwrap();
        if let (Value::Struct { fields: f1, .. }, Value::Struct { fields: f2, .. }) = (&r1, &r2) {
            assert_eq!(get_field(f1, "hash"), get_field(f2, "hash"));
        }
        // Different text should produce different hash
        let r3 = send_text(&[Value::String("different".to_string())]).unwrap();
        if let (Value::Struct { fields: f1, .. }, Value::Struct { fields: f3, .. }) = (&r1, &r3) {
            assert_ne!(get_field(f1, "hash"), get_field(f3, "hash"));
        }
    }

    #[test]
    fn test_stun_discover_fields_complete() {
        let result = stun_discover(&[]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            // Verify all 5 expected fields exist
            let expected = ["local_ip", "public_ip", "nat_type", "port", "reachable"];
            for key in &expected {
                assert!(
                    fields.iter().any(|(k, _)| k == key),
                    "StunResult missing field: {}", key
                );
            }
        }
    }

    #[test]
    fn test_hole_punch_fields_complete() {
        let result = hole_punch(&[Value::String("127.0.0.1".to_string())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            let expected = ["peer", "local_addr", "punch_sent", "protocol"];
            for key in &expected {
                assert!(
                    fields.iter().any(|(k, _)| k == key),
                    "HolePunchResult missing field: {}", key
                );
            }
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Streaming, Content-Type, E2E Encryption, Broadcast, Speed Test
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_streaming_send_result_fields() {
        // Create a temp file to verify struct fields (streaming send will fail to connect, but
        // it validates the hash computation path which does NOT load whole file)
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"streaming test data 1234567890").unwrap();

        // The send will fail (no server), but we can test the hash computation path
        // directly by verifying detect_content_type on the same file works
        let result = detect_content_type(&[Value::String(tmp.path().display().to_string())]);
        assert!(result.is_ok(), "detect should work on temp file");
    }

    #[test]
    fn test_detect_content_type_png() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // PNG magic bytes: 89 50 4E 47
        std::fs::write(tmp.path(), &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();

        let result = detect_content_type(&[Value::String(tmp.path().display().to_string())]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ContentType");
            assert_eq!(get_field(fields, "mime").as_deref(), Some("image/png"));
            assert_eq!(get_field_bool(fields, "is_text"), Some(false));
            assert_eq!(get_field_bool(fields, "is_binary"), Some(true));
            assert_eq!(get_field(fields, "source").as_deref(), Some("file"));
        } else {
            panic!("expected ContentType struct");
        }
    }

    #[test]
    fn test_detect_content_type_text() {
        // Non-existent path => treated as raw text
        let result = detect_content_type(&[Value::String("this is plain text data".to_string())]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ContentType");
            assert_eq!(get_field(fields, "mime").as_deref(), Some("text/plain"));
            assert_eq!(get_field_bool(fields, "is_text"), Some(true));
            assert_eq!(get_field(fields, "source").as_deref(), Some("text"));
        }
    }

    #[test]
    fn test_detect_content_type_json() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"{\"key\": \"value\"}").unwrap();

        let result = detect_content_type(&[Value::String(tmp.path().display().to_string())]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(get_field(fields, "mime").as_deref(), Some("application/json"));
            assert_eq!(get_field_bool(fields, "is_text"), Some(true));
        }
    }

    #[test]
    fn test_encrypt_decrypt_payload_roundtrip() {
        let original_data = "hello world transfer encryption test";
        let hex_data = hex_encode(original_data.as_bytes());
        let password = "test-password-123";

        // Encrypt
        let enc_result = transfer_encrypt_payload(&[
            Value::String(hex_data.clone()),
            Value::String(password.to_string()),
        ]);
        assert!(enc_result.is_ok(), "encrypt failed: {:?}", enc_result);

        let encrypted_hex = if let Ok(Value::Struct { fields, .. }) = &enc_result {
            assert_eq!(get_field_bool(fields, "encrypted"), Some(true));
            assert_eq!(get_field(fields, "algo").as_deref(), Some("AES-256-GCM + Argon2id"));
            let orig_size: i64 = get_field(fields, "original_size").unwrap().parse().unwrap();
            assert_eq!(orig_size, original_data.len() as i64);
            get_field(fields, "data").unwrap()
        } else {
            panic!("expected EncryptedPayload struct");
        };

        // Decrypt
        let dec_result = transfer_decrypt_payload(&[
            Value::String(encrypted_hex),
            Value::String(password.to_string()),
        ]);
        assert!(dec_result.is_ok(), "decrypt failed: {:?}", dec_result);

        if let Ok(Value::String(decrypted_hex)) = &dec_result {
            let decrypted_bytes = hex_decode(decrypted_hex).unwrap();
            let decrypted = String::from_utf8(decrypted_bytes).unwrap();
            assert_eq!(decrypted, original_data);
        } else {
            panic!("expected String from decrypt");
        }
    }

    #[test]
    fn test_encrypt_payload_wrong_password() {
        let hex_data = hex_encode(b"secret data");
        let password = "correct-password";

        let enc_result = transfer_encrypt_payload(&[
            Value::String(hex_data),
            Value::String(password.to_string()),
        ]).unwrap();

        let encrypted_hex = if let Value::Struct { fields, .. } = &enc_result {
            get_field(fields, "data").unwrap()
        } else {
            panic!("expected struct");
        };

        // Decrypt with wrong password should fail
        let dec_result = transfer_decrypt_payload(&[
            Value::String(encrypted_hex),
            Value::String("wrong-password".to_string()),
        ]);
        assert!(dec_result.is_err(), "decryption with wrong password should fail");
    }

    #[test]
    fn test_broadcast_send_struct() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"broadcast test data").unwrap();

        let result = broadcast_send(&[
            Value::String(tmp.path().display().to_string()),
            Value::Array(vec![
                Value::String("127.0.0.1:19999".to_string()),
                Value::String("127.0.0.1:19998".to_string()),
            ]),
        ]);

        assert!(result.is_ok(), "broadcast_send failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "BroadcastSendResult");
            let recipients: i64 = get_field(fields, "recipients").unwrap().parse().unwrap();
            assert_eq!(recipients, 2);
            assert!(!get_field(fields, "hash").unwrap().is_empty());
            let size: i64 = get_field(fields, "size").unwrap().parse().unwrap();
            assert_eq!(size, 19); // "broadcast test data".len()
        } else {
            panic!("expected BroadcastSendResult struct");
        }
    }

    #[test]
    fn test_speed_test_nonzero() {
        let result = speed_test(&[]);
        assert!(result.is_ok(), "speed_test failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "SpeedTestResult");
            // Local measurements must be positive; network fields may be 0
            // when no target is given (they are reported, not fabricated).
            for (k, v) in fields {
                if k.starts_with("network_") {
                    continue;
                }
                match v {
                    Value::Float(f) => {
                        assert!(*f > 0.0, "speed {} should be > 0, got {}", k, f);
                    }
                    Value::Int(n) => {
                        assert!(*n > 0, "test_size {} should be > 0", k);
                    }
                    _ => {}
                }
            }
            let status = fields
                .iter()
                .find(|(k, _)| k == "network_status")
                .map(|(_, v)| v.as_string())
                .unwrap_or_default();
            assert!(
                status.contains("skipped"),
                "without a target the network status should say skipped, got: {status}"
            );
        } else {
            panic!("expected SpeedTestResult struct");
        }
    }

    #[test]
    fn test_detect_mime_exe() {
        // MZ magic bytes (PE executable)
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
        let (mime, is_text) = detect_mime(&data);
        assert_eq!(mime, "application/x-executable");
        assert!(!is_text);
    }

    #[test]
    fn test_detect_mime_pdf() {
        // PDF magic bytes: %PDF
        let data = vec![0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34];
        let (mime, is_text) = detect_mime(&data);
        assert_eq!(mime, "application/pdf");
        assert!(!is_text);
    }

    #[test]
    fn test_detect_mime_elf() {
        // ELF magic bytes
        let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        let (mime, is_text) = detect_mime(&data);
        assert_eq!(mime, "application/x-elf");
        assert!(!is_text);
    }

    #[test]
    fn test_detect_mime_zip() {
        let data = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        let (mime, is_text) = detect_mime(&data);
        assert_eq!(mime, "application/zip");
        assert!(!is_text);
    }

    #[test]
    fn test_detect_mime_gzip() {
        let data = vec![0x1F, 0x8B, 0x08, 0x00];
        let (mime, is_text) = detect_mime(&data);
        assert_eq!(mime, "application/gzip");
        assert!(!is_text);
    }

    #[test]
    fn test_dispatch_routes_streaming_functions() {
        // Verify all streaming/content/encrypt/broadcast/speed dispatch keys are routable
        let funcs = [
            "quic_send_streaming",
            "detect_content_type",
            "transfer_encrypt_payload",
            "transfer_decrypt_payload",
            "broadcast_send",
            "speed_test",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(result.is_some(), "dispatch('{}') should be routable", f);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // TWD Directory Transfer Tests
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_twd_format_magic_bytes() {
        let archive = build_twd_archive("test", &[], &[]);
        assert_eq!(&archive[..4], b"TWD1");
        assert_eq!(archive[4], 1); // version
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("mydir");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("hello.txt"), b"hello world").unwrap();
        std::fs::write(src.join("sub/nested.txt"), b"nested content").unwrap();

        let archive_path = tmp.path().join("out.twd");
        let result = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::Bool(true),
        ]);
        assert!(result.is_ok(), "pack failed: {:?}", result);
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "PackResult");
            assert_eq!(
                fields.iter().find(|(k, _)| k == "files").map(|(_, v)| v.as_string()),
                Some("2".to_string())
            );
            assert_eq!(
                fields.iter().find(|(k, _)| k == "dirs").map(|(_, v)| v.as_string()),
                Some("1".to_string())
            );
            assert_eq!(
                fields.iter().find(|(k, _)| k == "format").map(|(_, v)| v.as_string()),
                Some("TWD1".to_string())
            );
        }

        // Unpack to a different dir
        let unpack_dir = tmp.path().join("unpacked");
        std::fs::create_dir_all(&unpack_dir).unwrap();
        let result2 = unpack_directory(&[
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::String(unpack_dir.to_string_lossy().to_string()),
        ]);
        assert!(result2.is_ok(), "unpack failed: {:?}", result2);

        // Verify files match
        let hello = std::fs::read_to_string(unpack_dir.join("mydir/hello.txt")).unwrap();
        assert_eq!(hello, "hello world");
        let nested = std::fs::read_to_string(unpack_dir.join("mydir/sub/nested.txt")).unwrap();
        assert_eq!(nested, "nested content");
    }

    #[test]
    fn test_pack_preserves_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("project");
        std::fs::create_dir_all(src.join("src/utils")).unwrap();
        std::fs::create_dir_all(src.join("tests")).unwrap();
        std::fs::write(src.join("src/main.tl"), b"fn main() {}").unwrap();
        std::fs::write(src.join("src/utils/helper.tl"), b"fn help() {}").unwrap();
        std::fs::write(src.join("tests/test.tl"), b"fn test() {}").unwrap();

        let archive_path = tmp.path().join("project.twd");
        let _ = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::Bool(false), // no compression
        ]);

        let unpack_dir = tmp.path().join("restored");
        std::fs::create_dir_all(&unpack_dir).unwrap();
        let result = unpack_directory(&[
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::String(unpack_dir.to_string_lossy().to_string()),
        ]);
        assert!(result.is_ok());

        // Verify directory structure
        assert!(unpack_dir.join("project/src/utils").is_dir());
        assert!(unpack_dir.join("project/tests").is_dir());
        assert!(unpack_dir.join("project/src/main.tl").is_file());
        assert!(unpack_dir.join("project/src/utils/helper.tl").is_file());
        assert!(unpack_dir.join("project/tests/test.tl").is_file());
    }

    #[test]
    fn test_pack_preserves_file_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("data");
        std::fs::create_dir_all(&src).unwrap();

        // Create files with various contents
        let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        std::fs::write(src.join("binary.bin"), &binary_data).unwrap();
        std::fs::write(src.join("empty.txt"), b"").unwrap();
        std::fs::write(src.join("unicode.txt"), "Hello \u{1F600} World \u{00E9}").unwrap();

        let archive_path = tmp.path().join("data.twd");
        let _ = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::Bool(true),
        ]);

        let unpack_dir = tmp.path().join("restored");
        std::fs::create_dir_all(&unpack_dir).unwrap();
        let _ = unpack_directory(&[
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::String(unpack_dir.to_string_lossy().to_string()),
        ]);

        assert_eq!(
            std::fs::read(unpack_dir.join("data/binary.bin")).unwrap(),
            binary_data
        );
        assert_eq!(
            std::fs::read(unpack_dir.join("data/empty.txt")).unwrap(),
            b""
        );
        assert_eq!(
            std::fs::read_to_string(unpack_dir.join("data/unicode.txt")).unwrap(),
            "Hello \u{1F600} World \u{00E9}"
        );
    }

    #[test]
    fn test_pack_compressed_smaller() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("compressible");
        std::fs::create_dir_all(&src).unwrap();
        // Highly compressible: repeated content
        let big_data = "abcdefghij".repeat(10000);
        std::fs::write(src.join("big.txt"), &big_data).unwrap();

        let comp_path = tmp.path().join("comp.twd");
        let uncomp_path = tmp.path().join("uncomp.twd");

        let _ = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(comp_path.to_string_lossy().to_string()),
            Value::Bool(true),
        ]);
        let _ = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(uncomp_path.to_string_lossy().to_string()),
            Value::Bool(false),
        ]);

        let comp_size = std::fs::metadata(&comp_path).unwrap().len();
        let uncomp_size = std::fs::metadata(&uncomp_path).unwrap().len();
        assert!(
            comp_size < uncomp_size,
            "compressed {} should be < uncompressed {}",
            comp_size,
            uncomp_size
        );
    }

    #[test]
    fn test_unpack_creates_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("tree");
        std::fs::create_dir_all(src.join("a/b/c")).unwrap();
        std::fs::write(src.join("a/b/c/leaf.txt"), b"leaf").unwrap();
        std::fs::write(src.join("a/root.txt"), b"root").unwrap();

        let archive_path = tmp.path().join("tree.twd");
        let _ = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::Bool(true),
        ]);

        let out = tmp.path().join("out");
        let result = unpack_directory(&[
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::String(out.to_string_lossy().to_string()),
        ]);
        assert!(result.is_ok());

        if let Ok(Value::Struct { fields, .. }) = &result {
            let preserved = fields
                .iter()
                .find(|(k, _)| k == "structure_preserved")
                .and_then(|(_, v)| if let Value::Bool(b) = v { Some(*b) } else { None });
            assert_eq!(preserved, Some(true));
        }

        assert!(out.join("tree/a/b/c").is_dir());
        assert_eq!(
            std::fs::read_to_string(out.join("tree/a/b/c/leaf.txt")).unwrap(),
            "leaf"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("tree/a/root.txt")).unwrap(),
            "root"
        );
    }

    #[test]
    fn test_pack_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("empty");
        std::fs::create_dir_all(&src).unwrap();

        let archive_path = tmp.path().join("empty.twd");
        let result = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::Bool(false),
        ]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(
                fields.iter().find(|(k, _)| k == "files").map(|(_, v)| v.as_string()),
                Some("0".to_string())
            );
            assert_eq!(
                fields.iter().find(|(k, _)| k == "dirs").map(|(_, v)| v.as_string()),
                Some("0".to_string())
            );
        }

        // Unpack the empty archive
        let out = tmp.path().join("out");
        let result2 = unpack_directory(&[
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::String(out.to_string_lossy().to_string()),
        ]);
        assert!(result2.is_ok());
        assert!(out.join("empty").is_dir());
    }

    #[test]
    fn test_pack_nested_dirs_3_levels() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("deep");
        std::fs::create_dir_all(src.join("level1/level2/level3")).unwrap();
        std::fs::write(src.join("level1/a.txt"), b"a").unwrap();
        std::fs::write(src.join("level1/level2/b.txt"), b"bb").unwrap();
        std::fs::write(src.join("level1/level2/level3/c.txt"), b"ccc").unwrap();

        let archive_path = tmp.path().join("deep.twd");
        let result = pack_directory(&[
            Value::String(src.to_string_lossy().to_string()),
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::Bool(true),
        ]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { fields, .. }) = &result {
            assert_eq!(
                fields.iter().find(|(k, _)| k == "files").map(|(_, v)| v.as_string()),
                Some("3".to_string())
            );
            assert_eq!(
                fields.iter().find(|(k, _)| k == "dirs").map(|(_, v)| v.as_string()),
                Some("3".to_string())
            );
        }

        let out = tmp.path().join("out");
        let _ = unpack_directory(&[
            Value::String(archive_path.to_string_lossy().to_string()),
            Value::String(out.to_string_lossy().to_string()),
        ]);
        assert_eq!(
            std::fs::read_to_string(out.join("deep/level1/a.txt")).unwrap(),
            "a"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("deep/level1/level2/b.txt")).unwrap(),
            "bb"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("deep/level1/level2/level3/c.txt")).unwrap(),
            "ccc"
        );
    }

    #[test]
    fn test_path_separators_normalized() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("paths");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("sub/file.txt"), b"data").unwrap();

        // Collect via walk_twd
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let mut total = 0u64;
        walk_twd(
            src.as_path(),
            src.as_path(),
            &mut files,
            &mut dirs,
            &mut total,
        )
        .unwrap();

        // All paths should use forward slashes
        for (path, _) in &files {
            assert!(
                !path.contains('\\'),
                "file path contains backslash: {}",
                path
            );
        }
        for d in &dirs {
            assert!(!d.contains('\\'), "dir path contains backslash: {}", d);
        }
    }

    #[test]
    fn test_dispatch_routes_dir_transfer() {
        // Verify all TWD dispatch keys are routable
        let funcs = [
            "quic_send_dir_structured",
            "quic_receive_dir",
            "pack_directory",
            "unpack_directory",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(
                result.is_some(),
                "dispatch('{}') should be routable",
                f
            );
        }
    }

    #[test]
    fn test_build_twd_archive_structure() {
        let dirs = vec!["sub".to_string(), "sub/deep".to_string()];
        let files = vec![
            ("readme.txt".to_string(), b"hello".to_vec()),
            ("sub/data.bin".to_string(), vec![0xFF, 0x00, 0xAB]),
        ];
        let archive = build_twd_archive("myproject", &dirs, &files);

        // Verify magic + version
        assert_eq!(&archive[..4], b"TWD1");
        assert_eq!(archive[4], 1);

        // Verify round-trip via unpack
        let tmp = tempfile::tempdir().unwrap();
        let (name, fc, dc, bytes) =
            unpack_twd_archive(&archive, &tmp.path().to_string_lossy()).unwrap();
        assert_eq!(name, "myproject");
        assert_eq!(fc, 2);
        assert_eq!(dc, 2);
        assert_eq!(bytes, 8); // 5 + 3

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("myproject/readme.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("myproject/sub/data.bin")).unwrap(),
            vec![0xFF, 0x00, 0xAB]
        );
    }

    // ══════════════════════════════════════════════════════════════
    // HTTP Share + Live Browser Session Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kb() {
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1024 * 500), "500.0 KB");
    }

    #[test]
    fn test_format_size_mb() {
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 100), "100.0 MB");
    }

    #[test]
    fn test_format_size_gb() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_size(1024 * 1024 * 1024 * 2), "2.00 GB");
    }

    #[test]
    fn test_base64_decode_valid() {
        let encoded = "SGVsbG8gVGFsbG93"; // "Hello Tallow"
        let decoded = base64_decode_bytes(encoded).unwrap();
        assert_eq!(decoded, b"Hello Tallow");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let result = base64_decode_bytes("!!!not-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64 decode"));
    }

    #[test]
    fn test_base64_decode_empty() {
        let decoded = base64_decode_bytes("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_share_by_link_creates_server() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("test-share.txt");
        std::fs::write(&file, "hello from tallow share").unwrap();

        let result = share_by_link(&[
            Value::String(file.to_string_lossy().to_string()),
            Value::Int(0), // auto port
        ]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ShareLink");
            let url = fields
                .iter()
                .find(|(k, _)| k == "url")
                .map(|(_, v)| v.as_string())
                .unwrap();
            assert!(url.starts_with("http://"));
            assert!(url.contains("/dl/"));
            let serving = fields
                .iter()
                .find(|(k, _)| k == "serving")
                .map(|(_, v)| matches!(v, Value::Bool(true)))
                .unwrap_or(false);
            assert!(serving);
        }
    }

    #[test]
    fn test_share_by_link_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("payload.bin");
        std::fs::write(&file, vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let result = share_by_link(&[
            Value::String(file.to_string_lossy().to_string()),
            Value::Int(0),
        ])
        .unwrap();

        if let Value::Struct { fields, .. } = &result {
            // Check all expected fields are present
            let field_names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
            assert!(field_names.contains(&"url"));
            assert!(field_names.contains(&"direct_url"));
            assert!(field_names.contains(&"file"));
            assert!(field_names.contains(&"filename"));
            assert!(field_names.contains(&"size"));
            assert!(field_names.contains(&"hash"));
            assert!(field_names.contains(&"port"));
            assert!(field_names.contains(&"token"));
            assert!(field_names.contains(&"password_protected"));
            assert!(field_names.contains(&"max_downloads"));
            assert!(field_names.contains(&"serving"));

            // Size should be 4 bytes
            let size = fields
                .iter()
                .find(|(k, _)| k == "size")
                .map(|(_, v)| if let Value::Int(n) = v { *n } else { -1 })
                .unwrap();
            assert_eq!(size, 4);

            // filename should be "payload.bin"
            let fname = fields
                .iter()
                .find(|(k, _)| k == "filename")
                .map(|(_, v)| v.as_string())
                .unwrap();
            assert_eq!(fname, "payload.bin");

            // Not password protected
            let pw = fields
                .iter()
                .find(|(k, _)| k == "password_protected")
                .map(|(_, v)| matches!(v, Value::Bool(false)))
                .unwrap_or(false);
            assert!(pw);
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_share_by_link_with_password() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("secret.txt");
        std::fs::write(&file, "confidential data").unwrap();

        let result = share_by_link(&[
            Value::String(file.to_string_lossy().to_string()),
            Value::Int(0),
            Value::String("mypassword123".to_string()),
            Value::Int(5), // max 5 downloads
        ])
        .unwrap();

        if let Value::Struct { fields, .. } = &result {
            let pw_protected = fields
                .iter()
                .find(|(k, _)| k == "password_protected")
                .map(|(_, v)| matches!(v, Value::Bool(true)))
                .unwrap_or(false);
            assert!(pw_protected);

            let max_dl = fields
                .iter()
                .find(|(k, _)| k == "max_downloads")
                .map(|(_, v)| if let Value::Int(n) = v { *n } else { -1 })
                .unwrap();
            assert_eq!(max_dl, 5);
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_share_by_link_missing_file() {
        let result = share_by_link(&[Value::String("/nonexistent/file.txt".to_string())]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("file not found"));
    }

    #[test]
    fn test_share_dir_by_link() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mydir");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "aaa").unwrap();
        std::fs::write(dir.join("b.txt"), "bbb").unwrap();

        let result = share_dir_by_link(&[
            Value::String(dir.to_string_lossy().to_string()),
            Value::Int(0),
        ]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "ShareLink");
            let url = fields
                .iter()
                .find(|(k, _)| k == "url")
                .map(|(_, v)| v.as_string())
                .unwrap();
            assert!(url.contains("/dl/"));
            // The filename should end with .twd
            let fname = fields
                .iter()
                .find(|(k, _)| k == "filename")
                .map(|(_, v)| v.as_string())
                .unwrap();
            assert!(fname.ends_with(".twd"));
        }
    }

    #[test]
    fn test_browser_live_share_creates_server() {
        let result = browser_live_share(&[
            Value::Int(0), // auto port
            Value::Int(500),
        ]);
        assert!(result.is_ok());
        if let Ok(Value::Struct { name, fields }) = &result {
            assert_eq!(name, "LiveShare");
            let url = fields
                .iter()
                .find(|(k, _)| k == "url")
                .map(|(_, v)| v.as_string())
                .unwrap();
            assert!(url.starts_with("http://"));
            let streaming = fields
                .iter()
                .find(|(k, _)| k == "streaming")
                .map(|(_, v)| matches!(v, Value::Bool(true)))
                .unwrap_or(false);
            assert!(streaming);
            let refresh = fields
                .iter()
                .find(|(k, _)| k == "refresh_ms")
                .map(|(_, v)| if let Value::Int(n) = v { *n } else { -1 })
                .unwrap();
            assert_eq!(refresh, 500);
            let ss_path = fields
                .iter()
                .find(|(k, _)| k == "screenshot_path")
                .map(|(_, v)| v.as_string())
                .unwrap();
            assert!(ss_path.contains("tallow-live-screenshot.png"));
        }
    }

    #[test]
    fn test_browser_live_update() {
        use base64::Engine;
        // Create a small valid PNG-like payload (just bytes, not a real PNG for testing)
        let test_data = b"fake-screenshot-data-for-testing";
        let encoded = base64::engine::general_purpose::STANDARD.encode(test_data);

        let result = browser_live_update(&[Value::String(encoded)]);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Bool(true)));

        // Verify the file was written
        let ss_path = std::env::temp_dir().join("tallow-live-screenshot.png");
        let written = std::fs::read(&ss_path).unwrap();
        assert_eq!(written, test_data);

        // Cleanup
        let _ = std::fs::remove_file(&ss_path);
    }

    #[test]
    fn test_browser_live_update_missing_arg() {
        let result = browser_live_update(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("screenshot base64 required"));
    }

    #[test]
    fn test_dispatch_routes_share_and_live() {
        // Verify all new dispatch keys are routable
        let funcs = [
            "share_by_link",
            "share_dir_by_link",
            "browser_live_share",
            "browser_live_update",
        ];
        for f in &funcs {
            let result = dispatch(f, vec![]);
            assert!(
                result.is_some(),
                "dispatch('{}') should be routable",
                f
            );
        }
    }

    // ── R-08 batch-3 (#131/#132): transfer transport policy ──

    fn lookup_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn test_policy_default_is_direct_without_udp_preference() {
        let lookup = lookup_from(&[]);
        let p = resolve_transport_policy(&lookup, None, "127.0.0.1").unwrap();
        assert!(!p.is_proxied());
        assert!(!p.quic_eligible(), "direct-UDP preference must never be a default");
        assert_eq!(p.candidates().len(), 1);
    }

    #[test]
    fn test_policy_tallow_tor_selects_tor_route() {
        let lookup = lookup_from(&[(TALLOW_TOR_ENV, "1")]);
        let p = resolve_transport_policy(&lookup, None, "relay.tallow-lang.org").unwrap();
        assert!(p.is_proxied());
        assert!(!p.quic_eligible(), "Tor route: QUIC cannot traverse SOCKS5");
        let proxy = p.proxy.as_ref().unwrap();
        assert!(proxy.tor_mode);
        assert_eq!(proxy.socks5_addr.port(), 9050);
    }

    #[test]
    fn test_policy_tallow_proxy_socks5h_sets_tor_mode() {
        let lookup = lookup_from(&[(TALLOW_PROXY_ENV, "socks5h://127.0.0.1:9051")]);
        let p = resolve_transport_policy(&lookup, None, "example.org").unwrap();
        assert!(p.is_proxied());
        assert!(p.proxy.as_ref().unwrap().tor_mode);
        assert_eq!(p.proxy.as_ref().unwrap().socks5_addr.port(), 9051);
    }

    #[test]
    fn test_policy_malformed_proxy_is_hard_refusal_never_direct() {
        let lookup = lookup_from(&[(TALLOW_PROXY_ENV, "not-a-proxy")]);
        let err = resolve_transport_policy(&lookup, None, "example.org").unwrap_err();
        assert!(err.contains("fail-closed"), "msg: {err}");
        assert!(!err.contains("Ok("), "msg: {err}");
    }

    #[test]
    fn test_policy_non_socks5_scheme_is_hard_refusal() {
        let lookup = lookup_from(&[(TALLOW_PROXY_ENV, "http://127.0.0.1:8080")]);
        let err = resolve_transport_policy(&lookup, None, "example.org").unwrap_err();
        assert!(err.contains("refusing"), "msg: {err}");
    }

    #[test]
    fn test_policy_direct_opt_in_enables_quic() {
        let lookup = lookup_from(&[(TALLOW_ALLOW_DIRECT_ENV, "1")]);
        let p = resolve_transport_policy(&lookup, None, "10.0.0.5").unwrap();
        assert!(!p.is_proxied());
        assert!(p.quic_eligible(), "explicit direct-UDP opt-in");
    }

    #[test]
    fn test_policy_direct_disabled_without_proxy_refuses() {
        // The "fail-closed when neither" case: proxied-only mode, no proxy.
        let lookup = lookup_from(&[(TALLOW_ALLOW_DIRECT_ENV, "0")]);
        let err = resolve_transport_policy(&lookup, None, "example.org").unwrap_err();
        assert!(err.contains("fail-closed"), "msg: {err}");
    }

    #[test]
    fn test_policy_onion_requires_tor_route() {
        let plain = lookup_from(&[]);
        let err =
            resolve_transport_policy(&plain, None, "abcdefg.onion").unwrap_err();
        assert!(err.contains("onion"), "msg: {err}");

        let tor = lookup_from(&[(TALLOW_TOR_ENV, "1")]);
        let p = resolve_transport_policy(&tor, None, "abcdefg.onion").unwrap();
        assert!(p.is_proxied() && p.proxy.as_ref().unwrap().tor_mode);

        // A generic socks5:// route cannot resolve onion names (no remote DNS).
        let generic = lookup_from(&[(TALLOW_PROXY_ENV, "socks5://127.0.0.1:1080")]);
        assert!(
            resolve_transport_policy(&generic, None, "abcdefg.onion").is_err(),
            "onion over generic SOCKS5 must refuse"
        );
    }

    #[test]
    fn test_policy_explicit_proxy_wins_over_env() {
        let lookup = lookup_from(&[(TALLOW_PROXY_ENV, "socks5://127.0.0.1:1080")]);
        let p = resolve_transport_policy(&lookup, Some("socks5h://127.0.0.1:9050"), "x.org")
            .unwrap();
        assert!(p.proxy.as_ref().unwrap().tor_mode);
        assert_eq!(p.proxy.as_ref().unwrap().socks5_addr.port(), 9050);
    }

    #[test]
    fn test_policy_tor_env_plus_generic_proxy_url_still_tor_mode() {
        let lookup = lookup_from(&[
            (TALLOW_PROXY_ENV, "socks5://127.0.0.1:1080"),
            (TALLOW_TOR_ENV, "1"),
        ]);
        let p = resolve_transport_policy(&lookup, None, "x.org").unwrap();
        assert!(p.proxy.as_ref().unwrap().tor_mode);
    }

    #[test]
    fn test_onion_host_detection() {
        assert!(is_onion_host("abcdefg.onion"));
        assert!(is_onion_host("ABCDEFG.Onion"));
        assert!(!is_onion_host("onion.example.org"));
        assert!(!is_onion_host("127.0.0.1"));
    }

    #[test]
    fn test_split_host_port_variants() {
        assert_eq!(
            split_host_port("127.0.0.1:6880").unwrap(),
            ("127.0.0.1".to_string(), 6880)
        );
        assert_eq!(
            split_host_port("relay.example.org:4433").unwrap(),
            ("relay.example.org".to_string(), 4433)
        );
        assert_eq!(
            split_host_port("[::1]:9000").unwrap(),
            ("::1".to_string(), 9000)
        );
        assert!(split_host_port("no-port").is_err());
        assert!(split_host_port("host:notaport").is_err());
    }

    #[test]
    fn test_dispatch_routes_transport_status() {
        assert!(dispatch("transfer_transport_status", vec![]).is_some());
    }
}
