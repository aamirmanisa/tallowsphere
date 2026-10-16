//! CDP relay server for distributed browser pool.
//!
//! Listens on QUIC (quinn), accepts CDP commands as JSON on a bidirectional
//! stream, and routes them to the local BrowserPool via the SessionRegistry.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::registry::SessionRegistry;

/// CDP relay server that accepts remote commands and routes to local pool.
pub struct CdpRelay {
    addr: SocketAddr,
    registry: Arc<SessionRegistry>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Wire format for a remote CDP command.
#[derive(serde::Deserialize)]
struct RemoteCommand {
    session_id: String,
    method: String,
    #[serde(default)]
    params: Option<Vec<u8>>,
}

impl CdpRelay {
    pub fn new(addr: SocketAddr, registry: SessionRegistry) -> Self {
        Self {
            addr,
            registry: Arc::new(registry),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start listening for incoming CDP commands over QUIC.
    ///
    /// Creates a quinn server endpoint with a runtime-generated self-signed
    /// certificate, spawns a background accept loop, and returns once the
    /// listener is bound. Each client opens a bidirectional stream carrying a
    /// JSON `RemoteCommand`; the response is the `route_command` JSON.
    pub async fn start(&self) -> Result<(), String> {
        let config = create_relay_server_config()?;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let endpoint = quinn::Endpoint::server(config, self.addr)
            .map_err(|e| format!("[CdpRelay] failed to bind QUIC endpoint on {}: {e}", self.addr))?;

        self.running.store(true, std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "[CdpRelay] Ready on {} (QUIC) — accepting CDP command streams",
            self.addr
        );

        let running = self.running.clone();
        let registry = self.registry.clone();

        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                match endpoint.accept().await {
                    Some(incoming) => {
                        let registry = registry.clone();
                        let running = running.clone();
                        tokio::spawn(async move {
                            // Await the handshake to obtain the Connection.
                            match incoming.await {
                                Ok(conn) => {
                                    let _ = handle_connection(conn, registry).await;
                                }
                                Err(_) => {
                                    // Handshake failed — drop and keep serving.
                                }
                            }
                            let _ = running.load(std::sync::atomic::Ordering::Relaxed);
                        });
                    }
                    None => break,
                }
            }
        });

        Ok(())
    }

    /// Stop the relay.
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns `true` if the relay has been started and not stopped.
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Route a CDP command to the correct local browser session.
    ///
    /// Looks up the session in the registry and returns a JSON response
    /// indicating which node/session handled the command.
    pub async fn route_command(
        &self,
        session_id: &str,
        method: &str,
        params: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        if !self.is_running() {
            return Err("relay is not running".to_string());
        }
        route_command_core(&self.registry, session_id, method, params).await
    }
}

/// Handle a single QUIC connection: read each command stream and reply.
async fn handle_connection(
    conn: quinn::Connection,
    registry: Arc<SessionRegistry>,
) -> Result<(), String> {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let registry = registry.clone();
                tokio::spawn(async move {
                    // Read the full request body (CDP commands are small; cap at 8 MiB).
                    let mut body = Vec::new();
                    let mut buf = [0u8; 4096];
                    let mut recv = recv;
                    let mut send = send;
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                body.extend_from_slice(&buf[..n]);
                                if body.len() > 8 * 1024 * 1024 {
                                    let _ = send
                                        .write_all(br#"{"error":"command too large"}"#)
                                        .await;
                                    return;
                                }
                            }
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }

                    let response = match serde_json::from_slice::<RemoteCommand>(&body) {
                        Ok(cmd) => route_command_core(&registry, &cmd.session_id, &cmd.method, cmd.params)
                            .await
                            .unwrap_or_else(|e| {
                                serde_json::to_vec(&serde_json::json!({"error": e})).unwrap_or_default()
                            }),
                        Err(_) => {
                            serde_json::to_vec(&serde_json::json!({"error": "invalid command JSON"}))
                                .unwrap_or_default()
                        }
                    };
                    let _ = send.write_all(&response).await;
                });
            }
            Err(_) => return Ok(()),
        }
    }
}

/// Shared command-routing core used by both the local API and QUIC handler.
///
/// NOTE: real CDP dispatch is NOT wired. `SessionRegistry` only stores
/// routing metadata (which node owns a session, and its node-local id) — it
/// holds no `CdpClient` handle and no reference to a browser pool, so there
/// is no transport to forward a command to. Returning canned success here
/// would silently drop every remote command, so this returns an explicit
/// error instead. Wiring real dispatch requires extending `SessionRegistry`
/// (or the relay) with a live `CdpClient` per session and a round-trip
/// through `CdpClient::send_command[_with_session]`.
async fn route_command_core(
    registry: &SessionRegistry,
    session_id: &str,
    method: &str,
    _params: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let entry = registry
        .lookup(session_id)
        .await
        .ok_or_else(|| format!("session {} not found or expired", session_id))?;

    Err(format!(
        "relay dispatch not implemented: no browser client handle for session {} \
         (node {}, internal {}) — SessionRegistry stores routing metadata only; \
         wire a CdpClient handle into the registry to enable real CDP dispatch \
         (method {})",
        session_id, entry.node_id, entry.internal_session_id, method
    ))
}

/// Create a QUIC server config with a runtime-generated self-signed cert.
fn create_relay_server_config() -> Result<quinn::ServerConfig, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let subject_alt_names = vec![
        "localhost".to_string(),
        "tallow-relay".to_string(),
    ];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| format!("[CdpRelay] cert gen failed: {e}"))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| format!("[CdpRelay] key conversion failed: {e}"))?;

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("[CdpRelay] rustls config failed: {e}"))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("[CdpRelay] quic server config failed: {e}"))?,
    ));

    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
    ));

    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_relay() -> CdpRelay {
        let reg = SessionRegistry::new(Duration::from_secs(300));
        CdpRelay::new("127.0.0.1:0".parse().unwrap(), reg)
    }

    #[test]
    fn relay_not_running_initially() {
        let relay = make_relay();
        assert!(!relay.is_running());
    }

    #[tokio::test]
    async fn relay_start_creates_endpoint() {
        let relay = make_relay();
        relay.start().await.unwrap();
        assert!(relay.is_running());
        relay.stop();
        assert!(!relay.is_running());
    }

    #[tokio::test]
    async fn route_command_when_not_running() {
        let relay = make_relay();

        let result = relay.route_command("any-session", "Page.navigate", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not running"));
    }

    #[tokio::test]
    async fn route_command_session_not_found() {
        let reg = SessionRegistry::new(Duration::from_secs(300));
        let relay = CdpRelay::new("127.0.0.1:0".parse().unwrap(), reg);
        relay.start().await.unwrap();

        let result = relay.route_command("nonexistent", "Page.navigate", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found or expired"));
    }

    #[tokio::test]
    async fn route_command_dispatch_not_implemented() {
        // SessionRegistry holds routing metadata only — no live CdpClient
        // handle — so relay dispatch must fail honestly, never return a
        // canned {"result":{}} success.
        let reg = SessionRegistry::new(Duration::from_secs(300));
        reg.register(
            "ext-session-1".into(),
            "node-alpha".into(),
            "internal-99".into(),
        )
        .await;

        let relay = CdpRelay::new("127.0.0.1:0".parse().unwrap(), reg);
        relay.start().await.unwrap();

        let result = relay
            .route_command(
                "ext-session-1",
                "Page.navigate",
                Some(br#"{"url":"https://example.com"}"#.to_vec()),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("relay dispatch not implemented"),
            "expected honest dispatch error, got: {err}"
        );
    }
}
