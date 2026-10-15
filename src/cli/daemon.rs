use anyhow::Context;
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

use crate::ipc_auth::{self, Hello, Role, Session};

/// Discover daemon connection details from config files on disk.
/// Reads `~/.tallow/daemon/port` and `~/.tallow/daemon/token`.
fn discover_daemon() -> Option<(u16, String)> {
    let data_dir = dirs::data_dir()?.join("tallow").join("daemon");
    let port_str = std::fs::read_to_string(data_dir.join("port")).ok()?;
    let port: u16 = port_str.trim().parse().ok()?;
    let token = std::fs::read_to_string(data_dir.join("token")).ok()?;
    Some((port, token.trim().to_string()))
}

/// Header carrying the `ipc_auth` session id on daemon requests (audit).
const SESSION_HEADER: &str = "X-Tallow-Session";

/// Frozen handshake wire contract (see `docs/ops/ipc_auth.md` §Wire contract).
///
/// The client opens `POST {base_url}/auth/handshake` carrying its [`Hello`]
/// and initiator proof; the daemon answers `200` with its own [`Hello`] (same
/// transcript) and the responder proof. Both hello headers carry the
/// lowercase-hex UTF-8 JSON serialization of `ipc_auth::Hello` (the serde
/// wire form pinned by the module's tests); the proof headers carry the
/// 64-hex HMAC proofs verbatim.
const HANDSHAKE_PATH: &str = "/auth/handshake";
const HELLO_HEADER: &str = "X-Tallow-Hello";
const INITIATOR_HEADER: &str = "X-Tallow-Initiator";
const RESPONDER_HEADER: &str = "X-Tallow-Responder";

/// Modest per-request timeout for the handshake exchange: a slow or
/// unreachable daemon must never stall the request path — the caller
/// downgrades to no session (`X-Tallow-Session: none`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// TTL for the per-invocation audit session (one CLI command's requests).
const SESSION_TTL_MS: i64 = 60_000;

/// Lowercase hex encoding (same canonical form the module uses for nonces and
/// proofs).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Strict hex decoding: even length, hex alphabet, either case accepted.
/// `None` for anything malformed — a bad wire value is a failed handshake,
/// never a panic.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((nibble(bytes[i])? << 4) | nibble(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Encode a [`Hello`] for the [`HELLO_HEADER`] wire header: lowercase hex of
/// its canonical serde JSON form.
fn encode_hello(h: &Hello) -> Option<String> {
    let bytes: Vec<u8> = serde_json::to_vec(h).ok()?;
    Some(to_hex(&bytes))
}

/// Decode a [`HELLO_HEADER`] wire value back into a [`Hello`]. Refuses
/// non-hex bytes and JSON that is not a `Hello` (⇒ handshake failure → no
/// session, never a panic).
fn decode_hello(hex: &str) -> Option<Hello> {
    let bytes = from_hex(hex)?;
    serde_json::from_slice(&bytes).ok()
}

/// Complete the client half of the `ipc_auth` handshake from raw wire
/// material: both hellos (ours and the daemon's) and both role proofs.
///
/// The daemon's hello must echo **our transcript** (same
/// `initiator`/`responder`/`nonce` — the module's transcript binding);
/// [`Session::establish`] then re-verifies **both** proofs against the PSK in
/// constant time, checks the replay guard, and mints the session. Pure and
/// clock-free (`now_ms` is passed in), so tests drive it with a locally
/// generated daemon hello + responder proof — no network, no daemon.
fn complete_handshake(
    psk: &[u8],
    local_hello: &Hello,
    initiator_proof: &str,
    daemon_hello: &Hello,
    responder_proof: &str,
    now_ms: i64,
    ttl_ms: i64,
) -> Option<String> {
    // The responder proof is only meaningful over a hello carrying our
    // transcript; a moved nonce/ids means the daemon answered a different
    // handshake — refuse before any crypto.
    if ipc_auth::transcript(local_hello) != ipc_auth::transcript(daemon_hello) {
        return None;
    }
    let mut seen = ipc_auth::SeenNonces::new();
    let session = Session::establish(
        psk,
        daemon_hello,
        initiator_proof,
        responder_proof,
        now_ms,
        ttl_ms,
        &mut seen,
    )
    .ok()?;
    session.valid(now_ms).then_some(session.id)
}

/// Establish the client half of the `ipc_auth` handshake for this invocation
/// and mint its audit session id (B7.1.2 wiring — see `docs/ops/ipc_auth.md`,
/// §Wire contract).
///
/// Real **mutual** verification: opens the handshake (fresh nonce → hello →
/// initiator proof) and sends it to `POST {base_url}`[`HANDSHAKE_PATH`]. Only
/// a `200` response that echoes the transcript **and** carries a responder
/// proof verifying against the same PSK mints a session — the responder half
/// runs in the daemon. `401` = replayed nonce / bad proof; `400` = bad input.
/// Never fails the request path: empty token, connection error, timeout, an
/// old daemon without the route (404), any non-`200`, or a verification
/// failure ⇒ `None` — the request goes out with `X-Tallow-Session: none`
/// (honest downgrade), bearer flow unchanged.
async fn establish_audit_session(client: &Client, base_url: &str, token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;

    // 32 random bytes, lowercase hex (canonical nonce form).
    let mut nonce_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce: String = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let hello = ipc_auth::hello("tallow-cli", "tallow-daemon", &nonce).ok()?;
    let initiator = ipc_auth::proof(token.as_bytes(), &hello, Role::Initiator).ok()?;
    let hello_hex = encode_hello(&hello)?;

    // The bearer token rides along too, so the route also passes the daemon's
    // existing bearer middleware when it sits behind it.
    let resp = client
        .post(format!("{base_url}{HANDSHAKE_PATH}"))
        .header("Authorization", format!("Bearer {}", token))
        .header(HELLO_HEADER, hello_hex)
        .header(INITIATOR_HEADER, initiator.as_str())
        .timeout(HANDSHAKE_TIMEOUT)
        .send()
        .await
        .ok()?;

    // 200 = verified; 401 = replayed/bad proof; 400 = bad input. Every other
    // status (404 from a pre-handshake daemon, 5xx, …) is a downgrade too:
    // no session, requests still go out with `none`.
    if !resp.status().is_success() {
        return None;
    }

    let daemon_hello = decode_hello(resp.headers().get(HELLO_HEADER)?.to_str().ok()?)?;
    let responder = resp.headers().get(RESPONDER_HEADER)?.to_str().ok()?;
    complete_handshake(
        token.as_bytes(),
        &hello,
        &initiator,
        &daemon_hello,
        responder,
        now_ms,
        SESSION_TTL_MS,
    )
}

/// Create an HTTP client and base URL for talking to the daemon.
/// Returns (client, base_url, token, session) or None if daemon not running.
/// `session` (B7.1.2) is the `ipc_auth` audit value attached to requests as
/// [`SESSION_HEADER`]; `None` when the mutual handshake could not run
/// (honest downgrade — the bearer flow is unchanged).
async fn daemon_client() -> Option<(Client, String, String, Option<String>)> {
    let (port, token) = discover_daemon()?;
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();
    let session = establish_audit_session(&client, &base_url, &token).await;
    Some((client, base_url, token, session))
}

/// Handle `tallow daemon status` — health check against the daemon.
pub async fn daemon_status() -> anyhow::Result<()> {
    match discover_daemon() {
        Some((port, _token)) => {
            let url = format!("http://127.0.0.1:{}/health", port);
            let resp = reqwest::get(&url).await.context("failed to connect to daemon")?;
            if resp.status().is_success() {
                let body: Value = resp.json().await.unwrap_or_default();
                println!("Daemon: running");
                println!(
                    "  Status:    {}",
                    body["status"].as_str().unwrap_or("unknown")
                );
                println!(
                    "  Uptime:    {:.1}s",
                    body["uptime_secs"].as_f64().unwrap_or(0.0)
                );
                println!(
                    "  Version:   {}",
                    body["version"].as_str().unwrap_or("unknown")
                );
                println!(
                    "  Jobs:      {}",
                    body["active_jobs"].as_u64().unwrap_or(0)
                );
                println!("  Port:      {}", port);
            } else {
                println!("Daemon: error (HTTP {})", resp.status());
            }
        }
        None => {
            println!("Daemon: not running");
            println!("  (No port/token file found in ~/.tallow/daemon/)");
        }
    }
    Ok(())
}

/// Handle `tallow daemon stop` — POST /shutdown.
pub async fn daemon_stop() -> anyhow::Result<()> {
    let (client, base_url, token, session) = daemon_client()
        .await
        .context("Daemon is not running (no port/token found)")?;

    let resp = client
        .post(format!("{}/shutdown", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .header(SESSION_HEADER, session.as_deref().unwrap_or("none"))
        .send()
        .await
        .context("failed to connect to daemon")?;

    if resp.status().is_success() {
        let body: Value = resp.json().await.unwrap_or_default();
        println!(
            "Daemon: {}",
            body["status"].as_str().unwrap_or("shutting_down")
        );
    } else {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to stop daemon: {}", body);
    }
    Ok(())
}

/// Handle `tallow job list [--status <status>]`.
pub async fn job_list(status_filter: Option<String>) -> anyhow::Result<()> {
    let (client, base_url, token, session) =
        daemon_client().await.context("Daemon is not running (no port/token found)")?;

    let mut url = format!("{}/jobs", base_url);
    if let Some(ref status) = status_filter {
        url = format!("{}?status={}", url, status);
    }

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header(SESSION_HEADER, session.as_deref().unwrap_or("none"))
        .send()
        .await
        .context("failed to connect to daemon")?;

    let body: Value = resp.json().await.unwrap_or_default();
    let jobs = body["jobs"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);

    if jobs.is_empty() {
        println!("No jobs found.");
    } else {
        println!(
            "{:<36} | {:<12} | {:<20} | {}",
            "ID", "Status", "Name", "Created"
        );
        println!("{}", "-".repeat(90));
        for job in jobs {
            let name = job["name"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(20)
                .collect::<String>();
            println!(
                "{:<36} | {:<12} | {:<20} | {}",
                job["id"].as_str().unwrap_or(""),
                job["status"].as_str().unwrap_or(""),
                name,
                job["created_at"].as_str().unwrap_or(""),
            );
        }
    }
    Ok(())
}

/// Handle `tallow job submit <script>` — POST /jobs.
pub async fn job_submit(script_path: &str) -> anyhow::Result<()> {
    let (client, base_url, token, session) =
        daemon_client().await.context("Daemon is not running (no port/token found)")?;

    // Read the script file
    let script_content =
        std::fs::read_to_string(script_path).context("failed to read script file")?;
    let script_name = PathBuf::from(script_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "untitled".to_string());

    let body = serde_json::json!({
        "name": script_name,
        "config": {
            "script": script_content,
            "type": "tallow_script"
        }
    });

    let resp = client
        .post(format!("{}/jobs", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .header(SESSION_HEADER, session.as_deref().unwrap_or("none"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .context("failed to connect to daemon")?;

    if resp.status().is_success() {
        let job: Value = resp.json().await.unwrap_or_default();
        println!("Job submitted: {}", job["id"].as_str().unwrap_or("unknown"));
        println!(
            "Status: {}",
            job["status"].as_str().unwrap_or("unknown")
        );
    } else {
        let status = resp.status();
        let error = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            // The daemon rejected the job at submit time (honest contract).
            // Surface its reason verbatim so the user knows the job was never
            // queued.
            anyhow::bail!("Job rejected at submit time (HTTP 422): {}", error.trim());
        }
        anyhow::bail!("Failed to submit job (HTTP {}): {}", status, error.trim());
    }
    Ok(())
}

/// Handle `tallow job show <id>` — GET /jobs/{id}.
pub async fn job_show(id: &str) -> anyhow::Result<()> {
    let (client, base_url, token, session) =
        daemon_client().await.context("Daemon is not running (no port/token found)")?;

    let resp = client
        .get(format!("{}/jobs/{}", base_url, id))
        .header("Authorization", format!("Bearer {}", token))
        .header(SESSION_HEADER, session.as_deref().unwrap_or("none"))
        .send()
        .await
        .context("failed to connect to daemon")?;

    if resp.status().is_success() {
        let job: Value = resp.json().await.unwrap_or_default();
        println!("Job: {}", id);
        println!("  Name:       {}", job["name"].as_str().unwrap_or(""));
        println!("  Status:     {}", job["status"].as_str().unwrap_or(""));
        println!(
            "  Created:    {}",
            job["created_at"].as_str().unwrap_or("")
        );
        println!(
            "  Updated:    {}",
            job["updated_at"].as_str().unwrap_or("")
        );
        if let Some(err) = job["error_message"].as_str() {
            if !err.is_empty() {
                println!("  Error:      {}", err);
            }
        }
    } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("Job not found: {}", id);
    } else {
        let error = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to get job: {}", error);
    }
    Ok(())
}

/// Handle `tallow job history <id>` — GET /jobs/{id}/history.
pub async fn job_history(id: &str) -> anyhow::Result<()> {
    let (client, base_url, token, session) =
        daemon_client().await.context("Daemon is not running (no port/token found)")?;

    let resp = client
        .get(format!("{}/jobs/{}/history", base_url, id))
        .header("Authorization", format!("Bearer {}", token))
        .header(SESSION_HEADER, session.as_deref().unwrap_or("none"))
        .send()
        .await
        .context("failed to connect to daemon")?;

    if resp.status().is_success() {
        let body: Value = resp.json().await.unwrap_or_default();
        let events = body["events"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        println!("History for job {}:", id);
        for event in events {
            println!(
                "  {} | {} | {}",
                event["timestamp"].as_str().unwrap_or(""),
                event["event"].as_str().unwrap_or(""),
                event["detail"].as_str().unwrap_or(""),
            );
        }
    } else {
        let error = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to get job history: {}", error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PSK for the in-process exchange — the role the on-disk daemon token
    /// plays live.
    const PSK: &[u8] = b"token-abc";

    /// Canonical 64-lowercase-hex nonces (the module's nonce pin).
    const NONCE_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// One full exchange over the frozen wire form, no network: the client
    /// half runs exactly as `establish_audit_session` does around transport,
    /// and the "daemon" half is the module's responder role over the decoded
    /// wire hello.
    fn in_process_exchange(psk: &[u8], nonce: &str) -> Option<String> {
        // Client: opening hello + initiator proof, encoded for the wire.
        let hello = ipc_auth::hello("tallow-cli", "tallow-daemon", nonce).expect("valid hello");
        let initiator = ipc_auth::proof(psk, &hello, Role::Initiator).expect("initiator proof");
        let hello_wire = encode_hello(&hello).expect("hello encodes");

        // Daemon: decode the wire hello, answer over the same transcript.
        let daemon_hello = decode_hello(&hello_wire).expect("hello decodes");
        let responder =
            ipc_auth::proof(psk, &daemon_hello, Role::Responder).expect("responder proof");

        // Client: verify both hellos + both proofs and mint the session.
        complete_handshake(
            psk,
            &hello,
            &initiator,
            &daemon_hello,
            &responder,
            1_000,
            SESSION_TTL_MS,
        )
    }

    #[test]
    fn audit_session_mints_a_valid_session_id() {
        // The real handshake shape: a daemon hello + responder proof (the
        // module's responder half) over our wire hello mint the session. The
        // id is transcript-derived — stable for the same exchange (so the
        // daemon computes the same value and can validate it), distinct
        // across nonces.
        let a = in_process_exchange(PSK, NONCE_A).expect("session minted");
        assert!(a.starts_with("sess-"));
        assert_eq!(a.len(), 17);
        let a_again = in_process_exchange(PSK, NONCE_A).expect("session minted");
        assert_eq!(a, a_again, "same exchange ⇒ same id on both sides");
        let b = in_process_exchange(PSK, NONCE_B).expect("session minted");
        assert_ne!(a, b);
    }

    #[test]
    fn hello_wire_roundtrip_and_strict_decode() {
        let hello = ipc_auth::hello("tallow-cli", "tallow-daemon", NONCE_A).unwrap();
        let wire = encode_hello(&hello).expect("hello encodes");
        assert!(
            wire.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "wire hello must be lowercase hex"
        );
        assert_eq!(decode_hello(&wire), Some(hello));
        // Malformed wire values refuse instead of panicking:
        assert_eq!(decode_hello("not-hex"), None);
        assert_eq!(decode_hello(&wire[..wire.len() - 1]), None); // odd hex length
        assert_eq!(decode_hello("7b7d"), None); // "{}" is not a Hello
    }

    #[test]
    fn handshake_refuses_bad_responder_evidence() {
        let hello = ipc_auth::hello("tallow-cli", "tallow-daemon", NONCE_A).unwrap();
        let initiator = ipc_auth::proof(PSK, &hello, Role::Initiator).unwrap();

        // Responder proof minted with a different PSK: BadProof, no session.
        let forged = ipc_auth::proof(b"wrong-psk", &hello, Role::Responder).unwrap();
        assert_eq!(
            complete_handshake(
                PSK,
                &hello,
                &initiator,
                &hello,
                &forged,
                1_000,
                SESSION_TTL_MS
            ),
            None
        );

        // Responder proof over a moved transcript: the hello echo check
        // refuses before any crypto.
        let moved = ipc_auth::hello("tallow-cli", "tallow-daemon", NONCE_B).unwrap();
        let responder = ipc_auth::proof(PSK, &moved, Role::Responder).unwrap();
        assert_eq!(
            complete_handshake(
                PSK,
                &hello,
                &initiator,
                &moved,
                &responder,
                1_000,
                SESSION_TTL_MS
            ),
            None
        );
    }

    #[test]
    fn handshake_refuses_a_role_swapped_proof() {
        // The responder proof replayed in the initiator slot fails the
        // module's role binding inside `Session::establish`.
        let hello = ipc_auth::hello("tallow-cli", "tallow-daemon", NONCE_A).unwrap();
        let responder = ipc_auth::proof(PSK, &hello, Role::Responder).unwrap();
        assert_eq!(
            complete_handshake(
                PSK,
                &hello,
                &responder,
                &hello,
                &responder,
                1_000,
                SESSION_TTL_MS
            ),
            None
        );
    }

    #[tokio::test]
    async fn audit_session_is_withheld_for_empty_token() {
        // Empty token short-circuits before any I/O: the unroutable base URL
        // proves no request is attempted.
        let client = Client::new();
        assert_eq!(
            establish_audit_session(&client, "http://127.0.0.1:1", "").await,
            None
        );
    }
}
