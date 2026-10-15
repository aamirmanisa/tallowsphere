//! Revocation check-at-use gate at the daemon's **session-admission seam**
//! (row #127 leg b: R-5.11 + freshness — "checked at every use").
//!
//! Design (U-201 G-09 / D-4; report §5.4 + ATK-2.3 mitigation 1):
//!
//! * The narrowest existing seam for a *new* session is the accepted
//!   `POST /auth/handshake` → registry insert in [`crate::routes::handshake`].
//!   Between those two steps the handler consults [`DaemonRevocationGate::admit`]
//!   — the session is only minted when the gate admits it. Established
//!   sessions are deliberately untouched (a stale list refuses *new*
//!   sessions, per D-4).
//! * The policy is the landed tallow-svid model: a signed [`RevocationList`]
//!   verified against a pinned Ed25519 signer, applied through
//!   [`RevocationGate`], and re-checked for freshness **at use**
//!   (`min(ttl/2, 6 h)` ceiling). Every refusal is fail-closed and typed.
//! * Policy source (no new formats): `<data_dir>/revocation/signer.hex`
//!   (64 hex chars = the trusted 32-byte Ed25519 public key) and
//!   `<data_dir>/revocation/list.json` (the serde form of the signed list).
//! * Mode (`TALLOW_DAEMON_REVOCATION`): `off` disables the gate (staged,
//!   logged); `enforce` requires a loadable, fresh list; **unset** ⇒ enforce
//!   iff both files exist; any unrecognized value ⇒ enforce (fail-closed) with
//!   a loud warning. In `enforce` mode with no loadable policy every new
//!   session is refused (`revocation_unavailable`) — never a silent pass.
//! * KT logging: the gate returns a [`RevocationEventV1`] payload for every
//!   decision; this module emits it on the `tracing` stream. Appending those
//!   payloads to the key-transparency log is the root-crate bridge
//!   (`tallow::kt_log::KtLog::append_json` — see the lane log §OPEN: the
//!   daemon binary cannot depend on the root crate).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tallow_svid::revocation::{
    AdmissionRefusal, RevocationEventV1, RevocationGate, RevocationList, REVOCATION_MAX_AGE_SECS,
};

/// Enforcement mode of the daemon's revocation gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// The gate is not consulted (staged coverage; logged at startup).
    Off,
    /// Every new session must pass the gate; refusals are fail-closed.
    Enforce,
}

impl GateMode {
    /// Stable label for logs/tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Enforce => "enforce",
        }
    }
}

/// What the gate decided for one new-session admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Mode `off`: no revocation evidence was consulted (staged label).
    NotChecked,
    /// Mode `enforce`: checked and admitted on a fresh list.
    Admitted {
        /// Age of the applied list at admission (seconds).
        age_secs: i64,
        /// Applied high-water sequence.
        list_seq: u64,
        /// The KT payload for the decision (caller may append it).
        event: RevocationEventV1,
    },
}

/// A fail-closed refusal for one new-session admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Machine-readable code (`revocation_*`), for the HTTP body + logs.
    pub code: &'static str,
    /// Human-readable detail (typed reason, never a silent pass).
    pub detail: String,
    /// The KT payload for the decision, when a policy was consulted.
    pub event: Option<RevocationEventV1>,
}

/// Daemon-side revocation admission gate: mode + loaded policy.
///
/// Construct once at boot ([`Self::resolve`]); the handler consults
/// [`Self::admit`] before registering a newly minted session.
#[derive(Debug)]
pub struct DaemonRevocationGate {
    mode: GateMode,
    dir: PathBuf,
    /// The loaded policy (only ever `Some` after a successful load+apply).
    gate: Option<Mutex<RevocationGate>>,
    /// Why the policy could not be loaded/used (diagnostics; never a pass).
    load_note: Option<String>,
}

/// Environment variable selecting the mode (see module docs).
pub const MODE_ENV: &str = "TALLOW_DAEMON_REVOCATION";

impl DaemonRevocationGate {
    /// Resolve the gate from `data_dir` + [`MODE_ENV`] (see module docs).
    pub fn resolve(data_dir: &Path) -> Self {
        Self::resolve_with(data_dir, std::env::var(MODE_ENV).ok().as_deref())
    }

    /// Resolve with an explicit mode value — the deterministic entry point
    /// (tests never mutate the process environment).
    pub fn resolve_with(data_dir: &Path, mode_env: Option<&str>) -> Self {
        let dir = data_dir.join("revocation");
        let files_present = dir.join("signer.hex").is_file() && dir.join("list.json").is_file();
        let mode = match mode_env {
            Some(v) if v.eq_ignore_ascii_case("off") => GateMode::Off,
            Some(v) if v.eq_ignore_ascii_case("enforce") => GateMode::Enforce,
            Some(v) => {
                tracing::warn!(
                    value = v,
                    "{MODE_ENV} value not recognized — treating as `enforce` (fail-closed)"
                );
                GateMode::Enforce
            }
            None if files_present => GateMode::Enforce,
            None => GateMode::Off,
        };

        let mut gate = Self {
            mode,
            dir: dir.clone(),
            gate: None,
            load_note: None,
        };
        if mode == GateMode::Enforce {
            match gate.load(now_unix_secs()) {
                Ok(()) => {}
                Err(note) => {
                    tracing::warn!(
                        dir = %dir.display(),
                        note = %note,
                        "revocation policy not loadable; new sessions will be refused (fail-closed)"
                    );
                    gate.load_note = Some(note);
                }
            }
        } else {
            tracing::info!(
                "revocation admission gate is OFF (staged coverage; set {MODE_ENV}=enforce to arm)"
            );
        }
        gate
    }

    /// A gate that is never consulted (tests / staged deployments; mode `off`).
    pub fn disabled() -> Self {
        Self {
            mode: GateMode::Off,
            dir: PathBuf::new(),
            gate: None,
            load_note: None,
        }
    }

    /// The resolved mode.
    pub fn mode(&self) -> GateMode {
        self.mode
    }

    /// Whether a policy is loaded and usable.
    pub fn policy_loaded(&self) -> bool {
        self.gate.is_some()
    }

    /// Why the policy is not loaded (empty when it is / when mode is `off`).
    pub fn load_note(&self) -> Option<&str> {
        self.load_note.as_deref()
    }

    /// Policy directory this gate resolves from.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// (Re)load `signer.hex` + `list.json` and apply the list at `now`.
    /// Returns a diagnostic string on refusal; nothing is swapped in unless
    /// the list verifies, is fresh, and advances the sequence.
    fn load(&mut self, now: i64) -> Result<(), String> {
        let signer_path = self.dir.join("signer.hex");
        let list_path = self.dir.join("list.json");

        let signer_raw = std::fs::read_to_string(&signer_path)
            .map_err(|e| format!("{}: {e}", signer_path.display()))?;
        let signer_bytes = decode_hex(signer_raw.trim())
            .ok_or_else(|| format!("{}: not valid hex", signer_path.display()))?;
        let signer: [u8; 32] = signer_bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "{}: expected 32 bytes (64 hex chars), got {}",
                signer_path.display(),
                v.len()
            )
        })?;

        let list_bytes = std::fs::read(&list_path)
            .map_err(|e| format!("{}: {e}", list_path.display()))?;
        let list: RevocationList = serde_json::from_slice(&list_bytes)
            .map_err(|e| format!("{}: {e}", list_path.display()))?;

        // The 6 h ceiling of `min(ttl/2, 6 h)`; when the SVID TTL is wired
        // through the daemon (G-06 family), construct with `for_ttl(ttl)`.
        let mut gate = RevocationGate::new(signer, REVOCATION_MAX_AGE_SECS);
        match gate.apply_list(&list, now) {
            (Ok(_), _) => {
                tracing::info!(
                    dir = %self.dir.display(),
                    seq = list.seq,
                    issued_at = list.issued_at,
                    entries = list.entries.len(),
                    "revocation policy loaded and applied"
                );
                self.gate = Some(Mutex::new(gate));
                self.load_note = None;
                Ok(())
            }
            (Err(err), _) => Err(format!("list refused: {err}")),
        }
    }

    /// Check **at use**: may a new session (for `serial`, when one is
    /// presented) be admitted at `now_secs` (unix seconds)?
    ///
    /// * mode `off` → [`Admission::NotChecked`] (staged; never silently armed).
    /// * mode `enforce` with no loaded policy → refusal `revocation_unavailable`.
    /// * otherwise the tallow-svid gate decides: freshness at use + membership.
    pub fn admit(&self, now_secs: i64, serial: Option<&str>) -> Result<Admission, Refusal> {
        if self.mode == GateMode::Off {
            return Ok(Admission::NotChecked);
        }
        let Some(gate) = self.gate.as_ref() else {
            return Err(Refusal {
                code: "revocation_unavailable",
                detail: self
                    .load_note
                    .clone()
                    .unwrap_or_else(|| "no revocation policy loaded".to_string()),
                event: None,
            });
        };
        let gate = gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (verdict, event) = gate.admit_new_session(now_secs, serial);
        match verdict {
            Ok(permit) => Ok(Admission::Admitted {
                age_secs: permit.age_secs,
                list_seq: permit.list_seq,
                event,
            }),
            Err(refusal) => Err(Refusal {
                code: refusal_code(&refusal),
                detail: format!("{refusal:?}"),
                event: Some(event),
            }),
        }
    }
}

/// HTTP/JSON code for a tallow-svid admission refusal.
pub fn refusal_code(refusal: &AdmissionRefusal) -> &'static str {
    match refusal {
        AdmissionRefusal::NoList => "revocation_no_list",
        AdmissionRefusal::ListFromFuture { .. } => "revocation_list_from_future",
        AdmissionRefusal::Stale { .. } => "revocation_stale",
        AdmissionRefusal::Revoked { .. } => "revocation_revoked",
    }
}

/// Unix seconds (pre-epoch ⇒ 0).
pub(crate) fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Strict lowercase/uppercase hex decode (`None` on any malformed input).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tallow_svid::revocation::{RevocationEntry, RevocationReason, REVOCATION_MAX_AGE_SECS};

    use tallow_crypto::sig::ed25519::Ed25519Signer;

    const NOW: i64 = 1_800_000_000;

    fn signer() -> Ed25519Signer {
        Ed25519Signer::keygen()
    }

    fn list_of(key: &Ed25519Signer, seq: u64, issued_at: i64, serial: &str) -> RevocationList {
        let entry = RevocationEntry::sign(key, serial, RevocationReason::KeyCompromise, issued_at)
            .expect("entry builds");
        RevocationList::sign(key, seq, issued_at, vec![entry]).expect("list signs")
    }

    fn write_policy(dir: &Path, key: &Ed25519Signer, list: &RevocationList) {
        std::fs::create_dir_all(dir).expect("mkdir");
        std::fs::write(
            dir.join("signer.hex"),
            hex_encode(&key.verifying_key_bytes()),
        )
        .expect("signer");
        std::fs::write(dir.join("list.json"), serde_json::to_vec(list).expect("json"))
            .expect("list");
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn off_mode_admits_without_consulting_policy() {
        let gate = DaemonRevocationGate::disabled();
        assert_eq!(gate.mode(), GateMode::Off);
        assert_eq!(gate.admit(NOW, None).unwrap(), Admission::NotChecked);
    }

    #[test]
    fn enforce_mode_without_policy_refuses_every_new_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No files under <data_dir>/revocation; force enforce via the explicit
        // mode value (no process-environment mutation — parallel-safe).
        let gate = DaemonRevocationGate::resolve_with(dir.path(), Some("enforce"));

        assert_eq!(gate.mode(), GateMode::Enforce);
        assert!(!gate.policy_loaded());
        let refusal = gate.admit(NOW, None).expect_err("must refuse");
        assert_eq!(refusal.code, "revocation_unavailable");
        assert!(refusal.event.is_none(), "no policy → no event to log");
    }

    #[test]
    fn auto_enforce_when_policy_files_present_and_admit_on_fresh_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signer();
        let now = now_unix_secs();
        write_policy(
            &dir.path().join("revocation"),
            &key,
            &list_of(&key, 1, now - 60, "svid-revoked"),
        );

        // Unset env: files present ⇒ auto-enforce.
        let gate = DaemonRevocationGate::resolve(dir.path());
        assert_eq!(gate.mode(), GateMode::Enforce);
        assert!(gate.policy_loaded());

        let admission = gate.admit(now, None).expect("fresh list admits");
        match admission {
            Admission::Admitted { age_secs, list_seq, event } => {
                assert_eq!(age_secs, 60);
                assert_eq!(list_seq, 1);
                assert_eq!(event.kind.as_str(), "revocation_admission_allowed");
            }
            other => panic!("expected Admitted, got {other:?}"),
        }

        // A revoked serial (when presented) is refused by the same gate.
        let refusal = gate.admit(now, Some("svid-revoked")).expect_err("revoked");
        assert_eq!(refusal.code, "revocation_revoked");
        assert_eq!(
            refusal.event.as_ref().map(|e| e.reason.as_deref()),
            Some(Some("revoked"))
        );
    }

    #[test]
    fn enforce_refuses_stale_policy_at_use() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signer();
        let now = now_unix_secs();
        write_policy(
            &dir.path().join("revocation"),
            &key,
            // Fresh at load…
            &list_of(&key, 3, now, "svid-a"),
        );
        let gate = DaemonRevocationGate::resolve(dir.path());
        assert!(gate.policy_loaded());
        // …stale one second past the 6 h ceiling at the moment of use.
        let stale_at = now + REVOCATION_MAX_AGE_SECS + 1;
        let refusal = gate.admit(stale_at, None).expect_err("stale refuses");
        assert_eq!(refusal.code, "revocation_stale");
        assert_eq!(
            refusal.event.as_ref().map(|e| e.reason.as_deref()),
            Some(Some("stale"))
        );
    }

    #[test]
    fn enforce_refuses_bad_signer_policy_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signer();
        let rogue = signer();
        let now = now_unix_secs();
        // Signer file pins `key`, but the list is signed by `rogue`.
        write_policy(
            &dir.path().join("revocation"),
            &key,
            &list_of(&rogue, 1, now, "svid-forged"),
        );
        let gate = DaemonRevocationGate::resolve(dir.path());
        assert_eq!(gate.mode(), GateMode::Enforce, "files present ⇒ armed");
        assert!(!gate.policy_loaded(), "forged list never loads");
        let refusal = gate.admit(now, None).expect_err("unavailable");
        assert_eq!(refusal.code, "revocation_unavailable");
        assert!(
            refusal.detail.contains("list refused"),
            "detail names the typed refusal: {}",
            refusal.detail
        );
    }

    #[test]
    fn malformed_signer_file_refuses_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signer();
        let now = now_unix_secs();
        let policy_dir = dir.path().join("revocation");
        std::fs::create_dir_all(&policy_dir).expect("mkdir");
        std::fs::write(policy_dir.join("signer.hex"), "zz-not-hex").expect("signer");
        std::fs::write(
            policy_dir.join("list.json"),
            serde_json::to_vec(&list_of(&key, 1, now, "svid-a")).expect("json"),
        )
        .expect("list");

        let gate = DaemonRevocationGate::resolve(dir.path());
        assert_eq!(gate.mode(), GateMode::Enforce);
        assert!(!gate.policy_loaded());
        assert_eq!(
            gate.admit(now, None).expect_err("refused").code,
            "revocation_unavailable"
        );
    }

    // ── Route-level seam tests (POST /auth/handshake) ───────────────────────
    //
    // These drive the real handler with a real `AppState`, so the refusal /
    // mint decision measured is the seam's, not a helper's.

    const PSK: &str = "tallow-ipc-test-psk";
    const NONCE_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_state(data_dir: PathBuf, gate: DaemonRevocationGate) -> std::sync::Arc<crate::AppState> {
        std::sync::Arc::new(crate::AppState {
            config: crate::config::Config {
                bind_addr: String::new(),
                port: 0,
                token: PSK.to_string(),
                data_dir: data_dir.clone(),
                token_path: data_dir.join("token"),
                port_file: data_dir.join("port"),
                db_path: data_dir.join("daemon.db"),
                tallow_bin: None,
                concurrency_limit: 4,
                retry_base_ms: 1000,
                retry_max_ms: 60000,
                retry_jitter_ms: 500,
                bandwidth_limit_bytes_per_sec: 0,
                bandwidth_schedule: Vec::new(),
                watch_dirs: Vec::new(),
                debounce_delay_ms: 2000,
                debounce_large_file_ms: 10000,
                large_file_threshold_bytes: 10485760,
            },
            start_time: std::time::Instant::now(),
            db: std::sync::Arc::new(tokio::sync::Mutex::new(
                rusqlite::Connection::open_in_memory().expect("in-memory db"),
            )),
            progress_tx: tokio::sync::broadcast::channel::<crate::sse::ProgressEvent>(4).0,
            shutdown_tx: tokio::sync::watch::channel(false).0,
            device_id: "m127-test-device".to_string(),
            ipc_auth_seen: std::sync::Mutex::new(crate::ipc_auth::SeenNonces::new()),
            ipc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            revocation: std::sync::Arc::new(gate),
        })
    }

    /// The client's wire material: (`X-Tallow-Hello` hex, initiator proof).
    fn wire_material(psk: &[u8], nonce: &str) -> (String, String) {
        let hello = crate::ipc_auth::hello("tallow-cli", "tallow-daemon", nonce).expect("hello");
        let hello_hex = serde_json::to_vec(&hello)
            .expect("json")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let proof = crate::ipc_auth::proof(psk, &hello, crate::ipc_auth::Role::Initiator)
            .expect("proof");
        (hello_hex, proof)
    }

    async fn post_handshake(
        state: std::sync::Arc<crate::AppState>,
        hello_hex: &str,
        proof: &str,
    ) -> axum::response::Response {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Tallow-Hello", hello_hex.parse().expect("header"));
        headers.insert("X-Tallow-Initiator", proof.parse().expect("header"));
        crate::routes::handshake::handshake_handler(axum::extract::State(state), headers).await
    }

    #[tokio::test]
    async fn handshake_route_mints_and_registers_session_when_gate_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = test_state(dir.path().to_path_buf(), DaemonRevocationGate::disabled());
        let (hello_hex, proof) = wire_material(PSK.as_bytes(), NONCE_A);

        let response = post_handshake(state.clone(), &hello_hex, &proof).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            state.ipc_sessions.lock().expect("lock").len(),
            1,
            "gate off (staged) preserves the existing mint path"
        );
    }

    #[tokio::test]
    async fn handshake_route_refuses_new_session_when_gate_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Enforcing with no policy files: every new session must be refused.
        let gate = DaemonRevocationGate::resolve_with(dir.path(), Some("enforce"));
        let state = test_state(dir.path().to_path_buf(), gate);
        let (hello_hex, proof) = wire_material(PSK.as_bytes(), NONCE_A);

        let response = post_handshake(state.clone(), &hello_hex, &proof).await;
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(body["error"], "revocation_unavailable");
        assert!(
            state.ipc_sessions.lock().expect("lock").is_empty(),
            "a refused admission must not register a session"
        );
    }

    #[tokio::test]
    async fn handshake_route_mints_session_when_gate_admits_on_fresh_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signer();
        let now = now_unix_secs();
        write_policy(
            &dir.path().join("revocation"),
            &key,
            &list_of(&key, 1, now, "svid-revoked"),
        );
        let gate = DaemonRevocationGate::resolve(dir.path());
        assert!(gate.policy_loaded());
        let state = test_state(dir.path().to_path_buf(), gate);
        let (hello_hex, proof) = wire_material(PSK.as_bytes(), NONCE_A);

        let response = post_handshake(state.clone(), &hello_hex, &proof).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(state.ipc_sessions.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn handshake_route_refuses_bad_proof_before_the_gate() {
        // The gate must not see (or need) a policy when the handshake itself
        // fails: a bad initiator proof refuses 401 with no gate consulted.
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = DaemonRevocationGate::resolve_with(dir.path(), Some("enforce"));
        let state = test_state(dir.path().to_path_buf(), gate);
        let (hello_hex, _good) = wire_material(PSK.as_bytes(), NONCE_A);
        let bad_hello = crate::ipc_auth::hello("tallow-cli", "tallow-daemon", NONCE_A)
            .expect("hello");
        let bad = crate::ipc_auth::proof(b"wrong-psk", &bad_hello, crate::ipc_auth::Role::Initiator)
            .expect("proof");

        let response = post_handshake(state.clone(), &hello_hex, &bad).await;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(state.ipc_sessions.lock().expect("lock").is_empty());
    }
}
