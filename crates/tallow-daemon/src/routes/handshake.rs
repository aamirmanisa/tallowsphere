//! `POST /auth/handshake` — the daemon's accepting (responder) side of the
//! `ipc_auth` mutual handshake (B7.1.2).
//!
//! Frozen wire contract (`docs/ops/ipc_auth.md` §Wire contract): the client
//! opens with `X-Tallow-Hello` — lowercase hex of the UTF-8 JSON
//! serialization of its `Hello` — plus `X-Tallow-Initiator`, the initiator
//! proof (64 lowercase hex characters). On success the daemon answers `200`
//! with `X-Tallow-Hello`, its own `Hello` echoing the client's transcript
//! (same initiator / responder / nonce), and `X-Tallow-Responder`, the
//! responder proof over that transcript. A replayed nonce or a bad initiator
//! proof refuses `401`; malformed input (non-hex or non-`Hello` header value)
//! refuses `400`.
//!
//! The route is exempted from the bearer middleware (`crate::auth`): the
//! handshake authenticates the peer itself, with HMAC-SHA256 proofs keyed by
//! the daemon token as the PSK. The pure model (`crate::ipc_auth`) does the
//! crypto and enforces the pinned check order; this module only moves bytes,
//! keeps the listener-lifetime replay guard, and maps refusals onto statuses.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};

use crate::ipc_auth::{self, Hello, IpcAuthError, Role, SeenNonces, Session};
use crate::AppState;

/// Request header: lowercase-hex JSON serialization of the initiator `Hello`.
const HELLO_HEADER: &str = "X-Tallow-Hello";
/// Request header: the initiator proof (64 lowercase hex characters).
const INITIATOR_HEADER: &str = "X-Tallow-Initiator";
/// Response header: the responder proof over the echoed transcript.
const RESPONDER_HEADER: &str = "X-Tallow-Responder";

/// TTL for the session minted on the responding side (mirrors the client's
/// per-invocation `SESSION_TTL_MS`). The TTL is never carried on the wire; it
/// only bounds the daemon-side session artifact.
const SESSION_TTL_MS: i64 = 60_000;

// ── Wire hex ↔ Hello ────────────────────────────────────────────────────────

/// Lowercase hex encoding — the canonical form the wire contract pins (and
/// the same form the model uses for nonces and proofs).
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
/// `None` for anything malformed — a bad wire value refuses the handshake,
/// never panics.
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

/// Encode a `Hello` for the `X-Tallow-Hello` wire header: lowercase hex of
/// its canonical serde JSON form.
fn encode_hello(h: &Hello) -> Option<String> {
    let bytes = serde_json::to_vec(h).ok()?;
    Some(to_hex(&bytes))
}

/// Decode a `X-Tallow-Hello` wire value back into a `Hello`. `None` for
/// non-hex bytes or JSON that is not a `Hello` (⇒ `BadInput("hello")`, 400).
fn decode_hello(hex: &str) -> Option<Hello> {
    let bytes = from_hex(hex)?;
    serde_json::from_slice(&bytes).ok()
}

// ── Accepting side ──────────────────────────────────────────────────────────

/// The accepted handshake, ready to render as the frozen `200` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcceptedHandshake {
    /// The daemon's `Hello`, canonically re-encoded (hex) — same transcript
    /// as the request.
    pub(crate) hello_hex: String,
    /// The responder proof over that transcript.
    pub(crate) responder_proof: String,
    /// The session minted by `Session::establish` (kept for audit logging).
    pub(crate) session: Session,
}

/// Pure accepting side of one handshake exchange: decode the wire values,
/// compute the responder proof, run the full mutual verification and replay
/// guard through `Session::establish`, and render the response hello.
///
/// Split out from the axum handler so tests drive it directly (no router, no
/// shared state); the handler only supplies the PSK, the clock, and the
/// listener-lifetime `SeenNonces`.
///
/// Refusals: malformed wire material ⇒ `BadInput("hello")` / `BadInput("proof")`
/// (400); a replayed nonce ⇒ `Replayed`, a bad initiator proof ⇒ `BadProof`
/// (both 401). A refused handshake records nothing in `seen`.
pub(crate) fn accept_handshake(
    psk: &[u8],
    hello_hex: &str,
    initiator_proof: &str,
    now_ms: i64,
    ttl_ms: i64,
    seen: &mut SeenNonces,
) -> Result<AcceptedHandshake, IpcAuthError> {
    // 1. Decode the initiator's `Hello`; malformed wire material refuses as
    //    BadInput("hello") — the model never sees unparsed bytes.
    let hello = decode_hello(hello_hex).ok_or(IpcAuthError::BadInput("hello"))?;

    // 2. Render the daemon's side of the hello (canonical hex; same
    //    transcript — the client pins that with `transcript == transcript`).
    let response_hello_hex = encode_hello(&hello).ok_or(IpcAuthError::BadInput("hello"))?;

    // 3. The responder proof over the same transcript (PSK-keyed HMAC).
    let responder_proof = ipc_auth::proof(psk, &hello, Role::Responder)?;

    // 4. Full mutual check: field invariants → replay guard → both proofs
    //    (the initiator's from the wire, ours just computed) → TTL → session.
    let session = Session::establish(
        psk,
        &hello,
        initiator_proof,
        &responder_proof,
        now_ms,
        ttl_ms,
        seen,
    )?;

    Ok(AcceptedHandshake {
        hello_hex: response_hello_hex,
        responder_proof,
        session,
    })
}

/// HTTP status and machine-readable code for a handshake refusal (frozen wire
/// contract): `BadInput` → `400 bad_request`; `BadProof` / `Replayed` →
/// `401 unauthorized`.
fn refusal_response(err: &IpcAuthError) -> (StatusCode, &'static str) {
    match err {
        IpcAuthError::BadInput(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        IpcAuthError::BadProof | IpcAuthError::Replayed => {
            (StatusCode::UNAUTHORIZED, "unauthorized")
        }
    }
}

/// `POST /auth/handshake` — the daemon's accepting side of the `ipc_auth`
/// handshake (frozen wire contract; see `docs/ops/ipc_auth.md`).
///
/// Exempted from the bearer middleware by `crate::auth` (path check): the
/// PSK proofs below are this route's authentication.
pub async fn handshake_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // Wire values; a missing or non-UTF-8 header degrades to the empty string,
    // which the refusal path below reports as a 400 BadInput.
    let hello_hex = headers
        .get(HELLO_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let initiator_proof = headers
        .get(INITIATOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    // Wall-clock milliseconds; the model never reads a clock, so the daemon
    // supplies it (a pre-epoch clock degrades to 0 — the session artifact is
    // only used for logging).
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0);

    // R-7.5: resolve the PSK at use time — config may hold a secret
    // reference (`env:`/`file:`) instead of inline plaintext. Unresolvable →
    // hard refusal (500), never a silent fallback to an empty/default PSK.
    let psk = match state.config.resolve_token() {
        Ok(psk) => psk,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "configured token secret reference failed to resolve; refusing handshake (R-7.5)"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "secret_resolution_failed",
                    "detail": "configured token reference could not be resolved",
                })),
            )
                .into_response();
        }
    };
    // Listener-lifetime replay guard: one nonce completes at most one
    // handshake per daemon run (`AppState::ipc_auth_seen`).
    let outcome = {
        let mut seen = state
            .ipc_auth_seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        accept_handshake(
            psk.as_bytes(),
            hello_hex,
            initiator_proof,
            now_ms,
            SESSION_TTL_MS,
            &mut *seen,
        )
    };

    match outcome {
        Ok(accepted) => {
            // Row #127 (batch-4 lane M): revocation check-at-use at the
            // session-admission seam. A new session is only minted when the
            // gate admits it — fresh applied list (bound `min(ttl/2, 6 h)`,
            // re-checked at use) and no revoked identity. Every refusal is
            // fail-closed and the handshake nonce stays burned; established
            // sessions are untouched (the gate is consulted on this mint path
            // only, per U-201 D-4 / ATK-2.3 mitigation 1).
            match state.revocation.admit(now_ms / 1000, None) {
                Ok(crate::revocation_gate::Admission::NotChecked) => {}
                Ok(admission) => {
                    if let crate::revocation_gate::Admission::Admitted { event, .. } = &admission {
                        tracing::info!(
                            event = %serde_json::to_string(&event.to_kt_payload())
                                .unwrap_or_default(),
                            "revocation admission allowed (new session)"
                        );
                    }
                }
                Err(refusal) => {
                    tracing::warn!(
                        code = refusal.code,
                        detail = %refusal.detail,
                        event = ?refusal.event.as_ref().map(|e| e.to_kt_payload()),
                        "revocation gate refused a new session (fail-closed)"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": refusal.code,
                            "detail": refusal.detail,
                        })),
                    )
                        .into_response();
                }
            }

            // Register the session for daemon-side validation (`crate::auth`):
            // a presented `X-Tallow-Session` must name a session this listener
            // minted and that has not expired.
            if let Ok(mut sessions) = state.ipc_sessions.lock() {
                sessions.insert(accepted.session.id.clone(), accepted.session.expires_ms);
            }
            // Mint-time durability (U-216 parent follow-up): flush the registry
            // now instead of waiting for the next sweeper tick, so a session
            // minted just before a hard crash is not lost. Called after the
            // lock is released (the flush takes it again).
            crate::sessions::persist_session_now(&state);
            tracing::info!(
                session = %accepted.session.id,
                expires_ms = accepted.session.expires_ms,
                "ipc_auth handshake accepted"
            );
            let headers = [
                (HELLO_HEADER, accepted.hello_hex),
                (RESPONDER_HEADER, accepted.responder_proof),
            ];
            (StatusCode::OK, headers).into_response()
        }
        Err(err) => {
            let (status, code) = refusal_response(&err);
            tracing::warn!(
                status = status.as_u16(),
                error = %err,
                "ipc_auth handshake refused"
            );
            (
                status,
                Json(serde_json::json!({ "error": code, "detail": err.to_string() })),
            )
                .into_response()
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &[u8] = b"tallow-ipc-test-psk";
    const NONCE_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// Build the client's wire material: (`Hello`, its hex form, initiator
    /// proof) — exactly what `src/cli/daemon.rs` would send.
    fn wire_material(psk: &[u8], nonce: &str) -> (Hello, String, String) {
        let hello = ipc_auth::hello("tallow-cli", "tallow-daemon", nonce).expect("valid hello");
        let hello_hex = encode_hello(&hello).expect("hello encodes");
        let initiator = ipc_auth::proof(psk, &hello, Role::Initiator).expect("initiator proof");
        (hello, hello_hex, initiator)
    }

    #[test]
    fn accept_completes_echoes_transcript_and_returns_responder_proof() {
        let (hello, hello_hex, initiator) = wire_material(PSK, NONCE_A);
        let mut seen = SeenNonces::new();
        let accepted =
            accept_handshake(PSK, &hello_hex, &initiator, 1_000, 500, &mut seen)
                .expect("handshake accepted");

        // The daemon hello echoes the client's transcript (what the client
        // pins) and, for canonical input, is byte-identical hex.
        let echoed = decode_hello(&accepted.hello_hex).expect("response hello decodes");
        assert_eq!(ipc_auth::transcript(&echoed), ipc_auth::transcript(&hello));
        assert_eq!(accepted.hello_hex, hello_hex);

        // The responder proof verifies against the same PSK and transcript.
        assert_eq!(
            ipc_auth::verify(PSK, &echoed, Role::Responder, &accepted.responder_proof),
            Ok(true)
        );

        // Session artifacts follow the model's pinned rules (the id is
        // transcript-derived: `sess-` + 12 hex chars).
        assert!(accepted.session.id.starts_with("sess-"));
        assert_eq!(accepted.session.id.len(), 17);
        assert_eq!(accepted.session.initiator, "tallow-cli");
        assert_eq!(accepted.session.responder, "tallow-daemon");
        assert_eq!(accepted.session.established_ms, 1_000);
        assert_eq!(accepted.session.expires_ms, 1_500);
        assert!(accepted.session.valid(1_000));

        // The nonce is burned for the listener's lifetime.
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn accept_refuses_replay_and_keeps_guard_size() {
        let (_hello, hello_hex, initiator) = wire_material(PSK, NONCE_A);
        let mut seen = SeenNonces::new();
        accept_handshake(PSK, &hello_hex, &initiator, 1_000, 500, &mut seen)
            .expect("first accept");

        let err = accept_handshake(PSK, &hello_hex, &initiator, 2_000, 500, &mut seen)
            .expect_err("replay refused");
        assert_eq!(err, IpcAuthError::Replayed);
        assert_eq!(seen.len(), 1, "a refusal records nothing new");
    }

    #[test]
    fn accept_refuses_bad_proof_without_burning_the_nonce() {
        let (hello, hello_hex, _good) = wire_material(PSK, NONCE_A);
        let bad = ipc_auth::proof(b"wrong-psk", &hello, Role::Initiator).expect("proof");
        let mut seen = SeenNonces::new();
        let err = accept_handshake(PSK, &hello_hex, &bad, 1_000, 500, &mut seen)
            .expect_err("bad proof refused");
        assert_eq!(err, IpcAuthError::BadProof);
        assert_eq!(seen.len(), 0);

        // The same nonce still completes afterwards (id is transcript-derived).
        let good = ipc_auth::proof(PSK, &hello, Role::Initiator).expect("proof");
        let accepted = accept_handshake(PSK, &hello_hex, &good, 1_000, 500, &mut seen)
            .expect("retry accepted");
        assert!(accepted.session.id.starts_with("sess-"));
        assert_eq!(accepted.session.id.len(), 17);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn accept_refuses_malformed_hello_as_bad_input() {
        let mut seen = SeenNonces::new();
        for bad in ["", "zz", "abcd", "not-hex-at-all"] {
            let err = accept_handshake(PSK, bad, "abcd", 1_000, 500, &mut seen)
                .expect_err("malformed hello refused");
            assert_eq!(err, IpcAuthError::BadInput("hello"), "hello={bad}");
        }
        assert_eq!(seen.len(), 0);
    }

    #[test]
    fn accept_refuses_hex_that_is_not_hello_json() {
        let mut seen = SeenNonces::new();
        // Valid hex, valid JSON, but not a `Hello` — refuses as BadInput.
        let not_hello = to_hex(br#"{"not":"a-hello"}"#);
        let err = accept_handshake(PSK, &not_hello, "abcd", 1_000, 500, &mut seen)
            .expect_err("non-Hello refused");
        assert_eq!(err, IpcAuthError::BadInput("hello"));
        assert_eq!(seen.len(), 0);
    }

    #[test]
    fn accept_refuses_empty_or_malformed_proof_as_bad_input() {
        let (_hello, hello_hex, _initiator) = wire_material(PSK, NONCE_A);
        let mut seen = SeenNonces::new();
        for bad in ["", "not-hex", "zzzz"] {
            let err = accept_handshake(PSK, &hello_hex, bad, 1_000, 500, &mut seen)
                .expect_err("malformed proof refused");
            assert_eq!(err, IpcAuthError::BadInput("proof"), "proof={bad}");
        }
        assert_eq!(seen.len(), 0);
    }

    #[test]
    fn accept_refuses_empty_psk_as_bad_input() {
        let (_hello, hello_hex, initiator) = wire_material(PSK, NONCE_A);
        let mut seen = SeenNonces::new();
        let err = accept_handshake(b"", &hello_hex, &initiator, 1_000, 500, &mut seen)
            .expect_err("empty psk refused");
        assert_eq!(err, IpcAuthError::BadInput("psk"));
        assert_eq!(seen.len(), 0);
    }

    #[test]
    fn accepted_session_expiry_is_strict_and_replay_outlives_it() {
        let (_hello, hello_hex, initiator) = wire_material(PSK, NONCE_A);
        let mut seen = SeenNonces::new();
        let accepted = accept_handshake(PSK, &hello_hex, &initiator, 10_000, 500, &mut seen)
            .expect("accepted");

        assert_eq!(accepted.session.expires_ms, 10_500);
        assert!(accepted.session.valid(10_000));
        assert!(accepted.session.valid(10_499)); // one ms before expiry: valid
        assert!(!accepted.session.valid(10_500)); // expiry ms itself: strict `<`
        assert!(!accepted.session.valid(10_501));

        // Expiry is not a replay amnesty: the burned nonce stays refused.
        let err = accept_handshake(PSK, &hello_hex, &initiator, 20_000, 500, &mut seen)
            .expect_err("still replayed");
        assert_eq!(err, IpcAuthError::Replayed);
    }

    #[test]
    fn session_ids_are_transcript_derived_not_sequential() {
        let (_a, hex_a, init_a) = wire_material(PSK, NONCE_A);
        let (_b, hex_b, init_b) = wire_material(PSK, NONCE_B);
        let mut seen = SeenNonces::new();
        let first = accept_handshake(PSK, &hex_a, &init_a, 1_000, 500, &mut seen).unwrap();
        let second = accept_handshake(PSK, &hex_b, &init_b, 1_100, 500, &mut seen).unwrap();
        assert!(first.session.id.starts_with("sess-"));
        assert_eq!(first.session.id.len(), 17);
        assert_ne!(first.session.id, second.session.id);
        assert_eq!(seen.len(), 2);

        // Both parties compute the same id for the same exchange: a client
        // (fresh guard) and this listener (busy guard) must agree — that is
        // what makes the daemon-side session check possible.
        let (hello, _same_hex, same_init) = wire_material(PSK, NONCE_A);
        let responder = ipc_auth::proof(PSK, &hello, Role::Responder).unwrap();
        let client_side = Session::establish(
            PSK,
            &hello,
            &same_init,
            &responder,
            1_000,
            500,
            &mut SeenNonces::new(),
        )
        .unwrap();
        assert_eq!(client_side.id, first.session.id);
    }

    #[test]
    fn refusal_statuses_match_the_frozen_contract() {
        assert_eq!(
            refusal_response(&IpcAuthError::BadInput("hello")).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            refusal_response(&IpcAuthError::BadInput("proof")).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            refusal_response(&IpcAuthError::BadProof).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            refusal_response(&IpcAuthError::Replayed).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            refusal_response(&IpcAuthError::BadProof).1,
            "unauthorized"
        );
        assert_eq!(
            refusal_response(&IpcAuthError::BadInput("psk")).1,
            "bad_request"
        );
    }
}
