use axum::{
    body::Body,
    extract::State,
    http::{header, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::AppState;
use crate::sessions::{now_ms, registered_expiry, sweep_expired};

/// Auth middleware — rejects requests without a valid bearer token and,
/// since R-5.2A, without a live `ipc_auth` session (C-16: the silent-downgrade
/// lane is closed on every non-bootstrap route).
/// Exempts GET /health and POST /auth/handshake from authentication.
///
/// Applied as a router `layer` — not `route_layer` — so unmatched paths are
/// authenticated too (audit-04 F-8: `route_layer` only runs for matched
/// routes, which let 404/405 probes see the route table unauthenticated).
/// The exemptions are handled inside the middleware itself (simple path
/// checks): /health is public liveness and /auth/handshake authenticates the
/// caller with `ipc_auth` PSK proofs (see `routes/handshake.rs`).
///
/// # Session hygiene (U-216 / G-07)
///
/// Session validation is **explicit-state** (`SessionCheck`): a presented
/// value naming a registered session whose expiry has passed is `Expired` —
/// a distinct verdict from `Unknown` (nothing registered under that value) —
/// and both refuse `401` under the frozen wire contract.
///
/// The registry self-cleans two ways (audit-04 F-7): **lazily**, every
/// validation doubles as an expiry sweep; and **periodically**, via
/// [`spawn_session_sweeper`] (tokio interval) which is callable from service
/// startup. Sessions survive a daemon restart (G-07): the registry is
/// persisted under `<data_dir>/sessions/` (dir 0700, file 0600) with
/// **hashed** session ids — the raw `X-Tallow-Session` token never touches
/// disk — and [`restore_sessions`] reloads it at boot, dropping expired
/// records at load. SVID-bound sessions (G-06) are a later wave; this module
/// deliberately keeps the mint/validate flow unchanged.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Exempt health endpoint from authentication
    if req.uri().path() == "/health" && req.method() == Method::GET {
        return next.run(req).await;
    }

    // Exempt the ipc_auth handshake endpoint (see routes/handshake.rs): it
    // authenticates the caller with PSK proofs over a nonce transcript
    // instead of the static bearer token. The client also sends the bearer
    // header, so requests pass whether or not the exemption is in force.
    if req.uri().path() == "/auth/handshake" && req.method() == Method::POST {
        return next.run(req).await;
    }

    // Check Authorization header
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized", "detail": "missing Bearer token"})),
        )
            .into_response();
    }

    let token = &auth_header[7..]; // Strip "Bearer " prefix (7 chars)

    // R-7.5: resolve the configured token at use time — config may hold a
    // secret reference (`env:`/`file:`) instead of inline plaintext. A
    // reference that cannot be resolved is a hard error (500), never a
    // fallback to a default token.
    let expected = match state.config.resolve_token() {
        Ok(expected) => expected,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "configured token secret reference failed to resolve; refusing request (R-7.5)"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "secret_resolution_failed",
                    "detail": "configured token reference could not be resolved",
                })),
            )
                .into_response();
        }
    };

    // R-5.2A: constant-time comparison (`ct_eq`) — a byte-wise `==` returns
    // at the first differing byte and lets a local attacker time the static
    // token out one byte at a time (rt-2 ATK-2.5).
    if !ct_eq(token.as_bytes(), expected.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized", "detail": "invalid token"})),
        )
            .into_response();
    }

    // `ipc_auth` session validation (B7.1.2 + R-5.2A): every non-bootstrap
    // route now REQUIRES a session. A presented value must name a session
    // this listener minted (`POST /auth/handshake`) whose expiry has not
    // passed. Absent or `none` is the CLI's silent-downgrade lane (ATK-2.5)
    // and is refused like any unknown value — with a warning so a downgrade
    // attempt is loud, never silent (C-16). Only the /health and
    // /auth/handshake bootstrap pair exits before this check.
    let session_header = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok());
    match session_check(&state.ipc_sessions, session_header, now_ms()) {
        SessionCheck::Ok => {}
        SessionCheck::Missing => {
            tracing::warn!(
                path = %req.uri().path(),
                "refused request without a session header (downgrade lane closed, R-5.2A)"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "unauthorized",
                    "detail": "session required: X-Tallow-Session must name a session minted by POST /auth/handshake",
                })),
            )
                .into_response();
        }
        SessionCheck::Expired => {
            // G-07: expiry is an explicit verdict, not folded into `Unknown`.
            // The refusal below is byte-identical to the pre-U-216 response
            // (frozen wire contract); the distinction lives in this typed
            // state and in the log line, so expiry is visible in audits.
            tracing::warn!(
                path = %req.uri().path(),
                "refused request with expired session (explicit expiry state, G-07)"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized", "detail": "unknown or expired session"})),
            )
                .into_response();
        }
        SessionCheck::Unknown => {
            tracing::warn!(
                path = %req.uri().path(),
                "refused request with unknown session"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized", "detail": "unknown or expired session"})),
            )
                .into_response();
        }
    }

    next.run(req).await
}

/// Constant-time byte equality — xor-accumulate with no data-dependent early
/// exit (R-5.2A constant-time token compare; dependency-free).
///
/// The length difference folds into the same accumulator and the loop runs
/// over the shorter input, so the caller learns only "equal"/"not equal" —
/// never the position of the first differing byte. `black_box` keeps the
/// optimizer from rewriting the fold into an early-return comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= std::hint::black_box(a[i] ^ b[i]);
    }
    diff == 0
}

/// Request header carrying the session id minted by `POST /auth/handshake`.
const SESSION_HEADER: &str = "X-Tallow-Session";

/// Verdict of the R-5.2A session policy: every non-bootstrap route requires a
/// live session; absent and `none` are the distinct "silent downgrade" case
/// (C-16); a registered-but-past-expiry value is `Expired` (G-07, explicit —
/// no longer collapsed into `Unknown`); anything else is `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionCheck {
    /// A session this listener minted and whose expiry has not passed
    /// (strict `<`, the model's rule).
    Ok,
    /// Absent header or the honest-degrade `none` — refused with its own
    /// message so the downgrade is loud.
    Missing,
    /// A value that names a registry entry whose expiry has passed
    /// (`now_ms >= expires_ms`, strict `<`). Distinct from [`Unknown`]
    /// (U-216): both refuse, but expiry stays attributable in logs/tests.
    ///
    /// [`Unknown`]: SessionCheck::Unknown
    Expired,
    /// A value that names no live minted session (unknown, empty).
    Unknown,
}

/// Session policy (R-5.2A): the header must name a session this listener
/// minted (`POST /auth/handshake`) whose expiry has not passed (strict `<`);
/// absent or `none` no longer passes — the silent-downgrade lane is closed
/// (ATK-2.5 / C-16).
///
/// G-07 (U-216): the expiry verdict is explicit (`Expired` vs `Unknown`), the
/// presented entry is resolved through [`registered_expiry`] (raw id or
/// restored digest — never a digest read back as a literal credential), and
/// every non-`Missing` call also performs a lazy expiry sweep, so the
/// registry self-cleans at use rate in addition to the periodic sweeper.
pub(crate) fn session_check(
    sessions: &std::sync::Mutex<std::collections::HashMap<String, i64>>,
    header: Option<&str>,
    now_ms: i64,
) -> SessionCheck {
    let Some(id) = header else {
        return SessionCheck::Missing;
    };
    if id == "none" {
        return SessionCheck::Missing;
    }
    let Ok(mut sessions) = sessions.lock() else {
        return SessionCheck::Unknown;
    };

    // Explicit expiry verdict for the presented value — taken BEFORE the
    // lazy sweep below, so an expired presented entry still reports
    // `Expired` (otherwise the sweep would remove the evidence).
    let verdict = match registered_expiry(&sessions, id) {
        Some(expires) if now_ms < expires => SessionCheck::Ok,
        Some(_) => SessionCheck::Expired,
        None => SessionCheck::Unknown,
    };

    // Lazy sweep (G-07): every validation also drops expired entries. Cheap
    // and bounded — the registry only holds sessions minted within one TTL
    // window (the periodic [`spawn_session_sweeper`] task is the backstop
    // for entries nothing ever presents again).
    let swept = sweep_expired(&mut sessions, now_ms);
    if swept > 0 {
        tracing::debug!(swept, "lazy session sweep: dropped expired registry entries");
    }

    verdict
}


// ── Session registry + persistence moved to `sessions.rs` (U-216 / G-07) ──
// The registry, its at-rest digest form (hashed ids only), the periodic
// sweep/flush and the boot restore/sweeper wiring now live in `crate::sessions`;
// this module keeps request-path validation and imports `registered_expiry` /
// `sweep_expired` from there.

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions_with(
        pairs: &[(&str, i64)],
    ) -> std::sync::Mutex<std::collections::HashMap<String, i64>> {
        std::sync::Mutex::new(
            pairs
                .iter()
                .map(|(id, exp)| (id.to_string(), *exp))
                .collect(),
        )
    }

    #[test]
    fn ct_eq_accepts_equal_and_rejects_any_difference() {
        let token = "61c33ed2".repeat(8); // 64 hex chars — the real wire shape
        assert!(ct_eq(token.as_bytes(), token.as_bytes()));

        // One flipped byte: refused, wherever the difference sits (no
        // early-exit prefix rule).
        let mut first = token.clone().into_bytes();
        first[0] ^= 0x01;
        assert!(!ct_eq(token.as_bytes(), &first));
        let mut last = token.clone().into_bytes();
        let last_idx = last.len() - 1;
        last[last_idx] ^= 0x01;
        assert!(!ct_eq(token.as_bytes(), &last));

        // Length differences are refused (folded into the accumulator).
        assert!(!ct_eq(token.as_bytes(), token[..63].as_bytes()));
        assert!(!ct_eq(b"", token.as_bytes()));
        assert!(!ct_eq(token.as_bytes(), b""));
    }

    #[test]
    fn absent_or_none_session_header_is_refused_on_non_bootstrap_routes() {
        let s = sessions_with(&[("sess-abc123456789", 5_000)]);
        assert_eq!(session_check(&s, None, 1_000), SessionCheck::Missing);
        assert_eq!(session_check(&s, Some("none"), 1_000), SessionCheck::Missing);
        assert_eq!(session_check(&s, Some(""), 1_000), SessionCheck::Unknown);
    }

    #[test]
    fn minted_and_unexpired_session_is_allowed() {
        let s = sessions_with(&[("sess-abc123456789", 5_000)]);
        assert_eq!(
            session_check(&s, Some("sess-abc123456789"), 1_000),
            SessionCheck::Ok
        );
        assert_eq!(
            session_check(&s, Some("sess-abc123456789"), 4_999),
            SessionCheck::Ok
        );
    }

    #[test]
    fn expired_session_is_a_distinct_state_from_unknown() {
        let s = sessions_with(&[("sess-abc123456789", 5_000)]);
        // Strict `<`: the expiry millisecond itself is already expired.
        assert_eq!(
            session_check(&s, Some("sess-abc123456789"), 5_000),
            SessionCheck::Expired
        );
        // The call above lazily swept the dead entry (by design — see
        // `expired_presentation_reports_expired_before_the_sweep_removes_it`),
        // so re-seed the registry to probe the boundary one ms later.
        let s = sessions_with(&[("sess-abc123456789", 5_000)]);
        assert_eq!(
            session_check(&s, Some("sess-abc123456789"), 5_001),
            SessionCheck::Expired
        );
        // Not registered at all → Unknown (the two states never conflate).
        assert_eq!(
            session_check(&s, Some("sess-ffff00000000"), 1_000),
            SessionCheck::Unknown
        );
    }

    #[test]
    fn validation_lazily_sweeps_expired_entries() {
        let s = sessions_with(&[("sess-dead00000000", 1_000), ("sess-live00000000", 9_000)]);

        // Validating the live session is Ok and drops the expired entry.
        assert_eq!(
            session_check(&s, Some("sess-live00000000"), 2_000),
            SessionCheck::Ok
        );
        let guard = s.lock().unwrap();
        assert!(!guard.contains_key("sess-dead00000000"), "lazy sweep removed it");
        assert!(guard.contains_key("sess-live00000000"));
        assert_eq!(guard.len(), 1);
        drop(guard);

        // Even an unknown presentation sweeps (any non-Missing validation).
        {
            let mut guard = s.lock().unwrap();
            guard.insert("sess-dead00000001".to_string(), 500);
        }
        assert_eq!(session_check(&s, Some("sess-unknown00000"), 2_000), SessionCheck::Unknown);
        assert!(!s.lock().unwrap().contains_key("sess-dead00000001"));
    }

    #[test]
    fn expired_presentation_reports_expired_before_the_sweep_removes_it() {
        let s = sessions_with(&[("sess-abc123456789", 5_000)]);
        assert_eq!(
            session_check(&s, Some("sess-abc123456789"), 6_000),
            SessionCheck::Expired
        );
        // The very same value now reads Unknown: the expired entry was
        // swept, so the pre-sweep verdict is what made `Expired` possible.
        assert_eq!(
            session_check(&s, Some("sess-abc123456789"), 6_000),
            SessionCheck::Unknown
        );
    }

}
