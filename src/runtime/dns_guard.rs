//! `dns_guard` — fail-closed guard for plain-DNS (`:53`) lookups (P4-2 residue:
//! SFIL T-122, rows #28/#61).
//!
//! Resolving a hostname through the OS resolver (`UDP`/`TCP :53`,
//! `to_socket_addrs` / `lookup_host`) sends cleartext queries to whatever
//! nameserver the box is configured with — the observation surface this task
//! closes. The sanctioned path is DNS-over-HTTPS on the egress route:
//! `crate::stdlib::net::resolve_doh` (`hickory-resolver`, `CLOUDFLARE`) and
//! `crate::browser::dpi_bypass` both resolve that way.
//!
//! Existing raw-resolution sites (`src/stdlib/net.rs` L349/L866/L950,
//! `src/stdlib/osint.rs` L459/L1173, `src/stdlib/transfer.rs` L935,
//! `src/browser/network_stealth.rs` L223/L290) are registered with written
//! reasons in `tests/egress_census.rs` (resolver guard test); this module is
//! the runtime leg those sites must adopt before resolving:
//!
//! ```ignore
//! // at a raw-resolution site, before calling lookup_host / to_socket_addrs:
//! crate::runtime::dns_guard::check(port, via_egress)?; // Err(reason) = refuse, do not resolve
//! ```
//!
//! Semantics mirror [`crate::runtime::egress_http::egress_refusal`] (invariant
//! N3): `None` / `Ok(())` means the lookup may proceed; a refusal **attempts no
//! resolution** and is journaled via
//! [`crate::observability::emit_to_default_journal`] (`EgressRefusal` class).
//! The only escape hatch is the explicit operator opt-out,
//! `TALLOW_ALLOW_DIRECT=1|true|yes` — the same parse as
//! [`crate::runtime::fetch::allow_direct`] (trimmed, case-insensitive; junk
//! stays fail-closed) — and even that is journaled (`DirectEgress` class; a
//! leak-by-design opt-in must never be silent).
//!
//! Wiring (recorded for the parent in
//! `research/tallow-security-2026-09-12/phase13-implementation/impl/T-122.md`):
//! add `pub mod dns_guard;` to `src/runtime/mod.rs`, between `pub mod db_ffi;`
//! and `pub mod egress_http;` (alphabetical module list).
// T-122b: every registered raw-resolution site now adopts this guard
// (stdlib/net.rs L349/L866/L950, stdlib/osint.rs L459/L1173,
// stdlib/transfer.rs L935, browser/network_stealth.rs L223/L290), so no
// dead-code allowance is needed here any more.

use crate::observability::{emit_to_default_journal, now_ms, EventClass, SecurityEvent};

/// The plain-DNS port this guard exists for (`UDP`/`TCP` 53).
pub const PLAIN_DNS_PORT: u16 = 53;

/// Actor recorded on emitted security events.
pub const ACTOR: &str = "runtime.dns_guard";

/// Same accepted opt-out as [`crate::runtime::fetch::allow_direct`]:
/// `TALLOW_ALLOW_DIRECT` = `1|true|yes` after trim + ASCII-lowercase. Anything
/// else (unset, `0`, `false`, junk, empty) stays fail-closed, so a typo cannot
/// open a plain-DNS leak.
pub fn allow_direct() -> bool {
    match std::env::var("TALLOW_ALLOW_DIRECT") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

/// `Some(reason)` when a lookup on `port` must be **refused**: the caller is
/// about to use plain DNS (`:53`) and is not on the egress path.
///
/// * `via_egress == true` — resolution rides the DoH/egress route → `None`.
/// * `port != PLAIN_DNS_PORT` — not a plain-DNS lookup → `None`.
/// * `TALLOW_ALLOW_DIRECT=1|true|yes` — explicit operator opt-in: `None`, plus
///   one `DirectEgress` audit record.
/// * otherwise — `Some(reason)`; a refusal event is journaled best-effort and
///   the caller must not resolve. Reuses the load-bearing "refusing" wording
///   of the egress refusal (invariant N3): it is only ever produced on a path
///   that attempts no lookup.
pub fn plain_dns_refusal(port: u16, via_egress: bool) -> Option<String> {
    if via_egress || port != PLAIN_DNS_PORT {
        return None;
    }
    let reason = format!(
        "[dns] refusing plain DNS on udp/tcp :{} — name resolution must go through the \
         DoH/egress path; set TALLOW_ALLOW_DIRECT=1|true|yes to override",
        PLAIN_DNS_PORT
    );
    if allow_direct() {
        emit_direct_bypass();
        return None;
    }
    let _ = emit_to_default_journal(&SecurityEvent {
        class: EventClass::EgressRefusal,
        actor: ACTOR.to_string(),
        target: Some(format!("plain-dns://:{}", PLAIN_DNS_PORT)),
        size: reason.len(),
        at_ms: now_ms(),
    });
    Some(reason)
}

/// Convenience for raw sites: `Err(reason)` where a plain-DNS lookup would be
/// refused; `Ok(())` on the egress path, for non-`:53` lookups, or under the
/// explicit opt-in. Call before `to_socket_addrs` / `lookup_host` / any `:53`
/// send.
pub fn check(port: u16, via_egress: bool) -> Result<(), String> {
    match plain_dns_refusal(port, via_egress) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// One `DirectEgress` audit record per bypass decision — same contract as the
/// browser zone's `emit_zone_direct_bypass` (`src/browser/zone.rs`): a
/// leak-by-design opt-in must never be silent.
pub fn emit_direct_bypass() {
    let _ = emit_to_default_journal(&SecurityEvent {
        class: EventClass::DirectEgress,
        actor: ACTOR.to_string(),
        target: Some(format!(
            "TALLOW_ALLOW_DIRECT — plain DNS (:{}) allowed directly",
            PLAIN_DNS_PORT
        )),
        size: usize::from(PLAIN_DNS_PORT),
        at_ms: now_ms(),
    });
}
