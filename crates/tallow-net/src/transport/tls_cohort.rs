//! Pinned TLS/JA4 client cohort profile + snapshot tests (T-126, P4-9; DISP-3 rows #109/#110).
//!
//! # What this pins
//!
//! Tallow's compiled clients (QUIC via quinn, TCP+TLS via tokio-rustls) share one
//! rustls client config built by [`super::tls_config::client_config`] on the
//! `aws_lc_rs` provider. This module captures that config's **wire shape** — the
//! exact ClientHello cohort it produces — as a versioned snapshot:
//!
//! * [`JA4_COHORT_ID`] — cohort version tag (`JA4_COHORT_V1`).
//! * [`Ja4CohortV1`] — structured descriptor: legacy version, offered cipher
//!   suites, extension list/order, supported groups, signature algorithms,
//!   ALPN, key-share groups, wire GREASE flag.
//! * [`JA4_COHORT_V1_TCP`] / [`JA4_COHORT_V1_QUIC`] — the pinned renders of that
//!   descriptor for each transport.
//!
//! `test_ja4_cohort_v1_matches_pinned_snapshot` fails whenever any cohort-relevant
//! input changes (rustls/provider upgrade, cipher list edit, group policy, ALPN,
//! extension set). Re-pinning is then a conscious, reviewable diff to the two
//! constants — never a silent fingerprint drift.
//!
//! # How the ClientHello is captured (no network)
//!
//! rustls can emit its ClientHello offline: a fresh connection object writes the
//! first flight to a buffer (`ClientConnection::write_tls` for TCP,
//! `quic::ClientConnection::write_hs` for QUIC). We parse those bytes directly.
//! No socket, no live handshake.
//!
//! # Determinism and honest JA4 limits
//!
//! Two ClientHello regions are semantically random per handshake and are
//! **normalized**: the 32-byte `random` field (never hashed) and the `key_share`
//! public-key payload (reduced to its group IDs). rustls additionally
//! **randomizes the extension order per connection** (anti-ossification:
//! `exts.order_seed` in rustls `client/hs.rs`), so the snapshot records the
//! extension SET (sorted) rather than one wire permutation — JA4 digests are
//! order-insensitive by construction. JA4_a and JA4_b cover only
//! handshake-stable fields. JA4_c is a JA4-shaped digest over the sorted
//! extension list with documented normalizations: SNI/ALPN are excluded (they are
//! already represented in JA4_a), signature-algorithms (0x000d) values are
//! expanded to the (sorted, GREASE-filtered) algorithm list, and the
//! random-valued extensions key_share (0x0033), pre_shared_key (0x0029) and QUIC
//! transport parameters (0x0039) contribute their extension ID only. This keeps
//! the digest handshake-stable; it is therefore **not claimed to be byte-exact
//! FoxIO JA4_c**, and is consumed here as tallow-net's cohort fingerprint.
//!
//! # GREASE (RFC 8701)
//!
//! rustls 0.23 does not inject GREASE values into cipher suites, extension IDs,
//! groups or sigalgs (its only `Grease` support is the unrelated ECH-GREASE
//! feature). Everything observable is therefore GREASE-free today — but every
//! digest path defensively filters GREASE ([`is_grease`]), the
//! [`Ja4CohortV1::grease_present`] flag records any occurrence, and
//! `test_synthetic_grease_hello_is_filtered` proves the filtering with a
//! synthetic RFC 8701 hello.
//!
//! # Residuals
//!
//! * quinn/QUIC normalization: [`ja4_cohort_v1`] renders the QUIC variant through
//!   `rustls::quic` directly (identical TLS config; empty client transport
//!   parameters). A live quinn handshake additionally carries quinn's real
//!   TLS-encoded transport parameters and any ALPN the caller sets on the rustls
//!   config. The 0x0039 extension is normalized to its ID in JA4_c, so this does
//!   not perturb the pinned fingerprint; the render truthfully records that the
//!   parameters were empty for the snapshot. See T-126 evidence §Residual.
//! * No new dependencies: `sha2` is not a tallow-net dependency, so SHA-256
//!   (FIPS 180-4) is implemented in-file with its round constants derived
//!   arithmetically (§4.2.2) and validated against the standard vectors —
//!   avoiding Cargo.lock churn in the shared workspace.

use std::sync::{Arc, OnceLock};

use rustls::pki_types::ServerName;

use super::tls_config;

/// Version tag for Tallow's pinned client TLS cohort.
///
/// Bump only when the cohort *shape* changes intentionally; ordinary re-pins of
/// the snapshot constants below keep the V1 id.
pub const JA4_COHORT_ID: &str = "JA4_COHORT_V1";

/// SNI presented when capturing the cohort snapshot.
///
/// `.invalid` is reserved (RFC 2606) and can never resolve; a hostname (not an
/// IP) is used so the SNI extension is actually offered.
pub const COHORT_SERVER_NAME: &str = "relay.tallow.invalid";

/// Provider tag for the pinned cohort (see Cargo.lock pins in the T-126 evidence).
/// Re-pinned 2026-09-16 with rustls 0.23.45 / aws-lc-rs 1.18.1 / quinn 0.11.12
/// (dependency-remediation update): +rsa_pss_rsae_sha256/384/512 sigalgs in both
/// transports; QUIC additionally drops the session_ticket (0x0023) extension.
pub const COHORT_PROVIDER: &str = "rustls/aws-lc-rs(default_provider)";

/// Pinned render ([`Ja4CohortV1::render`]) of the TCP+TLS client cohort.
///
/// Verified by `test_ja4_cohort_v1_matches_pinned_snapshot`. Re-pin only with a
/// deliberate, reviewed cohort change.
pub const JA4_COHORT_V1_TCP: &str = concat!(
    "cohort=JA4_COHORT_V1\n",
    "transport=tcp\n",
    "provider=rustls/aws-lc-rs(default_provider)\n",
    "server_name=relay.tallow.invalid\n",
    "legacy_version=0x0303\n",
    "tls13_offered=true\n",
    "sni=relay.tallow.invalid\n",
    "alpn=(none)\n",
    "ciphers=0x1302,0x1301,0x1303,0xc02c,0xc02b,0xcca9,0xc030,0xc02f,0xcca8,0x00ff\n",
    "extensions=0x0000,0x0005,0x000a,0x000b,0x000d,0x0017,0x0023,0x002b,0x002d,0x0033\n",
    "groups=0x11ec,0x001d,0x0017,0x0018\n",
    "sigalgs=0x0503,0x0403,0x0603,0x0807,0x0806,0x0805,0x0804,0x0601,0x0501,0x0401,0x0904,0x0905,0x0906\n",
    "key_share_groups=0x11ec,0x001d\n",
    "grease_present=false\n",
    "ja4_a=t13d101000\n",
    "ja4_b=b9b30c653583\n",
    "ja4_c=89edc948a715\n",
    "ja4=t13d101000_b9b30c653583_89edc948a715"
);

/// Pinned render ([`Ja4CohortV1::render`]) of the QUIC client cohort.
///
/// Verified by `test_ja4_cohort_v1_matches_pinned_snapshot`. Re-pin only with a
/// deliberate, reviewed cohort change.
pub const JA4_COHORT_V1_QUIC: &str = concat!(
    "cohort=JA4_COHORT_V1\n",
    "transport=quic\n",
    "provider=rustls/aws-lc-rs(default_provider)\n",
    "server_name=relay.tallow.invalid\n",
    "legacy_version=0x0303\n",
    "tls13_offered=true\n",
    "sni=relay.tallow.invalid\n",
    "alpn=(none)\n",
    "ciphers=0x1302,0x1301,0x1303\n",
    "extensions=0x0000,0x0005,0x000a,0x000b,0x000d,0x0017,0x002b,0x002d,0x0033,0x0039\n",
    "groups=0x11ec,0x001d,0x0017,0x0018\n",
    "sigalgs=0x0503,0x0403,0x0603,0x0807,0x0806,0x0805,0x0804,0x0601,0x0501,0x0401,0x0904,0x0905,0x0906\n",
    "key_share_groups=0x11ec,0x001d\n",
    "grease_present=false\n",
    "ja4_a=q13d031000\n",
    "ja4_b=24b2f16fafab\n",
    "ja4_c=4479bb40581a\n",
    "ja4=q13d031000_24b2f16fafab_4479bb40581a"
);

/// Transport variant of the client cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4Transport {
    /// TCP + TLS (tokio-rustls path).
    Tcp,
    /// QUIC (quinn path).
    Quic,
}

impl Ja4Transport {
    fn proto_char(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

/// Pinned, versioned descriptor of the client TLS cohort (see module docs).
///
/// The list fields record the hello's lists (GREASE included, should it ever
/// appear — see [`Self::grease_present`]); GREASE is filtered only inside the
/// digest inputs (`ja4_a` counts, `ja4_b`, `ja4_c`). The extension list is
/// sorted because rustls randomizes its wire order per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4CohortV1 {
    /// Cohort version tag ([`JA4_COHORT_ID`]).
    pub cohort: &'static str,
    /// `tcp` or `quic`.
    pub transport: &'static str,
    /// Provider tag ([`COHORT_PROVIDER`]).
    pub provider: &'static str,
    /// Server name the snapshot was captured against ([`COHORT_SERVER_NAME`]).
    pub server_name: &'static str,
    /// ClientHello `legacy_version` (0x0303 for TLS 1.3-capable clients).
    pub legacy_version: u16,
    /// Whether TLS 1.3 (0x0304) is offered in supported_versions.
    pub tls13_offered: bool,
    /// SNI hostname offered, if any.
    pub sni: Option<String>,
    /// Offered cipher suites, wire order.
    pub ciphers: Vec<u16>,
    /// Offered extension IDs, sorted ascending (rustls randomizes the wire order
    /// per connection — see module docs).
    pub extensions: Vec<u16>,
    /// supported_groups (0x000a), wire order.
    pub groups: Vec<u16>,
    /// signature_algorithms (0x000d), wire order.
    pub sigalgs: Vec<u16>,
    /// ALPN protocols (0x0010), wire order (empty if ALPN not offered).
    pub alpn: Vec<String>,
    /// key_share (0x0033) group IDs, wire order.
    pub key_share_groups: Vec<u16>,
    /// True if any RFC 8701 GREASE value appears anywhere in the hello.
    pub grease_present: bool,
    /// JA4_a segment: `[t|q][13|12][d|i][ciphers:02][extensions:02][alpn]`.
    pub ja4_a: String,
    /// JA4_b segment: truncated SHA-256 of the sorted, GREASE-filtered cipher list.
    pub ja4_b: String,
    /// JA4_c segment: JA4-shaped digest of the sorted extension list (normalizations
    /// documented in the module docs).
    pub ja4_c: String,
}

impl Ja4CohortV1 {
    /// Full `a_b_c` fingerprint string.
    pub fn ja4(&self) -> String {
        format!("{}_{}_{}", self.ja4_a, self.ja4_b, self.ja4_c)
    }

    /// Stable, diff-friendly render of the whole descriptor. This exact string is
    /// what the snapshot constants pin.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "cohort={}", self.cohort);
        let _ = writeln!(s, "transport={}", self.transport);
        let _ = writeln!(s, "provider={}", self.provider);
        let _ = writeln!(s, "server_name={}", self.server_name);
        let _ = writeln!(s, "legacy_version=0x{:04x}", self.legacy_version);
        let _ = writeln!(s, "tls13_offered={}", self.tls13_offered);
        let _ = writeln!(s, "sni={}", self.sni.as_deref().unwrap_or("(none)"));
        let _ = writeln!(
            s,
            "alpn={}",
            if self.alpn.is_empty() {
                "(none)".to_string()
            } else {
                self.alpn.join(",")
            }
        );
        let _ = writeln!(s, "ciphers={}", hex_u16s(&self.ciphers));
        let _ = writeln!(s, "extensions={}", hex_u16s(&self.extensions));
        let _ = writeln!(s, "groups={}", hex_u16s(&self.groups));
        let _ = writeln!(s, "sigalgs={}", hex_u16s(&self.sigalgs));
        let _ = writeln!(s, "key_share_groups={}", hex_u16s(&self.key_share_groups));
        let _ = writeln!(s, "grease_present={}", self.grease_present);
        let _ = writeln!(s, "ja4_a={}", self.ja4_a);
        let _ = writeln!(s, "ja4_b={}", self.ja4_b);
        let _ = writeln!(s, "ja4_c={}", self.ja4_c);
        let _ = write!(s, "ja4={}", self.ja4());
        s
    }
}

/// Capture the pinned client cohort for `transport` from the config the code
/// actually builds ([`super::tls_config::client_config`] with no ALPN).
pub fn ja4_cohort_v1(transport: Ja4Transport) -> std::result::Result<Ja4CohortV1, String> {
    let cfg = client_config_for_snapshot()?;
    let name = ServerName::try_from(COHORT_SERVER_NAME)
        .map_err(|e| format!("cohort server name: {}", e))?;

    let hello = match transport {
        Ja4Transport::Tcp => {
            let mut conn = rustls::ClientConnection::new(cfg.clone(), name)
                .map_err(|e| format!("tcp client connection: {}", e))?;
            let mut buf = Vec::new();
            conn.write_tls(&mut buf)
                .map_err(|e| format!("tcp ClientHello write: {}", e))?;
            buf
        }
        Ja4Transport::Quic => {
            let mut conn = rustls::quic::ClientConnection::new(
                cfg.clone(),
                rustls::quic::Version::V1,
                name,
                Vec::new(),
            )
            .map_err(|e| format!("quic client connection: {}", e))?;
            let mut buf = Vec::new();
            let _key_change = conn.write_hs(&mut buf);
            buf
        }
    };

    let parsed = parse_client_hello(&hello)?;
    Ok(cohort_from_hello(transport, parsed))
}

fn client_config_for_snapshot() -> std::result::Result<Arc<rustls::ClientConfig>, String> {
    tls_config::client_config(&[])
        .map(Arc::new)
        .map_err(|e| format!("cohort client config: {}", e))
}

fn hex_u16s(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("0x{:04x}", v))
        .collect::<Vec<_>>()
        .join(",")
}

/// RFC 8701 GREASE detection: both bytes equal with low nibble 0x0a.
pub fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && (hi & 0x0f) == 0x0a
}

// ── PQ hybrid key-exchange posture (P4-6) ────────────────────────────────────

/// TLS 1.3 hybrid (post-quantum) key-exchange groups this cohort offers.
///
/// `0x11ec` = X25519MLKEM768. The `prefer-post-quantum` rustls feature places
/// it first in the offer (see [`super::tls_config::client_config`]); the
/// classical groups (`0x001d` X25519, `0x0017` secp256r1, `0x0018` secp384r1)
/// remain as fallbacks. A completed handshake that lands on any OTHER group
/// has silently dropped the post-quantum half of the exchange.
pub const PQ_HYBRID_KEX_GROUPS: &[u16] = &[0x11ec];

/// Human name of the hybrid group this cohort offers first (for alarms/logs).
pub const PQ_HYBRID_KEX_GROUP_NAME: &str = "X25519MLKEM768";

/// True when `group` is one of this cohort's hybrid (post-quantum) groups.
pub fn is_pq_hybrid_kex_group(group: u16) -> bool {
    PQ_HYBRID_KEX_GROUPS.contains(&group)
}

/// Posture of a completed TLS handshake's key exchange, relative to this
/// cohort's PQ-first offer. See [`assert_pq_hybrid_kex_group`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexGroupPosture {
    /// A hybrid (post-quantum) group is in effect.
    Hybrid {
        /// Wire group ID (0x11ec = X25519MLKEM768).
        group: u16,
    },
    /// A classical-only group is in effect even though a hybrid group was
    /// offered: a silent PQ downgrade (P4-6).
    ClassicalOnly {
        /// Wire group ID of the classical group that was negotiated.
        group: u16,
    },
    /// No key-exchange group was reported (pre-TLS-1.3 handshake, TLS 1.2
    /// resumption, or a stack that does not expose it): hybrid cannot be
    /// proven to be in effect.
    NoGroup,
}

impl KexGroupPosture {
    /// Classify the group negotiated by a completed handshake
    /// (`None` = the stack reported no group).
    pub fn classify(group: Option<u16>) -> Self {
        match group {
            Some(g) if is_pq_hybrid_kex_group(g) => Self::Hybrid { group: g },
            Some(g) => Self::ClassicalOnly { group: g },
            None => Self::NoGroup,
        }
    }

    /// True only when the hybrid exchange is actually in effect.
    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::Hybrid { .. })
    }

    /// One-line description for logs and alarms.
    pub fn describe(self) -> String {
        let hybrid = PQ_HYBRID_KEX_GROUPS.first().copied().unwrap_or(0x11ec);
        match self {
            Self::Hybrid { group } => format!(
                "hybrid key exchange in effect (group 0x{:04x} {})",
                group, PQ_HYBRID_KEX_GROUP_NAME
            ),
            Self::ClassicalOnly { group } => format!(
                "classical-only key exchange (group 0x{:04x}) — {} (0x{:04x}) was offered and not negotiated",
                group, PQ_HYBRID_KEX_GROUP_NAME, hybrid
            ),
            Self::NoGroup => format!(
                "no TLS 1.3 key-exchange group reported — {} (0x{:04x}) cannot be in effect",
                PQ_HYBRID_KEX_GROUP_NAME, hybrid
            ),
        }
    }
}

/// Read the key-exchange group a completed `rustls` client connection
/// negotiated, as a wire group ID.
///
/// `None` means the stack reported no group (handshake still in progress,
/// pre-TLS-1.3, or a TLS 1.2 resumption — see rustls
/// `ConnectionCommon::negotiated_key_exchange_group`).
pub fn negotiated_kex_group(conn: &rustls::ClientConnection) -> Option<u16> {
    conn.negotiated_key_exchange_group()
        .map(|g| u16::from(g.name()))
}

/// Fail-loud PQ-downgrade assert for a completed handshake: `Err` when the
/// negotiated group is classical-only (or absent) even though this cohort
/// offers X25519MLKEM768.
///
/// The cohort offers the hybrid group first (`prefer-post-quantum`), so on a
/// Tallow↔Tallow transport a classical-only result is a silent downgrade
/// (misconfiguration, policy override, or active interference) — never
/// ordinary traffic. Callers either propagate this error or emit the alarm
/// via [`alarm_on_classical_kex`].
pub fn assert_pq_hybrid_kex_group(
    peer: &str,
    negotiated: Option<u16>,
) -> std::result::Result<(), String> {
    let posture = KexGroupPosture::classify(negotiated);
    if posture.is_hybrid() {
        Ok(())
    } else {
        Err(format!(
            "PQ-DOWNGRADE ALARM [{}]: {}",
            peer,
            posture.describe()
        ))
    }
}

/// Loud, unmistakable alarm when a completed handshake is not PQ-hybrid.
///
/// Emits `PQ-DOWNGRADE ALARM ...` to stderr and returns the posture so callers
/// can decide whether the connection is acceptable. A hybrid result is silent.
pub fn alarm_on_classical_kex(peer: &str, negotiated: Option<u16>) -> KexGroupPosture {
    let posture = KexGroupPosture::classify(negotiated);
    if let Err(alarm) = assert_pq_hybrid_kex_group(peer, negotiated) {
        eprintln!("{alarm}; connection continues on the classical-only exchange (P4-6)");
    }
    posture
}

fn non_grease(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

fn cohort_from_hello(transport: Ja4Transport, p: ParsedHello) -> Ja4CohortV1 {
    let ciphers_nc = non_grease(&p.ciphers);
    let extensions_nc = non_grease(&p.extensions);

    let tls13 = p.supported_versions.contains(&0x0304);
    let alpn_seg = if p.alpn.is_empty() {
        "00".to_string()
    } else {
        let first = p.alpn.first().and_then(|a| a.chars().next()).unwrap_or('0');
        let last = p.alpn.last().and_then(|a| a.chars().last()).unwrap_or('0');
        format!("{}{}", first, last)
    };
    let ja4_a = format!(
        "{}{}{}{:02}{:02}{}",
        transport.proto_char(),
        if tls13 { 13 } else { 12 },
        if p.sni.is_some() { "d" } else { "i" },
        ciphers_nc.len().min(99),
        extensions_nc.len().min(99),
        alpn_seg
    );
    let ja4_b = sha12(
        &ciphers_nc
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(","),
    );
    let ja4_c = sha12(&ja4_c_input(&p));

    let grease_present = p.ciphers.iter().any(|v| is_grease(*v))
        || p.extensions.iter().any(|v| is_grease(*v))
        || p.groups.iter().any(|v| is_grease(*v))
        || p.sigalgs.iter().any(|v| is_grease(*v))
        || p.key_share_groups.iter().any(|v| is_grease(*v));

    Ja4CohortV1 {
        cohort: JA4_COHORT_ID,
        transport: transport.id(),
        provider: COHORT_PROVIDER,
        server_name: COHORT_SERVER_NAME,
        legacy_version: p.legacy_version,
        tls13_offered: tls13,
        sni: p.sni,
        ciphers: p.ciphers,
        extensions: {
            // rustls randomizes extension order per connection (order_seed); the
            // cohort records the sorted set, JA4-style.
            let mut sorted = p.extensions;
            sorted.sort_unstable();
            sorted
        },
        groups: p.groups,
        sigalgs: p.sigalgs,
        alpn: p.alpn,
        key_share_groups: p.key_share_groups,
        grease_present,
        ja4_a,
        ja4_b,
        ja4_c,
    }
}

/// JA4-shaped digest input for the sorted extension list. Normalizations are
/// documented in the module docs (SNI/ALPN excluded; sigalgs expanded; key_share,
/// pre_shared_key and QUIC transport parameters reduced to their IDs).
fn ja4_c_input(p: &ParsedHello) -> String {
    let mut exts: Vec<(u16, &[u8])> = p
        .ext_values
        .iter()
        .map(|(id, v)| (*id, v.as_slice()))
        .collect();
    exts.sort_by_key(|(id, _)| *id);

    let mut parts: Vec<String> = Vec::new();
    for (id, value) in exts {
        if is_grease(id) {
            continue;
        }
        match id {
            // Hostname / protocol are already represented in JA4_a.
            0x0000 | 0x0010 => {}
            // Signature algorithms: expand to the sorted, GREASE-filtered list.
            0x000d => {
                let mut sigalgs = p.sigalgs.clone();
                sigalgs.retain(|v| !is_grease(*v));
                sigalgs.sort_unstable();
                parts.push(format!(
                    "{:04x}{}",
                    id,
                    sigalgs
                        .iter()
                        .map(|v| format!("{:04x}", v))
                        .collect::<Vec<_>>()
                        .join("-")
                ));
            }
            // Random-valued extensions: ID only (handshake-stable digest).
            0x0029 | 0x0033 | 0x0039 => parts.push(format!("{:04x}", id)),
            _ => parts.push(format!("{:04x}{}", id, hex::encode(value))),
        }
    }
    parts.join(",")
}

#[derive(Debug, Default)]
struct ParsedHello {
    legacy_version: u16,
    sni: Option<String>,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    sigalgs: Vec<u16>,
    alpn: Vec<String>,
    key_share_groups: Vec<u16>,
    supported_versions: Vec<u16>,
    ext_values: Vec<(u16, Vec<u8>)>,
}

fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> std::result::Result<&'a [u8], String> {
    let end = p.checked_add(n).ok_or("length overflow")?;
    let s = b
        .get(*p..end)
        .ok_or_else(|| "truncated structure".to_string())?;
    *p = end;
    Ok(s)
}

fn take_u8(b: &[u8], p: &mut usize) -> std::result::Result<u8, String> {
    Ok(take(b, p, 1)?[0])
}

fn take_u16(b: &[u8], p: &mut usize) -> std::result::Result<u16, String> {
    let s = take(b, p, 2)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Minimal single-record ClientHello parser (record content type 22 → handshake
/// type 1). Only the cohort-relevant fields are extracted.
fn parse_client_hello(record: &[u8]) -> std::result::Result<ParsedHello, String> {
    if record.len() < 4 {
        return Err("cohort capture buffer too short".into());
    }
    // TCP: rustls writes a TLS record (content type 22 = handshake).
    // QUIC: `write_hs` emits the bare handshake message with no record layer.
    let body: &[u8] = if record[0] == 22 {
        if record.len() < 5 {
            return Err("truncated TLS record header".into());
        }
        let rec_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        record
            .get(5..5 + rec_len)
            .ok_or("handshake record length exceeds buffer")?
    } else {
        record
    };
    if body.len() < 4 || body[0] != 1 {
        return Err("not a ClientHello".into());
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    let hs = body
        .get(4..4 + hs_len)
        .ok_or("ClientHello length exceeds buffer")?;

    let mut p = 0usize;
    let legacy_version = take_u16(hs, &mut p)?;
    let _random = take(hs, &mut p, 32)?;
    let sid_len = take_u8(hs, &mut p)? as usize;
    let _session_id = take(hs, &mut p, sid_len)?;
    let cs_len = take_u16(hs, &mut p)? as usize;
    let ciphers = u16_list(take(hs, &mut p, cs_len)?);
    let comp_len = take_u8(hs, &mut p)? as usize;
    let _compression = take(hs, &mut p, comp_len)?;

    let mut out = ParsedHello {
        legacy_version,
        ciphers,
        ..Default::default()
    };

    if p + 2 <= hs.len() {
        let ext_total = take_u16(hs, &mut p)? as usize;
        let ext_block = take(hs, &mut p, ext_total)?;
        let mut q = 0usize;
        while q + 4 <= ext_block.len() {
            let id = u16::from_be_bytes([ext_block[q], ext_block[q + 1]]);
            let len = u16::from_be_bytes([ext_block[q + 2], ext_block[q + 3]]) as usize;
            let value = ext_block
                .get(q + 4..q + 4 + len)
                .ok_or("extension length exceeds buffer")?
                .to_vec();
            q += 4 + len;

            out.extensions.push(id);
            match id {
                // server_name: list-len u16, name type u8, name-len u16, name.
                0x0000 => {
                    if value.len() >= 5 {
                        let name_len = u16::from_be_bytes([value[3], value[4]]) as usize;
                        if let Some(name) = value.get(5..5 + name_len) {
                            out.sni = Some(String::from_utf8_lossy(name).into_owned());
                        }
                    }
                }
                // supported_groups / signature_algorithms: u16 list-len, u16 items.
                0x000a | 0x000d => {
                    if value.len() >= 2 {
                        let list_len = u16::from_be_bytes([value[0], value[1]]) as usize;
                        let list = value.get(2..2 + list_len).unwrap_or_default();
                        if id == 0x000a {
                            out.groups = u16_list(list);
                        } else {
                            out.sigalgs = u16_list(list);
                        }
                    }
                }
                // ALPN: u16 list-len, then u8-len-prefixed protocol names.
                0x0010 => {
                    if value.len() >= 2 {
                        let list_len = u16::from_be_bytes([value[0], value[1]]) as usize;
                        if let Some(list) = value.get(2..2 + list_len) {
                            let mut i = 0usize;
                            while i < list.len() {
                                let n = list[i] as usize;
                                i += 1;
                                if let Some(proto) = list.get(i..i + n) {
                                    out.alpn.push(String::from_utf8_lossy(proto).into_owned());
                                }
                                i += n;
                            }
                        }
                    }
                }
                // supported_versions: u8 list-len, u8 items (client form).
                0x002b => {
                    if !value.is_empty() {
                        let list_len = value[0] as usize;
                        if let Some(list) = value.get(1..1 + list_len) {
                            out.supported_versions = u16_list(list);
                        }
                    }
                }
                // key_share (client): u16 list-len, then (group u16, key-len u16, key).
                0x0033 if value.len() >= 2 => {
                    let list_len = u16::from_be_bytes([value[0], value[1]]) as usize;
                    let mut i = 2usize;
                    while i + 4 <= 2 + list_len && i + 4 <= value.len() {
                        let group = u16::from_be_bytes([value[i], value[i + 1]]);
                        let key_len = u16::from_be_bytes([value[i + 2], value[i + 3]]) as usize;
                        out.key_share_groups.push(group);
                        i += 4 + key_len;
                    }
                }
                _ => {}
            }
            out.ext_values.push((id, value));
        }
    }

    Ok(out)
}

fn sha12(input: &str) -> String {
    sha256_hex(input.as_bytes()).chars().take(12).collect()
}

/// SHA-256 (FIPS 180-4) → lowercase hex. Implemented in-file because `sha2` is
/// not a tallow-net dependency and T-126 must not churn the shared Cargo.lock.
/// Round constants are derived arithmetically from the fractional parts of the
/// cube/square roots of the first primes (§4.2.2) using pure IEEE-754 arithmetic
/// (deterministic on every platform), then validated against the standard vectors
/// by `test_sha256_matches_fips180_4_vectors`.
fn sha256_hex(data: &[u8]) -> String {
    let (k, h0) = sha256_tables();
    let mut h = *h0;

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().expect("4-byte chunk"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{:08x}", word));
    }
    out
}

fn sha256_tables() -> &'static ([u32; 64], [u32; 8]) {
    static TABLES: OnceLock<([u32; 64], [u32; 8])> = OnceLock::new();
    TABLES.get_or_init(|| {
        let primes = first_64_primes();
        let mut k = [0u32; 64];
        let mut h = [0u32; 8];
        for (i, &p) in primes.iter().enumerate() {
            let c = cbrt_det(p as f64);
            k[i] = ((c - c.floor()) * 4294967296.0) as u32;
            if i < 8 {
                let s = (p as f64).sqrt();
                h[i] = ((s - s.floor()) * 4294967296.0) as u32;
            }
        }
        (k, h)
    })
}

fn first_64_primes() -> [u16; 64] {
    let mut primes = [0u16; 64];
    let mut found = 0usize;
    let mut cand: u16 = 2;
    'search: while found < 64 {
        let mut d: u32 = 2;
        while d * d <= cand as u32 {
            if (cand as u32).is_multiple_of(d) {
                cand += 1;
                continue 'search;
            }
            d += 1;
        }
        primes[found] = cand;
        found += 1;
        cand += 1;
    }
    primes
}

/// Newton–Raphson cube root using only IEEE-754 correctly-rounded operations, so
/// the derived constants are bit-identical on every platform (system libm `cbrt`
/// is not guaranteed to be).
fn cbrt_det(x: f64) -> f64 {
    let mut y = x; // x >= 2 for all callers; crude but safe seed
    for _ in 0..80 {
        y = (2.0 * y + x / (y * y)) / 3.0;
    }
    y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_matches_fips180_4_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_is_grease_rfc8701_vectors() {
        for v in [
            0x0a0au16, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
            0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ] {
            assert!(is_grease(v), "0x{:04x} should be GREASE", v);
        }
        for v in [0x0000u16, 0x0a0b, 0x0b0a, 0x1301, 0x0304, 0xffff, 0x1a1b] {
            assert!(!is_grease(v), "0x{:04x} should not be GREASE", v);
        }
    }

    /// P4-6: the cohort's own offer must keep including the hybrid group —
    /// otherwise there is no PQ exchange for a downgrade to drop.
    #[test]
    fn test_cohort_offer_includes_pq_hybrid_group_first() {
        for transport in [Ja4Transport::Tcp, Ja4Transport::Quic] {
            let cohort = ja4_cohort_v1(transport).unwrap();
            assert!(
                cohort.groups.iter().any(|g| is_pq_hybrid_kex_group(*g)),
                "{:?} groups must include the hybrid group: {:?}",
                transport,
                cohort.groups
            );
            assert_eq!(
                cohort.groups.first().copied(),
                Some(0x11ec),
                "{:?} must offer X25519MLKEM768 first (prefer-post-quantum): {:?}",
                transport,
                cohort.groups
            );
            assert!(
                cohort
                    .key_share_groups
                    .first()
                    .is_some_and(|g| is_pq_hybrid_kex_group(*g)),
                "{:?} must send a hybrid key share first: {:?}",
                transport,
                cohort.key_share_groups
            );
        }
    }

    /// P4-6: classification of the negotiated group — hybrid vs classical-only
    /// vs unreported.
    #[test]
    fn test_kex_posture_classifies_hybrid_classical_and_none() {
        assert_eq!(
            KexGroupPosture::classify(Some(0x11ec)),
            KexGroupPosture::Hybrid { group: 0x11ec }
        );
        assert_eq!(
            KexGroupPosture::classify(Some(0x001d)),
            KexGroupPosture::ClassicalOnly { group: 0x001d }
        );
        assert_eq!(KexGroupPosture::classify(None), KexGroupPosture::NoGroup);
        for (g, expected) in [
            (Some(0x11ec), true),
            (Some(0x001d), false),
            (Some(0x0017), false),
            (None, false),
        ] {
            assert_eq!(
                KexGroupPosture::classify(g).is_hybrid(),
                expected,
                "posture for {g:?}"
            );
        }
    }

    /// P4-6: the assert must fail LOUDLY on a classical-only negotiation,
    /// naming both the negotiated group and the hybrid group that was offered.
    #[test]
    fn test_assert_pq_hybrid_kex_group_fails_loud_on_classical_only() {
        assert!(assert_pq_hybrid_kex_group("relay.test", Some(0x11ec)).is_ok());

        let err = assert_pq_hybrid_kex_group("relay.test", Some(0x001d)).unwrap_err();
        assert!(err.contains("PQ-DOWNGRADE ALARM"), "alarm text: {err}");
        assert!(
            err.contains("0x001d"),
            "must name the negotiated group: {err}"
        );
        assert!(
            err.contains("X25519MLKEM768"),
            "must name the offered hybrid group: {err}"
        );

        let err = assert_pq_hybrid_kex_group("relay.test", None).unwrap_err();
        assert!(err.contains("PQ-DOWNGRADE ALARM"), "alarm text: {err}");
    }

    /// Synthetic RFC 8701 ClientHello: GREASE must be flagged on the wire fields
    /// but filtered from every digest input (counts, ja4_b).
    #[test]
    fn test_synthetic_grease_hello_is_filtered() {
        let sni_value = {
            let name = b"x";
            let mut v = vec![0x00, (name.len() + 3) as u8, 0x00, 0x00, name.len() as u8];
            v.extend_from_slice(name);
            v
        };
        let hello = build_synthetic_hello(
            &[0x0a0a, 0x1301],
            &[
                (0x0000, sni_value),
                (0x1a1a, vec![0x00]),
                (0x000d, vec![0x00, 0x04, 0x0a, 0x0a, 0x04, 0x03]),
                (0x0010, vec![0x00, 0x03, 0x02, 0x68, 0x32]),
            ],
            &[0x2a2a, 0x001d],
        );

        let parsed = parse_client_hello(&hello).unwrap();
        let cohort = cohort_from_hello(Ja4Transport::Tcp, parsed);

        assert!(cohort.grease_present, "GREASE must be flagged");
        // Wire truth keeps GREASE; digests must not.
        assert_eq!(cohort.ciphers, vec![0x0a0a, 0x1301]);
        assert_eq!(cohort.groups, vec![0x2a2a, 0x001d]);
        assert_eq!(cohort.sigalgs, vec![0x0a0a, 0x0403]);
        // Filtered counts + ALPN segment: 1 cipher, 4 non-GREASE extensions
        // (0x000a groups, 0x0000 SNI, 0x000d sigalgs, 0x0010 ALPN), ALPN "h2".
        assert_eq!(cohort.ja4_a, "t12d0104h2");
        assert_eq!(cohort.ja4_b, sha12("1301"));
        assert_ne!(cohort.ja4_b, sha12("0a0a,1301"));
    }

    #[test]
    fn test_client_config_alpn_hook() {
        let none = tls_config::client_config(&[]).unwrap();
        assert!(none.alpn_protocols.is_empty());
        let h2 = tls_config::client_config(&[b"h2"]).unwrap();
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_ja4_cohort_v1_matches_pinned_snapshot() {
        let tcp = ja4_cohort_v1(Ja4Transport::Tcp).unwrap();
        let quic = ja4_cohort_v1(Ja4Transport::Quic).unwrap();
        println!(
            "--- JA4_COHORT_V1 / TCP ---\n{}\n--- JA4_COHORT_V1 / QUIC ---\n{}",
            tcp.render(),
            quic.render()
        );
        assert_eq!(
            tcp.render(),
            JA4_COHORT_V1_TCP,
            "TCP+TLS client cohort changed — re-verify and re-pin JA4_COHORT_V1_TCP (bump JA4_COHORT_ID only for intentional shape changes)"
        );
        assert_eq!(
            quic.render(),
            JA4_COHORT_V1_QUIC,
            "QUIC client cohort changed — re-verify and re-pin JA4_COHORT_V1_QUIC"
        );
    }

    #[test]
    fn test_cohort_snapshot_is_deterministic() {
        for transport in [Ja4Transport::Tcp, Ja4Transport::Quic] {
            let a = ja4_cohort_v1(transport).unwrap().render();
            let b = ja4_cohort_v1(transport).unwrap().render();
            assert_eq!(
                a, b,
                "cohort render must be deterministic for {:?}",
                transport
            );
        }
    }

    #[test]
    fn test_tcp_and_quic_share_provider_cipher_cohort() {
        let tcp = ja4_cohort_v1(Ja4Transport::Tcp).unwrap();
        let quic = ja4_cohort_v1(Ja4Transport::Quic).unwrap();
        // QUIC offers only the TLS 1.3 suites usable for QUIC (rustls filters the
        // TLS 1.2 suites and drops the renegotiation SCSV) — a subset of the
        // shared provider offer.
        assert!(quic.ciphers.iter().all(|c| tcp.ciphers.contains(c)));
        assert!(
            tcp.ciphers.contains(&0xc02c) && !quic.ciphers.contains(&0xc02c),
            "TLS 1.2 suite must appear in TCP but never in QUIC"
        );
        assert_eq!(tcp.groups, quic.groups);
        assert_eq!(tcp.sigalgs, quic.sigalgs);
        assert!(tcp.tls13_offered && quic.tls13_offered);
        assert!(!tcp.grease_present, "rustls must not inject GREASE (tcp)");
        assert!(!quic.grease_present, "rustls must not inject GREASE (quic)");
    }

    /// Build a minimal-but-valid single-record ClientHello for parser/GREASE tests.
    fn build_synthetic_hello(ciphers: &[u16], exts: &[(u16, Vec<u8>)], groups: &[u16]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // empty session id

        let mut cs = Vec::new();
        for c in ciphers {
            cs.extend_from_slice(&c.to_be_bytes());
        }
        hs.extend_from_slice(&(cs.len() as u16).to_be_bytes());
        hs.extend_from_slice(&cs);
        hs.extend_from_slice(&[1, 0]); // compression: null only

        let mut eb = Vec::new();
        let mut gv = Vec::new();
        for g in groups {
            gv.extend_from_slice(&g.to_be_bytes());
        }
        let mut gvalue = Vec::new();
        gvalue.extend_from_slice(&(gv.len() as u16).to_be_bytes());
        gvalue.extend_from_slice(&gv);
        eb.extend_from_slice(&0x000au16.to_be_bytes());
        eb.extend_from_slice(&(gvalue.len() as u16).to_be_bytes());
        eb.extend_from_slice(&gvalue);
        for (id, value) in exts {
            eb.extend_from_slice(&id.to_be_bytes());
            eb.extend_from_slice(&(value.len() as u16).to_be_bytes());
            eb.extend_from_slice(value);
        }
        hs.extend_from_slice(&(eb.len() as u16).to_be_bytes());
        hs.extend_from_slice(&eb);

        let mut body = vec![1u8]; // ClientHello
        let len = hs.len();
        body.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        body.extend_from_slice(&hs);

        let mut record = vec![22u8, 0x03, 0x01];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }
}
