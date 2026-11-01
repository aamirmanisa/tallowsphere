//! Scope gate — the authorization register for outbound targets.
//!
//! Deny-by-default. A host that is not in the register is refused *before* a
//! socket is opened, so the refusal happens at the same place the decision is
//! made rather than after the request is on the wire.
//!
//! This mirrors the isolated scrape sandbox's `targets.allowlist` contract
//! (`/etc/scrape-isolated/scrape.yaml`: "An URL whose host is not listed is
//! refused before a circuit is even built") and the blocking rule that config
//! already enforces, generalised from sandbox-local config to the engine.
//!
//! ## Doctrine this implements
//!
//! `docs/opsec/stealth-scanning-statement-of-intent.md`, directive 1 and 2:
//! confirm scope and authorization before anything else; the posture is for
//! **read-only, public-data** collection; no authentication surfaces, no
//! credentials.
//!
//! That is enforced structurally: [`Basis`] has no variant that could authorise
//! credential-gated work, and [`ScopeRegister::authorize`] refuses known
//! authentication paths regardless of which basis a host carries. A register
//! cannot be edited into permitting an authenticated surface, because the type
//! system has no value for it.
//!
//! ## Fail-closed
//!
//! A missing, unreadable or malformed register refuses **every** host. The
//! absence of an authorization is never read as a permission.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Default register location, relative to the workspace root.
pub const DEFAULT_REGISTER_PATH: &str = "configs/tallow/scope/authorized-hosts.toml";

/// Why a target may be contacted.
///
/// Deliberately excludes anything credential-shaped: there is no
/// `AuthenticatedSession`, no `StolenCookie`, no `CredentialHarvest` variant,
/// and therefore no configuration that unlocks one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Basis {
    /// The operator owns the host and the data behind it.
    Ownership,
    /// The host's owner granted written permission. Requires `evidence`.
    WrittenConsent,
    /// Infrastructure the operator controls directly (loopback, home lab).
    SelfHosted,
    /// Public data, published for machine retrieval, no authentication.
    PublicReadOnly,
}

impl Basis {
    /// Human-readable ground, used verbatim in refusal and audit output.
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Ownership => "ownership",
            Basis::WrittenConsent => "written-consent",
            Basis::SelfHosted => "self-hosted",
            Basis::PublicReadOnly => "public-read-only",
        }
    }

    /// Bases that are meaningless without a pointer to their authorization
    /// artifact. `WrittenConsent` without evidence is an assertion, and an
    /// assertion is not a grant.
    pub fn requires_evidence(self) -> bool {
        matches!(self, Basis::WrittenConsent)
    }
}

/// One authorized target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeEntry {
    /// Exact host, or a leading-`*.` wildcard for a domain the operator owns.
    pub host: String,
    pub basis: Basis,
    /// Who granted this. A name or a role, not "everyone".
    pub granted_by: String,
    /// ISO date `YYYY-MM-DD`.
    pub granted_at: String,
    /// ISO date `YYYY-MM-DD`. `None` means no expiry, which is still audited
    /// (`tallow scope list` prints every unexpiring entry explicitly).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Path or URI to the authorization artifact. Required for
    /// [`Basis::WrittenConsent`].
    #[serde(default)]
    pub evidence: Option<String>,
    /// Methods permitted. Defaults to read-only HTTP (`GET`, `HEAD`).
    /// `CONNECT` is the raw-socket / port-scan verb; it is grantable and
    /// never a default. See [`GRANTABLE_METHODS`].
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

/// Closed method vocabulary a register entry may grant.
///
/// `GET` / `HEAD` are the default. `CONNECT` is the raw-socket verb
/// (`Scanner.scan` and similar port probes): grantable, never default.
/// It is not HTTP CONNECT (RFC 9110 proxy tunneling). The remaining
/// names are the other HTTP methods; they stay grantable so an existing
/// `methods = ["POST"]` entry does not become malformed.
pub const GRANTABLE_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
];

fn is_grantable_method(method: &str) -> bool {
    let m = method.trim().to_ascii_uppercase();
    GRANTABLE_METHODS.iter().copied().any(|g| g == m)
}

impl ScopeEntry {
    fn matches_host(&self, host: &str) -> bool {
        let entry = normalize_key(&self.host);
        let host = normalize_key(host);
        if let Some(suffix) = entry.strip_prefix("*.") {
            // Explicit, opt-in subdomain grant. The apex itself is NOT covered:
            // `*.example.com` does not authorise `example.com`, because they are
            // frequently different owners.
            host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        } else {
            entry == host
        }
    }

    fn permits_method(&self, method: &str) -> bool {
        let m = method.trim().to_ascii_uppercase();
        self.methods.iter().any(|x| x.trim().to_ascii_uppercase() == m)
    }
}

/// Why a target was refused. Every variant names the ground, in the form the
/// operator's doctrine asks for: the reason, not a shrug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "refusal", content = "detail")]
pub enum Refusal {
    /// Not in the register. The default answer.
    NotListed { host: String },
    /// Listed, but the grant has lapsed. Fail-closed: an expired entry is not
    /// an entry.
    Expired {
        host: String,
        expires_at: String,
        today: String,
    },
    /// Claimed `WrittenConsent` with nothing pointing at the consent.
    EvidenceMissing { host: String, basis: String },
    /// The method is outside the granted set.
    MethodNotAllowed {
        host: String,
        method: String,
        allowed: Vec<String>,
    },
    /// An authentication surface. Refused on every basis, by doctrine.
    AuthenticationSurface { host: String, path: String },
    /// The register could not be read. Nothing is authorized.
    RegisterUnreadable { path: String, detail: String },
    /// The register parsed but is not a valid register. Nothing is authorized.
    RegisterMalformed { path: String, detail: String },
    /// The input was not a host or a URL we can read a host out of.
    HostMalformed { input: String },
}

impl Refusal {
    /// Stable machine-readable code, e.g. `scope:not-listed`.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::NotListed { .. } => "scope:not-listed",
            Refusal::Expired { .. } => "scope:expired",
            Refusal::EvidenceMissing { .. } => "scope:evidence-missing",
            Refusal::MethodNotAllowed { .. } => "scope:method-not-allowed",
            Refusal::AuthenticationSurface { .. } => "scope:authentication-surface",
            Refusal::RegisterUnreadable { .. } => "scope:register-unreadable",
            Refusal::RegisterMalformed { .. } => "scope:register-malformed",
            Refusal::HostMalformed { .. } => "scope:host-malformed",
        }
    }

    /// One-line explanation for a human reading `tallow scope check`.
    pub fn explain(&self) -> String {
        match self {
            Refusal::NotListed { host } => format!(
                "refused: {host} is not in the authorization register (deny-by-default)"
            ),
            Refusal::Expired {
                host,
                expires_at,
                today,
            } => format!("refused: the grant for {host} expired on {expires_at} (today {today})"),
            Refusal::EvidenceMissing { host, basis } => format!(
                "refused: {host} claims basis '{basis}' but carries no evidence pointer; \
                 an assertion is not a grant"
            ),
            Refusal::MethodNotAllowed {
                host,
                method,
                allowed,
            } => format!(
                "refused: {method} on {host} is outside the granted set [{}]",
                allowed.join(", ")
            ),
            Refusal::AuthenticationSurface { host, path } => format!(
                "refused: {host}{path} is an authentication surface; the posture is \
                 read-only public data (no authentication surfaces, no credentials)"
            ),
            Refusal::RegisterUnreadable { path, detail } => format!(
                "refused: the register at {path} could not be read ({detail}); \
                 with no register nothing is authorized"
            ),
            Refusal::RegisterMalformed { path, detail } => format!(
                "refused: the register at {path} is malformed ({detail}); \
                 with no valid register nothing is authorized"
            ),
            Refusal::HostMalformed { input } => {
                format!("refused: could not read a host out of '{input}'")
            }
        }
    }
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed(Box<ScopeEntry>),
    Refused(Refusal),
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed(_))
    }

    /// The refusal, if refused. `None` when allowed.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Decision::Allowed(_) => None,
            Decision::Refused(r) => Some(r),
        }
    }

    /// One-line renderable outcome, for CLI and audit output.
    pub fn render(&self) -> String {
        match self {
            Decision::Allowed(e) => format!(
                "allowed: {} via {} (granted by {} at{})",
                e.host,
                e.basis.as_str(),
                e.granted_by,
                e.expires_at
                    .as_deref()
                    .map(|d| format!(", expires {d}"))
                    .unwrap_or_else(|| ", no expiry set".to_string())
            ),
            Decision::Refused(r) => r.explain(),
        }
    }
}

/// Path fragments that identify an authentication surface.
///
/// Kept deliberately broad and case-insensitive: a false refusal here costs a
/// retry, a false allow costs the line the doctrine draws.
const AUTH_PATH_MARKERS: &[&str] = &[
    "/login",
    "/logout",
    "/signin",
    "/sign-in",
    "/signup",
    "/sign-up",
    "/auth",
    "/oauth",
    "/oauth2",
    "/session",
    "/sessions",
    "/account",
    "/accounts",
    "/user/settings",
    "/profile/settings",
    "/password",
    "/reset",
    "/token",
    "/credential",
    "/checkout/payment",
    "/payment",
    "/billing",
    "/admin",
    "/api/v1/keys",
    "/api/keys",
];

/// The host key an authority contributes to a scope decision.
///
/// A name or an IPv4 literal ends at the first `:`, which is its port
/// separator. An IPv6 literal does not: splitting it on `:` truncates the
/// address to its first label (`::1` -> "", `2001:db8::1` -> "2001"), so an
/// IPv6 grant could not be expressed in the register at all. A bracketed
/// authority (RFC 3986) is cut at `]`; an unbracketed one that is itself a
/// literal — with or without a `%zone` — is taken whole.
fn host_key(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    let is_literal = authority.parse::<std::net::Ipv6Addr>().is_ok()
        || authority
            .split_once('%')
            .map(|(addr, zone)| {
                !zone.is_empty()
                    && !zone.contains(':')
                    && addr.parse::<std::net::Ipv6Addr>().is_ok()
            })
            .unwrap_or(false);
    if is_literal {
        return authority;
    }
    authority.split(':').next().unwrap_or("")
}

/// The one spelling both a register entry and a target are reduced to.
///
/// A grant that is written one way and matched another can never fire: a
/// bracketed IPv6 entry (`[::1]`) never equals a bare target (`::1`), and an
/// FQDN written with its root dot (`example.com.`) never equals the same name
/// without it. Both sides go through this, so those are the same key.
fn normalize_key(s: &str) -> String {
    let mut k = host_key(s.trim()).trim().to_ascii_lowercase();
    while k.ends_with('.') {
        k.pop();
    }
    k
}

/// `YYYY-MM-DD`, checked field by field.
///
/// Expiry is compared as text, so a value that is not a date silently never
/// lapses: `"soon"` sorts after every real date, and a grant carrying it would
/// be permanent. An unparseable date is a malformed register, not a grant.
fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    if !(b[..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let month: u32 = s[5..7].parse().unwrap_or(0);
    let day: u32 = s[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// The host part of an authority, with a port suffix either validated or
/// refused.
///
/// Dropping an unparseable suffix is worse than refusing it: `host:99999`
/// would be answered as `host`, so the allow would be reported against a target
/// nobody spelled.
fn authority_host<'a>(authority: &'a str, input: &str) -> Result<&'a str, Refusal> {
    let bad = || Refusal::HostMalformed {
        input: input.to_string(),
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (inner, tail) = rest.split_once(']').ok_or_else(bad)?;
        check_port_suffix(tail, input)?;
        return Ok(inner);
    }
    // A bare IPv6 literal (optionally with a zone) contains colons but no port.
    if authority.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(authority);
    }
    if let Some((addr, zone)) = authority.split_once('%') {
        if !zone.is_empty() && addr.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok(authority);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, port)) => {
            check_port_suffix(&format!(":{port}"), input)?;
            Ok(h)
        }
        None => Ok(authority),
    }
}

fn check_port_suffix(tail: &str, input: &str) -> Result<(), Refusal> {
    let bad = || Refusal::HostMalformed {
        input: input.to_string(),
    };
    if tail.is_empty() {
        return Ok(());
    }
    let port = tail.strip_prefix(':').ok_or_else(bad)?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    match port.parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => Ok(()),
        _ => Err(bad()),
    }
}

/// Extract `(host, path)` from a bare host or a URL.
///
/// Hand-rolled rather than pulling a URL parser in: this module must be usable
/// on the code path that decides whether a request may even be built.
fn split_host_path(input: &str) -> Result<(String, String), Refusal> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Refusal::HostMalformed {
            input: input.to_string(),
        });
    }
    // Strip a scheme if present.
    let after_scheme = match trimmed.find("://") {
        Some(i) => &trimmed[i + 3..],
        None => trimmed,
    };
    // Drop userinfo: a credential in the URL is itself a defect worth refusing.
    let authority_and_rest = match after_scheme.find('@') {
        Some(i) => {
            return Err(Refusal::AuthenticationSurface {
                host: after_scheme[..i].to_string(),
                path: " (credentials embedded in the target URL)".to_string(),
            })
        }
        None => after_scheme,
    };
    let (authority, path) = match authority_and_rest.find('/') {
        Some(i) => (
            &authority_and_rest[..i],
            authority_and_rest[i..].to_string(),
        ),
        None => (authority_and_rest, String::new()),
    };
    // Drop the port — validating it rather than discarding it — and take the
    // rest as the host key.
    let host = authority_host(authority, input)?.trim().to_ascii_lowercase();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(Refusal::HostMalformed {
            input: input.to_string(),
        });
    }
    Ok((host, path))
}

fn is_authentication_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    AUTH_PATH_MARKERS.iter().any(|m| p.contains(m))
}

/// The loadable register.
#[derive(Debug, Clone)]
pub struct ScopeRegister {
    path: PathBuf,
    entries: BTreeMap<String, ScopeEntry>,
    /// Set when the register could not be loaded. When present, every
    /// authorization attempt refuses with this reason.
    load_failure: Option<Refusal>,
}

#[derive(Debug, Deserialize)]
struct RegisterFile {
    #[serde(default)]
    authorized: Vec<ScopeEntry>,
}

impl ScopeRegister {
    /// Load from `path`. Never fails: an unreadable or malformed file yields a
    /// register that refuses everything, carrying the reason.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let display = path.display().to_string();
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                return Self {
                    path,
                    entries: BTreeMap::new(),
                    load_failure: Some(Refusal::RegisterUnreadable {
                        path: display,
                        detail: e.to_string(),
                    }),
                }
            }
        };
        let parsed: RegisterFile = match toml::from_str(&raw) {
            Ok(p) => p,
            Err(e) => {
                return Self {
                    path,
                    entries: BTreeMap::new(),
                    load_failure: Some(Refusal::RegisterMalformed {
                        path: display,
                        detail: e.to_string(),
                    }),
                }
            }
        };
        let mut entries = BTreeMap::new();
        for e in parsed.authorized {
            let key = normalize_key(&e.host);
            // A defective entry invalidates the register rather than being
            // skipped: authorising the sound siblings of a file the operator
            // got wrong grants a subset nobody chose, and `scope verify` would
            // call the same file defective. Both must agree, and the safe
            // reading of "this file is wrong" is "authorise nothing".
            if e.basis.requires_evidence()
                && e.evidence.as_deref().unwrap_or("").trim().is_empty()
            {
                return Self {
                    path,
                    entries: BTreeMap::new(),
                    load_failure: Some(Refusal::RegisterMalformed {
                        path: display,
                        detail: format!(
                            "entry for '{}' claims basis '{}' but carries no evidence pointer",
                            e.host, e.basis.as_str()
                        ),
                    }),
                };
            }
            if let Some(expires) = e.expires_at.as_deref() {
                if !is_iso_date(expires.trim()) {
                    return Self {
                        path,
                        entries: BTreeMap::new(),
                        load_failure: Some(Refusal::RegisterMalformed {
                            path: display,
                            detail: format!(
                                "entry for '{}' has an unparseable expires_at '{expires}' \
                                 (expected YYYY-MM-DD); a grant that cannot be dated cannot lapse",
                                e.host
                            ),
                        }),
                    };
                }
            }
            if key.is_empty() {
                return Self {
                    path,
                    entries: BTreeMap::new(),
                    load_failure: Some(Refusal::RegisterMalformed {
                        path: display,
                        detail: "an entry has an empty host".to_string(),
                    }),
                };
            }
            for m in &e.methods {
                if !is_grantable_method(m) {
                    return Self {
                        path,
                        entries: BTreeMap::new(),
                        load_failure: Some(Refusal::RegisterMalformed {
                            path: display,
                            detail: format!(
                                "entry for '{}' carries method '{}' which is outside the grantable set [{}]",
                                e.host,
                                m.trim(),
                                GRANTABLE_METHODS.join(", ")
                            ),
                        }),
                    };
                }
            }
            // Duplicate hosts are a register defect, not a merge.
            if entries.contains_key(&key) {
                return Self {
                    path,
                    entries: BTreeMap::new(),
                    load_failure: Some(Refusal::RegisterMalformed {
                        path: display,
                        detail: format!("host '{key}' appears more than once"),
                    }),
                };
            }
            entries.insert(key, e);
        }
        Self {
            path,
            entries,
            load_failure: None,
        }
    }

    /// The default register, from [`DEFAULT_REGISTER_PATH`].
    pub fn load_default() -> Self {
        Self::load(DEFAULT_REGISTER_PATH)
    }

    /// A register with no entries and no failure: every host is refused as
    /// `not-listed`. Useful in tests and for "no scope configured yet".
    pub fn empty() -> Self {
        Self {
            path: PathBuf::from("<empty>"),
            entries: BTreeMap::new(),
            load_failure: None,
        }
    }

    /// In-memory register from already-built entries. `authorize` is unchanged:
    /// an unlisted host is still refused, an expired grant still refuses.
    #[cfg(test)]
    pub fn from_entries(entries: Vec<ScopeEntry>) -> Self {
        let mut map = BTreeMap::new();
        for e in entries {
            let key = normalize_key(&e.host);
            map.insert(key, e);
        }
        Self {
            path: PathBuf::from("<test>"),
            entries: map,
            load_failure: None,
        }
    }

    /// In-memory register: each `(host, methods)` is a self-hosted grant with
    /// no expiry. Methods must be in [`GRANTABLE_METHODS`]. Does not weaken
    /// [`Self::authorize`].
    #[cfg(test)]
    pub fn granting(hosts: &[(&str, &[&str])]) -> Self {
        let entries = hosts
            .iter()
            .map(|(host, methods)| {
                let methods: Vec<String> = methods
                    .iter()
                    .map(|m| {
                        let u = m.trim().to_ascii_uppercase();
                        assert!(
                            is_grantable_method(&u),
                            "test grant for {host} carries non-grantable method {u}"
                        );
                        u
                    })
                    .collect();
                ScopeEntry {
                    host: (*host).to_string(),
                    basis: Basis::SelfHosted,
                    granted_by: "test".to_string(),
                    granted_at: "2026-01-01".to_string(),
                    expires_at: None,
                    evidence: None,
                    methods,
                    notes: None,
                }
            })
            .collect();
        Self::from_entries(entries)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in host order, for `tallow scope list`.
    pub fn entries(&self) -> impl Iterator<Item = &ScopeEntry> {
        self.entries.values()
    }

    /// The load failure, if the register could not be used at all.
    pub fn load_failure(&self) -> Option<&Refusal> {
        self.load_failure.as_ref()
    }

    /// Decide. `today` is an ISO date, passed in rather than read from the
    /// clock so the decision is deterministic and testable.
    pub fn authorize(&self, input: &str, method: &str, today: &str) -> Decision {
        if let Some(failure) = &self.load_failure {
            return Decision::Refused(failure.clone());
        }
        let (host, path) = match split_host_path(input) {
            Ok(v) => v,
            Err(r) => return Decision::Refused(r),
        };
        // Credentials and authentication surfaces are refused before any entry
        // is consulted, so no basis can override it.
        if is_authentication_path(&path) {
            return Decision::Refused(Refusal::AuthenticationSurface { host, path });
        }
        let entry = match self
            .entries
            .values()
            .find(|e| e.matches_host(&host))
        {
            Some(e) => e.clone(),
            None => return Decision::Refused(Refusal::NotListed { host }),
        };
        if entry.basis.requires_evidence() && entry.evidence.as_deref().unwrap_or("").trim().is_empty()
        {
            return Decision::Refused(Refusal::EvidenceMissing {
                host,
                basis: entry.basis.as_str().to_string(),
            });
        }
        if let Some(expires) = entry.expires_at.as_deref() {
            // ISO dates compare lexicographically. An entry expiring *today* is
            // still valid for today; it lapses the day after.
            if today.trim() > expires.trim() {
                return Decision::Refused(Refusal::Expired {
                    host,
                    expires_at: expires.to_string(),
                    today: today.to_string(),
                });
            }
        }
        if !entry.permits_method(method) {
            return Decision::Refused(Refusal::MethodNotAllowed {
                host,
                method: method.to_string(),
                allowed: entry.methods.clone(),
            });
        }
        Decision::Allowed(Box::new(entry))
    }
}

/// Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
/// Hand-rolled so the gate carries no date-library dependency: it must be
/// usable on the code path that decides whether a request may be built.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Today, UTC, as `YYYY-MM-DD`.
pub fn utc_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Fail-closed convenience for call sites: load the default register and
/// authorize. Returns the granting entry, or the refusal that names the ground.
///
/// Call sites in a loop should hold a [`ScopeRegister`] and call
/// [`ScopeRegister::authorize`] directly rather than re-reading the file per
/// request.
///
/// In a test build, a thread-local override (`override_register`) is
/// consulted first so a unit test can plant a grant without touching
/// `configs/` and without leaking that grant to other test threads. A
/// non-test build has no such cell: `require` always loads the default file.
pub fn require(input: &str, method: &str) -> Result<ScopeEntry, Refusal> {
    let register = {
        #[cfg(test)]
        {
            if let Some(r) = TEST_REGISTER.with(|c| c.borrow().clone()) {
                r
            } else {
                ScopeRegister::load_default()
            }
        }
        #[cfg(not(test))]
        {
            // Proof of absence: this arm is the only `require` path in a
            // release build. The override cell is not in scope here.
            let _ = TEST_REGISTER_OVERRIDE_ABSENT;
            ScopeRegister::load_default()
        }
    };
    match register.authorize(input, method, &utc_today()) {
        Decision::Allowed(entry) => Ok(*entry),
        Decision::Refused(refusal) => Err(refusal),
    }
}

/// Named so a non-test build fails to compile if the override cell is lifted
/// out of `#[cfg(test)]` and this constant is deleted to hide it.
#[cfg(not(test))]
const TEST_REGISTER_OVERRIDE_ABSENT: () = ();

#[cfg(test)]
thread_local! {
    static TEST_REGISTER: std::cell::RefCell<Option<ScopeRegister>> =
        const { std::cell::RefCell::new(None) };
}

/// Plant `register` as the one [`require`] consults on **this thread**.
/// Dropping the guard restores the previous cell (usually `None`).
#[cfg(test)]
pub fn override_register(register: ScopeRegister) -> ScopeOverrideGuard {
    let previous = TEST_REGISTER.with(|c| c.borrow_mut().replace(register));
    ScopeOverrideGuard { previous }
}

/// Restores the thread-local register override when dropped.
#[cfg(test)]
pub struct ScopeOverrideGuard {
    previous: Option<ScopeRegister>,
}

#[cfg(test)]
impl Drop for ScopeOverrideGuard {
    fn drop(&mut self) {
        TEST_REGISTER.with(|c| *c.borrow_mut() = self.previous.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "2026-10-16";

    fn entry(host: &str, basis: Basis, expires: Option<&str>) -> ScopeEntry {
        ScopeEntry {
            host: host.to_string(),
            basis,
            granted_by: "operator".to_string(),
            granted_at: "2026-01-01".to_string(),
            expires_at: expires.map(|s| s.to_string()),
            evidence: Some("docs/consent/example.txt".to_string()),
            methods: default_methods(),
            notes: None,
        }
    }

    fn register_with(entries: Vec<ScopeEntry>) -> ScopeRegister {
        ScopeRegister::from_entries(entries)
    }

    #[test]
    fn unlisted_host_is_refused() {
        let r = register_with(vec![entry("owned.example", Basis::Ownership, None)]);
        let d = r.authorize("https://other.example/x", "GET", T);
        assert_eq!(
            d.refusal(),
            Some(&Refusal::NotListed {
                host: "other.example".to_string()
            })
        );
        assert!(!d.is_allowed());
    }

    #[test]
    fn listed_host_is_allowed_and_reports_its_basis() {
        let r = register_with(vec![entry("owned.example", Basis::Ownership, None)]);
        let d = r.authorize("https://owned.example/pricing", "GET", T);
        assert!(d.is_allowed());
        match d {
            Decision::Allowed(e) => assert_eq!(e.basis, Basis::Ownership),
            Decision::Refused(r) => panic!("expected allowed, got {}", r.explain()),
        }
    }

    #[test]
    fn no_register_refuses_everything() {
        let r = ScopeRegister::empty();
        let d = r.authorize("https://owned.example/", "GET", T);
        assert!(matches!(d.refusal(), Some(Refusal::NotListed { .. })));
    }

    #[test]
    fn missing_register_file_fails_closed() {
        let r = ScopeRegister::load("/nonexistent/register.toml");
        assert!(matches!(
            r.load_failure(),
            Some(Refusal::RegisterUnreadable { .. })
        ));
        let d = r.authorize("http://127.0.0.1:8080/", "GET", T);
        assert!(matches!(
            d.refusal(),
            Some(Refusal::RegisterUnreadable { .. })
        ));
    }

    #[test]
    fn malformed_register_fails_closed() {
        let dir = std::env::temp_dir().join("tallow-scope-test-malformed");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("register.toml");
        std::fs::write(&p, "authorized = \"not-a-list\"").expect("write");
        let r = ScopeRegister::load(&p);
        assert!(matches!(
            r.load_failure(),
            Some(Refusal::RegisterMalformed { .. })
        ));
        assert!(!r.authorize("https://owned.example/", "GET", T).is_allowed());
    }

    #[test]
    fn expired_grant_is_refused_and_grants_lapse_the_day_after() {
        let r = register_with(vec![entry("owned.example", Basis::Ownership, Some(T))]);
        // Valid on the expiry date itself.
        assert!(r.authorize("https://owned.example/", "GET", T).is_allowed());
        // Lapsed the next day.
        let d = r.authorize("https://owned.example/", "GET", "2026-10-17");
        assert!(matches!(d.refusal(), Some(Refusal::Expired { .. })));
    }

    #[test]
    fn written_consent_without_evidence_is_refused() {
        let mut e = entry("consented.example", Basis::WrittenConsent, None);
        e.evidence = None;
        let r = register_with(vec![e]);
        let d = r.authorize("https://consented.example/", "GET", T);
        assert!(matches!(
            d.refusal(),
            Some(Refusal::EvidenceMissing { .. })
        ));
    }

    #[test]
    fn authentication_surfaces_are_refused_on_every_basis() {
        for basis in [
            Basis::Ownership,
            Basis::WrittenConsent,
            Basis::SelfHosted,
            Basis::PublicReadOnly,
        ] {
            let r = register_with(vec![entry("owned.example", basis, None)]);
            for path in ["/account/orders", "/login", "/api/v1/tokens", "/admin"] {
                let url = format!("https://owned.example{path}");
                let d = r.authorize(&url, "GET", T);
                assert!(
                    matches!(d.refusal(), Some(Refusal::AuthenticationSurface { .. })),
                    "basis {} path {} should be refused, got {}",
                    basis.as_str(),
                    path,
                    d.render()
                );
            }
        }
    }

    #[test]
    fn credentials_in_the_url_are_refused() {
        let r = register_with(vec![entry("owned.example", Basis::Ownership, None)]);
        let d = r.authorize("https://user:pass@owned.example/", "GET", T);
        assert!(matches!(
            d.refusal(),
            Some(Refusal::AuthenticationSurface { .. })
        ));
    }

    #[test]
    fn method_outside_the_grant_is_refused() {
        let r = register_with(vec![entry("owned.example", Basis::Ownership, None)]);
        let d = r.authorize("https://owned.example/", "POST", T);
        assert!(matches!(
            d.refusal(),
            Some(Refusal::MethodNotAllowed { .. })
        ));
        assert!(r.authorize("https://owned.example/", "HEAD", T).is_allowed());
    }

    #[test]
    fn connect_grant_authorizes_connect_on_that_host() {
        let dir = std::env::temp_dir().join("tallow-scope-test-connect-grant");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("register.toml");
        std::fs::write(
            &p,
            r#"
[[authorized]]
host = "scan.example"
basis = "ownership"
granted_by = "operator"
granted_at = "2026-01-01"
expires_at = "2027-01-01"
methods = ["CONNECT"]
"#,
        )
        .expect("write");
        let r = ScopeRegister::load(&p);
        assert_eq!(
            r.load_failure(),
            None,
            "CONNECT is a grantable verb, got {:?}",
            r.load_failure().map(Refusal::explain)
        );
        let d = r.authorize("scan.example", "CONNECT", T);
        assert!(d.is_allowed(), "{}", d.render());
        // A CONNECT-only grant does not imply HTTP reads.
        assert!(matches!(
            r.authorize("scan.example", "GET", T).refusal(),
            Some(Refusal::MethodNotAllowed { .. })
        ));
    }

    #[test]
    fn shipped_loopback_refuses_connect() {
        let r = ScopeRegister::load(DEFAULT_REGISTER_PATH);
        assert_eq!(
            r.load_failure(),
            None,
            "shipped register must parse, got {:?}",
            r.load_failure().map(Refusal::explain)
        );
        let d = r.authorize("127.0.0.1", "CONNECT", T);
        assert!(
            matches!(d.refusal(), Some(Refusal::MethodNotAllowed { .. })),
            "shipped loopback must not grant CONNECT, got {}",
            d.render()
        );
        // Vocabulary change must not silently widen the default GET/HEAD grant.
        assert!(
            r.authorize("127.0.0.1", "GET", T).is_allowed(),
            "shipped loopback GET must still be allowed"
        );
        assert!(
            r.authorize("127.0.0.1", "HEAD", T).is_allowed(),
            "shipped loopback HEAD must still be allowed"
        );
    }

    #[test]
    fn wildcard_covers_subdomains_but_not_the_apex() {
        let r = register_with(vec![entry("*.owned.example", Basis::Ownership, None)]);
        assert!(r
            .authorize("https://api.owned.example/", "GET", T)
            .is_allowed());
        // The apex is a different owner until proven otherwise.
        let d = r.authorize("https://owned.example/", "GET", T);
        assert!(matches!(d.refusal(), Some(Refusal::NotListed { .. })));
        // Not a suffix match on a lookalike domain.
        let d = r.authorize("https://evil-owned.example/", "GET", T);
        assert!(matches!(d.refusal(), Some(Refusal::NotListed { .. })));
    }

    #[test]
    fn bare_host_and_port_are_accepted() {
        let r = register_with(vec![entry("127.0.0.1", Basis::SelfHosted, None)]);
        assert!(r.authorize("127.0.0.1:8080", "GET", T).is_allowed());
        assert!(r.authorize("http://127.0.0.1:8080/health", "GET", T).is_allowed());
    }

    #[test]
    fn hostless_input_is_refused_as_malformed() {
        let r = register_with(vec![entry("owned.example", Basis::Ownership, None)]);
        let d = r.authorize("   ", "GET", T);
        assert!(matches!(d.refusal(), Some(Refusal::HostMalformed { .. })));
    }

    #[test]
    fn refusal_codes_are_stable() {
        assert_eq!(Refusal::NotListed { host: "x".into() }.code(), "scope:not-listed");
        assert_eq!(
            Refusal::AuthenticationSurface {
                host: "x".into(),
                path: "/login".into()
            }
            .code(),
            "scope:authentication-surface"
        );
    }

    fn load_toml(name: &str, body: &str) -> ScopeRegister {
        let dir = std::env::temp_dir().join(format!("tallow-scope-test-{name}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("register.toml");
        std::fs::write(&p, body).expect("write");
        ScopeRegister::load(&p)
    }

    #[test]
    fn connect_is_a_grantable_method() {
        let r = load_toml(
            "connect",
            r#"
[[authorized]]
host = "127.0.0.1"
basis = "self-hosted"
granted_by = "test"
granted_at = "2026-01-01"
methods = ["CONNECT"]
"#,
        );
        assert!(
            r.load_failure().is_none(),
            "CONNECT must load: {:?}",
            r.load_failure()
        );
        assert!(r.authorize("127.0.0.1", "CONNECT", T).is_allowed());
        // A CONNECT grant does not smuggle GET.
        assert!(matches!(
            r.authorize("127.0.0.1", "GET", T).refusal(),
            Some(Refusal::MethodNotAllowed { .. })
        ));
    }

    #[test]
    fn unknown_method_makes_the_register_malformed() {
        let r = load_toml(
            "unknown-method",
            r#"
[[authorized]]
host = "owned.example"
basis = "ownership"
granted_by = "test"
granted_at = "2026-01-01"
methods = ["FROBNICATE"]
"#,
        );
        assert!(matches!(
            r.load_failure(),
            Some(Refusal::RegisterMalformed { .. })
        ));
        assert!(!r.authorize("https://owned.example/", "GET", T).is_allowed());
    }

    #[test]
    fn in_memory_register_does_not_weaken_authorize() {
        let r = ScopeRegister::granting(&[("listed.test", &["GET"])]);
        assert!(r.authorize("listed.test", "GET", T).is_allowed());
        assert!(matches!(
            r.authorize("other.test", "GET", T).refusal(),
            Some(Refusal::NotListed { .. })
        ));

        let mut e = entry("expired.test", Basis::SelfHosted, Some("2020-06-01"));
        e.methods = vec!["GET".to_string()];
        let r = ScopeRegister::from_entries(vec![e]);
        assert!(matches!(
            r.authorize("expired.test", "GET", T).refusal(),
            Some(Refusal::Expired { .. })
        ));
    }

    #[test]
    fn require_consults_thread_local_before_default() {
        // Shipped register lists 127.0.0.1 for GET/HEAD, not CONNECT.
        let denied = require("127.0.0.1", "CONNECT");
        assert!(
            matches!(denied, Err(Refusal::MethodNotAllowed { .. })),
            "default register must still refuse CONNECT: {denied:?}"
        );

        let _g = override_register(ScopeRegister::granting(&[("127.0.0.1", &["CONNECT"])]));
        assert!(require("127.0.0.1", "CONNECT").is_ok());
        assert!(matches!(
            require("not-in-the-grant.test", "GET"),
            Err(Refusal::NotListed { .. })
        ));
    }

    #[test]
    fn override_does_not_leak_to_other_threads() {
        let _g = override_register(ScopeRegister::granting(&[("only-here.test", &["GET"])]));
        assert!(require("only-here.test", "GET").is_ok());
        let other = std::thread::spawn(|| require("only-here.test", "GET"))
            .join()
            .expect("join");
        assert!(
            matches!(other, Err(Refusal::NotListed { .. })),
            "other thread must not see this thread's grant: {other:?}"
        );
    }

    #[test]
    fn test_seam_source_is_cfg_test_gated() {
        let src = include_str!("scope.rs");
        assert!(
            src.contains("#[cfg(not(test))]\nconst TEST_REGISTER_OVERRIDE_ABSENT"),
            "non-test build must name the absence of the override cell"
        );
        assert!(
            src.contains("#[cfg(test)]\nthread_local!"),
            "override cell must sit under cfg(test)"
        );
        // Ignore the tests module so string literals here cannot be mistaken
        // for uses of the cell.
        let prod = src.split("#[cfg(test)]\nmod tests").next().unwrap();
        let lines: Vec<&str> = prod.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("TEST_REGISTER") && !line.contains("TEST_REGISTER_OVERRIDE_ABSENT") {
                let start = i.saturating_sub(11);
                let window = lines[start..=i].join("\n");
                assert!(
                    window.contains("#[cfg(test)]"),
                    "override cell on line {} is not under cfg(test):\n{window}",
                    i + 1
                );
            }
        }
    }
}
