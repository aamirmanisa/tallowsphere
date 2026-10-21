//! `tallow fingerprint-audit` — OFFLINE fingerprint audit CLI (matrix row #209;
//! report ag03 R-2 audit CLI).
//!
//! Dumps the client fingerprint surface Tallow would present, with every
//! section's provenance stated explicitly (nothing is captured from the wire,
//! nothing is invented):
//!
//! 1. **JA4 (tcp + quic)** — real: computed from the ClientHello the code
//!    actually builds (`crates/tallow-net/src/transport/tls_cohort.rs`,
//!    `ja4_cohort_v1`), i.e. the current/default transport TLS configuration.
//! 2. **JA4 (browser profile) + JA4H** — from the stdlib TLS profile selected
//!    with `--profile` (default `chrome_131`, the stdlib default). The JA4H is
//!    a render of Tallow's *declared* navigation header set for that profile
//!    (canonical header order documented below); it is not a wire capture and
//!    says so in the output.
//! 3. **Browser attribute coherence** — internal cross-vector checks
//!    (`FingerprintValidator`) plus network-context coherence
//!    (`CoherenceValidator`, TLS↔UA/Client-Hints family included) run against
//!    the selected `StealthProfile` (default `chrome_windows`). Runs with an
//!    empty GeoContext (geo-only checks skip; the report says so).
//! 4. **JA4T** — *derived* from the local kernel TCP configuration
//!    (`/proc/sys/net/ipv4/*` + interface MTU) using a documented model of the
//!    Linux SYN option layout. Explicitly "not observed on wire"; reports
//!    `unavailable` (never a fake value) when the sysctl root is unreadable.
//! 5. **cohort-k** — k-anonymity-style exact-match count for the selected
//!    profile's key (default: its JA4) within a **user-provided** profile set
//!    (`--cohort <file>`). Without a dataset the audit reports `k undefined` —
//!    it never fabricates population statistics (there is no population
//!    dataset in-repo).
//! 6. **Egress** — reports the resolved egress-contract proxy
//!    (`TALLOW_PROXY` / `TALLOW_TOR` via `runtime::egress_http::proxy_url`).
//!    `--tor-check` only TCP-probes the resolved/local SOCKS port for
//!    reachability; it sends no application data. Any Tor-routed fetch must
//!    use `socks5h://` per the egress contract — this command performs no
//!    fetches at all.
//!
//! JA4H/JA4T formatting follows the FoxIO JA4+ reference (spec + golden
//! vectors used as unit tests): `JA4H = abc_def_ghi_jkl` with
//! `a` = method(2) · version(2: 10/11/20/30) · cookie c/n · referer r/n ·
//! header count (2, excluding pseudo/cookie/referer) · primary Accept-Language
//! (4, lowercased, dashes stripped, zero-padded); `b` = sha256[:12] of header
//! names in order; `c` = sha256[:12] of sorted cookie *names*; `d` =
//! sha256[:12] of sorted `name=value` cookie pairs (c/d are 12 zeros when no
//! Cookie header). `JA4T = window_options_mss_wscale` (option kinds joined by
//! `-`, empty → `00`; mss zero-padded; wscale `00` when 0).
//!
//! Canonical declared navigation header order (JA4H render, per family — the
//! values are Tallow's declared set for the profile, the order is fixed here
//! so audits are reproducible):
//! - Chromium (chrome_*/edge_*): Sec-Ch-Ua, Sec-Ch-Ua-Mobile,
//!   Sec-Ch-Ua-Platform, Upgrade-Insecure-Requests, User-Agent, Accept,
//!   Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest,
//!   Accept-Encoding, Accept-Language.
//! - Firefox (firefox_*): User-Agent, Accept, Accept-Language,
//!   Accept-Encoding, Upgrade-Insecure-Requests, Sec-Fetch-Dest,
//!   Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User.
//! - Safari (safari_*): Accept, Sec-Fetch-Site, Sec-Fetch-Dest,
//!   Sec-Fetch-Mode, User-Agent, Accept-Language, Accept-Encoding.
//!
//! Usage / flags: see [`print_help`]. Exit codes: `0` audit ran, no critical
//! findings · `2` critical findings · `64` usage error · `1` invalid input or
//! runtime error (unknown profile/dataset, unreadable file).

use std::fmt::Write as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::browser::fingerprint_coherence::{
    CoherenceReport, CoherenceValidator, GeoContext, TlsBrowser,
};
use crate::browser::fingerprint_validator::{FingerprintValidator, FingerprintWarning, Severity};
use crate::browser::stealth::StealthProfile;
use crate::interp::Value;
use tallow_net::transport::tls_cohort::{ja4_cohort_v1, Ja4Transport};

/// Stable schema tag for `--format json` output.
pub const AUDIT_SCHEMA: &str = "tallow.fingerprint_audit.v1";
/// Default stdlib TLS profile (matches `tls_profile::get` default).
pub const DEFAULT_TLS_PROFILE: &str = "chrome_131";
/// Default stealth/browser profile preset.
pub const DEFAULT_BROWSER_PROFILE: &str = "chrome_windows";
/// Default cohort dataset key field.
pub const DEFAULT_COHORT_KEY: &str = "ja4";
/// Cohort verdict threshold: exact-match k below this is "low".
pub const LOW_K_THRESHOLD: u64 = 5;

const EXIT_OK: i32 = 0;
const EXIT_RUNTIME: i32 = 1;
const EXIT_CRITICAL: i32 = 2;
const EXIT_USAGE: i32 = 64;

// Accepted navigation header values (declared set — see module docs).
const ACCEPT_CHROMIUM: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const ACCEPT_FIREFOX: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const ACCEPT_SAFARI: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const ACCEPT_ENCODING_CHROMIUM: &str = "gzip, deflate, br, zstd";
const ACCEPT_ENCODING_FIREFOX: &str = "gzip, deflate, br, zstd";
const ACCEPT_ENCODING_SAFARI: &str = "gzip, deflate, br";

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditArgs {
    pub tls_profile: String,
    pub browser_profile: String,
    pub cohort: Option<PathBuf>,
    pub cohort_key: String,
    pub key_value: Option<String>,
    pub format: OutputFormat,
    pub method: String,
    pub with_referer: bool,
    pub cookie: Option<String>,
    pub sysctl_root: PathBuf,
    pub mtu: Option<u16>,
    pub tor_check: bool,
    /// P1 C2: run only the cross-config coherence check against the effective
    /// browser configuration and exit (0 clean / 2 findings).
    pub coherence: bool,
}

impl Default for AuditArgs {
    fn default() -> Self {
        Self {
            tls_profile: DEFAULT_TLS_PROFILE.to_string(),
            browser_profile: DEFAULT_BROWSER_PROFILE.to_string(),
            cohort: None,
            cohort_key: DEFAULT_COHORT_KEY.to_string(),
            key_value: None,
            format: OutputFormat::Text,
            method: "GET".to_string(),
            with_referer: false,
            cookie: None,
            sysctl_root: PathBuf::from("/proc/sys"),
            mtu: None,
            tor_check: false,
            coherence: false,
        }
    }
}

/// Parse `args` (everything after `fingerprint-audit`). `Ok(None)` = help was
/// printed and the command should exit 0.
pub fn parse_args(args: &[String]) -> Result<Option<AuditArgs>, String> {
    let mut out = AuditArgs::default();
    let mut i = 0;

    // `take` supports both `--flag value` and `--flag=value` (the inline form
    // is split off the flag token before dispatch).
    let take =
        |flag: &str, inline: &Option<String>, args: &[String], i: &mut usize| -> Result<String, String> {
            if let Some(v) = inline {
                return Ok(v.clone());
            }
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag `{flag}` requires a value"))
        };

    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (args[i].clone(), None),
        };
        match flag.as_str() {
            "-h" | "--help" | "help" => return Ok(None),
            "--profile" | "--tls-profile" => {
                out.tls_profile = take("--profile", &inline, args, &mut i)?
            }
            "--browser" | "--browser-profile" => {
                out.browser_profile = take("--browser", &inline, args, &mut i)?
            }
            "--cohort" => out.cohort = Some(PathBuf::from(take("--cohort", &inline, args, &mut i)?)),
            "--cohort-key" => out.cohort_key = take("--cohort-key", &inline, args, &mut i)?,
            "--key-value" => out.key_value = Some(take("--key-value", &inline, args, &mut i)?),
            "--format" => {
                out.format = match take("--format", &inline, args, &mut i)?.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => {
                        return Err(format!(
                            "unknown --format `{other}` (expected `text` or `json`)"
                        ))
                    }
                }
            }
            "--json" => out.format = OutputFormat::Json,
            "--method" => out.method = take("--method", &inline, args, &mut i)?,
            "--with-referer" => out.with_referer = true,
            "--cookie" => out.cookie = Some(take("--cookie", &inline, args, &mut i)?),
            "--sysctl-root" => {
                out.sysctl_root = PathBuf::from(take("--sysctl-root", &inline, args, &mut i)?)
            }
            "--mtu" => {
                let v = take("--mtu", &inline, args, &mut i)?;
                out.mtu = Some(
                    v.parse::<u16>()
                        .map_err(|_| format!("--mtu expects a number, got `{v}`"))?,
                );
            }
            "--tor-check" => out.tor_check = true,
            "--coherence" | "--config-coherence" => out.coherence = true,
            other if other.starts_with('-') => {
                return Err(format!(
                    "unknown flag `{other}`;\nusage: tallow fingerprint-audit [--profile <p>] \
                     [--browser <p>] [--cohort <file>] [--format text|json] [--tor-check]"
                ));
            }
            other => {
                return Err(format!(
                    "fingerprint-audit takes no positional arguments (got `{other}`); \
                     see `tallow fingerprint-audit --help`"
                ));
            }
        }
        i += 1;
    }
    Ok(Some(out))
}

/// Run the `tallow fingerprint-audit` subcommand (`args` is everything after
/// `fingerprint-audit`). Returns the process exit code — see module docs.
pub fn run_fingerprint_audit_args(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(Some(p)) => p,
        Ok(None) => {
            print_help();
            return EXIT_OK;
        }
        Err(e) => {
            eprintln!("fingerprint-audit: {e}");
            return EXIT_USAGE;
        }
    };

    // P1 C2: the cross-config coherence mode short-circuits the JA4 render —
    // it checks the *effective browser configuration* (the values the run
    // path resolves from ~/.tallow/browser/config/*.toml) and fails loud.
    if parsed.coherence {
        return run_coherence_check(parsed.format);
    }

    match collect_report(&parsed) {
        Ok(report) => {
            match parsed.format {
                OutputFormat::Text => println!("{}", report.render_text()),
                OutputFormat::Json => match report.to_json() {
                    Ok(j) => println!("{j}"),
                    Err(e) => {
                        eprintln!("fingerprint-audit: json render failed: {e}");
                        return EXIT_RUNTIME;
                    }
                },
            }
            report.exit_code()
        }
        Err(e) => {
            eprintln!("fingerprint-audit: {e}");
            EXIT_RUNTIME
        }
    }
}

/// P1 C2: run the cross-config coherence check against the *effective* browser
/// configuration (the values the run path resolves from
/// `~/.tallow/browser/config/*.toml`) and print every finding.
///
/// Fail-loud contract: any finding → exit 2 (this is the check the battery and
/// `scripts/check_coherence.sh` gate on); clean → 0.
fn run_coherence_check(format: OutputFormat) -> i32 {
    use crate::browser::fingerprint_coherence::{
        EffectiveConfigSnapshot, check_effective_config,
    };
    use crate::browser::fingerprint_validator::Severity;

    let cfg = crate::browser::config::BrowserFullConfig::load();
    let snapshot = EffectiveConfigSnapshot {
        profile: cfg.stealth.to_stealth_profile(),
        tor_isolate_by_domain: Some(cfg.tor.isolation.isolate_by_domain),
        block_third_party: Some(cfg.session.cookies.block_third_party),
        expect_utc: true,
    };
    let report = check_effective_config(&snapshot);
    let config_dir = crate::browser::config::BrowserFullConfig::config_dir();

    match format {
        OutputFormat::Json => {
            let findings: Vec<serde_json::Value> = report
                .warnings
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "severity": match w.severity {
                            Severity::Critical => "critical",
                            Severity::Warning => "warning",
                            Severity::Info => "info",
                        },
                        "vectors": w.vectors,
                        "message": w.message,
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "schema": "tallow.config_coherence.v1",
                "check": "effective_config_coherence",
                "status": if report.warnings.is_empty() { "PASS" } else { "FAIL" },
                "config_dir": config_dir.display().to_string(),
                "critical_count": report.critical_count,
                "warning_count": report.warning_count,
                "score": report.score,
                "findings": findings,
            });
            match serde_json::to_string_pretty(&doc) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("fingerprint-audit: coherence json render failed: {e}");
                    return EXIT_RUNTIME;
                }
            }
        }
        OutputFormat::Text => {
            println!("── Effective-config coherence (P1 C2) ──");
            println!("config dir: {}", config_dir.display());
            if report.warnings.is_empty() {
                println!("COHERENCE OK — 0 findings");
            } else {
                for w in &report.warnings {
                    let sev = match w.severity {
                        Severity::Critical => "CRITICAL",
                        Severity::Warning => "WARNING",
                        Severity::Info => "INFO",
                    };
                    println!("[{sev}] {}: {}", w.vectors.join(" ↔ "), w.message);
                }
                println!(
                    "COHERENCE FINDINGS: {} (critical {} / warning {} / info {})",
                    report.warnings.len(),
                    report.critical_count,
                    report.warning_count,
                    report.info_count
                );
            }
        }
    }

    if report.warnings.is_empty() {
        EXIT_OK
    } else {
        EXIT_CRITICAL
    }
}

fn print_help() {
    println!(
        "tallow fingerprint-audit — offline fingerprint audit (JA4/JA4H/JA4T + coherence + cohort-k)\n\
         \n\
         Usage:\n\
           tallow fingerprint-audit [OPTIONS]\n\
         \n\
         Options:\n\
           --profile <name>      stdlib TLS profile for the JA4/JA4H render\n\
                                 (default {DEFAULT_TLS_PROFILE}; {DEFAULT_TLS_PROFILE}, firefox_132, safari_18, edge_131)\n\
           --browser <name>      StealthProfile preset for attribute coherence\n\
                                 (default {DEFAULT_BROWSER_PROFILE}; chrome_windows, chrome_macos, chrome_linux,\n\
                                 mobile_android, mobile_ios)\n\
           --cohort <file>       cohort dataset: JSON array of strings/objects, or\n\
                                 one key per line ('#' comments allowed)\n\
           --cohort-key <field>  object field used as the cohort key (default {DEFAULT_COHORT_KEY})\n\
           --key-value <value>   override the cohort target key (default: the selected profile's JA4)\n\
           --method <M>          HTTP method for the JA4H render (default GET)\n\
           --cookie <str>        render JA4H as if this Cookie header were sent\n\
           --with-referer        render JA4H as if a Referer header were sent\n\
           --format text|json    output format (default text); --json is an alias\n\
           --sysctl-root <dir>   sysctl root for the derived JA4T (default /proc/sys)\n\
           --mtu <n>             MTU override for the derived JA4T MSS\n\
           --tor-check           TCP-probe the resolved/local SOCKS port (no data sent)\n\
           --coherence           run ONLY the effective-config coherence check\n\
                                 (P1 C2; fails loud per finding; exit 0/2)\n\
           -h, --help            show this help\n\
         \n\
         Output provenance (offline; nothing is captured from the wire):\n\
           JA4 tcp/quic  real  — from the code-built ClientHello (tls_cohort)\n\
           JA4/JA4H      declared — stdlib profile + canonical navigation headers\n\
           JA4T          derived — local kernel TCP config model (labeled, never faked)\n\
           cohort-k      exact-match count within YOUR dataset; undefined without one\n\
         \n\
         Exit codes: 0 = no critical findings; 2 = critical findings;\n\
                     64 = usage error; 1 = invalid input / runtime error."
    );
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProfileDump {
    pub name: String,
    pub ja4: String,
    pub user_agent: String,
    pub tls_version: String,
    pub family: &'static str,
    pub supports_h2: bool,
    pub grease: bool,
    pub cipher_count: i128,
    pub curl_args: String,
}

#[derive(Debug, Clone)]
pub struct Ja4hDump {
    pub ja4h: String,
    pub method: String,
    pub version_code: String,
    pub cookie: bool,
    pub referer: bool,
    pub header_count: usize,
    pub language: String,
    /// Header names in rendered order (the JA4H hash input, after filtering).
    pub headers: Vec<String>,
    pub provenance: String,
}

#[derive(Debug, Clone)]
pub struct Ja4TransportDump {
    pub transport: &'static str,
    pub ja4: Option<String>,
    pub ja4_a: Option<String>,
    pub ja4_b: Option<String>,
    pub ja4_c: Option<String>,
    pub tls13_offered: Option<bool>,
    pub cipher_count: Option<usize>,
    pub ext_count: Option<usize>,
    pub report: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Ja4tDump {
    /// `derived` | `unavailable`.
    pub state: &'static str,
    pub ja4t: Option<String>,
    pub window: Option<u64>,
    pub options: Vec<u8>,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    /// (source path/label, value read) pairs.
    pub sources: Vec<(String, String)>,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct CohortEstimate {
    /// `undefined` | `computed`.
    pub state: &'static str,
    pub k: Option<u64>,
    pub dataset_size: Option<u64>,
    pub distinct: Option<u64>,
    pub key_field: String,
    pub target: String,
    pub share: Option<f64>,
    /// `undefined` | `absent` | `unique` | `low` | `adequate`.
    pub verdict: &'static str,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct EgressDump {
    pub resolved: Option<String>,
    pub tor_check: &'static str,
    pub endpoint: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct AuditWarning {
    pub severity: &'static str,
    pub vectors: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub profile: ProfileDump,
    pub ja4h: Ja4hDump,
    pub tls_tcp: Ja4TransportDump,
    pub tls_quic: Ja4TransportDump,
    pub browser_profile: String,
    pub warnings: Vec<AuditWarning>,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub score: f64,
    pub ja4t: Ja4tDump,
    pub cohort: CohortEstimate,
    pub egress: EgressDump,
}

impl AuditReport {
    pub fn exit_code(&self) -> i32 {
        if self.critical_count > 0 {
            EXIT_CRITICAL
        } else {
            EXIT_OK
        }
    }

    pub fn to_json(&self) -> Result<String, String> {
        let warnings: Vec<serde_json::Value> = self
            .warnings
            .iter()
            .map(|w| {
                serde_json::json!({
                    "severity": w.severity,
                    "vectors": w.vectors,
                    "message": w.message,
                })
            })
            .collect();
        let sources: Vec<serde_json::Value> = self
            .ja4t
            .sources
            .iter()
            .map(|(k, v)| serde_json::json!({"source": k, "value": v}))
            .collect();
        let doc = serde_json::json!({
            "schema": AUDIT_SCHEMA,
            "profile": {
                "name": self.profile.name,
                "family": self.profile.family,
                "ja4": self.profile.ja4,
                "user_agent": self.profile.user_agent,
                "tls_version": self.profile.tls_version,
                "supports_h2": self.profile.supports_h2,
                "grease": self.profile.grease,
                "cipher_count": self.profile.cipher_count as i64,
                "curl_args": self.profile.curl_args,
            },
            "ja4h": {
                "ja4h": self.ja4h.ja4h,
                "method": self.ja4h.method,
                "version": self.ja4h.version_code,
                "cookie": self.ja4h.cookie,
                "referer": self.ja4h.referer,
                "header_count": self.ja4h.header_count,
                "language": self.ja4h.language,
                "headers": self.ja4h.headers,
                "provenance": self.ja4h.provenance,
            },
            "tls_config": {
                "tcp": transport_json(&self.tls_tcp),
                "quic": transport_json(&self.tls_quic),
            },
            "browser": {
                "profile": self.browser_profile,
                "critical_count": self.critical_count,
                "warning_count": self.warning_count,
                "info_count": self.info_count,
                "score": self.score,
                "warnings": warnings,
            },
            "ja4t": {
                "state": self.ja4t.state,
                "ja4t": self.ja4t.ja4t,
                "window": self.ja4t.window,
                "options": self.ja4t.options,
                "mss": self.ja4t.mss,
                "wscale": self.ja4t.wscale,
                "sources": sources,
                "note": self.ja4t.note,
            },
            "cohort_k": {
                "state": self.cohort.state,
                "k": self.cohort.k,
                "dataset_size": self.cohort.dataset_size,
                "distinct": self.cohort.distinct,
                "key_field": self.cohort.key_field,
                "target": self.cohort.target,
                "share": self.cohort.share,
                "verdict": self.cohort.verdict,
                "note": self.cohort.note,
            },
            "egress": {
                "resolved": self.egress.resolved,
                "tor_check": self.egress.tor_check,
                "endpoint": self.egress.endpoint,
                "note": self.egress.note,
            },
            "verdict": {
                "critical_count": self.critical_count,
                "exit_code": self.exit_code(),
            },
        });
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
    }

    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "tallow fingerprint-audit — schema {}", AUDIT_SCHEMA);
        let _ = writeln!(s);

        // ── TLS configuration (real) ──
        let _ = writeln!(
            s,
            "── TLS configuration (current code-built client hello) ──"
        );
        for t in [&self.tls_tcp, &self.tls_quic] {
            match (&t.ja4, &t.error) {
                (Some(ja4), _) => {
                    let _ = writeln!(
                        s,
                        "{:>4} : ja4={ja4}  (tls13={}, ciphers={}, extensions={})",
                        t.transport,
                        t.tls13_offered.unwrap_or(false),
                        t.cipher_count.unwrap_or(0),
                        t.ext_count.unwrap_or(0),
                    );
                }
                (None, Some(e)) => {
                    let _ = writeln!(s, "{:>4} : unavailable — {e}", t.transport);
                }
                _ => {
                    let _ = writeln!(s, "{:>4} : unavailable", t.transport);
                }
            }
        }
        let _ = writeln!(s);

        // ── Profile + JA4H (declared) ──
        let _ = writeln!(
            s,
            "── Profile (stdlib TLS) + JA4H (declared navigation render) ──"
        );
        let _ = writeln!(
            s,
            "profile : {} ({})  ja4={}  h2={}  grease={}  tls={}",
            self.profile.name,
            self.profile.family,
            self.profile.ja4,
            self.profile.supports_h2,
            self.profile.grease,
            self.profile.tls_version,
        );
        let _ = writeln!(
            s,
            "ja4h    : {}  [method={} version={} cookie={} referer={} headers={} lang={}]",
            self.ja4h.ja4h,
            self.ja4h.method,
            self.ja4h.version_code,
            if self.ja4h.cookie { "c" } else { "n" },
            if self.ja4h.referer { "r" } else { "n" },
            self.ja4h.header_count,
            self.ja4h.language,
        );
        let _ = writeln!(s, "headers : {}", self.ja4h.headers.join(", "));
        let _ = writeln!(s, "note    : {}", self.ja4h.provenance);
        let _ = writeln!(s);

        // ── Browser coherence ──
        let _ = writeln!(s, "── Browser attribute coherence (offline) ──");
        let _ = writeln!(
            s,
            "browser : {}  score={:.2}  critical={} warning={} info={}",
            self.browser_profile,
            self.score,
            self.critical_count,
            self.warning_count,
            self.info_count,
        );
        if self.warnings.is_empty() {
            let _ = writeln!(s, "checks  : all coherent (no findings)");
        } else {
            for w in &self.warnings {
                let _ = writeln!(
                    s,
                    "[{:>8}] ({}) {}",
                    w.severity,
                    w.vectors.join(", "),
                    w.message
                );
            }
        }
        let _ = writeln!(s);

        // ── JA4T (derived) ──
        let _ = writeln!(s, "── JA4T (derived from local kernel config) ──");
        match &self.ja4t.ja4t {
            Some(ja4t) => {
                let _ = writeln!(
                    s,
                    "ja4t    : {ja4t}  [window={} options={} mss={} wscale={}]",
                    self.ja4t.window.unwrap_or(0),
                    self.ja4t
                        .options
                        .iter()
                        .map(|o| o.to_string())
                        .collect::<Vec<_>>()
                        .join("-"),
                    self.ja4t.mss.unwrap_or(0),
                    self.ja4t.wscale.unwrap_or(0),
                );
            }
            None => {
                let _ = writeln!(s, "ja4t    : unavailable");
            }
        }
        for (k, v) in &self.ja4t.sources {
            let _ = writeln!(s, "source  : {k} = {v}");
        }
        let _ = writeln!(s, "note    : {}", self.ja4t.note);
        let _ = writeln!(s);

        // ── Cohort-k ──
        let _ = writeln!(s, "── Cohort-k (user-supplied dataset only) ──");
        match self.cohort.k {
            Some(k) => {
                let _ = writeln!(
                    s,
                    "cohort-k: k={k} of n={} (share={:.2}), key={} target={}",
                    self.cohort.dataset_size.unwrap_or(0),
                    self.cohort.share.unwrap_or(0.0),
                    self.cohort.key_field,
                    self.cohort.target,
                );
            }
            None => {
                let _ = writeln!(s, "cohort-k: undefined (key={})", self.cohort.key_field);
            }
        }
        let _ = writeln!(s, "verdict : {}", self.cohort.verdict);
        let _ = writeln!(s, "note    : {}", self.cohort.note);
        let _ = writeln!(s);

        // ── Egress ──
        let _ = writeln!(s, "── Egress ──");
        match &self.egress.resolved {
            Some(r) => {
                let _ = writeln!(s, "contract: {r}");
            }
            None => {
                let _ = writeln!(s, "contract: direct (no TALLOW_PROXY / TALLOW_TOR)");
            }
        }
        let _ = writeln!(s, "tor     : {}", self.egress.tor_check);
        let _ = writeln!(s, "note    : {}", self.egress.note);
        let _ = writeln!(s);

        let verdict = if self.critical_count > 0 {
            "FAIL (critical findings)"
        } else {
            "PASS"
        };
        let _ = write!(
            s,
            "verdict: {verdict} — critical={} warning={} info={}",
            self.critical_count, self.warning_count, self.info_count
        );
        s
    }
}

fn transport_json(t: &Ja4TransportDump) -> serde_json::Value {
    serde_json::json!({
        "transport": t.transport,
        "ja4": t.ja4,
        "ja4_a": t.ja4_a,
        "ja4_b": t.ja4_b,
        "ja4_c": t.ja4_c,
        "tls13_offered": t.tls13_offered,
        "cipher_count": t.cipher_count,
        "ext_count": t.ext_count,
        "render": t.report,
        "error": t.error,
    })
}

// ---------------------------------------------------------------------------
// JA4 / JA4H / JA4T primitives
// ---------------------------------------------------------------------------

/// `sha256(input)[:12]` hex, or 12 zeros for an empty input — exactly the
/// FoxIO reference `hash12` semantics (JA4H/JA4T segments).
pub fn hash12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_string();
    }
    let digest = Sha256::digest(input.as_bytes());
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// JA4H method code (`GET` → `ge`, …); mirrors the FoxIO reference set.
pub fn method_code(method: &str) -> Result<&'static str, String> {
    Ok(match method.to_ascii_uppercase().as_str() {
        "CONNECT" => "co",
        "DELETE" => "de",
        "GET" => "ge",
        "HEAD" => "he",
        "OPTIONS" => "op",
        "PATCH" => "pa",
        "POST" => "po",
        "PUT" => "pu",
        "TRACE" => "tr",
        other => {
            return Err(format!(
                "unknown HTTP method `{other}` (expected GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/CONNECT/TRACE)"
            ))
        }
    })
}

fn primary_language(language: &str) -> String {
    language
        .trim_start()
        .split(',')
        .next()
        .unwrap_or("")
        .replace('-', "")
        .to_ascii_lowercase()
}

fn truncate_to(n: usize, s: String) -> String {
    if s.len() > n {
        s[..n].to_string()
    } else {
        let mut s = s;
        while s.len() < n {
            s.push('0');
        }
        s
    }
}

/// Sorted cookie segments: (joined names, joined `name=value` pairs).
/// Empty joins for `None` — `hash12` then yields the 12-zero segments.
fn cookie_segments(cookie: Option<&str>) -> (String, String) {
    let Some(raw) = cookie else {
        return (String::new(), String::new());
    };
    let mut pairs: Vec<(String, Option<String>)> = raw
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| match c.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), Some(v.to_string())),
            None => (c.to_string(), None),
        })
        .collect();
    pairs.sort();
    let names = pairs
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>()
        .join(",");
    let joined = pairs
        .iter()
        .map(|(n, v)| match v {
            Some(v) => format!("{n}={v}"),
            None => n.clone(),
        })
        .collect::<Vec<_>>()
        .join(",");
    (names, joined)
}

/// Compute a JA4H fingerprint (FoxIO JA4+ semantics — verified against the
/// reference golden vectors in the tests below).
///
/// `headers` must be the header *names* in wire order; pseudo-headers
/// (`:method`, …), `Cookie` and `Referer` are excluded from the count and the
/// hash (their presence is the c/r markers instead). `cookie` is the raw
/// `Cookie` header value (sorted before hashing). `language` is the raw
/// `Accept-Language` value.
pub fn ja4h(
    method: &str,
    version_code: &str,
    headers: &[String],
    cookie: Option<&str>,
    referer: bool,
    language: Option<&str>,
) -> Result<String, String> {
    let code = method_code(method)?;
    if !matches!(version_code, "10" | "11" | "20" | "30") {
        return Err(format!(
            "unknown HTTP version code `{version_code}` (expected 10|11|20|30)"
        ));
    }
    let kept: Vec<&str> = headers
        .iter()
        .map(|h| h.as_str())
        .filter(|h| {
            !h.is_empty()
                && !h.starts_with(':')
                && !h.eq_ignore_ascii_case("cookie")
                && !h.eq_ignore_ascii_case("referer")
        })
        .collect();
    let nr = kept.len().min(99);
    let lang = truncate_to(4, primary_language(language.unwrap_or("")));
    let (names, pairs) = cookie_segments(cookie);
    Ok(format!(
        "{code}{version_code}{}{}{nr:02}{lang}_{}_{}_{}",
        if cookie.is_some() { 'c' } else { 'n' },
        if referer { 'r' } else { 'n' },
        hash12(&kept.join(",")),
        hash12(&names),
        hash12(&pairs),
    ))
}

/// Browser family for a stdlib TLS profile name.
pub fn family_for_profile(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.starts_with("chrome") {
        "Chrome"
    } else if n.starts_with("edge") {
        "Edge"
    } else if n.starts_with("firefox") {
        "Firefox"
    } else if n.starts_with("safari") {
        "Safari"
    } else {
        "Unknown"
    }
}

/// Map a profile family to the coherence validator's TLS-browser hint.
pub fn tls_browser_for_family(family: &str) -> TlsBrowser {
    match family {
        "Chrome" => TlsBrowser::Chrome,
        "Edge" => TlsBrowser::Edge,
        "Firefox" => TlsBrowser::Firefox,
        "Safari" => TlsBrowser::Safari,
        _ => TlsBrowser::Unknown,
    }
}

// ---------------------------------------------------------------------------
// JA4T (derived)
// ---------------------------------------------------------------------------

/// Derive the host's JA4T from its local kernel TCP configuration.
///
/// This is an explicitly **modeled** value: the advertised SYN window is the
/// Linux initial receive window rounded down to an MSS multiple
/// (`floor(min(65535, tcp_rmem.max) / mss) * mss`), the window scale is the
/// smallest shift whose scaled window covers `tcp_rmem.max` (capped at 14),
/// and the option-kind sequence follows the documented Linux SYN layout
/// (`MSS [NOP WS] [NOP NOP SACK] [NOP NOP TS]`, kinds gated on
/// `tcp_window_scaling` / `tcp_sack` / `tcp_timestamps`). None of it is
/// observed on the wire — the note in the output says so.
pub fn derive_ja4t(sysctl_root: &Path, mtu: Option<u16>) -> Ja4tDump {
    let read = |rel: &str| -> Option<String> {
        std::fs::read_to_string(sysctl_root.join(rel))
            .ok()
            .map(|s| s.trim().to_string())
    };

    let mut sources: Vec<(String, String)> = Vec::new();
    let Some(rmem_raw) = read("net/ipv4/tcp_rmem") else {
        return Ja4tDump {
            state: "unavailable",
            ja4t: None,
            window: None,
            options: Vec::new(),
            mss: None,
            wscale: None,
            sources,
            note: format!(
                "sysctl root {} is not readable — JA4T unavailable (never fabricated)",
                sysctl_root.display()
            ),
        };
    };
    sources.push(("net/ipv4/tcp_rmem".to_string(), rmem_raw.clone()));
    let rmem: Vec<u64> = rmem_raw
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    if rmem.len() != 3 || rmem[2] == 0 {
        return Ja4tDump {
            state: "unavailable",
            ja4t: None,
            window: None,
            options: Vec::new(),
            mss: None,
            wscale: None,
            sources,
            note: "tcp_rmem unparseable — JA4T unavailable (never fabricated)".to_string(),
        };
    }
    let rmem_max = rmem[2];

    let flag = |rel: &str, default: u8| -> (bool, String) {
        match read(rel) {
            Some(v) => {
                let on = v.parse::<u8>().unwrap_or(default) == 1;
                (on, v)
            }
            None => (default == 1, format!("{default} (assumed; file unreadable)")),
        }
    };
    let (scaling, scaling_raw) = flag("net/ipv4/tcp_window_scaling", 1);
    let (timestamps, ts_raw) = flag("net/ipv4/tcp_timestamps", 1);
    let (sack, sack_raw) = flag("net/ipv4/tcp_sack", 1);
    sources.push(("net/ipv4/tcp_window_scaling".to_string(), scaling_raw));
    sources.push(("net/ipv4/tcp_timestamps".to_string(), ts_raw));
    sources.push(("net/ipv4/tcp_sack".to_string(), sack_raw));

    let mtu_val = mtu.unwrap_or(1500);
    let mss = mtu_val.saturating_sub(40);
    sources.push((
        "mtu".to_string(),
        match mtu {
            Some(_) => format!("{mtu_val} (argument)"),
            None => format!("{mtu_val} (default; pass --mtu to override)"),
        },
    ));

    let window = (rmem_max.min(65535) / u64::from(mss)) * u64::from(mss);
    let wscale: u8 = if scaling {
        let mut w = 0u8;
        while w < 14 && (65535u64 << w) < rmem_max {
            w += 1;
        }
        w
    } else {
        0
    };

    let mut options: Vec<u8> = vec![2]; // MSS
    if scaling {
        options.extend_from_slice(&[1, 3]); // NOP, WScale
    }
    if sack {
        options.extend_from_slice(&[1, 1, 4]); // NOP NOP SACK-permitted
    }
    if timestamps {
        options.extend_from_slice(&[1, 1, 8]); // NOP NOP Timestamps
    }

    let opts = if options.is_empty() {
        "00".to_string()
    } else {
        options
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let wscale_seg = if wscale == 0 {
        format!("{wscale:02}")
    } else {
        wscale.to_string()
    };
    let ja4t = format!("{window}_{opts}_{mss:02}_{wscale_seg}");

    Ja4tDump {
        state: "derived",
        ja4t: Some(ja4t),
        window: Some(window),
        options,
        mss: Some(mss),
        wscale: Some(wscale),
        sources,
        note: "derived (modeled) from local kernel TCP configuration — NOT observed on \
               the wire; use a pcap capture to verify the real SYN fingerprint"
            .to_string(),
    }
}

/// Best-effort MTU of the default-route interface (Linux). `None` → callers
/// fall back to the documented 1500 default.
pub fn detect_default_mtu() -> Option<u16> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    let iface = route
        .lines()
        .skip(1)
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 2 && f[1] == "00000000" {
                Some(f[0].to_string())
            } else {
                None
            }
        })?;
    std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Cohort-k
// ---------------------------------------------------------------------------

/// Exact-match k within a supplied dataset. `k` is how many dataset entries
/// share `target` as their key — a k-anonymity-style *distinguishability*
/// count, not a population estimate.
pub fn estimate_cohort_k(target: &str, entries: &[String], key_field: &str) -> CohortEstimate {
    let n = entries.len() as u64;
    let k = entries.iter().filter(|e| e.as_str() == target).count() as u64;
    let distinct = {
        let mut set: Vec<&String> = entries.iter().collect();
        set.sort();
        set.dedup();
        set.len() as u64
    };
    let verdict = if k == 0 {
        "absent"
    } else if k == 1 {
        "unique"
    } else if k < LOW_K_THRESHOLD {
        "low"
    } else {
        "adequate"
    };
    CohortEstimate {
        state: "computed",
        k: Some(k),
        dataset_size: Some(n),
        distinct: Some(distinct),
        key_field: key_field.to_string(),
        target: target.to_string(),
        share: if n == 0 { None } else { Some(k as f64 / n as f64) },
        verdict,
        note: format!(
            "exact-match count within the supplied dataset only (n={n}, distinct keys={distinct}); \
             threshold k<{LOW_K_THRESHOLD} = {}. This is not a population-frequency estimate.",
            if k < LOW_K_THRESHOLD { "low" } else { "adequate" }
        ),
    }
}

/// The honest no-dataset state — k is undefined rather than guessed.
pub fn undefined_cohort(target: &str, key_field: &str) -> CohortEstimate {
    CohortEstimate {
        state: "undefined",
        k: None,
        dataset_size: None,
        distinct: None,
        key_field: key_field.to_string(),
        target: target.to_string(),
        share: None,
        verdict: "undefined",
        note: "no cohort dataset provided (--cohort <file>): there is no population data \
               in-repo, so cohort-k is undefined — the audit never invents statistics. \
               Provide a profile set (JA4 strings or objects) for an exact-match estimate."
            .to_string(),
    }
}

/// Load a cohort dataset: JSON array of strings or objects (key taken from
/// `key_field`, default `ja4`), or a plain-text file with one key per line
/// (`#` comments and blank lines ignored).
pub fn load_cohort(path: &Path, key_field: &str) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read cohort dataset '{}': {e}", path.display()))?;
    if text.trim_start().starts_with('[') {
        let v: serde_json::Value = serde_json::from_str(text.trim())
            .map_err(|e| format!("cohort dataset '{}' is not valid JSON: {e}", path.display()))?;
        let arr = v
            .as_array()
            .ok_or_else(|| "cohort dataset JSON must be an array".to_string())?;
        arr.iter()
            .map(|entry| match entry {
                serde_json::Value::String(s) => Ok(s.clone()),
                serde_json::Value::Object(o) => {
                    o.get(key_field).and_then(|x| x.as_str()).map(str::to_string).ok_or_else(|| {
                        let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
                        keys.sort();
                        format!(
                            "cohort entry has no string field `{key_field}` (available: {})",
                            keys.join(", ")
                        )
                    })
                }
                other => Err(format!(
                    "unsupported cohort entry (expected string or object, got {other})"
                )),
            })
            .collect()
    } else {
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------------

fn neutral_geo() -> GeoContext {
    GeoContext {
        ip: String::new(),
        country_code: String::new(),
        region: String::new(),
        city: String::new(),
        timezone: String::new(),
        latitude: 0.0,
        longitude: 0.0,
        asn: 0,
        asn_org: String::new(),
        is_datacenter: false,
        is_residential: false,
        is_mobile: false,
    }
}

fn struct_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Struct { fields, .. } => fields.iter().find(|(n, _)| n == name).map(|(_, v)| v),
        _ => None,
    }
}

fn field_str(value: &Value, name: &str) -> String {
    match struct_field(value, name) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Int(i)) => i.to_string(),
        _ => String::new(),
    }
}

fn field_bool(value: &Value, name: &str) -> bool {
    matches!(struct_field(value, name), Some(Value::Bool(true)))
}

fn field_int(value: &Value, name: &str) -> i128 {
    match struct_field(value, name) {
        Some(Value::Int(i)) => *i,
        _ => 0,
    }
}

/// Fetch a stdlib TLS profile as an interp `Value` via the module's public
/// dispatcher (no edits to `tls_profile.rs`).
pub fn load_tls_profile(name: &str) -> Result<Value, String> {
    let result = crate::stdlib::tls_profile::dispatch(
        "get",
        vec![Value::String(name.to_string())],
    )
    .ok_or_else(|| "tls_profile::dispatch is unavailable".to_string())?;
    result.map_err(|e| format!("unknown --profile `{name}`: {e}"))
}

fn profile_dump(value: &Value, name: &str) -> ProfileDump {
    let curl_args = crate::stdlib::tls_profile::dispatch_method(value, "to_curl_args", vec![])
        .and_then(|r| r.ok())
        .and_then(|v| match v {
            Value::String(s) => Some(s),
            _ => None,
        })
        .unwrap_or_default();
    ProfileDump {
        name: name.to_string(),
        ja4: field_str(value, "ja4"),
        user_agent: field_str(value, "user_agent"),
        tls_version: field_str(value, "tls_version"),
        family: family_for_profile(name),
        supports_h2: field_bool(value, "supports_h2"),
        grease: field_bool(value, "grease"),
        cipher_count: field_int(value, "cipher_count"),
        curl_args,
    }
}

fn profile_headers(value: &Value) -> Vec<(String, String)> {
    crate::stdlib::tls_profile::dispatch_method(value, "to_headers", vec![])
        .and_then(|r| r.ok())
        .and_then(|v| match v {
            Value::Map(pairs) => Some(
                pairs
                    .into_iter()
                    .filter_map(|(k, v)| match (k, v) {
                        (Value::String(k), Value::String(v)) => Some((k, v)),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// The declared navigation header names for the JA4H render (canonical order
/// per family — see module docs). Returns names only, in order.
pub fn declared_navigation_headers(family: &str) -> Vec<(&'static str, &'static str)> {
    match family {
        "Firefox" => vec![
            ("User-Agent", "@ua"),
            ("Accept", ACCEPT_FIREFOX),
            ("Accept-Language", "@al"),
            ("Accept-Encoding", ACCEPT_ENCODING_FIREFOX),
            ("Upgrade-Insecure-Requests", "1"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
        ],
        "Safari" => vec![
            ("Accept", ACCEPT_SAFARI),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("User-Agent", "@ua"),
            ("Accept-Language", "@al"),
            ("Accept-Encoding", ACCEPT_ENCODING_SAFARI),
        ],
        // Chromium + Edge
        _ => vec![
            ("Sec-Ch-Ua", "@chua"),
            ("Sec-Ch-Ua-Mobile", "@chmobile"),
            ("Sec-Ch-Ua-Platform", "@chplatform"),
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", "@ua"),
            ("Accept", ACCEPT_CHROMIUM),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-User", "?1"),
            ("Sec-Fetch-Dest", "document"),
            ("Accept-Encoding", ACCEPT_ENCODING_CHROMIUM),
            ("Accept-Language", "@al"),
        ],
    }
}

fn build_ja4h(profile_value: &Value, profile: &ProfileDump, args: &AuditArgs) -> Result<Ja4hDump, String> {
    let hdrs = profile_headers(profile_value);
    let mut names: Vec<String> = Vec::new();
    let mut values: Vec<(String, String)> = Vec::new();
    for (name, val) in declared_navigation_headers(profile.family) {
        let resolved = match val {
            "@ua" => Some(
                header_get(&hdrs, "User-Agent").unwrap_or_else(|| profile.user_agent.clone()),
            ),
            "@al" => Some(
                header_get(&hdrs, "Accept-Language")
                    .unwrap_or_else(|| "en-US,en;q=0.9".to_string()),
            ),
            "@chua" => header_get(&hdrs, "Sec-Ch-Ua"),
            "@chmobile" => header_get(&hdrs, "Sec-Ch-Ua-Mobile"),
            "@chplatform" => header_get(&hdrs, "Sec-Ch-Ua-Platform"),
            other => Some(other.to_string()),
        };
        if let Some(v) = resolved {
            names.push(name.to_string());
            values.push((name.to_string(), v));
        }
    }
    let language = values
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Accept-Language"))
        .map(|(_, v)| v.clone());
    let ja4h = ja4h(
        &args.method,
        "20",
        &names,
        args.cookie.as_deref(),
        args.with_referer,
        language.as_deref(),
    )?;
    Ok(Ja4hDump {
        ja4h,
        method: args.method.to_ascii_uppercase(),
        version_code: "20".to_string(),
        cookie: args.cookie.is_some(),
        referer: args.with_referer,
        header_count: names.len(),
        language: truncate_to(4, primary_language(language.as_deref().unwrap_or(""))),
        headers: names,
        provenance: "declared navigation header set for this profile in a canonical order \
                     (offline render, not a wire capture; wreq may add/reorder headers at \
                     the transport layer)"
            .to_string(),
    })
}

fn dump_transport(transport: Ja4Transport) -> Ja4TransportDump {
    let name = match transport {
        Ja4Transport::Tcp => "tcp",
        Ja4Transport::Quic => "quic",
    };
    match ja4_cohort_v1(transport) {
        Ok(c) => Ja4TransportDump {
            transport: name,
            ja4: Some(c.ja4()),
            ja4_a: Some(c.ja4_a.clone()),
            ja4_b: Some(c.ja4_b.clone()),
            ja4_c: Some(c.ja4_c.clone()),
            tls13_offered: Some(c.tls13_offered),
            cipher_count: Some(c.ciphers.len()),
            ext_count: Some(c.extensions.len()),
            report: Some(c.render()),
            error: None,
        },
        Err(e) => Ja4TransportDump {
            transport: name,
            ja4: None,
            ja4_a: None,
            ja4_b: None,
            ja4_c: None,
            tls13_offered: None,
            cipher_count: None,
            ext_count: None,
            report: None,
            error: Some(e),
        },
    }
}

fn stealth_profile(name: &str) -> Result<StealthProfile, String> {
    Ok(match name {
        "chrome_windows" => StealthProfile::chrome_windows(),
        "chrome_macos" => StealthProfile::chrome_macos(),
        "chrome_linux" => StealthProfile::chrome_linux(),
        "mobile_android" => StealthProfile::mobile_android(),
        "mobile_ios" => StealthProfile::mobile_ios(),
        other => {
            return Err(format!(
                "unknown --browser `{other}` (expected chrome_windows, chrome_macos, \
                 chrome_linux, mobile_android, mobile_ios)"
            ))
        }
    })
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

/// Mask userinfo in a proxy URL (may carry credentials).
fn mask_proxy(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_, host)) => format!("{scheme}://***@{host}"),
            None => url.to_string(),
        },
        None => url.to_string(),
    }
}

/// Host:port of a proxy URL (defaults: socks5/socks5h → 9050; http → 80;
/// https → 443).
pub fn proxy_endpoint(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let rest = rest.split_once('@').map(|(_, h)| h).unwrap_or(rest);
    let rest = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => {
            let default = match scheme {
                "socks5" | "socks5h" => 9050,
                "http" => 80,
                "https" => 443,
                _ => return None,
            };
            (rest.to_string(), default)
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

fn build_egress(tor_check: bool) -> EgressDump {
    let resolved = crate::runtime::egress_http::proxy_url();
    if !tor_check {
        return EgressDump {
            resolved: resolved.map(|u| mask_proxy(&u)),
            tor_check: "not_requested",
            endpoint: None,
            note: "no network probe performed (offline audit); any Tor-routed fetch must use \
                   socks5h per the egress contract (TALLOW_PROXY/TALLOW_TOR)"
                .to_string(),
        };
    }
    // Local reachability probe of the SOCKS endpoint only — no application
    // data, no request. Egress never leaves via a non-socks5h path because
    // nothing is fetched at all.
    let endpoint = match resolved.as_deref() {
        Some(url) => proxy_endpoint(url),
        None => Some(("127.0.0.1".to_string(), 9050)),
    };
    let (state, note) = match &endpoint {
        Some((host, port)) => {
            let target = format!("{host}:{port}");
            match target.parse::<std::net::SocketAddr>() {
                Ok(addr) => match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
                    Ok(_) => (
                        "reachable",
                        format!(
                            "TCP connect to {target} succeeded — port is listening. No data was \
                             sent; this audit performs no fetches. Tor-routed traffic must use \
                             socks5h:// per the egress contract."
                        ),
                    ),
                    Err(e) => (
                        "unreachable",
                        format!(
                            "TCP connect to {target} failed ({e}) — the SOCKS port is not \
                             reachable from this host. No data was sent."
                        ),
                    ),
                },
                Err(_) => (
                    "unreachable",
                    format!("endpoint `{target}` is not a direct IP:port (DNS names are never resolved by this audit)"),
                ),
            }
        }
        None => (
            "unreachable",
            "no probe endpoint could be derived (no resolvable proxy URL and no local default)"
                .to_string(),
        ),
    };
    EgressDump {
        resolved: resolved.map(|u| mask_proxy(&u)),
        tor_check: state,
        endpoint: endpoint.map(|(h, p)| format!("{h}:{p}")),
        note,
    }
}

/// Assemble the full audit report for `args`.
pub fn collect_report(args: &AuditArgs) -> Result<AuditReport, String> {
    // STDIN is never touched; every input is a path or an explicit flag.

    let profile_value = load_tls_profile(&args.tls_profile)?;
    let profile = profile_dump(&profile_value, &args.tls_profile);
    let ja4h_dump = build_ja4h(&profile_value, &profile, args)?;

    let tls_tcp = dump_transport(Ja4Transport::Tcp);
    let tls_quic = dump_transport(Ja4Transport::Quic);

    // Browser attribute coherence: internal cross-vector + network-context
    // (empty GeoContext → geo-only checks skip; TLS↔UA family check runs).
    let browser = stealth_profile(&args.browser_profile)?;
    let mut raw_warnings: Vec<FingerprintWarning> = FingerprintValidator::validate(&browser);
    raw_warnings.extend(
        CoherenceValidator::validate(
            &browser,
            &neutral_geo(),
            Some(tls_browser_for_family(profile.family)),
        )
        .warnings,
    );
    let coherence = CoherenceReport::from_warnings(raw_warnings);
    let warnings: Vec<AuditWarning> = coherence
        .warnings
        .iter()
        .map(|w| AuditWarning {
            severity: severity_name(w.severity),
            vectors: w.vectors.iter().map(|v| v.to_string()).collect(),
            message: w.message.clone(),
        })
        .collect();

    let ja4t = derive_ja4t(&args.sysctl_root, args.mtu.or_else(detect_default_mtu));

    let cohort = match &args.cohort {
        Some(path) => {
            let entries = load_cohort(path, &args.cohort_key)?;
            let target = args
                .key_value
                .clone()
                .unwrap_or_else(|| profile.ja4.clone());
            estimate_cohort_k(&target, &entries, &args.cohort_key)
        }
        None => {
            let target = args
                .key_value
                .clone()
                .unwrap_or_else(|| profile.ja4.clone());
            undefined_cohort(&target, &args.cohort_key)
        }
    };

    let egress = build_egress(args.tor_check);

    Ok(AuditReport {
        profile,
        ja4h: ja4h_dump,
        tls_tcp,
        tls_quic,
        browser_profile: args.browser_profile.clone(),
        warnings,
        critical_count: coherence.critical_count,
        warning_count: coherence.warning_count,
        info_count: coherence.info_count,
        score: coherence.score,
        ja4t,
        cohort,
        egress,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // ── JA4H golden vectors (FoxIO JA4+ reference test suite) ──────────────

    #[test]
    fn test_ja4h_foxio_vector_http1() {
        // FoxIO ja4 rust crate, http.rs::test_http_stats_into_out (HTTP/1.1).
        let headers = s(&[
            "Host",
            "Sec-Ch-Ua",
            "Sec-Ch-Ua-Mobile",
            "User-Agent",
            "Sec-Ch-Ua-Platform",
            "Accept",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Dest",
            "Accept-Encoding",
            "Accept-Language",
        ]);
        let cookie = "FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726";
        let got = ja4h("GET", "11", &headers, Some(cookie), true, Some("en-US,en;q=0.9"))
            .expect("ja4h");
        assert_eq!(got, "ge11cr13enus_88d2d584d47f_0f2659b474bf_161698816dab");
    }

    #[test]
    fn test_ja4h_foxio_vector_http2_no_cookies() {
        // FoxIO ja4 rust crate, http.rs::test_http2_pseudo_headers_do_not_affect_ja4h.
        let headers = s(&[
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
        ]);
        let got = ja4h("GET", "20", &headers, None, false, Some("en-US,en;q=0.9")).expect("ja4h");
        assert_eq!(got, "ge20nn12enus_60f823d07c94_000000000000_000000000000");
    }

    #[test]
    fn test_ja4h_method_version_language_mapping() {
        let none = Vec::new();
        // POST → po, HTTP/3 → 30, no language → 0000.
        let got = ja4h("POST", "30", &none, None, false, None).expect("ja4h");
        assert!(got.starts_with("po30nn000000_"), "{got}");
        // Lowercase language tag, dash stripping, zero padding.
        let got = ja4h("get", "20", &none, None, false, Some("de")).expect("ja4h");
        assert!(got.starts_with("ge20nn00de00_"), "{got}");
        // Unknown method rejected.
        assert!(ja4h("BREW", "20", &none, None, false, None).is_err());
        // Unknown version code rejected.
        assert!(ja4h("GET", "99", &none, None, false, None).is_err());
    }

    #[test]
    fn test_ja4h_cookie_sorting_and_freeform_values() {
        // `name` with no '=', multiple '=' inside the value, unsorted input.
        let got = ja4h(
            "GET",
            "11",
            &s(&["Host"]),
            Some("b=2; a=1=x; raw"),
            false,
            Some("en-US"),
        )
        .expect("ja4h");
        // sorted: a=1=x · b=2 · raw → names "a,b,raw"; pairs "a=1=x,b=2,raw"
        let names = hash12("a,b,raw");
        let pairs = hash12("a=1=x,b=2,raw");
        // Marker 5 is the COOKIE flag: `c` when a Cookie header is sent, `n`
        // otherwise (spec above, and `--cookie` renders it at :657-661). A
        // cookie IS passed here (third argument), so the marker is `c`. This
        // expectation previously read `nn`, which contradicted both the input
        // and the sibling `test_ja4h_method_version_language_mapping` (which
        // correctly expects `nn` for `cookie: None`). Only that marker was
        // wrong: every hash below already matched what the code produced.
        assert_eq!(got, format!("ge11cn01enus_{}_", hash12("Host")) + &format!("{names}_{pairs}"));
    }

    #[test]
    fn test_ja4h_header_filtering() {
        // Pseudo-headers, Cookie and Referer never count toward the header
        // number and are never hashed.
        let with_noise = s(&[":method", ":path", "cookie", "Referer", "User-Agent", "Accept"]);
        let clean = s(&["User-Agent", "Accept"]);
        let a = ja4h("GET", "20", &with_noise, None, false, Some("en")).expect("ja4h");
        let b = ja4h("GET", "20", &clean, None, false, Some("en")).expect("ja4h");
        assert_eq!(a, b, "pseudo/cookie/referer headers must be filtered out");
    }

    // ── JA4T ────────────────────────────────────────────────────────────────

    fn fake_sysctl_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let net = dir.path().join("net/ipv4");
        std::fs::create_dir_all(&net).expect("mkdir");
        std::fs::write(net.join("tcp_rmem"), "4096\t131072\t6291456\n").expect("write");
        std::fs::write(net.join("tcp_window_scaling"), "1\n").expect("write");
        std::fs::write(net.join("tcp_timestamps"), "1\n").expect("write");
        std::fs::write(net.join("tcp_sack"), "1\n").expect("write");
        dir
    }

    #[test]
    fn test_ja4t_linux_defaults_model() {
        let dir = fake_sysctl_tree();
        let dump = derive_ja4t(dir.path(), Some(1500));
        assert_eq!(dump.state, "derived");
        // window = floor(min(65535, 6291456)/1460)*1460 = 64240 (44 MSS segments)
        assert_eq!(dump.window, Some(64240));
        // smallest wscale with 65535<<w >= 6291456 → 7
        assert_eq!(dump.wscale, Some(7));
        assert_eq!(dump.mss, Some(1460));
        assert_eq!(dump.options, vec![2, 1, 3, 1, 1, 4, 1, 1, 8]);
        assert_eq!(dump.ja4t.as_deref(), Some("64240_2-1-3-1-1-4-1-1-8_1460_7"));
        assert!(dump.note.contains("NOT observed"));
    }

    #[test]
    fn test_ja4t_scaling_off_and_no_extras() {
        let dir = fake_sysctl_tree();
        std::fs::write(dir.path().join("net/ipv4/tcp_window_scaling"), "0\n").expect("write");
        std::fs::write(dir.path().join("net/ipv4/tcp_timestamps"), "0\n").expect("write");
        std::fs::write(dir.path().join("net/ipv4/tcp_sack"), "0\n").expect("write");
        let dump = derive_ja4t(dir.path(), Some(1500));
        assert_eq!(dump.options, vec![2]);
        assert_eq!(dump.wscale, Some(0));
        assert_eq!(dump.ja4t.as_deref(), Some("64240_2_1460_00"));
    }

    #[test]
    fn test_ja4t_unavailable_when_root_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("no-such-root");
        let dump = derive_ja4t(&missing, Some(1500));
        assert_eq!(dump.state, "unavailable");
        assert_eq!(dump.ja4t, None);
        assert!(dump.note.contains("never fabricated"));
    }

    #[test]
    fn test_ja4t_small_mtu_mss() {
        let dir = fake_sysctl_tree();
        // MTU 1280 → MSS 1240; window = floor(65535/1240)*1240 = 64480.
        let dump = derive_ja4t(dir.path(), Some(1280));
        assert_eq!(dump.mss, Some(1240));
        assert_eq!(dump.window, Some(64480));
    }

    // ── cohort-k ────────────────────────────────────────────────────────────

    #[test]
    fn test_cohort_k_counts_and_verdicts() {
        let entries = s(&["a", "b", "a", "a", "c"]);
        let est = estimate_cohort_k("a", &entries, "ja4");
        assert_eq!(est.state, "computed");
        assert_eq!(est.k, Some(3));
        assert_eq!(est.dataset_size, Some(5));
        assert_eq!(est.distinct, Some(3));
        assert_eq!(est.verdict, "low"); // 3 < LOW_K_THRESHOLD
        assert!((est.share.unwrap() - 0.6).abs() < 1e-9);

        let est = estimate_cohort_k("c", &entries, "ja4");
        assert_eq!(est.k, Some(1));
        assert_eq!(est.verdict, "unique");

        let est = estimate_cohort_k("zz", &entries, "ja4");
        assert_eq!(est.k, Some(0));
        assert_eq!(est.verdict, "absent");

        let many = s(&["x", "x", "x", "x", "x"]);
        let est = estimate_cohort_k("x", &many, "ja4");
        assert_eq!(est.verdict, "adequate"); // 5 >= LOW_K_THRESHOLD
    }

    #[test]
    fn test_cohort_undefined_without_dataset() {
        let est = undefined_cohort("t13d...", "ja4");
        assert_eq!(est.state, "undefined");
        assert_eq!(est.k, None);
        assert_eq!(est.verdict, "undefined");
        assert!(est.note.contains("never invents statistics"));
    }

    #[test]
    fn test_load_cohort_lines_and_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        // plain-text lines with comments/blanks
        let lines = dir.path().join("cohort.txt");
        std::fs::write(&lines, "# comment\n\na1\nb2\n  a1  \n").expect("write");
        let entries = load_cohort(&lines, "ja4").expect("lines");
        assert_eq!(entries, s(&["a1", "b2", "a1"]));

        // JSON array of strings
        let strings = dir.path().join("cohort.json");
        std::fs::write(&strings, r#"["x1","x2","x1"]"#).expect("write");
        assert_eq!(load_cohort(&strings, "ja4").expect("json"), s(&["x1", "x2", "x1"]));

        // JSON array of objects with key field
        let objects = dir.path().join("cohort_obj.json");
        std::fs::write(&objects, r#"[{"ja4":"j1","note":"n"},{"ja4":"j2"}]"#).expect("write");
        assert_eq!(load_cohort(&objects, "ja4").expect("obj"), s(&["j1", "j2"]));

        // Missing key field errors instead of guessing
        assert!(load_cohort(&objects, "ja4h").is_err());

        // Missing file errors
        assert!(load_cohort(&dir.path().join("nope.json"), "ja4").is_err());
    }

    // ── profile / family helpers ────────────────────────────────────────────

    #[test]
    fn test_family_and_tls_browser_mapping() {
        assert_eq!(family_for_profile("chrome_131"), "Chrome");
        assert_eq!(family_for_profile("edge_131"), "Edge");
        assert_eq!(family_for_profile("firefox_132"), "Firefox");
        assert_eq!(family_for_profile("safari_18"), "Safari");
        assert_eq!(family_for_profile("lynx_1"), "Unknown");
        assert_eq!(tls_browser_for_family("Firefox"), TlsBrowser::Firefox);
        assert_eq!(tls_browser_for_family("Chrome"), TlsBrowser::Chrome);
    }

    #[test]
    fn test_load_tls_profile_and_declared_headers() {
        let v = load_tls_profile("chrome_131").expect("profile");
        let p = profile_dump(&v, "chrome_131");
        assert_eq!(p.family, "Chrome");
        assert_eq!(p.ja4, "t13d1516h2_8daaf6152771_e9e4f3b7");
        assert!(p.supports_h2);

        // Unknown profile → error.
        assert!(load_tls_profile("netscape_4").is_err());

        let dump = build_ja4h(&v, &p, &AuditArgs::default()).expect("ja4h");
        // Chromium family: 12 declared headers, h2, no cookie/referer.
        assert_eq!(dump.header_count, 12);
        assert!(dump.ja4h.starts_with("ge20nn12enus_"), "{}", dump.ja4h);
        assert!(dump.headers.contains(&"Sec-Ch-Ua".to_string()));

        // Firefox family: no Client-Hint headers.
        let vf = load_tls_profile("firefox_132").expect("profile");
        let pf = profile_dump(&vf, "firefox_132");
        let dumpf = build_ja4h(&vf, &pf, &AuditArgs::default()).expect("ja4h ff");
        assert_eq!(dumpf.header_count, 9);
        assert!(!dumpf.headers.contains(&"Sec-Ch-Ua".to_string()));
    }

    // ── full report ─────────────────────────────────────────────────────────

    #[test]
    fn test_collect_report_defaults_is_coherent() {
        let args = AuditArgs {
            mtu: Some(1500),
            ..Default::default()
        };
        let report = collect_report(&args).expect("report");
        // Real JA4 of the code-built ClientHello must be present for both
        // transports (values pinned by tls_cohort's own snapshot tests).
        assert!(report.tls_tcp.ja4.is_some(), "tcp ja4: {:?}", report.tls_tcp.error);
        assert!(report.tls_quic.ja4.is_some(), "quic ja4: {:?}", report.tls_quic.error);
        // Default profile coherent with the default TLS profile → no criticals.
        assert_eq!(
            report.critical_count, 0,
            "warnings: {:?}",
            report.warnings
        );
        assert_eq!(report.exit_code(), 0);
        // Cohort without a dataset is the honest undefined state.
        assert_eq!(report.cohort.state, "undefined");
        // JA4T is derived from Linux's /proc/sys/net/ipv4/tcp_rmem. Off Linux
        // there is no such file, and the honest state is "unavailable" -- the
        // module deliberately never fabricates a fingerprint. Asserting
        // "derived" on macOS (where this test also runs) was wrong.
        if cfg!(target_os = "linux") {
            assert_eq!(report.ja4t.state, "derived");
        } else {
            assert_eq!(report.ja4t.state, "unavailable");
        }
        // JSON round-trip shape.
        let json: serde_json::Value =
            serde_json::from_str(&report.to_json().expect("json")).expect("valid json");
        assert_eq!(json["schema"], AUDIT_SCHEMA);
        assert!(json["tls_config"]["tcp"]["ja4"].is_string());
        assert_eq!(json["cohort_k"]["state"], "undefined");
    }

    #[test]
    fn test_collect_report_flags_family_mismatch() {
        // Chrome browser profile + Firefox TLS profile → critical TLS↔UA
        // mismatch, audit fails with exit 2.
        let args = AuditArgs {
            tls_profile: "firefox_132".to_string(),
            mtu: Some(1500),
            ..Default::default()
        };
        let report = collect_report(&args).expect("report");
        assert!(report.critical_count >= 1, "warnings: {:?}", report.warnings);
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn test_collect_report_with_cohort_dataset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cohort.json");
        // 3 of 5 entries share the default profile's JA4.
        std::fs::write(
            &path,
            r#"["t13d1516h2_8daaf6152771_e9e4f3b7","t13d1516h2_8daaf6152771_e9e4f3b7","t13d1516h2_8daaf6152771_e9e4f3b7","other","other2"]"#,
        )
        .expect("write");
        let args = AuditArgs {
            cohort: Some(path),
            mtu: Some(1500),
            ..Default::default()
        };
        let report = collect_report(&args).expect("report");
        assert_eq!(report.cohort.state, "computed");
        assert_eq!(report.cohort.k, Some(3));
        assert_eq!(report.cohort.verdict, "low");
        // default target = the profile's own ja4
        assert_eq!(report.cohort.target, "t13d1516h2_8daaf6152771_e9e4f3b7");
    }

    // ── args / exit codes ───────────────────────────────────────────────────

    #[test]
    fn test_parse_args_flags() {
        let a = parse_args(&s(&[
            "--profile=firefox_132",
            "--browser",
            "chrome_macos",
            "--format",
            "json",
            "--method",
            "POST",
            "--cookie",
            "a=1; b=2",
            "--with-referer",
            "--cohort",
            "/tmp/x.json",
            "--cohort-key",
            "ja4",
            "--tor-check",
        ]))
        .expect("parse")
        .expect("not help");
        assert_eq!(a.tls_profile, "firefox_132");
        assert_eq!(a.browser_profile, "chrome_macos");
        assert_eq!(a.format, OutputFormat::Json);
        assert_eq!(a.method, "POST");
        assert_eq!(a.cookie.as_deref(), Some("a=1; b=2"));
        assert!(a.with_referer);
        assert!(a.tor_check);
        assert_eq!(a.cohort.as_deref().map(Path::to_path_buf), Some(PathBuf::from("/tmp/x.json")));

        // Help forms parse to None.
        assert!(parse_args(&s(&["--help"])).expect("parse").is_none());
        assert!(parse_args(&s(&["help"])).expect("parse").is_none());

        // Unknown flag and positional both error.
        assert!(parse_args(&s(&["--nope"])).is_err());
        assert!(parse_args(&s(&["extra"])).is_err());
        // Bad values error.
        assert!(parse_args(&s(&["--format", "xml"])).is_err());
        assert!(parse_args(&s(&["--mtu", "big"])).is_err());
        assert!(parse_args(&s(&["--profile"])).is_err());
    }

    #[test]
    fn test_run_exit_codes() {
        // help → 0
        assert_eq!(run_fingerprint_audit_args(&s(&["--help"])), 0);
        // unknown flag → 64
        assert_eq!(run_fingerprint_audit_args(&s(&["--bogus"])), EXIT_USAGE);
        // unknown profile → runtime error 1
        assert_eq!(
            run_fingerprint_audit_args(&s(&["--profile", "netscape_4"])),
            EXIT_RUNTIME
        );
        // missing cohort file → runtime error 1
        assert_eq!(
            run_fingerprint_audit_args(&s(&[
                "--cohort",
                "/definitely/not/a/cohort/file.json",
                "--format",
                "json"
            ])),
            EXIT_RUNTIME
        );
        // valid json run → 0 (deterministic offline audit)
        assert_eq!(
            run_fingerprint_audit_args(&s(&[
                "--format",
                "json",
                "--mtu",
                "1500",
                "--cohort-key",
                "ja4"
            ])),
            0
        );
        // critical mismatch → 2
        assert_eq!(
            run_fingerprint_audit_args(&s(&["--profile", "firefox_132", "--format", "json"])),
            EXIT_CRITICAL
        );
    }

    #[test]
    fn test_proxy_endpoint_parsing() {
        assert_eq!(
            proxy_endpoint("socks5h://127.0.0.1:9050"),
            Some(("127.0.0.1".to_string(), 9050))
        );
        assert_eq!(
            proxy_endpoint("socks5://user:pass@10.0.0.2"),
            Some(("10.0.0.2".to_string(), 9050))
        );
        assert_eq!(
            proxy_endpoint("http://proxy.local"),
            Some(("proxy.local".to_string(), 80))
        );
        assert_eq!(proxy_endpoint("not a url"), None);
    }

    #[test]
    fn test_mask_proxy_hides_userinfo() {
        assert_eq!(mask_proxy("socks5h://u:p@127.0.0.1:9050"), "socks5h://***@127.0.0.1:9050");
        assert_eq!(mask_proxy("socks5h://127.0.0.1:9050"), "socks5h://127.0.0.1:9050");
    }
}
