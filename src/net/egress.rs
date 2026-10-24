//! Egress ledger: a per-target budget and a stop rule for hostile responses.
//!
//! The directorate's scope gate answers *may we touch this host at all*. This
//! ledger answers a narrower, per-run question: *how much, and what happens when
//! the target says no*. Two rules, both enforced before a request leaves:
//!
//! 1. **Budget.** At most `TALLOW_EGRESS_BUDGET` requests (default 50) per host
//!    per process. A collection task that would exceed it is refused with the
//!    host and the count, not silently slowed.
//! 2. **Stop on refusal.** A `403` or `429` from a host ends that host: every
//!    later request to it is refused for the rest of the run. A `403` means the
//!    target has said no; retrying it is what a hostile scanner does.
//!
//! Every decision is appended to the ledger file as JSONL, including the
//! refusals — a ledger that only records what was allowed cannot show restraint.
//!
//! The ledger is **fail-closed**: if a record cannot be written, later egress is
//! refused. An audit trail that silently stops recording is worse than none.
//!
//! Enabled by setting `TALLOW_EGRESS_LEDGER` to a file path. When it is unset the
//! ledger is inert, which is what keeps ordinary library use and the test suite
//! unaffected — but a directorate run sets it, and then the rules are real.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Hosts whose budget is tracked.
#[derive(Debug)]
struct Host {
    requests: u32,
    stopped: Option<String>,
}

pub struct EgressLedger {
    path: PathBuf,
    budget: u32,
    hosts: Mutex<HashMap<String, Host>>,
    /// Set when the ledger could not be written: from then on every request is
    /// refused, because an unrecorded request is an unauditable one.
    broken: Mutex<Option<String>>,
}

impl EgressLedger {
    pub fn new(path: impl Into<PathBuf>, budget: u32) -> Self {
        let path = path.into();
        // Reload prior decisions: a ledger that forgets everything between runs
        // enforces nothing across the runs that matter (one process per
        // collection step). Counts and stops are reconstructed from the file.
        let hosts = Self::load(&path);
        EgressLedger {
            path,
            budget: budget.max(1),
            hosts: Mutex::new(hosts),
            broken: Mutex::new(None),
        }
    }

    fn load(path: &Path) -> HashMap<String, Host> {
        let mut hosts: HashMap<String, Host> = HashMap::new();
        let Ok(text) = std::fs::read_to_string(path) else {
            return hosts;
        };
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            let status = v.get("status").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            let decision = v.get("decision").and_then(|x| x.as_str()).unwrap_or("");
            let host = host_of(url);
            if host.is_empty() {
                continue;
            }
            let entry = hosts.entry(host).or_insert(Host {
                requests: 0,
                stopped: None,
            });
            // A refusal records no request; an allowed one records a real send.
            if decision == "allowed" {
                entry.requests += 1;
            }
            if status == 403 {
                entry.stopped = Some("target returned 403 (refused)".to_string());
            } else if status == 429 {
                entry.stopped = Some("target returned 429 (rate limited); stopping".to_string());
            } else if let Some(reason) = v.get("stopped").and_then(|x| x.as_str()) {
                if !reason.is_empty() {
                    entry.stopped = Some(reason.to_string());
                }
            }
        }
        hosts
    }

    /// Build from the environment. `None` means "no ledger configured", which is
    /// not an error: only a run that asks for accounting gets it.
    pub fn from_env() -> Option<Self> {
        let path = std::env::var("TALLOW_EGRESS_LEDGER").ok()?;
        if path.trim().is_empty() {
            return None;
        }
        let budget = std::env::var("TALLOW_EGRESS_BUDGET")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(50);
        Some(EgressLedger::new(path, budget))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn budget(&self) -> u32 {
        self.budget
    }

    /// Ask permission for one request to `host`. Refuses when the host is
    /// stopped, the budget is spent, or the ledger is broken.
    pub fn permit(&self, host: &str) -> Result<(), String> {
        if let Some(reason) = self.broken.lock().unwrap().clone() {
            return Err(format!("egress ledger: refusing all egress — {reason}"));
        }
        let hosts = self.hosts.lock().unwrap();
        match hosts.get(host) {
            Some(h) if h.stopped.is_some() => Err(format!(
                "egress ledger: {host} is stopped — {}",
                h.stopped.as_deref().unwrap_or("refused")
            )),
            Some(h) if h.requests >= self.budget => Err(format!(
                "egress ledger: budget {} exhausted for {host} ({} requests)",
                self.budget, h.requests
            )),
            _ => Ok(()),
        }
    }

    /// Record one completed request. `status` is the HTTP status the caller saw
    /// (0 for a transport failure).
    pub fn record(&self, host: &str, url: &str, method: &str, status: u16) {
        let mut blocked: Option<String> = None;
        {
            let mut hosts = self.hosts.lock().unwrap();
            let entry = hosts.entry(host.to_string()).or_insert(Host {
                requests: 0,
                stopped: None,
            });
            entry.requests += 1;
            if status == 403 {
                entry.stopped = Some("target returned 403 (refused)".to_string());
                blocked = entry.stopped.clone();
            } else if status == 429 {
                entry.stopped = Some("target returned 429 (rate limited); stopping".to_string());
                blocked = entry.stopped.clone();
            }
        }
        self.append(url, method, status, "allowed", blocked.as_deref());
    }

    /// Record a refusal (no request was made).
    pub fn record_refusal(&self, host: &str, url: &str, method: &str, reason: &str) {
        let entry_requests = self
            .hosts
            .lock()
            .unwrap()
            .get(host)
            .map(|h| h.requests)
            .unwrap_or(0);
        self.append(
            url,
            method,
            0,
            &format!("refused: {reason} (host requests={entry_requests})"),
            None,
        );
    }

    fn append(&self, url: &str, method: &str, status: u16, decision: &str, stop: Option<&str>) {
        let line = serde_json::json!({
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "url": url,
            "method": method,
            "status": status,
            "decision": decision,
            "stopped": stop,
        })
        .to_string();
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = result {
            let mut broken = self.broken.lock().unwrap();
            if broken.is_none() {
                *broken = Some(format!(
                    "ledger {} is unwritable: {e}",
                    self.path.display()
                ));
            }
        }
    }

    /// Whether `host` is currently stopped.
    pub fn is_stopped(&self, host: &str) -> bool {
        self.hosts
            .lock()
            .unwrap()
            .get(host)
            .map(|h| h.stopped.is_some())
            .unwrap_or(false)
    }

    /// Requests recorded for `host`.
    pub fn requests_to(&self, host: &str) -> u32 {
        self.hosts
            .lock()
            .unwrap()
            .get(host)
            .map(|h| h.requests)
            .unwrap_or(0)
    }
}

/// The process-wide ledger, if one is configured.
pub fn ledger() -> Option<&'static EgressLedger> {
    static LEDGER: std::sync::OnceLock<Option<EgressLedger>> = std::sync::OnceLock::new();
    LEDGER.get_or_init(EgressLedger::from_env).as_ref()
}

/// The host part of a URL, without the scheme or port.
pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host_port = rest.split('/').next().unwrap_or("");
    let host = match host_port.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host_port,
    };
    host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_in(dir: &str, budget: u32) -> EgressLedger {
        let path = std::env::temp_dir().join(format!(
            "egress-{}-{}.jsonl",
            dir,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        EgressLedger::new(path, budget)
    }

    #[test]
    fn the_budget_is_per_host_and_refuses_by_name() {
        let l = ledger_in("budget", 2);
        l.permit("a.example").unwrap();
        l.record("a.example", "https://a.example/1", "GET", 200);
        l.record("a.example", "https://a.example/2", "GET", 200);
        let err = l.permit("a.example").unwrap_err();
        assert!(err.contains("budget 2 exhausted for a.example"), "{err}");
        // A different host has its own budget.
        l.permit("b.example").unwrap();
    }

    #[test]
    fn a_403_stops_the_host_for_the_rest_of_the_run() {
        let l = ledger_in("stop", 50);
        l.permit("no.example").unwrap();
        l.record("no.example", "https://no.example/private", "GET", 403);
        assert!(l.is_stopped("no.example"));
        let err = l.permit("no.example").unwrap_err();
        assert!(err.contains("403"), "{err}");
        let text = std::fs::read_to_string(l.path()).unwrap();
        assert!(text.contains("\"status\":403"), "{text}");
        assert!(text.contains("\"stopped\":\"target returned 403"), "{text}");
    }

    #[test]
    fn a_429_stops_the_host_and_the_refusal_is_journalled() {
        let l = ledger_in("rate", 50);
        l.record("slow.example", "https://slow.example/", "GET", 429);
        assert!(l.is_stopped("slow.example"));
        l.record_refusal("slow.example", "https://slow.example/x", "GET", "host stopped");
        let text = std::fs::read_to_string(l.path()).unwrap();
        assert!(text.contains("\"decision\":\"refused: host stopped"), "{text}");
    }

    #[test]
    fn an_unwritable_ledger_stops_all_egress() {
        let l = EgressLedger::new("/proc/definitely/not/writable.jsonl", 50);
        l.record("a.example", "https://a.example/", "GET", 200);
        let err = l.permit("b.example").unwrap_err();
        assert!(err.contains("refusing all egress"), "{err}");
    }

    #[test]
    fn host_extraction_handles_ports_brackets_and_case() {
        assert_eq!(host_of("https://Example.COM:443/x"), "example.com");
        assert_eq!(host_of("http://[::1]:8080/x"), "::1");
        assert_eq!(host_of("https://a.example"), "a.example");
    }
}
