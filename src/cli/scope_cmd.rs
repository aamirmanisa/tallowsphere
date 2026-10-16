//! `tallow scope` — inspect and audit the outbound authorization register.
//!
//! Three verbs:
//!
//! * `scope check <url-or-host>` — ask the gate. Exit 0 when allowed; non-zero
//!   with the refusal reason when not. This is the verb to put in front of any
//!   pipeline that fetches, so the "may I" question is answered by the register
//!   rather than by whoever wrote the URL into a config.
//! * `scope list` — every entry with its basis, granter and expiry. Unexpiring
//!   grants are printed as `unbounded` rather than silently omitted.
//! * `scope verify` — audit the register itself: expired entries, written
//!   consent with no evidence, unbounded grants, and the loaded state. Exits
//!   non-zero if the register is defective, so it can gate a release.
//!
//! `--today` overrides the date used for expiry decisions, which makes the
//! output reproducible in tests instead of clock-dependent.

use crate::scope::{Decision, Refusal, ScopeEntry, ScopeRegister, DEFAULT_REGISTER_PATH};
use std::time::{SystemTime, UNIX_EPOCH};

/// Days from civil date (Howard Hinnant's `days_from_civil`), and back again.
/// Hand-rolled so this verb carries no date-library dependency.
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

/// Today as `YYYY-MM-DD`, UTC.
pub fn today_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

struct Opts {
    register: String,
    today: String,
    json: bool,
    method: String,
    positional: Vec<String>,
}

fn parse_opts(args: &[String]) -> Opts {
    let mut o = Opts {
        register: DEFAULT_REGISTER_PATH.to_string(),
        today: today_iso(),
        json: false,
        method: "GET".to_string(),
        positional: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--register" => {
                if let Some(v) = args.get(i + 1) {
                    o.register = v.clone();
                    i += 2;
                    continue;
                }
            }
            "--today" => {
                if let Some(v) = args.get(i + 1) {
                    o.today = v.clone();
                    i += 2;
                    continue;
                }
            }
            "--method" => {
                if let Some(v) = args.get(i + 1) {
                    o.method = v.to_ascii_uppercase();
                    i += 2;
                    continue;
                }
            }
            "--json" => o.json = true,
            other => o.positional.push(other.to_string()),
        }
        i += 1;
    }
    o
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `tallow scope check <url-or-host> [--method M] [--register P] [--today D] [--json]`
fn cmd_check(o: &Opts) -> Result<(), String> {
    let target = o
        .positional
        .first()
        .ok_or_else(|| "usage: tallow scope check <url-or-host> [--method GET] [--register PATH] [--today YYYY-MM-DD] [--json]".to_string())?;
    let register = ScopeRegister::load(&o.register);
    let decision = register.authorize(target, &o.method, &o.today);

    if o.json {
        let payload = match &decision {
            Decision::Allowed(e) => format!(
                "{{\"decision\":\"allow\",\"host\":\"{}\",\"basis\":\"{}\",\"granted_by\":\"{}\",\"expires_at\":{},\"register\":\"{}\"}}",
                json_escape(&e.host),
                e.basis.as_str(),
                json_escape(&e.granted_by),
                e.expires_at
                    .as_deref()
                    .map(|d| format!("\"{}\"", json_escape(d)))
                    .unwrap_or_else(|| "null".to_string()),
                json_escape(&o.register)
            ),
            Decision::Refused(r) => format!(
                "{{\"decision\":\"refuse\",\"code\":\"{}\",\"reason\":\"{}\",\"register\":\"{}\"}}",
                r.code(),
                json_escape(&r.explain()),
                json_escape(&o.register)
            ),
        };
        println!("{payload}");
    } else {
        println!("{}", decision.render());
    }

    match decision {
        Decision::Allowed(_) => Ok(()),
        Decision::Refused(r) => Err(format!("{} — {}", r.code(), r.explain())),
    }
}

fn entry_line(e: &ScopeEntry) -> String {
    format!(
        "{:<32} {:<18} {:<24} {:<29} {}",
        e.host,
        e.basis.as_str(),
        e.granted_by,
        e.granted_at,
        match e.expires_at.as_deref() {
            Some(d) => d.to_string(),
            None => "unbounded".to_string(),
        }
    )
}

/// `tallow scope list [--register P] [--json]`
fn cmd_list(o: &Opts) -> Result<(), String> {
    let register = ScopeRegister::load(&o.register);
    if let Some(failure) = register.load_failure() {
        return Err(format!("{} — {}", failure.code(), failure.explain()));
    }
    let entries: Vec<&ScopeEntry> = register.entries().collect();
    if o.json {
        let items: Vec<String> = entries
            .iter()
            .map(|e| {
                format!(
                    "{{\"host\":\"{}\",\"basis\":\"{}\",\"granted_by\":\"{}\",\"granted_at\":\"{}\",\"expires_at\":{},\"evidence\":{},\"methods\":[{}]}}",
                    json_escape(&e.host),
                    e.basis.as_str(),
                    json_escape(&e.granted_by),
                    json_escape(&e.granted_at),
                    e.expires_at
                        .as_deref()
                        .map(|d| format!("\"{}\"", json_escape(d)))
                        .unwrap_or_else(|| "null".to_string()),
                    e.evidence
                        .as_deref()
                        .map(|d| format!("\"{}\"", json_escape(d)))
                        .unwrap_or_else(|| "null".to_string()),
                    e.methods
                        .iter()
                        .map(|m| format!("\"{}\"", json_escape(m)))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect();
        println!(
            "{{\"register\":\"{}\",\"count\":{},\"authorized\":[{}]}}",
            json_escape(&o.register),
            entries.len(),
            items.join(",")
        );
        return Ok(());
    }
    println!("register: {}", o.register);
    println!("entries:  {}", entries.len());
    println!();
    println!(
        "{:<32} {:<18} {:<24} {:<29} {}",
        "HOST", "BASIS", "GRANTED BY", "GRANTED AT", "EXPIRES"
    );
    for e in &entries {
        println!("{}", entry_line(e));
    }
    if entries.iter().any(|e| e.expires_at.is_none()) {
        println!();
        println!("note: 'unbounded' grants never lapse on their own — give them an expiry.");
    }
    Ok(())
}

/// `tallow scope verify [--register P] [--today D]`
fn cmd_verify(o: &Opts) -> Result<(), String> {
    let register = ScopeRegister::load(&o.register);
    if let Some(failure) = register.load_failure() {
        return Err(format!("{} — {}", failure.code(), failure.explain()));
    }
    let mut defects: Vec<String> = Vec::new();
    let mut expired = 0usize;
    let mut unbounded = 0usize;

    for e in register.entries() {
        if e.basis.requires_evidence() && e.evidence.as_deref().unwrap_or("").trim().is_empty() {
            defects.push(format!(
                "{}: basis '{}' without an evidence pointer",
                e.host,
                e.basis.as_str()
            ));
        }
        match e.expires_at.as_deref() {
            Some(exp) if o.today.as_str() > exp => {
                expired += 1;
                defects.push(format!("{}: expired on {exp} (today {})", e.host, o.today));
            }
            Some(_) => {}
            None => {
                unbounded += 1;
                defects.push(format!("{}: no expiry set", e.host));
            }
        }
    }

    println!("register: {}", o.register);
    println!("entries:  {}", register.len());
    println!("expired:  {expired}");
    println!("unbounded: {unbounded}");
    if defects.is_empty() {
        println!("RESULT: register is sound ({})", register.len());
        return Ok(());
    }
    println!();
    for d in &defects {
        println!("  - {d}");
    }
    Err(format!(
        "scope:register-defective — {} defect(s) across {} entries",
        defects.len(),
        register.len()
    ))
}

/// Entry point, called from `main.rs`.
pub fn run_scope_cmd(args: &[String]) -> Result<(), String> {
    let (verb, rest) = match args.split_first() {
        Some((v, r)) => (v.as_str(), r),
        None => ("help", &[][..]),
    };
    let o = parse_opts(rest);
    match verb {
        "check" => cmd_check(&o),
        "list" => cmd_list(&o),
        "verify" => cmd_verify(&o),
        "help" | "--help" | "-h" => {
            println!("tallow scope — outbound authorization register (deny-by-default)");
            println!();
            println!("  tallow scope check <url-or-host> [--method GET] [--json]");
            println!("      Ask the gate. Exit 0 = allowed, non-zero = refused, with the ground named.");
            println!("  tallow scope list [--json]");
            println!("      Every grant: host, basis, granter, expiry.");
            println!("  tallow scope verify");
            println!("      Audit the register (expired, missing evidence, unbounded).");
            println!();
            println!("  --register PATH   default {DEFAULT_REGISTER_PATH}");
            println!("  --today YYYY-MM-DD  override the expiry date (reproducible output)");
            Ok(())
        }
        other => Err(format!(
            "unknown scope verb '{other}' (expected check | list | verify)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn today_is_iso_shaped() {
        let t = today_iso();
        assert_eq!(t.len(), 10, "expected YYYY-MM-DD, got {t}");
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[7..8], "-");
        let year: i32 = t[..4].parse().expect("year parses");
        assert!(year >= 2026, "year {year} is implausible");
    }

    #[test]
    fn civil_from_days_known_dates() {
        // Day zero is the epoch, by definition.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-10-16: 56 years from 1970 = 56*365 + 14 leaps = 20,454 days to
        // 2026-01-01, plus 288 (Jan-Sep = 273, +15) = 20,742. Derived, not
        // guessed — the first version of this test hardcoded 20,749 and failed
        // by seven days, which was the test being wrong, not the function.
        assert_eq!(civil_from_days(20_742), (2026, 10, 16));
        // A leap-day anchor: 1970->2024 = 54*365 + 13 leaps = 19,723 days to
        // 2024-01-01, plus 31 (Jan) + 28 = 19,782 for 2024-02-29.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        // And the day either side, so an off-by-one cannot pass.
        assert_eq!(civil_from_days(20_741), (2026, 10, 15));
        assert_eq!(civil_from_days(20_743), (2026, 10, 17));
    }

    #[test]
    fn opts_parse_and_default() {
        let o = parse_opts(&["https://x.example/".to_string(), "--method".to_string(), "head".to_string()]);
        assert_eq!(o.positional, vec!["https://x.example/".to_string()]);
        assert_eq!(o.method, "HEAD");
        assert_eq!(o.register, DEFAULT_REGISTER_PATH);
    }

    #[test]
    fn check_refuses_an_unlisted_host_with_a_named_ground() {
        let o = Opts {
            register: "configs/tallow/scope/authorized-hosts.toml".to_string(),
            today: "2026-10-16".to_string(),
            json: false,
            method: "GET".to_string(),
            positional: vec!["https://nowhere-unauthorized.example/".to_string()],
        };
        let err = cmd_check(&o).expect_err("unlisted host must refuse");
        assert!(err.contains("scope:not-listed"), "reason was: {err}");
    }

    #[test]
    fn check_allows_a_seeded_host() {
        let o = Opts {
            register: "configs/tallow/scope/authorized-hosts.toml".to_string(),
            today: "2026-10-16".to_string(),
            json: false,
            method: "GET".to_string(),
            positional: vec!["https://example.com/".to_string()],
        };
        cmd_check(&o).expect("example.com is seeded");
    }

    #[test]
    fn verify_reports_an_unbounded_grant() {
        // The shipped register has none: every seeded entry carries an expiry.
        let o = Opts {
            register: "configs/tallow/scope/authorized-hosts.toml".to_string(),
            today: "2026-10-16".to_string(),
            json: false,
            method: "GET".to_string(),
            positional: Vec::new(),
        };
        cmd_verify(&o).expect("shipped register is sound");
    }
}
