//! `tallow-locator` CLI — scan (fixtures | live) + selftest.
//!
//! Exit codes: `0` chosen · `3` refused (fail-close) · `2` usage · `1` error.

use crate::model::{JobClass, Offer};
use crate::receipts;
use crate::score::ScoringModel;
use crate::select::{select, DecisionRecord};
use crate::watchers::{FixtureWatcher, HttpWatcher, Watcher};

const USAGE: &str = "\
tallow-locator — lawful egress broker v1 (local)\n\
\n\
usage:\n\
  tallow-locator scan --fixtures <DIR> [--class privacy|relay|general] [--json]\n\
                      [--only-country CC,CC] [--ledger <receipts.jsonl>] [--live]\n\
  tallow-locator selftest\n\
\n\
scan: poll provider catalogs (fixtures, or --live with own keys in env:\n\
      HCLOUD_TOKEN / VULTR_API_KEY / DIGITALOCEAN_TOKEN / OVH_APP_KEY), and
      the proxy to egress through in TALLOW_LOCATOR_PROXY\n\
      normalize → score → select. Fail-close: no compliant offer ⇒ refusal + exit 3.\n\
      --ledger appends one signed locator.scorecard | locator.refusal receipt (DEV key).\n";

struct ScanArgs {
    fixtures: String,
    class: JobClass,
    json: bool,
    only_country: Option<Vec<String>>,
    ledger: Option<String>,
    live: bool,
}

fn parse_scan(args: &[String]) -> Result<ScanArgs, String> {
    let mut a = ScanArgs {
        fixtures: format!("{}/fixtures", env!("CARGO_MANIFEST_DIR")),
        class: JobClass::Privacy,
        json: false,
        only_country: None,
        ledger: None,
        live: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fixtures" => {
                i += 1;
                a.fixtures = args.get(i).ok_or("--fixtures needs a value")?.clone();
            }
            "--class" => {
                i += 1;
                let v = args.get(i).ok_or("--class needs a value")?;
                a.class = JobClass::parse(v).ok_or(format!("bad class: {v}"))?;
            }
            "--only-country" => {
                i += 1;
                let v = args.get(i).ok_or("--only-country needs a value")?;
                a.only_country = Some(
                    v.split(',')
                        .map(|s| s.trim().to_uppercase())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
            "--ledger" => {
                i += 1;
                a.ledger = Some(args.get(i).ok_or("--ledger needs a value")?.clone());
            }
            "--json" => a.json = true,
            "--live" => a.live = true,
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    Ok(a)
}

fn collect(a: &ScanArgs) -> (Vec<Offer>, Vec<(String, String)>) {
    let providers = ["hetzner", "vultr", "digitalocean", "ovh"];
    let mut offers = Vec::new();
    let mut status = Vec::new();
    for id in providers {
        if a.live {
            let Some((url, token_env)) = HttpWatcher::endpoint(id) else {
                continue;
            };
            // The egress plane comes from the caller: without it the live scan
            // refuses rather than leaving from the box IP.
            let transport = match HttpWatcher::proxied_transport() {
                Ok(t) => t,
                Err(e) => {
                    status.push((id.to_string(), format!("live refused: {e}")));
                    continue;
                }
            };
            let w = HttpWatcher::new(id, url, token_env, transport);
            match w.offers() {
                Ok(mut o) => {
                    status.push((id.to_string(), format!("live ok ({} offers)", o.len())));
                    offers.append(&mut o);
                }
                Err(e) => status.push((id.to_string(), format!("live error: {e}"))),
            }
        } else {
            let dir = std::path::Path::new(&a.fixtures);
            let w = FixtureWatcher::new(
                match id {
                    "hetzner" => "hetzner",
                    "vultr" => "vultr",
                    "digitalocean" => "digitalocean",
                    _ => "ovh",
                },
                dir,
            );
            match w.offers() {
                Ok(mut o) => {
                    status.push((id.to_string(), format!("fixture ok ({} offers)", o.len())));
                    offers.append(&mut o);
                }
                Err(e) => status.push((id.to_string(), format!("fixture missing/error: {e}"))),
            }
        }
    }
    if let Some(cc) = &a.only_country {
        offers.retain(|o| cc.contains(&o.country.to_uppercase()));
        status.push(("filter".into(), format!("--only-country {}", cc.join(","))));
    }
    (offers, status)
}

fn print_human(rec: &DecisionRecord, status: &[(String, String)]) {
    println!(
        "tallow-locator — {} · class {} · considered {}",
        rec.model,
        rec.class.as_str(),
        rec.considered
    );
    for (id, s) in status {
        println!("  watcher {id:<14} {s}");
    }
    println!();
    if let Some(r) = &rec.refusal {
        println!("REFUSED (fail-close): {}", r.rule);
        for (k, v) in &r.excluded_by_reason {
            println!("  excluded {k:<18} {v}");
        }
        println!("\n→ job refused — no compliant node. No fallback exists by design.");
        return;
    }
    let c = rec.chosen.as_ref().expect("chosen when not refused");
    println!("CHOSEN  {}  [{:.1}]", c.id, c.score);
    println!(
        "        {} · {} · {:.2} EUR/mo · {} vcpu / {} MB / {} GB · {}",
        c.city, c.country, c.price_month_eur, c.vcpu, c.mem_mb, c.disk_gb, c.arch
    );
    println!();
    println!(
        "top {} of {} compliant ({} excluded):",
        rec.ranked.len().min(8),
        rec.ranked.len(),
        rec.excluded.len()
    );
    for r in rec.ranked.iter().take(8) {
        println!(
            "  {:<34} {:>6.2}  {} {} {:.2} EUR/mo",
            r.id, r.score, r.country, r.region, r.price_month_eur
        );
    }
}

/// Entry point. Returns the process exit code.
pub fn run(args: Vec<String>) -> i32 {
    let Some(cmd) = args.first().cloned() else {
        print!("{USAGE}");
        return 2;
    };
    match cmd.as_str() {
        "scan" => {
            let a = match parse_scan(&args[1..]) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("error: {e}\n\n{USAGE}");
                    return 2;
                }
            };
            let (offers, status) = collect(&a);
            if offers.is_empty() {
                eprintln!("error: zero offers collected (all watchers dark). Fail closed.");
                // Say WHY each watcher was dark: "no egress plane configured" and
                // "no API token" are different problems with different fixes, and
                // the generic line above cannot tell them apart.
                for (id, s) in &status {
                    eprintln!("  {id}: {s}");
                }
                return 3;
            }
            let rec = match select(&offers, a.class, &ScoringModel::default()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            if a.json {
                println!("{}", serde_json::to_string_pretty(&rec).unwrap());
            } else {
                print_human(&rec, &status);
            }
            if let Some(ledger_path) = &a.ledger {
                let key = tallow_registry::receipt::dev_actor_key();
                eprintln!("warn: signing with DEV key (production keys ride the deploy)");
                let ledger = tallow_registry::ledger::Ledger::new(ledger_path);
                let seq = ledger.next_seq().unwrap_or(1);
                let prev = ledger.next_prev().unwrap_or(None);
                let r = match &rec.refusal {
                    None => receipts::scorecard_receipt(seq, "locator", prev, &key, &rec),
                    Some(refusal) => receipts::refusal_receipt(
                        seq,
                        "locator",
                        prev,
                        &key,
                        rec.class.as_str(),
                        rec.considered,
                        refusal,
                    ),
                };
                match ledger.append(&r) {
                    Ok(()) => eprintln!(
                        "receipt: {} seq {} appended to {ledger_path}",
                        r.kind, r.seq
                    ),
                    Err(e) => {
                        eprintln!("error: ledger append failed: {e}");
                        return 1;
                    }
                }
            }
            if rec.refusal.is_some() {
                3
            } else {
                0
            }
        }
        "selftest" => selftest(),
        _ => {
            eprintln!("unknown command: {cmd}\n\n{USAGE}");
            2
        }
    }
}

/// Self-test — the fail-close proof in one command (also covered by `cargo test`).
fn selftest() -> i32 {
    let offers = vec![
        Offer {
            provider: "hetzner".into(),
            plan: "cx22".into(),
            region: "ash".into(),
            city: "Ashburn".into(),
            country: "US".into(),
            price_month_eur: 4.99,
            vcpu: 2,
            mem_mb: 4096,
            disk_gb: 40,
            arch: "x86_64".into(),
            source_id: "1".into(),
        },
        Offer {
            provider: "vultr".into(),
            plan: "vc2-1c-2gb".into(),
            region: "ewr".into(),
            city: "New Jersey".into(),
            country: "US".into(),
            price_month_eur: 5.0,
            vcpu: 1,
            mem_mb: 2048,
            disk_gb: 55,
            arch: "x86_64".into(),
            source_id: "vc2-1c-2gb".into(),
        },
    ];
    let m = ScoringModel::default();
    let privacy = select(&offers, JobClass::Privacy, &m).unwrap();
    let relay = select(&offers, JobClass::Relay, &m).unwrap();
    let ok1 = privacy.refusal.is_some() && privacy.chosen.is_none();
    let ok2 = relay.chosen.is_some();
    println!(
        "selftest 1: all-US catalog, privacy class → refusal            {}",
        if ok1 { "PASS" } else { "FAIL" }
    );
    println!(
        "selftest 2: all-US catalog, relay class   → chosen             {}",
        if ok2 { "PASS" } else { "FAIL" }
    );
    if ok1 && ok2 {
        0
    } else {
        1
    }
}
