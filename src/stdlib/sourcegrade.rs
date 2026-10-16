//! Standard library: `tallow.sourcegrade` — source grading / provenance.
//!
//! Offline scoring of how much evidentiary weight a research pipeline
//! should give a source: an A–F institutional grade derived from a static
//! registry of trusted domains plus TLD policy, a numeric confidence, an
//! epoch timestamp, and citation formatting helpers so every extracted
//! claim can carry a provenance sticker.
//!
//! # API
//! - `sourcegrade.grade(host)`             — SourceGrade struct (A–F + confidence + rationale)
//! - `sourcegrade.confidence(grade, signals, contradictions)` — Float in [0,1]
//! - `sourcegrade.timestamp_ms()`          — current epoch milliseconds
//! - `sourcegrade.date_from_ms(ms)`        — "YYYY-MM-DD" civil date
//! - `sourcegrade.citation(title, url, accessed_ms, grade?)` — formatted citation

use super::StdlibResult;
use crate::interp::{type_name, Value};

// ── Domain registries ──────────────────────────────────────────────────

/// Tier-A: official government and treaty/intergovernmental organizations.
/// Matching is by exact host or by any subdomain of the listed domain.
const TIER_A: &[&str] = &[
    "nih.gov", "cdc.gov", "fda.gov", "nist.gov", "nasa.gov", "noaa.gov",
    "usgs.gov", "gao.gov", "state.gov", "justice.gov", "fbi.gov", "census.gov",
    "irs.gov", "sec.gov", "who.int", "un.org", "unicef.org", "unesco.org",
    "oecd.org", "imf.org", "worldbank.org", "unodc.org", "icrc.org",
    "europa.eu", "ecb.europa.eu", "iea.org", "fao.org", "wto.org",
    "interpol.int", "icann.org",
];

/// Tier-B: established wire services, flagship papers, national
/// broadcasters, peer-reviewed publishers, and major research bodies.
const TIER_B: &[&str] = &[
    "site-26.example", "site-01.example", "ap.org", "site-03.example", "ft.com",
    "site-34.example", "site-21.example", "washingtonpost.com", "economist.com",
    "bbc.com", "bbc.co.uk", "theguardian.com", "npr.org", "pbs.org",
    "nature.com", "science.org", "bmj.com", "nejm.org", "thelancet.com",
    "cell.com", "jamanetwork.com", "ieee.org", "acm.org", "arxiv.org",
    "ssrn.com", "nber.org", "brookings.edu", "rand.org", "pewresearch.org",
    "cambridge.org", "oup.com", "springer.com", "elsevier.com", "wiley.com",
    "mit.edu", "harvard.edu", "stanford.edu", "ox.ac.uk", "cam.ac.uk",
    "cbo.gov",
];

/// Tier-E: low-credibility zones — unknown junk TLDs.
const TIER_E_TLDS: &[&str] = &[
    ".info", ".biz", ".xyz", ".top", ".click", ".download", ".stream", ".loan",
    ".win", ".review", ".work", ".date", ".racing", ".gdn",
];

/// Tier-F: widely documented disinformation / hoax outlets.
const TIER_F: &[&str] = &[
    "infowars.com", "naturalnews.com", "beforeitsnews.com", "globalresearch.ca",
];

fn host_matches_registry(host: &str, registry: &[&str]) -> bool {
    registry.iter().any(|entry| {
        host == *entry || host.ends_with(&format!(".{entry}"))
    })
}

/// Strip scheme, port, path, query, and leading "www." from a host string.
fn clean_host(raw: &str) -> String {
    let mut h = raw.trim().to_lowercase();
    for scheme in ["https://", "http://", "ftp://"] {
        if let Some(rest) = h.strip_prefix(scheme) {
            h = rest.to_string();
            break;
        }
    }
    if let Some(idx) = h.find('/') {
        h.truncate(idx);
    }
    if let Some(idx) = h.find('?') {
        h.truncate(idx);
    }
    if let Some(idx) = h.find('#') {
        h.truncate(idx);
    }
    // Strip :port
    if let Some(idx) = h.rfind(':') {
        if h[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            h.truncate(idx);
        }
    }
    if let Some(rest) = h.strip_prefix("www.") {
        h = rest.to_string();
    }
    h
}

/// Policy grader: returns (grade, rationale) for a cleaned host.
fn grade_host(host: &str) -> (String, String) {
    if host.is_empty() {
        return ("D".into(), "empty host — no signal".into());
    }
    if host_matches_registry(host, TIER_F) {
        return ("F".into(), "documented disinformation outlet (watchlist)".into());
    }
    if host_matches_registry(host, TIER_A) {
        return ("A".into(), "official government / treaty organization (A-tier registry)".into());
    }
    if host_matches_registry(host, TIER_B) {
        return ("B".into(), "established source in B-tier registry (wire / flagship / publisher)".into());
    }
    if host.ends_with(".gov") || host.ends_with(".mil") {
        return ("A".into(), "official US government / military domain".into());
    }
    if host.ends_with(".int") {
        return ("A".into(), "international treaty organization (.int)".into());
    }
    if host.ends_with(".edu") {
        return ("B".into(), "academic (.edu) domain".into());
    }
    // Non-US official domains (gov.uk, go.jp, gov.au, ...) → B.
    for tld in [".gov.uk", ".gov.au", ".gov.ca", ".go.jp", ".gov.in", ".gov.sg", ".gc.ca"] {
        if host.ends_with(tld) {
            return ("B".into(), "foreign official government domain".into());
        }
    }
    if host.ends_with(".org") {
        return ("C".into(), "unlisted .org — unknown institutional standing".into());
    }
    if TIER_E_TLDS.iter().any(|t| host.ends_with(t)) {
        return ("E".into(), "low-credibility TLD zone".into());
    }
    if host.ends_with(".com") || host.ends_with(".net") {
        return ("D".into(), "unlisted commercial domain — verify independently".into());
    }
    ("D".into(), "unlisted domain — verify independently".into())
}

fn base_confidence(grade: &str) -> f64 {
    match grade {
        "A" => 0.95,
        "B" => 0.87,
        "C" => 0.72,
        "D" => 0.55,
        "E" => 0.35,
        "F" => 0.15,
        _ => 0.5,
    }
}

/// Numeric confidence from an A–F grade plus corroboration signals and
/// contradictions. `signals` are independent sources agreeing with the
/// claim (+0.06 each, capped at +0.24); `contradictions` are independent
/// sources disagreeing (−0.25 each, floor −0.75).
fn confidence_for(grade: &str, signals: i128, contradictions: i128) -> f64 {
    let base = base_confidence(grade);
    let sig = (signals.clamp(0, 10) as f64 * 0.06).min(0.24);
    let con = (contradictions.clamp(0, 10) as f64 * 0.25).min(0.75);
    (base + sig - con).clamp(0.02, 0.99)
}

fn now_ms() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i128)
        .unwrap_or(0)
}

/// Days-since-epoch → (year, month, day). Howard Hinnant's civil calendar
/// algorithm (public domain), so date math is dependency-free.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d)
}

fn date_from_ms(ms: i128) -> String {
    let days = ms.div_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn citation_for(title: &str, url: &str, accessed_ms: i128, grade: Option<&str>) -> String {
    let date = date_from_ms(accessed_ms);
    match grade {
        Some(g) if !g.is_empty() => {
            format!("{title}. {url}. Accessed {date}. [source grade: {}]", g.to_uppercase())
        }
        _ => format!("{title}. {url}. Accessed {date}."),
    }
}

// ── Dispatch ───────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "grade" => Some(grade_dispatch(args)),
        "confidence" => Some(confidence_dispatch(args)),
        "timestamp_ms" => Some(Ok(Value::Int(now_ms()))),
        "date_from_ms" => Some(date_dispatch(args)),
        "citation" => Some(citation_dispatch(args)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(
        function,
        "grade" | "confidence" | "timestamp_ms" | "date_from_ms" | "citation"
    )
}

fn str_arg<'a>(args: &'a [Value], idx: usize, fname: &str) -> Result<&'a str, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(format!(
            "{fname}: argument {} expected String, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("{fname}: missing argument {}", idx + 1)),
    }
}

fn int_arg(args: &[Value], idx: usize, fname: &str) -> Result<i128, String> {
    match args.get(idx) {
        Some(Value::Int(i)) => Ok(*i),
        Some(other) => Err(format!(
            "{fname}: argument {} expected Int, got {}",
            idx + 1,
            type_name(other)
        )),
        None => Err(format!("{fname}: missing argument {}", idx + 1)),
    }
}

fn grade_dispatch(args: Vec<Value>) -> StdlibResult {
    let raw = str_arg(&args, 0, "grade")?;
    let host = clean_host(raw);
    let (grade, rationale) = grade_host(&host);
    let confidence = base_confidence(&grade);
    Ok(Value::Struct {
        name: "SourceGrade".into(),
        fields: vec![
            ("grade".into(), Value::String(grade)),
            ("host".into(), Value::String(host)),
            ("confidence".into(), Value::Float(confidence)),
            ("rationale".into(), Value::String(rationale)),
            ("ts_ms".into(), Value::Int(now_ms())),
        ],
    })
}

fn confidence_dispatch(args: Vec<Value>) -> StdlibResult {
    let grade_raw = str_arg(&args, 0, "confidence")?;
    let grade = grade_raw.trim().to_uppercase();
    if !matches!(grade.as_str(), "A" | "B" | "C" | "D" | "E" | "F") {
        return Err(format!(
            "confidence: expected grade A-F, got `{grade_raw}`"
        ));
    }
    let signals = int_arg(&args, 1, "confidence")?;
    let contradictions = int_arg(&args, 2, "confidence")?;
    Ok(Value::Float(confidence_for(&grade, signals, contradictions)))
}

fn date_dispatch(args: Vec<Value>) -> StdlibResult {
    let ms = int_arg(&args, 0, "date_from_ms")?;
    Ok(Value::String(date_from_ms(ms)))
}

fn citation_dispatch(args: Vec<Value>) -> StdlibResult {
    let title = str_arg(&args, 0, "citation")?;
    let url = str_arg(&args, 1, "citation")?;
    let ms = int_arg(&args, 2, "citation")?;
    let grade = match args.get(3) {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(other) => {
            return Err(format!(
                "citation: argument 4 expected String or omitted, got {}",
                type_name(other)
            ))
        }
        None => None,
    };
    Ok(Value::String(citation_for(title, url, ms, grade)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cleanup() {
        assert_eq!(clean_host("HTTPS://Www.Nih.Gov/path?q=1"), "nih.gov");
        assert_eq!(clean_host("http://sub.who.int:8080/x"), "sub.who.int");
        assert_eq!(clean_host("site-26.example/"), "site-26.example");
    }

    #[test]
    fn grade_policy_table() {
        // Tier A exact + subdomain.
        assert_eq!(grade_host("nih.gov").0, "A");
        assert_eq!(grade_host("www.cdc.gov").0, "A");
        assert_eq!(grade_host("who.int").0, "A");
        assert_eq!(grade_host("data.un.org").0, "A");
        // Tier B.
        assert_eq!(grade_host("site-26.example").0, "B");
        assert_eq!(grade_host("www.bbc.co.uk").0, "B");
        assert_eq!(grade_host("nature.com").0, "B");
        assert_eq!(grade_host("mit.edu").0, "B");
        // TLD policy.
        assert_eq!(grade_host("state.ak.us").0, "D"); // .us not .gov — honest miss
        assert_eq!(grade_host("someuniversity.edu").0, "B");
        assert_eq!(grade_host("example.org").0, "C");
        assert_eq!(grade_host("example.com").0, "D");
        assert_eq!(grade_host("example.xyz").0, "E");
        // Watchlist.
        assert_eq!(grade_host("infowars.com").0, "F");
        assert_eq!(grade_host("cdn.globalresearch.ca").0, "F");
        // Rationale text rides along.
        assert!(grade_host("nih.gov").1.contains("official"));
    }

    #[test]
    fn confidence_math() {
        assert_eq!(confidence_for("A", 0, 0), 0.95);
        let boosted = confidence_for("A", 4, 0);
        assert!((boosted - 0.99).abs() < 1e-9, "got {boosted}");
        let sunk = confidence_for("A", 0, 3);
        assert!((sunk - 0.2).abs() < 1e-9, "got {sunk}");
        // Never outside [0.02, 0.99].
        assert!(confidence_for("F", 10, 10) >= 0.02);
        assert!(confidence_for("A", 10, 0) <= 0.99);
        // Corroboration of a weak source can exceed a lone mid source.
        assert!(confidence_for("D", 4, 0) > confidence_for("D", 0, 0));
    }

    #[test]
    fn civil_date_conversion() {
        assert_eq!(date_from_ms(0), "1970-01-01");
        assert_eq!(date_from_ms(1_700_000_000_000), "2023-11-14");
        assert_eq!(date_from_ms(1_752_787_200_000), "2025-07-17");
        // Leap year.
        assert_eq!(date_from_ms(1_583_020_800_000), "2020-03-01");
    }

    #[test]
    fn citation_format() {
        let c = citation_for("Acme Annual Report", "https://acme.example/r.pdf", 1_700_000_000_000, None);
        assert_eq!(c, "Acme Annual Report. https://acme.example/r.pdf. Accessed 2023-11-14.");
        let c2 = citation_for("Claim X", "https://x.example", 1_700_000_000_000, Some("b"));
        assert!(c2.contains("[source grade: B]"), "got {c2}");
    }

    #[test]
    fn dispatch_routes() {
        // grade returns a SourceGrade struct with grade + confidence fields.
        match dispatch("grade", vec![Value::String("https://www.cdc.gov".into())])
            .unwrap()
            .unwrap()
        {
            Value::Struct { name, fields } => {
                assert_eq!(name, "SourceGrade");
                let get = |k: &str| {
                    fields
                        .iter()
                        .find(|(fk, _)| fk == k)
                        .unwrap_or_else(|| panic!("missing field {k}"))
                        .1
                        .clone()
                };
                assert!(matches!(get("grade"), Value::String(s) if s == "A"));
                assert!(matches!(get("host"), Value::String(s) if s == "cdc.gov"));
                assert!(matches!(get("confidence"), Value::Float(f) if (f - 0.95).abs() < 1e-9));
            }
            other => panic!("expected SourceGrade struct, got {:?}", type_name(&other)),
        }
        // Invalid grade letter → honest Err.
        let r = dispatch(
            "confidence",
            vec![
                Value::String("Z".into()),
                Value::Int(1),
                Value::Int(0),
            ],
        );
        assert!(r.unwrap().is_err());
        // Missing arg → honest Err.
        assert!(dispatch("grade", vec![]).unwrap().is_err());
        // Unknown fn → None.
        assert!(dispatch("nope", vec![]).is_none());
        // timestamp_ms is real epoch time.
        let now = dispatch("timestamp_ms", vec![]).unwrap().unwrap();
        if let Value::Int(ms) = now {
            assert!(ms > 1_700_000_000_000, "epoch ms implausible: {ms}");
        } else {
            panic!("timestamp_ms not Int");
        }
    }

    #[test]
    fn interp_end_to_end() {
        let src = r#"
        fn main() {
            let g = sourcegrade.grade("https://www.cdc.gov/flu")
            print(g.grade)
            print(g.host)
            print(g.rationale)
            let c = sourcegrade.confidence("B", 2, 1)
            print(c.to_string())
            print(sourcegrade.date_from_ms(0))
        }
        "#;
        let (tokens, lex_errs) = crate::lexer::tokenize(src);
        assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        let mut interp = crate::interp::Interpreter::new();
        interp.run(&program).expect("interp run failed");
        assert_eq!(interp.output[0], "A");
        assert_eq!(interp.output[1], "cdc.gov");
        assert!(interp.output[2].contains("official"), "{}", interp.output[2]);
        // B base 0.87 + 0.12 - 0.25 ≈ 0.74 (float print may carry epsilon)
        let conf: f64 = interp.output[3].parse().expect("confidence float");
        assert!((conf - 0.74).abs() < 1e-6, "got {}", interp.output[3]);
        assert_eq!(interp.output[4], "1970-01-01");
    }
}
