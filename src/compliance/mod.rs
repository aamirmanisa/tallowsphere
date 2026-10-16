//! Local-first compliance reporting (row #179, spec R-12
//! `phase2-agents/agent-09-geopolitics.md:182`): regulation-ready report
//! payloads generated **on the operator's machine** for the operator to
//! review and submit — never a telemetry backdoor.
//!
//! Three legs, one module per leg:
//!
//! | module | leg | spec anchor |
//! |---|---|---|
//! | [`clocks`] | early-warning clock computation: CRA 24 h / NIS2 24 h+72 h / CERT-In 6 h | `agent-09-geopolitics.md:90` |
//! | [`incident`] | CERT-In incident report generator (6-hour rule; Annex-I fields; redacted + evidence-linked) | `agent-09-geopolitics.md:48` |
//! | [`znism`] | NIS2 / NZISM-style self-assessment evidence pack, built from the machine checks that exist (`src/config/lint.rs` zero-trust pack, row #144) | `agent-09-geopolitics.md:279` |
//!
//! **Posture (acceptance `final/priority-matrix.md:185`):** every artifact is
//! generated locally; nothing is transmitted; the operator approves
//! submission. Reports are redacted before rendering and carry a digest so
//! they can be signed externally. Where a claim has no machine check behind
//! it, the pack says `unsupported` rather than guessing.
//!
//! This module lives in the `tallow` binary target (`src/main.rs` declares
//! `mod compliance;`) — it is CLI surface, not compiler pipeline.

pub mod cli;
pub mod clocks;
pub mod incident;
pub mod znism;

/// Civil date math (Howard Hinnant's `days_from_civil` / `civil_from_days`)
/// and timestamp helpers. Kept dependency-free and integer-only so the
/// computed deadlines are exactly reproducible across platforms.

/// Days since 1970-01-01 for a proleptic-Gregorian year/month/day.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `2026-09-14T03:21:05Z` for a Unix timestamp (UTC, seconds resolution).
pub fn iso8601_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Strict UTC timestamp parser: Unix seconds (`1757823605`) or
/// `YYYY-MM-DDTHH:MM:SSZ` (the only two forms the reports emit). `+00:00`
/// is accepted as a suffix alias for `Z`; no other offsets — fail closed
/// rather than guess a timezone for a regulatory deadline.
pub fn parse_timestamp(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty timestamp".to_string());
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s
            .parse::<i64>()
            .map_err(|e| format!("invalid unix seconds {s:?}: {e}"));
    }
    let s = s
        .strip_suffix('Z')
        .or_else(|| s.strip_suffix("+00:00"))
        .ok_or_else(|| {
            format!("timestamp {s:?} is neither unix seconds nor `YYYY-MM-DDTHH:MM:SSZ`")
        })?;
    let bytes = s.as_bytes();
    if bytes.len() != 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(format!("malformed timestamp {s:?}"));
    }
    let num = |range: std::ops::Range<usize>, what: &str| -> Result<i64, String> {
        s.get(range)
            .filter(|v| v.chars().all(|c| c.is_ascii_digit()))
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(|| format!("malformed {what} in {s:?}"))
    };
    let (y, mo, d) = (num(0..4, "year")?, num(5..7, "month")?, num(8..10, "day")?);
    let (hh, mm, ss) = (
        num(11..13, "hour")?,
        num(14..16, "minute")?,
        num(17..19, "second")?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return Err(format!("out-of-range component in {s:?}"));
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Lowercase-hex digest, same convention as `tallow::enforcement::sha256_hex`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Length-prefixed field push for canonical (unambiguous) hashing payloads —
/// the same convention the crypto lanes use for signed payloads.
pub fn push_field(buf: &mut String, field: &str) {
    buf.push_str(&format!("{}:{}", field.len(), field));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_round_trips_known_epochs() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_757_818_805), "2025-09-14T03:00:05Z");
        // 2024-02-29 (leap day) — the classic civil-math boundary.
        assert_eq!(iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Ok(0));
    }

    #[test]
    fn timestamp_parser_accepts_documented_forms_only() {
        assert_eq!(parse_timestamp("1757818805"), Ok(1_757_818_805));
        assert_eq!(parse_timestamp("2025-09-14T03:00:05Z"), Ok(1_757_818_805));
        assert_eq!(
            parse_timestamp("2025-09-14T03:00:05+00:00"),
            Ok(1_757_818_805)
        );
        // Fail closed: local-time offsets and loose forms are refused.
        assert!(parse_timestamp("2025-09-14T03:00:05+02:00").is_err());
        assert!(parse_timestamp("2025-09-14 03:00:05").is_err());
        assert!(parse_timestamp("2025-13-01T00:00:00Z").is_err());
        assert!(parse_timestamp("").is_err());
    }

    #[test]
    fn iso8601_and_parser_round_trip_over_a_year_of_days() {
        let start = parse_timestamp("2026-01-01T00:00:00Z").unwrap();
        for day in 0..366 {
            let ts = start + day * 86_400 + 12 * 3600;
            assert_eq!(parse_timestamp(&iso8601_utc(ts)), Ok(ts), "day {day}");
        }
    }

    #[test]
    fn push_field_is_length_prefixed_and_unambiguous() {
        let mut a = String::new();
        push_field(&mut a, "ab");
        push_field(&mut a, "c");
        let mut b = String::new();
        push_field(&mut b, "a");
        push_field(&mut b, "bc");
        assert_ne!(a, b);
        assert_eq!(a, "2:ab1:c");
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
