//! Canary monitoring — sweep observed text for leaked canary tokens and
//! render operator-facing alerts (E12 / A3.5.2).
//!
//! Planting, generation, and validation live in [`crate::canary_tokens`];
//! this module is the **detection** half. An [`Observation`] is any text the
//! operator can read but did not write (leak-dump scrape, paste capture,
//! shared-artifact copy, feed result). [`sweep`] scans each observation for
//! the investigation's planted canaries and raises a [`LeakAlert`] per
//! occurrence: a hit proves the planted data moved beyond the audience it was
//! planted for.
//!
//! ```text
//! observations ──scan()──▶ hits ──filter(is_valid)──▶ LeakAlert{origin,offset,severity}
//!                                                          │
//!                                      alert_report() ─────┘──▶ operator report
//! ```
//!
//! ## Severity (derived from the token text alone)
//!
//! A canary's `KIND` segment (`TLW-<KIND>-…`) states which surface it was
//! built for, so severity is derivable from the token text with no registry
//! lookup — it survives copying, serialization, and report forwarding:
//!
//! * **2 — manifest/artifact-grade** ([`SEVERITY_MANIFEST`]): `MARKER` and
//!   `SERIAL` are the manifest-embeddable kinds — per [`crate::canary_tokens`]
//!   a marker is a "free-standing text marker embedded in a
//!   document/manifest" and a serial is shaped for "databases/receipts/
//!   exports" (structured output copies). Finding one means a *controlled
//!   artifact* left the perimeter.
//! * **1 — link-grade** ([`SEVERITY_LINK`]): `URL` tokens are planted into
//!   URLs (query parameters, redirect targets); URL strings replicate through
//!   caches, crawlers, and browser history by design, so a hit still fires an
//!   alert but carries less confidence that a document-grade artifact leaked.
//!
//! Only tokens that pass [`canary_tokens::is_valid`] reach severity
//! assignment: [`sweep`] drops invalid canaries before scanning. The `_ => 1`
//! fallback in [`severity_of`] is therefore unreachable for real alerts; it
//! exists only so the function is total for arbitrary input.
//!
//! ## Ordering and determinism
//!
//! [`sweep`] returns alerts sorted ascending by `(origin, offset)`, with the
//! token text as final tiebreak — deterministic for identical inputs.
//! [`alert_report`] renders alerts in exactly the order given; feed it
//! [`sweep`] output directly. Offsets are byte offsets into the observation
//! text (as produced by [`canary_tokens::scan`]), usable as
//! `&obs.text[offset..offset + canary.len()]`.

use crate::canary_tokens;
use serde::{Deserialize, Serialize};

/// One piece of observed text, tagged with where it was observed.
///
/// `origin` should be a stable, human-readable label of the observation
/// channel (e.g. `"paste.example/abc123 (capture 2026-09-11)"`) — it is what
/// an operator acts on during containment. `text` is the exact observed
/// bytes as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Where this text was observed (channel/capture label).
    pub origin: String,
    /// The observed text, scanned verbatim for canary tokens.
    pub text: String,
}

/// A leaked canary: one planted token found in one observation.
///
/// One alert is emitted per occurrence (same token in the same text twice =
/// two alerts, distinct offsets); see [`sweep`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakAlert {
    /// The canary token that was found.
    pub canary: String,
    /// Origin of the observation it was found in (copied from
    /// [`Observation::origin`]).
    pub origin: String,
    /// Byte offset of the match start within the observation text.
    pub offset: usize,
    /// Alert severity: [`SEVERITY_MANIFEST`] (2) for manifest-embeddable
    /// kinds (`MARKER`, `SERIAL`), else [`SEVERITY_LINK`] (1). Derived from
    /// the token text; see the module docs.
    pub severity: u8,
}

/// Severity for manifest/artifact-grade canary kinds (`MARKER`, `SERIAL`):
/// a controlled document/manifest/export copy surfaced somewhere it does not
/// belong.
pub const SEVERITY_MANIFEST: u8 = 2;

/// Severity for link-grade canary kinds (`URL`) and — defensively — anything
/// else: alert-worthy, but URL strings replicate through caches/crawlers/
/// history by design.
pub const SEVERITY_LINK: u8 = 1;

/// First line of [`alert_report`] output. Contains the substring
/// `"CANARY ALERT"`; operators grep for it.
pub const ALERT_HEADER: &str = "CANARY ALERT";

/// Derive the severity of a canary **from its text alone**.
///
/// Reads the `KIND` segment of `TLW-<KIND>-…`: `MARKER` and `SERIAL` →
/// [`SEVERITY_MANIFEST`] (2); everything else → [`SEVERITY_LINK`] (1).
/// Total function: malformed input defaults to 1 (unreachable for alerts,
/// which are always `is_valid`-filtered first — see module docs).
pub fn severity_of(canary: &str) -> u8 {
    match canary.split('-').nth(1) {
        Some("MARKER") | Some("SERIAL") => SEVERITY_MANIFEST,
        _ => SEVERITY_LINK,
    }
}

/// Scan every observation for every planted canary and return the leak
/// alerts.
///
/// Semantics (frozen interface §9):
/// * Canaries failing [`canary_tokens::is_valid`] are dropped **before**
///   scanning — a corrupted or lookalike string never produces an alert.
/// * Each observation is scanned via [`canary_tokens::scan`], so duplicates
///   in `canaries` do not double-report and offsets are byte offsets.
/// * One [`LeakAlert`] per occurrence; output sorted ascending by
///   `(origin, offset)`, token text as final tiebreak. Never panics.
/// * Empty `observations` or an all-invalid `canaries` slice yields an empty
///   vec.
pub fn sweep(observations: &[Observation], canaries: &[String]) -> Vec<LeakAlert> {
    let valid: Vec<String> = canaries
        .iter()
        .filter(|c| canary_tokens::is_valid(c))
        .cloned()
        .collect();
    let mut alerts: Vec<LeakAlert> = Vec::new();
    for obs in observations {
        for hit in canary_tokens::scan(&obs.text, &valid) {
            let severity = severity_of(&hit.token);
            alerts.push(LeakAlert {
                canary: hit.token,
                origin: obs.origin.clone(),
                offset: hit.offset,
                severity,
            });
        }
    }
    alerts.sort_by(|a, b| {
        a.origin
            .cmp(&b.origin)
            .then_with(|| a.offset.cmp(&b.offset))
            .then_with(|| a.canary.cmp(&b.canary))
    });
    alerts
}

/// Render an operator-facing alert report.
///
/// Format (deterministic, one line per alert, in the order given):
///
/// ```text
/// CANARY ALERT — <n> hit(s)
/// - origin=<origin> offset=<offset> severity=<severity> canary=<canary>
/// ...
/// ```
///
/// Empty input still yields the header plus `- (no canary hits)` so the
/// absence of hits is explicit in logs. Output always ends with a newline.
pub fn alert_report(alerts: &[LeakAlert]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{ALERT_HEADER} — {} hit(s)", alerts.len());
    if alerts.is_empty() {
        let _ = writeln!(out, "- (no canary hits)");
    } else {
        for a in alerts {
            let _ = writeln!(
                out,
                "- origin={} offset={} severity={} canary={}",
                a.origin, a.offset, a.severity, a.canary
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary_tokens::{generate, CanaryKind};

    fn mk_token(kind: CanaryKind) -> String {
        generate(kind)
    }

    #[test]
    fn hit_reports_origin_and_offset() {
        let t = mk_token(CanaryKind::Url);
        let prefix = "→→ "; // 7 bytes of multibyte prefix
        let text = format!("{prefix}[{t}] tail");
        let obs = Observation {
            origin: "paste.example/abc".to_string(),
            text: text.clone(),
        };
        let alerts = sweep(std::slice::from_ref(&obs), std::slice::from_ref(&t));
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.canary, t);
        assert_eq!(a.origin, "paste.example/abc");
        assert_eq!(a.offset, prefix.len() + 1); // after '['; byte offset
        assert_eq!(a.severity, SEVERITY_LINK); // URL kind
        // Offset slices back to the token in the observed text.
        assert_eq!(&text[a.offset..a.offset + t.len()], t.as_str());
    }

    #[test]
    fn clean_corpus_yields_no_alerts() {
        let t = mk_token(CanaryKind::Marker);
        let obs = vec![
            Observation {
                origin: "feed.example".into(),
                text: "nothing to see here".into(),
            },
            Observation {
                origin: "paste.example".into(),
                text: "still nothing".into(),
            },
        ];
        assert!(sweep(&obs, std::slice::from_ref(&t)).is_empty());
        // Valid canary, empty text corpus.
        assert!(sweep(&[], &[t]).is_empty());
    }

    #[test]
    fn alerts_sorted_by_origin_then_offset() {
        let t1 = mk_token(CanaryKind::Serial);
        let t2 = mk_token(CanaryKind::Url);
        let t3 = mk_token(CanaryKind::Marker);
        // Input order deliberately not sorted: "b" first, then two "a" hits.
        let obs = vec![
            Observation {
                origin: "b.example".into(),
                text: format!("{t1}"),
            },
            Observation {
                origin: "a.example".into(),
                text: format!("xx{t2}"),
            },
            Observation {
                origin: "a.example".into(),
                text: format!("{t3}"),
            },
        ];
        let alerts = sweep(&obs, &[t1.clone(), t2.clone(), t3.clone()]);
        assert_eq!(alerts.len(), 3);
        assert_eq!(
            (alerts[0].origin.as_str(), alerts[0].offset),
            ("a.example", 0)
        );
        assert_eq!(alerts[0].canary, t3);
        assert_eq!(
            (alerts[1].origin.as_str(), alerts[1].offset),
            ("a.example", 2)
        );
        assert_eq!(alerts[1].canary, t2);
        assert_eq!(
            (alerts[2].origin.as_str(), alerts[2].offset),
            ("b.example", 0)
        );
        assert_eq!(alerts[2].canary, t1);
    }

    #[test]
    fn invalid_canary_is_ignored() {
        let good = mk_token(CanaryKind::Marker);
        // Shape-valid but checksum-corrupt (flip last checksum char).
        let mut corrupted = mk_token(CanaryKind::Marker);
        let bad_char = if corrupted.ends_with('0') { '1' } else { '0' };
        corrupted.pop();
        corrupted.push(bad_char);
        assert!(!canary_tokens::is_valid(&corrupted), "fixture must be invalid");

        let text = format!("leak: {corrupted} and {good}");
        let obs = vec![Observation {
            origin: "dump.example".into(),
            text,
        }];
        let alerts = sweep(&obs, &[corrupted.clone(), good.clone()]);
        // Only the valid canary fires; the corrupted one never even scans.
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].canary, good);
    }

    #[test]
    fn severity_is_derived_from_token_text() {
        let u = mk_token(CanaryKind::Url);
        let m = mk_token(CanaryKind::Marker);
        let s = mk_token(CanaryKind::Serial);
        assert_eq!(severity_of(&u), 1);
        assert_eq!(severity_of(&m), 2);
        assert_eq!(severity_of(&s), 2);
        assert_eq!(severity_of("garbage"), SEVERITY_LINK); // total fallback

        let obs = vec![Observation {
            origin: "x.example".into(),
            text: format!("{u} {m} {s}"),
        }];
        let alerts = sweep(&obs, &[u, m, s]);
        assert_eq!(alerts.len(), 3);
        // Text order: URL(1), MARKER(2), SERIAL(2). Offsets ascending.
        assert_eq!(alerts[0].severity, SEVERITY_LINK);
        assert_eq!(alerts[1].severity, SEVERITY_MANIFEST);
        assert_eq!(alerts[2].severity, SEVERITY_MANIFEST);
        assert!(alerts[0].offset < alerts[1].offset);
        assert!(alerts[1].offset < alerts[2].offset);
    }

    #[test]
    fn report_contains_header_and_one_line_per_alert() {
        let t = mk_token(CanaryKind::Serial);
        let obs = vec![Observation {
            origin: "leak.example".into(),
            text: format!("planted: {t}"),
        }];
        let alerts = sweep(&obs, std::slice::from_ref(&t));
        let report = alert_report(&alerts);
        assert!(report.contains(ALERT_HEADER), "header line missing");
        assert!(report.contains("CANARY ALERT"));
        // header + exactly one alert line
        assert_eq!(report.lines().count(), 1 + alerts.len());
        let line = report.lines().nth(1).unwrap();
        assert!(line.contains("origin=leak.example"));
        assert!(line.contains(&format!("offset={}", alerts[0].offset)));
        assert!(line.contains("severity=2"));
        assert!(line.contains(&t));
        assert!(report.ends_with('\n'));

        // Empty report: header + explicit none-line.
        let empty = alert_report(&[]);
        assert!(empty.contains(ALERT_HEADER));
        assert!(empty.contains("(no canary hits)"));
        assert_eq!(empty.lines().count(), 2);
    }

    #[test]
    fn sweep_and_report_are_deterministic() {
        let t1 = mk_token(CanaryKind::Url);
        let t2 = mk_token(CanaryKind::Marker);
        let obs = vec![
            Observation {
                origin: "b.example".into(),
                text: format!("{t1} x"),
            },
            Observation {
                origin: "a.example".into(),
                text: format!("{t2} {t1}"),
            },
        ];
        let canaries = [t1, t2];
        let r1 = sweep(&obs, &canaries);
        let r2 = sweep(&obs, &canaries);
        assert_eq!(r1, r2, "sweep must be deterministic");
        assert_eq!(alert_report(&r1), alert_report(&r2));
    }

    #[test]
    fn duplicate_canary_entries_do_not_duplicate_alerts() {
        let t = mk_token(CanaryKind::Url);
        let obs = vec![Observation {
            origin: "x.example".into(),
            text: format!("{t} and {t}"),
        }];
        let alerts = sweep(&obs, &[t.clone(), t.clone()]);
        // Two occurrences in text → two alerts (not four from duplicate input).
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].offset < alerts[1].offset);
    }

    #[test]
    fn leak_alert_serde_roundtrip() {
        let alert = LeakAlert {
            canary: mk_token(CanaryKind::Serial),
            origin: "leak.example".into(),
            offset: 42,
            severity: 2,
        };
        let json = serde_json::to_string(&alert).unwrap();
        let back: LeakAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(back, alert);
        // Observation round-trips too (documented additive serde).
        let obs = Observation {
            origin: "o".into(),
            text: "t".into(),
        };
        let j = serde_json::to_string(&obs).unwrap();
        assert_eq!(serde_json::from_str::<Observation>(&j).unwrap(), obs);
    }
}
