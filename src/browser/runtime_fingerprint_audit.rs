//! Empirical runtime fingerprint audit — what the page *actually sees*
//! (matrix row #5, report ag03 R-2(a): "after page start, capture what the
//! page actually sees (canvas/WebGL/audio/fonts/UA-CH/timezone vs. intended
//! profile) — a lightweight in-page audit, fail-closed/quarantine on drift").
//!
//! The rule-based validators ([`crate::browser::fingerprint_validator`],
//! [`CoherenceValidator`]) check a *profile* for internal consistency; they
//! cannot see a new Chrome build, a changed GPU driver or a container font set.
//! This module closes that gap for the browser path: the runtime executes
//! [`PROBE_JS`] after page start, feeds the JSON back through
//! [`PageObservation::from_probe_json`], and [`RuntimeFingerprintAudit::audit`]
//! compares the *observed* attributes against the intended [`StealthProfile`].
//!
//! # Fail-closed semantics
//!
//! * A probe that cannot be parsed, a missing required attribute, or a
//!   `webdriver`/headless marker → the call is **quarantined** (never served
//!   as a "pass"): detection-visible automation markers are the exact drift
//!   this audit exists to catch.
//! * Attribute drift between profile and observation is a **Critical** finding
//!   (UA, platform, timezone, WebGL renderer) or a **Warning** (languages,
//!   hardware concurrency, memory, touch points, blocked canvas readback,
//!   empty font set) — the caller decides to re-profile or quarantine.
//! * Absent *optional* attributes are reported as **Info** (unverified, never
//!   silently passed) — the report always states which fields were not
//!   measured.
//!
//! [`RuntimeFingerprintAudit::audit_full`] additionally runs the browser-side
//! [`CoherenceValidator`] against an optional [`GeoContext`]/[`TlsBrowser`]
//! hint and merges both finding sets, so "profile rules" and "observed
//! reality" are judged in one report (R-2(b)/(c) share the same entry point).
//!
//! The report renderers are deterministic (stable ordering, no timestamps, no
//! map iteration): two audits of identical inputs produce byte-identical
//! output. The module performs no I/O and starts no browser.

use serde_json::Value;

use crate::browser::fingerprint_coherence::{CoherenceReport, CoherenceValidator, GeoContext, TlsBrowser};
use crate::browser::stealth::StealthProfile;

/// Version tag carried by [`PROBE_JS`]; observations from a different tag are
/// reported as unverified rather than compared field-by-field.
pub const PROBE_VERSION: &str = "tallow.fp_probe.v1";

/// The in-page probe the browser runtime executes after page start.
///
/// Deterministic: it only reads standardised DOM/Navigator surfaces and never
/// draws randomness. `canvas_hash` is a stable hash of the readback bytes
/// (non-zero only when readback is not blocked/poisoned); `fonts_detected` is
/// the size of a fixed detector set resolved by width measurements.
pub const PROBE_JS: &str = r##"(() => {
  const out = { probe_version: "tallow.fp_probe.v1" };
  try { out.user_agent = navigator.userAgent; } catch (e) {}
  try {
    const d = navigator.userAgentData;
    out.ua_brands = d && d.brands ? d.brands.map(b => b.brand + ":" + b.version) : [];
    out.ua_mobile = d && typeof d.mobile === "boolean" ? d.mobile : null;
    out.ua_platform = d && d.platform ? String(d.platform) : null;
  } catch (e) { out.ua_brands = []; }
  try { out.platform = navigator.platform || ""; } catch (e) {}
  try { out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) {}
  try { out.languages = Array.from(navigator.languages || [navigator.language]); } catch (e) {}
  try { out.hardware_concurrency = navigator.hardwareConcurrency || 0; } catch (e) {}
  try { out.device_memory = typeof navigator.deviceMemory === "number" ? navigator.deviceMemory : null; } catch (e) {}
  try { out.max_touch_points = navigator.maxTouchPoints || 0; } catch (e) {}
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    const dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
    out.webgl_vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : (gl ? gl.getParameter(gl.VENDOR) : null);
    out.webgl_renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : (gl ? gl.getParameter(gl.RENDERER) : null);
  } catch (e) { out.webgl_vendor = null; out.webgl_renderer = null; }
  try {
    const c = document.createElement("canvas");
    c.width = 240; c.height = 60;
    const ctx = c.getContext("2d");
    ctx.textBaseline = "top"; ctx.font = "14px 'Arial'";
    ctx.fillStyle = "#f60"; ctx.fillRect(0, 0, 240, 60);
    ctx.fillStyle = "#069"; ctx.fillText("TallowFpProbe", 2, 15);
    const d = ctx.getImageData(0, 0, 240, 60).data;
    let h = 2166136261 >>> 0;
    for (let i = 0; i < d.length; i += 4) { h ^= d[i] | (d[i + 1] << 8) | (d[i + 2] << 16); h = Math.imul(h, 16777619) >>> 0; }
    out.canvas_hash = h.toString(16);
    out.canvas_readback = "enabled";
  } catch (e) { out.canvas_hash = null; out.canvas_readback = "blocked"; }
  try {
    const oac = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (oac) {
      const ctx = new oac(1, 44100, 44100);
      const osc = ctx.createOscillator(); osc.type = "triangle"; osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
      out.audio_hash = "pending";
      ctx.startRendering().then(buf => {
        const d = buf.getChannelData(0); let h = 0;
        for (let i = 4500; i < 5000; i++) { h += Math.abs(d[i]); }
        out.audio_hash = h.toFixed(6);
        window.__tallowFpProbeResult = out;
      }).catch(() => { out.audio_hash = "errored"; window.__tallowFpProbeResult = out; });
      out.window_probe_result = "__tallowFpProbeResult";
      return out;
    }
    out.audio_hash = null;
  } catch (e) { out.audio_hash = "errored"; }
  try {
    const detectors = ["Arial", "Courier New", "Times New Roman", "Georgia", "Verdana", "Tahoma", "Trebuchet MS", "Comic Sans MS", "Impact", "Segoe UI", "Calibri", "Cambria", "Fira Sans", "DejaVu Sans", "Liberation Sans", "Noto Sans", "Helvetica Neue", "Menlo", "Consolas", "Roboto"];
    const span = document.createElement("span");
    span.style.fontSize = "72px"; span.style.position = "absolute"; span.style.left = "-9999px";
    span.textContent = "mmmmmmmmmmlli";
    document.body.appendChild(span);
    let n = 0;
    for (const f of detectors) { span.style.fontFamily = "'" + f + "', monospace"; if (span.offsetWidth > 0) n++; }
    span.remove();
    out.fonts_detected = n;
  } catch (e) { out.fonts_detected = 0; }
  try { out.webdriver = !!navigator.webdriver; } catch (e) {}
  try {
    const markers = [];
    if (/HeadlessChrome/i.test(navigator.userAgent)) markers.push("HeadlessChrome");
    if (window.__playwright__ || window.__pw_manual) markers.push("playwright");
    if (window.__webdriver_evaluate || window.__selenium_evaluate) markers.push("selenium");
    if (window.__nightmare) markers.push("nightmare");
    if (window._phantom || window.callPhantom) markers.push("phantom");
    out.headless_markers = markers;
  } catch (e) { out.headless_markers = []; }
  window.__tallowFpProbeResult = out;
  return out;
})()"##;

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

/// Canvas readback state observed in the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanvasReadback {
    /// Readback succeeded (a hash may be present).
    Enabled,
    /// Readback threw or was poisoned — the classic anti-fingerprinting posture.
    Blocked,
    /// The probe could not attempt readback at all.
    Errored,
}

impl CanvasReadback {
    /// The string value carried by the probe.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Blocked => "blocked",
            Self::Errored => "errored",
        }
    }
}

/// Why an observation could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationError {
    /// The payload was not valid JSON / not an object.
    Json(String),
    /// A required attribute was absent.
    Missing(&'static str),
    /// A required attribute had the wrong shape.
    Shape(&'static str),
}

impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "probe payload is not a JSON object: {e}"),
            Self::Missing(k) => write!(f, "probe payload is missing required attribute `{k}`"),
            Self::Shape(k) => write!(f, "probe attribute `{k}` has an unexpected shape"),
        }
    }
}

impl std::error::Error for ObservationError {}

/// What the page reported through [`PROBE_JS`].
///
/// Required fields are those the audit cannot verify alignment without; a
/// payload missing any of them is rejected ([`ObservationError`]) and the
/// caller must treat that as quarantine (fail-closed), not as a pass.
#[derive(Debug, Clone, PartialEq)]
pub struct PageObservation {
    pub probe_version: String,
    pub user_agent: String,
    pub ua_brands: Vec<String>,
    pub ua_mobile: Option<bool>,
    pub ua_platform: Option<String>,
    pub platform: String,
    pub timezone: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: Option<f64>,
    pub max_touch_points: u32,
    pub webgl_vendor: Option<String>,
    pub webgl_renderer: Option<String>,
    pub canvas_readback: CanvasReadback,
    pub canvas_hash: Option<String>,
    pub audio_hash: Option<String>,
    pub fonts_detected: u32,
    pub webdriver: bool,
    pub headless_markers: Vec<String>,
}

impl PageObservation {
    /// Parse the JSON returned by [`PROBE_JS`]. `audio_hash` may arrive later
    /// (offline rendering is async) — callers merge it via
    /// [`Self::with_audio_hash`] when the page reports completion.
    pub fn from_probe_json(payload: &str) -> Result<Self, ObservationError> {
        let v: Value = serde_json::from_str(payload).map_err(|e| ObservationError::Json(e.to_string()))?;
        let obj = v.as_object().ok_or_else(|| ObservationError::Json("not an object".into()))?;

        let str_field = |k: &'static str| -> Result<String, ObservationError> {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(ObservationError::Missing(k))
        };
        let u32_field = |k: &'static str| -> Result<u32, ObservationError> {
            let n = obj.get(k).and_then(Value::as_u64).ok_or(ObservationError::Missing(k))?;
            u32::try_from(n).map_err(|_| ObservationError::Shape(k))
        };

        let user_agent = str_field("user_agent")?;
        let platform = str_field("platform")?;
        let timezone = str_field("timezone")?;
        let hardware_concurrency = u32_field("hardware_concurrency")?;

        let languages: Vec<String> = match obj.get("languages") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(_) => return Err(ObservationError::Shape("languages")),
            None => return Err(ObservationError::Missing("languages")),
        };

        let probe_version = obj
            .get("probe_version")
            .and_then(Value::as_str)
            .unwrap_or("(unversioned)")
            .to_string();

        let ua_brands = match obj.get("ua_brands") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };

        let canvas_readback = match obj.get("canvas_readback").and_then(Value::as_str) {
            Some("enabled") => CanvasReadback::Enabled,
            Some("errored") => CanvasReadback::Errored,
            Some("blocked") => CanvasReadback::Blocked,
            _ => CanvasReadback::Errored,
        };

        let opt_str = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_string);

        Ok(Self {
            probe_version,
            user_agent,
            ua_brands,
            ua_mobile: obj.get("ua_mobile").and_then(Value::as_bool),
            ua_platform: opt_str("ua_platform"),
            platform,
            timezone,
            languages,
            hardware_concurrency,
            device_memory: obj.get("device_memory").and_then(Value::as_f64),
            max_touch_points: obj
                .get("max_touch_points")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0),
            webgl_vendor: opt_str("webgl_vendor"),
            webgl_renderer: opt_str("webgl_renderer"),
            canvas_readback,
            canvas_hash: opt_str("canvas_hash"),
            audio_hash: opt_str("audio_hash"),
            fonts_detected: obj
                .get("fonts_detected")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0),
            webdriver: obj.get("webdriver").and_then(Value::as_bool).unwrap_or(false),
            headless_markers: match obj.get("headless_markers") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            },
        })
    }

    /// Attach the asynchronously-rendered audio hash (probe `audio_hash` =
    /// `"pending"` → caller merges the later result here).
    pub fn with_audio_hash(mut self, audio_hash: impl Into<String>) -> Self {
        self.audio_hash = Some(audio_hash.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Findings + report
// ---------------------------------------------------------------------------

/// Severity of one observed-vs-intended finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationSeverity {
    /// Automation markers or identity drift the page can see — quarantine.
    Critical,
    /// Suspicious drift that should be re-profiled or explained.
    Warning,
    /// Not measured / unverified — never silently treated as a pass.
    Info,
}

/// One observed-vs-intended finding.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservationFinding {
    pub severity: ObservationSeverity,
    /// Stable code (`RFA0xx`) for tests, greps and audit logs.
    pub code: &'static str,
    /// The attribute under test (probe field name).
    pub attribute: &'static str,
    /// What was intended vs what was observed.
    pub detail: String,
}

/// Verdict of a runtime audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    /// No critical findings — the observed surface matched the intended one.
    Allow,
    /// Critical findings (or an unusable probe) — fail closed.
    Quarantine,
}

/// Full runtime audit report: probe findings plus (optionally) the rule-based
/// browser-side [`CoherenceReport`] for the same profile.
#[derive(Debug, Clone)]
pub struct RuntimeAuditReport {
    /// Probe version observed (or `None` when the probe could not be used).
    pub probe_version: Option<String>,
    /// Observation findings, in check order (deterministic).
    pub findings: Vec<ObservationFinding>,
    /// Browser-side rule report (`audit_full` only).
    pub browser: Option<CoherenceReport>,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

impl RuntimeAuditReport {
    fn from_parts(probe_version: Option<String>, findings: Vec<ObservationFinding>, browser: Option<CoherenceReport>) -> Self {
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == ObservationSeverity::Critical)
            .count()
            + browser.as_ref().map(|b| b.critical_count).unwrap_or(0);
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == ObservationSeverity::Warning)
            .count()
            + browser.as_ref().map(|b| b.warning_count).unwrap_or(0);
        let info_count = findings
            .iter()
            .filter(|f| f.severity == ObservationSeverity::Info)
            .count()
            + browser.as_ref().map(|b| b.info_count).unwrap_or(0);
        Self {
            probe_version,
            findings,
            browser,
            critical_count,
            warning_count,
            info_count,
        }
    }

    /// Fail-closed verdict: any critical finding → quarantine.
    pub fn verdict(&self) -> AuditVerdict {
        if self.critical_count > 0 {
            AuditVerdict::Quarantine
        } else {
            AuditVerdict::Allow
        }
    }

    /// Convenience: is this report a quarantine?
    pub fn is_quarantine(&self) -> bool {
        self.verdict() == AuditVerdict::Quarantine
    }

    /// A probe-level quarantine report (payload unparseable / missing fields).
    pub fn unusable(reason: impl Into<String>) -> Self {
        Self::from_parts(
            None,
            vec![ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA000",
                attribute: "probe",
                detail: reason.into(),
            }],
            None,
        )
    }

    /// Deterministic text render (stable ordering, no timestamps).
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "runtime fingerprint audit (row #5 / ag03 R-2a)");
        let _ = writeln!(
            s,
            "probe   : {}",
            self.probe_version.as_deref().unwrap_or("(unusable)")
        );
        let _ = writeln!(
            s,
            "verdict : {:?} (critical {} · warning {} · info {})",
            self.verdict(),
            self.critical_count,
            self.warning_count,
            self.info_count
        );
        for f in &self.findings {
            let _ = writeln!(
                s,
                "  [{}] {} {}: {}",
                match f.severity {
                    ObservationSeverity::Critical => "CRITICAL",
                    ObservationSeverity::Warning => "WARNING ",
                    ObservationSeverity::Info => "INFO    ",
                },
                f.code,
                f.attribute,
                f.detail
            );
        }
        if let Some(b) = &self.browser {
            let _ = writeln!(
                s,
                "browser rule report: score {:.2} (critical {} · warning {} · info {})",
                b.score, b.critical_count, b.warning_count, b.info_count
            );
            for w in &b.warnings {
                let _ = writeln!(s, "  [rule] {:?} {:?}: {}", w.severity, w.vectors, w.message);
            }
        }
        s
    }

    /// Deterministic JSON render (same field order on every run).
    pub fn render_json(&self) -> String {
        let findings: Vec<Value> = self
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "severity": match f.severity {
                        ObservationSeverity::Critical => "critical",
                        ObservationSeverity::Warning => "warning",
                        ObservationSeverity::Info => "info",
                    },
                    "code": f.code,
                    "attribute": f.attribute,
                    "detail": f.detail,
                })
            })
            .collect();
        let browser = self.browser.as_ref().map(|b| {
            serde_json::json!({
                "score": b.score,
                "critical_count": b.critical_count,
                "warning_count": b.warning_count,
                "info_count": b.info_count,
            })
        });
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "tallow.runtime_fingerprint_audit.v1",
            "probe_version": self.probe_version,
            "verdict": match self.verdict() {
                AuditVerdict::Allow => "allow",
                AuditVerdict::Quarantine => "quarantine",
            },
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "findings": findings,
            "browser_rule_report": browser,
        }))
        .expect("report is serializable")
    }
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

/// Empirical runtime fingerprint audit (fail-closed).
pub struct RuntimeFingerprintAudit;

impl RuntimeFingerprintAudit {
    /// Compare one observation against the intended profile. Runs the
    /// observation checks only (no geo/TLS context).
    pub fn audit(profile: &StealthProfile, obs: &PageObservation) -> RuntimeAuditReport {
        Self::audit_full(profile, None, None, obs)
    }

    /// Compare one observation against the intended profile **and** run the
    /// browser-side [`CoherenceValidator`] with the optional geo/TLS context
    /// (R-2(c): the same entry point used at pool/page start).
    pub fn audit_full(
        profile: &StealthProfile,
        geo: Option<&GeoContext>,
        tls: Option<TlsBrowser>,
        obs: &PageObservation,
    ) -> RuntimeAuditReport {
        let mut findings = Vec::new();

        // ── probe provenance ────────────────────────────────────────────────
        if obs.probe_version != PROBE_VERSION {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA016",
                attribute: "probe_version",
                detail: format!(
                    "probe reported `{}` but the audit expects `{PROBE_VERSION}` — field comparisons run against the current schema; re-deploy the probe",
                    obs.probe_version
                ),
            });
        }

        // ── lethal signals: automation markers are never a "pass" ───────────
        if obs.webdriver {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA013",
                attribute: "webdriver",
                detail: "navigator.webdriver is true — the page can read the automation marker".into(),
            });
        }
        if !obs.headless_markers.is_empty() {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA014",
                attribute: "headless_markers",
                detail: format!(
                    "headless/automation markers visible to the page: {}",
                    obs.headless_markers.join(", ")
                ),
            });
        }

        // ── identity: UA / UA-CH / platform ─────────────────────────────────
        if obs.user_agent != profile.user_agent {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA001",
                attribute: "user_agent",
                detail: format!(
                    "intended `{}` but the page saw `{}`",
                    profile.user_agent, obs.user_agent
                ),
            });
        }

        let ua_major = user_agent_major(&obs.user_agent);
        let brands = parse_brands(&obs.ua_brands);
        if profile.is_firefox_profile {
            if !brands.is_empty() {
                findings.push(ObservationFinding {
                    severity: ObservationSeverity::Warning,
                    code: "RFA002",
                    attribute: "ua_brands",
                    detail: format!(
                        "Firefox profile but the page received UA-CH brands {:?}",
                        obs.ua_brands
                    ),
                });
            }
        } else {
            match (&ua_major, brands.iter().find(|(b, _)| b == "Chromium" || b == "Google Chrome")) {
                (Some(want), Some((brand, got))) if got == want => {}
                (Some(want), Some((brand, got))) => findings.push(ObservationFinding {
                    severity: ObservationSeverity::Critical,
                    code: "RFA002",
                    attribute: "ua_brands",
                    detail: format!(
                        "UA claims major `{want}` but UA-CH brand `{brand}` reports `{got}` (version drift between UA string and Client Hints)"
                    ),
                }),
                (_, None) => findings.push(ObservationFinding {
                    severity: ObservationSeverity::Critical,
                    code: "RFA002",
                    attribute: "ua_brands",
                    detail: format!(
                        "Chromium-family profile but the page saw no UA-CH brands (got {:?})",
                        obs.ua_brands
                    ),
                }),
                (None, _) => {}
            }
            match (profile_platform_hint(profile), obs.ua_platform.as_deref()) {
                (Some(want), Some(got)) if want == got => {}
                (Some(want), other) => findings.push(ObservationFinding {
                    severity: ObservationSeverity::Critical,
                    code: "RFA003",
                    attribute: "ua_platform",
                    detail: format!(
                        "profile platform `{}` implies UA-CH platform `{want}` but the page saw {other:?}",
                        profile.platform
                    ),
                }),
                (None, Some(got)) => findings.push(ObservationFinding {
                    severity: ObservationSeverity::Info,
                    code: "RFA003",
                    attribute: "ua_platform",
                    detail: format!("UA-CH platform `{got}` observed; profile declares no platform hint"),
                }),
                (None, None) => findings.push(ObservationFinding {
                    severity: ObservationSeverity::Info,
                    code: "RFA003",
                    attribute: "ua_platform",
                    detail: "UA-CH platform not sent (probe saw null) — unverified".into(),
                }),
            }
        }

        if obs.platform != profile.platform {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA004",
                attribute: "platform",
                detail: format!(
                    "intended navigator.platform `{}` but the page saw `{}`",
                    profile.platform, obs.platform
                ),
            });
        }

        // ── locale / timezone ───────────────────────────────────────────────
        if obs.timezone != profile.timezone {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA005",
                attribute: "timezone",
                detail: format!(
                    "intended timezone `{}` but the page saw `{}`",
                    profile.timezone, obs.timezone
                ),
            });
        }
        if !same_primary_language(&obs.languages, &profile.languages) {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA006",
                attribute: "languages",
                detail: format!(
                    "intended languages {:?} but the page saw {:?}",
                    profile.languages, obs.languages
                ),
            });
        }

        // ── hardware ────────────────────────────────────────────────────────
        if obs.hardware_concurrency != profile.hardware_concurrency {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA007",
                attribute: "hardware_concurrency",
                detail: format!(
                    "intended {} but the page saw {}",
                    profile.hardware_concurrency, obs.hardware_concurrency
                ),
            });
        }
        match obs.device_memory {
            Some(seen) if (seen - profile.device_memory).abs() > f64::EPSILON => {
                findings.push(ObservationFinding {
                    severity: ObservationSeverity::Warning,
                    code: "RFA008",
                    attribute: "device_memory",
                    detail: format!(
                        "intended {} but the page saw {}",
                        profile.device_memory, seen
                    ),
                });
            }
            Some(_) => {}
            None => findings.push(ObservationFinding {
                severity: ObservationSeverity::Info,
                code: "RFA008",
                attribute: "device_memory",
                detail: "navigator.deviceMemory absent (non-Chromium engine or restricted) — unverified".into(),
            }),
        }
        if obs.max_touch_points != profile.max_touch_points {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA009",
                attribute: "max_touch_points",
                detail: format!(
                    "intended {} but the page saw {}",
                    profile.max_touch_points, obs.max_touch_points
                ),
            });
        }

        // ── WebGL / canvas / audio / fonts ──────────────────────────────────
        match (&obs.webgl_renderer, &obs.webgl_vendor) {
            (Some(r), Some(v)) if r == &profile.webgl_renderer && v == &profile.webgl_vendor => {}
            (Some(r), Some(v)) => findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA010",
                attribute: "webgl_renderer",
                detail: format!(
                    "intended `{}` / `{}` but the page saw `{r}` / `{v}` (GPU↔platform drift)",
                    profile.webgl_vendor, profile.webgl_renderer
                ),
            }),
            _ => findings.push(ObservationFinding {
                severity: ObservationSeverity::Info,
                code: "RFA010",
                attribute: "webgl_renderer",
                detail: "WebGL renderer not readable in the page — unverified".into(),
            }),
        }
        match obs.canvas_readback {
            CanvasReadback::Enabled => {
                if obs.canvas_hash.as_deref().unwrap_or("").is_empty() {
                    findings.push(ObservationFinding {
                        severity: ObservationSeverity::Warning,
                        code: "RFA012",
                        attribute: "canvas_hash",
                        detail: "readback reported enabled but no canvas hash was captured".into(),
                    });
                }
            }
            CanvasReadback::Blocked => findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA011",
                attribute: "canvas_readback",
                detail: "canvas readback is blocked (or poisoned) in the page — verify this matches the declared posture".into(),
            }),
            CanvasReadback::Errored => findings.push(ObservationFinding {
                severity: ObservationSeverity::Critical,
                code: "RFA011",
                attribute: "canvas_readback",
                detail: "canvas readback errored in the page — the declared profile expects a readable canvas".into(),
            }),
        }
        match obs.audio_hash.as_deref() {
            Some("errored") => findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA017",
                attribute: "audio_hash",
                detail: "audio fingerprint probe errored — audio surface differs from the profile".into(),
            }),
            Some("pending") | None => findings.push(ObservationFinding {
                severity: ObservationSeverity::Info,
                code: "RFA017",
                attribute: "audio_hash",
                detail: "audio hash not captured (async render not yet merged) — unverified".into(),
            }),
            Some(_) => {}
        }
        if obs.fonts_detected == 0 {
            findings.push(ObservationFinding {
                severity: ObservationSeverity::Warning,
                code: "RFA015",
                attribute: "fonts_detected",
                detail: "font detector set resolved to zero fonts — container/headless font drift".into(),
            });
        }

        let browser = match geo {
            Some(g) => Some(CoherenceValidator::validate(profile, g, tls)),
            None => None,
        };
        RuntimeAuditReport::from_parts(Some(obs.probe_version.clone()), findings, browser)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Major version of the browser in a UA string (`"Chromium/151.0" → 151`).
fn user_agent_major(ua: &str) -> Option<String> {
    for token in ["Chrome/", "Chromium/", "Firefox/"] {
        if let Some(idx) = ua.find(token) {
            let rest = &ua[idx + token.len()..];
            let major: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !major.is_empty() {
                return Some(major);
            }
        }
    }
    None
}

/// Parse `"Chromium:151"` brand strings into `(brand, version)` pairs.
fn parse_brands(brands: &[String]) -> Vec<(String, String)> {
    brands
        .iter()
        .filter_map(|b| {
            let (name, version) = b.split_once(':')?;
            Some((name.to_string(), version.split('.').next().unwrap_or("").to_string()))
        })
        .collect()
}

/// The UA-CH `platform` value implied by `navigator.platform`.
fn profile_platform_hint(profile: &StealthProfile) -> Option<&'static str> {
    match profile.platform.as_str() {
        "Win32" | "Win64" => Some("Windows"),
        "MacIntel" => Some("macOS"),
        p if p.starts_with("Linux") => Some("Linux"),
        p if p.contains("Android") => Some("Android"),
        p if p.contains("iPhone") || p.contains("iPad") => Some("iOS"),
        _ => None,
    }
}

/// Compare primary languages by base tag (`en-US` ≈ `en`) so regional variants
/// are a warning only when the base language itself differs.
fn same_primary_language(observed: &[String], intended: &[String]) -> bool {
    match (observed.first(), intended.first()) {
        (Some(a), Some(b)) => base_language(a) == base_language(b),
        (None, None) => true,
        _ => false,
    }
}

fn base_language(tag: &str) -> String {
    tag.split(['-', '_']).next().unwrap_or("").to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// An observation that matches `chrome_windows()` exactly.
    fn coherent_observation() -> PageObservation {
        let p = StealthProfile::chrome_windows();
        PageObservation {
            probe_version: PROBE_VERSION.to_string(),
            user_agent: p.user_agent.clone(),
            ua_brands: vec![
                "Chromium:151".to_string(),
                "Google Chrome:151".to_string(),
                "Not_A Brand:99".to_string(),
            ],
            ua_mobile: Some(false),
            ua_platform: Some("Windows".to_string()),
            platform: p.platform.clone(),
            timezone: p.timezone.clone(),
            languages: p.languages.clone(),
            hardware_concurrency: p.hardware_concurrency,
            device_memory: Some(p.device_memory),
            max_touch_points: p.max_touch_points,
            webgl_vendor: Some(p.webgl_vendor.clone()),
            webgl_renderer: Some(p.webgl_renderer.clone()),
            canvas_readback: CanvasReadback::Enabled,
            canvas_hash: Some("deadbeef".to_string()),
            audio_hash: Some("0.123456".to_string()),
            fonts_detected: 14,
            webdriver: false,
            headless_markers: Vec::new(),
        }
    }

    #[test]
    fn coherent_observation_allows_with_zero_findings() {
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &coherent_observation());
        assert_eq!(report.verdict(), AuditVerdict::Allow, "{}", report.render_text());
        assert_eq!(report.critical_count, 0);
        assert_eq!(report.warning_count, 0, "{}", report.render_text());
        assert_eq!(report.info_count, 0, "{}", report.render_text());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn user_agent_drift_is_critical_rfa001() {
        let mut obs = coherent_observation();
        obs.user_agent = obs.user_agent.replace("Chrome/151", "Chrome/152");
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA001" && f.severity == ObservationSeverity::Critical));
    }

    #[test]
    fn ua_ch_version_drift_is_critical_rfa002() {
        let mut obs = coherent_observation();
        obs.ua_brands = vec!["Chromium:150".to_string(), "Google Chrome:150".to_string()];
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA002"));
    }

    #[test]
    fn missing_ua_ch_brands_on_chromium_profile_is_critical() {
        let mut obs = coherent_observation();
        obs.ua_brands.clear();
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA002"));
    }

    #[test]
    fn timezone_drift_is_critical_rfa005() {
        let mut obs = coherent_observation();
        obs.timezone = "Europe/Berlin".to_string();
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA005"));
    }

    #[test]
    fn platform_drift_is_critical_rfa004() {
        let mut obs = coherent_observation();
        obs.platform = "Linux x86_64".to_string();
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA004"));
    }

    #[test]
    fn ua_platform_drift_is_critical_rfa003() {
        let mut obs = coherent_observation();
        obs.ua_platform = Some("Linux".to_string());
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA003"));
    }

    #[test]
    fn webgl_renderer_drift_is_critical_rfa010() {
        let mut obs = coherent_observation();
        obs.webgl_renderer = Some("ANGLE (Intel, Intel UHD 620, OpenGL 4.5)".to_string());
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA010"));
    }

    #[test]
    fn webdriver_and_headless_markers_quarantine() {
        let mut obs = coherent_observation();
        obs.webdriver = true;
        obs.headless_markers = vec!["HeadlessChrome".to_string()];
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.is_quarantine());
        assert!(report.findings.iter().any(|f| f.code == "RFA013"));
        assert!(report.findings.iter().any(|f| f.code == "RFA014"));
    }

    #[test]
    fn blocked_canvas_is_a_warning_and_zero_fonts_warns() {
        let mut obs = coherent_observation();
        obs.canvas_readback = CanvasReadback::Blocked;
        obs.canvas_hash = None;
        obs.fonts_detected = 0;
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert_eq!(report.verdict(), AuditVerdict::Allow, "{}", report.render_text());
        assert!(report.findings.iter().any(|f| f.code == "RFA011" && f.severity == ObservationSeverity::Warning));
        assert!(report.findings.iter().any(|f| f.code == "RFA015"));
        // No raw canvas-hash warning when readback is blocked (the block is the finding).
        assert!(!report.findings.iter().any(|f| f.code == "RFA012"));
    }

    #[test]
    fn absent_optional_fields_are_info_never_silent() {
        let mut obs = coherent_observation();
        obs.device_memory = None;
        obs.audio_hash = None;
        obs.ua_platform = None;
        obs.webgl_renderer = None;
        obs.webgl_vendor = None;
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        let infos: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.severity == ObservationSeverity::Info)
            .map(|f| f.code)
            .collect();
        for code in ["RFA008", "RFA017", "RFA010"] {
            assert!(infos.contains(&code), "expected {code} among infos: {:?}", infos);
        }
        // UA-CH platform null on a Chromium profile is a critical (platform hint implied).
        assert!(report.findings.iter().any(|f| f.code == "RFA003"));
        assert!(report.is_quarantine());
    }

    #[test]
    fn probe_version_mismatch_warns_but_does_not_pass_silently() {
        let mut obs = coherent_observation();
        obs.probe_version = "tallow.fp_probe.v0".to_string();
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert!(report.findings.iter().any(|f| f.code == "RFA016"));
    }

    #[test]
    fn unusable_probe_quarantines_fail_closed() {
        let report = RuntimeAuditReport::unusable("probe payload missing `timezone`");
        assert!(report.is_quarantine());
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.findings[0].code, "RFA000");
    }

    #[test]
    fn probe_json_roundtrip_matches_probe_script_contract() {
        let payload = r#"{
            "probe_version": "tallow.fp_probe.v1",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
            "ua_brands": ["Chromium:151", "Google Chrome:151"],
            "ua_mobile": false,
            "ua_platform": "Windows",
            "platform": "Win32",
            "timezone": "America/New_York",
            "languages": ["en-US", "en"],
            "hardware_concurrency": 8,
            "device_memory": 8.0,
            "max_touch_points": 0,
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "canvas_hash": "abc123",
            "canvas_readback": "enabled",
            "audio_hash": "pending",
            "fonts_detected": 14,
            "webdriver": false,
            "headless_markers": []
        }"#;
        let obs = PageObservation::from_probe_json(payload).expect("payload parses");
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert_eq!(report.verdict(), AuditVerdict::Allow, "{}", report.render_text());
        // `audio_hash: "pending"` is unverified, never a silent pass.
        assert!(report.findings.iter().any(|f| f.code == "RFA017"));
    }

    #[test]
    fn probe_json_missing_required_field_is_an_error() {
        let err = PageObservation::from_probe_json(r#"{"user_agent":"x"}"#).unwrap_err();
        assert!(matches!(err, ObservationError::Missing(_)), "{err:?}");
        let err = PageObservation::from_probe_json("not json").unwrap_err();
        assert!(matches!(err, ObservationError::Json(_)), "{err:?}");
    }

    #[test]
    fn renderers_are_deterministic() {
        let mut obs = coherent_observation();
        obs.webdriver = true;
        let a = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        let b = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &obs);
        assert_eq!(a.render_text(), b.render_text());
        assert_eq!(a.render_json(), b.render_json());
        let json: serde_json::Value = serde_json::from_str(&a.render_json()).unwrap();
        assert_eq!(json["schema"], "tallow.runtime_fingerprint_audit.v1");
        assert_eq!(json["verdict"], "quarantine");
    }

    #[test]
    fn probe_script_contract_covers_required_attributes() {
        for needle in [
            "probe_version",
            "user_agent",
            "ua_brands",
            "ua_platform",
            "platform",
            "timezone",
            "languages",
            "hardware_concurrency",
            "device_memory",
            "max_touch_points",
            "webgl_renderer",
            "canvas_readback",
            "canvas_hash",
            "audio_hash",
            "fonts_detected",
            "webdriver",
            "headless_markers",
        ] {
            assert!(PROBE_JS.contains(needle), "probe script must report `{needle}`");
        }
        assert!(PROBE_JS.contains(PROBE_VERSION));
    }

    #[test]
    fn audit_full_merges_rule_and_observation_findings() {
        let profile = StealthProfile::chrome_windows();
        let geo = GeoContext::us_residential("New York", "NY", "America/New_York");
        let mut obs = coherent_observation();
        obs.timezone = "Europe/Berlin".to_string();
        let report = RuntimeFingerprintAudit::audit_full(
            &profile,
            Some(&geo),
            Some(TlsBrowser::Chrome),
            &obs,
        );
        assert!(report.is_quarantine());
        assert!(report.browser.is_some(), "browser rule report must be merged");
        assert!(report.findings.iter().any(|f| f.code == "RFA005"));
    }

    #[test]
    fn audit_without_context_has_no_rule_report() {
        let report = RuntimeFingerprintAudit::audit(&StealthProfile::chrome_windows(), &coherent_observation());
        assert!(report.browser.is_none());
    }
}
