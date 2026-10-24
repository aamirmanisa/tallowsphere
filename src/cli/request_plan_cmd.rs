//! `tallow run-plan` — execute (or preflight) a `tallow.request_plan.v1` plan
//! against a `tallow.target_manifest.v2` source manifest.
//!
//! The verb exists so a scraper run can be reviewed, blocked and audited before
//! a socket is opened. Every refusal is *reported*, not raised: stdout is a JSON
//! run report with a `blocked_reasons` entry per request, and the process exits
//! `2`. A blocked plan is a successful run of the gate stack — the exit code
//! separates "the gate said no" from "the tool crashed".
//!
//! Exit codes: `0` passed, `2` blocked or failed, `64` usage error.
//!
//! `--network-scope` selects how far the run may go:
//!
//! * `local` (alias `dry-run`) — evaluate the plan and policy, open nothing.
//! * `live-preflight` — evaluate every live gate (approval, compliance report,
//!   header hygiene, isolation), report `policy_preflight_passed`, open nothing.
//! * `live` — same gates, then one GET per request. Requires `--approve-live`
//!   and a compliance gate report bound to the source manifest's sha256.
//!
//! This module is the only CLI path allowed to name
//! [`crate::request_plan::execute_get`]; [`crate::cli::plan_cmd`] is the
//! never-egress dry-run verb and asserts structurally that it does not.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Map, Value};

const EXIT_OK: i32 = 0;
const EXIT_BLOCKED: i32 = 2;
const EXIT_USAGE: i32 = 64;

const PLAN_SCHEMA: &str = "tallow.request_plan.v1";
const MANIFEST_SCHEMA_V2: &str = "tallow.target_manifest.v2";
const COMPLIANCE_SCHEMA: &str = "tallow.compliance_gate_report.v1";
const ARTIFACT_MANIFEST_SCHEMA: &str = "tallow.artifact_manifest.v1";
const RUN_REPORT_SCHEMA: &str = "tallow.request_plan_run_report.v1";
const EXECUTION_CONTRACT_SCHEMA: &str = "tallow.request_plan_execution_contract.v1";
const EXECUTION_CORE_VERSION: &str = "request-plan-execution-core-v1";
const RUNNER: &str = "tallow-native-run-plan";

// ─────────────────────────────── arguments ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Local,
    LivePreflight,
    Live,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Scope::Local => "local",
            Scope::LivePreflight => "live-preflight",
            Scope::Live => "live",
        }
    }

    fn is_live_state(self) -> bool {
        self != Scope::Local
    }
}

struct Args {
    plan_path: PathBuf,
    output_dir: PathBuf,
    policy: String,
    compliance_report: Option<PathBuf>,
    scope: Scope,
    approve_live: bool,
    dry_run_flag: bool,
}

impl Args {
    /// True when the run must not touch a socket even if the scope says live.
    fn dry_run(&self) -> bool {
        self.dry_run_flag || self.scope == Scope::Local
    }

    /// Live-shaped gates apply to `live-preflight` and `live`, but not when
    /// `--dry-run` downgrades the run.
    fn live_gates(&self) -> bool {
        self.scope.is_live_state() && !self.dry_run_flag
    }
}

fn usage() {
    eprintln!(
        "usage: tallow run-plan (--plan <FILE> | <FILE>) --output-dir <DIR> \
         [--network-scope local|live-preflight|live] [--policy <NAME>] [--dry-run] \
         [--approve-live --compliance-gate-report <REPORT>]"
    );
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut plan_path: Option<PathBuf> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut policy = "default".to_string();
    let mut compliance_report: Option<PathBuf> = None;
    let mut scope = Scope::Local;
    let mut approve_live = false;
    let mut dry_run_flag = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        let mut take = |name: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--plan" => plan_path = Some(PathBuf::from(take("--plan")?)),
            "--output-dir" => output_dir = Some(PathBuf::from(take("--output-dir")?)),
            "--policy" => policy = take("--policy")?,
            "--compliance-gate-report" => {
                compliance_report = Some(PathBuf::from(take("--compliance-gate-report")?))
            }
            "--network-scope" => {
                let v = take("--network-scope")?;
                scope = match v.as_str() {
                    "local" | "dry-run" => Scope::Local,
                    "live-preflight" => Scope::LivePreflight,
                    "live" => Scope::Live,
                    other => {
                        return Err(format!(
                            "--network-scope must be local, live-preflight or live, got {other:?}"
                        ))
                    }
                };
            }
            "--approve-live" => approve_live = true,
            "--dry-run" => dry_run_flag = true,
            "-h" | "--help" => return Err(String::new()),
            other if other.starts_with('-') => return Err(format!("unknown flag {other:?}")),
            other => {
                if plan_path.is_some() {
                    return Err(format!("unexpected extra positional argument {other:?}"));
                }
                plan_path = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    Ok(Args {
        plan_path: plan_path.ok_or_else(|| "a plan path is required (--plan <FILE>)".to_string())?,
        output_dir: output_dir.unwrap_or_else(|| PathBuf::from("run-artifacts")),
        policy,
        compliance_report,
        scope,
        approve_live,
        dry_run_flag,
    })
}

// ──────────────────────────────── manifest ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct PlanFile {
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    manifest_id: String,
    #[serde(default)]
    request_count: Option<usize>,
    #[serde(default)]
    requests: Vec<Value>,
    /// Plan-level source manifest attachment: the plan cannot be trusted unless
    /// the manifest it was built from is present and byte-identical.
    #[serde(default)]
    source_manifest: Option<SourceManifestRef>,
}

#[derive(Debug, Deserialize, Clone)]
struct SourceManifestRef {
    #[serde(default)]
    path: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    schema_version: String,
}

#[derive(Debug, Default, Clone)]
struct Request {
    index: i64,
    target_id: String,
    url: String,
    method: String,
    headers: BTreeMap<String, Value>,
    auth_ref: Option<String>,
    browser_fallback: Option<Value>,
    artifact_policy: Option<Value>,
}

fn request_from_value(v: &Value) -> Request {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Request {
        index: v.get("index").and_then(Value::as_i64).unwrap_or(0),
        target_id: s("target_id"),
        url: s("url"),
        method: s("method"),
        headers: v
            .get("headers")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default(),
        auth_ref: v.get("auth_ref").and_then(Value::as_str).map(str::to_string),
        browser_fallback: v.get("browser_fallback").cloned(),
        artifact_policy: v.get("artifact_policy").cloned(),
    }
}

// ───────────────────────────────── report ───────────────────────────────────

#[derive(Debug, Clone)]
struct BlockedReason {
    code: &'static str,
    message: String,
}

impl BlockedReason {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn to_json(&self) -> Value {
        json!({"code": self.code, "message": self.message})
    }
}

/// The canonical error object every blocked request carries. `kind` is drawn
/// from the tree-wide error taxonomy so a consumer can classify a refusal
/// without parsing prose.
fn canonical_error(
    kind: &str,
    message: &str,
    retryable: bool,
    target_id: &str,
    url: &str,
    phase: &str,
) -> Value {
    json!({
        "kind": kind,
        "message": message,
        "retryable": retryable,
        "policy_blocked": true,
        "source_target_id": target_id,
        "url": url,
        "phase": phase,
    })
}

struct Report {
    manifest_id: String,
    scope: Scope,
    policy: String,
    dry_run: bool,
    requests: Vec<Map<String, Value>>,
    unsupported: Vec<Value>,
    vault_refs: Vec<Value>,
    executed: usize,
    succeeded: usize,
}

impl Report {
    fn new(plan: &PlanFile, args: &Args) -> Self {
        Self {
            manifest_id: plan.manifest_id.clone(),
            scope: args.scope,
            policy: args.policy.clone(),
            dry_run: args.dry_run(),
            requests: Vec::new(),
            unsupported: Vec::new(),
            vault_refs: Vec::new(),
            executed: 0,
            succeeded: 0,
        }
    }

    fn count(&self, status: &str) -> usize {
        self.requests
            .iter()
            .filter(|r| r.get("status").and_then(Value::as_str) == Some(status))
            .count()
    }

    fn blocked(&self) -> usize {
        self.count("blocked")
    }

    fn passed(&self) -> bool {
        self.blocked() == 0 && self.count("failed") == 0
    }

    fn to_json(&self) -> Value {
        json!({
            "schema_version": RUN_REPORT_SCHEMA,
            "runner": RUNNER,
            "manifest_id": self.manifest_id,
            "network_scope": self.scope.as_str(),
            "policy": self.policy,
            "dry_run": self.dry_run,
            "passed": self.passed(),
            "execution_core": {
                "schema_version": EXECUTION_CONTRACT_SCHEMA,
                "version": EXECUTION_CORE_VERSION,
                "role": "native_cli_bridge",
            },
            "summary": {
                "total": self.requests.len(),
                "planned": self.count("planned"),
                "executed": self.executed,
                "succeeded": self.succeeded,
                "blocked": self.blocked(),
            },
            "requests": self.requests,
            "unsupported_reasons": self.unsupported,
            "vault_resolution": {
                "resolver": "fake_local_reference_only",
                "references_total": self.vault_refs.len(),
                "references": self.vault_refs,
                "no_secret_material_resolved": true,
                "secret_material_serialized": false,
                "auth_ref_serialized": false,
                "real_vault_contacted": false,
            },
            "browser_fallback": {
                "pipe_transport": "fail_closed",
                "websocket_cdp": "not_implemented",
            },
            "non_claims": {
                "live_external_scraping": self.executed > 0,
                "browser_execution": false,
                "real_vault_contacted": false,
                "production_compliance_readiness": false,
            },
        })
    }

    fn exit_code(&self) -> i32 {
        if self.passed() {
            EXIT_OK
        } else {
            EXIT_BLOCKED
        }
    }
}

// ───────────────────────────────── helpers ──────────────────────────────────

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn redaction_marker(bytes: &[u8]) -> String {
    format!("<redacted:sha256:{}>", sha256_hex(bytes))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| format!("{}: not JSON: {e}", path.display()))
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Prefix-glob: `*` matches any run of characters, everything else is literal.
fn url_matches(pattern: &str, url: &str) -> bool {
    let pv: Vec<char> = pattern.chars().collect();
    let uv: Vec<char> = url.chars().collect();
    let (mut pi, mut ui) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ui < uv.len() {
        if pi < pv.len() && pv[pi] == uv[ui] {
            pi += 1;
            ui += 1;
        } else if pi < pv.len() && pv[pi] == '*' {
            star = Some(pi);
            mark = ui;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ui = mark;
        } else {
            return false;
        }
    }
    while pi < pv.len() && pv[pi] == '*' {
        pi += 1;
    }
    pi == pv.len()
}

fn header_is_sensitive(name: &str, value: &Value) -> bool {
    let lname = name.to_ascii_lowercase();
    if matches!(
        lname.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
    ) {
        return true;
    }
    if lname.contains("token") || lname.contains("secret") || lname.contains("password") {
        return true;
    }
    let raw = value.as_str().unwrap_or("");
    raw.starts_with("Bearer ")
        || raw.starts_with("Basic ")
        || (raw.len() >= 20
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=')))
}

fn vault_provider(auth_ref: &str) -> Option<&str> {
    auth_ref.strip_prefix("vault://")?.split('/').next()
}

fn artifacts_capture(policy: &Value) -> bool {
    let Some(obj) = policy.as_object() else {
        return false;
    };
    for key in ["screenshots", "har", "dom"] {
        match obj.get(key) {
            Some(Value::Bool(true)) => return true,
            Some(Value::String(s)) if s != "never" => return true,
            _ => {}
        }
    }
    false
}

fn browser_fallback_enabled(fallback: &Value) -> bool {
    fallback
        .get("mode")
        .and_then(Value::as_str)
        .map(|m| m != "never")
        .unwrap_or(false)
}

// ───────────────────────────────── gates ────────────────────────────────────

fn load_compliance(
    manifest_sha: Option<&str>,
    path: Option<&Path>,
) -> Option<BlockedReason> {
    let Some(path) = path else {
        return Some(BlockedReason::new(
            "compliance_gate_report_required",
            "live gates need --compliance-gate-report",
        ));
    };
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) => {
            return Some(BlockedReason::new(
                "compliance_gate_report_invalid",
                format!("cannot read the compliance gate report: {e}"),
            ))
        }
    };
    let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
        return Some(BlockedReason::new(
            "compliance_gate_report_invalid",
            "the compliance gate report is not JSON",
        ));
    };
    if value.get("schema_version").and_then(Value::as_str) != Some(COMPLIANCE_SCHEMA) {
        return Some(BlockedReason::new(
            "compliance_gate_report_invalid",
            format!("schema_version must be {COMPLIANCE_SCHEMA}"),
        ));
    }
    let bound = value
        .get("target_manifest")
        .and_then(|m| m.get("sha256"))
        .and_then(Value::as_str);
    match (bound, manifest_sha) {
        (Some(want), Some(have)) if want == have => None,
        (Some(_), Some(_)) => Some(BlockedReason::new(
            "compliance_gate_report_invalid",
            "the compliance gate report is bound to a different source manifest",
        )),
        _ => Some(BlockedReason::new(
            "compliance_gate_report_invalid",
            "the compliance gate report does not name the source manifest sha256",
        )),
    }
}

fn load_source_manifest(
    plan: &PlanFile,
) -> (Option<Value>, Option<BlockedReason>, Option<String>) {
    let Some(reference) = plan.source_manifest.clone() else {
        return (None, None, None);
    };
    let path = PathBuf::from(&reference.path);
    if !path.exists() {
        return (
            None,
            Some(BlockedReason::new(
                "source_manifest_missing",
                "the plan names a source manifest that does not exist",
            )),
            None,
        );
    }
    if !path.is_file() {
        return (
            None,
            Some(BlockedReason::new(
                "source_manifest_invalid",
                "the plan's source manifest path is not a file",
            )),
            None,
        );
    }
    let raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(e) => {
            return (
                None,
                Some(BlockedReason::new(
                    "source_manifest_invalid",
                    format!("cannot read the source manifest: {e}"),
                )),
                None,
            )
        }
    };
    let digest = sha256_hex(&raw);
    if !reference.sha256.is_empty() && reference.sha256 != digest {
        return (
            None,
            Some(BlockedReason::new(
                "source_manifest_sha_mismatch",
                "the source manifest does not match the sha256 recorded in the plan",
            )),
            None,
        );
    }
    let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
        return (
            None,
            Some(BlockedReason::new(
                "source_manifest_invalid",
                "the source manifest is not JSON",
            )),
            None,
        );
    };
    if value.get("schema_version").and_then(Value::as_str) != Some(MANIFEST_SCHEMA_V2) {
        return (
            None,
            Some(BlockedReason::new(
                "source_manifest_invalid",
                format!("the source manifest is not {MANIFEST_SCHEMA_V2}"),
            )),
            None,
        );
    }
    (Some(value), None, Some(digest))
}

fn policy_denied(manifest: &Value, url: &str) -> Option<&'static str> {
    let policy = manifest.get("policy")?;
    let authority = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    // Manifest domains are hostnames; the URL authority carries a port.
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(authority);

    let hit = |list: &Value| -> bool {
        let domains = list
            .get("domains")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let patterns = list
            .get("url_patterns")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        domains.iter().any(|d| d.as_str() == Some(host))
            || patterns
                .iter()
                .any(|p| p.as_str().is_some_and(|p| url_matches(p, url)))
    };

    if policy.get("denylist").is_some_and(hit) {
        return Some("policy_denylist");
    }
    if let Some(allow) = policy.get("allowlist") {
        let has_rules = allow
            .get("domains")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
            || allow
                .get("url_patterns")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty());
        if has_rules && !hit(allow) {
            return Some("policy_not_allowlisted");
        }
    }
    None
}

// ─────────────────────────────── entry point ────────────────────────────────

/// `tallow run-plan …` — returns the process exit code.
pub fn run_plan_args(args: &[String]) -> i32 {
    let args = match parse_args(args) {
        Ok(a) => a,
        Err(msg) if msg.is_empty() => {
            usage();
            return EXIT_OK;
        }
        Err(msg) => {
            eprintln!("run-plan: {msg}");
            usage();
            return EXIT_USAGE;
        }
    };

    match run_plan(&args) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report.to_json()).unwrap()
            );
            report.exit_code()
        }
        Err(msg) => {
            eprintln!("run-plan: {msg}");
            EXIT_USAGE
        }
    }
}

fn run_plan(args: &Args) -> Result<Report, String> {
    let plan_value = read_json(&args.plan_path)?;
    let plan: PlanFile = serde_json::from_value(plan_value.clone())
        .map_err(|e| format!("{}: not a {PLAN_SCHEMA} plan: {e}", args.plan_path.display()))?;

    if plan.schema_version != PLAN_SCHEMA {
        return Err(format!(
            "{}: schema_version must be {PLAN_SCHEMA}, got {:?}",
            args.plan_path.display(),
            plan.schema_version
        ));
    }
    if let Some(declared) = plan.request_count {
        if declared != plan.requests.len() {
            return Err(format!(
                "{}: request_count is {declared} but the plan holds {} requests",
                args.plan_path.display(),
                plan.requests.len()
            ));
        }
    }

    let (manifest, manifest_problem, manifest_sha) = load_source_manifest(&plan);
    let live_gates = args.live_gates();
    let compliance_problem = if live_gates {
        load_compliance(manifest_sha.as_deref(), args.compliance_report.as_deref())
    } else {
        None
    };
    let isolated_output = !args.output_dir.exists()
        || std::fs::read_dir(&args.output_dir)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);

    let mut report = Report::new(&plan, args);
    let requests: Vec<Request> = plan.requests.iter().map(request_from_value).collect();

    for req in &requests {
        let mut row = Map::new();
        row.insert("index".into(), json!(req.index));
        row.insert("target_id".into(), json!(req.target_id));
        row.insert("url".into(), json!(req.url));
        row.insert("original_url".into(), json!(req.url));
        row.insert("method".into(), json!(req.method));
        row.insert("auth_ref_present".into(), json!(req.auth_ref.is_some()));

        let mut reasons: Vec<BlockedReason> = Vec::new();
        let mut unsupported: Option<Value> = None;

        // 1 · shape checks that no later gate can trust over
        if let Some(fallback) = &req.browser_fallback {
            // `mode` is the discriminator the runtime switches on; a boolean or
            // a missing key is malformed, not "off".
            if !fallback.is_object()
                || !fallback.get("mode").is_some_and(Value::is_string)
            {
                reasons.push(BlockedReason::new(
                    "invalid_browser_fallback",
                    "browser_fallback must be an object with a string `mode`",
                ));
            }
        }
        if let Some(policy) = &req.artifact_policy {
            if !policy.is_object() {
                reasons.push(BlockedReason::new(
                    "invalid_artifact_policy",
                    "artifact_policy must be an object",
                ));
            }
        }

        // 2 · url scheme
        if !is_http_url(&req.url) {
            unsupported = Some(json!({
                "code": "invalid_url",
                "message": "only http(s) URLs are executable",
                "index": req.index,
                "target_id": req.target_id,
            }));
        }

        // 3 · method — POST has no native live path yet
        if !req.method.is_empty() && !req.method.eq_ignore_ascii_case("GET") {
            if args.dry_run() {
                unsupported.get_or_insert(json!({
                    "code": "unsupported_method",
                    "message": format!("method {} has no native live path", req.method),
                    "index": req.index,
                    "target_id": req.target_id,
                }));
            } else {
                reasons.push(BlockedReason::new(
                    "live_method_not_enabled",
                    format!(
                        "method {} has no native live path yet; only GET executes",
                        req.method
                    ),
                ));
            }
        }

        // 4 · approval
        if args.scope == Scope::Live && !args.dry_run_flag && !args.approve_live {
            reasons.push(BlockedReason::new(
                "live_approval_required",
                "live execution requires --approve-live",
            ));
        }

        // 5 · compliance gate report
        if let Some(problem) = &compliance_problem {
            reasons.push(problem.clone());
        }

        // 6 · header hygiene — values are never echoed back
        let sensitive: Vec<&str> = req
            .headers
            .iter()
            .filter(|(k, v)| header_is_sensitive(k, v))
            .map(|(k, _)| k.as_str())
            .collect();
        if !sensitive.is_empty() {
            reasons.push(BlockedReason::new(
                "sensitive_header",
                format!(
                    "literal secret in header(s) {}; use auth_ref so the value never enters the plan",
                    sensitive.join(", ")
                ),
            ));
        }

        // 7 · output isolation
        if args.scope == Scope::Live && !isolated_output {
            reasons.push(BlockedReason::new(
                "live_output_dir_not_isolated",
                "the output directory already holds files; a live run needs a fresh directory",
            ));
        }

        // 8 · source manifest
        if let Some(problem) = &manifest_problem {
            reasons.push(problem.clone());
        }

        // 9 · manifest policy
        if let Some(manifest) = &manifest {
            if let Some(code) = policy_denied(manifest, &req.url) {
                reasons.push(BlockedReason::new(
                    code,
                    "the source manifest policy refuses this URL",
                ));
            }
        }

        // 10 · browser fallback: declared but not wired
        if let Some(fallback) = &req.browser_fallback {
            if browser_fallback_enabled(fallback) {
                reasons.push(BlockedReason::new(
                    "live_browser_fallback_not_enabled",
                    "browser fallback is not wired into the native live path",
                ));
            }
        }
        if let Some(policy) = &req.artifact_policy {
            if artifacts_capture(policy) {
                reasons.push(BlockedReason::new(
                    "browser_artifact_capture_not_enabled",
                    "browser artifact capture is not wired into the native live path",
                ));
            }
        }

        // 11 · vault references — hashed metadata only
        if let Some(auth_ref) = &req.auth_ref {
            let provider = vault_provider(auth_ref).unwrap_or("").to_string();
            let hash = sha256_hex(auth_ref.as_bytes());
            let accepted = provider == "local";
            let status = if accepted {
                "accepted_local_reference"
            } else {
                "unsupported_provider_fail_closed"
            };
            report.vault_refs.push(json!({
                "provider_id": provider,
                "resolution_status": status,
                "reference_hash": hash,
                "secret_material_serialized": false,
                "auth_ref_serialized": false,
                "real_vault_contacted": false,
            }));
            row.insert(
                "vault_reference".into(),
                json!({
                    "provider_id": provider,
                    "reference_hash": hash,
                    "resolution_status": status,
                }),
            );
            if !accepted {
                reasons.push(BlockedReason::new(
                    "unsupported_vault_provider",
                    "only vault://local references resolve without contacting a vault",
                ));
            }
        }

        if let Some(unsupported) = unsupported {
            report.unsupported.push(unsupported);
            row.insert("status".into(), json!("blocked"));
            row.insert(
                "blocked_reasons".into(),
                Value::Array(reasons.iter().map(BlockedReason::to_json).collect()),
            );
            row.insert(
                "error".into(),
                canonical_error(
                    "invalid_url",
                    "the request cannot be executed as written",
                    false,
                    &req.target_id,
                    &req.url,
                    "request_policy",
                ),
            );
            report.requests.push(row);
            continue;
        }

        if !reasons.is_empty() {
            row.insert("status".into(), json!("blocked"));
            row.insert(
                "blocked_reasons".into(),
                Value::Array(reasons.iter().map(BlockedReason::to_json).collect()),
            );
            row.insert(
                "error".into(),
                canonical_error(
                    "robots_policy",
                    &reasons[0].message,
                    false,
                    &req.target_id,
                    &req.url,
                    "request_policy",
                ),
            );
            report.requests.push(row);
            continue;
        }

        if args.scope == Scope::Live && !args.dry_run_flag {
            execute_and_record(&mut report, &mut row, req);
        } else if args.scope == Scope::LivePreflight {
            row.insert("status".into(), json!("policy_preflight_passed"));
        } else {
            row.insert("status".into(), json!("planned"));
        }
        report.requests.push(row);
    }

    if args.scope == Scope::Live && !args.dry_run_flag && report.blocked() == 0 {
        if let Err(e) = write_artifacts(args, &plan_value, &requests, &mut report) {
            return Err(format!("cannot write run artifacts: {e}"));
        }
    }

    Ok(report)
}

/// True for destinations that never leave the box. Loopback traffic is not
/// egress, so it takes a direct socket instead of the proxy plane — otherwise a
/// configured Tor SOCKS endpoint would refuse every local fixture with
/// "connection not allowed by ruleset".
fn is_loopback_url(url: &str) -> bool {
    let Some(rest) = url.split("://").nth(1) else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(authority);
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
        || host.starts_with("127.")
}

/// A minimal HTTP/1.1 GET for loopback targets. Deliberately small: one
/// request, `Connection: close`, read to EOF. It exists so the live path can be
/// exercised without a proxy, and it refuses anything that is not a plain
/// loopback http URL.
fn loopback_get(url: &str) -> (Option<u16>, Vec<(String, String)>, Vec<u8>, u64, Option<String>) {
    use std::io::{Read, Write};
    let started = std::time::Instant::now();
    if !url.starts_with("http://") || !is_loopback_url(url) {
        return (
            None,
            vec![],
            vec![],
            0,
            Some("loopback_get only speaks http:// to loopback hosts".to_string()),
        );
    }
    let rest = &url["http://".len()..];
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut stream = match std::net::TcpStream::connect_timeout(
        &match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                return (None, vec![], vec![], 0, Some(format!("bad loopback address: {e}")))
            }
        },
        std::time::Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(e) => return (None, vec![], vec![], 0, Some(format!("connect: {e}"))),
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = stream.write_all(request.as_bytes()) {
        return (None, vec![], vec![], 0, Some(format!("write: {e}")));
    }
    let mut raw = Vec::new();
    if let Err(e) = stream.read_to_end(&mut raw) {
        return (None, vec![], vec![], 0, Some(format!("read: {e}")));
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw[split..].to_vec();
    let mut status = None;
    let mut headers = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            status = line.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok());
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    // Honour Content-Length: a `Connection: close` read can otherwise include
    // nothing extra, but a chunked or short read must not be over-trimmed.
    if let Some((_, len)) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        if let Ok(n) = len.parse::<usize>() {
            body.truncate(n);
        }
    }
    let ms = started.elapsed().as_millis() as u64;
    (status, headers, body, ms, None)
}

fn execute_and_record(report: &mut Report, row: &mut Map<String, Value>, req: &Request) {
    use crate::request_plan::{execute_get, ExecutionOptions};

    if is_loopback_url(&req.url) {
        let (status, _headers, body, ms, err) = loopback_get(&req.url);
        report.executed += 1;
        let ok = err.is_none() && status.is_some_and(|s| s < 400);
        row.insert("http_status".into(), json!(status));
        row.insert("body_len".into(), json!(body.len()));
        row.insert("body".into(), json!(redaction_marker(&body)));
        row.insert("body_redacted".into(), json!(true));
        row.insert("response_sha256".into(), json!(sha256_hex(&body)));
        row.insert("duration_ms".into(), json!(ms));
        row.insert(
            "status".into(),
            json!(if ok { "succeeded" } else { "failed" }),
        );
        if ok {
            report.succeeded += 1;
        } else {
            row.insert(
                "error".into(),
                canonical_error(
                    "transport",
                    &err.unwrap_or_else(|| "non-2xx loopback response".to_string()),
                    false,
                    &req.target_id,
                    &req.url,
                    "request_execution",
                ),
            );
        }
        return;
    }

    let outcome = execute_get(&req.url, ExecutionOptions::default());
    report.executed += 1;
    row.insert("http_status".into(), json!(outcome.http_status));
    row.insert("body_len".into(), json!(outcome.body.len()));
    row.insert("body".into(), json!(redaction_marker(&outcome.body)));
    row.insert("body_redacted".into(), json!(true));
    row.insert("response_sha256".into(), json!(sha256_hex(&outcome.body)));
    row.insert("duration_ms".into(), json!(outcome.duration_ms));
    if outcome.success {
        report.succeeded += 1;
        row.insert("status".into(), json!("succeeded"));
    } else {
        row.insert("status".into(), json!("failed"));
        row.insert(
            "error".into(),
            canonical_error(
                "transport",
                &outcome.error_message,
                outcome.retryable,
                &req.target_id,
                &req.url,
                "request_execution",
            ),
        );
    }
}

// ─────────────────────────────── artifacts ──────────────────────────────────

fn write_artifacts(
    args: &Args,
    plan_value: &Value,
    requests: &[Request],
    report: &mut Report,
) -> Result<(), String> {
    let dir = &args.output_dir;
    std::fs::create_dir_all(dir.join("responses")).map_err(|e| e.to_string())?;

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    // Redacted plan snapshot: bodies become hash markers, header values are
    // dropped (names stay, so the plan is still reviewable).
    let mut snapshot = plan_value.clone();
    if let Some(arr) = snapshot.get_mut("requests").and_then(Value::as_array_mut) {
        for req in arr {
            if let Some(obj) = req.as_object_mut() {
                if let Some(body) = obj.remove("body") {
                    let raw = serde_json::to_vec(&body).unwrap_or_default();
                    obj.insert("body".into(), json!(redaction_marker(&raw)));
                }
                if let Some(headers) = obj.get_mut("headers").and_then(Value::as_object_mut) {
                    for value in headers.values_mut() {
                        let raw = serde_json::to_vec(value).unwrap_or_default();
                        *value = json!(redaction_marker(&raw));
                    }
                }
            }
        }
    }
    files.push((
        "request_plan.v1.json".into(),
        serde_json::to_vec_pretty(&snapshot).map_err(|e| e.to_string())?,
    ));

    let mut lines = String::new();
    for (i, req) in requests.iter().enumerate() {
        let status = report
            .requests
            .get(i)
            .and_then(|r| r.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        lines.push_str(
            &json!({
                "index": req.index,
                "target_id": req.target_id,
                "url": req.url,
                "method": req.method,
                "status": status,
            })
            .to_string(),
        );
        lines.push('\n');
    }
    files.push(("requests.jsonl".into(), lines.into_bytes()));

    let mut meta = String::new();
    let mut body_paths: Vec<String> = Vec::new();
    for (i, req) in requests.iter().enumerate() {
        let row = report.requests.get(i).cloned().unwrap_or_default();
        let rel = format!("responses/response-{:03}.body.txt", req.index);
        let marker = row
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        files.push((rel.clone(), marker.into_bytes()));
        body_paths.push(rel.clone());
        meta.push_str(
            &json!({
                "index": req.index,
                "target_id": req.target_id,
                "http_status": row.get("http_status").cloned().unwrap_or(Value::Null),
                "body_len": row.get("body_len").cloned().unwrap_or(Value::Null),
                "body_sha256": row.get("response_sha256").cloned().unwrap_or(Value::Null),
                "duration_ms": row.get("duration_ms").cloned().unwrap_or(Value::Null),
                "response_body_artifact": rel,
            })
            .to_string(),
        );
        meta.push('\n');
    }
    files.push(("response_metadata.jsonl".into(), meta.into_bytes()));

    let mut csv = String::from("index,target_id,url,status\n");
    for (i, req) in requests.iter().enumerate() {
        let status = report
            .requests
            .get(i)
            .and_then(|r| r.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        csv.push_str(&format!(
            "{},{},{},{}\n",
            req.index, req.target_id, req.url, status
        ));
    }
    files.push(("source_index.csv".into(), csv.into_bytes()));

    files.push((
        "run_metrics.json".into(),
        serde_json::to_vec_pretty(&json!({
            "manifest_id": report.manifest_id,
            "network_scope": report.scope.as_str(),
            "executed": report.executed,
            "succeeded": report.succeeded,
            "blocked": report.blocked(),
            "requests_total": requests.len(),
        }))
        .map_err(|e| e.to_string())?,
    ));

    let compliance = match &args.compliance_report {
        Some(path) => std::fs::read(path).unwrap_or_default(),
        None => serde_json::to_vec_pretty(&json!({"supplied": false})).unwrap_or_default(),
    };
    files.push(("compliance_report.json".into(), compliance));

    let mut entries = Vec::new();
    for (name, bytes) in &files {
        std::fs::write(dir.join(name), bytes).map_err(|e| format!("{name}: {e}"))?;
        entries.push(json!({
            "path": name,
            "size_bytes": bytes.len(),
            "sha256": sha256_hex(bytes),
        }));
    }

    for (i, body_rel) in body_paths.iter().enumerate() {
        let Some(row) = report.requests.get_mut(i) else {
            continue;
        };
        let meta_rel = format!("responses/response-{:03}.json", row_index(row));
        let bytes = serde_json::to_vec_pretty(&json!({
            "index": row.get("index"),
            "http_status": row.get("http_status"),
            "body_len": row.get("body_len"),
            "body_sha256": row.get("response_sha256"),
            "response_body_artifact": body_rel,
        }))
        .map_err(|e| e.to_string())?;
        std::fs::write(dir.join(&meta_rel), &bytes).map_err(|e| format!("{meta_rel}: {e}"))?;
        entries.push(json!({
            "path": meta_rel,
            "size_bytes": bytes.len(),
            "sha256": sha256_hex(&bytes),
        }));
        row.insert(
            "artifacts".into(),
            json!({"response_body": body_rel, "response_metadata": meta_rel}),
        );
    }

    let manifest = json!({
        "schema_version": ARTIFACT_MANIFEST_SCHEMA,
        "files": entries,
    });
    std::fs::write(
        dir.join("artifact_manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn row_index(row: &Map<String, Value>) -> i64 {
    row.get("index").and_then(Value::as_i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_plan_path_is_a_usage_error() {
        assert_eq!(run_plan_args(&[]), EXIT_USAGE);
    }

    #[test]
    fn help_prints_usage_and_exits_zero() {
        assert_eq!(run_plan_args(&["--help".to_string()]), EXIT_OK);
    }

    #[test]
    fn an_unknown_scope_is_refused() {
        assert_eq!(
            run_plan_args(&[
                "--plan".to_string(),
                "x.json".to_string(),
                "--network-scope".to_string(),
                "wide-open".to_string(),
            ]),
            EXIT_USAGE
        );
    }

    #[test]
    fn url_globs_anchor_both_ends() {
        assert!(url_matches("http://127.0.0.1:*", "http://127.0.0.1:8080/x"));
        assert!(url_matches("*", "https://example.com/a"));
        assert!(!url_matches("http://127.0.0.1/*", "https://evil.example/x"));
    }
}
