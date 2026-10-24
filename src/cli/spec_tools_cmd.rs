//! Operator spec tools: `validate-manifest`, `build-plan`, `package-report`
//! and the `scraper` lint profile.
//!
//! These verbs are the local half of the request-plan workflow:
//!
//! * `validate-manifest` checks a `tallow.target_manifest.v2` before anything
//!   else reads it, and writes the same JSON report to stdout and to an
//!   optional file.
//! * `build-plan` turns a manifest into a `tallow.request_plan.v1` plan, with
//!   the manifest's sha256 attached so `run-plan` can prove the plan still
//!   matches the manifest it was built from.
//! * `package-report` hashes a run directory into a `tallow.package_report.v1`
//!   manifest, excluding its own output even when the two are spelled
//!   differently (`run-dir/x.json` vs `/abs/path/run-dir/x.json`).
//!
//! None of them touch the network. `non_claims.no_network_io` is asserted by
//! the tests rather than promised here.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const EXIT_OK: i32 = 0;
const EXIT_FAILED: i32 = 2;
const EXIT_USAGE: i32 = 64;

const MANIFEST_SCHEMA_V2: &str = "tallow.target_manifest.v2";
const PLAN_SCHEMA: &str = "tallow.request_plan.v1";
const VALIDATE_REPORT_SCHEMA: &str = "tallow.validate_manifest_report.v1";
const BUILD_REPORT_SCHEMA: &str = "tallow.request_plan_report.v1";
const PACKAGE_REPORT_SCHEMA: &str = "tallow.package_report.v1";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| format!("{}: not JSON: {e}", path.display()))
}

/// A v2 target id must survive being a filename, a JSON key and a CLI argument.
fn id_is_v2_safe(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !id.starts_with('.')
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

// ───────────────────────────── validate-manifest ────────────────────────────

struct Opts {
    input: PathBuf,
    output: Option<PathBuf>,
    report_path: Option<PathBuf>,
    profile: Option<String>,
}

fn parse_opts(args: &[String], allow_output: bool, allow_profile: bool) -> Result<Opts, String> {
    let mut input: Option<PathBuf> = None;
    let mut output = None;
    let mut report_path = None;
    let mut profile = None;
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
            "--output" if allow_output => output = Some(PathBuf::from(take("--output")?)),
            "--report-path" => report_path = Some(PathBuf::from(take("--report-path")?)),
            "--profile" if allow_profile => profile = Some(take("--profile")?),
            "-h" | "--help" => return Err(String::new()),
            other if other.starts_with('-') => return Err(format!("unknown flag {other:?}")),
            other => {
                if input.is_some() {
                    return Err(format!("unexpected extra positional argument {other:?}"));
                }
                input = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }
    Ok(Opts {
        input: input.ok_or_else(|| "an input path is required".to_string())?,
        output,
        report_path,
        profile,
    })
}

fn emit(report: &Value, report_path: Option<&Path>) -> Result<(), String> {
    let text = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    if let Some(path) = report_path {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        std::fs::write(path, format!("{text}\n")).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    println!("{text}");
    Ok(())
}

fn validate_manifest_value(manifest: &Value) -> (Vec<String>, usize) {
    let mut errors = Vec::new();

    if manifest.get("schema_version").and_then(Value::as_str) != Some(MANIFEST_SCHEMA_V2) {
        errors.push(format!("schema_version must be {MANIFEST_SCHEMA_V2}"));
    }
    if manifest
        .get("manifest_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        errors.push("manifest_id is required".to_string());
    }

    let targets = manifest
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    for (i, target) in targets.iter().enumerate() {
        let id = target.get("id").and_then(Value::as_str).unwrap_or("");
        if !id_is_v2_safe(id) {
            errors.push(format!(
                "targets[{i}].id is required and must be v2-safe (letters, digits, '-', '_', '.', \
                 no leading dot, at most 64 chars)"
            ));
        } else if !seen.insert(id.to_string()) {
            errors.push(format!("targets[{i}].id {id:?} is duplicated"));
        }
        let url = target.get("url").and_then(Value::as_str).unwrap_or("");
        if !is_http_url(url) {
            errors.push(format!("targets[{i}].url must be http(s)"));
        }
        let method = target
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "HEAD" | "POST") {
            errors.push(format!(
                "targets[{i}].method {method:?} is not one this tree can express"
            ));
        }
        let compliance = target.get("compliance").and_then(Value::as_object);
        let Some(compliance) = compliance else {
            errors.push(format!(
                "targets[{i}].compliance is required: a target without a legal basis cannot be fetched"
            ));
            continue;
        };
        for field in [
            "source_authority",
            "purpose",
            "legal_basis",
            "pii_policy",
        ] {
            if compliance
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                errors.push(format!("targets[{i}].compliance.{field} is required"));
            }
        }
        if compliance
            .get("retention_days")
            .and_then(Value::as_i64)
            .is_none()
        {
            errors.push(format!(
                "targets[{i}].compliance.retention_days is required"
            ));
        }
    }

    (errors, targets.len())
}

/// `tallow validate-manifest <manifest> [--report-path <FILE>]`
pub fn validate_manifest_args(args: &[String]) -> i32 {
    let opts = match parse_opts(args, false, false) {
        Ok(o) => o,
        Err(msg) if msg.is_empty() => {
            eprintln!("usage: tallow validate-manifest <MANIFEST> [--report-path <FILE>]");
            return EXIT_OK;
        }
        Err(msg) => {
            eprintln!("validate-manifest: {msg}");
            return EXIT_USAGE;
        }
    };

    let manifest = match read_json(&opts.input) {
        Ok(v) => v,
        Err(e) => {
            let report = json!({
                "schema_version": VALIDATE_REPORT_SCHEMA,
                "passed": false,
                "summary": {"targets": 0},
                "errors": [e],
                "non_claims": {"no_network_io": true},
            });
            let _ = emit(&report, opts.report_path.as_deref());
            return EXIT_FAILED;
        }
    };

    let (errors, targets) = validate_manifest_value(&manifest);
    let report = json!({
        "schema_version": VALIDATE_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id").cloned().unwrap_or(Value::Null),
        "passed": errors.is_empty(),
        "summary": {"targets": targets, "errors": errors.len()},
        "errors": errors,
        "non_claims": {
            "no_network_io": true,
            "no_targets_fetched": true,
            "no_compliance_readiness_claimed": true,
        },
    });
    if let Err(e) = emit(&report, opts.report_path.as_deref()) {
        eprintln!("validate-manifest: {e}");
        return EXIT_USAGE;
    }
    if errors.is_empty() {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

// ──────────────────────────────── build-plan ────────────────────────────────

/// `tallow build-plan <manifest> --output <PLAN> [--report-path <FILE>]`
pub fn build_plan_args(args: &[String]) -> i32 {
    let opts = match parse_opts(args, true, false) {
        Ok(o) => o,
        Err(msg) if msg.is_empty() => {
            eprintln!("usage: tallow build-plan <MANIFEST> --output <PLAN> [--report-path <FILE>]");
            return EXIT_OK;
        }
        Err(msg) => {
            eprintln!("build-plan: {msg}");
            return EXIT_USAGE;
        }
    };
    let Some(output) = opts.output.clone() else {
        eprintln!("build-plan: --output <PLAN> is required");
        return EXIT_USAGE;
    };

    let raw = match std::fs::read(&opts.input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("build-plan: {}: {e}", opts.input.display());
            return EXIT_USAGE;
        }
    };
    let manifest: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("build-plan: {}: not JSON: {e}", opts.input.display());
            return EXIT_USAGE;
        }
    };
    let (errors, _) = validate_manifest_value(&manifest);
    if !errors.is_empty() {
        let report = json!({
            "schema_version": BUILD_REPORT_SCHEMA,
            "passed": false,
            "errors": errors,
            "non_claims": {"no_network_io": true},
        });
        let _ = emit(&report, opts.report_path.as_deref());
        return EXIT_FAILED;
    }

    let targets = manifest
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let default_headers = manifest
        .get("defaults")
        .and_then(|d| d.get("headers"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let default_fallback = manifest
        .get("defaults")
        .and_then(|d| d.get("browser_fallback"))
        .cloned()
        .unwrap_or_else(|| json!({"mode": "never"}));

    let mut requests = Vec::new();
    for (i, target) in targets.iter().enumerate() {
        let mut headers = default_headers.clone();
        if let (Some(base), Some(own)) = (
            headers.as_object_mut(),
            target.get("headers").and_then(Value::as_object),
        ) {
            for (k, v) in own {
                base.insert(k.clone(), v.clone());
            }
        }
        let mut request = json!({
            "index": i,
            "target_id": target.get("id").cloned().unwrap_or(Value::Null),
            "url": target.get("url").cloned().unwrap_or(Value::Null),
            "method": target
                .get("method")
                .cloned()
                .unwrap_or_else(|| json!("GET")),
            "headers": headers,
            "browser_fallback": target
                .get("browser_fallback")
                .cloned()
                .unwrap_or(default_fallback.clone()),
            "compliance": target.get("compliance").cloned().unwrap_or(Value::Null),
        });
        if let Some(auth_ref) = target.get("auth_ref") {
            request["auth_ref"] = auth_ref.clone();
        }
        requests.push(request);
    }

    let plan = json!({
        "schema_version": PLAN_SCHEMA,
        "manifest_id": manifest.get("manifest_id").cloned().unwrap_or(Value::Null),
        "request_count": requests.len(),
        "requests": requests,
        "source_manifest": {
            "path": std::fs::canonicalize(&opts.input)
                .unwrap_or_else(|_| opts.input.clone())
                .display()
                .to_string(),
            "sha256": sha256_hex(&raw),
            "schema_version": MANIFEST_SCHEMA_V2,
        },
        "status_boundary": "built by tallow build-plan; no request has been made",
    });

    let plan_text = match serde_json::to_string_pretty(&plan) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("build-plan: {e}");
            return EXIT_USAGE;
        }
    };
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if let Err(e) = std::fs::write(&output, format!("{plan_text}\n")) {
        eprintln!("build-plan: {}: {e}", output.display());
        return EXIT_USAGE;
    }

    let report = json!({
        "schema_version": BUILD_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id").cloned().unwrap_or(Value::Null),
        "plan_path": output.display().to_string(),
        "passed": true,
        "summary": {"requests": plan["request_count"].clone()},
        "non_claims": {"no_network_io": true},
    });
    if let Err(e) = emit(&report, opts.report_path.as_deref()) {
        eprintln!("build-plan: {e}");
        return EXIT_USAGE;
    }
    EXIT_OK
}

// ────────────────────────────── package-report ──────────────────────────────

fn collect_files(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(&path, base, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => {
            // The output may not exist yet; compare the parent plus the name.
            a.parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .zip(b.parent().and_then(|p| std::fs::canonicalize(p).ok()))
                .map(|(pa, pb)| pa == pb && a.file_name() == b.file_name())
                .unwrap_or(false)
        }
    }
}

/// `tallow package-report <RUN_DIR> --output <REPORT>`
pub fn package_report_args(args: &[String]) -> i32 {
    let opts = match parse_opts(args, true, false) {
        Ok(o) => o,
        Err(msg) if msg.is_empty() => {
            eprintln!("usage: tallow package-report <RUN_DIR> --output <REPORT>");
            return EXIT_OK;
        }
        Err(msg) => {
            eprintln!("package-report: {msg}");
            return EXIT_USAGE;
        }
    };
    let Some(output) = opts.output.clone() else {
        eprintln!("package-report: --output <REPORT> is required");
        return EXIT_USAGE;
    };
    if !opts.input.is_dir() {
        eprintln!("package-report: {} is not a directory", opts.input.display());
        return EXIT_USAGE;
    }

    let mut found = Vec::new();
    if let Err(e) = collect_files(&opts.input, &opts.input, &mut found) {
        eprintln!("package-report: {e}");
        return EXIT_USAGE;
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));

    let mut files = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut skipped_output = 0usize;
    for (rel, path) in found {
        if same_file(&path, &output) {
            // Never hash the report into itself: the path may be spelled
            // relative to the run dir or absolutely, so compare identity.
            skipped_output += 1;
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                total_bytes += bytes.len() as u64;
                files.push(json!({
                    "path": rel,
                    "size_bytes": bytes.len(),
                    "sha256": sha256_hex(&bytes),
                }));
            }
            Err(e) => {
                eprintln!("package-report: {}: {e}", path.display());
                return EXIT_USAGE;
            }
        }
    }

    let report = json!({
        "schema_version": PACKAGE_REPORT_SCHEMA,
        "root": opts.input.display().to_string(),
        "passed": true,
        "summary": {
            "files": files.len(),
            "bytes": total_bytes,
            "excluded_output": skipped_output,
        },
        "files": files,
        "error": {
            "kind": "none",
            "message": "no error",
            "retryable": false,
            "policy_blocked": false,
            "source_target_id": "",
            "url": "",
            "phase": "artifact_packaging",
        },
        "non_claims": {
            "no_network_io": true,
            "no_retention_purge": true,
        },
    });
    if let Err(e) = emit(&report, Some(&output)) {
        eprintln!("package-report: {e}");
        return EXIT_USAGE;
    }
    EXIT_OK
}

// ───────────────────────────── scraper lint profile ─────────────────────────

/// The `scraper` profile: a generated scraper must declare its legal basis and
/// must reach HTTP through the canonical module. An import alone is not HTTP
/// work, so `import tallow.http` without a call passes.
pub fn scraper_diagnostics(source: &str) -> Vec<Value> {
    let mut diags = Vec::new();
    let has_import = source.lines().any(|l| {
        let t = l.trim();
        t == "import tallow.http" || t.starts_with("import tallow.http as ")
    });
    let calls_http = source.contains("http.get(")
        || source.contains("http.post(")
        || source.contains("http.request(");
    let has_legal = source.contains("@legal");

    if calls_http && !has_import {
        diags.push(json!({
            "code": "E-SCRAPER-IMPORT",
            "severity": "error",
            "message": "scraper code calls http.* without `import tallow.http`",
        }));
    }
    if calls_http && !has_legal {
        diags.push(json!({
            "code": "E-SCRAPER-LEGAL",
            "severity": "error",
            "message": "scraper code that performs HTTP work must declare @legal",
        }));
    }
    diags
}
