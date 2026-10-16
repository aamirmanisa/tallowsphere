//! SEC1 honesty-sweep verification (wave2, 2026-09-05).
//!
//! Proves the four S1–S4 fixes end-to-end through the public stdlib surface.
//! The unit tests added inside `src/stdlib/{crypto,copy_engine,agent}.rs`
//! carry the same assertions; this file exists so the fixes are executable even
//! when unrelated in-flight unit-test code breaks the `cargo test --lib` binary.
//!
//! Offline by design: no live network calls.

use tallow::interp::Value;
use tallow::stdlib;
use tallow::stdlib::copy_engine::{plan as ce_plan, CopyJob};

fn field<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn step(name: &str, action: &str, args: Vec<Value>) -> Value {
    Value::Struct {
        name: "PlaybookStep".into(),
        fields: vec![
            ("name".into(), Value::String(name.into())),
            ("action".into(), Value::String(action.into())),
            ("args".into(), Value::Array(args)),
        ],
    }
}


// ── S2: crypto Tpm.seal plaintext echo ─────────────────────────────────

#[test]
fn s2_tpm_seal_no_plaintext_echo_and_roundtrip() {
    let sealed = stdlib::dispatch(
        "crypto",
        "tpm_seal",
        vec![
            Value::String("hunter2-secret".into()),
            Value::String("pcr-0,pcr-7".into()),
        ],
    )
    .expect("tpm_seal should route")
    .expect("tpm_seal should succeed");

    let Value::Struct { name, fields } = &sealed else {
        panic!("expected TpmSealedData struct, got {sealed:?}");
    };
    assert_eq!(name, "TpmSealedData");
    // No plaintext echo anywhere in the sealed struct.
    assert!(
        fields.iter().all(|(k, _)| k != "original_data"),
        "sealed struct must not carry original_data"
    );
    for (k, v) in fields {
        if let Value::String(s) = v {
            assert!(
                !s.contains("hunter2-secret"),
                "sealed struct leaks plaintext via field '{k}'"
            );
        }
    }

    // Correct policy still round-trips through unseal.
    let unsealed = stdlib::dispatch(
        "crypto",
        "tpm_unseal",
        vec![sealed.clone(), Value::String("pcr-0,pcr-7".into())],
    )
    .expect("tpm_unseal should route")
    .expect("tpm_unseal should succeed");
    assert_eq!(unsealed.as_string(), "hunter2-secret");

    // Wrong policy is an honest error.
    let bad = stdlib::dispatch(
        "crypto",
        "tpm_unseal",
        vec![sealed, Value::String("pcr-0,pcr-1".into())],
    )
    .expect("tpm_unseal should route");
    assert!(bad.is_err(), "wrong PCR policy must fail the AEAD check");
}

// ── S3: copy_engine real bytes ─────────────────────────────────────────

#[test]
fn s3_copy_engine_copies_real_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src.bin");
    let dst = tmp.path().join("deep").join("nested").join("dst.bin");
    let payload = b"real bytes \x00\x01\x02\xff";
    std::fs::write(&src, payload).unwrap();

    let plan = ce_plan(CopyJob::copy(
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ))
    .expect("plan should succeed for an existing file");
    assert_eq!(plan.actions.len(), 2, "missing-parent dir + file copy");
    let report = tallow::stdlib::copy_engine::execute(&plan)
        .expect("execute must perform real I/O and succeed");

    assert_eq!(report.bytes_copied, payload.len() as u64, "real byte count");
    assert_eq!(report.copied_files, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(std::fs::read(&dst).unwrap(), payload, "destination bytes");

    // Missing source: honest Err from plan().
    let missing = tmp.path().join("nope.txt");
    let err = ce_plan(CopyJob::copy(missing.to_str().unwrap(), dst.to_str().unwrap()))
        .expect_err("missing source must error");
    assert!(err.to_string().contains("not accessible"), "{err}");
}

// ── S4: agent Playbook.execute honest dispatch ─────────────────────────

fn spawn_pb(name: &str, steps: Vec<Value>) -> Value {
    stdlib::dispatch("agent", "spawn", vec![Value::String(name.into()), Value::Array(steps)])
        .expect("spawn should route")
        .expect("spawn should succeed")
}

#[test]
fn s4_playbook_unsupported_action_errs_not_simulated() {
    let pb = spawn_pb("p", vec![step("fetch-page", "fetch", vec![])]);
    let r = stdlib::dispatch_method(&pb, "execute", vec![]);
    let msg = match r {
        Some(Err(m)) => m,
        other => panic!("'fetch' must not simulate success; got {other:?}"),
    };
    assert!(msg.contains("does not implement"), "{msg}");
    assert!(msg.contains("fetch"), "error names the action: {msg}");
}

#[test]
fn s4_playbook_record_honors_args() {
    let pb = spawn_pb(
        "p",
        vec![step("capture", "record", vec![Value::String("note".into()), Value::Int(42)])],
    );
    let ex = stdlib::dispatch_method(&pb, "execute", vec![])
        .expect("execute should route")
        .expect("record is supported and should succeed");
    let Value::Struct { fields, .. } = ex else { panic!("expected Playbook") };

    // Executed steps carry the args (not discarded).
    let Value::Array(executed) = field(&fields, "steps").unwrap() else {
        panic!("steps must be an array");
    };
    let Value::Struct { fields: sf, .. } = &executed[0] else { panic!() };
    assert!(matches!(field(sf, "args"), Some(Value::Array(a)) if a.len() == 2));

    // StepResult records the args verbatim as output.
    let Value::Array(results) = field(&fields, "results").unwrap() else {
        panic!("results must be an array");
    };
    let Value::Struct { fields: rf, .. } = &results[0] else { panic!() };
    assert!(matches!(field(rf, "status"), Some(Value::String(s)) if s == "succeeded"));
    let Value::Array(output) = field(rf, "output").unwrap() else {
        panic!("record step must have an output array");
    };
    assert_eq!(output.len(), 2);
    assert_eq!(output[0].as_string(), "note");
    assert!(matches!(output[1], Value::Int(42)));
}

#[test]
fn s4_playbook_fail_records_reason() {
    let pb = spawn_pb(
        "p",
        vec![step("x", "fail", vec![Value::String("denied".into())])],
    );
    let ex = stdlib::dispatch_method(&pb, "execute", vec![])
        .expect("execute should route")
        .expect("execute should succeed");
    let Value::Struct { fields, .. } = ex else { panic!() };
    let Value::Array(results) = field(&fields, "results").unwrap() else {
        panic!("results must be an array");
    };
    let Value::Struct { fields: rf, .. } = &results[0] else { panic!() };
    assert!(matches!(field(rf, "status"), Some(Value::String(s)) if s == "failed"));
    assert!(matches!(field(rf, "reason"), Some(Value::String(s)) if s == "denied"));
}

// ── Docs-truth wiring (E-3-09 §3.5 six rewrites + mockup claim banners) ──
//
// These read the docs tree from the repo root; they exist so doc-truth
// regressions fail the same test run as the S1–S4 stdlib surface checks.

mod docs_truth {
    use std::fs;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn read(rel: &str) -> String {
        let path = root().join(rel);
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    fn section_3_5_doc_align_no_comptime_drift() {
        let reference = read("docs/tallow-complete-reference.html");
        assert!(reference.contains("Constant folding in codegen (no <code>comptime</code> language feature)"));
        assert!(reference
            .contains("Policy/safety passes (@legal validation, privacy flow, agent boundaries)"));
        let low = reference.to_lowercase();
        assert!(!low.contains("comptime execution"), "ref-html: stale 'comptime execution' claim");
        assert!(!low.contains("zero runtime cost"), "ref-html: stale 'zero runtime cost' claim");
        assert!(!low.contains("borrow/lifetime analysis"), "ref-html: stale borrow-analysis step");

        let caps = read("docs/TALLOW-CAPABILITIES.md");
        assert!(caps.contains("Constant Folding (codegen; no comptime feature)"));

        let comparison = read("docs/TALLOW-LANGUAGE-COMPARISON-2026-09-12.md");
        assert!(comparison.contains("31 compiler passes"), "comparison: fresh pass count missing");
        assert!(!comparison.contains("29 compiler passes"), "comparison: stale 29-pass claim");
        assert!(!comparison.contains("comptime"), "comparison: comptime must not sit in the pipeline string");
    }

    #[test]
    fn compiler_pass_count_no_stale_29_claims() {
        for rel in [
            "docs/TALLOW-CAPABILITIES.md",
            "docs/TALLOW-330-TOOLS.md",
            "docs/MEGA_SCRAPER_ENGINE_RESEARCH.md",
        ] {
            let text = read(rel);
            assert!(!text.contains("29 compiler passes"), "{rel}: stale 29-pass claim");
            assert!(!text.contains("29 Compiler Passes"), "{rel}: stale 29-pass heading");
        }
        assert!(
            !read("docs/MEGA_SCRAPER_ENGINE_RESEARCH.md").contains("29 passes"),
            "MEGA: stale (29 passes) cell"
        );
    }

    #[test]
    fn delta_sync_flags_and_ops_docs_paths() {
        let caps = read("docs/TALLOW-CAPABILITIES.md");
        // 23, not 24: `--vss` was removed in W2-08 (design D-C1) and both the count note and the
        // enumeration in the document were updated for it. The code agrees — src/main.rs's
        // `DeltaSync` variant defines 23 named flags (25 #[arg] fields with the two positionals).
        // This assertion said 24 and had therefore been red wherever it ran, which is why a
        // doc-truth check needs to be wired into a runner to mean anything.
        assert!(caps.contains("Delta-Sync Flags (23)"));
        assert!(!caps.contains("Delta-Sync Flags (22)"));
        assert!(!caps.contains("Delta-Sync Flags (24)"));
        for rel in [
            "docs/operations/quickstart.md",
            "docs/operations/operator-checklist.md",
            "docs/operations/tallow-runtime-bootstrap.md",
            "docs/operations/phase1-smoke-ladder.md",
            "docs/operations/target-policy.md",
            "docs/operations/phase11-proving-grounds.md",
        ] {
            assert!(!read(rel).contains("/mnt/Personal"), "{rel}: stale workspace path");
        }
    }

    #[test]
    fn mockup_docs_have_truth_banners_and_claim_labels() {
        let dir = root().join("docs/mockups");
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("html"))
            .collect();
        files.sort();
        assert!(files.len() >= 13, "expected >=13 mockups, found {}", files.len());

        let label_required = [
            "v1-editorial.html",
            "v2-cinematic.html",
            "v3-stripe.html",
            "v4-spatial.html",
            "v5-brutalist.html",
            "tallow-copy-premium.html",
            "tallow-presets.html",
            "tallow-search-final.html",
            "tallow-luxury.html",
        ];
        let undetectable_files = ["tallow-search-final.html", "tallow-presets.html", "tallow-luxury.html"];

        for path in &files {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let head: String = text.lines().take(8).collect::<Vec<_>>().join("\n");
            assert!(head.contains("Docs truth label"), "{name}: missing truth banner");
            if label_required.contains(&name.as_str()) {
                assert!(text.contains("claim label:"), "{name}: no per-claim labels");
            }
            if undetectable_files.contains(&name.as_str()) {
                let lines: Vec<&str> = text.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.to_lowercase().contains("undetectable")
                        && !line.contains("claim label")
                        && !line.trim_start().starts_with("<!--")
                    {
                        let window = lines[i + 1..lines.len().min(i + 3)].join("\n");
                        assert!(window.contains("claim label:"), "{name}:{}: unlabeled 'undetectable'", i + 1);
                    }
                }
            }
        }
    }
}
