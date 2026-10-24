//! `llm`-class mesh tasks, through the shipped binary.
//!
//! The point of these tests is the journal, not the model: a `llm` task must
//! record what was asked and what was answered, a public run must be replayable,
//! and a private run must be refused by `Mesh.replay` rather than quietly
//! pretending the answer can be reproduced.
//!
//! The model is a fixture: a TCP listener that answers every POST with a fixed
//! chat-completion body. That keeps the test hermetic (no network, no key, no
//! llama.cpp) while still exercising the engine's real HTTP path, its loopback
//! credential rule, and the worker's call capture.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PRELUDE: &str = r#"
struct MeshTask {
    id:              String,
    func:            String,
    deps:            []String,
    class:           String,
    idempotency_key: String?,
}

struct MeshRun {
    waves:      i64,
    committed:  i64,
    failed:     i64,
    journal:    String,
}
"#;

/// A tiny OpenAI-compatible endpoint: one fixed answer per request.
fn fixture_server() -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut s) = stream else { continue };
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some(v) = line.trim().strip_prefix("Content-Length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            let _ = std::io::Read::read_exact(&mut reader, &mut body);
            let payload = serde_json::json!({
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture-answer"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                "model": "fixture-model"
            })
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    (port, stop)
}

fn run_env(dir: &std::path::Path, source: &str, name: &str, cfg: &std::path::Path) -> (bool, String) {
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(dir)
        .env("TALLOW_LLM_CONFIG", cfg)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn program(journal: &str, class_arg: &str) -> String {
    format!(
        r#"{PRELUDE}
fn brief() -> String {{
    let c = llm.complete("fixture", "fixture-model", "Summarise the dossier.", 64)
    return c.text
}}

@legal(basis: .public_data, purpose: "mesh llm journal test", personal_data: false)
fn main() {{
    let tasks = [
        MeshTask {{ id: "brief", func: "brief", deps: [], class: "llm", idempotency_key: nil }}
    ]
    let r = Mesh.run(tasks, 1, "{journal}", 11{class_arg})
    print(r.committed)
}}
"#
    )
}

#[test]
fn a_public_llm_task_is_journalled_with_its_text_and_replays() {
    let (port, stop) = fixture_server();
    let dir = std::env::temp_dir().join(format!("tallow-mesh-llm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let cfg = dir.join("llm.toml");
    std::fs::write(
        &cfg,
        format!(
            "[providers.fixture]\nprotocol = \"openai\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\n"
        ),
    )
    .expect("config");
    let journal = dir.join("public.jsonl");
    let _ = std::fs::remove_file(&journal);

    let (ok, output) = run_env(&dir, &program(journal.to_str().unwrap(), ""), "public", &cfg);
    assert!(ok, "run failed: {output}");
    assert!(output.contains('1'), "expected one commit, got: {output}");

    let text = std::fs::read_to_string(&journal).expect("journal written");
    assert!(text.contains("\"kind\":\"llm_recorded\""), "no llm record: {text}");
    assert!(text.contains("fixture-answer"), "the public text is journalled: {text}");
    assert!(text.contains("\"data_class\":\"public\""), "{text}");
    assert!(
        text.contains("\"prompt_hash\":\"") && text.contains("\"response_hash\":\""),
        "hashes are recorded: {text}"
    );

    // Replay verifies the journal without the model: the fixture is still up but
    // replay never calls it (it only reads hashes and the text it recorded).
    let replay = format!(
        r#"@legal(basis: .public_data, purpose: "replay", personal_data: false)
fn main() {{
    let r = Mesh.replay("{}")
    print(r.ok)
}}
"#,
        journal.to_str().unwrap()
    );
    let (ok, output) = run_env(&dir, &replay, "replay", &cfg);
    assert!(ok, "replay failed: {output}");
    assert!(output.contains("true"), "replay should be ok: {output}");

    stop.store(true, Ordering::SeqCst);
}

#[test]
fn a_private_llm_task_keeps_hashes_only_and_replay_refuses_it() {
    let (port, stop) = fixture_server();
    let dir = std::env::temp_dir().join(format!("tallow-mesh-llm-priv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let cfg = dir.join("llm.toml");
    std::fs::write(
        &cfg,
        format!(
            "[providers.fixture]\nprotocol = \"openai\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\n"
        ),
    )
    .expect("config");
    let journal = dir.join("private.jsonl");
    let _ = std::fs::remove_file(&journal);

    let (ok, output) = run_env(
        &dir,
        &program(journal.to_str().unwrap(), ", \"private\""),
        "private",
        &cfg,
    );
    assert!(ok, "run failed: {output}");

    let text = std::fs::read_to_string(&journal).expect("journal written");
    assert!(text.contains("\"data_class\":\"private\""), "{text}");
    assert!(
        !text.contains("fixture-answer"),
        "private text must not be written: {text}"
    );
    assert!(text.contains("\"response\":null"), "response withheld: {text}");
    assert!(text.contains("\"prompt_hash\":\""), "hashes still recorded: {text}");

    let replay = format!(
        r#"@legal(basis: .public_data, purpose: "replay", personal_data: false)
fn main() {{
    let r = Mesh.replay("{}")
    print(r.ok)
}}
"#,
        journal.to_str().unwrap()
    );
    let (ok, output) = run_env(&dir, &replay, "replay-private", &cfg);
    assert!(!ok, "replay must refuse a private run, got: {output}");
    assert!(
        output.contains("non-replayable: private data class"),
        "expected the named refusal, got: {output}"
    );

    stop.store(true, Ordering::SeqCst);
}
