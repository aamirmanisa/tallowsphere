//! `llm.complete` must produce the same `Completion` struct on both planes.
//!
//! The interpreter builds it from `stdlib::llm::dispatch`; the compiled path
//! goes through the `tallow_llm_complete` FFI (src/runtime/llm_ffi.rs) and loads
//! a `%struct.Completion` record built by the same function. A mock
//! OpenAI-compatible server makes the response deterministic, so any difference
//! in the printed fields is a lowering defect, not sampling.
//!
//! `TALLOW_LLM_CONFIG` points the engine at a temporary `llm.toml`; the loopback
//! base_url is why no credential is required.

use std::io::{Read, Write};
use std::net::TcpListener;

fn serve_completion() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            // One mock, two endpoints: the model list and the chat completion.
            let body = if head.contains("GET /v1/models") {
                r#"{"object":"list","data":[{"id":"mock-1","object":"model","owned_by":"fixture"},{"id":"mock-2","object":"model","owned_by":"fixture"}]}"#
            } else {
                r#"{
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "model": "mock-1",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ready"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
            }"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

const PROGRAM: &str = r#"import tallow.llm

fn main() {
    let c = llm.complete("mock", "mock-1", "say ready", 16)
    print("text=" + c.text)
    print("model=" + c.model)
    print("provider=" + c.provider)
    print("tokens_in=" + c.tokens_in)
    print("tokens_out=" + c.tokens_out)
    let ms = llm.models("mock")
    print("models_len=" + ms.len)
    print("model0=" + ms[0].id)
    print("owner0=" + ms[0].owned_by)
}
"#;

fn run(flag: &str, tag: &str, config: &std::path::Path) -> (bool, Vec<String>) {
    let path = std::env::temp_dir().join(format!(
        "tallow-llm-parity-{}-{tag}.tl",
        std::process::id()
    ));
    std::fs::write(&path, PROGRAM).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .env("TALLOW_LLM_CONFIG", config)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| {
            // Drop diagnostics scaffolding (the `4 | ...` source line, the
            // `-->` caret chain) and the engine's runtime-archive note, so the
            // comparison is over the program's own output only.
            !l.is_empty()
                && !l.starts_with('*')
                && !l.starts_with("warning[")
                && !l.starts_with("runtime archive:")
                && !l.contains("--> ")
                && !l.contains('^')
                && !l.starts_with('|')
                && !(l.starts_with(|c: char| c.is_ascii_digit())
                    && l.contains(" | "))
        })
        .map(str::to_string)
        .collect();
    (out.status.success(), lines)
}

#[test]
fn completion_struct_matches_on_both_planes() {
    let port = serve_completion();
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("llm.toml");
    std::fs::write(
        &config,
        format!(
            "[providers.mock]\nprotocol = \"openai\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\nmodel_path = \"/models\"\n"
        ),
    )
    .expect("write llm.toml");

    let (native_ok, native) = run("--require-native", "native", &config);
    assert!(native_ok, "compiled leg failed:\n{}", native.join("\n"));
    let (interp_ok, interp) = run("--interpret", "interp", &config);
    assert!(interp_ok, "interpreter leg failed:\n{}", interp.join("\n"));

    assert_eq!(
        native, interp,
        "planes disagree on the Completion struct:\nnative={native:?}\ninterp={interp:?}"
    );
    assert!(
        native.contains(&"text=ready".to_string()),
        "the completion text must be real, got {native:?}"
    );
    assert!(
        native.contains(&"tokens_in=7".to_string())
            && native.contains(&"tokens_out=3".to_string()),
        "token counts must come from the provider's usage block, got {native:?}"
    );
    assert!(
        native.contains(&"provider=mock".to_string()),
        "the provider id must be the configured one, got {native:?}"
    );
    assert!(
        native.contains(&"models_len=2".to_string())
            && native.contains(&"model0=mock-1".to_string())
            && native.contains(&"owner0=fixture".to_string()),
        "llm.models must return the real model list on both planes, got {native:?}"
    );
}
