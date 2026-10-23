//! Provider integration tests against a local mock that speaks each wire protocol.
//!
//! The mock is not a simulation of the providers' *behaviour* — it is an HTTP
//! server that enforces the same authentication surface (Bearer for OpenAI-style,
//! `x-api-key` + `anthropic-version` for Anthropic, `x-goog-api-key` for Google,
//! `api-key` for Azure) and returns the documented response shapes. That proves
//! the request construction, header placement, model discovery and parsing are
//! real; it cannot prove a given vendor is up today, which requires the user's key
//! and is what `tallow llm verify` is for.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn read_request(stream: &mut TcpStream) -> (String, String, String) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut headers_raw = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line == "\r\n" {
            break;
        }
        headers_raw.push_str(&line);
    }
    let lower = headers_raw.to_lowercase();
    let len = lower
        .lines()
        .find(|l| l.starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).unwrap();
    }
    (
        request_line.trim().to_string(),
        lower,
        String::from_utf8_lossy(&body).to_string(),
    )
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.flush();
}

/// Start the mock and return its base URL plus a request counter.
fn mock_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::Relaxed);
            let (line, headers, body) = read_request(&mut stream);
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let has = |h: &str| headers.lines().any(|l| l.starts_with(h));
            match path.as_str() {
                p if p.starts_with("/v1/models") => {
                    if has("authorization: bearer good-key") {
                        respond(&mut stream, "200 OK",
                            r#"{"data":[{"id":"mock-large","owned_by":"mock"},{"id":"mock-small","owned_by":"mock"}]}"#);
                    } else {
                        respond(&mut stream, "401 Unauthorized", r#"{"error":{"message":"bad key"}}"#);
                    }
                }
                p if p.starts_with("/v1/chat/completions") => {
                    if has("authorization: bearer good-key") && body.contains("\"model\":\"mock-large\"") {
                        respond(&mut stream, "200 OK",
                            r#"{"choices":[{"message":{"content":"echo:mock-large"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#);
                    } else {
                        respond(&mut stream, "401 Unauthorized", r#"{"error":{"message":"bad key or model"}}"#);
                    }
                }
                "/v1/messages" => {
                    if has("x-api-key: anthropic-key") && has("anthropic-version: 2023-06-01") {
                        respond(&mut stream, "200 OK",
                            r#"{"content":[{"type":"text","text":"anthropic-ok"}],"usage":{"input_tokens":4,"output_tokens":1}}"#);
                    } else {
                        respond(&mut stream, "401 Unauthorized", r#"{"error":{"message":"missing anthropic headers"}}"#);
                    }
                }
                p if p.starts_with("/v1beta/models") && !p.contains(":generateContent") => {
                    if has("x-goog-api-key: google-key") {
                        respond(&mut stream, "200 OK", r#"{"models":[{"name":"models/gemini-mock"}]}"#);
                    } else {
                        respond(&mut stream, "401 Unauthorized", r#"{"error":{"message":"bad google key"}}"#);
                    }
                }
                p if p.contains(":generateContent") => {
                    if has("x-goog-api-key: google-key") {
                        respond(&mut stream, "200 OK",
                            r#"{"candidates":[{"content":{"parts":[{"text":"google-ok"}]}}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1}}"#);
                    } else {
                        respond(&mut stream, "401 Unauthorized", r#"{"error":{"message":"bad google key"}}"#);
                    }
                }
                p if p.starts_with("/openai/deployments/") => {
                    if has("api-key: azure-key") {
                        respond(&mut stream, "200 OK",
                            r#"{"choices":[{"message":{"content":"azure-ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}}"#);
                    } else {
                        respond(&mut stream, "401 Unauthorized", r#"{"error":{"message":"bad azure key"}}"#);
                    }
                }
                _ => respond(&mut stream, "404 Not Found", r#"{"error":{"message":"no route"}}"#),
            }
        }
    });
    (format!("http://{addr}/v1"), hits)
}

struct Env {
    dir: std::path::PathBuf,
    base: String,
}

impl Env {
    fn new(tag: &str, base: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("tallow-llm-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = base.trim_end_matches("/v1").to_string();
        let cfg = format!(
            "[providers.openai]\nbase_url = \"{base}\"\nkey_env = \"T_OPENAI_KEY\"\n\n\
             [providers.anthropic]\nbase_url = \"{base}\"\nkey_env = \"T_ANTHROPIC_KEY\"\n\n\
             [providers.google]\nbase_url = \"{root}/v1beta\"\nkey_env = \"T_GOOGLE_KEY\"\n\n\
             [providers.microsoft]\nprotocol = \"azure-openai\"\nbase_url = \"{root}/openai\"\nkey_env = \"T_AZURE_KEY\"\nchat_path = \"/deployments/mock/chat/completions?api-version=2024-10-21\"\n\n\
             [providers.selfhosted]\nprotocol = \"openai\"\nbase_url = \"{base}\"\nkey_env = \"T_OPENAI_KEY\"\n",
            base = base,
            root = root
        );
        std::fs::write(dir.join("llm.toml"), cfg).unwrap();
        Env { dir, base: base.to_string() }
    }

    fn run(&self, program: &str, envs: &[(&str, &str)]) -> (bool, String, String) {
        let file = self.dir.join("prog.tl");
        std::fs::write(&file, program).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tallow"));
        cmd.arg("run").arg(&file);
        cmd.env("TALLOW_LLM_CONFIG", self.dir.join("llm.toml"));
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run tallow");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }
}

#[test]
fn openai_style_discovery_and_completion() {
    let (base, _hits) = mock_server();
    let env = Env::new("openai", &base);
    let prog = r#"
@legal(basis: .public_data, purpose: "llm provider integration test", personal_data: false)
fn main() {
    let ms = llm.models("openai")
    print(ms.len())
    print(ms[0].id)
    let c = llm.complete("openai", "mock-large", "hello", 64)
    print(c.text)
    print(c.tokens_in)
    print(c.tokens_out)
    print(c.provider)
    let v = llm.verify("openai")
    print(v.ok)
    print(v.models)
}
"#;
    let (ok, out, err) = env.run(prog, &[("T_OPENAI_KEY", "good-key")]);
    assert!(ok, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('*')).collect();
    assert_eq!(lines, vec!["2", "mock-large", "echo:mock-large", "3", "2", "openai", "true", "2"], "{out}");
}

#[test]
fn anthropic_and_google_use_their_own_auth_and_shapes() {
    let (base, _hits) = mock_server();
    let env = Env::new("multi", &base);
    let prog = r#"
@legal(basis: .public_data, purpose: "llm provider integration test", personal_data: false)
fn main() {
    let a = llm.complete("anthropic", "claude-mock", "hi", 32)
    print(a.text)
    let g = llm.models("google")
    print(g[0].id)
    let c = llm.complete("google", "gemini-mock", "hi", 32)
    print(c.text)
}
"#;
    let (ok, out, err) = env.run(
        prog,
        &[("T_ANTHROPIC_KEY", "anthropic-key"), ("T_GOOGLE_KEY", "google-key")],
    );
    assert!(ok, "{out}\n{err}");
    let body = out.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('*')).collect::<Vec<_>>();
    assert_eq!(body, vec!["anthropic-ok", "gemini-mock", "google-ok"], "{out}");
}

#[test]
fn azure_and_a_custom_selfhosted_provider_work() {
    let (base, _hits) = mock_server();
    let env = Env::new("azure", &base);
    let prog = r#"
@legal(basis: .public_data, purpose: "llm provider integration test", personal_data: false)
fn main() {
    let a = llm.complete("microsoft", "mock-large", "hi", 32)
    print(a.text)
    let s = llm.complete("selfhosted", "mock-large", "hi", 32)
    print(s.text)
}
"#;
    let (ok, out, err) = env.run(prog, &[("T_AZURE_KEY", "azure-key"), ("T_OPENAI_KEY", "good-key")]);
    assert!(ok, "{out}\n{err}");
    let body = out.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('*')).collect::<Vec<_>>();
    assert_eq!(body, vec!["azure-ok", "echo:mock-large"], "{out}");
}

#[test]
fn a_bad_key_fails_without_echoing_it() {
    let (base, _hits) = mock_server();
    let env = Env::new("badkey", &base);
    let prog = r#"
@legal(basis: .public_data, purpose: "llm provider integration test", personal_data: false)
fn main() {
    let v = llm.verify("openai")
    print(v.ok)
    print(v.detail)
}
"#;
    let (ok, out, err) = env.run(prog, &[("T_OPENAI_KEY", "super-secret-bad-key")]);
    assert!(ok, "{out}\n{err}");
    assert!(out.contains("false"), "{out}");
    assert!(!out.contains("super-secret-bad-key"), "the key leaked into output: {out}");
    assert!(out.contains("401"), "the status must be reported: {out}");
}

#[test]
fn a_missing_key_names_the_variable_instead_of_calling_out() {
    let (base, hits) = mock_server();
    let env = Env::new("nokey", &base);
    let prog = r#"
@legal(basis: .public_data, purpose: "llm provider integration test", personal_data: false)
fn main() {
    let v = llm.verify("openai")
    print(v.ok)
    print(v.detail)
}
"#;
    let (ok, out, _err) = env.run(prog, &[]);
    assert!(ok, "{out}");
    assert!(out.contains("T_OPENAI_KEY"), "must name the variable to set: {out}");
    assert_eq!(hits.load(Ordering::Relaxed), 0, "no request may be sent without a credential");
}

#[test]
fn providers_lists_all_twenty_and_explains_the_unavailable_four() {
    let (base, _hits) = mock_server();
    let env = Env::new("registry", &base);
    let prog = r#"
@legal(basis: .public_data, purpose: "llm provider integration test", personal_data: false)
fn main() {
    let ps = llm.providers()
    print(ps.len())
    var unavailable = 0
    for p in ps {
        if p.status == "unavailable" { unavailable = unavailable + 1 }
    }
    print(unavailable)
}
"#;
    let (ok, out, err) = env.run(prog, &[]);
    assert!(ok, "{out}\n{err}");
    let nums: Vec<&str> = out.lines().map(str::trim).filter(|l| l.chars().all(|c| c.is_ascii_digit())).collect();
    // 20 registry entries plus the custom `selfhosted` provider this test's config adds.
    assert_eq!(nums.first().copied(), Some("21"), "{out}");
    assert_eq!(nums.get(1).copied(), Some("4"), "{out}");
}

#[test]
fn an_inline_key_in_the_config_is_refused() {
    let dir = std::env::temp_dir().join(format!("tallow-llm-inline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("llm.toml"),
        "[providers.openai]\nbase_url = \"https://api.openai.com/v1\"\nkey = \"sk-live-should-not-be-here\"\n",
    )
    .unwrap();
    let prog = dir.join("p.tl");
    std::fs::write(
        &prog,
        "@legal(basis: .public_data, purpose: \"x\", personal_data: false)\nfn main() { let p = llm.providers()\n print(p.len()) }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&prog)
        .env("TALLOW_LLM_CONFIG", dir.join("llm.toml"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success(), "an inline key must fail the call");
    assert!(stderr.contains("key_env"), "the refusal must name the fix: {stderr}");
    assert!(!stderr.contains("sk-live-should-not-be-here"), "the key must never be echoed: {stderr}");
}
