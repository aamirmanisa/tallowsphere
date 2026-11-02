//! Minimal, browser-free reproduction of the v1.7.0 cookie-array split.
//!
//! `tests/browser_array_parity_cookies.rs` reported
//! native=["0","1","1"] vs interp=["0","1","3"] for
//! `page.get_cookies().len`. The array itself was correct on the compiled
//! plane; the LENGTH was read with `strlen` over the native array header.
//!
//! A native array is `[count: i64][slot: i64]...`, so `strlen` on that buffer
//! reads the count's low byte and stops at the NUL of its second byte:
//! 0 -> 0, and every count in 1..=255 -> 1. That is why 3 printed 1.
//!
//! `env.args()` is the same shape (native string array, no browser needed), so
//! this test pins the class without launching Chrome. Both the chained form
//! (`env.args().len`, the broken one) and the bound form (`argv.len`, which was
//! already right) are checked, at N = 0, 1 and 3.

use std::process::Command;

const PROGRAM: &str = include_str!("fixtures/chained_native_array_len.tl");

fn run(flag: &str, args: &[&str]) -> Vec<String> {
    let path = std::env::temp_dir().join(format!(
        "tallow-chained-arr-{}-{flag}.tl",
        std::process::id()
    ));
    std::fs::write(&path, PROGRAM).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .arg("--")
        .args(args)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "{flag} leg failed:\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("* running in the interpreter"))
        .map(str::to_string)
        .collect()
}

#[test]
fn chained_native_array_len_is_the_count_not_strlen() {
    for (args, want) in [(vec![], "0"), (vec!["a"], "1"), (vec!["a", "b", "c"], "3")] {
        let native = run("--require-native", &args);
        let interp = run("--interpret", &args);
        assert_eq!(
            native,
            interp,
            "planes disagree at N={} ({}):\nnative={native:?}\ninterp={interp:?}",
            args.len(),
            args.join(" ")
        );
        // Chained then bound: both read the same count slot.
        assert_eq!(
            native,
            vec![want.to_string(), want.to_string()],
            "chained `.len` on a native array is not the count at N={}",
            args.len()
        );
    }
}

fn run_program(flag: &str, program: &str, tag: &str, extra_env: &[(&str, &str)]) -> Vec<String> {
    let path = std::env::temp_dir().join(format!(
        "tallow-chained-arr-{tag}-{}-{flag}.tl",
        std::process::id()
    ));
    std::fs::write(&path, program).expect("write program");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tallow"));
    cmd.arg("run")
        .arg(flag)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "{flag} {tag} failed:\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("* running in the interpreter"))
        .map(str::to_string)
        .collect()
}

fn assert_chained_and_bound(flag_pair: [Vec<String>; 2], want: &str, tag: &str) {
    let [native, interp] = flag_pair;
    assert_eq!(
        native, interp,
        "{tag}: planes disagree:\nnative={native:?}\ninterp={interp:?}"
    );
    assert_eq!(
        native,
        vec![want.to_string(), want.to_string()],
        "{tag}: chained `.len` is not the count (want {want})"
    );
}

/// `Transfer.chunk` returns a native array with no `*Array` Kind until
/// `method_result_kind` names `ChunkInfoArray`. Three chunks (10 000 bytes at
/// 4 000) so strlen's "1" cannot pass.
#[test]
fn chained_transfer_chunk_len_is_the_count_not_strlen() {
    let dir = std::env::temp_dir().join(format!("tallow-chained-chunk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("work dir");
    let payload = dir.join("payload.bin");
    let data: Vec<u8> = (0..10_000u32).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    std::fs::write(&payload, data).expect("payload");
    let program = format!(
        r#"fn main() {{
    print(Transfer.chunk("{path}", 4000).len)
    let cs = Transfer.chunk("{path}", 4000)
    print(cs.len)
}}
"#,
        path = payload.display()
    );
    let native = run_program("--require-native", &program, "chunk", &[]);
    let interp = run_program("--interpret", &program, "chunk", &[]);
    assert_chained_and_bound([native, interp], "3", "Transfer.chunk");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `llm.providers()` is the same hole: native array, no Kind, chained `.len`
/// used to strlen. The registry has more than one entry, so "1" is the
/// strlen answer and cannot pass.
#[test]
fn chained_llm_providers_len_is_the_count_not_strlen() {
    let program = r#"import tallow.llm
fn main() {
    print(llm.providers().len)
    let ps = llm.providers()
    print(ps.len)
}
"#;
    let native = run_program("--require-native", program, "providers", &[]);
    let interp = run_program("--interpret", program, "providers", &[]);
    assert_eq!(
        native, interp,
        "llm.providers: planes disagree:\nnative={native:?}\ninterp={interp:?}"
    );
    assert_eq!(native.len(), 2, "chained then bound: {native:?}");
    assert_eq!(
        native[0], native[1],
        "chained and bound must agree: {native:?}"
    );
    let n: i64 = native[0].parse().expect("count");
    assert!(
        n > 1,
        "registry must have more than one provider so strlen(1) cannot pass, got {n}"
    );
}

/// `llm.models(provider)` with two fixture models. Bound form was already
/// pinned in `llm_native_parity`; this is the chained form f972560 missed.
#[test]
fn chained_llm_models_len_is_the_count_not_strlen() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = String::from_utf8_lossy(&buf[..n]);
            let body = r#"{"object":"list","data":[{"id":"mock-1","object":"model","owned_by":"fixture"},{"id":"mock-2","object":"model","owned_by":"fixture"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let cfg_dir =
        std::env::temp_dir().join(format!("tallow-chained-models-{}", std::process::id()));
    std::fs::create_dir_all(&cfg_dir).expect("cfg dir");
    let config = cfg_dir.join("llm.toml");
    std::fs::write(
        &config,
        format!(
            "[providers.mock]\nprotocol = \"openai\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\nmodel_path = \"/models\"\n"
        ),
    )
    .expect("llm.toml");

    let program = r#"import tallow.llm
fn main() {
    print(llm.models("mock").len)
    let ms = llm.models("mock")
    print(ms.len)
}
"#;
    let env = [("TALLOW_LLM_CONFIG", config.to_str().unwrap())];
    let native = run_program("--require-native", program, "models", &env);
    let interp = run_program("--interpret", program, "models", &env);
    assert_chained_and_bound([native, interp], "2", "llm.models");
    let _ = std::fs::remove_dir_all(&cfg_dir);
}
