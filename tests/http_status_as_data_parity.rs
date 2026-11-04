//! Two-plane audit of `http.get` / `http.post`: a fetched 4xx/5xx is claimed to
//! be data (a `Response`), not a transport error.
//!
//! Measured 2026-10-31 against `/workspace/tallowsphere/target/debug/tallow`
//! (`tallow 1.5.8` / git `0ae4f3016f` dirty / build `2026-10-31T04:12:10Z`)
//! on loopback only. The planes do **not** all agree. This file pins the
//! agreement where it holds and names both planes' values where it does not.
//!
//! Verdicts:
//! - 200 GET with body — AGREE (`200` / `ok-body` / rc 0 / data)
//! - 404 GET with body — DISAGREE (interp `Err("http.get: http status: 404")`;
//!   native `404` + `missing-body`)
//! - 500 GET with body — DISAGREE (interp `Err("http.get: http status: 500")`;
//!   native `500` + `server-error-body`)
//! - 302 to a second local path — AGREE (both follow to `200` / `ok-body`)
//! - connection refused — DISAGREE (interp `Err("http.get: redirect-transport:
//!   refusing <url> — io: Connection refused (os error 111)")`; native aborts
//!   with `runtime error:` + Connection refused, rc != 0)
//! - timeout via extra Int milliseconds — DISAGREE (interp honours `http.get(url, 200)`
//!   as `Err("http.get: redirect-transport: refusing <url> — timeout: per call")`;
//!   native ignores the extra arg and returns `200` / `slow-body`)
//! - POST returning 404 — AGREE on status-as-data now that loopback grants POST
//!   (`authorized-hosts.toml` methods include POST) and `http.post` returns a
//!   `Response` for a 4xx instead of wrapping it as `Err`
//!
//! `tallow check` accepts both `let r: Response = http.get(u)` and
//! `let r: Result<Response> = http.get(u)` (rc 0, only W0130). A checker that
//! will not pick a shape cannot contradict a runtime claim by naming one, but
//! it also cannot protect the claim.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static PROG_SEQ: AtomicU64 = AtomicU64::new(0);

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        return PathBuf::from(p);
    }
    if let Some(p) = option_env!("CARGO_BIN_EXE_tallow") {
        return PathBuf::from(p);
    }
    panic!("set TALLOW_BIN or run via cargo test so CARGO_BIN_EXE_tallow is set");
}

fn annotations() -> &'static str {
    r#"@legal(
    basis: .research,
    purpose: "loopback two-plane audit of http.get status-as-data",
    personal_data: false,
    rate_limit: 10.per_second
)
@cra_class(.default)
@persona(id: "assay-http", cover_class: .researcher, compartment: "assay", fingerprint_seed: "assay-http-160")
@burn_plan(persona: "assay-http", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowAssay/1.0 (+https://tallow.invalid/bot)")
"#
}

fn fields_program() -> String {
    format!(
        r#"{ann}fn main() with Net(get), Net(post) {{
    let u = env.get("MSURL")
    let m = env.get("MSMETHOD")
    if m == "POST" {{
        let r = http.post(u, "post-body")
        print(r.status)
        print(r.text())
    }} else {{
        let r = http.get(u)
        print(r.status)
        print(r.text())
    }}
}}
"#,
        ann = annotations()
    )
}

fn print_program() -> String {
    format!(
        r#"{ann}fn main() with Net(get), Net(post) {{
    let u = env.get("MSURL")
    let m = env.get("MSMETHOD")
    if m == "POST" {{
        let r = http.post(u, "post-body")
        print(r)
    }} else {{
        let r = http.get(u)
        print(r)
    }}
}}
"#,
        ann = annotations()
    )
}

fn timeout_fields_program() -> String {
    format!(
        r#"{ann}fn main() with Net(get) {{
    let u = env.get("MSURL")
    let r = http.get(u, 200)
    print(r.status)
    print(r.text())
}}
"#,
        ann = annotations()
    )
}

fn timeout_print_program() -> String {
    format!(
        r#"{ann}fn main() with Net(get) {{
    let u = env.get("MSURL")
    let r = http.get(u, 200)
    print(r)
}}
"#,
        ann = annotations()
    )
}

fn as_response_program() -> String {
    format!(
        r#"{ann}fn main() with Net(get) {{
    let u = env.get("MSURL")
    let r: Response = http.get(u)
    print(r.status)
}}
"#,
        ann = annotations()
    )
}

fn as_result_program() -> String {
    format!(
        r#"{ann}fn main() with Net(get) {{
    let u = env.get("MSURL")
    let r: Result<Response> = http.get(u)
    print(r)
}}
"#,
        ann = annotations()
    )
}

fn write_prog(tag: &str, src: &str) -> PathBuf {
    let mut hasher = 0u64;
    for b in src.as_bytes() {
        hasher = hasher.wrapping_mul(16777619) ^ *b as u64;
    }
    let seq = PROG_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "tallow-assay-http-{}-{}-{seq}-{tag}.tl",
        std::process::id(),
        hasher
    ));
    std::fs::write(&path, src).expect("write program");
    path
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(program: &Path, extra: &[&str], method: &str, url: &str) -> Run {
    let output: Output = Command::new(tallow_bin())
        .arg("run")
        .args(extra)
        .arg(program)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env("TALLOW_FETCH_DELAY_MS", "0")
        .env_remove("TALLOW_PROXY")
        .env("MSMETHOD", method)
        .env("MSURL", url)
        .output()
        .expect("run tallow");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        code: output.status.code().unwrap_or(-1),
    }
}

fn check(program: &Path) -> Run {
    let output = Command::new(tallow_bin())
        .arg("check")
        .arg(program)
        .output()
        .expect("tallow check");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        code: output.status.code().unwrap_or(-1),
    }
}

fn spawn_loopback() -> String {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || handle_request(stream));
            }
        });
        format!("http://{addr}")
    })
    .clone()
}

fn handle_request(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0_u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);

    if method == "GET" && path == "/slow" {
        thread::sleep(Duration::from_secs(3));
    }

    let (status_line, body, extra_headers): (&str, &[u8], &str) = match (method, path) {
        ("GET", "/ok") => ("200 OK", b"ok-body", ""),
        ("GET", "/missing") => ("404 Not Found", b"missing-body", ""),
        ("GET", "/boom") => ("500 Internal Server Error", b"server-error-body", ""),
        ("GET", "/go") => ("302 Found", b"", "Location: /ok\r\n"),
        ("GET", "/slow") => ("200 OK", b"slow-body", ""),
        ("POST", "/ok") => ("200 OK", b"post-ok", ""),
        ("POST", "/missing") => ("404 Not Found", b"post-missing-body", ""),
        _ => ("404 Not Found", b"nope", ""),
    };
    let response = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len(),
        extra = extra_headers
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);

    // Close cleanly. A POST leaves its request body unread — this handler only
    // ever reads the first segment — and on Linux a close with unread received
    // data sends RST instead of FIN, which lets the peer discard the response
    // that was just written. Measured 2026-11-03 on run 41738066552:
    // post_404_measured_values saw `status: 404, body: ""` against a server
    // that had sent `Content-Length: 17`. GETs never hit it because they send
    // no body, which is why only the POST assertions flaked.
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0_u8; 1024];
    while let Ok(n) = stream.read(&mut sink) {
        if n == 0 {
            break;
        }
    }
}

fn closed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind closed port");
    let addr = listener.local_addr().expect("closed addr");
    drop(listener);
    format!("http://{addr}/x")
}

fn assert_native_ran(run: &Run) {
    assert!(
        !run.stderr.contains("native build unavailable"),
        "native leg fell back:\\n{}",
        run.stderr
    );
}

#[test]
fn checker_accepts_response_and_result_annotations() {
    let as_resp = write_prog("as-resp", &as_response_program());
    let as_res = write_prog("as-result", &as_result_program());
    let r1 = check(&as_resp);
    let r2 = check(&as_res);
    let _ = std::fs::remove_file(&as_resp);
    let _ = std::fs::remove_file(&as_res);

    assert_eq!(
        r1.code, 0,
        "check Response annotation failed:\\n{}{}",
        r1.stdout, r1.stderr
    );
    assert_eq!(
        r2.code, 0,
        "check Result<Response> annotation failed:\\n{}{}",
        r2.stdout, r2.stderr
    );
    let text1 = format!("{}{}", r1.stdout, r1.stderr);
    let text2 = format!("{}{}", r2.stdout, r2.stderr);
    assert!(
        text1.contains("check passed"),
        "Response check stdout/err:\\n{text1}"
    );
    assert!(
        text2.contains("check passed"),
        "Result check stdout/err:\\n{text2}"
    );
}

#[test]
fn http_get_200_agrees_status_body_and_data() {
    let base = spawn_loopback();
    let prog = write_prog("fields", &fields_program());
    let url = format!("{base}/ok");
    let interp = run(&prog, &["--interpret"], "GET", &url);
    let native = run(&prog, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&prog);

    assert_eq!(
        interp.code, 0,
        "interp 200 failed:\\n{}{}",
        interp.stdout, interp.stderr
    );
    assert_eq!(
        native.code, 0,
        "native 200 failed:\\n{}{}",
        native.stdout, native.stderr
    );
    assert_native_ran(&native);
    assert_eq!(interp.stdout, "200\nok-body\n");
    assert_eq!(native.stdout, interp.stdout);
}

#[test]
fn http_get_302_follows_and_agrees() {
    let base = spawn_loopback();
    let prog = write_prog("fields", &fields_program());
    let url = format!("{base}/go");
    let interp = run(&prog, &["--interpret"], "GET", &url);
    let native = run(&prog, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&prog);

    assert_eq!(
        interp.code, 0,
        "interp 302 failed:\\n{}{}",
        interp.stdout, interp.stderr
    );
    assert_eq!(
        native.code, 0,
        "native 302 failed:\\n{}{}",
        native.stdout, native.stderr
    );
    assert_native_ran(&native);
    assert_eq!(interp.stdout, "200\nok-body\n");
    assert_eq!(native.stdout, interp.stdout);
}

#[test]
fn http_get_404_measured_values() {
    let base = spawn_loopback();
    let fields = write_prog("fields", &fields_program());
    let printed = write_prog("print", &print_program());
    let url = format!("{base}/missing");

    let interp_print = run(&printed, &["--interpret"], "GET", &url);
    let interp_fields = run(&fields, &["--interpret"], "GET", &url);
    let native_fields = run(&fields, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&fields);
    let _ = std::fs::remove_file(&printed);

    assert_eq!(
        interp_print.code, 0,
        "interp print 404:\\n{}{}",
        interp_print.stdout, interp_print.stderr
    );
    assert!(
        interp_print
            .stdout
            .contains("Err(\"http.get: http status: 404\")"),
        "interp 404 print moved: {:?}",
        interp_print.stdout
    );
    assert_ne!(interp_fields.code, 0);
    assert!(
        interp_fields
            .stderr
            .contains("unknown method: .status() on Err"),
        "interp 404 field-access stderr moved:\\n{}",
        interp_fields.stderr
    );

    assert_eq!(
        native_fields.code, 0,
        "native 404:\\n{}{}",
        native_fields.stdout, native_fields.stderr
    );
    assert_native_ran(&native_fields);
    assert_eq!(
        native_fields.stdout, "404\nmissing-body\n",
        "native 404 field-access moved: {:?}",
        native_fields.stdout
    );
}

#[test]
fn http_get_500_measured_values() {
    let base = spawn_loopback();
    let fields = write_prog("fields", &fields_program());
    let printed = write_prog("print", &print_program());
    let url = format!("{base}/boom");

    let interp_print = run(&printed, &["--interpret"], "GET", &url);
    let native_fields = run(&fields, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&fields);
    let _ = std::fs::remove_file(&printed);

    assert_eq!(interp_print.code, 0);
    assert!(
        interp_print
            .stdout
            .contains("Err(\"http.get: http status: 500\")"),
        "interp 500 print moved: {:?}",
        interp_print.stdout
    );
    assert_eq!(
        native_fields.code, 0,
        "native 500:\\n{}{}",
        native_fields.stdout, native_fields.stderr
    );
    assert_native_ran(&native_fields);
    assert_eq!(native_fields.stdout, "500\nserver-error-body\n");
}

#[test]
fn connection_refused_measured_values() {
    let fields = write_prog("fields", &fields_program());
    let printed = write_prog("print", &print_program());
    let url = closed_url();

    let interp_print = run(&printed, &["--interpret"], "GET", &url);
    let native_fields = run(&fields, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&fields);
    let _ = std::fs::remove_file(&printed);

    assert_eq!(interp_print.code, 0);
    // Re-pinned after gated redirect follow (egress_http::follow): a refused
    // connection is FollowRefusal::Transport, whose Display is
    // `redirect-transport: refusing <url> — <detail>`. The os-error text is
    // unchanged; the wrapper is the change.
    assert!(
        interp_print.stdout.contains("redirect-transport: refusing")
            && interp_print
                .stdout
                .contains("io: Connection refused (os error 111)"),
        "interp refused print moved: {:?}",
        interp_print.stdout
    );
    // UPDATED 2026-10-31 after the egress-register merge (86d44a5): the compiled
    // plane no longer returns -1/(null) with exit 0 for a transport failure. The
    // null handle now goes through tallow_check_string, so the program aborts with
    // `runtime error: fetch: io: Connection refused (os error 111)` and exit 1.
    // Loud instead of silent — still not parity, because the interpreter returns
    // the Err as a value (measured above, exit 0).
    assert_ne!(
        native_fields.code, 0,
        "native plane exited 0 on a refused connection: \n{}{}",
        native_fields.stdout, native_fields.stderr
    );
    assert_native_ran(&native_fields);
    assert!(
        native_fields.stderr.contains("runtime error:")
            && native_fields.stderr.contains("Connection refused"),
        "native abort message moved: {:?}",
        native_fields.stderr
    );
    assert!(
        native_fields.stdout.trim().is_empty(),
        "native printed a value: {:?}",
        native_fields.stdout
    );
}

#[test]
fn post_404_measured_values() {
    // Re-pinned after two genuine changes, not a test softening:
    // 1. configs/tallow/scope/authorized-hosts.toml grants POST on loopback
    //    (local model servers). The 2026-10-31 pin assumed GET/HEAD only, so
    //    it expected method-not-allowed on both planes; that refusal is gone.
    // 2. http.post now returns build_response_value for any final status
    //    (gated follow). A 404 is a Response, not Err("http.post: http status:
    //    404"). GET still wraps 4xx as Err — that split is the measured surface.
    let base = spawn_loopback();
    let fields = write_prog("fields", &fields_program());
    let printed = write_prog("print", &print_program());
    let url = format!("{base}/missing");
    let ok_url = format!("{base}/ok");

    let interp_print = run(&printed, &["--interpret"], "POST", &url);
    let native_fields = run(&fields, &["--require-native"], "POST", &url);
    let native_ok = run(&fields, &["--require-native"], "POST", &ok_url);
    let _ = std::fs::remove_file(&fields);
    let _ = std::fs::remove_file(&printed);

    let interp_all = format!("{}{}", interp_print.stdout, interp_print.stderr);
    assert_eq!(
        interp_print.code, 0,
        "interp POST 404 should be data now that loopback grants POST: {interp_all}"
    );
    assert!(
        interp_print.stdout.contains("status: 404")
            && interp_print.stdout.contains("cG9zdC1taXNzaW5nLWJvZHk="),
        "interp POST 404 print moved (want Response status 404, body b64 of post-missing-body): {interp_all}"
    );

    assert_eq!(
        native_fields.code, 0,
        "native POST 404:\n{}{}",
        native_fields.stdout, native_fields.stderr
    );
    assert_native_ran(&native_fields);
    assert_eq!(
        native_fields.stdout, "404\npost-missing-body\n",
        "native POST 404 field-access moved: {:?}",
        native_fields.stdout
    );

    assert_eq!(
        native_ok.code, 0,
        "native POST 200:\n{}{}",
        native_ok.stdout, native_ok.stderr
    );
    assert_native_ran(&native_ok);
    assert_eq!(
        native_ok.stdout, "200\npost-ok\n",
        "native POST 200 field-access moved: {:?}",
        native_ok.stdout
    );
}

#[test]
fn timeout_extra_int_measured_values() {
    let base = spawn_loopback();
    let fields = write_prog("to-fields", &timeout_fields_program());
    let printed = write_prog("to-print", &timeout_print_program());
    let url = format!("{base}/slow");

    let interp_print = run(&printed, &["--interpret"], "GET", &url);
    let native_fields = run(&fields, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&fields);
    let _ = std::fs::remove_file(&printed);

    assert_eq!(interp_print.code, 0);
    // Re-pinned after gated redirect follow: the timeout is the same
    // FollowRefusal::Transport wrapper as connection-refused, with detail
    // `timeout: per call`.
    assert!(
        interp_print.stdout.contains("redirect-transport: refusing")
            && interp_print.stdout.contains("timeout: per call"),
        "interp timeout print moved: {:?}",
        interp_print.stdout
    );
    assert_eq!(
        native_fields.code, 0,
        "native timeout:\\n{}{}",
        native_fields.stdout, native_fields.stderr
    );
    assert_native_ran(&native_fields);
    assert_eq!(
        native_fields.stdout, "200\nslow-body\n",
        "native ignored the 200ms extra arg; stdout moved: {:?}",
        native_fields.stdout
    );
}

#[ignore = "DISAGREE: interp Err(\"http.get: http status: 404\") vs native status=404 body=missing-body — do not un-ignore until both planes return a Response"]
#[test]
fn http_get_404_planes_agree() {
    let base = spawn_loopback();
    let prog = write_prog("fields", &fields_program());
    let url = format!("{base}/missing");
    let interp = run(&prog, &["--interpret"], "GET", &url);
    let native = run(&prog, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&prog);
    assert_eq!(interp.code, native.code);
    assert_eq!(interp.stdout, native.stdout);
}

#[ignore = "DISAGREE: interp Err(\"http.get: http status: 500\") vs native status=500 body=server-error-body"]
#[test]
fn http_get_500_planes_agree() {
    let base = spawn_loopback();
    let prog = write_prog("fields", &fields_program());
    let url = format!("{base}/boom");
    let interp = run(&prog, &["--interpret"], "GET", &url);
    let native = run(&prog, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&prog);
    assert_eq!(interp.code, native.code);
    assert_eq!(interp.stdout, native.stdout);
}

#[ignore = "DISAGREE: interp Err(connection refused) vs native status=-1 body=(null)"]
#[test]
fn connection_refused_planes_agree() {
    let prog = write_prog("fields", &fields_program());
    let url = closed_url();
    let interp = run(&prog, &["--interpret"], "GET", &url);
    let native = run(&prog, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&prog);
    assert_eq!(interp.code, native.code);
    assert_eq!(interp.stdout, native.stdout);
}

#[ignore = "DISAGREE: interp Err(\"http.post: http status: 404\") vs native status=-1 body=(null); native POST /ok is also null"]
#[test]
fn post_404_planes_agree() {
    let base = spawn_loopback();
    let prog = write_prog("fields", &fields_program());
    let url = format!("{base}/missing");
    let interp = run(&prog, &["--interpret"], "POST", &url);
    let native = run(&prog, &["--require-native"], "POST", &url);
    let _ = std::fs::remove_file(&prog);
    assert_eq!(interp.code, native.code);
    assert_eq!(interp.stdout, native.stdout);
}

#[ignore = "DISAGREE: interp Err(\"http.get: timeout: per call\") on extra Int 200ms vs native 200/slow-body (extra arg ignored)"]
#[test]
fn timeout_extra_int_planes_agree() {
    let base = spawn_loopback();
    let prog = write_prog("to-fields", &timeout_fields_program());
    let url = format!("{base}/slow");
    let interp = run(&prog, &["--interpret"], "GET", &url);
    let native = run(&prog, &["--require-native"], "GET", &url);
    let _ = std::fs::remove_file(&prog);
    assert_eq!(interp.code, native.code);
    assert_eq!(interp.stdout, native.stdout);
}
