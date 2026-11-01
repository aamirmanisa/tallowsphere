//! Two-plane parity for `http.batch`'s register gate: one program, two planes,
//! one refusal sentence.
//!
//! The compiled plane consults the register per URL (`runtime/fetch.rs::fetch_entry`)
//! and boxes a refusal as that URL's own entry, leaving the rest of the batch
//! running; the interpreter reaches `http.batch` through `stdlib/http.rs` and,
//! until this lane, reported the register's bare sentence instead of the plane's
//! `http.batch[<url>]: ` prefixed one. `src/interp.rs::http_batch_scoped` now
//! gates before the facade, in the compiled plane's words.
//!
//! The test is deliberately small and loopback-only:
//!
//! * `127.0.0.2:<closed port>` — unlisted in `configs/tallow/scope/authorized-hosts.toml`,
//!   so both planes must refuse it with the register's `scope:not-listed` code
//!   *before* a socket is opened (nothing is listening there, so a transport
//!   error would prove a connection was attempted).
//! * a `127.0.0.1` listener — listed (`self-hosted`), so it must still be fetched
//!   by the same batch: a refusal that also killed the permitted URL would pass a
//!   weaker test.
//!
//! The expected sentence is derived from `tallow::scope::require`, not hardcoded,
//! so a register or wording change fails here instead of silently drifting.
//!
//! Known divergence this test does NOT paper over: the interpreter's entries are
//! the declared `BatchResponse` structs, the compiled plane's are `Result` boxes,
//! so the two programs below read their entries in each plane's own idiom and the
//! comparison is on the refusal sentence and the permitted fetch.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

const UNLISTED: &str = "http://127.0.0.2:18082/unlisted";

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        return PathBuf::from(p);
    }
    if let Some(p) = option_env!("CARGO_BIN_EXE_tallow") {
        return PathBuf::from(p);
    }
    panic!("set TALLOW_BIN or run via cargo test so CARGO_BIN_EXE_tallow is set");
}

/// A listed loopback listener that answers two requests with `200 listed-body`.
fn spawn_listed_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let addr = listener.local_addr().expect("fixture addr");
    thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "listed-body";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}/listed")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn annotations() -> &'static str {
    r#"@cra_class(.default)
@legal(basis: .self_hosted, purpose: "two-plane scope-gate parity on loopback", personal_data: false, robots_txt: .respect)
"#
}

/// The interpreter's idiom: `[]BatchResponse` with `ok` / `error.message`.
fn interpreter_program(unlisted: &str, listed: &str) -> String {
    format!(
        r#"{ann}import tallow.http

fn main() with Net(batch) {{
    let urls = ["{unlisted}", "{listed}"]
    let rs = http.batch(urls, 1, {{}})
    let refused = rs[0]
    if refused.ok {{
        print("refused=<unlisted ran>")
    }} else {{
        print("refused=" + refused.error.message)
    }}
    let listed_entry = rs[1]
    if listed_entry.ok {{
        print("listed status=" + listed_entry.response.status.to_string())
    }} else {{
        print("listed error=" + listed_entry.error.message)
    }}
}}
"#,
        ann = annotations()
    )
}

/// The compiled plane's idiom: `Result` entries read with `match`.
fn native_program(unlisted: &str, listed: &str) -> String {
    format!(
        r#"{ann}import tallow.http

fn main() with Net(batch) {{
    let urls = ["{unlisted}", "{listed}"]
    let rs = http.batch(urls, 1, {{}})
    match rs[0] {{
        Ok(v) -> print("refused=<unlisted ran>"),
        Err(m) -> print("refused=" + m),
    }}
    match rs[1] {{
        Ok(v) -> print("listed status=" + v.status.to_string()),
        Err(m) -> print("listed error=" + m),
    }}
}}
"#,
        ann = annotations()
    )
}

struct PlaneRun {
    stdout: String,
    stderr: String,
    status: Option<i32>,
}

fn run_plane(dir: &Path, program: &str, flag: &str) -> PlaneRun {
    let path = dir.join(if flag == "--interpret" {
        "batch_interp.tl"
    } else {
        "batch_native.tl"
    });
    std::fs::write(&path, program).expect("write program");
    let out = Command::new(tallow_bin())
        .args(["run", flag, path.to_str().expect("utf-8 path")])
        .current_dir(manifest_dir())
        // Loopback fixtures are the only egress; no proxy hop is involved.
        .env("TALLOW_ALLOW_DIRECT", "1")
        .env_remove("TALLOW_PROXY")
        .env_remove("TALLOW_TOR")
        .output()
        .expect("run tallow");
    PlaneRun {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        status: out.status.code(),
    }
}

/// The line the plane printed for the refused URL, verbatim.
fn refused_line(run: &PlaneRun) -> String {
    run.stdout
        .lines()
        .find(|l| l.starts_with("refused="))
        .unwrap_or_else(|| {
            panic!(
                "no refusal line in stdout (rc={:?}):\nstdout:\n{}\nstderr:\n{}",
                run.status, run.stdout, run.stderr
            )
        })
        .to_string()
}

#[test]
fn http_batch_scope_refusal_matches_across_planes_and_the_listed_url_still_runs() {
    // The expected sentence is the register's, taken from the gate itself: if
    // 127.0.0.2 ever becomes listed this fails loudly instead of asserting a
    // refusal that no longer happens.
    let refusal = tallow::scope::require(UNLISTED, "GET")
        .expect_err("127.0.0.2 must be unlisted in the shipped register");
    let expected = format!(
        "refused=http.batch[{UNLISTED}]: {} — {}",
        refusal.code(),
        refusal.explain()
    );

    let listed = spawn_listed_server();

    let dir = std::env::temp_dir().join(format!("tallow-batch-scope-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let interp = run_plane(&dir, &interpreter_program(UNLISTED, &listed), "--interpret");
    let native = run_plane(&dir, &native_program(UNLISTED, &listed), "--require-native");

    assert_eq!(
        refused_line(&interp),
        expected,
        "interpreter refusal sentence drifted from the register\nstderr:\n{}",
        interp.stderr
    );
    assert_eq!(
        refused_line(&native),
        expected,
        "compiled-plane refusal sentence drifted from the register\nstderr:\n{}",
        native.stderr
    );

    // The refusal is one entry, not a failed batch: the listed URL in the same
    // call still went out and came back 200 on both planes.
    assert!(
        interp.stdout.contains("listed status=200"),
        "the permitted URL must still run under --interpret:\n{}",
        interp.stdout
    );
    assert!(
        native.stdout.contains("listed status=200"),
        "the permitted URL must still run under --require-native:\n{}",
        native.stdout
    );

    let _ = std::fs::remove_dir_all(&dir);
}
