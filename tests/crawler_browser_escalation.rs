//! Register #32: browser escalation must be reachable from Tallow.
//!
//! `AdaptiveCrawler::fetch` always implemented the escalation branch, but the
//! Tallow-facing dispatch hard-wired `page: None`, so a JS-rendered page could
//! only ever return "HTTP fetch failed and no browser page available". This
//! test drives the real path end to end:
//!
//!   loopback HTTP server serving a skeleton whose visible text is written by
//!   <script>  →  crawler gets the 146-byte skeleton over HTTP  →  it is below
//!   the completeness threshold  →  escalates into the Page the program passed
//!   →  the returned body contains the JS-written marker and `source=Browser`.
//!
//! Requirements: a Chromium the Tallow launcher can find. When the launch
//! fails the test reports the reason and returns (a machine without a browser
//! cannot exercise this path; pretending it passed would be the bug #100 class).
//!
//! `TALLOW_ALLOW_DIRECT=1`: the target is 127.0.0.1, so the contract-bound Tor
//! egress is not involved — the test never leaves the box.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const SKELETON: &str = "<!doctype html><html><body><div id=\"app\">loading</div>\
<script>document.getElementById(\"app\").textContent=\"RENDERED-BY-JS\";</script></body></html>";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tallow_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("TALLOW_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let release = repo_root().join("target/release/tallow");
    let debug = repo_root().join("target/debug/tallow");
    let mtime = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&release), mtime(&debug)) {
        (Some(r), Some(d)) if r >= d => release,
        (Some(_), Some(_)) => debug,
        (Some(_), None) => release,
        (None, Some(_)) => debug,
        (None, None) => debug,
    }
}

/// Serve `SKELETON` on a loopback port for the duration of the test.
fn serve_skeleton() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            // Read the request head far enough that curl-like clients don't
            // reset on an early close.
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                SKELETON.len(),
                SKELETON
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, handle)
}

#[test]
fn crawler_escalates_to_the_page_it_is_given() {
    let bin = tallow_bin();
    if !bin.exists() {
        eprintln!("skipping: no tallow binary at {}", bin.display());
        return;
    }

    let (port, _server) = serve_skeleton();
    let url = format!("http://127.0.0.1:{port}/");

    let dir = std::env::temp_dir().join(format!("tallow_crawl_esc_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let prog = dir.join("escalate.tl");
    std::fs::write(
        &prog,
        format!(
            r#"@fingerprint_policy(policy: .normalize, bot_identity: "TallowCrawlerEscalationTest/1.0 (+https://tallow.invalid/bot)")
@legal(basis: .public_data, purpose: "crawler escalation regression test", personal_data: false, robots_txt: .respect, rate_limit: 1.per_second)
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let b = Browser.launch(true) match {{ Ok(x) -> x, Err(e) -> {{ print("LAUNCH_ERR: " + e); return }} }}
    let p = b.new_page() match {{ Ok(x) -> x, Err(e) -> {{ print("PAGE_ERR: " + e); b.close(); return }} }}
    let c = AdaptiveCrawler.new()
    match c.fetch("{url}", p) {{
        Ok(r) -> {{
            print("source=" + r.source)
            print("has_js=" + r.body.contains("RENDERED-BY-JS").to_string())
        }}
        Err(e) -> print("FETCH_ERR: " + e)
    }}
    b.close()
}}
"#
        ),
    )
    .unwrap();

    let started = Instant::now();
    let out = Command::new(&bin)
        .args(["run", "--interpret", prog.to_str().unwrap()])
        .env("TALLOW_ALLOW_DIRECT", "1")
        .current_dir(repo_root())
        .output()
        .expect("failed to run tallow");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // No browser on this machine: say so and stop. Do not report a pass.
    if stdout.contains("LAUNCH_ERR") || stdout.contains("PAGE_ERR") {
        eprintln!(
            "skipping: no usable Chromium for the launcher\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );
        return;
    }

    assert!(
        stdout.contains("source=Browser"),
        "the crawl must report Browser as its source, not Http.\nstdout: {}\nstderr: {}\n({:?} elapsed)",
        stdout.trim(),
        stderr.trim(),
        started.elapsed()
    );
    assert!(
        stdout.contains("has_js=true"),
        "the escalated body must contain the JS-written text; a skeleton means the page was not rendered.\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    );
}
