//! Register #105 — standalone reproduction: `Page::navigate` against one
//! loopback page, no interpreter, no policy annotations, one timer.
//!
//! The `.tl` path has produced three false leads. This test drives the CDP
//! layer directly: launch → connect → create_page → navigate, and asserts the
//! call returns well inside its own deadline.
//!
//! Run with:
//!   TALLOW_ALLOW_DIRECT=1 cargo test --test nav_direct -- --nocapture --test-threads=1
//! and with `TALLOW_DEBUG_NAV=1` for the `[nav]` markers.
//!
//! `TALLOW_ALLOW_DIRECT=1` is mandatory, not a convenience. The browser zone
//! launches Chrome with `--proxy-bypass-list=<-loopback>`, which routes
//! loopback through the zone's SOCKS proxy on purpose (it stops page JS from
//! reaching services on this host), and Tor refuses loopback destinations
//! (`curl --socks5-hostname 127.0.0.1:9050 http://127.0.0.1:PORT/` fails with
//! SOCKS code 2). Without the flag every load here dies with
//! `net::ERR_SOCKS_CONNECTION_FAILED` before navigation starts.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use tallow::browser::cdp::CdpClient;
use tallow::browser::page::WaitUntil;
use tallow::browser::process::{BrowserConfig, BrowserProcess};

const PAGE: &str = "<!doctype html><html><head><title>nav-direct</title></head>\
<body><div id=\"app\">loading</div>\
<script>document.getElementById(\"app\").textContent=\"RENDERED-BY-JS\";</script>\
</body></html>";

/// Serve one page on loopback for the life of the process.
fn serve(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

async fn open_page() -> (BrowserProcess, CdpClient, tallow::browser::page::Page) {
    let config = BrowserConfig {
        headless: true,
        stealth: false,
        ..Default::default()
    };
    let process = BrowserProcess::launch(&config).expect("launch chromium");
    let client = CdpClient::connect(&process.ws_url)
        .await
        .expect("connect cdp");
    let page = client.create_page(None).await.expect("create page");
    (process, client, page)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn navigate_returns_on_a_page_that_loads() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");
    let (_process, _client, page) = open_page().await;

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        page.navigate(&url, WaitUntil::DomContentLoaded),
    )
    .await;
    let elapsed = started.elapsed();

    match result {
        Ok(Ok(nav)) => {
            eprintln!(
                "navigate ok in {:?}: url={} frame={} status={:?}",
                elapsed, nav.url, nav.frame_id, nav.status_code
            );
            assert!(
                elapsed < Duration::from_secs(10),
                "navigation completed but took {elapsed:?} — the wait loop is spending its deadline"
            );
        }
        Ok(Err(e)) => panic!("navigate returned Err after {elapsed:?}: {e}"),
        Err(_) => panic!("navigate did not return within 20 s (its own timeout is 30 s)"),
    }

    let body = page
        .evaluate_expression("document.body.innerText")
        .await
        .expect("evaluate after navigate");
    eprintln!("body after navigate: {body}");
    assert!(
        body.as_str().unwrap_or_default().contains("RENDERED-BY-JS"),
        "page did not render: {body}"
    );
}

/// Same direct call, but on the runtime flavour the interpreter actually uses
/// (`src/runtime/mod.rs`: `Builder::new_current_thread()`). A multi-thread
/// runtime hides starvation bugs that a single-threaded one exposes.
#[tokio::test]
async fn navigate_returns_on_a_current_thread_runtime() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");
    let (_process, _client, page) = open_page().await;

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        page.navigate(&url, WaitUntil::DomContentLoaded),
    )
    .await;
    let elapsed = started.elapsed();

    match result {
        Ok(Ok(nav)) => eprintln!(
            "current_thread navigate ok in {elapsed:?}: url={} frame={}",
            nav.url, nav.frame_id
        ),
        Ok(Err(e)) => panic!("current_thread navigate returned Err after {elapsed:?}: {e}"),
        Err(_) => panic!("current_thread navigate did not return within 20 s"),
    }
    assert!(
        elapsed < Duration::from_secs(10),
        "current_thread navigation took {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn navigate_twice_returns_both_times() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");
    let (_process, _client, page) = open_page().await;

    for attempt in 1..=2 {
        let started = Instant::now();
        let nav = tokio::time::timeout(
            Duration::from_secs(20),
            page.navigate(&url, WaitUntil::DomContentLoaded),
        )
        .await
        .unwrap_or_else(|_| panic!("navigation {attempt} did not return within 20 s"))
        .unwrap_or_else(|e| panic!("navigation {attempt} failed: {e}"));
        eprintln!("attempt {attempt}: {:?} url={}", started.elapsed(), nav.url);
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
