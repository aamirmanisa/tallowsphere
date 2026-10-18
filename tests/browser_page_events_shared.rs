//! Register #112 — one event buffer and one pump per CDP session.
//!
//! `Page` is cloned freely and a pooled page is wrapped in a fresh `Page` on
//! every acquire. When the buffer lived on the `Page` value and the pump was
//! spawned at creation, every clone/re-acquire started another listener whose
//! events nobody drained. This test holds two `Page` values for one session and
//! asserts that a single event is delivered exactly once through either handle.
//!
//! A duplicate pump would deliver the same console line twice; a per-value
//! buffer would deliver it only through the handle that created the page.
//!
//! Run with `TALLOW_ALLOW_DIRECT=1` — the browser zone routes loopback through
//! SOCKS by design and Tor refuses loopback (see `tests/nav_direct.rs`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use tallow::browser::cdp::CdpClient;
use tallow::browser::page::{Page, WaitUntil};
use tallow::browser::process::{BrowserConfig, BrowserProcess};

const PAGE: &str = "<!doctype html><html><head><title>shared-events</title></head>\
<body><script>console.log('one-shared-line');</script></body></html>";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_page_handles_share_one_buffer_and_one_pump() {
    let port = serve(PAGE);
    let url = format!("http://127.0.0.1:{port}/");

    let config = BrowserConfig {
        headless: true,
        stealth: false,
        ..Default::default()
    };
    let mut process = BrowserProcess::launch(&config).expect("launch chromium");
    let client = CdpClient::connect(&process.ws_url)
        .await
        .expect("connect cdp");
    let page = client.create_page(None).await.expect("create page");

    // A second handle for the same session, as a pool re-acquire produces.
    let same_session = Page::from_cdp(
        client.clone(),
        page.session_id().to_string(),
        None,
        None,
    )
    .await;
    assert_eq!(same_session.session_id(), page.session_id());
    same_session.enable_runtime_events().await.expect("runtime");

    page.navigate(&url, WaitUntil::Load)
        .await
        .expect("navigate");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drain through the second handle: a per-value buffer would be empty here.
    let from_second = same_session.drain_events("console", 0);
    let from_first = page.drain_events("console", 0);

    let console: Vec<String> = from_second
        .iter()
        .chain(from_first.iter())
        .map(|e| e.payload.clone())
        .collect();
    let occurrences = console.iter().filter(|p| p.contains("one-shared-line")).count();
    assert_eq!(
        occurrences, 1,
        "expected the console line exactly once (one pump, one buffer), got {occurrences}: {console:?}"
    );
    assert!(
        from_second
            .iter()
            .any(|e| e.payload.contains("one-shared-line")),
        "the second handle drained nothing: buffers are per Page value, not per session"
    );

    let _ = process.kill();
}
