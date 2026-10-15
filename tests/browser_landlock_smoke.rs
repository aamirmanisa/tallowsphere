//! RT-FIX-7A smoke test: launch the real browser THROUGH the normal
//! `BrowserProcess::launch` path (which now installs the Landlock read+execute
//! confinement for the child on Linux) and drive it end-to-end over CDP.
//!
//! Ignored by default (launches a real headless browser). Run with:
//!   cargo test --test browser_landlock_smoke -- --ignored --nocapture
//!
//! Pass = the confinement is compatible with a full browser launch + page
//! creation + JS evaluation on this host; failure = the read set needs tuning
//! (the launch error / chrome stderr shows what got denied).

use std::time::Duration;

use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient};

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn chrome_launches_and_drives_under_landlock() {
    let config = BrowserConfig {
        headless: true,
        ..BrowserConfig::default()
    };
    eprintln!("[landlock-smoke] chrome = {:?}", config.chrome_path);

    let mut proc = BrowserProcess::launch(&config).expect("launch under landlock");
    eprintln!("[landlock-smoke] ws = {}", proc.ws_url);

    let client = CdpClient::connect(&proc.ws_url)
        .await
        .expect("cdp connect");
    let page = client
        .create_page(Some("data:text/html,<title>landlock-smoke</title>"))
        .await
        .expect("create page");

    // Title may need a beat after the data-URL commit; poll briefly.
    let mut title = serde_json::Value::Null;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(t) = page.evaluate_expression("document.title").await {
            if t.as_str() == Some("landlock-smoke") {
                title = t;
                break;
            }
            title = t;
        }
    }
    eprintln!("[landlock-smoke] document.title = {title:?}");
    assert_eq!(title.as_str(), Some("landlock-smoke"), "title should match data URL");

    let _ = proc.kill();
    eprintln!("[landlock-smoke] SUCCESS — chrome ran start-to-finish under Landlock");
}
