//! End-to-end Juggler smoke test against the real Camoufox binary.
//!
//! Ignored by default (requires Camoufox installed at the known cache path).
//! Run with:
//!   cargo test --test juggler_smoke -- --ignored --nocapture

use std::time::Duration;

use tallow::browser::juggler::JugglerClient;
use tallow::browser::{BrowserBackend, BrowserConfig};

const CAMOUFOX: &str =
    "~/.cache/camoufox/browsers/official/152.0.4-beta.28-924f3109/camoufox-bin";

#[test]
#[ignore]
fn juggler_drives_camoufox_end_to_end() {
    if !std::path::Path::new(CAMOUFOX).exists() {
        eprintln!("[juggler-smoke] Camoufox not found at {CAMOUFOX}; skipping");
        return;
    }

    let mut config = BrowserConfig::default();
    config.chrome_path = std::path::PathBuf::from(CAMOUFOX);
    config.backend = BrowserBackend::Camoufox;
    config.headless = true;
    config.timeout = Duration::from_secs(30);

    let (mut child, client, _profile_dir) = JugglerClient::launch(&config).expect("launch Camoufox via Juggler");
    println!("[juggler-smoke] launched Camoufox (pid {})", child.id());

    // 1. Enable the browser and fetch version/UA.
    client.enable(true).expect("Browser.enable");
    let info = client.get_info().expect("Browser.getInfo");
    println!("[juggler-smoke] Browser.getInfo => {info}");

    // 2. Open a page and learn its session id.
    let target_id = client.new_page().expect("Browser.newPage");
    let session = client
        .wait_for_session(&target_id, Duration::from_secs(10))
        .expect("wait for Browser.attachedToTarget");
    println!("[juggler-smoke] page session = {session}");

    // 3. Learn the main frame id, then navigate to a data URL.
    let frame_id = client
        .wait_for_main_frame(&session, Duration::from_secs(10))
        .expect("wait for Page.frameAttached");
    println!("[juggler-smoke] main frame = {frame_id}");

    client
        .navigate(&session, &frame_id, "data:text/html,<title>juggler-smoke</title>")
        .expect("Page.navigate");

    // 4. Learn the (post-navigation) execution context, then evaluate JS.
    let ctx = client
        .wait_for_execution_context(&session, &frame_id, Duration::from_secs(10))
        .expect("wait for Runtime.executionContextCreated");
    println!("[juggler-smoke] execution context = {ctx}");

    let title = client
        .evaluate(&session, &ctx, "document.title")
        .expect("Runtime.evaluate document.title");
    println!("[juggler-smoke] document.title = {title:?}");
    assert_eq!(title.as_str(), Some("juggler-smoke"), "title should match data URL");

    // 5. Stealth check: navigator.webdriver must NOT be truthy (Camoufox strips it).
    let webdriver = client
        .evaluate(&session, &ctx, "navigator.webdriver")
        .expect("Runtime.evaluate navigator.webdriver");
    println!("[juggler-smoke] navigator.webdriver = {webdriver:?}");
    assert!(
        webdriver.is_null() || webdriver == false,
        "navigator.webdriver should be false/undefined, got {webdriver:?}"
    );

    // 6. User agent should be Firefox (not Chromium).
    let ua = client
        .evaluate(&session, &ctx, "navigator.userAgent")
        .expect("Runtime.evaluate navigator.userAgent");
    println!("[juggler-smoke] navigator.userAgent = {ua:?}");

    let _ = client.close();
    let _ = child.kill();
    println!("[juggler-smoke] SUCCESS");
}
