use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient, Page, WaitUntil};

#[tokio::main]
async fn main() {
    // Launch Chromium through Tor (same config as repro_proxy, verified working)
    let config = BrowserConfig {
        proxy: Some("socks5://127.0.0.1:9050".to_string()),
        headless: true,
        stealth: true,
        args: vec!["--no-sandbox".to_string()],
        ..Default::default()
    };
    let process = BrowserProcess::launch(&config).expect("launch");
    eprintln!("launched ws_url={}", process.ws_url);
    let client = CdpClient::connect(&process.ws_url).await.expect("connect");
    eprintln!("connected");
    let page: Page = client.create_page(None).await.expect("create_page");
    eprintln!("page created");

    // Navigate to the store locator for TX. Use a long timeout by overriding.
    // navigate uses self.timeout (30s). We'll accept the partial result on
    // timeout via navigate_soft if available, else just try navigate.
    eprintln!("=== navigating storelocator?state=TX (may hang server-side) ===");
    match page.navigate("https://stma.membersgomobile.com/storelocator?state=TX", WaitUntil::DomContentLoaded).await {
        Ok(nav) => eprintln!("NAV OK: status={:?} url={}", nav.status_code, nav.url),
        Err(e) => eprintln!("NAV ERR: {e}"),
    }

    // Give any client-side JS a moment, then read window.locations
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let expr = r#"JSON.stringify({
        locLen: (typeof locations !== 'undefined') ? locations.length : -1,
        locs: (typeof locations !== 'undefined') ? locations : [],
        url: location.href,
        title: document.title
    })"#;
    match page.evaluate_expression(expr).await {
        Ok(v) => eprintln!("RESULT: {}", v),
        Err(e) => eprintln!("EVAL ERR: {e}"),
    }

    // Also dump the raw page text to see if store names rendered
    match page.evaluate_expression("document.body ? document.body.innerText.substring(0,3000) : ''").await {
        Ok(v) => eprintln!("BODY: {}", v),
        Err(e) => eprintln!("BODY ERR: {e}"),
    }

    std::mem::forget(process);
}
