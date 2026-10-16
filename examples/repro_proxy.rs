use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient, Page, WaitUntil};

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = BrowserConfig {
            proxy: Some("socks5://127.0.0.1:9050".to_string()),
            headless: true,
            stealth: true,
            args: vec!["--no-sandbox".to_string()],
            ..Default::default()
        };
        let process = BrowserProcess::launch(&config).unwrap();
        eprintln!("launched, ws_url={}", process.ws_url);
        let client = CdpClient::connect(&process.ws_url).await.unwrap();
        eprintln!("connected");
        let page: Page = client.create_page(None).await.unwrap();
        eprintln!("page created");
        match page.navigate("https://example.com", WaitUntil::Load).await {
            Ok(nav) => eprintln!("NAV OK: status={:?} url={}", nav.status_code, nav.url),
            Err(e) => eprintln!("NAV ERR: {e}"),
        }
        std::mem::forget(process);
    });
}
