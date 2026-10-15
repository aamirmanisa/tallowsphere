//! vin_iaai.rs — IAAI salvage-auction VIN lookup via the Tallow stealth browser.
//!
//! IAAI (iaai.com) is confirmed-clear of bot walls when driven through the Tallow
//! stealth browser (real Chromium + stealth profile + optional Tor/residential proxy),
//! unlike Carfax's API host and Copart. It returns Carfax-style salvage depth that the
//! free `.tl` aggregator is missing: lot number, title/brand (Clean/Salvage/Rebuilt),
//! primary & secondary damage, odometer, sale price/status, sale date, salvage yard.
//!
//! Strategy:
//!   1. Stealth Chromium (headless).
//!   2. Navigate to IAAI VIN search: https://www.iaai.com/Search?keyword=<VIN>
//!   3. Let the page's own JS/XHR load the results (IAAI is ASP.NET MVC; lot data is
//!      XHR-rendered, not in the initial HTML).
//!   4. Extract the rendered lot cards from the DOM via JS (querySelectorAll over the
//!      lot grid), plus the result count, into a JSON report.
//!
//! Build: cargo build --example vin_iaai
//! Run:   ./target/debug/examples/vin_iaai <VIN>
//!        # optional exit proxy: VIN_PROXY=socks5://<residential>
//!
//! Public-data scrape only — reads what IAAI publicly renders for a VIN search.

use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient, Page, WaitUntil};

#[tokio::main]
async fn main() {
    let vin = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "2T3F1RFV1PC382478".to_string());
    let proxy = std::env::var("VIN_PROXY").ok();

    let config = BrowserConfig {
        proxy: proxy.clone(),
        headless: true,
        stealth: true,
        args: vec![
            "--no-sandbox".to_string(),
            "--disable-blink-features=AutomationControlled".to_string(),
            "--window-size=1366,900".to_string(),
        ],
        ..Default::default()
    };
    let process = BrowserProcess::launch(&config).expect("launch");
    eprintln!("[+] launched");
    let client = CdpClient::connect(&process.ws_url).await.expect("connect");
    let page: Page = client.create_page(None).await.expect("page");
    let profile = tallow::browser::stealth::StealthProfile::chrome_linux();
    let _ = page.apply_stealth(&profile).await;
    eprintln!("[+] stealth applied");

    let url = format!("https://www.iaai.com/Search?keyword={vin}");
    eprintln!("[+] navigating IAAI search: {url}");
    let nav = page.navigate(&url, WaitUntil::DomContentLoaded).await;
    match &nav {
        Ok(n) => eprintln!("[+] nav status={:?} url={}", n.status_code, n.url),
        Err(e) => eprintln!("[!] nav err: {e}"),
    }
    // Let the XHR results render.
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // Extract the rendered lot data + result count from the DOM.
    let extract = r#"JSON.stringify((() => {
        // Result count
        const countEl = document.querySelector('[class*="result-count"], [class*="ResultCount"], .results-header span, h1, h2');
        const count = countEl ? countEl.innerText.trim() : '';
        // Lot cards — IAAI renders results in cards containing title/href with /VehicleDetail/ or /Buy-Now/.
        const cards = Array.from(document.querySelectorAll('a[href*="/VehicleDetail/"], a[href*="/Buy-Now/"], [class*="vehicle-card"], [class*="VehicleCard"], [class*="lot-card"], [class*="LotCard"]'));
        const lots = [];
        for (const c of cards.slice(0, 30)) {
            const card = c.closest('[class*="card"], article, li') || c;
            lots.push({
                href: c.href || '',
                title: (card.querySelector('[class*="title"], [class*="Title"], h3, h4, h5')||{}).innerText || '',
                lot: (card.innerText.match(/(?:Lot\s*#?|Stock\s*#?)\s*:?\s*([0-9]+)/i)||[])[1] || '',
                vin: (card.innerText.match(/[A-HJ-NPR-Z0-9]{17}/)||[])[0] || '',
                text: card.innerText.replace(/\s+/g,' ').trim().substring(0, 600)
            });
        }
        return { count, lotCount: lots.length, lots };
    })())"#;
    let result = page.evaluate_expression(extract).await;
    let body = result.map(|v| v.to_string()).unwrap_or_else(|e| format!("ERR:{e}"));

    std::fs::create_dir_all("out").ok();
    let f = format!("out/iaai_{vin}.json");
    std::fs::write(&f, &body).ok();
    eprintln!("[+] RESULT: {body}");
    eprintln!("[+] wrote {f}");

    std::mem::forget(process);
}
