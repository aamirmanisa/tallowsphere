//! vin_stealth_scan.rs — scan free residential/exit proxies with the Tallow stealth
//! browser to find which exit IPs clear the bot-walled VIN-history tier.
//!
//! The bot-walled tier (Carfax API host `consumerapi.carfax.com/crc/vhrlvincheck`,
//! Copart, IAAI) is DataDome/Incapsula/Cloudflare-protected. The Tallow stealth browser
//! defeats DataDome at the PAGE level from any IP (proven in vin_carfax_stealth.rs), but
//! the Carfax *API host* and Copart/IAAI need a clean, non-datacenter exit IP. This tool
//! uses Tallow's built-in `ProxyPool` (free_proxies.rs) to fetch + validate free SOCKS5
//! proxies, then drives the stealth browser through each working exit and probes the
//! three walls, reporting exactly which sites clear from which IP.
//!
//! Build: cargo build --example vin_stealth_scan
//! Run:   ./target/debug/examples/vin_stealth_scan [--sites carfax,copart,iaai] [--max 8]
//!        # optional override exit proxy: VIN_PROXY=socks5://ip:port (test one specific IP)
//!
//! Capability probe only — it fetches the FREE pre-paywall response / page-availability
//! signal. No payment, no paid-report exfiltration.

use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient, Page, WaitUntil};
use tallow::browser::free_proxies::ProxyPool;

const VIN: &str = "2T3F1RFV1PC382478";

async fn probe_site(page: &Page, name: &str, url: &str, js_check: &str) -> String {
    eprintln!("[>] {name}: {url}");
    let nav = page.navigate(url, WaitUntil::DomContentLoaded).await;
    let _ = nav; // nav may be None on challenges; we rely on JS-state below
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let state = page
        .evaluate_expression(js_check)
        .await
        .map(|v| v.to_string())
        .unwrap_or_default();
    format!("{name} => {state}")
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Which sites to probe (default all three).
        let sites: Vec<String> = std::env::args()
            .skip_while(|a| a != "--sites")
            .nth(1)
            .unwrap_or_else(|| "carfax,copart,iaai".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Collect exit proxies: either a single override or the free ProxyPool.
        let mut exits: Vec<String> = Vec::new();
        if let Ok(p) = std::env::var("VIN_PROXY") {
            eprintln!("[+] using single override exit: {p}");
            exits.push(p);
        } else {
            let max = std::env::args()
                .skip_while(|a| a != "--max")
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(8);
            eprintln!("[+] fetching+validating free proxies (max {max})...");
            let pool = ProxyPool::new(max).await;
            for _ in 0..max {
                if let Some(fp) = pool.get_proxy().await {
                    exits.push(format!("socks5://{}", fp.addr));
                }
            }
            eprintln!("[+] got {} working exit proxies", exits.len());
        }

        for (i, proxy) in exits.iter().enumerate() {
            eprintln!("═══ exit #{i} proxy={proxy} ═══");
            let config = BrowserConfig {
                proxy: Some(proxy.clone()),
                headless: true,
                stealth: true,
                args: vec![
                    "--no-sandbox".to_string(),
                    "--disable-blink-features=AutomationControlled".to_string(),
                    "--window-size=1366,768".to_string(),
                ],
                ..Default::default()
            };
            let process = match BrowserProcess::launch(&config) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[!] launch failed: {e}");
                    continue;
                }
            };
            let client = match CdpClient::connect(&process.ws_url).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[!] connect failed: {e}");
                    continue;
                }
            };
            let page: Page = client.create_page(None).await.unwrap();
            let profile = tallow::browser::stealth::StealthProfile::chrome_linux();
            let _ = page.apply_stealth(&profile).await;

            let mut results = Vec::new();
            for site in &sites {
                let r = match site.as_str() {
                    "carfax" => {
                        // Establish www session, then probe the API host via in-page fetch.
                        let _ = page
                            .navigate("https://www.carfax.com/vehicle-history-reports/", WaitUntil::DomContentLoaded)
                            .await;
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        let kick = format!(
                            r#"window.__cfx=null;fetch("https://consumerapi.carfax.com/crc/vhrlvincheck",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{"vin":"{VIN}"}})}}).then(r=>r.text()).then(t=>window.__cfx=t.substring(0,200)).catch(e=>window.__cfx="ERR:"+e);"#
                        );
                        let _ = page.evaluate_expression(&kick).await;
                        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
                        let mut got = String::new();
                        while std::time::Instant::now() < deadline {
                            let v = page
                                .evaluate_expression("window.__cfx?window.__cfx:'null'")
                                .await
                                .map(|x| x.to_string())
                                .unwrap_or_default();
                            if !v.is_empty() && v != "null" && v != "\"null\"" {
                                got = v;
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                        }
                        format!("carfax_api => {}", if got.is_empty() { "TIMEOUT" } else { &got[..got.len().min(120)] })
                    }
                    "copart" => {
                        let js = r#"JSON.stringify({title:document.title, hasWall:(document.body.innerText.indexOf('Access Denied')>=0||document.title.indexOf('security')>=0||document.title.indexOf('blocked')>=0), dd:(document.cookie.match(/datadome=[^;]+/)||[''])[0].substring(0,40)})"#;
                        probe_site(&page, "copart", &format!("https://www.copart.com/vehicleFinder?searchQuery={VIN}"), js).await
                    }
                    "iaai" => {
                        let js = r#"JSON.stringify({title:document.title, hasWall:(document.body.innerText.indexOf('Access Denied')>=0||document.title.indexOf('security')>=0), body:(document.body?document.body.innerText.replace(/\s+/g,' ').substring(0,150):'')})"#;
                        probe_site(&page, "iaai", &format!("https://www.iaai.com/Search?keyword={VIN}"), js).await
                    }
                    _ => format!("{site} => unknown"),
                };
                results.push(r);
            }

            // Print this exit's results in one line.
            let line = results.join("  |  ");
            println!("EXIT {proxy} :: {line}");
            std::mem::forget(process);
        }
        eprintln!("[+] scan complete");
    });
}
