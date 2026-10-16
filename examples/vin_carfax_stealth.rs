//! vin_carfax_stealth.rs — drive the real Tallow stealth-browser stack against the
//! DataDome-walled tier (Carfax free VIN check, and by extension Copart/IAAI/Carvana).
//!
//! Carfax's free VIN check is a client-side POST to `consumerapi.carfax.com/crc/vhrlvincheck`
//! guarded by DataDome. Plain HTTP is blocked (403 x-datadome-botname). The only way
//! through is a REAL browser session with a valid DataDome JS-fingerprint cookie. This
//! helper does exactly that using the `src/browser/` stealth stack (which is Rust-API-only
//! and NOT reachable from `.tl`):
//!
//!   1. Launch headless Chromium with the stealth profile + optional Tor/residential proxy.
//!   2. Navigate to the Carfax VIN-check page to obtain a real session + DataDome cookie.
//!   3. Issue the vhrlvincheck POST *in-page* via fetch() so it inherits the browser's
//!      cookies + JS fingerprint (same-origin bypasses CORS).
//!   4. Print the returned JSON (free-vs-paywall boundary data: whether a report exists).
//!
//! Build:   cargo build --example vin_carfax_stealth
//! Run:     ./target/debug/examples/vin_carfax_stealth <VIN>
//!          # optional: VIN_CFX_PROXY=socks5://127.0.0.1:9050 (or a residential HTTP proxy)
//!
//! NOTE: This is a capability demonstration + bot-protection probe. It retrieves the
//! FREE pre-paywall response ("does a report exist" / validation). It does NOT purchase
//! or exfiltrate the paid report.

use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient, Page, WaitUntil};

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let vin = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "2T3F1RFV1PC382478".to_string());
        let proxy = std::env::var("VIN_CFX_PROXY").ok(); // optional socks5/http proxy

        // 1. Launch headless stealth Chromium (optionally through proxy / Tor).
        let config = BrowserConfig {
            proxy: proxy.clone(),
            headless: true,
            stealth: true,
            args: vec![
                "--no-sandbox".to_string(),
                "--disable-blink-features=AutomationControlled".to_string(),
                "--window-size=1366,768".to_string(),
            ],
            ..Default::default()
        };
        let process = BrowserProcess::launch(&config).unwrap();
        eprintln!("[+] launched ws_url={}", process.ws_url);
        let client = CdpClient::connect(&process.ws_url).await.unwrap();
        let page: Page = client.create_page(None).await.unwrap();

        // 2. Apply the JS-level stealth profile (V1+V2+V3 evasion, DataDome-aware).
        let profile = tallow::browser::stealth::StealthProfile::chrome_linux();
        let _ = page.apply_stealth(&profile).await;
        eprintln!("[+] stealth profile applied");

        // 3. Visit the Carfax VIN-check page to establish a session + DataDome cookie.
        eprintln!("[+] navigating carfax.com (establishing session)");
        let nav_res = page
            .navigate("https://www.carfax.com/vehicle-history-reports/", WaitUntil::DomContentLoaded)
            .await;
        match &nav_res {
            Ok(nav) => eprintln!("[+] nav status={:?} url={}", nav.status_code, nav.url),
            Err(e) => eprintln!("[!] nav err: {e} (may still have a session)"),
        }
        // Let DataDome's JS run and set its cookie.
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;

        // Diagnostics: what is the page actually showing? Is there a DataDome challenge?
        if let Ok(diag) = page
            .evaluate_expression(
                r#"JSON.stringify({
                    url: location.href,
                    title: document.title,
                    hasDD: document.cookie.indexOf('datadome') >= 0,
                    ddCookie: (document.cookie.match(/datadome=[^;]+/)||[''])[0].substring(0,120),
                    hasChallenge: (document.querySelector('#dd-challenge, .challenge-form, iframe[src*="datadome"], #bx-captcha') !== null),
                    bodySnippet: (document.body ? document.body.innerText.replace(/\s+/g,' ').substring(0,300) : '')
                })"#,
            )
            .await
        {
            eprintln!("[+] PAGE DIAG: {}", diag.to_string());
        }

        // 3b. The API host consumerapi.carfax.com has its OWN DataDome challenge, separate
        //     from www.carfax.com. Visit it directly so its challenge JS runs and issues a
        //     datadome cookie for that host. It will still 403 from the challenge shell, but
        //     the cookie is what matters. Then navigate back to www for a clean page.
        eprintln!("[+] pre-warming consumerapi.carfax.com (its own DataDome challenge)");
        let _ = page
            .navigate("https://consumerapi.carfax.com/crc/vin/info?vin=UNKNOWN", WaitUntil::DomContentLoaded)
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        if let Ok(d) = page.evaluate_expression(
            "JSON.stringify({ url: location.href, dd: (document.cookie.match(/datadome=[^;]+/)||[''])[0].substring(0,80) })",
        ).await {
            eprintln!("[+] API-HOST DIAG: {}", d.to_string());
        }

        // 3c. Back to the real carfax page (clean session with both hosts' cookies now).
        let _ = page
            .navigate("https://www.carfax.com/vehicle-history-reports/", WaitUntil::DomContentLoaded)
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // 4. Fire the vhrlvincheck POST in-page (same-origin -> carries cookies+fingerprint).
        //    This is the exact endpoint the free VIN check hits. We read the response text.
        //    Store the promise ONCE in window.__cfx, then poll the stored result (re-firing
        //    the fetch on every poll would create a fresh promise each time and never resolve).
        let kick = format!(
            r#"window.__cfx = null;
            fetch("https://consumerapi.carfax.com/crc/vhrlvincheck", {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify({{ "vin": "{vin}" }})
            }}).then(async r => {{
                const t = await r.text();
                window.__cfx = JSON.stringify({{ status: r.status, contentType: r.headers.get("content-type"),
                                        datadome: r.headers.get("x-datadome-botname") || null,
                                        body: t.substring(0, 2000) }});
                return window.__cfx;
            }}).catch(e => {{ window.__cfx = JSON.stringify({{ fetchError: String(e) }}); return window.__cfx; }});"#
        );
        let _ = page.evaluate_expression(&kick).await;

        // Poll the stored window.__cfx result until it resolves (non-empty JSON).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        let mut got: Option<String> = None;
        while std::time::Instant::now() < deadline {
            let v = page.evaluate_expression("window.__cfx ? window.__cfx : 'null'").await;
            let s = v.map(|x| x.to_string()).unwrap_or_default();
            if !s.is_empty() && s != "null" && s != "\"null\"" {
                got = Some(s.clone());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        }
        // Also grab the raw (unstringified) __cfx in case it's a nested object.
        let raw = page
            .evaluate_expression("window.__cfx ? String(window.__cfx) : ''")
            .await
            .map(|x| x.to_string())
            .unwrap_or_default();
        match got.or_else(|| if raw.is_empty() { None } else { Some(raw) }) {
            Some(s) => {
                eprintln!("[+] CARFAX FREE RESPONSE:");
                println!("{s}");
                // Persist to a results file (out/ dir, so it survives the run).
                std::fs::create_dir_all("out").ok();
                let f = format!("out/carfax_free_{vin}.json");
                std::fs::write(&f, s).ok();
                eprintln!("[+] wrote {}", f);
            }
            None => eprintln!("[!] no response within 45s (API-host DataDome challenge not auto-solved from this IP)"),
        }

        std::mem::forget(process);
    });
}
