//! vin_carfax.rs — Carfax-only: drive the REAL carfax.com VIN-check form with the
//! Tallow stealth browser and capture everything Carfax returns for a VIN.
//!
//! Strategy:
//!   1. Stealth Chromium (defeats DataDome on www.carfax.com from any IP — verified).
//!   2. Pre-warm consumerapi.carfax.com so its per-host DataDome cookie is issued.
//!   3. Before submitting, install an in-page interceptor on window.fetch + XMLHttpRequest
//!      that records the vhrlvincheck API response body (JS-side, no CDP session needed).
//!   4. Type the VIN into the real input via the native setter (so React registers it),
//!      click submit, and let the site's own code call the API.
//!   5. Read back the captured API response + the post-submit rendered page state.
//!
//! Build: cargo build --example vin_carfax
//! Run:   ./target/debug/examples/vin_carfax <VIN>
//!        # optional exit proxy: VIN_PROXY=socks5://<residential> (needed to fully solve
//!        # the API-host DataDome challenge; from a datacenter/Tor exit the API may still 403)
//!
//! Capability probe only: captures the FREE pre-paywall response. No payment, no paid-report exfiltration.

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
            "--window-size=1366,768".to_string(),
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

    // Pre-warm the API host to obtain its own DataDome cookie.
    eprintln!("[+] pre-warming consumerapi.carfax.com");
    let _ = page
        .navigate("https://consumerapi.carfax.com/crc/vin/info?vin=UNKNOWN", WaitUntil::DomContentLoaded)
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // Go to the VIN-check page.
    eprintln!("[+] navigating carfax VIN check");
    let _ = page
        .navigate("https://www.carfax.com/vehicle-history-reports/", WaitUntil::DomContentLoaded)
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Install in-page API-response interceptor BEFORE submitting. Captures the body of
    // any fetch/XHR to the carfax API (vhrlvincheck / vincheck / vin/info).
    let _ = page.evaluate_expression(
        r#"(function() {
            if (window.__cfxCaptured) return 'already';
            window.__cfxCaptured = [];
            const origFetch = window.fetch;
            window.fetch = function(...args) {
                try {
                    const url = (args[0] && args[0].url) ? args[0].url : String(args[0]||'');
                    if (url.indexOf('carfax') >= 0 || url.indexOf('vhrlvincheck') >= 0 || url.indexOf('vin/info') >= 0) {
                        return origFetch.apply(this, args).then(async resp => {
                            try {
                                const clone = resp.clone();
                                const text = await clone.text();
                                window.__cfxCaptured.push({url:url, status:resp.status, body:text.substring(0,3000)});
                            } catch(e) {}
                            return resp;
                        });
                    }
                } catch(e) {}
                return origFetch.apply(this, args);
            };
            const origOpen = XMLHttpRequest.prototype.open;
            const origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this.__cfxUrl = url;
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                const url = this.__cfxUrl || '';
                if (url.indexOf('carfax') >= 0 || url.indexOf('vhrlvincheck') >= 0 || url.indexOf('vin/info') >= 0) {
                    this.addEventListener('load', () => {
                        try { window.__cfxCaptured.push({url:url, status:this.status, body:String(this.responseText||'').substring(0,3000)}); } catch(e){}
                    });
                }
                return origSend.apply(this, arguments);
            };
            return 'installed';
        })()"#,
    ).await;
    eprintln!("[+] interceptor installed");

    // Type the VIN via the native setter so React registers it, then submit.
    let set_js = format!(
        r#"(() => {{
            const inp = document.querySelector('#vin-input, input[data-testid="vin-input"], input[name="vin"], input[type="text"]');
            if (!inp) return 'no-input';
            const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
            setter.call(inp, '{vin}');
            inp.dispatchEvent(new Event('input', {{ bubbles: true }}));
            inp.dispatchEvent(new Event('change', {{ bubbles: true }}));
            const btn = document.querySelector('button[data-testid="vin-submit"], button[type="submit"], form button');
            if (btn) {{ setTimeout(()=>btn.click(), 300); }}
            return 'typed:' + inp.value + ', willSubmit:' + (btn?'yes':'no');
        }})()"#
    );
    let set_res = page.evaluate_expression(&set_js).await;
    eprintln!("[+] set+submit: {:?}", set_res);

    // Wait for the interceptor to capture an API response.
    let mut captured: Option<String> = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while std::time::Instant::now() < deadline {
        let cap = page
            .evaluate_expression(
                "window.__cfxCaptured && window.__cfxCaptured.length ? JSON.stringify(window.__cfxCaptured) : 'null'",
            )
            .await
            .map(|v| v.to_string())
            .unwrap_or_default();
        if !cap.is_empty() && cap != "null" && cap != "\"null\"" {
            captured = Some(cap);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }

    // Dump the post-submit rendered page state too.
    let rendered = page
        .evaluate_expression(
            "JSON.stringify({url:location.href, title:document.title, body:(document.body?document.body.innerText.replace(/\\s+/g,' ').substring(0,900):'')})",
        )
        .await
        .map(|v| v.to_string())
        .unwrap_or_default();
    eprintln!("[+] RENDERED PAGE: {rendered}");

    std::fs::create_dir_all("out").ok();
    let f = format!("out/carfax_{vin}.json");
    let payload = captured.clone().unwrap_or_else(|| rendered);
    std::fs::write(&f, &payload).ok();
    if let Some(c) = &captured {
        eprintln!("[+] CAPTURED API RESPONSE(S): {c}");
    }
    eprintln!("[+] wrote {f}");

    std::mem::forget(process);
}
