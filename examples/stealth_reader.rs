//! stealth_reader.rs — drive the Tallow stealth-browser stack to read any article
//! (Medium paywall, hard WAFs, JS-heavy sites) that plain HTTP can't reach.
//!
//! Medium's paywall is CSS-only: the full article text lives in the DOM (div.meteredContent)
//! on every page load; Cloudflare just refuses datacenter curl. A real browser session with
//! the stealth profile renders it fully. We grab the title + full innerText and emit JSON.
//!
//! Usage:
//!   cargo build --example stealth_reader
//!   ./target/debug/examples/stealth_reader "https://site-09.example/@author/slug"
//!   SR_PROXY=socks5://127.0.0.1:9050 ./target/debug/examples/stealth_reader "URL"
//!
//! Output: prints a single JSON object {url,title,content,length} on stdout.

use tallow::browser::{BrowserConfig, BrowserProcess, CdpClient, Page, WaitUntil};

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let url = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "https://site-09.example/@author/slug".to_string());
        let proxy = std::env::var("SR_PROXY").ok();

        let config = BrowserConfig {
            proxy: proxy.clone(),
            headless: true,
            stealth: true,
            args: vec![
                "--no-sandbox".to_string(),
                "--disable-blink-features=AutomationControlled".to_string(),
                "--window-size=1366,2200".to_string(),
            ],
            ..Default::default()
        };
        let process = BrowserProcess::launch(&config).unwrap();
        eprintln!("[+] launched ws_url={}", process.ws_url);
        let client = CdpClient::connect(&process.ws_url).await.unwrap();
        let page: Page = client.create_page(None).await.unwrap();

        // Standard stealth profile (Chrome UA). Note: Medium serves member-only content
        // truncated to non-subscriber browser sessions; presenting as Googlebot triggers
        // a Cloudflare block from datacenter IPs. The twitter-referrer trick (below) makes
        // Medium serve FULL content while the Chrome UA keeps Cloudflare happy.
        let profile = tallow::browser::stealth::StealthProfile::chrome_linux();
        let _ = page.apply_stealth(&profile).await;
        eprintln!("[+] stealth profile applied");

        // For Medium: set the twitter-referrer trick via extra HTTP headers so the server
        // serves the full article body (Medium whitelists site-10.example referrers), while keeping
        // the Chrome UA so Cloudflare doesn't block us.
        if url.contains("site-09.example") {
            let _ = client
                .send_command(
                    "Network.setExtraHTTPHeaders",
                    Some(serde_json::json!({
                        "headers": {
                            "Referer": "https://site-10.example/reader"
                        }
                    })),
                )
                .await;
            eprintln!("[+] twitter-referrer set for Medium");
        }

        eprintln!("[+] navigating {url}");
        let nav = page.navigate(&url, WaitUntil::DomContentLoaded).await;
        match &nav {
            Ok(n) => eprintln!("[+] nav status={:?} final={}", n.status_code, n.url),
            Err(e) => eprintln!("[!] nav err: {e}"),
        }

        // Let JS render (paywall gate, lazy images, Cloudflare checks).
        tokio::time::sleep(std::time::Duration::from_secs(9)).await;

        // Scroll to force lazy-loading of the rest of the article body.
        for _ in 0..6 {
            let _ = page
                .evaluate_expression("window.scrollBy(0, document.body.scrollHeight/6)")
                .await;
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        }

        // DIAGNOSTICS: what is the page actually showing?
        if let Ok(diag) = page
            .evaluate_expression(
                r#"JSON.stringify({
                    url: location.href,
                    title: document.title,
                    bodyLen: (document.body ? document.body.innerText.length : 0),
                    isChallenge: (document.querySelector('#challenge-form, .cf-please-wait, iframe[src*="challenges.cloudflare"], .g-recaptcha, [class*="challenge"]') !== null),
                    hasArticle: (document.querySelector('article, .meteredContent, .pw-post-body') !== null),
                    snippet: (document.body ? document.body.innerText.replace(/\s+/g,' ').substring(0,200) : '')
                })"#,
            )
            .await
        {
            eprintln!("[+] PAGE DIAG: {}", diag.to_string());
        }

        // Extract: prefer the Medium meteredContent div (full article incl. member-only).
        // Use textContent, NOT innerText: Medium's paywall is CSS-only (content is in the
        // DOM but visually clipped), and innerText omits CSS-hidden nodes -> truncated body.
        let script = r#"
          (function(){
            var out = {};
            var tc = document.querySelector('article') || document.body;
            // Medium full content lives in .meteredContent (or .pw-post-body)
            var mc = document.querySelector('.meteredContent, .pw-post-body, [data-testid*="postContent"], article');
            var root = mc || tc || document.body;
            out.title = (document.querySelector('meta[property="og:title"]')||{}).content
                        || (document.querySelector('h1')||{}).textContent || document.title;
            out.articleLen = (document.querySelector('article')||{}).textContent ? document.querySelector('article').textContent.length : 0;
            out.rootLen = (root.textContent||'').length;
            out.sections = document.querySelectorAll('article section').length;
            out.pCount = document.querySelectorAll('article p').length;
            var raw = (root.textContent || '').replace(/\u00a0/g,' ');
            // collapse whitespace but keep paragraph breaks
            raw = raw.replace(/[ \t]+/g,' ').replace(/\n{3,}/g,'\n\n').trim();
            // drop boilerplate nav/meta lines that are not article copy
            var lines = raw.split('\n').filter(function(l){
                var t=l.trim(); if(!t) return true;
                if(/^(Get app|Write|Sign up|Sign in|Follow|Member-only story|Press enter or click to view image in full size)$/i.test(t)) return false;
                if(/^(\d+ min read|·|\d+ clap|\d+ response|\d+ repost)/.test(t)) return false;
                return true;
            });
            out.content = lines.join('\n').trim();
            out.member = (root.querySelector('.meteredContent, [class*="metered"]') !== null) || /medium/i.test(document.title) && out.content.length>500;
            return JSON.stringify(out);
          })()
        "#;
        let res = page.evaluate_expression(script).await;
        let s = res.map(|x| x.to_string()).unwrap_or_default();

        // Also try to capture the raw full article if the above came back short.
        let s = if s.trim().is_empty() || s == "null" || s == "\"null\"" || s.len() < 30 {
            let alt = page
                .evaluate_expression("JSON.stringify({title:document.title, content:(document.body.textContent||'').trim().substring(0,200000)})")
                .await
                .map(|x| x.to_string())
                .unwrap_or_default();
            if alt.trim().is_empty() || alt == "null" { "{\"error\":\"no content\"}".to_string() } else { alt }
        } else {
            s
        };

        // s is a JSON-encoded JS string (double-encoded: the page result is a string
        // containing JSON). Unwrap: parse s -> if it's a String, parse that string again.
        let mut obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&s)
            .ok()
            .and_then(|v: serde_json::Value| match v {
                serde_json::Value::Object(m) => Some(m),
                serde_json::Value::String(inner) => {
                    serde_json::from_str::<serde_json::Value>(&inner)
                        .ok()
                        .and_then(|v2| v2.as_object().cloned())
                }
                _ => None,
            })
            .unwrap_or_default();
        obj.insert("url".to_string(), serde_json::Value::String(url.clone()));
        obj.insert("length".to_string(), serde_json::Value::Number(
            obj.get("content").and_then(|c| c.as_str()).map(|c| c.len() as i64)
                .unwrap_or(0).into()));
        println!("{}", serde_json::Value::Object(obj));

        std::mem::forget(process);
    });
}
