//! Sitemap parser for XML sitemaps and sitemap index files.
//!
//! Handles standard sitemap.xml files, sitemap index files (which reference
//! multiple sitemaps), and gzipped sitemaps. Fetches remote sitemaps via ureq.

/// A single entry from a sitemap.
#[derive(Debug, Clone)]
pub struct SitemapEntry {
    /// The URL from the `<loc>` element.
    pub url: String,
    /// The `<lastmod>` value, if present (ISO 8601 date string).
    pub lastmod: Option<String>,
    /// The `<priority>` value, if present (0.0 to 1.0).
    pub priority: Option<f64>,
    /// The `<changefreq>` value, if present.
    pub changefreq: Option<String>,
}

/// Parser for XML sitemaps and sitemap index files.
pub struct SitemapParser;

impl SitemapParser {
    /// Parse a sitemap XML string and return all URL entries.
    ///
    /// Handles both `<urlset>` sitemaps (returns URLs) and `<sitemapindex>`
    /// files (returns the sitemap locations as entries).
    pub fn parse(xml: &str) -> Vec<SitemapEntry> {
        // Detect if this is a sitemap index or a urlset
        let lower = xml.to_lowercase();
        if lower.contains("<sitemapindex") {
            Self::parse_sitemap_index_entries(xml)
        } else {
            Self::parse_urlset(xml)
        }
    }

    /// Fetch and parse a sitemap from a URL.
    ///
    /// If the URL points to a sitemap index, all referenced sub-sitemaps are
    /// fetched and their entries are merged. Handles gzipped sitemaps (.gz).
    pub fn fetch_sitemap(url: &str) -> Result<Vec<SitemapEntry>, String> {
        let xml = Self::fetch_xml(url)?;
        let lower = xml.to_lowercase();

        if lower.contains("<sitemapindex") {
            // Parse sub-sitemap URLs from the index
            let sub_urls = Self::parse_sitemap_index_entries(&xml);
            let mut all_entries = Vec::new();

            for sub in &sub_urls {
                match Self::fetch_xml(&sub.url) {
                    Ok(sub_xml) => {
                        let entries = Self::parse_urlset(&sub_xml);
                        all_entries.extend(entries);
                    }
                    Err(e) => {
                        // Log but continue — one bad sub-sitemap shouldn't fail everything
                        eprintln!("Warning: failed to fetch sub-sitemap {}: {}", sub.url, e);
                    }
                }
            }

            Ok(all_entries)
        } else {
            Ok(Self::parse_urlset(&xml))
        }
    }

    /// Discover the sitemap URL for a domain by checking common locations
    /// and parsing robots.txt.
    pub fn discover_sitemap(base_url: &str) -> Vec<String> {
        let base = base_url.trim_end_matches('/');
        let mut candidates = Vec::new();

        // Check robots.txt for Sitemap directives
        let robots_url = format!("{base}/robots.txt");
        if let Ok(robots) = Self::fetch_xml(&robots_url) {
            for line in robots.lines() {
                let trimmed = line.trim();
                if let Some(stripped) = trimmed.strip_prefix("Sitemap:") {
                    let sitemap_url = stripped.trim();
                    if !sitemap_url.is_empty() {
                        candidates.push(sitemap_url.to_string());
                    }
                } else if let Some(stripped) = trimmed.strip_prefix("sitemap:") {
                    let sitemap_url = stripped.trim();
                    if !sitemap_url.is_empty() {
                        candidates.push(sitemap_url.to_string());
                    }
                }
            }
        }

        // If no sitemaps found in robots.txt, try common locations
        if candidates.is_empty() {
            candidates.push(format!("{base}/sitemap.xml"));
            candidates.push(format!("{base}/sitemap_index.xml"));
            candidates.push(format!("{base}/sitemap.xml.gz"));
        }

        candidates
    }

    /// Parse a `<urlset>` sitemap into entries.
    fn parse_urlset(xml: &str) -> Vec<SitemapEntry> {
        let mut entries = Vec::new();
        let mut search_from = 0;

        while let Some(url_start) = find_tag_start(xml, "<url>", search_from)
            .or_else(|| find_tag_start(xml, "<url ", search_from))
        {
            let content_start = xml[url_start..].find('>').map(|i| url_start + i + 1);
            let Some(content_start) = content_start else {
                break;
            };

            let url_end = find_tag_start(xml, "</url>", content_start);
            let Some(url_end) = url_end else { break };

            let block = &xml[content_start..url_end];

            let loc = extract_tag_content(block, "loc");
            if let Some(url) = loc {
                let url = xml_unescape(&url.trim().to_string());
                if !url.is_empty() {
                    entries.push(SitemapEntry {
                        url,
                        lastmod: extract_tag_content(block, "lastmod").map(|s| s.trim().to_string()),
                        priority: extract_tag_content(block, "priority")
                            .and_then(|s| s.trim().parse::<f64>().ok()),
                        changefreq: extract_tag_content(block, "changefreq")
                            .map(|s| s.trim().to_string()),
                    });
                }
            }

            search_from = url_end + 6; // past "</url>"
        }

        entries
    }

    /// Parse a `<sitemapindex>` file and return the sub-sitemap URLs as entries.
    fn parse_sitemap_index_entries(xml: &str) -> Vec<SitemapEntry> {
        let mut entries = Vec::new();
        let mut search_from = 0;

        while let Some(sm_start) = find_tag_start(xml, "<sitemap>", search_from)
            .or_else(|| find_tag_start(xml, "<sitemap ", search_from))
        {
            let content_start = xml[sm_start..].find('>').map(|i| sm_start + i + 1);
            let Some(content_start) = content_start else {
                break;
            };

            let sm_end = find_tag_start(xml, "</sitemap>", content_start);
            let Some(sm_end) = sm_end else { break };

            let block = &xml[content_start..sm_end];

            if let Some(loc) = extract_tag_content(block, "loc") {
                let url = xml_unescape(&loc.trim().to_string());
                if !url.is_empty() {
                    entries.push(SitemapEntry {
                        url,
                        lastmod: extract_tag_content(block, "lastmod")
                            .map(|s| s.trim().to_string()),
                        priority: None,
                        changefreq: None,
                    });
                }
            }

            search_from = sm_end + 10; // past "</sitemap>"
        }

        entries
    }

    /// Fetch XML content from a URL, handling gzipped responses.
    fn fetch_xml(url: &str) -> Result<String, String> {
        // T-207 browser-zone lockdown: ride the contract (Tor by default)
        // instead of a hand-built unproxied agent.
        let agent = crate::runtime::egress_http::agent_with_timeouts(
            Some(std::time::Duration::from_secs(30)),
            None,
        );

        let resp = agent
            .get(url)
            .header("User-Agent", "Tallow-Crawler/0.4")
            .header("Accept", "application/xml, text/xml, */*")
            .call()
            .map_err(|e| format!("HTTP request failed for {url}: {e}"))?;

        let content_type: String = resp
            .headers()
            .get("content-type")
            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let is_gzip = url.ends_with(".gz")
            || content_type.contains("gzip")
            || content_type.contains("x-gzip");

        if is_gzip {
            let compressed = resp
                .into_body()
                .read_to_vec()
                .map_err(|e| format!("Failed to read gzipped body: {e}"))?;
            let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
            let mut xml = String::new();
            std::io::Read::read_to_string(&mut decoder, &mut xml)
                .map_err(|e| format!("Failed to decompress gzip: {e}"))?;
            Ok(xml)
        } else {
            resp.into_body()
                .read_to_string()
                .map_err(|e| format!("Failed to read body: {e}"))
        }
    }
}

/// Case-insensitive tag start finder.
fn find_tag_start(xml: &str, tag: &str, from: usize) -> Option<usize> {
    let hay = &xml[from..];
    let tag_lower = tag.to_lowercase();
    let hay_lower = hay.to_lowercase();
    hay_lower.find(&tag_lower).map(|i| from + i)
}

/// Extract text content between `<tag>` and `</tag>`.
fn extract_tag_content(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let lower = xml.to_lowercase();
    let open_lower = open.to_lowercase();
    let close_lower = close.to_lowercase();

    let start = lower.find(&open_lower)?;
    let content_start = xml[start..].find('>')? + start + 1;
    let end = lower[content_start..].find(&close_lower)? + content_start;

    Some(xml[content_start..end].to_string())
}

/// Unescape basic XML entities.
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_urlset() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/page1</loc>
    <lastmod>2026-01-15</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://example.com/page2</loc>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://example.com/page3</loc>
  </url>
</urlset>"#;

        let entries = SitemapParser::parse(xml);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].url, "https://example.com/page1");
        assert_eq!(entries[0].lastmod.as_deref(), Some("2026-01-15"));
        assert_eq!(entries[0].changefreq.as_deref(), Some("weekly"));
        assert_eq!(entries[0].priority, Some(0.8));

        assert_eq!(entries[1].url, "https://example.com/page2");
        assert!(entries[1].lastmod.is_none());
        assert_eq!(entries[1].priority, Some(0.5));

        assert_eq!(entries[2].url, "https://example.com/page3");
        assert!(entries[2].priority.is_none());
    }

    #[test]
    fn test_parse_sitemap_index() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap1.xml</loc>
    <lastmod>2026-03-01</lastmod>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap2.xml</loc>
  </sitemap>
</sitemapindex>"#;

        let entries = SitemapParser::parse(xml);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].url, "https://example.com/sitemap1.xml");
        assert_eq!(entries[0].lastmod.as_deref(), Some("2026-03-01"));
        assert_eq!(entries[1].url, "https://example.com/sitemap2.xml");
    }

    #[test]
    fn test_xml_unescape() {
        assert_eq!(
            xml_unescape("https://example.com?a=1&amp;b=2"),
            "https://example.com?a=1&b=2"
        );
    }

    #[test]
    fn test_extract_tag_content() {
        let xml = "<loc>https://example.com</loc>";
        assert_eq!(
            extract_tag_content(xml, "loc"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_empty_sitemap() {
        let xml = r#"<?xml version="1.0"?><urlset></urlset>"#;
        let entries = SitemapParser::parse(xml);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_discover_sitemap_returns_defaults() {
        // Can't actually fetch, but verify the function returns default candidates
        let candidates = SitemapParser::discover_sitemap("https://unreachable.invalid");
        assert!(!candidates.is_empty());
        assert!(candidates[0].contains("sitemap.xml"));
    }
}
