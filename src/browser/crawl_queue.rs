//! Persistent URL queue with deduplication for crawl job scheduling.
//!
//! Provides a priority-based job queue that deduplicates URLs and supports
//! checkpoint save/load for crash recovery via JSON serialization.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A single crawl job with URL, priority, retry tracking, and domain info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlJob {
    /// The URL to crawl.
    pub url: String,
    /// Priority (0 = highest, 255 = lowest).
    pub priority: u8,
    /// Number of times this job has been retried.
    pub retries: u8,
    /// Maximum number of retries before the job is dropped.
    pub max_retries: u8,
    /// The domain extracted from the URL.
    pub domain: String,
    /// Depth in the crawl tree (0 = seed URL).
    pub depth: u32,
}

impl CrawlJob {
    /// Create a new crawl job from a URL with the given priority.
    pub fn new(url: &str, priority: u8) -> Self {
        let domain = extract_domain(url);
        Self {
            url: url.to_string(),
            priority,
            retries: 0,
            max_retries: 3,
            domain,
            depth: 0,
        }
    }

    /// Create a crawl job with depth information (for discovered links).
    pub fn with_depth(url: &str, priority: u8, depth: u32) -> Self {
        let domain = extract_domain(url);
        Self {
            url: url.to_string(),
            priority,
            retries: 0,
            max_retries: 3,
            domain,
            depth,
        }
    }

    /// Whether this job can be retried.
    pub fn can_retry(&self) -> bool {
        self.retries < self.max_retries
    }

    /// Increment the retry counter and return a clone for re-queuing.
    pub fn retried(&self) -> Self {
        let mut job = self.clone();
        job.retries += 1;
        // Lower priority on retry
        job.priority = job.priority.saturating_add(10);
        job
    }
}

/// Checkpoint format for serialization.
#[derive(Serialize, Deserialize)]
struct QueueCheckpoint {
    seen: Vec<String>,
    queue: Vec<CrawlJob>,
    /// Per-URL HTTP cache metadata (ETag / Last-Modified / content hash).
    cache: Vec<(String, UrlCacheEntry)>,
}

/// HTTP cache metadata tracked per URL to enable delta / incremental crawls.
///
/// On a re-crawl, if `content_hash` is unchanged the caller can skip
/// re-extraction. When `etag`/`last_modified` are present, the caller can issue
/// a conditional GET (`If-None-Match` / `If-Modified-Since`) and receive a
/// cheap `304 Not Modified` instead of the full body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UrlCacheEntry {
    /// ETag from the last response (for `If-None-Match`).
    pub etag: Option<String>,
    /// Last-Modified from the last response (for `If-Modified-Since`).
    pub last_modified: Option<String>,
    /// `sha256(body)` of the last fetched body (for change detection).
    pub content_hash: Option<String>,
    /// Unix timestamp of the last successful fetch.
    pub fetched_at_epoch: Option<i64>,
}

/// A delta (incremental) crawl plan over a URL set, derived from the queue's
/// stored HTTP cache metadata (content hash + ETag/Last-Modified validators).
#[derive(Debug, Clone, Default)]
pub struct DeltaPlan {
    /// URLs that must be re-fetched (first crawl, or cached-but-no-validator
    /// so the caller must confirm via a conditional GET / body-hash match).
    pub re_fetch: Vec<String>,
    /// URLs trusted-unchanged: a stored content hash **and** a revalidation
    /// validator (ETag / Last-Modified) — skip re-crawling entirely.
    pub skip: Vec<String>,
}

impl DeltaPlan {
    /// Fraction of the full set (re-fetch + skip) that was skipped.
    pub fn skip_ratio(&self) -> f64 {
        let total = self.re_fetch.len() + self.skip.len();
        if total == 0 {
            0.0
        } else {
            self.skip.len() as f64 / total as f64
        }
    }
}

/// Whether delta/incremental crawling is enabled via `TALLOW_DELTA_CRAWL=1`.
///
/// The scheduler sets this on subprocesses when a `ScheduledJob.delta` is set;
/// the crawl path consumes it to skip re-fetching/re-extracting unchanged URLs.
pub fn delta_crawl_enabled() -> bool {
    std::env::var("TALLOW_DELTA_CRAWL")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Persistent URL queue with deduplication and priority ordering.
///
/// Jobs are ordered by priority (lower number = higher priority).
/// URLs that have already been seen are rejected on push.
pub struct CrawlQueue {
    /// Set of all URLs seen (for deduplication).
    seen: HashSet<String>,
    /// The priority queue implemented as a sorted VecDeque.
    queue: VecDeque<CrawlJob>,
    /// Maximum queue size (0 = unlimited).
    max_size: usize,
    /// Per-URL HTTP cache metadata (ETag / Last-Modified / content hash).
    cache: HashMap<String, UrlCacheEntry>,
}

impl CrawlQueue {
    /// Create a new empty crawl queue.
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            queue: VecDeque::new(),
            max_size: 0,
            cache: HashMap::new(),
        }
    }

    /// Create a queue with a maximum size limit.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            seen: HashSet::new(),
            queue: VecDeque::new(),
            max_size,
            cache: HashMap::new(),
        }
    }

    /// Push a URL into the queue with the given priority.
    ///
    /// Returns `false` if the URL has already been seen (duplicate).
    /// The URL is normalized before deduplication (trailing slash, fragment removal).
    pub fn push(&mut self, url: &str, priority: u8) -> bool {
        let normalized = normalize_url(url);
        if self.seen.contains(&normalized) {
            return false;
        }
        if self.max_size > 0 && self.queue.len() >= self.max_size {
            return false;
        }
        self.seen.insert(normalized);
        let job = CrawlJob::new(url, priority);
        self.insert_by_priority(job);
        true
    }

    /// Push a pre-built CrawlJob into the queue.
    ///
    /// Returns `false` if the URL has already been seen.
    pub fn push_job(&mut self, job: CrawlJob) -> bool {
        let normalized = normalize_url(&job.url);
        if self.seen.contains(&normalized) {
            return false;
        }
        if self.max_size > 0 && self.queue.len() >= self.max_size {
            return false;
        }
        self.seen.insert(normalized);
        self.insert_by_priority(job);
        true
    }

    /// Re-queue a failed job for retry (bypasses deduplication).
    ///
    /// Returns `false` if the job has exhausted its retries.
    pub fn retry(&mut self, job: &CrawlJob) -> bool {
        if !job.can_retry() {
            return false;
        }
        let retried = job.retried();
        self.insert_by_priority(retried);
        true
    }

    /// Pop the highest-priority job from the queue.
    pub fn pop(&mut self) -> Option<CrawlJob> {
        self.queue.pop_front()
    }

    /// Peek at the next job without removing it.
    pub fn peek(&self) -> Option<&CrawlJob> {
        self.queue.front()
    }

    /// Number of jobs currently in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Total number of unique URLs seen (including already-processed ones).
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    /// Check if a URL has been seen before.
    pub fn has_seen(&self, url: &str) -> bool {
        self.seen.contains(&normalize_url(url))
    }

    /// Mark a URL as seen without adding it to the queue.
    /// Useful for pre-seeding the dedup set (e.g., with previously crawled URLs).
    pub fn mark_seen(&mut self, url: &str) {
        self.seen.insert(normalize_url(url));
    }

    // ── HTTP cache: content-hash change detection + ETag/304 ────────────────
    //
    // Enables delta / incremental crawls: store `sha256(body)` + `etag` +
    // `last_modified` per URL; on re-crawl, an unchanged hash means re-extraction
    // can be skipped, and a conditional GET (`If-None-Match`/`If-Modified-Since`)
    // yields a cheap 304 instead of a full body.

    /// Record a fetched response for a URL and return the content hash.
    ///
    /// Computes `sha256(body)` and stores it alongside the optional `etag` and
    /// `last_modified` for later change detection / conditional GETs.
    pub fn record_response(
        &mut self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
        body: &str,
    ) -> String {
        let hash = sha256_hex(body);
        let entry = UrlCacheEntry {
            etag: etag.map(|s| s.to_string()).filter(|s| !s.is_empty()),
            last_modified: last_modified.map(|s| s.to_string()).filter(|s| !s.is_empty()),
            content_hash: Some(hash.clone()),
            fetched_at_epoch: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ),
        };
        self.cache.insert(normalize_url(url), entry);
        hash
    }

    /// Last recorded `sha256(body)` for a URL, if any.
    pub fn last_content_hash(&self, url: &str) -> Option<&str> {
        self.cache
            .get(&normalize_url(url))
            .and_then(|e| e.content_hash.as_deref())
    }

    /// Whether a freshly-fetched body hash matches the last recorded hash.
    ///
    /// Returns `true` (unchanged → skip re-extraction) only when a prior hash
    /// exists and equals `new_hash`. Returns `false` when there is no prior
    /// record (first crawl) or the content actually changed.
    pub fn is_unchanged(&self, url: &str, new_hash: &str) -> bool {
        self.last_content_hash(url)
            .map(|h| h == new_hash)
            .unwrap_or(false)
    }

    /// Stored ETag for a URL, if any.
    pub fn etag(&self, url: &str) -> Option<&str> {
        self.cache
            .get(&normalize_url(url))
            .and_then(|e| e.etag.as_deref())
    }

    /// Stored Last-Modified value for a URL, if any.
    pub fn last_modified(&self, url: &str) -> Option<&str> {
        self.cache
            .get(&normalize_url(url))
            .and_then(|e| e.last_modified.as_deref())
    }

    /// Build conditional-GET headers (`If-None-Match` / `If-Modified-Since`)
    /// from the last response metadata for a URL.
    ///
    /// Empty if no cache metadata exists. Callers should attach these to the
    /// outgoing request and treat a `304` as "unchanged".
    pub fn conditional_headers(&self, url: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(etag) = self.etag(url) {
            out.push(("If-None-Match".to_string(), etag.to_string()));
        }
        if let Some(lm) = self.last_modified(url) {
            out.push(("If-Modified-Since".to_string(), lm.to_string()));
        }
        out
    }

    /// Plan a delta (incremental) crawl over `urls` using the stored HTTP cache
    /// metadata (content hash + ETag/Last-Modified validators).
    ///
    /// This is the glue that connects the queue's cache to `plan_incremental_crawl`:
    /// * no prior `content_hash` → `re_fetch` (first crawl / unknown);
    /// * `content_hash` **and** a validator (ETag/Last-Modified) → `skip`
    ///   (trusted unchanged, no re-crawl this pass);
    /// * `content_hash` but no validator → `re_fetch` (confirm via conditional GET).
    pub fn delta_plan(&self, urls: &[String]) -> DeltaPlan {
        let mut plan = DeltaPlan::default();
        for url in urls {
            let entry = self.cache.get(&normalize_url(url));
            let has_hash = entry.and_then(|e| e.content_hash.as_ref()).is_some();
            let has_validator = entry
                .map(|e| e.etag.is_some() || e.last_modified.is_some())
                .unwrap_or(false);
            if has_hash && has_validator {
                plan.skip.push(url.clone());
            } else {
                plan.re_fetch.push(url.clone());
            }
        }
        plan
    }

    /// Whether extraction should be skipped for a freshly-fetched body during a
    /// delta crawl: `TALLOW_DELTA_CRAWL=1` **and** the body's hash matches the
    /// last recorded hash (unchanged content). Consume this before re-extracting.
    pub fn should_skip_extraction(&self, url: &str, body: &str) -> bool {
        delta_crawl_enabled() && self.is_unchanged(url, &sha256_hex(body))
    }

    /// Number of URLs with cached response metadata.
    pub fn cached_url_count(&self) -> usize {
        self.cache.len()
    }

    /// Drain all jobs for a specific domain.
    pub fn drain_domain(&mut self, domain: &str) -> Vec<CrawlJob> {
        let mut domain_jobs = Vec::new();
        let mut remaining = VecDeque::new();
        for job in self.queue.drain(..) {
            if job.domain == domain {
                domain_jobs.push(job);
            } else {
                remaining.push_back(job);
            }
        }
        self.queue = remaining;
        domain_jobs
    }

    /// Clear the queue and the seen set.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.seen.clear();
    }

    /// Save the current queue state to a JSON checkpoint file.
    pub fn save_checkpoint(&self, path: &str) -> Result<(), std::io::Error> {
        let mut cache: Vec<(String, UrlCacheEntry)> =
            self.cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        cache.sort_by(|a, b| a.0.cmp(&b.0));
        let checkpoint = QueueCheckpoint {
            seen: self.seen.iter().cloned().collect(),
            queue: self.queue.iter().cloned().collect(),
            cache,
        };
        let json = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        // Write atomically: write to temp file, then rename
        let tmp_path = format!("{path}.tmp");
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load a queue from a JSON checkpoint file.
    pub fn load_checkpoint(path: &str) -> Result<Self, std::io::Error> {
        let data = fs::read_to_string(path)?;
        let checkpoint: QueueCheckpoint = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let seen: HashSet<String> = checkpoint.seen.into_iter().collect();
        let queue: VecDeque<CrawlJob> = checkpoint.queue.into_iter().collect();
        let cache: HashMap<String, UrlCacheEntry> = checkpoint.cache.into_iter().collect();
        Ok(Self {
            seen,
            queue,
            max_size: 0,
            cache,
        })
    }

    /// Insert a job maintaining priority order (lower priority number = front).
    fn insert_by_priority(&mut self, job: CrawlJob) {
        let pos = self
            .queue
            .iter()
            .position(|j| j.priority > job.priority)
            .unwrap_or(self.queue.len());
        self.queue.insert(pos, job);
    }
}

impl Default for CrawlQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the lowercase hex `sha256` of a UTF-8 body string.
///
/// Used for content-hash change detection (delta / incremental crawls).
pub fn hash_body(body: &str) -> String {
    sha256_hex(body)
}

/// Compute the lowercase hex `sha256` of a UTF-8 body string.
///
/// Used for content-hash change detection (delta / incremental crawls).
fn sha256_hex(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Normalize a URL for deduplication: remove fragment, trailing slash,
/// and lowercase the scheme+host.
fn normalize_url(url: &str) -> String {
    let mut s = url.to_string();
    // Remove fragment
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }
    // Remove trailing slash (but keep root "/")
    if s.ends_with('/') && s.len() > 1 {
        let path_start = s.find("://").map(|i| i + 3).unwrap_or(0);
        // Only strip if there's a path component (not just "https://example.com/")
        if s[path_start..].contains('/') && s.len() > path_start + s[path_start..].find('/').unwrap_or(0) + 1 {
            // Keep the trailing slash for root paths like "https://example.com/"
            let after_host = &s[path_start..];
            let slash_pos = after_host.find('/').unwrap_or(after_host.len());
            let path_part = &after_host[slash_pos..];
            if path_part != "/" {
                s.truncate(s.len() - 1);
            }
        }
    }
    // Lowercase scheme and host
    if let Some(scheme_end) = s.find("://") {
        let host_start = scheme_end + 3;
        let host_end = s[host_start..]
            .find('/')
            .map(|i| host_start + i)
            .unwrap_or(s.len());
        let lowered = format!(
            "{}{}{}",
            s[..host_start].to_lowercase(),
            s[host_start..host_end].to_lowercase(),
            &s[host_end..]
        );
        return lowered;
    }
    s
}

/// Extract the domain from a URL string.
pub fn extract_domain(url: &str) -> String {
    let without_scheme = url
        .find("://")
        .map(|i| &url[i + 3..])
        .unwrap_or(url);
    let host = without_scheme
        .find('/')
        .map(|i| &without_scheme[..i])
        .unwrap_or(without_scheme);
    // Strip port
    let domain = host
        .rfind(':')
        .and_then(|i| {
            // Make sure it's a port, not part of IPv6
            if host[i + 1..].chars().all(|c| c.is_ascii_digit()) {
                Some(&host[..i])
            } else {
                None
            }
        })
        .unwrap_or(host);
    domain.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_pop() {
        let mut q = CrawlQueue::new();
        assert!(q.push("https://example.com/a", 5));
        assert!(q.push("https://example.com/b", 1));
        assert!(q.push("https://example.com/c", 3));
        assert_eq!(q.len(), 3);

        // Should pop in priority order
        let j1 = q.pop().unwrap();
        assert_eq!(j1.priority, 1);
        assert!(j1.url.contains("/b"));

        let j2 = q.pop().unwrap();
        assert_eq!(j2.priority, 3);

        let j3 = q.pop().unwrap();
        assert_eq!(j3.priority, 5);

        assert!(q.pop().is_none());
    }

    #[test]
    fn test_deduplication() {
        let mut q = CrawlQueue::new();
        assert!(q.push("https://example.com/page", 1));
        assert!(!q.push("https://example.com/page", 2)); // duplicate
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_dedup_with_fragment() {
        let mut q = CrawlQueue::new();
        assert!(q.push("https://example.com/page#section1", 1));
        assert!(!q.push("https://example.com/page#section2", 2)); // same after normalization
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_max_size() {
        let mut q = CrawlQueue::with_max_size(2);
        assert!(q.push("https://a.com", 1));
        assert!(q.push("https://b.com", 1));
        assert!(!q.push("https://c.com", 1)); // queue full
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_retry() {
        let mut q = CrawlQueue::new();
        q.push("https://example.com/fail", 5);
        let job = q.pop().unwrap();
        assert_eq!(job.retries, 0);

        assert!(q.retry(&job));
        let retried = q.pop().unwrap();
        assert_eq!(retried.retries, 1);
        assert_eq!(retried.priority, 15); // priority degraded
    }

    #[test]
    fn test_retry_exhausted() {
        let mut q = CrawlQueue::new();
        let mut job = CrawlJob::new("https://example.com", 1);
        job.retries = 3;
        job.max_retries = 3;
        assert!(!q.retry(&job));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(extract_domain("https://example.com:8080/path"), "example.com");
        assert_eq!(extract_domain("http://SUB.Example.COM/"), "sub.example.com");
    }

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("HTTPS://Example.COM/Page#frag"),
            "https://example.com/Page"
        );
    }

    #[test]
    fn test_has_seen() {
        let mut q = CrawlQueue::new();
        q.push("https://example.com/a", 1);
        assert!(q.has_seen("https://example.com/a"));
        assert!(!q.has_seen("https://example.com/b"));
    }

    #[test]
    fn test_drain_domain() {
        let mut q = CrawlQueue::new();
        q.push("https://a.com/1", 1);
        q.push("https://b.com/1", 1);
        q.push("https://a.com/2", 1);
        let drained = q.drain_domain("a.com");
        assert_eq!(drained.len(), 2);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_checkpoint_roundtrip() {
        let mut q = CrawlQueue::new();
        q.push("https://example.com/a", 1);
        q.push("https://example.com/b", 5);
        q.push("https://example.com/c", 3);

        let tmp = std::env::temp_dir().join("tallow_queue_test.json");
        let path = tmp.to_str().unwrap();
        q.save_checkpoint(path).unwrap();

        let loaded = CrawlQueue::load_checkpoint(path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded.seen_count(), 3);

        // Clean up
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_delta_plan_classifies_by_cache() {
        let mut q = CrawlQueue::new();
        // first crawl: no cache → re_fetch
        // cached with ETag validator → skip
        // cached with content hash but no validator → re_fetch (conditional)
        q.record_response("https://a.com/1", None, None, "body-a");
        q.record_response("https://b.com/2", Some("\"etag-1\""), None, "body-b");
        q.record_response("https://c.com/3", None, None, "body-c");

        let urls = vec![
            "https://a.com/1".to_string(), // hash, no validator → re_fetch
            "https://b.com/2".to_string(), // hash + etag → skip
            "https://c.com/3".to_string(), // hash, no validator → re_fetch
            "https://d.com/4".to_string(), // never seen → re_fetch
        ];

        let plan = q.delta_plan(&urls);
        assert_eq!(plan.skip, vec!["https://b.com/2".to_string()]);
        assert_eq!(plan.re_fetch.len(), 3);
        assert!((plan.skip_ratio() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_should_skip_extraction_gated_by_env() {
        // TALLOW_DELTA_CRAWL is unset by default → never skip.
        let mut q = CrawlQueue::new();
        q.record_response("https://a.com/1", None, None, "same-body");
        // Same body (unchanged) but delta disabled → do NOT skip.
        assert!(!q.should_skip_extraction("https://a.com/1", "same-body"));
        // Changed body → never skip regardless.
        assert!(!q.should_skip_extraction("https://a.com/1", "different"));
    }
}
