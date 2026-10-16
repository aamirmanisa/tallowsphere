//! Unified middleware request pipeline for crawling.
//!
//! Provides a Scrapy-style ordered chain of interceptors that wrap
//! [`AdaptiveCrawler::fetch`]. Each interceptor can run a `before` hook (mutate
//! the outgoing request / short-circuit it) and an `after` hook (inspect the
//! result / record metadata). The default [`CrawlPipelineBuilder`] composes the
//! canonical chain:
//!
//! ```text
//! proxy-selection → headers/UA → robots.txt → per-domain rate-limit
//!   → retry/backoff (Retry-After aware) → HTTP-cache(ETag/content-hash)
//!   → browser-escalation (via AdaptiveCrawler::fetch)
//! ```
//!
//! This is the "missing spine" from gap G3-§1: it replaces the dispersed,
//! uncomposed fetch path with a single ordered, extensible abstraction that
//! reuses the existing modules:
//! - [`crate::browser::retry::retry_with_backoff_governed`] for retry/backoff
//!   (honoring `Retry-After` / soft-block signals),
//! - [`crate::browser::ratelimit::DomainRateManager`] for per-domain pacing,
//! - [`crate::browser::retry_intelligence::RetryIntelligence::classify_failure`]
//!   for fine-grained failure classification,
//! - [`crate::browser::robots::RobotsCache`] for robots.txt compliance,
//! - [`crate::browser::crawl_queue::CrawlQueue`] for content-hash/ETag
//!   conditional GET + delta-crawl change detection (G3-§3).
//!
//! Content-hash / ETag wiring is **on by default** (B2, 2026-10-12): a fresh
//! pipeline starts with an empty cache, so the first run behaves exactly like a
//! plain `AdaptiveCrawler::fetch`; later runs emit conditional GETs and skip
//! unchanged bodies. [`CrawlPipelineBuilder::with_content_cache`] overrides it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::browser::adaptive_crawler::{AdaptiveCrawler, CrawlResult, CrawlSource};
use crate::browser::crawl_queue::{delta_crawl_enabled, CrawlQueue};
use crate::browser::dlq::{DeadLetter, DeadLetterQueue, DlqStats};
use crate::browser::error::BrowserError;
use crate::browser::page::Page;
use crate::browser::ratelimit::DomainRateManager;
use crate::browser::retry::{retry_with_backoff_governed, RetryConfig, RetrySignal};
use crate::browser::retry_intelligence::{RetryIntelligence, SmartFailureType};
use crate::browser::robots::RobotsCache;
// Delta-crawl planning helpers live in the scheduler module's
// "Delta / Incremental Crawl Planning" region; the pipeline consumes them so
// scheduled delta runs skip already-fetched-unchanged URLs (hash compare).
use crate::browser::scheduler::{
    content_hash_of, is_unchanged_after_fetch, plan_incremental_crawl, CachedUrl,
};

/// Per-request state threaded through the interceptor chain.
///
/// `before` hooks mutate the outgoing `headers` / `conditional` / `proxy`, or
/// set `stop` to short-circuit the transport. After the transport runs, `result`
/// holds the fetched [`CrawlResult`] and `etag` / `last_modified` / `status` /
/// `unchanged` expose response metadata to `after` hooks.
#[derive(Debug, Default)]
pub struct PipelineContext {
    /// The URL being crawled.
    pub url: String,
    /// Domain extracted from the URL (used for rate limiting / robots).
    pub domain: String,
    /// Outgoing request headers accumulated by `before` hooks.
    pub headers: Vec<(String, String)>,
    /// Conditional-GET headers (`If-None-Match` / `If-Modified-Since`).
    pub conditional: Vec<(String, String)>,
    /// Optional proxy URL selected for this request.
    pub proxy: Option<String>,
    /// Result produced by the transport / a short-circuiting interceptor.
    pub result: Option<CrawlResult>,
    /// ETag observed on this response (if any).
    pub etag: Option<String>,
    /// Last-Modified observed on this response (if any).
    pub last_modified: Option<String>,
    /// HTTP status code of the last response.
    pub status: u16,
    /// True when the body hash is unchanged vs the prior crawl, or a 304.
    pub unchanged: bool,
    /// True when the delta crawl cache middleware skipped the transport
    /// because the URL's stored hash + validator proved it unchanged.
    /// The after-hooks synthesize an `unchanged` result for this request.
    pub delta_skipped: bool,
    /// Set by a `before` hook to skip the transport entirely.
    pub stop: bool,
}

impl PipelineContext {
    /// Build a context for a URL, deriving the domain.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            domain: crate::browser::crawl_queue::extract_domain(url),
            ..Self::default()
        }
    }
}

/// Per-run delta-crawl statistics, accumulated by the HTTP-cache middleware
/// and exposed via [`CrawlPipeline::delta_stats`]. `reset_delta_stats` starts
/// a new run; a scheduled delta job's run log embeds these numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DeltaRunStats {
    /// URLs whose fetch actually reached the HTTP transport.
    pub attempted: usize,
    /// URLs skipped *before* the transport: a stored content hash plus a
    /// revalidation validator (ETag / Last-Modified) let the delta run trust
    /// the cached copy (see `scheduler::DeltaNeed::Skip`).
    pub skipped_cached: usize,
    /// Responses that came back `304 Not Modified` (no body re-transferred).
    pub conditional_304: usize,
    /// HTTP 200 responses whose `sha256(body)` matched the stored hash.
    pub fetched_unchanged: usize,
    /// HTTP 200 responses whose body hash differed from the stored hash
    /// (or that had no stored hash — first-seen content).
    pub fetched_changed: usize,
}

impl DeltaRunStats {
    /// URLs this run did not need to re-extract (skipped + 304 + hash-match).
    pub fn unchanged_total(&self) -> usize {
        self.skipped_cached + self.conditional_304 + self.fetched_unchanged
    }

    /// Total URLs handled this run.
    pub fn total(&self) -> usize {
        self.attempted + self.skipped_cached
    }

    /// Human-readable one-line summary of the run's delta stats.
    pub fn summary(&self) -> String {
        let total = self.total();
        let pct = if total == 0 {
            0.0
        } else {
            self.unchanged_total() as f64 * 100.0 / total as f64
        };
        format!(
            "delta run: {} urls ({} fetched, {} skipped-cached), {} unchanged ({} hash-match, {} 304), {} changed/new — {:.1}% unchanged",
            total,
            self.attempted,
            self.skipped_cached,
            self.unchanged_total(),
            self.fetched_unchanged,
            self.conditional_304,
            self.fetched_changed,
            pct
        )
    }
}

/// A single middleware interceptor in the crawl pipeline.
///
/// Both hooks are synchronous (politeness sleeps are blocking, which is fine for
/// a crawl loop). Return an error from `before` to fail the request before it
/// reaches the transport (e.g. robots disallow, rate-limit exhausted).
pub trait Middleware: Send {
    /// Human-readable name (used for diagnostics / ordering).
    fn name(&self) -> &'static str;

    /// Runs before the transport; may mutate `ctx` or set `ctx.stop`.
    fn before(&mut self, _ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        Ok(())
    }

    /// Runs after the transport; may inspect / annotate `ctx`.
    fn after(&mut self, _ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        Ok(())
    }
}

// ── Built-in interceptors ──────────────────────────────────────────────────

/// Proxy-selection slot. When a proxy URL is set, it is attached to the
/// request (the transport builds the agent with it). Left empty to use the
/// direct connection.
pub struct ProxySelectorMiddleware {
    proxy: Option<String>,
}

impl ProxySelectorMiddleware {
    pub fn new(proxy: Option<String>) -> Self {
        Self { proxy }
    }
}

impl Middleware for ProxySelectorMiddleware {
    fn name(&self) -> &'static str {
        "proxy-selection"
    }

    fn before(&mut self, ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        ctx.proxy = self.proxy.clone();
        Ok(())
    }
}

/// Headers / User-Agent interceptor. Sets the base UA/Accept/Accept-Language
/// headers and merges any caller-supplied extra headers.
pub struct HeaderMiddleware {
    user_agent: String,
    extra: Vec<(String, String)>,
}

impl HeaderMiddleware {
    pub fn new(user_agent: &str, extra: Vec<(String, String)>) -> Self {
        Self {
            user_agent: user_agent.to_string(),
            extra,
        }
    }
}

impl Middleware for HeaderMiddleware {
    fn name(&self) -> &'static str {
        "headers/ua"
    }

    fn before(&mut self, ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        ctx.headers.clear();
        ctx.headers.push(("User-Agent".to_string(), self.user_agent.clone()));
        ctx.headers.push((
            "Accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        ));
        ctx.headers.push(("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()));
        for (k, v) in &self.extra {
            ctx.headers.push((k.clone(), v.clone()));
        }
        Ok(())
    }
}

/// Robots.txt compliance interceptor. Fails the request (`RobotsTxtDisallowed`)
/// when the target is not allowed by the cached robots policy for the UA.
pub struct RobotsMiddleware {
    robots: RobotsCache,
}

impl RobotsMiddleware {
    pub fn new(user_agent: &str) -> Self {
        Self {
            robots: RobotsCache::new(user_agent, Duration::from_secs(3600)),
        }
    }
}

impl Middleware for RobotsMiddleware {
    fn name(&self) -> &'static str {
        "robots.txt"
    }

    fn before(&mut self, ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        if !self.robots.is_allowed(&ctx.url)? {
            return Err(BrowserError::RobotsTxtDisallowed(ctx.url.clone()));
        }
        Ok(())
    }
}

/// Per-domain rate-limit interceptor. Consumes a token from
/// [`DomainRateManager`] (token bucket + circuit breaker). If the circuit is
/// open / the bucket is exhausted, fails with `RateLimitExceeded`.
///
/// **Pacing is not done here** (B3, 2026-10-12): the wait is awaited by
/// [`CrawlPipeline::fetch`] so it never blocks a runtime thread. This sync hook
/// only acquires.
///
/// The shared manager is also fed success / soft-block signals by the transport
/// so retry-soft-blocks propagate back to the domain governor.
pub struct RateLimitMiddleware {
    ratelim: Arc<Mutex<DomainRateManager>>,
}

impl RateLimitMiddleware {
    pub fn new(default_rate: f64) -> Self {
        Self {
            ratelim: Arc::new(Mutex::new(DomainRateManager::new(default_rate))),
        }
    }

    pub fn with_shared(ratelim: Arc<Mutex<DomainRateManager>>) -> Self {
        Self { ratelim }
    }
}

impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    fn before(&mut self, ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        // B3 (2026-10-12): per-domain pacing moved to `CrawlPipeline::fetch`,
        // which awaits the wait asynchronously instead of blocking this sync
        // hook with `std::thread::sleep`. This hook only consumes a token (or
        // trips the circuit breaker) after that wait has elapsed.
        let mut rl = self.ratelim.lock().map_err(|_| {
            BrowserError::ActionFailed("rate-limit lock poisoned".into())
        })?;
        if !rl.try_acquire(&ctx.domain) {
            return Err(BrowserError::RateLimitExceeded(ctx.domain.clone()));
        }
        Ok(())
    }
}

/// HTTP-cache / ETag interceptor — **opt-in**. When enabled, attaches
/// conditional-GET headers (`If-None-Match` / `If-Modified-Since`) from the
/// last response for the URL, and after a fetch records the new
/// `sha256(body)` + `etag` + `last_modified` into the [`CrawlQueue`] cache.
///
/// When the content hash is unchanged (delta crawl) it marks the result
/// `unchanged` so callers can skip re-extraction. When the server returns a
/// `304`, the transport produces a result with `status == 304` and
/// `unchanged == true` and no body is re-transferred.
///
/// **Delta-crawl consumer (B10):** the middleware is also the run-path
/// consumer of the scheduler module's delta planning helpers
/// ([`CachedUrl`] / [`plan_incremental_crawl`]). Delta mode is active when
/// `delta_crawl_enabled()` (env `TALLOW_DELTA_CRAWL=1`, set by the scheduler
/// for `ScheduledJob.delta`) or the builder's `with_delta_crawl(true)` flag
/// is set; in delta mode:
/// - the cache is effectively enabled even when the builder left it off, so
///   a scheduled delta run records and compares content hashes;
/// - a URL whose stored hash + validator classifies `DeltaNeed::Skip` is
///   **not re-fetched** — `ctx.delta_skipped` short-circuits the transport
///   and the after-hook synthesizes an `unchanged` result;
/// - per-run counters land in [`DeltaRunStats`] and are persisted to
///   `TALLOW_DELTA_STATS` so the scheduler embeds them in the run log.
pub struct HttpCacheMiddleware {
    queue: Arc<Mutex<CrawlQueue>>,
    enabled: bool,
    /// Force delta mode regardless of env (builder `with_delta_crawl`).
    delta: bool,
    /// Shared per-run counters (pipeline + middleware + stats file).
    stats: Arc<Mutex<DeltaRunStats>>,
    /// Persisted-queue checkpoint already loaded from `TALLOW_DELTA_QUEUE`.
    queue_loaded: bool,
}

impl HttpCacheMiddleware {
    pub fn new(enabled: bool) -> Self {
        Self::with_queue(enabled, Arc::new(Mutex::new(CrawlQueue::new())))
    }

    pub fn with_queue(enabled: bool, queue: Arc<Mutex<CrawlQueue>>) -> Self {
        Self {
            queue,
            enabled,
            delta: false,
            stats: Arc::new(Mutex::new(DeltaRunStats::default())),
            queue_loaded: false,
        }
    }

    /// Force delta mode (independent of the `TALLOW_DELTA_CRAWL` env var).
    pub fn with_delta(mut self, delta: bool) -> Self {
        self.delta = delta;
        self
    }

    /// Share a per-run stats cell with the owning pipeline.
    pub fn with_stats(mut self, stats: Arc<Mutex<DeltaRunStats>>) -> Self {
        self.stats = stats;
        self
    }

    /// Access the underlying queue (e.g. for checkpointing between runs).
    pub fn queue(&self) -> Arc<Mutex<CrawlQueue>> {
        Arc::clone(&self.queue)
    }

    /// Snapshot of this run's delta counters.
    pub fn delta_stats(&self) -> DeltaRunStats {
        self.stats
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Delta mode is on when forced by the builder or signalled by the
    /// scheduler (`TALLOW_DELTA_CRAWL=1` on scheduled delta-job subprocesses).
    fn delta_active(&self) -> bool {
        self.delta || delta_crawl_enabled()
    }

    /// The cache's change-detection is effective when the builder enabled it
    /// *or* delta mode is active (a delta run must record hashes to have
    /// anything to skip against on the next run).
    fn effective_enabled(&self) -> bool {
        self.enabled || self.delta_active()
    }

    /// Load a persisted crawl-queue checkpoint (across scheduled runs) from
    /// `TALLOW_DELTA_QUEUE`, replacing the in-memory queue contents.
    fn load_persisted_queue(&mut self) {
        if let Ok(path) = std::env::var("TALLOW_DELTA_QUEUE") {
            if path.is_empty() {
                return;
            }
            if let Ok(loaded) = CrawlQueue::load_checkpoint(&path) {
                if let Ok(mut q) = self.queue.lock() {
                    *q = loaded;
                }
            }
        }
    }

    /// Persist the queue checkpoint (`TALLOW_DELTA_QUEUE`) and the per-run
    /// delta stats (`TALLOW_DELTA_STATS`) so the *next* scheduled run starts
    /// from this run's hashes and the scheduler log records this run's stats.
    fn persist_delta_state(&self) {
        if let Ok(path) = std::env::var("TALLOW_DELTA_QUEUE") {
            if !path.is_empty() {
                if let Ok(q) = self.queue.lock() {
                    let _ = q.save_checkpoint(&path);
                }
            }
        }
        if let Ok(path) = std::env::var("TALLOW_DELTA_STATS") {
            if !path.is_empty() {
                if let Ok(st) = self.stats.lock() {
                    let _ = std::fs::write(&path, serde_json::to_string(&*st).unwrap_or_default());
                }
            }
        }
    }

    fn bump_stats(&self, f: impl FnOnce(&mut DeltaRunStats)) {
        if let Ok(mut st) = self.stats.lock() {
            f(&mut st);
        }
    }
}

impl Middleware for HttpCacheMiddleware {
    fn name(&self) -> &'static str {
        "http-cache(etag)"
    }

    fn before(&mut self, ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        if !self.effective_enabled() {
            return Ok(());
        }
        // Delta mode only: load the persisted checkpoint once (TALLOW_DELTA_QUEUE
        // is scheduler-set on delta-job subprocesses; plain content-cache runs
        // never touch the env paths).
        if self.delta_active() && !self.queue_loaded {
            self.load_persisted_queue();
            self.queue_loaded = true;
        }
        let q = self.queue.lock().map_err(|_| {
            BrowserError::ActionFailed("http-cache lock poisoned".into())
        })?;
        ctx.conditional = q.conditional_headers(&ctx.url);

        // Delta run: plan this single URL against the stored hash + validator
        // metadata. A `Skip` classification (stored hash **and** validator)
        // means the origin revalidates the resource, so trust the cached copy
        // and do not re-fetch it this pass.
        if self.delta_active() {
            let entry = CachedUrl::from_queue(&q, &ctx.url);
            let plan = plan_incremental_crawl(std::slice::from_ref(&entry));
            if plan.unchanged_count() == 1 && plan.re_crawl.is_empty() {
                drop(q);
                ctx.delta_skipped = true;
                ctx.stop = true;
                self.bump_stats(|st| st.skipped_cached += 1);
                self.persist_delta_state();
            }
        }
        Ok(())
    }

    fn after(&mut self, ctx: &mut PipelineContext) -> Result<(), BrowserError> {
        if !self.effective_enabled() {
            return Ok(());
        }
        // A delta-skipped request never reached the transport: synthesize an
        // `unchanged` result (empty body) so callers skip re-extraction.
        if ctx.delta_skipped {
            ctx.status = 200;
            ctx.unchanged = true;
            ctx.result = Some(CrawlResult {
                url: ctx.url.clone(),
                body: String::new(),
                status: 200,
                source: CrawlSource::Http,
                content_type: None,
                unchanged: true,
            });
            return Ok(());
        }
        let result = match ctx.result.as_mut() {
            Some(r) => r,
            None => return Ok(()),
        };
        // Browser-sourced results carry no response validators — nothing to cache.
        if result.source != CrawlSource::Http {
            return Ok(());
        }
        self.bump_stats(|st| st.attempted += 1);

        // 304: transport already marked it unchanged — count and move on.
        if result.status == 304 {
            self.bump_stats(|st| st.conditional_304 += 1);
            return Ok(());
        }
        let new_hash = content_hash_of(&result.body);
        let mut q = self.queue.lock().map_err(|_| {
            BrowserError::ActionFailed("http-cache lock poisoned".into())
        })?;
        // Compare against the *prior* stored hash before overwriting it.
        let entry = CachedUrl::from_queue(&q, &ctx.url);
        let unchanged = is_unchanged_after_fetch(&entry, false, Some(&new_hash));
        q.record_response(&ctx.url, ctx.etag.as_deref(), ctx.last_modified.as_deref(), &result.body);
        drop(q);
        result.unchanged = unchanged;
        ctx.unchanged = unchanged;
        if unchanged {
            self.bump_stats(|st| st.fetched_unchanged += 1);
        } else {
            self.bump_stats(|st| st.fetched_changed += 1);
        }
        if self.delta_active() {
            self.persist_delta_state();
        }
        Ok(())
    }
}

/// Result of the fast HTTP transport: the fetched page plus the response
/// validators (ETag / Last-Modified) needed to record cache metadata.
struct HttpFetch {
    result: CrawlResult,
    etag: Option<String>,
    last_modified: Option<String>,
}

/// The composed crawl pipeline.
///
/// Wraps an [`AdaptiveCrawler`] (for browser escalation) and runs a request
/// through an ordered chain of [`Middleware`] interceptors around an HTTP
/// transport that itself uses `retry_with_backoff_governed` for retry/backoff.
pub struct CrawlPipeline {
    crawler: AdaptiveCrawler,
    stages: Vec<Box<dyn Middleware>>,
    retry: RetryConfig,
    ratelim: Arc<Mutex<DomainRateManager>>,
    min_content_length: usize,
    http_timeout_secs: u64,
    /// Keep-alive HTTP agents shared across requests (see [`AgentCache`]).
    agents: AgentCache,
    /// Retry intelligence: classifies transport failures (403/429/503 +
    /// `Retry-After` / 304-aware) and learns from dead-lettered failures.
    intel: Arc<Mutex<RetryIntelligence>>,
    /// Dead-letter queue for transport failures that exhausted their governed
    /// retries. Failed attempts are recorded here and fed to [`Self::intel`]
    /// via `learn_from_dlq` at the recording site.
    dlq: Arc<DeadLetterQueue>,
    /// Per-run delta-crawl counters shared with the HTTP-cache middleware.
    delta_stats: Arc<Mutex<DeltaRunStats>>,
}

impl CrawlPipeline {
    /// Run a URL through the full pipeline.
    ///
    /// `page` enables browser-escalation (via [`AdaptiveCrawler::fetch`]) when
    /// the fast HTTP path fails or returns a JS-shell body.
    pub async fn fetch(
        &mut self,
        url: &str,
        page: Option<&Page>,
    ) -> Result<CrawlResult, BrowserError> {
        let mut ctx = PipelineContext::new(url);

        // 0. Per-domain pacing (B3, 2026-10-12): wait ASYNCHRONOUSLY so a
        //    rate-limited domain parks this task (yielding the runtime thread
        //    to other crawls) instead of blocking it inside the sync
        //    rate-limit hook. Order preserved: wait here, then the rate-limit
        //    stage consumes its token in the before-hook pass below. The lock
        //    guard is scoped so the future stays `Send` across the await.
        let wait = {
            let mut rl = self.ratelim.lock().map_err(|_| {
                BrowserError::ActionFailed("rate-limit lock poisoned".into())
            })?;
            rl.wait_duration(&ctx.domain)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }

        // 1. before-hooks (in order); a hook may stop the chain.
        for s in &mut self.stages {
            s.before(&mut ctx)?;
            if ctx.stop {
                break;
            }
        }

        // 2. transport (HTTP + retry), with browser escalation fallback.
        if !ctx.stop {
            match self.transport(&ctx).await {
                Ok(fetched) => {
                    ctx.etag = fetched.etag;
                    ctx.last_modified = fetched.last_modified;
                    ctx.status = fetched.result.status;
                    let mut result = fetched.result;
                    if result.source == CrawlSource::Http
                        && page.is_some()
                        && result.status == 200
                        && result.body.trim().len() < self.min_content_length
                    {
                        result = self.crawler.fetch(url, page).await?;
                        ctx.etag = None;
                        ctx.last_modified = None;
                        ctx.status = result.status;
                    }
                    ctx.result = Some(result);
                }
                Err(e) => {
                    if let Some(p) = page {
                        let result = self.crawler.fetch(url, Some(p)).await?;
                        ctx.result = Some(result);
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // 3. after-hooks (in order).
        for s in &mut self.stages {
            s.after(&mut ctx)?;
        }

        ctx.result
            .ok_or_else(|| BrowserError::ActionFailed(format!("crawl produced no result for {url}")))
    }

    /// Snapshot of the retry-intelligence learner (per-domain / per-proxy
    /// patterns accumulated from dead-lettered transport failures).
    pub fn intelligence(&self) -> RetryIntelligence {
        self.intel
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Shared dead-letter queue holding transport failures whose governed
    /// retries were exhausted.
    pub fn dlq(&self) -> Arc<DeadLetterQueue> {
        Arc::clone(&self.dlq)
    }

    /// Dead-letter statistics for this pipeline.
    pub fn dlq_stats(&self) -> DlqStats {
        self.dlq.stats()
    }

    /// Per-run delta-crawl counters (B10).
    pub fn delta_stats(&self) -> DeltaRunStats {
        self.delta_stats
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Start a new delta run: zero the per-run counters.
    pub fn reset_delta_stats(&self) {
        if let Ok(mut st) = self.delta_stats.lock() {
            *st = DeltaRunStats::default();
        }
    }

    /// Fast HTTP transport wrapped in retry/backoff. Sends the accumulated
    /// headers + conditional-GET headers, classifies failures via
    /// [`RetryIntelligence::classify_failure`] (403/429/503, `Retry-After`,
    /// 304-aware), honors `Retry-After` / soft-blocks, and reports back to
    /// the domain governor.
    ///
    /// Retry timing stays governed by [`retry_with_backoff_governed`]
    /// (retry.rs) — the intelligence is *connected*, not duplicated: every
    /// failed attempt is classified, and the fetch's final failure (retries
    /// exhausted) is dead-lettered and fed to `learn_from_dlq` at the
    /// recording site, so per-domain / per-proxy patterns accumulate.
    async fn transport(
        &mut self,
        ctx: &PipelineContext,
    ) -> Result<HttpFetch, BrowserError> {
        // Reuse a pooled keep-alive agent when one exists for this
        // (proxy, timeout) key instead of building a fresh agent (and losing
        // its HTTP connection pool) on every request.
        // T-207: the zone predicate decides the route per destination —
        // loopback (in-zone) targets stay direct; WAN rides the contract
        // (Tor SOCKS by default).
        let agent = self.agents.agent_for_url(
            &ctx.url,
            ctx.proxy.as_deref(),
            self.http_timeout_secs,
        );
        let url = ctx.url.clone();
        let domain = ctx.domain.clone();
        let headers = ctx.headers.clone();
        let conditional = ctx.conditional.clone();
        let proxy = ctx.proxy.clone();
        let ratelim = Arc::clone(&self.ratelim);
        let retry = self.retry.clone();
        let intel = Arc::clone(&self.intel);
        // Context of the last failed attempt. Only the *final* failure of the
        // fetch (after the governed retry loop exhausts) is dead-lettered, so
        // a DLQ entry means "this URL's transport failed permanently", not
        // "one retry attempt failed".
        let last_failure: Arc<Mutex<Option<DeadLetter>>> = Arc::new(Mutex::new(None));

        let attempt = || {
            let agent = agent.clone();
            let url = url.clone();
            let domain = domain.clone();
            let headers = headers.clone();
            let conditional = conditional.clone();
            let proxy = proxy.clone();
            let ratelim = Arc::clone(&ratelim);
            let intel = Arc::clone(&intel);
            let last_failure = Arc::clone(&last_failure);
            async move {
                let t0 = std::time::Instant::now();
                let mut req = agent.get(&url);
                for (k, v) in &headers {
                    req = req.header(k, v);
                }
                for (k, v) in &conditional {
                    req = req.header(k, v);
                }

                match req.call() {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let etag = resp
                            .headers()
                            .get("etag")
                            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
                            .map(|s| s.to_string());
                        let last_modified = resp
                            .headers()
                            .get("last-modified")
                            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
                            .map(|s| s.to_string());
                        let content_type = resp
                            .headers()
                            .get("content-type")
                            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
                            .map(|s| s.to_string());

                        let final_url = resp
                            .headers()
                            .get("location")
                            .and_then(|v: &ureq::http::HeaderValue| v.to_str().ok())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| url.clone());

                        // Full response headers — includes `Retry-After`, which
                        // `RetrySignal::from_response` parses for soft-block
                        // backoff. (Previously only `etag` was forwarded, so
                        // Retry-After was never honored.)
                        let hdr = response_headers(&resp);

                        let body = match resp.into_body().read_to_string() {
                            Ok(b) => b,
                            Err(e) => {
                                note_transport_failure(
                                    &last_failure,
                                    &intel,
                                    &url,
                                    &domain,
                                    proxy.as_deref(),
                                    None,
                                    &HashMap::new(),
                                    "",
                                    &format!("Failed to read response body: {e}"),
                                );
                                return Err(RetrySignal::from_error(BrowserError::ActionFailed(
                                    format!("Failed to read response body: {e}"),
                                )));
                            }
                        };

                        // 304 Not Modified → unchanged, skip body transfer.
                        if status == 304 {
                            if let Ok(mut rl) = ratelim.lock() {
                                rl.report_success(&domain);
                            }
                            record_intel_success(
                                &intel,
                                &domain,
                                proxy.as_deref(),
                                t0.elapsed().as_millis() as u64,
                                &headers,
                            );
                            return Ok(HttpFetch {
                                result: CrawlResult {
                                    url: final_url,
                                    body: String::new(),
                                    status,
                                    source: CrawlSource::Http,
                                    content_type,
                                    unchanged: true,
                                },
                                etag,
                                last_modified,
                            });
                        }

                        // Soft block / anti-bot → classify the failure for the
                        // intelligence, report to governor, and back off per
                        // the server's Retry-After when present.
                        if matches!(status, 429 | 403 | 503) {
                            if let Ok(mut rl) = ratelim.lock() {
                                rl.report_soft_block(&domain);
                            }
                            note_transport_failure(
                                &last_failure,
                                &intel,
                                &url,
                                &domain,
                                proxy.as_deref(),
                                Some(status),
                                &hdr,
                                &body,
                                &format!("HTTP {status} (rate-limit/anti-bot)"),
                            );
                            return Err(RetrySignal::from_response(
                                BrowserError::RateLimitExceeded(domain.clone()),
                                Some(status),
                                &hdr,
                                &domain,
                            ));
                        }

                        // Other 4xx/5xx arrive as responses because the agent
                        // runs with http_status_as_error(false); keep failing
                        // through the retry loop exactly like before.
                        if status >= 400 {
                            note_transport_failure(
                                &last_failure,
                                &intel,
                                &url,
                                &domain,
                                proxy.as_deref(),
                                Some(status),
                                &hdr,
                                &body,
                                &format!("HTTP request failed with status {status}"),
                            );
                            return Err(RetrySignal::from_response(
                                BrowserError::ActionFailed(format!(
                                    "HTTP request failed with status {status}"
                                )),
                                Some(status),
                                &hdr,
                                &domain,
                            ));
                        }

                        if let Ok(mut rl) = ratelim.lock() {
                            rl.report_success(&domain);
                        }
                        record_intel_success(
                            &intel,
                            &domain,
                            proxy.as_deref(),
                            t0.elapsed().as_millis() as u64,
                            &headers,
                        );

                        Ok(HttpFetch {
                            result: CrawlResult {
                                url: final_url,
                                body,
                                status,
                                source: CrawlSource::Http,
                                content_type,
                                unchanged: false,
                            },
                            etag,
                            last_modified,
                        })
                    }
                    Err(e) => {
                        // With http_status_as_error(false) this is a transport
                        // error (no response available). Handle StatusCode
                        // defensively in case a future config change surfaces
                        // it: classify 429/403/503 as soft blocks. ureq 3 does
                        // not attach the response to errors, so Retry-After
                        // cannot be read on this path — classification by
                        // status still works.
                        if let ureq::Error::StatusCode(code) = &e {
                            let status = *code;
                            let err = if matches!(status, 429 | 403 | 503) {
                                BrowserError::RateLimitExceeded(domain.clone())
                            } else {
                                BrowserError::ActionFailed(format!(
                                    "HTTP request failed with status {status}: {e}"
                                ))
                            };
                            note_transport_failure(
                                &last_failure,
                                &intel,
                                &url,
                                &domain,
                                proxy.as_deref(),
                                Some(status),
                                &HashMap::new(),
                                "",
                                &format!("HTTP request failed with status {status}: {e}"),
                            );
                            return Err(RetrySignal::from_response(
                                err,
                                Some(status),
                                &HashMap::new(),
                                &domain,
                            ));
                        }
                        let err = BrowserError::ActionFailed(format!("HTTP request failed: {e}"));
                        note_transport_failure(
                            &last_failure,
                            &intel,
                            &url,
                            &domain,
                            proxy.as_deref(),
                            None,
                            &HashMap::new(),
                            "",
                            &format!("HTTP request failed: {e}"),
                        );
                        // Classify via response status where possible; default to transient.
                        Err(RetrySignal::from_response(err, None, &HashMap::new(), &domain))
                    }
                }
            }
        };

        match retry_with_backoff_governed(attempt, &retry, |_| {}).await {
            Ok(fetched) => Ok(fetched),
            Err(e) => {
                // Governed retries exhausted — record the *final* classified
                // failure where crawl results are recorded: dead-letter it and
                // feed it straight into the intelligence learner so the next
                // run's recommendations see this domain's failure pattern.
                if let Some(dl) = last_failure
                    .lock()
                    .map_err(|_| BrowserError::ActionFailed("last-failure lock poisoned".into()))?
                    .take()
                {
                    if let Ok(mut g) = self.intel.lock() {
                        g.learn_from_dlq(std::slice::from_ref(&dl));
                    }
                    self.dlq.add(dl);
                }
                Err(e)
            }
        }
    }
}

// ── Retry-intelligence helpers (B9 wiring) ───────────────────────────────

/// Classify a failed transport attempt via
/// [`RetryIntelligence::classify_failure`] and remember it as the fetch's
/// last failure. The classification tag rides on the dead letter's
/// `final_error` so DLQ consumers see *why* it failed beyond the status code.
fn note_transport_failure(
    last_failure: &Arc<Mutex<Option<DeadLetter>>>,
    intel: &Arc<Mutex<RetryIntelligence>>,
    url: &str,
    domain: &str,
    proxy: Option<&str>,
    status: Option<u16>,
    hdr: &HashMap<String, String>,
    body_snippet: &str,
    error: &str,
) {
    let smart = match intel.lock() {
        Ok(g) => g.classify_failure(status, hdr, body_snippet, error),
        Err(_) => SmartFailureType::Unknown,
    };
    let mut headers = hdr.clone();
    if let Some(p) = proxy {
        headers.entry("x-proxy-used".to_string()).or_insert_with(|| p.to_string());
    }
    let dl = DeadLetter {
        id: format!("crawl-{}-{}", domain, epoch_secs_i64()),
        job_type: "crawl_pipeline".to_string(),
        target: domain.to_string(),
        url: url.to_string(),
        attempts: 1,
        final_error: format!("{error} [classified: {}]", smart.as_str()),
        last_http_status: status,
        response_body_snippet: body_snippet.chars().take(512).collect(),
        response_headers: headers,
        failed_at: epoch_secs_i64(),
        reason_category: DeadLetterQueue::classify_error(error, status, body_snippet),
    };
    if let Ok(mut lf) = last_failure.lock() {
        *lf = Some(dl);
    }
}

/// Record a successful request into the intelligence learner (the mirror of
/// `learn_from_dlq` on the success side, so success/attempt ratios stay real).
fn record_intel_success(
    intel: &Arc<Mutex<RetryIntelligence>>,
    domain: &str,
    proxy: Option<&str>,
    latency_ms: u64,
    headers: &[(String, String)],
) {
    if let Ok(mut g) = intel.lock() {
        let ua = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str());
        g.record_success(domain, proxy.unwrap_or("direct"), latency_ms, proxy_tier_of(proxy), ua);
    }
}

/// Best-effort proxy tier label for the intelligence's tier tracking.
fn proxy_tier_of(proxy: Option<&str>) -> &'static str {
    match proxy {
        None => "direct",
        Some(p) if p.starts_with("socks") => "socks5",
        Some(p) if p.starts_with("http") => "http",
        Some(_) => "other",
    }
}

/// Current unix time in seconds (used for dead-letter timestamps).
fn epoch_secs_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build an [`ureq::Agent`] with an optional proxy and timeout.
///
/// `http_status_as_error(false)` makes ureq return 4xx/5xx as ordinary
/// responses instead of `Err(StatusCode)`, so the transport can read the
/// response headers (notably `Retry-After`) when classifying soft blocks.
fn build_agent(proxy: Option<&str>, timeout_secs: u64) -> ureq::Agent {
    let mut builder = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false);
    if let Some(p) = proxy {
        if let Ok(p) = ureq::Proxy::new(p) {
            builder = builder.proxy(Some(p));
        }
    }
    builder.build().new_agent()
}

/// Copy all response headers into a plain map (lower-cased names), so the
/// retry governor can parse `Retry-After` and classify soft blocks.
///
/// Generic over the body type because ureq 3.x does not publicly export its
/// concrete `Response` alias (`ureq::http::Response<B>` is the public path).
fn response_headers<B>(resp: &ureq::http::Response<B>) -> HashMap<String, String> {
    let mut hdr = HashMap::new();
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            hdr.entry(name.as_str().to_string())
                .or_insert_with(|| v.to_string());
        }
    }
    hdr
}

// ── Keep-alive agent cache ─────────────────────────────────────────────────

/// Upper bound on concurrently-live agents retained by [`AgentCache`].
///
/// Each live agent holds its own connection pool (open sockets), so the cache
/// is intentionally small. A pipeline that alternates between more distinct
/// (proxy, timeout) keys than this simply rebuilds an agent on the miss —
/// identical to the pre-cache per-request behaviour — while still reusing
/// keep-alive connections within each sticky window.
const AGENT_CACHE_MAX: usize = 4;

/// Small bounded cache of live [`ureq::Agent`]s keyed by (proxy, timeout).
///
/// `ureq::Agent` owns its HTTP connection pool (TCP + TLS session reuse).
/// Building a fresh agent per request — as the transport originally did —
/// forces a new TCP handshake (and TLS handshake on `https`) on *every*
/// fetch, because the previous agent — and its pooled keep-alive
/// connections — is dropped as soon as the request ends. Caching one agent
/// per (proxy, timeout_secs) key lets HTTP/1.1 keep-alive connections be
/// reused across sequential requests to the same host for the lifetime of
/// the pipeline (or until the key changes, e.g. on proxy rotation).
///
/// The cache is bounded with most-recently-used eviction so a pipeline whose
/// proxy key changes every request cannot accumulate sockets unboundedly.
struct AgentCache {
    /// (proxy-url-or-empty, timeout-secs, live-agent), most-recent first.
    agents: Vec<(String, u64, ureq::Agent)>,
}

impl AgentCache {
    fn new() -> Self {
        Self {
            agents: Vec::with_capacity(AGENT_CACHE_MAX),
        }
    }

    /// Return a live agent for `(proxy, timeout_secs)`.
    ///
    /// Hits clone the cached handle (an `Arc` bump — the pool is shared).
    /// Misses build a new agent via [`build_agent`], cache it, and evict the
    /// least-recently-used entry when over capacity.
    /// Zone-aware variant of [`AgentCache::agent_for`]: with no explicit
    /// proxy, the T-207 browser-zone predicate decides by destination —
    /// in-zone (loopback) targets stay direct; anything else rides the
    /// egress contract (Tor SOCKS by default). A malformed contract proxy
    /// refuses loudly (N3) rather than egressing from the box IP.
    fn agent_for_url(&mut self, url: &str, proxy: Option<&str>, timeout_secs: u64) -> ureq::Agent {
        let zone_proxy: Option<String> = match proxy {
            Some(_) => None,
            None => match crate::browser::zone::browser_zone_egress_for(url) {
                Ok(crate::browser::zone::ZoneEgress::Contract { proxy }) => Some(proxy),
                Ok(_) => None,
                Err(reason) => panic!("{reason}"),
            },
        };
        let proxy = proxy.or(zone_proxy.as_deref());
        self.agent_for(proxy, timeout_secs)
    }

    fn agent_for(&mut self, proxy: Option<&str>, timeout_secs: u64) -> ureq::Agent {
        let key_proxy = proxy.unwrap_or("").to_string();
        if let Some(pos) = self
            .agents
            .iter()
            .position(|(p, t, _)| *p == key_proxy && *t == timeout_secs)
        {
            if pos != 0 {
                let (p, t, agent) = self.agents.remove(pos);
                self.agents.insert(0, (p, t, agent.clone()));
                return agent;
            }
            return self.agents[0].2.clone();
        }
        let agent = build_agent(proxy, timeout_secs);
        self.agents.insert(0, (key_proxy, timeout_secs, agent.clone()));
        while self.agents.len() > AGENT_CACHE_MAX {
            self.agents.pop(); // evict oldest — its pool closes on drop
        }
        agent
    }
}

// ── Builder ────────────────────────────────────────────────────────────────

/// Builder that composes the canonical interceptor chain in order:
/// proxy → headers → robots → rate-limit, plus optional HTTP-cache, around the
/// retry/backoff transport and browser-escalation fallback.
pub struct CrawlPipelineBuilder {
    crawler: AdaptiveCrawler,
    proxy: Option<String>,
    user_agent: String,
    extra_headers: Vec<(String, String)>,
    default_rate: f64,
    retry: RetryConfig,
    enable_content_cache: bool,
    min_content_length: usize,
    http_timeout_secs: u64,
    /// Force delta-crawl mode on the HTTP-cache middleware (independent of
    /// the `TALLOW_DELTA_CRAWL` env var set by the scheduler).
    enable_delta_crawl: bool,
}

impl Default for CrawlPipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CrawlPipelineBuilder {
    /// Start with a fresh crawler and default settings.
    pub fn new() -> Self {
        Self {
            crawler: AdaptiveCrawler::new(),
            proxy: None,
            user_agent: default_user_agent(),
            extra_headers: Vec::new(),
            default_rate: 0.5,
            retry: RetryConfig::default(),
            enable_content_cache: true,
            min_content_length: 1024,
            http_timeout_secs: 15,
            enable_delta_crawl: false,
        }
    }

    /// Use a specific [`AdaptiveCrawler`] for browser escalation.
    pub fn with_crawler(mut self, crawler: AdaptiveCrawler) -> Self {
        self.crawler = crawler;
        self
    }

    /// Route HTTP requests through a proxy URL (e.g. `socks5://127.0.0.1:9050`).
    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Override the User-Agent string.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Add extra request headers applied to every request.
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    /// Set the per-domain default request rate (requests/second).
    pub fn with_rate(mut self, default_rate: f64) -> Self {
        self.default_rate = default_rate;
        self
    }

    /// Configure the retry/backoff policy.
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// Content-hash / ETag change detection (delta crawls). **Default: on**
    /// (B2, 2026-10-12). Pass `false` to disable and reproduce the pre-cache
    /// behavior exactly.
    pub fn with_content_cache(mut self, enable: bool) -> Self {
        self.enable_content_cache = enable;
        self
    }

    /// Force delta-crawl mode: skip already-fetched-unchanged URLs (stored
    /// content hash + validator) and record per-run [`DeltaRunStats`].
    /// Independently of this flag, delta mode also activates automatically
    /// when `TALLOW_DELTA_CRAWL=1` (the scheduler sets it for
    /// `ScheduledJob.delta` runs). **Default: off** (backward compatible).
    pub fn with_delta_crawl(mut self, enable: bool) -> Self {
        self.enable_delta_crawl = enable;
        self
    }

    /// Minimum body length (bytes) below which a 200 HTTP response is treated
    /// as a JS shell and escalated to the browser.
    pub fn with_min_content_length(mut self, n: usize) -> Self {
        self.min_content_length = n;
        self
    }

    /// Compose the pipeline.
    pub fn build(self) -> CrawlPipeline {
        let ratelim = Arc::new(Mutex::new(DomainRateManager::new(self.default_rate)));

        // Shared per-run delta counters: the middleware accumulates them and
        // the pipeline exposes/resets them (and persists to TALLOW_DELTA_STATS).
        let delta_stats = Arc::new(Mutex::new(DeltaRunStats::default()));

        let mut stages: Vec<Box<dyn Middleware>> = Vec::new();
        stages.push(Box::new(ProxySelectorMiddleware::new(self.proxy)));
        stages.push(Box::new(HeaderMiddleware::new(&self.user_agent, self.extra_headers)));
        stages.push(Box::new(RobotsMiddleware::new(&self.user_agent)));
        stages.push(Box::new(RateLimitMiddleware::with_shared(Arc::clone(&ratelim))));
        stages.push(Box::new(
            HttpCacheMiddleware::new(self.enable_content_cache)
                .with_delta(self.enable_delta_crawl)
                .with_stats(Arc::clone(&delta_stats)),
        ));

        CrawlPipeline {
            crawler: self.crawler,
            stages,
            retry: self.retry,
            ratelim,
            min_content_length: self.min_content_length,
            http_timeout_secs: self.http_timeout_secs,
            agents: AgentCache::new(),
            intel: Arc::new(Mutex::new(RetryIntelligence::new())),
            dlq: Arc::new(DeadLetterQueue::new(1024)),
            delta_stats,
        }
    }
}

/// Default stealth-friendly desktop Chrome UA.
fn default_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_derives_domain() {
        let ctx = PipelineContext::new("https://Example.com:8080/path?q=1#frag");
        assert_eq!(ctx.domain, "example.com");
    }

    #[test]
    fn header_middleware_sets_ua() {
        let mut mw = HeaderMiddleware::new("TestUA", vec![("X-Test".into(), "1".into())]);
        let mut ctx = PipelineContext::new("https://example.com/");
        mw.before(&mut ctx).unwrap();
        assert!(ctx.headers.iter().any(|(k, v)| k == "User-Agent" && v == "TestUA"));
        assert!(ctx.headers.iter().any(|(k, v)| k == "X-Test" && v == "1"));
    }

    #[test]
    fn proxy_middleware_sets_proxy() {
        let mut mw = ProxySelectorMiddleware::new(Some("socks5://127.0.0.1:9050".into()));
        let mut ctx = PipelineContext::new("https://example.com/");
        mw.before(&mut ctx).unwrap();
        assert_eq!(ctx.proxy.as_deref(), Some("socks5://127.0.0.1:9050"));
    }

    #[test]
    fn rate_limit_middleware_does_not_block() {
        // B3 (2026-10-12): the sync hook must not sleep — async pacing lives in
        // `CrawlPipeline::fetch`. A fresh 0.5/s bucket holds <1 token, so the
        // hook must refuse IMMEDIATELY instead of blocking ~1s for a refill.
        let mut mw = RateLimitMiddleware::new(0.5);
        let mut ctx = PipelineContext::new("https://example.com/");
        let t = std::time::Instant::now();
        let r = mw.before(&mut ctx);
        assert!(
            t.elapsed() < std::time::Duration::from_millis(50),
            "rate-limit hook must not block; elapsed {:?}",
            t.elapsed()
        );
        assert!(matches!(r, Err(BrowserError::RateLimitExceeded(_))));
    }

    #[test]
    fn builder_default_enables_content_cache() {
        // B2 (2026-10-12): the content cache is ON by default (was opt-in).
        assert!(CrawlPipelineBuilder::new().enable_content_cache);
        // ...and can still be explicitly disabled.
        assert!(!CrawlPipelineBuilder::new().with_content_cache(false).enable_content_cache);
    }

    #[test]
    fn cache_middleware_off_is_noop() {
        let mut mw = HttpCacheMiddleware::new(false);
        let mut ctx = PipelineContext::new("https://example.com/");
        mw.before(&mut ctx).unwrap();
        assert!(ctx.conditional.is_empty());
        let mut result = CrawlResult {
            url: "https://example.com/".into(),
            body: "<html>hi</html>".into(),
            status: 200,
            source: CrawlSource::Http,
            content_type: None,
            unchanged: false,
        };
        ctx.result = Some(result.clone());
        mw.after(&mut ctx).unwrap();
        result = ctx.result.unwrap();
        assert!(!result.unchanged);
    }

    #[test]
    fn retry_signal_honors_retry_after_header() {
        // Regression: the transport must forward response headers (not just
        // `etag`) so RetrySignal can parse Retry-After for soft-block backoff.
        let mut hdr = HashMap::new();
        hdr.insert("retry-after".to_string(), "30".to_string());
        hdr.insert("etag".to_string(), "w/\"abc\"".to_string());
        let signal = RetrySignal::from_response(
            BrowserError::RateLimitExceeded("example.com".into()),
            Some(429),
            &hdr,
            "example.com",
        );
        assert_eq!(signal.retry_after_ms, Some(30_000));
        assert!(signal.soft_block);
    }

    #[test]
    fn cache_middleware_marks_unchanged_on_repeat_body() {
        let mut mw = HttpCacheMiddleware::new(true);
        let body = "<html><h1>hello</h1></html>".repeat(50);

        // First crawl: no prior hash → not unchanged.
        let mut ctx1 = PipelineContext::new("https://example.com/page");
        ctx1.result = Some(CrawlResult {
            url: "https://example.com/page".into(),
            body: body.clone(),
            status: 200,
            source: CrawlSource::Http,
            content_type: None,
            unchanged: false,
        });
        ctx1.etag = Some("w/\"abc\"".into());
        mw.before(&mut ctx1).unwrap();
        mw.after(&mut ctx1).unwrap();
        assert!(!ctx1.result.as_ref().unwrap().unchanged);

        // Second crawl with identical body → unchanged, conditional headers set.
        let mut ctx2 = PipelineContext::new("https://example.com/page");
        ctx2.result = Some(CrawlResult {
            url: "https://example.com/page".into(),
            body,
            status: 200,
            source: CrawlSource::Http,
            content_type: None,
            unchanged: false,
        });
        mw.before(&mut ctx2).unwrap();
        assert!(ctx2.conditional.iter().any(|(k, _)| k == "If-None-Match"));
        mw.after(&mut ctx2).unwrap();
        assert!(ctx2.result.as_ref().unwrap().unchanged);
    }

    /// Keep-alive agent-pool bench (regression guard for the transport's
    /// agent cache).
    ///
    /// Serves N sequential GETs from a loopback HTTP server that honours
    /// HTTP/1.1 keep-alive (reads further requests on the same socket until
    /// the client disconnects) and counts accepted TCP connections. Two client
    /// strategies are measured and printed:
    ///
    /// * **fresh agent per request** — the pre-cache transport behaviour: one
    ///   TCP connection per request, because the agent (and its pooled
    ///   socket) is dropped after every request;
    /// * **`AgentCache`-backed agent** — the current transport behaviour:
    ///   the keep-alive connection is reused, so ~1 connection serves all N
    ///   requests.
    ///
    /// The assertions are deliberately loose (fresh must open many more
    /// connections than pooled) so the test guards the reuse property without
    /// being flaky on slow/loaded CI hosts.
    #[tokio::test]
    async fn transport_agent_cache_reuses_keepalive_connections() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        const N: usize = 300;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_srv = Arc::clone(&accepted);
        let shutdown = Arc::new(AtomicUsize::new(0));
        let shutdown_srv = Arc::clone(&shutdown);
        let server = std::thread::spawn(move || {
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
            while shutdown_srv.load(Ordering::SeqCst) == 0 {
                let mut s = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => break,
                };
                accepted_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 8192];
                'conn: loop {
                    // Accumulate request bytes until the header terminator.
                    let mut head = Vec::new();
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break 'conn, // client closed → next connection
                            Ok(n) => {
                                head.extend_from_slice(&buf[..n]);
                                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if head.len() > 64 * 1024 {
                                    break 'conn;
                                }
                            }
                        }
                    }
                    if s.write_all(resp).is_err() {
                        break 'conn;
                    }
                }
            }
        });

        let url = format!("http://{addr}/keepalive-bench");

        // Phase A — pre-change behaviour: a brand-new agent per request.
        let t0 = Instant::now();
        for _ in 0..N {
            let agent = build_agent(None, 15);
            let resp = agent.get(&url).call().expect("phase A request");
            let _body = resp.into_body().read_to_string().expect("phase A body");
        }
        let fresh_elapsed = t0.elapsed();
        let fresh_conns = accepted.load(Ordering::SeqCst);

        // Phase B — post-change behaviour: pooled (cached) agent.
        let t0 = Instant::now();
        let mut cache = AgentCache::new();
        for _ in 0..N {
            let agent = cache.agent_for(None, 15);
            let resp = agent.get(&url).call().expect("phase B request");
            let _body = resp.into_body().read_to_string().expect("phase B body");
        }
        let pooled_elapsed = t0.elapsed();
        let pooled_conns = accepted.load(Ordering::SeqCst) - fresh_conns;

        eprintln!(
            "[agent-pool bench] N={N} | fresh-agent-per-request: {fresh_conns} conns in {fresh_elapsed:?} | cached-agent: {pooled_conns} conns in {pooled_elapsed:?}"
        );

        // Fresh agents must open ~one connection per request.
        assert!(
            fresh_conns >= N - 5,
            "fresh agents should open ~1 connection/request, opened {fresh_conns}"
        );
        // The cached agent must keep reusing its keep-alive connection.
        assert!(
            pooled_conns <= 4,
            "cached agent should reuse its keep-alive connection, opened {pooled_conns}"
        );
        assert!(
            pooled_conns < fresh_conns,
            "pooled ({pooled_conns}) should open fewer connections than fresh ({fresh_conns})"
        );
        // Release the cached agent(s) so their pooled keep-alive socket(s)
        // close; otherwise the server thread blocks forever waiting for the
        // next request on the still-open connection and join() hangs.
        drop(cache);
        shutdown.store(1, Ordering::SeqCst);
        let _ = server.join();
    }

    // ── B9: retry-intelligence wiring through the transport ─────────────

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            304 => "Not Modified",
            403 => "Forbidden",
            429 => "Too Many Requests",
            503 => "Service Unavailable",
            _ => "X",
        }
    }

    /// Tiny loopback HTTP server (fixture-only, never live). Each accepted
    /// connection is counted and answered with `(status, extra_headers,
    /// body)` chosen by `respond(n)` where `n` is the 1-based connection
    /// ordinal. Closes each connection after one response.
    struct MockServer {
        url: String,
        hits: Arc<std::sync::atomic::AtomicUsize>,
        shutdown: Arc<std::sync::atomic::AtomicUsize>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl MockServer {
        fn spawn(
            respond: impl Fn(u32) -> (u16, Vec<(String, String)>, String) + Send + 'static,
        ) -> Self {
            use std::io::{Read, Write};
            use std::net::TcpListener;
            use std::sync::atomic::{AtomicUsize, Ordering};

            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            listener.set_nonblocking(true).expect("nonblocking");
            // `page` counts only requests for the page path (/p). Robots.txt
            // probes from the pipeline's RobotsMiddleware are answered 404 and
            // do not advance the page ordinal nor `hits()`.
            let hits = Arc::new(AtomicUsize::new(0));
            let page = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicUsize::new(0));
            let hits_s = Arc::clone(&hits);
            let page_s = Arc::clone(&page);
            let shutdown_s = Arc::clone(&shutdown);
            let handle = std::thread::spawn(move || {
                while shutdown_s.load(Ordering::SeqCst) == 0 {
                    let mut s = match listener.accept() {
                        Ok((s, _)) => s,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                            continue;
                        }
                        Err(_) => break,
                    };
                    hits_s.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 8192];
                    let mut head = Vec::new();
                    'head: loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => {
                                head.clear();
                                break 'head;
                            }
                            Ok(m) => {
                                head.extend_from_slice(&buf[..m]);
                                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if head.len() > 64 * 1024 {
                                    head.clear();
                                    break 'head;
                                }
                            }
                        }
                    }
                    if head.is_empty() {
                        continue;
                    }
                    let is_page = head
                        .windows(7)
                        .any(|w| w == b"GET /p " || w == b"GET /p?");
                    if !is_page {
                        // robots.txt (or anything else): 404 → RobotsCache
                        // treats a missing robots as allow-all.
                        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = s.write_all(resp.as_bytes());
                        continue;
                    }
                    let n = page_s.fetch_add(1, Ordering::SeqCst) as u32 + 1;
                    let (status, extra, body) = respond(n);
                    let mut resp = format!(
                        "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        reason_phrase(status),
                        body.len()
                    );
                    for (k, v) in extra {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    resp.push_str("\r\n");
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.write_all(body.as_bytes());
                }
            });
            Self {
                url: format!("http://{addr}/p"),
                hits,
                shutdown,
                handle: Some(handle),
            }
        }

        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.shutdown.store(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn fast_retry() -> RetryConfig {
        RetryConfig {
            max_retries: 2,
            backoff: crate::browser::retry::BackoffStrategy::Fixed { interval_ms: 1 },
        }
    }

    #[test]
    fn classify_failure_pipeline_contexts() {
        // Unit coverage of the exact classifications the pipeline transport
        // feeds into its dead letters (B9) — 403/429/503 + Retry-After and
        // transport-error strings.
        let intel = RetryIntelligence::new();

        // 429 + Retry-After → soft rate limit (honor the header).
        let mut h = HashMap::new();
        h.insert("retry-after".to_string(), "30".to_string());
        assert_eq!(
            intel.classify_failure(Some(429), &h, "", ""),
            SmartFailureType::RateLimitSoft
        );
        // 429 without Retry-After → hard rate limit (IP likely banned).
        assert_eq!(
            intel.classify_failure(Some(429), &HashMap::new(), "", ""),
            SmartFailureType::RateLimitHard
        );
        // 403 + Cloudflare markers (body) → challenge, not a plain ban.
        let cf_body = "cf-browser-verification / challenge-platform / cloudflare";
        assert_eq!(
            intel.classify_failure(Some(403), &HashMap::new(), cf_body, ""),
            SmartFailureType::ChallengeCloudflare
        );
        // 403 challenge-free → proxy IP banned.
        assert_eq!(
            intel.classify_failure(Some(403), &HashMap::new(), "", ""),
            SmartFailureType::ProxyBanned
        );
        // 503: Cloudflare interstitial vs plain server error.
        assert_eq!(
            intel.classify_failure(Some(503), &HashMap::new(), "", ""),
            SmartFailureType::ServerError
        );
        let mut cf_hdr = HashMap::new();
        cf_hdr.insert("server".to_string(), "cloudflare".to_string());
        assert_eq!(
            intel.classify_failure(Some(503), &cf_hdr, "", ""),
            SmartFailureType::ChallengeCloudflare
        );
        // Transport-error strings (no response).
        assert_eq!(
            intel.classify_failure(None, &HashMap::new(), "", "tls handshake failed"),
            SmartFailureType::TlsHandshakeFail
        );
        assert_eq!(
            intel.classify_failure(None, &HashMap::new(), "", "connection reset by peer"),
            SmartFailureType::ConnectionReset
        );
        assert_eq!(
            intel.classify_failure(None, &HashMap::new(), "", "operation timed out"),
            SmartFailureType::Timeout
        );
    }

    #[tokio::test]
    async fn transport_429_exhaustion_dead_letters_and_learns() {
        // The governed retry loop retries 429s with backoff; when it exhausts,
        // the *final* failure must be classified (RateLimitSoft), dead-lettered
        // and learned into the domain pattern.
        let server = MockServer::spawn(|_| {
            (
                429,
                vec![
                    ("Retry-After".to_string(), "0".to_string()),
                    ("Server".to_string(), "nginx".to_string()),
                ],
                "slow down".to_string(),
            )
        });
        let mut pipeline = CrawlPipelineBuilder::new()
            .with_retry(fast_retry())
            .build();
        let err = pipeline.fetch(&server.url, None).await.unwrap_err();
        assert!(
            matches!(err, BrowserError::RateLimitExceeded(_)),
            "soft-block 429 must surface as RateLimitExceeded, got {err:?}"
        );
        assert_eq!(pipeline.dlq_stats().total_count, 1, "one DLQ entry per exhausted fetch");
        let entries = pipeline.dlq().list(10, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].last_http_status, Some(429));
        assert!(
            entries[0].final_error.contains("RateLimitSoft"),
            "dead letter must carry the smart classification, got {}",
            entries[0].final_error
        );
        let intel = pipeline.intelligence();
        let domain = PipelineContext::new(&server.url).domain;
        let dp = intel.domain_pattern(&domain).expect("domain pattern learned");
        assert_eq!(dp.failure_by_category.get("RateLimitSoft"), Some(&1));
        assert_eq!(dp.consecutive_failures, 1);
        assert!(dp.total_attempts >= 1);
    }

    #[tokio::test]
    async fn transport_403_challenge_classified_cloudflare() {
        let server = MockServer::spawn(|_| {
            (
                403,
                vec![("Server".to_string(), "cloudflare".to_string())],
                "<html>cf-browser-verification challenge-platform</html>".to_string(),
            )
        });
        let mut pipeline = CrawlPipelineBuilder::new()
            .with_retry(fast_retry())
            .build();
        let _err = pipeline.fetch(&server.url, None).await.unwrap_err();
        let entries = pipeline.dlq().list(10, None);
        assert!(!entries.is_empty());
        assert!(
            entries[0].final_error.contains("ChallengeCloudflare"),
            "403 + CF markers must classify as ChallengeCloudflare, got {}",
            entries[0].final_error
        );
    }

    #[tokio::test]
    async fn transport_200_records_success_into_intelligence() {
        // Successes are recorded too, so the learner's success/attempt ratios
        // stay real (mirror of learn_from_dlq).
        let server = MockServer::spawn(|_| (200, vec![], "hello world".repeat(200)));
        let mut pipeline = CrawlPipelineBuilder::new().build();
        let r = pipeline.fetch(&server.url, None).await.unwrap();
        assert_eq!(r.status, 200);
        assert!(!r.unchanged);
        assert_eq!(pipeline.dlq_stats().total_count, 0, "success must not dead-letter");
        let intel = pipeline.intelligence();
        let domain = PipelineContext::new(&server.url).domain;
        let dp = intel.domain_pattern(&domain).expect("domain pattern recorded");
        assert_eq!(dp.total_successes, 1);
        assert_eq!(dp.total_attempts, 1);
        assert_eq!(dp.success_rate(), 1.0);
    }

    // ── B10: delta-crawl consumer in the fetch path ─────────────────────

    fn stable_body_v1() -> String {
        "<html><body>stable page content version one</body></html>".repeat(40)
    }

    #[tokio::test]
    async fn delta_skips_url_with_stored_hash_and_validator() {
        // Builder-delta tests read TALLOW_DELTA_QUEUE/TALLOW_DELTA_STATS if
        // set; delta_persists_checkpoint_across_pipeline_runs sets them, so
        // serialize every env-visible delta test (Rust env is process-global).
        let _guard = crate::runtime::egress_http::env_lock();
        // Stored content hash + ETag validator ⇒ DeltaNeed::Skip: the second
        // fetch in a delta run must NOT hit the transport, and the caller
        // receives an `unchanged` result (empty body) it can skip extracting.
        let server = MockServer::spawn(|_| {
            (
                200,
                vec![("ETag".to_string(), "w/\"v1\"".to_string())],
                stable_body_v1(),
            )
        });
        let mut pipeline = CrawlPipelineBuilder::new()
            .with_content_cache(true)
            .with_delta_crawl(true)
            .build();

        // First fetch: nothing cached → full fetch, recorded (first-seen).
        let r1 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(!r1.unchanged);
        assert_eq!(pipeline.delta_stats().fetched_changed, 1);
        let hits_after_first = server.hits();

        // Second fetch: stored hash + validator → skip, no transport.
        pipeline.reset_delta_stats();
        let r2 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(r2.unchanged, "delta run must skip already-fetched-unchanged URL");
        assert!(r2.body.is_empty(), "skipped URL yields no body (caller skips extraction)");
        assert_eq!(
            server.hits(),
            hits_after_first,
            "skipped URL must not reach the transport"
        );
        let stats = pipeline.delta_stats();
        assert_eq!(stats.skipped_cached, 1);
        assert_eq!(stats.attempted, 0);
        assert!(pipeline.delta_stats().summary().contains("delta run"));
    }

    #[tokio::test]
    async fn delta_unchanged_hash_skip_is_gated_off_without_delta_mode() {
        // Serialized with the other env-visible delta tests (process-global env).
        let _guard = crate::runtime::egress_http::env_lock();
        // Backward compatibility: the same second fetch with delta mode OFF
        // (no env, no builder flag) re-fetches — only the *pre-fetch skip* is
        // gated on delta mode; hash-compare marking still applies.
        let server = MockServer::spawn(|_| {
            (
                200,
                vec![("ETag".to_string(), "w/\"v1\"".to_string())],
                stable_body_v1(),
            )
        });
        let mut pipeline = CrawlPipelineBuilder::new()
            .with_content_cache(true)
            .build();
        let r1 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(!r1.unchanged);
        let hits_after_first = server.hits();
        let r2 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(
            !r2.body.is_empty(),
            "non-delta run must actually fetch a body (no skip)"
        );
        assert_eq!(server.hits(), hits_after_first + 1, "re-fetch happened");
        let stats = pipeline.delta_stats();
        assert_eq!(stats.skipped_cached, 0, "skip is gated off without delta mode");
        assert_eq!(stats.attempted, 2);
        assert_eq!(stats.fetched_unchanged, 1, "identical body hash still detected");
        assert!(r2.unchanged);
    }

    #[tokio::test]
    async fn delta_revalidates_when_no_validator_and_marks_change() {
        // Serialized with the other env-visible delta tests (process-global env).
        let _guard = crate::runtime::egress_http::env_lock();
        // Stored hash but no validator ⇒ DeltaNeed::Conditional: the delta run
        // must re-fetch; a changed body is surfaced (unchanged=false) and the
        // new hash + validator are recorded, after which the URL is skippable.
        let server = MockServer::spawn(|n| {
            if n == 1 {
                // First crawl: body v1, no ETag → recorded without validator.
                (200, vec![], stable_body_v1())
            } else {
                // Re-crawl: body v2 (changed) + ETag now present.
                (
                    200,
                    vec![("ETag".to_string(), "w/\"v2\"".to_string())],
                    "<html><body>stable page content version two</body></html>".repeat(40),
                )
            }
        });
        let mut pipeline = CrawlPipelineBuilder::new()
            .with_content_cache(true)
            .with_delta_crawl(true)
            .build();

        let r1 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(!r1.unchanged);

        pipeline.reset_delta_stats();
        let r2 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(!r2.unchanged, "changed body must surface as changed");
        let stats = pipeline.delta_stats();
        assert_eq!(stats.fetched_changed, 1);
        let hits_after_r2 = server.hits();

        // Third fetch: v2 hash + ETag recorded → now skippable.
        pipeline.reset_delta_stats();
        let r3 = pipeline.fetch(&server.url, None).await.unwrap();
        assert!(r3.unchanged);
        assert_eq!(server.hits(), hits_after_r2, "third fetch must be skipped");
        assert_eq!(pipeline.delta_stats().skipped_cached, 1);
    }

    // T-128: env-backed tests serialize on the one process-global env lock.

    #[tokio::test]
    async fn delta_persists_checkpoint_across_pipeline_runs() {
        // The scheduler hands a delta job's subprocess TALLOW_DELTA_QUEUE /
        // TALLOW_DELTA_STATS. A second pipeline (next scheduled run) must
        // load the checkpoint and skip URLs unchanged since the first run.
        let _guard = crate::runtime::egress_http::env_lock();
        let dir = std::env::temp_dir().join(format!(
            "tallow-delta-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let queue_path = dir.join("delta-cache.json");
        let stats_path = dir.join("delta-run-stats.json");
        // Rust 2024: env mutation is unsafe — used only in this serialized test.
        unsafe {
            std::env::set_var("TALLOW_DELTA_QUEUE", &queue_path);
            std::env::set_var("TALLOW_DELTA_STATS", &stats_path);
        }

        let server = MockServer::spawn(|_| {
            (
                200,
                vec![("ETag".to_string(), "w/\"v1\"".to_string())],
                stable_body_v1(),
            )
        });

        // "Run 1": fetch records hash + ETag and persists the checkpoint.
        {
            let mut p1 = CrawlPipelineBuilder::new()
                .with_delta_crawl(true)
                .build();
            let r = p1.fetch(&server.url, None).await.unwrap();
            assert!(!r.unchanged);
        }
        assert!(queue_path.exists(), "checkpoint must be persisted for the next run");
        assert!(stats_path.exists(), "per-run delta stats must be persisted");
        let hits_after_run1 = server.hits();

        // "Run 2": a fresh pipeline (fresh in-memory queue) loads the
        // checkpoint and skips the unchanged URL — no new transport hit.
        {
            let mut p2 = CrawlPipelineBuilder::new()
                .with_delta_crawl(true)
                .build();
            let r = p2.fetch(&server.url, None).await.unwrap();
            assert!(r.unchanged, "second scheduled run must skip the unchanged URL");
            assert_eq!(server.hits(), hits_after_run1, "no re-fetch across runs");
            let stats = p2.delta_stats();
            assert_eq!(stats.skipped_cached, 1);
        }

        unsafe {
            std::env::remove_var("TALLOW_DELTA_QUEUE");
            std::env::remove_var("TALLOW_DELTA_STATS");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
