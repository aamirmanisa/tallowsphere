//! Criterion benches for the wave-3 A10 browser-reliability surfaces:
//!
//! - `pool/*` — browser-pool **admin path via the public API only**
//!   (pool.rs is sibling-owned and read-only). `acquire`/`release` launch and
//!   health-check real Chrome instances via CDP, which is outside the
//!   fixture-only bench boundary, so this benches the bookkeeping that guards
//!   them: construction (lazy — no browser launched), accessors, stats
//!   snapshot, `autoscale` decision when scaling is disabled, and the
//!   `scale_up`/`scale_down` target math (these only resize the slot vector +
//!   semaphore; actual browser launch happens later in `acquire`).
//! - `retry_intelligence/classify_failure` — pure classification over a
//!   realistic 403/429/503/Retry-After/transport-error corpus.
//! - `crawl_pipeline/middleware-dispatch` — the ordered `before`/`after`
//!   interceptor loop that `CrawlPipeline::fetch` runs per request, driven
//!   over the public `Middleware` surface with a fixture context (no I/O).
//! - `delta/*` — the per-URL delta planning decision and body hashing that a
//!   scheduled delta run performs per fetch.
//!
//! Run: `cargo bench --bench reliability_bench` (also wired into
//! `benches/run_benchmarks.sh`).

use criterion::{black_box, Criterion};
use std::collections::HashMap;

use tallow::browser::adaptive_crawler::{CrawlResult, CrawlSource};
use tallow::browser::crawl_pipeline::{
    HeaderMiddleware, HttpCacheMiddleware, Middleware, PipelineContext, ProxySelectorMiddleware,
};
use tallow::browser::pool::{system_headroom, BrowserPool, LoadSignal, PoolConfig, ScalingPolicy};
use tallow::browser::retry_intelligence::{RetryIntelligence, SmartFailureType};
use tallow::browser::scheduler::{content_hash_of, plan_incremental_crawl, CachedUrl};

fn bench_classify(c: &mut Criterion) {
    let intel = RetryIntelligence::new();
    let mut cf = HashMap::new();
    cf.insert("server".to_string(), "cloudflare".to_string());
    let mut dd = HashMap::new();
    dd.insert("x-datadome".to_string(), "block".to_string());
    let corpus: Vec<(Option<u16>, HashMap<String, String>, &str, &str)> = vec![
        (Some(429), cf.clone(), "", ""),                       // RateLimitSoft
        (Some(429), HashMap::new(), "", ""),                   // RateLimitHard
        (Some(403), cf.clone(), "cf-browser-verification / turnstile", ""), // ChallengeCloudflare
        (Some(403), HashMap::new(), "", ""),                   // ProxyBanned
        (Some(503), HashMap::new(), "cloudflare checking your browser", ""),
        (Some(200), dd.clone(), "", ""),                       // ChallengeDataDome (header)
        (None, HashMap::new(), "", "tls handshake failed"),
        (None, HashMap::new(), "", "http2 protocol error"),
        (None, HashMap::new(), "", "dns resolve failed"),
        (None, HashMap::new(), "", "connection reset by peer"),
        (None, HashMap::new(), "", "operation timed out"),
        (None, HashMap::new(), "", "socks5 proxy connection refused"),
    ];
    c.bench_function("retry_intelligence/classify_failure", |b| {
        b.iter(|| {
            let mut unknowns = 0usize;
            for (status, headers, body, err) in &corpus {
                let t = intel.classify_failure(*status, headers, body, err);
                unknowns += usize::from(t == SmartFailureType::Unknown);
            }
            black_box(unknowns)
        })
    });
}

fn bench_delta_planning(c: &mut Criterion) {
    let entry = CachedUrl {
        url: "https://example.com/page?n=1".to_string(),
        etag: Some("\"v9\"".to_string()),
        last_modified: Some("Tue, 01 Sep 2026 12:00:00 GMT".to_string()),
        content_hash: Some(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
        ),
        fetched_at_epoch: Some(1_752_000_000),
    };
    c.bench_function("delta/plan_single_url", |b| {
        b.iter(|| {
            let plan = plan_incremental_crawl(std::slice::from_ref(&entry));
            black_box((plan.unchanged_count(), plan.re_crawl_count()))
        })
    });
    c.bench_function("delta/content_hash_of_64kb", |b| {
        let body = "x".repeat(65536);
        b.iter(|| black_box(content_hash_of(&body)))
    });
}

fn bench_pipeline_dispatch(c: &mut Criterion) {
    // The ordered interceptor chain CrawlPipeline::fetch runs per request.
    // Robots/rate-limit stages are excluded: they do network / timed work,
    // not pure dispatch.
    let mut chain: Vec<Box<dyn Middleware>> = vec![
        Box::new(ProxySelectorMiddleware::new(None)),
        Box::new(HeaderMiddleware::new(
            "bench-UA",
            vec![("Accept-Language".to_string(), "en-US,en;q=0.9".to_string())],
        )),
        Box::new(HttpCacheMiddleware::new(true).with_delta(true)),
    ];
    c.bench_function("crawl_pipeline/middleware-dispatch", |b| {
        b.iter(|| {
            let mut ctx = PipelineContext::new("https://example.com/bench?q=1");
            for m in chain.iter_mut() {
                m.before(&mut ctx).unwrap();
                if ctx.stop {
                    break;
                }
            }
            if !ctx.stop && ctx.result.is_none() {
                // Simulate a transport result so after-hooks have work to do
                // (mirrors fetch(): transport Ok path).
                ctx.result = Some(CrawlResult {
                    url: ctx.url.clone(),
                    body: "x".repeat(2048),
                    status: 200,
                    source: CrawlSource::Http,
                    content_type: None,
                    unchanged: false,
                });
            }
            for m in chain.iter_mut() {
                m.after(&mut ctx).unwrap();
            }
            black_box((ctx.unchanged, ctx.result.is_some(), ctx.conditional.len()))
        })
    });
}

fn bench_pool(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime for async pool API");

    let mut g = c.benchmark_group("pool");
    g.bench_function("construct_accessors_snapshot", |b| {
        b.iter(|| {
            let cfg = PoolConfig {
                max_size: 8,
                ..Default::default()
            };
            let pool = rt.block_on(BrowserPool::new(cfg)).expect("pool constructs lazily");
            black_box((
                pool.target_size(),
                pool.hard_cap(),
                pool.autoscale_max(),
                pool.min_size(),
                pool.is_scaling_enabled(),
                pool.stats(),
            ))
        })
    });
    g.bench_function("autoscale_decision_disabled", |b| {
        b.iter(|| {
            let cfg = PoolConfig {
                max_size: 4,
                ..Default::default()
            };
            let pool = rt.block_on(BrowserPool::new(cfg)).expect("pool");
            let load = LoadSignal {
                queue_depth: 20,
                in_flight: 4,
                cpu_headroom: 0.9,
                mem_headroom: 0.9,
            };
            black_box(rt.block_on(pool.autoscale(load)))
        })
    });
    g.bench_function("scale_up_down_target_math", |b| {
        b.iter(|| {
            let cfg = PoolConfig {
                max_size: 2,
                ..Default::default()
            };
            let pool = rt
                .block_on(BrowserPool::new(cfg))
                .expect("pool")
                .with_scaling(ScalingPolicy {
                    enabled: true,
                    min_size: 1,
                    autoscale_max: 32,
                    hard_cap: 32,
                    increase_step: 2,
                    decrease_factor: 0.5,
                    ..Default::default()
                });
            let up = rt.block_on(pool.scale_up(2));
            let down = rt.block_on(pool.scale_down(0.5));
            black_box((up, down))
        })
    });
    g.bench_function("system_headroom", |b| b.iter(|| black_box(system_headroom())));
    g.finish();
}

fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench_classify(&mut c);
    bench_delta_planning(&mut c);
    bench_pipeline_dispatch(&mut c);
    bench_pool(&mut c);
    c.final_summary();
}
