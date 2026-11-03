//! Bounded-concurrency range fetching.
//!
//! [`fetch_plan`] turns a [`ShardPlan`] into `min(streams, shards)` worker
//! threads that pull shard indices from a shared counter. Distribution is
//! dynamic on purpose: a worker that draws a slow shard never idles the queue,
//! because the next free worker takes the next index.
//!
//! A shard only counts when it delivers exactly the bytes it asked for; each
//! shard is retried with exponential backoff, and one shard failing never cuts
//! another shard's transfer short — the plan finishes or fails as a unit.

use crate::plan::ShardPlan;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Concurrency and retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Maximum concurrent range requests.
    pub streams: u32,
    /// Retries per shard before the transfer fails.
    pub retries: u32,
    /// Base backoff between retries, milliseconds (doubled each attempt).
    pub backoff_ms: u64,
    /// Per-request timeout, seconds.
    pub timeout_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            streams: 8,
            retries: 3,
            backoff_ms: 250,
            timeout_secs: 30,
        }
    }
}

/// Outcome for one shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStat {
    /// Shard index.
    pub index: u32,
    /// Bytes received.
    pub bytes: u64,
    /// Attempts used, including the first.
    pub attempts: u32,
    /// Wall time for this shard, milliseconds.
    pub elapsed_ms: u64,
}

/// Whole-transfer outcome.
#[derive(Debug, Clone)]
pub struct PoolReport {
    /// Total bytes received.
    pub total_bytes: u64,
    /// Wall time, milliseconds.
    pub elapsed_ms: u64,
    /// Per-shard stats, ascending by index.
    pub per_shard: Vec<ShardStat>,
    /// Reassembled payload, in order.
    pub data: Vec<u8>,
}

/// Fetch failure.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Transport or protocol error from the fetcher.
    #[error("fetch failed: {0}")]
    Transport(String),
    /// Server returned fewer bytes than the range asked for.
    #[error("short read on shard {index}: expected {expected}, got {got}")]
    ShortRead {
        /// Shard index.
        index: u32,
        /// Bytes requested.
        expected: u64,
        /// Bytes received.
        got: u64,
    },
    /// Retries exhausted.
    #[error("shard {index} failed after {attempts} attempts: {last}")]
    Exhausted {
        /// Shard index.
        index: u32,
        /// Attempts made.
        attempts: u32,
        /// Last error text.
        last: String,
    },
    /// A worker thread panicked.
    #[error("worker panicked")]
    WorkerPanic,
}

/// Anything that can produce an exact byte range.
pub trait Fetcher: Sync {
    /// Return exactly `end - start` bytes beginning at `start`.
    fn fetch_range(&self, start: u64, end: u64) -> Result<Vec<u8>, FetchError>;
}

/// HTTP(S) range fetcher over one URL.
#[derive(Debug)]
pub struct HttpRangeFetcher {
    /// Source URL.
    pub url: String,
}

impl HttpRangeFetcher {
    /// Build a fetcher for `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// One shared client for every fetcher in the process.
///
/// `reqwest::blocking::Client` owns a connection pool and a background runtime,
/// so building one per request would throw away both. `Client` is `Sync` and
/// cheap to borrow, which is what the worker threads need.
static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

/// Deadline used when no caller has published one, mirroring
/// [`PoolConfig::default`].
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// User-Agent sent on every range request.
const USER_AGENT: &str = concat!("tallow-egress/", env!("CARGO_PKG_VERSION"));

/// Upper bound on a single backoff sleep, milliseconds.
const MAX_BACKOFF_MS: u64 = 4_000;

thread_local! {
    /// `Fetcher::fetch_range` takes no configuration, so a fetcher has no way to
    /// learn `PoolConfig::timeout_secs`. `fetch_plan` publishes the deadline on
    /// the worker thread immediately before each attempt and implementations
    /// that can enforce it (like [`HttpRangeFetcher`]) read it here.
    static REQUEST_TIMEOUT: Cell<Option<Duration>> = Cell::new(None);
}

fn client() -> Result<&'static reqwest::blocking::Client, FetchError> {
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let built = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| FetchError::Transport(format!("could not build the HTTP client: {err}")))?;
    Ok(CLIENT.get_or_init(|| built))
}

impl Fetcher for HttpRangeFetcher {
    fn fetch_range(&self, start: u64, end: u64) -> Result<Vec<u8>, FetchError> {
        if end <= start {
            return Ok(Vec::new());
        }
        let want = end - start;
        let last = end - 1;
        let url = &self.url;
        let client = client()?;
        let timeout = REQUEST_TIMEOUT
            .with(|slot| slot.get())
            .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let response = client
            .get(url)
            .header(reqwest::header::RANGE, format!("bytes={start}-{last}"))
            // Critical: a transparent gzip would decouple body offsets from file
            // offsets, so every range after the first would be stitched together
            // from the wrong bytes.
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            // Some origins answer an empty User-Agent with 403 (measured against
            // ipv4.download.thinkbroadband.com, 2026-11-03), so identify ourselves
            // rather than inheriting reqwest's bare default.
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .timeout(timeout)
            .send()
            .map_err(|err| {
                FetchError::Transport(format!("GET {url} bytes={start}-{last}: {err}"))
            })?;

        let status = response.status();
        if status != reqwest::StatusCode::PARTIAL_CONTENT && status != reqwest::StatusCode::OK {
            return Err(FetchError::Transport(format!(
                "GET {url} bytes={start}-{last}: unexpected status {status}"
            )));
        }

        let body = response.bytes().map_err(|err| {
            FetchError::Transport(format!("GET {url} bytes={start}-{last}: body: {err}"))
        })?;

        if body.len() as u64 != want {
            // A fetcher is handed byte offsets, not a shard index, so the pool
            // stamps the real index onto this when it surfaces the error.
            return Err(FetchError::ShortRead {
                index: 0,
                expected: want,
                got: body.len() as u64,
            });
        }

        Ok(body.to_vec())
    }
}

/// Bytes received for one shard, kept alongside the payload so reassembly can
/// order the pieces without copying twice.
struct ShardOutcome {
    index: u32,
    bytes: Vec<u8>,
    stat: ShardStat,
}

/// A fetcher never learns which shard it is serving, so any short read it
/// reports carries a placeholder index; replace it with the real one.
fn stamp_index(err: FetchError, index: u32) -> FetchError {
    match err {
        FetchError::ShortRead { expected, got, .. } => FetchError::ShortRead {
            index,
            expected,
            got,
        },
        other => other,
    }
}

/// Delay before retry number `attempt` (1-based), `backoff_ms` doubled each
/// time and capped at [`MAX_BACKOFF_MS`].
fn backoff_delay(backoff_ms: u64, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    let scaled = backoff_ms.saturating_mul(1u64 << shift);
    Duration::from_millis(scaled.min(MAX_BACKOFF_MS))
}

/// Fetch one shard, retrying transient failures.
fn fetch_shard(
    shard: &crate::plan::Shard,
    fetcher: &dyn Fetcher,
    config: &PoolConfig,
) -> Result<ShardOutcome, FetchError> {
    let started = Instant::now();
    let expected = shard.len();
    let max_attempts = config.retries.saturating_add(1);
    let deadline = Duration::from_secs(config.timeout_secs);
    let mut last: Option<FetchError> = None;

    for attempt in 1..=max_attempts {
        REQUEST_TIMEOUT.with(|slot| slot.set(Some(deadline)));

        let failure = match fetcher.fetch_range(shard.start, shard.end) {
            Ok(bytes) if bytes.len() as u64 == expected => {
                return Ok(ShardOutcome {
                    index: shard.index,
                    stat: ShardStat {
                        index: shard.index,
                        bytes: bytes.len() as u64,
                        attempts: attempt,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    },
                    bytes,
                });
            }
            Ok(bytes) => FetchError::ShortRead {
                index: shard.index,
                expected,
                got: bytes.len() as u64,
            },
            Err(err) => stamp_index(err, shard.index),
        };

        last = Some(failure);
        if attempt < max_attempts {
            thread::sleep(backoff_delay(config.backoff_ms, attempt));
        }
    }

    // A truncated body is a precise diagnosis ("expected N, got M") and stays
    // useful after retries; everything else collapses into the attempt count.
    match last {
        Some(err @ FetchError::ShortRead { .. }) => Err(err),
        Some(err) => Err(FetchError::Exhausted {
            index: shard.index,
            attempts: max_attempts,
            last: err.to_string(),
        }),
        None => Err(FetchError::Exhausted {
            index: shard.index,
            attempts: 0,
            last: "no attempt was made".to_string(),
        }),
    }
}

/// Fetch every shard in `plan` with at most `config.streams` in flight.
pub fn fetch_plan(
    plan: &ShardPlan,
    fetcher: &dyn Fetcher,
    config: &PoolConfig,
) -> Result<PoolReport, FetchError> {
    let started = Instant::now();
    let shards = &plan.shards;

    if shards.is_empty() {
        return Ok(PoolReport {
            total_bytes: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
            per_shard: Vec::new(),
            data: Vec::new(),
        });
    }

    let workers = (config.streams.max(1) as usize).min(shards.len());
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<(u32, Result<ShardOutcome, FetchError>)>();

    let mut outcomes: Vec<ShardOutcome> = Vec::with_capacity(shards.len());
    let mut failures: Vec<(u32, FetchError)> = Vec::new();

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let tx = tx.clone();
            let next = &next;
            let spawned = thread::Builder::new()
                .name(format!("egress-stream-{worker}"))
                .spawn_scoped(scope, move || {
                    loop {
                        let slot = next.fetch_add(1, Ordering::AcqRel);
                        let Some(shard) = shards.get(slot) else {
                            break;
                        };
                        // A panicking fetcher must fail the transfer, not kill the
                        // process or poison the remaining shards.
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            fetch_shard(shard, fetcher, config)
                        }))
                        .unwrap_or(Err(FetchError::WorkerPanic));
                        if tx.send((shard.index, result)).is_err() {
                            break;
                        }
                    }
                });
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(err) => failures.push((
                    u32::MAX,
                    FetchError::Transport(format!("could not spawn a worker thread: {err}")),
                )),
            }
        }
        // Only the workers keep the channel open now, so draining it is a join.
        drop(tx);
        for message in rx {
            match message {
                (_, Ok(outcome)) => outcomes.push(outcome),
                (index, Err(err)) => failures.push((index, err)),
            }
        }
        for handle in handles {
            if handle.join().is_err() {
                failures.push((u32::MAX, FetchError::WorkerPanic));
            }
        }
    });

    if let Some((_, err)) = failures.into_iter().min_by_key(|(index, _)| *index) {
        return Err(err);
    }

    outcomes.sort_by_key(|outcome| outcome.index);

    let mut data = Vec::with_capacity(plan.total_len as usize);
    for outcome in &outcomes {
        data.extend_from_slice(&outcome.bytes);
    }
    let per_shard: Vec<ShardStat> = outcomes.into_iter().map(|outcome| outcome.stat).collect();
    let total_bytes = data.len() as u64;

    if total_bytes != plan.total_len {
        return Err(FetchError::Transport(format!(
            "reassembled {total_bytes} bytes but the plan covers {}",
            plan.total_len
        )));
    }

    Ok(PoolReport {
        total_bytes,
        elapsed_ms: started.elapsed().as_millis() as u64,
        per_shard,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::plan_shards;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::time::Duration;

    /// Length of the mock server's virtual body.
    const PATTERN_LEN: u64 = 40_000;

    /// Deterministic, non-repeating-within-a-shard byte pattern. A stitched
    /// reassembly that is off by one byte will not match it.
    fn pattern_byte(offset: u64) -> u8 {
        ((offset * 31 + 7) % 251) as u8
    }

    fn pattern_range(start: u64, end: u64) -> Vec<u8> {
        (start..end).map(pattern_byte).collect()
    }

    /// Knobs the tests turn.
    #[derive(Clone, Default)]
    struct ServerCfg {
        /// Sleep before answering, milliseconds.
        delay_ms: u64,
        /// Answer with `short_by` fewer bytes than requested.
        short_by: u64,
        /// Answer the first N requests with a 500.
        fail_first: usize,
        /// Delay the early byte offsets more than the late ones, so shards
        /// complete in reverse index order.
        stagger: bool,
    }

    fn parse_range(head: &[u8]) -> Option<(u64, u64)> {
        let text = String::from_utf8_lossy(head);
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("range:") {
                let spec = rest.trim().strip_prefix("bytes=")?;
                let (start, end) = spec.split_once('-')?;
                let start: u64 = start.trim().parse().ok()?;
                let end: u64 = end.trim().parse().ok()?;
                return Some((start, end + 1));
            }
        }
        None
    }

    fn handle_conn(
        mut stream: TcpStream,
        cfg: &ServerCfg,
        hits: &Arc<AtomicUsize>,
    ) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut head = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Ok(());
            }
            head.extend_from_slice(&buf[..read]);
            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if head.len() > 32 * 1024 {
                break;
            }
        }

        let hit = hits.fetch_add(1, Ordering::SeqCst) + 1;
        if hit <= cfg.fail_first {
            if cfg.delay_ms > 0 {
                thread::sleep(Duration::from_millis(cfg.delay_ms));
            }
            let body = b"server error";
            write!(
                stream,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(body)?;
            stream.flush()?;
            return Ok(());
        }

        let (start, end) = parse_range(&head).unwrap_or((0, PATTERN_LEN));
        let end = end.min(PATTERN_LEN).max(start);
        let want = end - start;

        let mut delay = cfg.delay_ms;
        if cfg.stagger {
            delay += (PATTERN_LEN - start.min(PATTERN_LEN)) / 200;
        }
        if delay > 0 {
            thread::sleep(Duration::from_millis(delay));
        }

        let kept = want.saturating_sub(cfg.short_by);
        let body = pattern_range(start, start + kept);
        let header = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            start,
            end.saturating_sub(1),
            PATTERN_LEN,
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;
        Ok(())
    }

    /// A loopback range server. One thread per connection, so concurrent
    /// requests really are concurrent.
    struct MockServer {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        accept: Option<thread::JoinHandle<()>>,
    }

    impl MockServer {
        fn start(cfg: ServerCfg) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let addr = listener.local_addr().expect("local addr");
            let hits = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));

            let accept_hits = Arc::clone(&hits);
            let accept_stop = Arc::clone(&stop);
            let accept = thread::spawn(move || {
                while !accept_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let hits = Arc::clone(&accept_hits);
                            let cfg = cfg.clone();
                            thread::spawn(move || {
                                let _ = handle_conn(stream, &cfg, &hits);
                            });
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                addr,
                hits,
                stop,
                accept: Some(accept),
            }
        }

        fn url(&self) -> String {
            format!("http://{}/blob", self.addr)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(accept) = self.accept.take() {
                let _ = accept.join();
            }
        }
    }

    fn config(streams: u32, retries: u32, backoff_ms: u64) -> PoolConfig {
        PoolConfig {
            streams,
            retries,
            backoff_ms,
            timeout_secs: 10,
        }
    }

    #[test]
    fn eight_streams_beat_one_stream() {
        let server = MockServer::start(ServerCfg {
            delay_ms: 100,
            ..ServerCfg::default()
        });
        let fetcher = HttpRangeFetcher::new(server.url());

        // Same eight shards, one worker versus eight: the only difference is
        // how many requests are in flight at once.
        let plan = plan_shards(PATTERN_LEN, 8, 1).expect("plan");
        assert_eq!(plan.shards.len(), 8);

        let serial = fetch_plan(&plan, &fetcher, &config(1, 0, 1)).expect("1 stream");
        let parallel = fetch_plan(&plan, &fetcher, &config(8, 0, 1)).expect("8 streams");

        assert_eq!(serial.data.len() as u64, PATTERN_LEN);
        assert_eq!(parallel.data.len() as u64, PATTERN_LEN);
        assert!(
            parallel.elapsed_ms * 2 < serial.elapsed_ms,
            "8 streams took {}ms, 1 stream took {}ms",
            parallel.elapsed_ms,
            serial.elapsed_ms
        );
    }

    #[test]
    fn reassembles_bytes_exactly_in_shard_order() {
        // Staggered delays make the high index shards finish first, so a
        // reassembly that trusted completion order would be visibly wrong.
        let server = MockServer::start(ServerCfg {
            stagger: true,
            ..ServerCfg::default()
        });
        let plan = plan_shards(PATTERN_LEN, 8, 1).expect("plan");
        let report = fetch_plan(
            &plan,
            &HttpRangeFetcher::new(server.url()),
            &config(8, 0, 1),
        )
        .expect("fetch");

        assert_eq!(report.data, pattern_range(0, PATTERN_LEN));
        assert_eq!(report.total_bytes, PATTERN_LEN);
        assert_eq!(report.data.len() as u64, plan.total_len);
        let indices: Vec<u32> = report.per_shard.iter().map(|stat| stat.index).collect();
        assert_eq!(indices, (0..8).collect::<Vec<u32>>());
        for stat in &report.per_shard {
            let shard = &plan.shards[stat.index as usize];
            assert_eq!(stat.bytes, shard.len());
            assert_eq!(stat.attempts, 1);
        }
    }

    #[test]
    fn short_read_from_server_surfaces_short_read() {
        let server = MockServer::start(ServerCfg {
            short_by: 100,
            ..ServerCfg::default()
        });
        let plan = plan_shards(PATTERN_LEN, 4, 1).expect("plan");
        let err = fetch_plan(
            &plan,
            &HttpRangeFetcher::new(server.url()),
            &config(4, 0, 1),
        )
        .expect_err("a truncated body must fail the transfer");

        match err {
            FetchError::ShortRead {
                index,
                expected,
                got,
            } => {
                assert_eq!(expected, 10_000);
                assert_eq!(got, 9_900);
                assert!(index < 4, "index {index} is not a planned shard");
            }
            other => panic!("expected ShortRead, got {other:?}"),
        }
    }

    #[test]
    fn retries_fail_then_succeed_and_count_requests() {
        let server = MockServer::start(ServerCfg {
            fail_first: 2,
            ..ServerCfg::default()
        });
        let plan = plan_shards(PATTERN_LEN, 1, 1).expect("plan");
        let report = fetch_plan(
            &plan,
            &HttpRangeFetcher::new(server.url()),
            &config(1, 3, 5),
        )
        .expect("two 500s then a 206 must still succeed");

        assert_eq!(server.hits(), 3, "expected two failures then one success");
        assert_eq!(report.per_shard.len(), 1);
        assert_eq!(report.per_shard[0].attempts, 3);
        assert_eq!(report.data, pattern_range(0, PATTERN_LEN));
    }

    #[test]
    fn exhausted_after_retries_reports_attempt_count() {
        let server = MockServer::start(ServerCfg {
            fail_first: 10,
            ..ServerCfg::default()
        });
        let plan = plan_shards(PATTERN_LEN, 1, 1).expect("plan");
        let err = fetch_plan(
            &plan,
            &HttpRangeFetcher::new(server.url()),
            &config(1, 2, 5),
        )
        .expect_err("an always-500 server must fail the transfer");

        match err {
            FetchError::Exhausted {
                index,
                attempts,
                last,
            } => {
                assert_eq!(index, 0);
                assert_eq!(attempts, 3);
                assert!(last.contains("500"), "unexpected last error: {last}");
            }
            other => panic!("expected Exhausted, got {other:?}"),
        }
        assert_eq!(server.hits(), 3);
    }

    struct PanicFetcher;

    impl Fetcher for PanicFetcher {
        fn fetch_range(&self, _start: u64, _end: u64) -> Result<Vec<u8>, FetchError> {
            panic!("fetcher exploded");
        }
    }

    #[test]
    fn panicking_fetcher_surfaces_worker_panic() {
        let plan = plan_shards(64, 1, 1).expect("plan");
        let err = fetch_plan(&plan, &PanicFetcher, &config(1, 0, 1))
            .expect_err("a panicking fetcher must fail the transfer");
        assert!(matches!(err, FetchError::WorkerPanic), "got {err:?}");
    }
}
