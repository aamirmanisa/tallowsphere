//! Fan-out across egress nodes.
//!
//! [`ProxiedFetcher`] is the [`Fetcher`] that makes a [`NodePool`] mean
//! something: every range request leases one node, leaves through that node's
//! exit, and returns the lease before the next request can take it. The pool's
//! leaser already prefers the least-loaded node, so N concurrent shards end up
//! spread over the exits without this module choosing nodes itself.
//!
//! Three rules are deliberate and load-bearing:
//!
//! - **No direct fallback.** When the pool is empty or every node is at its
//!   cap, the request fails. Quietly going out over the host's own route would
//!   defeat the point of fan-out and, for a Tor or proxy pool, leak traffic
//!   onto the very path the caller paid to avoid. A refusal is the safe default.
//! - **One node per request.** A failed attempt is reported, not retried on a
//!   sibling node. Retry is [`fetch_plan`](crate::pool::fetch_plan)'s job; doing
//!   it in both places would multiply the attempt budget by the pool size.
//! - **One client per node, cached.** `reqwest::blocking::Client` owns a
//!   connection pool and a background runtime, so building one per request
//!   would throw away connection reuse on exactly the path where reuse is the
//!   whole point.

use crate::node::{NodeKind, NodePool, Reservation};
use crate::pool::{FetchError, Fetcher};
use reqwest::blocking::Client;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// User-Agent sent on every range request, matching
/// [`HttpRangeFetcher`](crate::pool::HttpRangeFetcher).
const USER_AGENT: &str = concat!("tallow-egress/", env!("CARGO_PKG_VERSION"));

/// TCP connect deadline. Reaching a dead proxy should fail fast rather than
/// hang a worker for the whole request budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-request deadline. `Fetcher::fetch_range` takes no configuration, and
/// `fetch_plan` publishes its deadline in a thread-local private to
/// [`pool`](crate::pool), so a proxied fetch cannot read the caller's
/// `PoolConfig::timeout_secs`. This mirrors `PoolConfig::default().timeout_secs`
/// rather than inventing a different number.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a request waits for a lease before declaring the pool saturated.
const SATURATION_WAIT: Duration = Duration::from_secs(2);

/// Poll interval while waiting for a lease. Short enough that a burst of
/// shards does not idle a node that just freed up.
const SATURATION_POLL: Duration = Duration::from_millis(5);

/// A [`Fetcher`] that leases a node from a [`NodePool`] per range request, so
/// concurrent shards leave through different exits.
#[derive(Debug)]
pub struct ProxiedFetcher {
    /// Source URL.
    pub url: String,
    /// Nodes to fan out across.
    pub pool: Arc<NodePool>,
    /// One client per node id, built on first use and reused afterwards.
    ///
    /// Keyed by id rather than by [`NodeKind`] because the pool's reports are
    /// keyed by id too, and one node means one exit with one connection pool.
    clients: Mutex<HashMap<String, Client>>,
}

impl ProxiedFetcher {
    /// Build a fetcher over `pool`.
    pub fn new(url: impl Into<String>, pool: Arc<NodePool>) -> Self {
        Self {
            url: url.into(),
            pool,
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Cached client for `lease`'s node, building it on first use.
    ///
    /// The lock is not held across the build: constructing a client is the
    /// slow path, and holding the cache lock there would serialise every other
    /// shard's first request. `Client` is a handle (an `Arc` internally), so
    /// returning a clone is cheap and keeps the guard out of the caller's
    /// lifetime.
    fn client_for(&self, lease: &Reservation) -> Result<Client, FetchError> {
        let id = lease.id().to_owned();
        {
            let cache = self
                .clients
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some(client) = cache.get(&id) {
                return Ok(client.clone());
            }
        }

        let client = build_client(lease.kind())?;
        let mut cache = self
            .clients
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Ok(cache.entry(id).or_insert(client).clone())
    }

    /// Lease a node, waiting briefly for one to free up.
    ///
    /// Returning `None` from [`NodePool::acquire`] means "every node is at its
    /// cap", not "no nodes configured" — but either way the answer is the same:
    /// wait a bounded time, then fail. Going direct instead would be a silent
    /// bypass of the pool.
    fn lease(&self) -> Result<Reservation, FetchError> {
        let started = Instant::now();
        loop {
            if let Some(lease) = self.pool.acquire() {
                return Ok(lease);
            }
            if started.elapsed() >= SATURATION_WAIT {
                return Err(FetchError::Transport(format!(
                    "all egress nodes saturated (pool capacity {})",
                    self.pool.capacity()
                )));
            }
            thread::sleep(SATURATION_POLL);
        }
    }

    /// Perform one attempt through `lease`, without touching the counters.
    fn attempt(&self, lease: &Reservation, start: u64, end: u64) -> Result<Vec<u8>, FetchError> {
        let want = end - start;
        let last = end - 1;
        let url = &self.url;
        let node = lease.id();
        let client = self.client_for(lease)?;

        let response = client
            .get(url)
            .header(reqwest::header::RANGE, format!("bytes={start}-{last}"))
            // Critical: a transparent gzip would decouple body offsets from
            // file offsets, so every range after the first would be stitched
            // together from the wrong bytes.
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            // Some origins answer an empty User-Agent with 403, so identify
            // ourselves rather than inheriting reqwest's bare default.
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .map_err(|err| {
                // `reqwest::Error`'s Display is only the outermost layer ("error
                // sending request"), which is exactly useless when the cause is a
                // proxy handshake. Walk the source chain so the bench output names
                // the real failure.
                FetchError::Transport(format!(
                    "GET {url} bytes={start}-{last} via {node}: {}",
                    describe(&err)
                ))
            })?;

        let status = response.status();
        if status != reqwest::StatusCode::PARTIAL_CONTENT && status != reqwest::StatusCode::OK {
            return Err(FetchError::Transport(format!(
                "GET {url} bytes={start}-{last} via {node}: unexpected status {status}"
            )));
        }

        let body = response.bytes().map_err(|err| {
            FetchError::Transport(format!(
                "GET {url} bytes={start}-{last} via {node}: body: {err}"
            ))
        })?;

        if body.len() as u64 != want {
            // A fetcher is handed byte offsets, not a shard index; the pool
            // stamps the real index when it surfaces the error.
            return Err(FetchError::ShortRead {
                index: 0,
                expected: want,
                got: body.len() as u64,
            });
        }

        Ok(body.to_vec())
    }
}

impl Fetcher for ProxiedFetcher {
    fn fetch_range(&self, start: u64, end: u64) -> Result<Vec<u8>, FetchError> {
        if end <= start {
            return Ok(Vec::new());
        }

        let lease = self.lease()?;
        // No retry on a sibling node here: fetch_plan retries the shard, and
        // the pool's leaser will hand out a different node on the next attempt
        // anyway. Retrying inside this call would square the attempt count.
        let outcome = self.attempt(&lease, start, end);

        match &outcome {
            Ok(_) => lease.success(),
            // The pool's own counter is what `acquire` orders by, so the node
            // must be marked failed there. `Reservation::failure` increments
            // that same `NodeState` counter, hence exactly one call here —
            // doing both would count one attempt twice and make a single
            // failure look like two to the leaser.
            Err(_) => self.pool.record_failure(lease.id()),
        }
        // Release the slot before the caller (or fetch_plan) sees the result,
        // so a retry can lease immediately instead of polling.
        drop(lease);

        outcome
    }
}

/// Build a client that egresses through `kind`.
/// Flatten a reqwest error's source chain into one line.
///
/// `Display` on `reqwest::Error` stops at the outermost layer, so a SOCKS
/// handshake failure reads "error sending request" with no cause. This is
/// diagnostic only — it never changes control flow.
fn describe(err: &reqwest::Error) -> String {
    let mut out = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        out.push_str(" <- ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// Rewrite a `socks5://` proxy URL to `socks5h://` so the proxy resolves the
/// target name instead of this host.
///
/// Extracted from the client builder so the rewrite is testable without opening
/// a socket: the failure it prevents is silent, and only surfaces as a generic
/// "error sending request" when it is wrong.
fn socks_remote_url(url: &str) -> String {
    match url.strip_prefix("socks5://") {
        Some(rest) => format!("socks5h://{rest}"),
        None => url.to_string(),
    }
}

fn build_client(kind: &NodeKind) -> Result<Client, FetchError> {
    let builder = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);

    let builder =
        match kind {
            // Explicitly `no_proxy`: reqwest otherwise honours HTTP(S)_PROXY in the
            // environment, which would silently route a "direct" node through a
            // proxy and make the node layout a lie.
            NodeKind::Direct => builder.no_proxy(),
            NodeKind::Http(url) => builder
                .proxy(reqwest::Proxy::http(url.as_str()).map_err(|err| {
                    FetchError::Transport(format!("bad HTTP proxy {url}: {err}"))
                })?),
            NodeKind::Socks5(url) => {
                // `socks5://` makes reqwest resolve the target name locally and only
                // tunnel the connection; `socks5h://` hands the name to the proxy.
                // For a Tor exit the local resolver is both useless and a leak — the
                // query leaves from this host before the tunnel exists.
                //
                // Measured 2026-11-03 against this box's Tor: `curl --socks5` to a
                // range target failed outright while `--socks5-hostname` returned
                // 206, i.e. the non-h variant does not merely leak, it breaks.
                let remote = socks_remote_url(url);
                builder.proxy(reqwest::Proxy::all(remote.as_str()).map_err(|err| {
                    FetchError::Transport(format!("bad SOCKS5 proxy {url}: {err}"))
                })?)
            }
        };

    builder.build().map_err(|err| {
        FetchError::Transport(format!("could not build a client for {kind:?}: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::EgressNode;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Length of the mock server's virtual body.
    const BODY_LEN: u64 = 1_000;

    /// Deterministic, non-repeating-within-a-range byte pattern.
    fn body_byte(offset: u64) -> u8 {
        ((offset * 37 + 11) % 251) as u8
    }

    fn body_range(start: u64, end: u64) -> Vec<u8> {
        (start..end).map(body_byte).collect()
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

    fn handle_conn(mut stream: TcpStream, delay_ms: u64) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut head = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Ok(());
            }
            head.extend_from_slice(&buf[..read]);
            if head.windows(4).any(|window| window == b"\r\n\r\n") || head.len() > 32 * 1024 {
                break;
            }
        }

        let (start, end) = parse_range(&head).unwrap_or((0, BODY_LEN));
        let end = end.min(BODY_LEN).max(start);
        if delay_ms > 0 {
            thread::sleep(Duration::from_millis(delay_ms));
        }

        let body = body_range(start, end);
        let header = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            start,
            end.saturating_sub(1),
            BODY_LEN,
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;
        Ok(())
    }

    /// A loopback range server. One thread per connection, so concurrent
    /// requests really are concurrent.
    struct RangeServer {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        accept: Option<thread::JoinHandle<()>>,
    }

    impl RangeServer {
        fn start(delay_ms: u64) -> Self {
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
                            accept_hits.fetch_add(1, Ordering::SeqCst);
                            thread::spawn(move || {
                                let _ = handle_conn(stream, delay_ms);
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

    impl Drop for RangeServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(accept) = self.accept.take() {
                let _ = accept.join();
            }
        }
    }

    fn direct_pool(caps: &[usize]) -> Arc<NodePool> {
        Arc::new(NodePool::new(
            caps.iter()
                .enumerate()
                .map(|(i, cap)| EgressNode::direct(format!("node-{i}"), *cap))
                .collect(),
        ))
    }

    #[test]
    fn direct_pool_fetches_a_range() {
        let server = RangeServer::start(0);
        let pool = direct_pool(&[4]);
        let fetcher = ProxiedFetcher::new(server.url(), Arc::clone(&pool));

        let got = fetcher.fetch_range(100, 400).expect("range fetch");
        assert_eq!(got.len() as u64, 300);
        assert_eq!(got, body_range(100, 400));

        let whole = fetcher.fetch_range(0, BODY_LEN).expect("full fetch");
        assert_eq!(whole, body_range(0, BODY_LEN));
        assert_eq!(server.hits(), 2, "one request per fetch, no retries");

        let stats = pool.stats();
        assert_eq!(stats[0].successes, 2);
        assert_eq!(stats[0].failures, 0);
        assert_eq!(stats[0].inflight, 0, "the lease must be released");
    }

    #[test]
    fn saturates_and_refuses_rather_than_going_direct() {
        let server = RangeServer::start(0);
        let pool = direct_pool(&[1]);
        // Hold the only slot: every node is now at its cap.
        let held = pool.acquire().expect("sole lease");
        let fetcher = ProxiedFetcher::new(server.url(), Arc::clone(&pool));

        let started = Instant::now();
        let err = fetcher
            .fetch_range(0, 10)
            .expect_err("a saturated pool must refuse, not go direct");
        let elapsed = started.elapsed();

        match &err {
            FetchError::Transport(message) => {
                assert!(
                    message.contains("saturated"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains("capacity 1"),
                    "capacity should be reported: {message}"
                );
            }
            other => panic!("expected Transport, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(3),
            "saturation should give up in ~2s, took {elapsed:?}"
        );
        assert_eq!(server.hits(), 0, "nothing may leave the host");
        assert_eq!(pool.stats()[0].successes, 0);

        drop(held);
        // With the slot back the same fetcher works, so the refusal was about
        // capacity rather than a broken fetcher.
        assert_eq!(fetcher.fetch_range(0, 10).expect("after release").len(), 10);
    }

    #[test]
    fn failure_is_recorded_on_the_pool() {
        // Bind then drop, so the port is (almost certainly) closed.
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            listener.local_addr().expect("local addr")
        };
        let pool = Arc::new(NodePool::new(vec![EgressNode::direct("dead", 1)]));
        let fetcher = ProxiedFetcher::new(format!("http://{addr}/blob"), Arc::clone(&pool));

        let err = fetcher
            .fetch_range(0, 100)
            .expect_err("a closed port must fail");
        assert!(
            matches!(err, FetchError::Transport(_)),
            "expected Transport, got {err:?}"
        );

        let stats = pool.stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].id, "dead");
        assert_eq!(stats[0].failures, 1, "one attempt, one recorded failure");
        assert_eq!(stats[0].successes, 0);
        assert_eq!(stats[0].inflight, 0, "the lease must be released");
    }

    #[test]
    fn two_nodes_split_the_load() {
        // 20ms per answer keeps leases overlapping, so the leaser has to move
        // to the second node instead of reusing the first.
        let server = RangeServer::start(20);
        let pool = direct_pool(&[1, 1]);
        let fetcher = Arc::new(ProxiedFetcher::new(server.url(), Arc::clone(&pool)));

        // Requests are issued from several threads: `acquire` breaks a
        // (inflight, failures) tie in favour of the first node, so back-to-back
        // sequential calls would stay on node-0 by design. Concurrency is what
        // forces the spread, and it is what fan-out actually runs.
        const REQUESTS: u64 = 8;
        let barrier = Arc::new(Barrier::new(REQUESTS as usize));
        let mut handles = Vec::new();
        for i in 0..REQUESTS {
            let fetcher = Arc::clone(&fetcher);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let start = i * 100;
                let end = start + 100;
                barrier.wait();
                let bytes = fetcher.fetch_range(start, end).expect("fetch");
                assert_eq!(bytes, body_range(start, end));
            }));
        }
        for handle in handles {
            handle.join().expect("worker");
        }

        let stats = pool.stats();
        assert_eq!(server.hits(), REQUESTS as usize);
        for stat in &stats {
            assert!(
                stat.successes > 0,
                "node {} never served a request: {stat:?}",
                stat.id
            );
            assert_eq!(stat.failures, 0);
            assert_eq!(stat.inflight, 0);
        }
        let total: u64 = stats.iter().map(|stat| stat.successes).sum();
        assert_eq!(total, REQUESTS, "each request is counted once");
    }
}

#[cfg(test)]
mod socks_tests {
    use super::socks_remote_url;

    #[test]
    fn socks5_is_rewritten_to_socks5h() {
        assert_eq!(
            socks_remote_url("socks5://127.0.0.1:9050"),
            "socks5h://127.0.0.1:9050"
        );
    }

    #[test]
    fn socks5h_is_left_alone() {
        assert_eq!(
            socks_remote_url("socks5h://127.0.0.1:9050"),
            "socks5h://127.0.0.1:9050"
        );
    }
}
