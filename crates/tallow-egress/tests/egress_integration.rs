//! End-to-end proof of the `pool` concurrency claim.
//!
//! Every test here runs against an in-process HTTP/1.1 server bound to
//! `127.0.0.1:0`, built only from `std` (TcpListener + threads). No external
//! crates, no tokio, no hyper, no traffic beyond loopback.
//!
//! The server serves a deterministic payload where the byte at absolute offset
//! `i` is `(i % 251) as u8`, so any shard can be produced independently and the
//! reassembled transfer can be compared byte-for-byte against the same formula.
//!
//! The concurrency claim under test: with `PoolConfig::streams` in flight, a
//! transfer of N equal shards costs roughly *one* per-response latency instead
//! of N. The server sleeps 120 ms per response, so a serialised run over 8
//! shards costs >= 960 ms while a fully concurrent run costs ~120-240 ms.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tallow_egress::{FetchError, Fetcher, HttpRangeFetcher, PoolConfig, fetch_plan, plan_shards};

/// Period of the deterministic payload.
const PATTERN_MODULUS: u64 = 251;

/// 8 MiB: large enough that eight 1 MiB shards are real work, small enough that
/// the byte-identity comparison stays cheap.
const TOTAL: u64 = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// Expected byte at absolute offset `i`.
fn pattern_at(i: u64) -> u8 {
    (i % PATTERN_MODULUS) as u8
}

/// The whole expected payload.
fn pattern_bytes(len: u64) -> Vec<u8> {
    (0..len).map(pattern_at).collect()
}

/// The expected payload for `[start, end)`.
fn pattern_slice(start: u64, end: u64) -> Vec<u8> {
    (start..end).map(pattern_at).collect()
}

// ---------------------------------------------------------------------------
// In-process HTTP/1.1 range server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ServerConfig {
    /// Size of the served object.
    total: u64,
    /// Artificial latency before every response head is written.
    sleep_ms: u64,
    /// Answer the first N requests with `503 Service Unavailable`.
    fail_first_n: usize,
    /// Advertise the full body length but send this many bytes fewer.
    truncate_body: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            total: TOTAL,
            sleep_ms: 0,
            fail_first_n: 0,
            truncate_body: 0,
        }
    }
}

struct ServerShared {
    cfg: ServerConfig,
}

/// A live loopback server; shuts its accept loop down on drop.
struct TestServer {
    addr: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start(cfg: ServerConfig) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback ephemeral port");
        let addr = listener.local_addr().expect("listener addr");

        let requests = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(ServerShared { cfg });

        let accept_shutdown = Arc::clone(&shutdown);
        let accept_requests = Arc::clone(&requests);
        let accept = thread::spawn(move || {
            for incoming in listener.incoming() {
                if accept_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                match incoming {
                    Ok(stream) => {
                        let shared = Arc::clone(&shared);
                        let counter = Arc::clone(&accept_requests);
                        // One thread per connection: this is what lets the
                        // eight concurrent range requests overlap at all.
                        thread::spawn(move || {
                            let _ = handle_connection(stream, &shared, &counter);
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            requests,
            shutdown,
            accept: Some(accept),
        }
    }

    fn base_url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the parked `accept()` so the thread can observe the flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    shared: &ServerShared,
    requests: &AtomicUsize,
) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let head = match read_request_head(&mut stream) {
        Some(head) => head,
        None => return Ok(()),
    };

    let seen = requests.fetch_add(1, Ordering::SeqCst) + 1;

    if shared.cfg.sleep_ms > 0 {
        thread::sleep(Duration::from_millis(shared.cfg.sleep_ms));
    }

    if seen <= shared.cfg.fail_first_n {
        let head = "HTTP/1.1 503 Service Unavailable\r\n\
                    Content-Length: 0\r\n\
                    Connection: close\r\n\
                    \r\n";
        stream.write_all(head.as_bytes())?;
        stream.flush()?;
        return Ok(());
    }

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();

    if method != "GET" {
        return respond_simple(&mut stream, "405 Method Not Allowed");
    }

    let mut range: Option<(u64, Option<u64>)> = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("range")
        {
            range = parse_range(value.trim());
        }
    }

    let total = shared.cfg.total;

    let Some((start, raw_end)) = range else {
        // No Range header: 200 with the whole object.
        let body = pattern_bytes(total);
        return respond(
            &mut stream,
            "200 OK",
            &[
                ("Content-Type", "application/octet-stream".to_string()),
                ("Content-Length", body.len().to_string()),
                ("Accept-Ranges", "bytes".to_string()),
                ("Connection", "close".to_string()),
            ],
            &body,
            shared.cfg.truncate_body,
        );
    };

    if start >= total {
        let head = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\n\
             Content-Range: bytes */{total}\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes())?;
        stream.flush()?;
        return Ok(());
    }

    // Clamp an open-ended or over-long range to the object.
    let end = raw_end.unwrap_or(total - 1).min(total - 1);
    if end < start {
        let head = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\n\
             Content-Range: bytes */{total}\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes())?;
        stream.flush()?;
        return Ok(());
    }

    let len = end - start + 1;
    let body = pattern_slice(start, end + 1);

    respond(
        &mut stream,
        "206 Partial Content",
        &[
            ("Content-Type", "application/octet-stream".to_string()),
            ("Content-Range", format!("bytes {start}-{end}/{total}")),
            ("Accept-Ranges", "bytes".to_string()),
            ("Content-Length", len.to_string()),
            ("Connection", "close".to_string()),
        ],
        &body,
        shared.cfg.truncate_body,
    )
}

/// `Range: bytes=A-B` / `bytes=A-` / `bytes=-N` (suffix form is not needed by
/// the pool, and is treated as unparseable so the request falls back to 200).
fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = end.trim();
    if end.is_empty() {
        Some((start, None))
    } else {
        Some((start, Some(end.parse::<u64>().ok()?)))
    }
}

fn respond_simple(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    respond(
        stream,
        status,
        &[("Content-Length", "0".to_string())],
        &[],
        0,
    )
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, String)],
    body: &[u8],
    truncate: usize,
) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;

    let keep = body.len().saturating_sub(truncate);
    stream.write_all(&body[..keep])?;
    stream.flush()?;

    if truncate > 0 {
        // Half-close so the client sees EOF while still short of the
        // advertised Content-Length.
        let _ = stream.shutdown(Shutdown::Write);
    }
    Ok(())
}

/// Read bytes up to and including the blank line ending the request head.
fn read_request_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 8 shards, 120 ms per response: one stream must serialise (~960 ms), eight
/// streams must overlap (~120-240 ms). Also proves both runs reassemble the
/// exact payload.
#[test]
fn single_vs_many_streams() {
    let server = TestServer::start(ServerConfig {
        total: TOTAL,
        sleep_ms: 120,
        fail_first_n: 0,
        truncate_body: 0,
    });
    let http = HttpRangeFetcher::new(server.base_url("/blob"));
    let fetcher: &dyn Fetcher = &http;

    let plan = plan_shards(TOTAL, 8, 1).expect("plan for 8 streams");
    plan.validate()
        .expect("plan must be contiguous and complete");
    assert_eq!(plan.shards.len(), 8, "expected 8 shards");
    assert!(
        plan.shards.iter().all(|shard| shard.len() == TOTAL / 8),
        "shards must be equal-sized: {:?}",
        plan.shards.iter().map(|s| s.len()).collect::<Vec<_>>()
    );

    let serial = fetch_plan(
        &plan,
        fetcher,
        &PoolConfig {
            streams: 1,
            retries: 3,
            backoff_ms: 20,
            timeout_secs: 60,
        },
    )
    .expect("one-stream fetch");

    let requests_after_serial = server.requests();

    let concurrent = fetch_plan(
        &plan,
        fetcher,
        &PoolConfig {
            streams: 8,
            retries: 3,
            backoff_ms: 20,
            timeout_secs: 60,
        },
    )
    .expect("eight-stream fetch");

    println!(
        "single_vs_many_streams: streams=1 -> {} ms ({} requests), streams=8 -> {} ms ({} requests)",
        serial.elapsed_ms,
        requests_after_serial,
        concurrent.elapsed_ms,
        server.requests() - requests_after_serial
    );
    println!(
        "  per-shard (streams=8): {:?}",
        concurrent
            .per_shard
            .iter()
            .map(|stat| (stat.index, stat.bytes, stat.attempts, stat.elapsed_ms))
            .collect::<Vec<_>>()
    );

    let expected = pattern_bytes(TOTAL);

    assert_eq!(serial.total_bytes, TOTAL, "serial total_bytes");
    assert_eq!(concurrent.total_bytes, TOTAL, "concurrent total_bytes");
    assert_eq!(serial.data.len() as u64, TOTAL, "serial data length");
    assert_eq!(
        concurrent.data.len() as u64,
        TOTAL,
        "concurrent data length"
    );
    assert_eq!(serial.data, expected, "serial payload differs from pattern");
    assert_eq!(
        concurrent.data, expected,
        "concurrent payload differs from pattern"
    );
    assert_eq!(
        serial.data, concurrent.data,
        "runs disagree with each other"
    );

    // Structural checks on the report.
    assert_eq!(
        concurrent.per_shard.len(),
        plan.shards.len(),
        "one ShardStat per shard"
    );
    for (position, stat) in concurrent.per_shard.iter().enumerate() {
        assert_eq!(stat.index as usize, position, "per_shard must ascend");
        assert_eq!(
            stat.bytes,
            plan.shards[position].len(),
            "shard {} byte count",
            stat.index
        );
        assert!(stat.attempts >= 1, "attempts includes the first try");
    }
    assert_eq!(
        concurrent.per_shard.iter().map(|s| s.bytes).sum::<u64>(),
        TOTAL,
        "shard byte counts must sum to the transfer"
    );

    // Exactly one request per shard when nothing fails.
    assert!(
        requests_after_serial >= plan.shards.len(),
        "expected at least one request per shard, saw {requests_after_serial}"
    );

    // The claim: eight streams is at least twice as fast as one.
    assert!(
        serial.elapsed_ms >= 800,
        "a single stream over 8 shards x 120 ms should take ~960 ms, took {} ms",
        serial.elapsed_ms
    );
    assert!(
        serial.elapsed_ms >= 2 * concurrent.elapsed_ms,
        "concurrency not observed: 1 stream = {} ms, 8 streams = {} ms (need 1-stream >= 2x 8-stream)",
        serial.elapsed_ms,
        concurrent.elapsed_ms
    );
}

/// Three 503s must be absorbed by `retries: 3` with `backoff_ms: 20`, and the
/// server must have seen more requests than the shard count.
#[test]
fn retries_recover_from_transient_failures() {
    const FLAKY_TOTAL: u64 = 256 * 1024;

    let server = TestServer::start(ServerConfig {
        total: FLAKY_TOTAL,
        sleep_ms: 10,
        fail_first_n: 3,
        truncate_body: 0,
    });
    let http = HttpRangeFetcher::new(server.base_url("/flaky"));
    let fetcher: &dyn Fetcher = &http;

    let plan = plan_shards(FLAKY_TOTAL, 4, 1).expect("plan for 4 shards");
    let report = fetch_plan(
        &plan,
        fetcher,
        &PoolConfig {
            streams: 1,
            retries: 3,
            backoff_ms: 20,
            timeout_secs: 30,
        },
    )
    .expect("three transient 503s must be recovered by retries: 3");

    let observed = server.requests();
    println!(
        "retries_recover_from_transient_failures: server saw {observed} requests for {} shards; attempts = {:?}",
        plan.shards.len(),
        report
            .per_shard
            .iter()
            .map(|s| s.attempts)
            .collect::<Vec<_>>()
    );

    assert_eq!(report.data, pattern_bytes(FLAKY_TOTAL));
    assert_eq!(report.total_bytes, FLAKY_TOTAL);

    assert!(
        observed > plan.shards.len(),
        "retries did not happen: {observed} requests for {} shards",
        plan.shards.len()
    );
    // 3 injected failures + one request per shard.
    assert!(
        observed >= plan.shards.len() + 3,
        "expected at least 3 retry attempts on top of {} shard requests, saw {observed}",
        plan.shards.len()
    );
    assert!(
        report.per_shard.iter().any(|stat| stat.attempts >= 2),
        "no shard reports a retry: {:?}",
        report
            .per_shard
            .iter()
            .map(|s| s.attempts)
            .collect::<Vec<_>>()
    );
    // `attempts` counts every try including the first, so it must account for
    // exactly the requests the server saw.
    assert_eq!(
        report.per_shard.iter().map(|s| s.attempts).sum::<u32>() as usize,
        observed,
        "per-shard attempt counters do not account for the requests the server saw"
    );
}

/// A body truncated by 10 bytes while `Content-Length` still advertises the
/// full range must not be accepted as a successful transfer.
#[test]
fn short_read_is_detected() {
    const SHORT_TOTAL: u64 = 64 * 1024;

    let server = TestServer::start(ServerConfig {
        total: SHORT_TOTAL,
        sleep_ms: 0,
        fail_first_n: 0,
        truncate_body: 10,
    });
    let http = HttpRangeFetcher::new(server.base_url("/truncated"));
    let fetcher: &dyn Fetcher = &http;

    let plan = plan_shards(SHORT_TOTAL, 4, 1).expect("plan for 4 shards");
    let result = fetch_plan(
        &plan,
        fetcher,
        &PoolConfig {
            streams: 1,
            retries: 1,
            backoff_ms: 5,
            timeout_secs: 30,
        },
    );

    let error = match result {
        Ok(report) => panic!(
            "a truncated body was accepted as success: total_bytes={} data_len={}",
            report.total_bytes,
            report.data.len()
        ),
        Err(error) => error,
    };

    println!("short_read_is_detected observed: {error:?} (display: {error})");

    match &error {
        FetchError::ShortRead {
            index,
            expected,
            got,
        } => {
            println!("  variant: ShortRead{{index: {index}, expected: {expected}, got: {got}}}");
            assert!(
                *got < *expected,
                "ShortRead must report fewer bytes than asked"
            );
        }
        FetchError::Exhausted { last, .. } => {
            assert!(
                mentions_short_read(last),
                "Exhausted after truncation, but the last error does not describe a short/incomplete body: {last}"
            );
        }
        other => panic!(
            "expected ShortRead (possibly wrapped in Exhausted), got {other:?} for a body truncated by 10 bytes"
        ),
    }
}

/// Tolerant matcher for how a truncated HTTP body surfaces. `HttpRangeFetcher`
/// may compare the received length itself (`ShortRead`) or surface the
/// transport's incomplete-body error, which `fetch_plan` then wraps in
/// `Exhausted`.
fn mentions_short_read(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    [
        "short read",
        "short",
        "truncat",
        "eof",
        "end of file",
        "incomplete",
        "not enough",
        "only got",
        "fewer bytes",
        "decoding response body",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

/// Pure logic: the header each shard produces, and that the shards reassembled
/// in plan order rebuild the pattern exactly.
#[test]
fn plan_header_roundtrip() {
    let plan = plan_shards(TOTAL, 8, 1).expect("plan for 8 shards");

    for shard in &plan.shards {
        assert_eq!(
            shard.range_header(),
            format!("bytes={}-{}", shard.start, shard.end - 1),
            "shard {} header",
            shard.index
        );
    }

    // Spot-check the exact strings, not just the formula.
    assert_eq!(
        plan.shards.first().unwrap().range_header(),
        "bytes=0-1048575"
    );
    assert_eq!(
        plan.shards.last().unwrap().range_header(),
        "bytes=7340032-8388607"
    );

    // Simulate serving each shard, then reassemble in plan order.
    let mut assembled = Vec::with_capacity(TOTAL as usize);
    for shard in &plan.shards {
        let piece = pattern_slice(shard.start, shard.end);
        assert_eq!(
            piece.len() as u64,
            shard.len(),
            "shard {} piece size",
            shard.index
        );
        assembled.extend_from_slice(&piece);
    }

    assert_eq!(assembled.len() as u64, TOTAL);
    assert_eq!(assembled, pattern_bytes(TOTAL));
}
