//! `egress-bench` — measure single-flow versus N-stream throughput, and report
//! what the host can actually do with those streams.
//!
//! The crate claims that splitting one transfer across N concurrent range
//! requests beats one flow, because a single TCP flow is bounded by its
//! bandwidth-delay product rather than by the link. This binary is the
//! falsification instrument: it moves the same object at 1, 2, 4, … streams over
//! the same URL and prints the ratio — or reports that there is no ratio.
//!
//! Two behaviours are deliberate:
//!
//! - A target that ignores `Range` is an error (exit 3), never a silent fallback
//!   to a plain download. A "speedup" measured against a server that ignores
//!   ranges is meaningless, so it is refused rather than approximated.
//! - The host path probe prints next to the measurement, because streams cannot
//!   invent capacity the host does not have. With one uplink, N streams raise a
//!   single transfer's throughput only until the link itself is saturated.

use std::cmp::Ordering;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use serde_json::{Value, json};
use tallow_egress::calibrate::weights_from_goodput;
use tallow_egress::node::{EgressNode, NodeKind, NodePool, NodeStat};
use tallow_egress::proxy::ProxiedFetcher;
use tallow_egress::{
    CapabilityReport, FetchError, Fetcher, HttpRangeFetcher, PoolConfig, ShardStat, fetch_plan,
    plan_shards, plan_shards_weighted, probe_host,
};

const USAGE: &str = "\
usage: egress-bench --url <URL> [--streams 1,2,4,8,16] [--bytes 67108864] \
[--retries 3] [--timeout 30] [--nodes direct,socks5://host:port] \
[--json <PATH>] [--probe-only]

  --url <URL>        target to benchmark (required unless --probe-only)
  --streams <csv>    stream counts to sweep, ascending, deduplicated
                     (default 1,2,4,8,16)
  --bytes <N>        cap each transfer at N bytes; the run uses
                     min(N, content length) (default 67108864 = 64 MiB)
  --retries <N>      retries per shard before a run fails (default 3)
  --timeout <secs>   per-request timeout (default 30)
  --nodes <csv>      egress exits to fan out across, each `direct`,
                     `socks5://host:port` or `http://host:port`. Omit to fetch
                     every range over the host's own route
  --json <PATH>      write the report JSON to PATH instead of stdout
  --probe-only       print this host's capability report and exit; no network I/O

Human output goes to stdout, and to stderr when the JSON report is written to
stdout, so `egress-bench --url … | jq .` works.

exit codes: 0 ok, 2 bad arguments, 3 target has no range support, 4 a run failed";

const DEFAULT_STREAMS: &str = "1,2,4,8,16";
const DEFAULT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_RETRIES: u32 = 3;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Matches `PoolConfig::default()`; not exposed as a flag to keep the surface small.
const DEFAULT_BACKOFF_MS: u64 = 250;
/// Smallest shard worth issuing. `plan_shards` lowers the stream count rather
/// than this floor, and the table notes it when that happens.
const MIN_CHUNK_BYTES: u64 = 64 * 1024;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    ExitCode::from(run(&argv))
}

// ---------------------------------------------------------------------------
// arguments
// ---------------------------------------------------------------------------

struct Args {
    url: String,
    streams: Vec<u32>,
    bytes: u64,
    retries: u32,
    timeout_secs: u64,
    nodes: Option<Vec<String>>,
    weights: Option<Vec<u32>>,
    calibrate: bool,
    json_path: Option<PathBuf>,
    probe_only: bool,
}

fn take_value(
    argv: &[String],
    inline: Option<String>,
    i: &mut usize,
    flag: &str,
) -> Result<String, String> {
    if let Some(v) = inline {
        if v.trim().is_empty() {
            return Err(format!("{flag} was given an empty value"));
        }
        return Ok(v);
    }
    *i += 1;
    match argv.get(*i) {
        Some(v) if !v.trim().is_empty() => Ok(v.clone()),
        _ => Err(format!("{flag} requires a value")),
    }
}

fn parse_number<T>(raw: &str, flag: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    raw.trim()
        .parse::<T>()
        .map_err(|e| format!("{flag}: `{raw}` is not a valid number ({e})"))
}

/// Parse `--nodes`: a comma-separated list of `direct`, `socks5://host:port` or
/// `http://host:port`. Order is preserved because it is the assignment order the
/// pool sees on its first pass.
fn parse_nodes(raw: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let ok = part == "direct"
            || part.starts_with("socks5://")
            || part.starts_with("http://")
            || part.starts_with("https://");
        if !ok {
            return Err(format!(
                "--nodes: `{part}` is not `direct`, `socks5://…` or `http(s)://…`"
            ));
        }
        out.push(part.to_string());
    }
    if out.is_empty() {
        return Err("--nodes: at least one exit is required".to_string());
    }
    Ok(out)
}

/// Parse `--weights`: one positive integer per `--nodes` entry, in the same
/// order. A weight of 0 would name a path that carries nothing, so it is an
/// error rather than a silent drop from the plan.
fn parse_weights(raw: &str) -> Result<Vec<u32>, String> {
    let mut out: Vec<u32> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let w: u32 = part
            .parse()
            .map_err(|_| format!("--weights: `{part}` is not a positive integer"))?;
        if w == 0 {
            return Err("--weights: every weight must be at least 1".to_string());
        }
        out.push(w);
    }
    if out.is_empty() {
        return Err("--weights: at least one weight is required".to_string());
    }
    Ok(out)
}

fn parse_streams(raw: &str) -> Result<Vec<u32>, String> {
    let mut out: Vec<u32> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let n: u32 = part
            .parse()
            .map_err(|_| format!("--streams: `{part}` is not a stream count"))?;
        if n == 0 {
            return Err("--streams: stream counts must be at least 1".to_string());
        }
        out.push(n);
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("--streams: at least one stream count is required".to_string());
    }
    Ok(out)
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut url: Option<String> = None;
    let mut streams: Option<Vec<u32>> = None;
    let mut bytes: Option<u64> = None;
    let mut retries: Option<u32> = None;
    let mut timeout_secs: Option<u64> = None;
    let mut json_path: Option<PathBuf> = None;
    let mut nodes: Option<Vec<String>> = None;
    let mut weights: Option<Vec<u32>> = None;
    let mut calibrate = false;
    let mut probe_only = false;

    let mut i = 1usize;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg, None),
        };
        match flag {
            "--url" => url = Some(take_value(argv, inline, &mut i, flag)?),
            "--streams" => {
                streams = Some(parse_streams(&take_value(argv, inline, &mut i, flag)?)?);
            }
            "--bytes" => {
                bytes = Some(parse_number(
                    &take_value(argv, inline, &mut i, flag)?,
                    flag,
                )?);
            }
            "--retries" => {
                retries = Some(parse_number(
                    &take_value(argv, inline, &mut i, flag)?,
                    flag,
                )?);
            }
            "--timeout" => {
                timeout_secs = Some(parse_number(
                    &take_value(argv, inline, &mut i, flag)?,
                    flag,
                )?);
            }
            "--nodes" => nodes = Some(parse_nodes(&take_value(argv, inline, &mut i, flag)?)?),
            "--weights" => weights = Some(parse_weights(&take_value(argv, inline, &mut i, flag)?)?),
            "--json" => json_path = Some(PathBuf::from(take_value(argv, inline, &mut i, flag)?)),
            "--calibrate" => {
                if inline.is_some() {
                    return Err("--calibrate takes no value".to_string());
                }
                calibrate = true;
            }
            "--probe-only" => {
                if inline.is_some() {
                    return Err("--probe-only takes no value".to_string());
                }
                probe_only = true;
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }

    let url = match url {
        Some(u) => u,
        None if probe_only => String::new(),
        None => return Err("--url is required (or pass --probe-only)".to_string()),
    };

    let bytes = bytes.unwrap_or(DEFAULT_BYTES);
    if bytes == 0 {
        return Err("--bytes must be greater than zero".to_string());
    }
    let timeout_secs = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    if timeout_secs == 0 {
        return Err("--timeout must be greater than zero seconds".to_string());
    }

    if calibrate {
        if nodes.is_none() {
            return Err("--calibrate needs --nodes: there is nothing to measure".to_string());
        }
        if weights.is_some() {
            return Err("--calibrate measures the weights; do not also pass --weights".to_string());
        }
    }
    if let Some(w) = &weights {
        match &nodes {
            None => {
                return Err("--weights needs --nodes: a weight is per exit".to_string());
            }
            Some(n) if n.len() != w.len() => {
                return Err(format!(
                    "--weights has {} entries but --nodes has {}",
                    w.len(),
                    n.len()
                ));
            }
            Some(_) => {}
        }
    }

    Ok(Args {
        url,
        streams: streams.unwrap_or_else(|| parse_streams(DEFAULT_STREAMS).unwrap_or_default()),
        bytes,
        retries: retries.unwrap_or(DEFAULT_RETRIES),
        timeout_secs,
        nodes,
        weights,
        calibrate,
        json_path,
        probe_only,
    })
}

// ---------------------------------------------------------------------------
// content-length discovery
// ---------------------------------------------------------------------------

/// Why discovery could not produce a length.
enum Fail {
    /// The target cannot do ranged requests (exit 3).
    NoRange(String),
    /// Transport or protocol failure (exit 4).
    Transport(String),
}

impl Fail {
    fn code(&self) -> u8 {
        match self {
            Fail::NoRange(_) => 3,
            Fail::Transport(_) => 4,
        }
    }

    fn text(&self) -> &str {
        match self {
            Fail::NoRange(t) | Fail::Transport(t) => t,
        }
    }
}

struct Discovered {
    content_length: u64,
}

/// Total resource length from a `Content-Range: bytes 0-0/<total>` response.
///
/// Returns `None` for `*` (length unknown) and for anything that is not a
/// final-range form, so the caller refuses instead of guessing.
fn parse_content_range_total(value: &str) -> Option<u64> {
    let (_, total) = value.rsplit_once('/')?;
    let total = total.trim();
    if total == "*" || total.is_empty() {
        return None;
    }
    total.parse::<u64>().ok()
}

/// Ask for one byte and read the length back out of the headers. The body is
/// never read: if the server ignores `Range` and starts sending the whole
/// object, dropping the response closes the connection.
fn discover_length(client: &Client, url: &str) -> Result<Discovered, Fail> {
    let resp = client
        .get(url)
        .header(RANGE, "bytes=0-0")
        .send()
        .map_err(|e| Fail::Transport(format!("range probe to {url} failed: {e}")))?;

    let status = resp.status();
    let content_range = resp
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(str::to_string);
    let content_length = resp
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    drop(resp);

    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        return Err(Fail::NoRange(format!(
            "{url} rejected `Range: bytes=0-0` with 416 Range Not Satisfiable; \
             there is no readable length to benchmark"
        )));
    }

    if let Some(raw) = content_range {
        let total = parse_content_range_total(&raw).ok_or_else(|| {
            Fail::NoRange(format!(
                "{url} answered `Content-Range: {raw}`, which does not state a total \
                 resource length; a whole-object benchmark cannot be sized"
            ))
        })?;
        if total == 0 {
            return Err(Fail::NoRange(format!(
                "{url} reports a resource length of 0 bytes"
            )));
        }
        return Ok(Discovered {
            content_length: total,
        });
    }

    // No Content-Range. A 200 here means the server served the whole object
    // instead of the requested byte: it does not implement ranges, and the
    // measurement this binary exists to make is impossible.
    if status == StatusCode::OK {
        return Err(Fail::NoRange(format!(
            "{url} answered 200 with no Content-Range: the target does not support \
             range requests, so multi-stream throughput cannot be measured"
        )));
    }

    match content_length {
        Some(n) if n > 0 => Ok(Discovered { content_length: n }),
        _ => Err(Fail::NoRange(format!(
            "{url} answered {status} with neither Content-Range nor a usable \
             Content-Length; the resource length is unknown"
        ))),
    }
}

// ---------------------------------------------------------------------------
// measurement
// ---------------------------------------------------------------------------

struct Run {
    streams: u32,
    bytes: u64,
    elapsed_ms: u64,
    mbs: f64,
    gbit: f64,
    per_shard: Vec<ShardStat>,
    shards_planned: usize,
    /// Per-node counters, empty when the run used the host's own route.
    nodes: Vec<NodeStat>,
}

struct Report {
    url: String,
    requested_bytes: u64,
    content_length: u64,
    probe: CapabilityReport,
    runs: Vec<Run>,
    baseline_added: bool,
    mismatches: Vec<String>,
}

impl Report {
    fn baseline_mbs(&self) -> f64 {
        self.runs
            .iter()
            .find(|r| r.streams == 1)
            .map(|r| r.mbs)
            .unwrap_or(0.0)
    }

    /// Fastest run; ties go to the lower stream count, because equal throughput
    /// with fewer connections is the better operating point.
    fn best(&self) -> Option<&Run> {
        self.runs.iter().max_by(|a, b| {
            a.mbs
                .partial_cmp(&b.mbs)
                .unwrap_or(Ordering::Equal)
                .then_with(|| b.streams.cmp(&a.streams))
        })
    }

    fn speedup(&self) -> f64 {
        let baseline = self.baseline_mbs();
        match self.best() {
            Some(best) if baseline > 0.0 => round_to(best.mbs / baseline, 2),
            _ => 1.0,
        }
    }
}

fn round_to(x: f64, places: i32) -> f64 {
    let f = 10f64.powi(places);
    (x * f).round() / f
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn fetch_failure(streams: u32, err: FetchError) -> u8 {
    eprintln!("egress-bench: run at streams={streams} failed: {err}");
    4
}

fn measure(
    client_timeout: u64,
    args: &Args,
    probe: CapabilityReport,
    content_length: u64,
) -> Result<Report, u8> {
    let target_len = args.bytes.min(content_length);
    if target_len == 0 {
        eprintln!("egress-bench: nothing to transfer (target length 0)");
        return Err(4);
    }

    // A 1-stream run is the denominator of every speedup, so it is always
    // measured — even when the caller's sweep omits it.
    let baseline_added = !args.streams.contains(&1);
    let mut list = args.streams.clone();
    if baseline_added {
        list.insert(0, 1);
    }
    // Calibration measures each exit once over a small range, then hands the
    // same weighted planner a ratio derived from what the exits actually did.
    // A failed probe yields 0.0, which `weights_from_goodput` turns into the
    // floor weight rather than dropping the path.
    let effective_weights: Option<Vec<u32>> = match (&args.weights, args.calibrate) {
        (Some(explicit), _) => Some(explicit.clone()),
        (None, true) => {
            let specs = args
                .nodes
                .as_ref()
                .expect("validated: --calibrate needs --nodes");
            let mut goodput: Vec<f64> = Vec::with_capacity(specs.len());
            for spec in specs {
                let measured =
                    probe_exit_goodput(&args.url, spec, target_len, args.retries, client_timeout);
                match measured {
                    Some(bps) => eprintln!(
                        "egress-bench: calibrate {spec} -> {:.2} MB/s",
                        bps / 1_000_000.0
                    ),
                    None => {
                        eprintln!("egress-bench: calibrate {spec} -> probe failed, floor weight")
                    }
                }
                goodput.push(measured.unwrap_or(0.0));
            }
            let derived = weights_from_goodput(&goodput);
            eprintln!("egress-bench: calibrated weights {derived:?}");
            Some(derived)
        }
        (None, false) => None,
    };

    // With weights the shard count *is* the number of exits: the point of the
    // run is how bytes split across paths, not how many connections open.
    if let Some(w) = &effective_weights {
        list = vec![w.len() as u32];
    }

    let mut runs: Vec<Run> = Vec::with_capacity(list.len());
    let mut mismatches: Vec<String> = Vec::new();

    for streams in list {
        let planned = match &effective_weights {
            Some(weights) => plan_shards_weighted(target_len, weights, MIN_CHUNK_BYTES),
            None => plan_shards(target_len, streams, MIN_CHUNK_BYTES),
        };
        let plan = match planned {
            Ok(plan) => plan,
            Err(err) => {
                eprintln!(
                    "egress-bench: cannot plan {target_len} bytes over {streams} streams: {err}"
                );
                return Err(4);
            }
        };
        if let Some(weights) = &effective_weights {
            let sizes: Vec<u64> = plan.shards.iter().map(|s| s.len()).collect();
            eprintln!("egress-bench: weights {weights:?} -> shard bytes {sizes:?}");
        }
        let config = PoolConfig {
            streams,
            retries: args.retries,
            backoff_ms: DEFAULT_BACKOFF_MS,
            timeout_secs: client_timeout,
        };
        // Fan-out is opt-in. Without --nodes every range leaves over the host's
        // own route, which is what the stream sweep is measuring; with it, each
        // range is leased a node so the aggregate ceiling becomes nodes x node.
        let (fetcher, pool): (Box<dyn Fetcher>, Option<Arc<NodePool>>) = match &args.nodes {
            None => (Box::new(HttpRangeFetcher::new(args.url.clone())), None),
            Some(specs) => {
                let per_node = (streams as usize).div_ceil(specs.len()).max(1);
                let mut built: Vec<EgressNode> = Vec::with_capacity(specs.len());
                for (idx, spec) in specs.iter().enumerate() {
                    let kind = if spec == "direct" {
                        NodeKind::Direct
                    } else if spec.starts_with("socks5://") {
                        NodeKind::Socks5(spec.clone())
                    } else {
                        NodeKind::Http(spec.clone())
                    };
                    built.push(EgressNode {
                        id: format!("node-{idx}"),
                        kind,
                        max_inflight: per_node,
                    });
                }
                let pool = Arc::new(NodePool::new(built));
                let fetcher = ProxiedFetcher::new(args.url.clone(), Arc::clone(&pool));
                (Box::new(fetcher), Some(pool))
            }
        };

        let started = Instant::now();
        let report = match fetch_plan(&plan, fetcher.as_ref(), &config) {
            Ok(report) => report,
            Err(err) => return Err(fetch_failure(streams, err)),
        };
        let elapsed = started.elapsed();
        // Snapshot before the pool is dropped: this is the only record that the
        // ranges actually spread across exits rather than sticking to one.
        let node_stats = pool.as_ref().map(|p| p.stats()).unwrap_or_default();

        let elapsed_ms_f = elapsed.as_secs_f64() * 1000.0;
        let bytes = report.total_bytes;
        let mbs = if elapsed_ms_f > 0.0 {
            round_to(bytes as f64 / elapsed_ms_f * 1000.0 / 1_000_000.0, 1)
        } else {
            0.0
        };
        let gbit = if elapsed.as_secs_f64() > 0.0 {
            round_to(bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1e9, 2)
        } else {
            0.0
        };

        if bytes != plan.total_len {
            mismatches.push(format!(
                "streams={streams} returned {bytes} of {} planned bytes",
                plan.total_len
            ));
        }

        eprintln!(
            "egress-bench: streams={streams} {bytes} bytes in {:.1} ms",
            elapsed_ms_f
        );

        runs.push(Run {
            streams,
            bytes,
            elapsed_ms: elapsed_ms_f.round() as u64,
            mbs,
            gbit,
            per_shard: report.per_shard,
            shards_planned: plan.shards.len(),
            nodes: node_stats,
        });
    }

    Ok(Report {
        url: args.url.clone(),
        requested_bytes: args.bytes,
        content_length,
        probe,
        runs,
        baseline_added,
        mismatches,
    })
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

fn render_human(report: &Report, target_len: u64) -> String {
    let mut out = String::new();
    let baseline = report.baseline_mbs();
    let speedup = report.speedup();

    let _ = writeln!(out, "target   {}", report.url);
    let _ = writeln!(
        out,
        "length   {} bytes ({:.1} MiB), ranged request accepted",
        report.content_length,
        mib(report.content_length)
    );
    let _ = writeln!(
        out,
        "transfer {} bytes per run ({:.1} MiB){}",
        target_len,
        mib(target_len),
        if report.requested_bytes < report.content_length {
            ", capped by --bytes"
        } else {
            ""
        }
    );
    if report.baseline_added {
        let _ = writeln!(
            out,
            "note: streams=1 was added as the baseline; it was not in --streams"
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "{:>7}  {:>12}  {:>10}  {:>8}  {:>7}  {:>8}",
        "streams", "bytes", "elapsed ms", "MB/s", "Gbit/s", "speedup"
    );
    for run in &report.runs {
        let factor = if baseline > 0.0 {
            run.mbs / baseline
        } else {
            1.0
        };
        let _ = writeln!(
            out,
            "{:>7}  {:>12}  {:>10}  {:>8.1}  {:>7.2}  {:>7.2}x",
            run.streams, run.bytes, run.elapsed_ms, run.mbs, run.gbit, factor
        );
    }

    if report.runs.iter().any(|r| !r.nodes.is_empty()) {
        let _ = writeln!(out);
        let _ = writeln!(out, "egress exits (shards served per node):");
        for run in &report.runs {
            if run.nodes.is_empty() {
                continue;
            }
            let spread: Vec<String> = run
                .nodes
                .iter()
                .map(|n| format!("{}={}", n.id, n.successes))
                .collect();
            let failures: u64 = run.nodes.iter().map(|n| n.failures).sum();
            let idle = run.nodes.iter().filter(|n| n.successes == 0).count();
            let _ = writeln!(
                out,
                "  streams={:<3} {}  failures={}  idle_nodes={}",
                run.streams,
                spread.join("  "),
                failures,
                idle
            );
        }
    }

    for run in &report.runs {
        if run.shards_planned != run.streams as usize {
            let _ = writeln!(
                out,
                "note: streams={} planned {} shards; plan_shards lowers the stream count \
                 rather than the {} KiB minimum chunk",
                run.streams,
                run.shards_planned,
                MIN_CHUNK_BYTES / 1024
            );
        }
    }
    for line in &report.mismatches {
        let _ = writeln!(out, "warning: {line}");
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "host paths");
    if report.probe.verdict.is_empty() {
        let _ = writeln!(out, "  - probe produced no verdict");
    } else {
        for line in &report.probe.verdict {
            let _ = writeln!(out, "  - {line}");
        }
    }

    let _ = writeln!(out);
    match report.best() {
        Some(best) => {
            let verdict = if speedup > 1.05 {
                format!("{speedup:.2}x the single-stream baseline")
            } else {
                format!("no measurable gain over the single-stream baseline ({speedup:.2}x)")
            };
            let _ = writeln!(
                out,
                "conclusion: {} streams moved {} bytes at {:.2} Gbit/s ({:.1} MB/s) — {}",
                best.streams, best.bytes, best.gbit, best.mbs, verdict
            );
        }
        None => {
            let _ = writeln!(out, "conclusion: no run completed");
        }
    }

    out
}

fn json_report(report: &Report) -> Result<String, String> {
    let runs: Vec<Value> = report
        .runs
        .iter()
        .map(|run| {
            let per_shard: Vec<Value> = run
                .per_shard
                .iter()
                .map(|s| {
                    json!({
                        "index": s.index,
                        "bytes": s.bytes,
                        "attempts": s.attempts,
                        "elapsed_ms": s.elapsed_ms,
                    })
                })
                .collect();
            json!({
                "streams": run.streams,
                "bytes": run.bytes,
                "elapsed_ms": run.elapsed_ms,
                "mbs": run.mbs,
                "gbit": run.gbit,
                "per_shard": per_shard,
                "nodes": run
                    .nodes
                    .iter()
                    .map(|n| json!({
                        "id": n.id,
                        "kind": n.kind,
                        "inflight": n.inflight,
                        "successes": n.successes,
                        "failures": n.failures,
                    }))
                    .collect::<Vec<Value>>(),
            })
        })
        .collect();

    // Bound to locals so the macro never has to move a field out of `&Report`.
    let url = report.url.clone();
    let probe_value = serde_json::to_value(&report.probe)
        .map_err(|e| format!("cannot serialise the probe report: {e}"))?;

    let doc = json!({
        "url": url,
        "requested_bytes": report.requested_bytes,
        "content_length": report.content_length,
        "ranged": true,
        "probe": probe_value,
        "runs": runs,
        "speedup_vs_1": report.speedup(),
    });

    serde_json::to_string_pretty(&doc).map_err(|e| format!("cannot serialise the report: {e}"))
}

fn probe_json(probe: &CapabilityReport) -> Result<String, String> {
    serde_json::to_string_pretty(probe)
        .map_err(|e| format!("cannot serialise the probe report: {e}"))
}

// ---------------------------------------------------------------------------
// entry
// ---------------------------------------------------------------------------

/// Bytes fetched through each exit during calibration.
///
/// 2 MiB, not 256 KiB: a small probe is dominated by connection setup and TCP
/// slow start, which makes a fast path look slow. Measured 2026-11-04 — a
/// 256 KiB probe reported the direct path at 0.98 MB/s while the same path
/// moved 2 MiB at 5.3 MB/s, so the derived ratio over-weighted the slow exit
/// by ~3x. The probe must be big enough that its own ramp-up is not the answer.
const CALIBRATION_BYTES: u64 = 2 * 1024 * 1024;

/// Measure one exit's goodput with a small ranged fetch through that exit alone.
///
/// Returns `None` when the probe fails: the caller turns that into the floor
/// weight so the path stays in the plan and can fail visibly rather than being
/// silently dropped.
fn probe_exit_goodput(
    url: &str,
    spec: &str,
    target_len: u64,
    retries: u32,
    timeout_secs: u64,
) -> Option<f64> {
    let kind = if spec == "direct" {
        NodeKind::Direct
    } else if spec.starts_with("socks5://") {
        NodeKind::Socks5(spec.to_string())
    } else {
        NodeKind::Http(spec.to_string())
    };
    let pool = Arc::new(NodePool::new(vec![EgressNode {
        id: "probe".to_string(),
        kind,
        max_inflight: 1,
    }]));
    let fetcher = ProxiedFetcher::new(url.to_string(), Arc::clone(&pool));
    let bytes = CALIBRATION_BYTES.min(target_len);
    let plan = plan_shards(bytes, 1, 1).ok()?;
    let config = PoolConfig {
        streams: 1,
        retries,
        backoff_ms: DEFAULT_BACKOFF_MS,
        timeout_secs,
    };
    let started = Instant::now();
    let report = fetch_plan(&plan, &fetcher, &config).ok()?;
    let secs = started.elapsed().as_secs_f64();
    if secs <= 0.0 || report.total_bytes == 0 {
        return None;
    }
    Some(report.total_bytes as f64 / secs)
}

fn run(argv: &[String]) -> u8 {
    if argv
        .iter()
        .skip(1)
        .any(|a| a.as_str() == "-h" || a.as_str() == "--help")
    {
        println!("{USAGE}");
        return 0;
    }

    let args = match parse_args(argv) {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("egress-bench: {msg}");
            eprintln!();
            eprintln!("{USAGE}");
            return 2;
        }
    };

    let probe = probe_host();

    if args.probe_only {
        return match probe_json(&probe) {
            Ok(text) => match &args.json_path {
                Some(path) => match std::fs::write(path, &text) {
                    Ok(()) => {
                        eprintln!("egress-bench: wrote probe report to {}", path.display());
                        0
                    }
                    Err(e) => {
                        eprintln!("egress-bench: cannot write {}: {e}", path.display());
                        4
                    }
                },
                None => {
                    println!("{text}");
                    0
                }
            },
            Err(e) => {
                eprintln!("egress-bench: {e}");
                4
            }
        };
    }

    let client = match Client::builder()
        .timeout(Duration::from_secs(args.timeout_secs))
        .user_agent(concat!("egress-bench/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            eprintln!("egress-bench: cannot build the HTTP client: {e}");
            return 4;
        }
    };

    let discovered = match discover_length(&client, &args.url) {
        Ok(d) => d,
        Err(fail) => {
            eprintln!("egress-bench: {}", fail.text());
            return fail.code();
        }
    };
    let content_length = discovered.content_length;
    let target_len = args.bytes.min(content_length);

    let report = match measure(args.timeout_secs, &args, probe, content_length) {
        Ok(report) => report,
        Err(code) => return code,
    };

    let human = render_human(&report, target_len);
    let json_text = match json_report(&report) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("egress-bench: {e}");
            return 4;
        }
    };

    match &args.json_path {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &json_text) {
                eprintln!("egress-bench: cannot write {}: {e}", path.display());
                return 4;
            }
            print!("{human}");
            eprintln!("egress-bench: wrote JSON report to {}", path.display());
        }
        None => {
            // Keep stdout a single parseable JSON object.
            eprint!("{human}");
            println!("{json_text}");
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_accept_the_three_kinds() {
        let got = parse_nodes("direct, socks5://127.0.0.1:9050,http://10.0.0.1:3128")
            .expect("valid spec list");
        assert_eq!(
            got.join(","),
            "direct,socks5://127.0.0.1:9050,http://10.0.0.1:3128"
        );
    }

    #[test]
    fn nodes_reject_an_unknown_scheme() {
        let err = parse_nodes("ftp://example.org").expect_err("must be refused");
        assert!(
            err.contains("ftp://example.org"),
            "error must name the spec: {err}"
        );
    }

    #[test]
    fn nodes_reject_an_empty_list() {
        assert!(
            parse_nodes(" , ").is_err(),
            "an empty --nodes must be an error"
        );
    }

    #[test]
    fn weights_parse_in_order() {
        assert_eq!(parse_weights("10, 1").expect("parse"), vec![10, 1]);
    }

    #[test]
    fn weights_reject_zero() {
        let err = parse_weights("1,0").expect_err("must refuse");
        assert!(err.contains("at least 1"), "{err}");
    }

    #[test]
    fn weights_reject_empty() {
        assert!(parse_weights(" , ").is_err());
    }

    #[test]
    fn streams_still_sort_and_dedupe() {
        assert_eq!(parse_streams("8,1,8,4").expect("parse"), vec![1, 4, 8]);
    }
}
