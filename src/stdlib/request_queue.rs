//! Standard library: `tallow.request_queue` — request queue with dedup and batch ops.
//!
//! Inspired by Apify's Request Queue and Scrapy's scheduler.
//! In-memory queue with URL deduplication, distributed locking readiness,
//! and batch operations for high-throughput crawling.
//!
//! # Per-campaign compartmentation (G8 §1)
//! The global queue store is keyed by an optional campaign/tenant id in
//! addition to the queue name. A queue created with a `campaign` arg is stored
//! under `"<campaign>::<name>"`; one created without a campaign (the original
//! API) is stored under `"<name>"` — fully backward compatible. Two campaigns
//! can never see or mutate each other's queues, so a recovered queue can be
//! attributed to one campaign but never correlates others. By convention the
//! `campaign` value mirrors the compile-time `@opsec(profile:"X")` namespace
//! and the `BrowserSession::campaign_id` field.
//!
//! # API
//! - `RequestQueue.new(name, campaign?)` — create a new queue (optionally scoped to a campaign)
//! - `queue.add(url, priority?, metadata?)` — enqueue a URL
//! - `queue.add_batch(urls)` — enqueue batch with auto-dedup
//! - `queue.next()` — pop next URL (highest priority first)
//! - `queue.next_batch(count)` — pop batch
//! - `queue.size()` — remaining count
//! - `queue.processed()` — processed count
//! - `queue.mark_done(url)` — mark URL as processed
//! - `queue.clear()` — clear all

use super::StdlibResult;
use crate::interp::{type_name, Value};

use std::collections::{HashMap, BinaryHeap, HashSet};
use std::cmp::Ordering;
use std::sync::Mutex;

#[derive(Debug, Clone, Eq, PartialEq)]
struct QueueItem {
    priority: i32,
    url: String,
    metadata: String,
}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct RequestQueue {
    name: String,
    /// Optional campaign/tenant scope. When `Some`, this queue lives under the
    /// key `"<campaign>::<name>"` in the global store, isolating it from every
    /// other campaign. See module docs for the `@opsec` mapping.
    campaign: Option<String>,
    heap: BinaryHeap<QueueItem>,
    seen: HashSet<String>,
    processed: HashSet<String>,
    total_added: usize,
}

impl RequestQueue {
    #[allow(dead_code)] // constructor kept for future in-language queue creation
    fn new(name: &str) -> Self {
        RequestQueue::with_campaign(name, None)
    }

    fn with_campaign(name: &str, campaign: Option<String>) -> Self {
        RequestQueue {
            name: name.to_string(),
            campaign,
            heap: BinaryHeap::new(),
            seen: HashSet::new(),
            processed: HashSet::new(),
            total_added: 0,
        }
    }

    fn add(&mut self, url: &str, priority: i32, metadata: &str) -> bool {
        if self.seen.contains(url) || self.processed.contains(url) {
            return false;
        }
        self.seen.insert(url.to_string());
        self.total_added += 1;
        self.heap.push(QueueItem {
            priority,
            url: url.to_string(),
            metadata: metadata.to_string(),
        });
        true
    }

    fn add_batch(&mut self, urls: &[(String, Option<i32>)]) -> Value {
        let mut added = Vec::new();
        let mut skipped = Vec::new();
        for (url, prio) in urls {
            let p = prio.unwrap_or(0);
            if self.add(url, p, "") {
                added.push(Value::String(url.clone()));
            } else {
                skipped.push(Value::String(url.clone()));
            }
        }
        Value::Struct {
            name: "BatchResult".into(),
            fields: vec![
                ("added".into(), Value::Int(added.len() as i128)),
                ("skipped".into(), Value::Int(skipped.len() as i128)),
                ("added_urls".into(), Value::Array(added)),
                ("skipped_urls".into(), Value::Array(skipped)),
            ],
        }
    }

    fn next(&mut self) -> Option<QueueItem> {
        while let Some(item) = self.heap.pop() {
            if !self.processed.contains(&item.url) {
                return Some(item);
            }
        }
        None
    }

    fn next_batch(&mut self, count: usize) -> Vec<QueueItem> {
        let mut batch = Vec::new();
        for _ in 0..count {
            match self.next() {
                Some(item) => batch.push(item),
                None => break,
            }
        }
        batch
    }

    fn mark_done(&mut self, url: &str) {
        self.processed.insert(url.to_string());
    }

    fn size(&self) -> usize {
        self.heap.iter().filter(|item| !self.processed.contains(&item.url)).count()
    }

    fn processed_count(&self) -> usize {
        self.processed.len()
    }

    fn to_value(&self) -> Value {
        Value::Struct {
            name: "RequestQueue".into(),
            fields: vec![
                ("name".into(), Value::String(self.name.clone())),
                ("campaign".into(), self.campaign.clone().map(Value::String).unwrap_or(Value::String(String::new()))),
                ("pending".into(), Value::Int(self.size() as i128)),
                ("processed".into(), Value::Int(self.processed_count() as i128)),
                ("total_added".into(), Value::Int(self.total_added as i128)),
            ],
        }
    }
}

// In-memory store of named queues
// FIX12 (2026-08-27): converted `static mut` to a Mutex-wrapped static —
// edition-2024 denies mutable references to mutable statics, so the orphaned
// module could not compile once registered.
static QUEUES: std::sync::LazyLock<Mutex<HashMap<String, RequestQueue>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_queues() -> std::sync::MutexGuard<'static, HashMap<String, RequestQueue>> {
    QUEUES.lock().expect("request_queue registry lock poisoned")
}

/// Namespaced storage key for a queue: `"<campaign>::<name>"` when a campaign
/// is present, otherwise just `"<name>"` — identical to the pre-compartmentation
/// behavior, so existing un-scoped callers are fully backward compatible.
fn queue_key(campaign: Option<&str>, name: &str) -> String {
    match campaign {
        Some(c) if !c.is_empty() => format!("{c}::{name}"),
        _ => name.to_string(),
    }
}

/// Extract the optional `campaign` field from a `RequestQueue` value handle.
fn extract_campaign(value: &Value) -> Option<String> {
    match value {
        Value::Struct { fields, .. } => fields
            .iter()
            .find(|(n, _)| n == "campaign")
            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
            .filter(|s| !s.is_empty()),
        _ => None,
    }
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(rq_new(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "RequestQueue") {
        return None;
    }
    // Resolve the namespaced storage key from the queue handle. The key
    // carries the campaign scope, so a queue handle is bound to exactly one
    // campaign and can never touch another campaign's queue.
    let key = queue_key(extract_campaign(object).as_deref(), &extract_name(object));
    match method {
        "add" => Some(rq_add(&key, args)),
        "add_batch" => Some(rq_add_batch(&key, args)),
        "next" => Some(rq_next(&key)),
        "next_batch" => Some(rq_next_batch(&key, args)),
        "size" => Some(rq_size(&key)),
        "processed" => Some(rq_processed(&key)),
        "mark_done" => Some(rq_mark_done(&key, args)),
        "clear" => Some(rq_clear(&key)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "new")
}

fn rq_new(args: Vec<Value>) -> StdlibResult {
    let name = expect_first_str(&args, "name")?;
    // Optional 2nd argument: campaign/tenant id for per-campaign isolation.
    let campaign = args
        .get(1)
        .and_then(|v| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .filter(|s| !s.is_empty());
    let q = RequestQueue::with_campaign(name, campaign.clone());
    let val = q.to_value();
    let key = queue_key(campaign.as_deref(), name);
    get_queues().insert(key, q);
    Ok(val)
}

fn rq_add(qname: &str, args: Vec<Value>) -> StdlibResult {
    let url = expect_first_str(&args, "url")?;
    let priority = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as i32) } else { None }).unwrap_or(0);
    let metadata = args.get(2).and_then(|v| if let Value::String(s) = v { Some(s.as_str()) } else { None }).unwrap_or("");
    let mut queues = get_queues();
    match queues.get_mut(qname) {
        Some(q) => Ok(Value::Bool(q.add(url, priority, metadata))),
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_add_batch(qname: &str, args: Vec<Value>) -> StdlibResult {
    let urls: Vec<(String, Option<i32>)> = match &args[0] {
        Value::Array(arr) => arr.iter().map(|v| {
            match v {
                Value::String(s) => (s.clone(), None),
                Value::Struct { fields, .. } => {
                    let url = field_str(fields, "url");
                    let prio = field_int(fields, "priority");
                    (url, prio)
                }
                _ => (String::new(), None),
            }
        }).collect(),
        _ => return Err("add_batch: first argument must be an array of URLs or structs".into()),
    };
    let mut queues = get_queues();
    match queues.get_mut(qname) {
        Some(q) => Ok(q.add_batch(&urls)),
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_next(qname: &str) -> StdlibResult {
    let mut queues = get_queues();
    match queues.get_mut(qname) {
        Some(q) => match q.next() {
            Some(item) => Ok(Value::Struct {
                name: "QueueItem".into(),
                fields: vec![
                    ("url".into(), Value::String(item.url)),
                    ("priority".into(), Value::Int(item.priority as i128)),
                    ("metadata".into(), Value::String(item.metadata)),
                ],
            }),
            None => Ok(Value::Nil),
        },
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_next_batch(qname: &str, args: Vec<Value>) -> StdlibResult {
    let count = args.first().and_then(|v| if let Value::Int(i) = v { Some(*i as usize) } else { None }).unwrap_or(10);
    let mut queues = get_queues();
    match queues.get_mut(qname) {
        Some(q) => {
            let batch = q.next_batch(count);
            let items: Vec<Value> = batch.into_iter().map(|item| {
                Value::Struct {
                    name: "QueueItem".into(),
                    fields: vec![
                        ("url".into(), Value::String(item.url)),
                        ("priority".into(), Value::Int(item.priority as i128)),
                        ("metadata".into(), Value::String(item.metadata)),
                    ],
                }
            }).collect();
            Ok(Value::Array(items))
        }
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_size(qname: &str) -> StdlibResult {
    let queues = get_queues();
    match queues.get(qname) {
        Some(q) => Ok(Value::Int(q.size() as i128)),
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_processed(qname: &str) -> StdlibResult {
    let queues = get_queues();
    match queues.get(qname) {
        Some(q) => Ok(Value::Int(q.processed_count() as i128)),
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_mark_done(qname: &str, args: Vec<Value>) -> StdlibResult {
    let url = expect_first_str(&args, "url")?;
    let mut queues = get_queues();
    match queues.get_mut(qname) {
        Some(q) => {
            q.mark_done(url);
            Ok(Value::Nil)
        }
        None => Err(format!("Queue not found: {qname}")),
    }
}

fn rq_clear(qname: &str) -> StdlibResult {
    let mut queues = get_queues();
    queues.remove(qname);
    Ok(Value::Bool(true))
}

fn extract_name(value: &Value) -> String {
    match value {
        Value::Struct { fields, .. } => field_str(fields, "name"),
        _ => String::new(),
    }
}

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn field_int(fields: &[(String, Value)], name: &str) -> Option<i32> {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::Int(i) = v { Some(*i as i32) } else { None })
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name} argument")),
    }
}
