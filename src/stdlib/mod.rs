//! Standard library dispatch infrastructure.
//!
//! Central router that delegates stdlib function calls to per-module
//! dispatch functions. Each module exports `dispatch()` and `dispatch_method()`.

use crate::interp::Value;

/// Result type for all stdlib dispatch functions.
pub type StdlibResult = Result<Value, String>;

pub mod browser;
pub mod algos;
pub mod cnam_dip;
pub mod compress;
pub mod copy;
pub mod copy_engine;
pub mod crypto;
#[cfg(feature = "stealth-http")]
pub mod stealth_http;
pub mod deals;
pub mod docs;
pub mod edgar;
pub mod env;
pub mod filter;
pub mod filings;
pub mod forensics;
pub mod fs;
pub mod html;
pub mod http;
pub mod io_backend;
pub mod json;
pub mod log;
pub mod lrn_dip;
pub mod market;
pub mod math;
pub mod mesh;
// Sitescan module (2026-09-12): comprehensive website + infrastructure scanning
pub mod sitescan;
pub mod net;
pub mod osint;
pub mod phone_osint;
pub mod platform;
pub mod process;
pub mod rand;
pub mod regex;
pub mod rmdb_store;
pub mod sync;
pub mod time;
pub mod transfer;
pub mod transfer_net;
pub mod relay_room;
pub mod url;
pub mod beehiiv;
pub mod medium;
pub mod substack;
pub mod cxense;
pub mod wordpress;
pub mod ghost;
pub mod oauth;
pub mod jwt;
pub mod sso;
pub mod legal;
pub mod secrets;
pub mod escalation;
pub mod azure_app_proxy;
// ── FIX12 stdlib triage: orphaned modules registered (2026-08-27) ──
pub mod csv;
pub mod curves;
pub mod decimal;
pub mod finance;
pub mod fred;
pub mod ohlcv;
pub mod options;
pub mod technical;
pub mod orders;
pub mod portfolio2;
pub mod positions;
pub mod sentiment;
pub mod timeseries;
pub mod yahoo;
pub mod markdown;
pub mod agent;
pub mod agentic;
pub mod cli;
pub mod config;
pub mod email;
pub mod test;
pub mod captcha;
pub mod cookie_jar;
pub mod csrf;
pub mod extract;
pub mod mime;
pub mod otp;
pub mod fingerprint;
pub mod frame;
pub mod graphql;
pub mod ocr;
pub mod pdf;
pub mod rate_limit;
pub mod request_queue;
pub mod scenarios;
pub mod session;
pub mod tls_profile;
pub mod turnstile;
pub mod warmup;
pub mod ws;
pub mod cloud;
pub mod detection;
pub mod iot;
pub mod otel;
pub mod pec;
pub mod safety;
pub mod path_util;
// ── FIX13 stdlib registration: last 3 honest-marked modules (2026-08-27) ──
pub mod heston;
pub mod spotify;
pub mod db;
pub mod db_support;
// ── Research modules (2026-09-04): recordlink, sourcegrade, geocode ──
pub mod recordlink;
pub mod sourcegrade;
pub mod geocode;
// ── Entity resolution / record linkage (roadmap #4, 2026-09-05) ──
pub mod entity;
// ── Provenance module (2026-09-05): collection-level provenance + grading ──
pub mod provenance;
// ── Jobs module (roadmap #3 stage 1, 2026-09-05): in-language scheduling
// bridge to the real scheduler (ScheduleStore/ScheduledJob in
// src/browser/scheduler.rs). Subprocess execution for now; stage-2
// warm-interpreter runner out of scope.
pub mod jobs;
// ── Advisory feed module (C5, 2026-09): local JSON vulnerability-advisory
// feed (env TALLOW_ADVISORY_FILE) consumed by audit --cra/--nis2. ──
pub mod advisory;

/// Dispatch a stdlib function call by module and function name.
///
/// Returns `Some(Ok(value))` on success, `Some(Err(msg))` if the function
/// is known but failed, or `None` if the module/function is not recognized
/// (allowing the caller to fall through to other dispatch mechanisms).
pub fn dispatch(module: &str, function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match module {
        "algos" => algos::dispatch(function, args),
        "browser" => browser::dispatch(function, args),
        "compress" => compress::dispatch(function, args),
        "copy" => copy::dispatch(function, args),
        "crypto" => crypto::dispatch(function, args),
        "deals" => deals::dispatch(function, args),
        "docs" => docs::dispatch(function, args),
        "edgar" => edgar::dispatch(function, args),
        "env" => env::dispatch(function, args),
        "filter" => filter::dispatch(function, args),
        "filings" => filings::dispatch(function, args),
        "forensics" => forensics::dispatch(function, args),
        "fs" => fs::dispatch(function, args),
        "html" => html::dispatch(function, args),
        "http" => http::dispatch(function, args),
        "json" => json::dispatch(function, args),
        "log" => log::dispatch(function, args),
        "market" => market::dispatch(function, args),
        "math" => math::dispatch(function, args),
        "mesh" => mesh::dispatch(function, args),
        "MeshNode" => mesh::dispatch(function, args),
        // Sitescan (2026-09-12): comprehensive website + infrastructure scanning
        "sitescan" => sitescan::dispatch(function, args),
        "net" => net::dispatch(function, args),
        "osint" => osint::dispatch(function, args),
        // Capitalized OSINT type namespaces route through osint dispatch with full name
        "Target" | "TechStack" | "DomainIntel" | "ASNIntel" | "EmailIntel" | "IntelGraph"
        | "IntelReport" | "Scanner" | "ScanScope" | "IOCEnrichment" | "WebArchive" | "ScanDB" => {
            osint::dispatch(&format!("{module}.{function}"), args)
        }
        // Phone OSINT namespace: PhoneNumber.lookup / .resolve_owner / .reputation / ...
        "PhoneNumber" => osint::dispatch(&format!("PhoneNumber.{function}"), args),
        // Phase 38: Digital Forensics & STIX type namespaces
        "EvidenceChain" | "MemoryDump" | "DiskImage" | "FileCarver" | "NetworkCapture"
        | "VolatileData" | "StixBundle" | "AttackTechnique" => {
            forensics::dispatch(&format!("{module}.{function}"), args)
        }
        "process" => process::dispatch(function, args),
        "rand" => rand::dispatch(function, args),
        "regex" => regex::dispatch(function, args),
        "time" => time::dispatch(function, args),
        "transfer" => transfer::dispatch(function, args),
        "transfer_net" => transfer_net::dispatch(function, args),
        // Stage 3 / Slice 2: RelayRoom sessions on the SendTallow product relay (WS wire)
        "relay_room" | "relayroom" | "RelayRoom" => relay_room::dispatch(function, args),
        // Phase 59: QuicTransfer QUIC file transfer
        "QuicTransfer" => transfer_net::dispatch(function, args),
        // Phase 60: Code phrase, relay, resume
        "TransferCode" | "Relay" => transfer_net::dispatch(function, args),
        // Phase 61: Multi-file, folder, compression, parallel, bandwidth, watch
        "MultiTransfer" | "TransferCompress" | "ParallelConfig" | "BandwidthConfig"
        | "WatchSession" => transfer_net::dispatch(function, args),
        // Phase 55: TallowTransfer type namespaces route through transfer dispatch
        "Transfer" | "FileCopy" | "FileVault" | "DeltaSync" | "Compress" => {
            transfer::dispatch(&format!("{module}.{function}"), args)
        }
        // Phase 56: TallowTransfer Network type namespaces
        "TransferSession" | "TransferStream" | "ErasureCode" | "NetworkPath" => {
            transfer::dispatch(&format!("{module}.{function}"), args)
        }
        // Phase 57: Peer/Swarm/DHT/Manifest type namespaces
        "Peer" | "Swarm" | "Dht" | "Manifest" => {
            transfer::dispatch(&format!("{module}.{function}"), args)
        }
        "url" => url::dispatch(function, args),
        "sync" => sync::dispatch(function, args),
        "beehiiv" => beehiiv::dispatch(function, args),
        "medium" => medium::dispatch(function, args),
        "cxense" => cxense::dispatch(function, args),
        "substack" => substack::dispatch(function, args),
        "wordpress" => wordpress::dispatch(function, args),
        "ghost" => ghost::dispatch(function, args),
        "oauth" => oauth::dispatch(function, args),
        "jwt" => jwt::dispatch(function, args),
        "sso" => sso::dispatch(function, args),
        "escalation" => escalation::dispatch(function, args),
        // legal: @legal runtime — honest contract dispatch (legal.rs)
        "legal" => legal::dispatch(function, args),
        // secrets: SecretStore key-value store (capitalized "SecretStore"
        // normalizes to "secretstore"; lowercase "secrets" also accepted)
        "secrets" | "secretstore" => secrets::dispatch(function, args),
        "azure_app_proxy" => azure_app_proxy::dispatch(function, args),
        // ── FIX12 stdlib triage: orphaned modules registered (2026-08-27) ──
        "csv" => csv::dispatch(function, args),
        "curves" => curves::dispatch(function, args),
        "decimal" => decimal::dispatch(function, args),
        "finance" => finance::dispatch(function, args),
        "fred" => fred::dispatch(function, args),
        "ohlcv" => ohlcv::dispatch(function, args),
        "options" => options::dispatch(function, args),
        "technical" => technical::dispatch(function, args),
        "orders" => orders::dispatch(function, args),
        "portfolio2" => portfolio2::dispatch(function, args),
        "positions" => positions::dispatch(function, args),
        "sentiment" => sentiment::dispatch(function, args),
        "timeseries" => timeseries::dispatch(function, args),
        "yahoo" => yahoo::dispatch(function, args),
        "markdown" => markdown::dispatch(function, args),
        "agent" => agent::dispatch(function, args),
        "agentic" => agentic::dispatch(function, args),
        "cli" => cli::dispatch(function, args),
        "config" => config::dispatch(function, args),
        "email" => email::dispatch(function, args),
        "test" => test::dispatch(function, args),
        "captcha" => captcha::dispatch(function, args),
        "cookie_jar" => cookie_jar::dispatch(function, args),
        "csrf" => csrf::dispatch(function, args),
        "extract" | "Extract" => extract::dispatch(function, args),
        "mime" => mime::dispatch(function, args),
        "otp" => otp::dispatch(function, args),
        "fingerprint" => fingerprint::dispatch(function, args),
        "frame" => frame::dispatch(function, args),
        "graphql" => graphql::dispatch(function, args),
        "ocr" => ocr::dispatch(function, args),
        "pdf" => pdf::dispatch(function, args),
        "rate_limit" => rate_limit::dispatch(function, args),
        "request_queue" => request_queue::dispatch(function, args),
        "scenarios" => scenarios::dispatch(function, args),
        "session" => session::dispatch(function, args),
        "tls_profile" => tls_profile::dispatch(function, args),
        "turnstile" => turnstile::dispatch(function, args),
        "warmup" => warmup::dispatch(function, args),
        "ws" => ws::dispatch(function, args),
        // P1-fix (2026-09-16): class-style namespaces for single-file stdlib
        // modules — `CookieJar.new()` etc. build the full "Type.method" name
        // via the interp sentinel and land here (static/constructor surface).
        "CookieJar" => cookie_jar::dispatch(function, args),
        "RateLimiter" => rate_limit::dispatch(function, args),
        "TLSProfile" => tls_profile::dispatch(function, args),
        "WS" => ws::dispatch(function, args),
        "Inbox" => email::dispatch(function, args),
        "CAPTCHA" => captcha::dispatch(function, args),
        // Sentinel modules: dispatch returns None by design; interp.rs handles inline
        "cloud" => cloud::dispatch(function, args),
        "detection" => detection::dispatch(function, args),
        "iot" => iot::dispatch(function, args),
        "otel" => otel::dispatch(function, args),
        "pec" => pec::dispatch(function, args),
        "safety" => safety::dispatch(function, args),
        "path_util" => path_util::dispatch(function, args),
        // ── FIX13 stdlib registration: last 3 honest-marked modules (2026-08-27) ──
        // heston/spotify: real dispatch. db: honest bridge — connection-open
        // arms return Err("db bridge requires interp support"); "connect" is
        // intentionally NOT an arm so the live inline db.connect handler in
        // interp.rs (line ~11157) keeps serving .tl scripts (FIX12 invariant).
        "heston" => heston::dispatch(function, args),
        "spotify" => spotify::dispatch(function, args),
        "db" => db::dispatch(function, args),
        // ── Research modules (2026-09-04) ──
        "recordlink" | "Recordlink" => recordlink::dispatch(function, args),
        "sourcegrade" | "Sourcegrade" => sourcegrade::dispatch(function, args),
        "geocode" | "Geocode" => geocode::dispatch(function, args),
        // Entity resolution / record linkage (roadmap #4, 2026-09-05)
        "entity" | "Entity" => entity::dispatch(function, args),
        // Provenance module (2026-09-05): lowercase key plus capitalized
        // "Provenance" namespace (resolves via interp lowercase fallback,
        // routed directly here for exact-match callers).
        "provenance" | "Provenance" => provenance::dispatch(function, args),
        // Jobs module (roadmap #3 stage 1, 2026-09-05): lowercase "jobs"
        // plus capitalized "Jobs" namespace (interp lowercases module names
        // before routing, so both arrive here as "jobs").
        "jobs" | "Jobs" => jobs::dispatch(function, args),
        // Advisory feed (C5, 2026-09-05): vulnerability advisories from a
        // local JSON file (env TALLOW_ADVISORY_FILE); honest Err when no
        // feed is configured.
        "advisory" | "Advisory" => advisory::dispatch(function, args),
        _ => None,
    }
}

/// Returns true if `module` is a registered stdlib dispatch module.
///
/// Mirrors the `match module` arms in [`dispatch`] so the interpreter can
/// resolve bare `module.func` namespaces for every registered module
/// (FIX12 triage added 56 modules to the router but not to interp.rs's
/// hardcoded lowercase-namespace list — this is the single source of truth).
pub fn is_registered_module(module: &str) -> bool {
    matches!(module,
        // Core + original modules
        "algos" | "browser" | "compress" | "copy" | "crypto" | "deals" | "docs" | "edgar"
        | "env" | "filter" | "filings" | "forensics" | "fs" | "html" | "http"
        | "json" | "log" | "market" | "math" | "mesh" | "net" | "osint" | "process" | "rand"
        | "regex" | "time" | "transfer" | "transfer_net" | "url" | "sync" | "beehiiv"
        | "relay_room" | "relayroom"
        | "medium" | "cxense" | "substack" | "wordpress" | "ghost" | "oauth" | "jwt" | "sso"
        | "escalation" | "legal" | "azure_app_proxy"
        // FIX12 stdlib triage modules (2026-08-27)
        | "csv" | "curves" | "decimal" | "finance" | "fred" | "ohlcv" | "options" | "technical"
        | "orders" | "portfolio2" | "positions" | "sentiment" | "timeseries" | "yahoo"
        | "markdown" | "agent" | "agentic" | "cli" | "config" | "email" | "test" | "captcha"
        | "cookie_jar" | "csrf" | "extract" | "Extract" | "mime" | "otp" | "fingerprint" | "frame"
        | "graphql" | "ocr" | "pdf" | "rate_limit" | "request_queue" | "scenarios" | "session"
        | "tls_profile" | "turnstile" | "warmup" | "ws" | "cloud" | "detection" | "iot"
        | "otel" | "pec" | "safety" | "path_util"
        // FIX13 modules (2026-08-27)
        | "heston" | "spotify" | "db"
        // Research modules (2026-09-04)
        | "recordlink" | "sourcegrade" | "geocode"
        // Entity resolution / record linkage (roadmap #4, 2026-09-05)
        | "entity"
        // Provenance module (2026-09-05)
        | "provenance" | "Provenance"
        // Sitescan module (2026-09-12)
        | "sitescan"
        // Aliases routed in dispatch
        | "secretstore"
        // Capitalized type namespaces routed through dispatch
        | "MeshNode" | "QuicTransfer" | "Target" | "TechStack" | "DomainIntel" | "ASNIntel"
        | "EmailIntel" | "IntelGraph" | "IntelReport" | "Scanner" | "ScanScope" | "IOCEnrichment"
        | "WebArchive" | "ScanDB" | "EvidenceChain" | "MemoryDump" | "DiskImage" | "FileCarver"
        | "NetworkCapture" | "VolatileData" | "StixBundle" | "AttackTechnique" | "Transfer"
        | "FileCopy" | "FileVault" | "DeltaSync" | "Compress" | "TransferSession"
        | "TransferStream" | "ErasureCode" | "NetworkPath" | "Peer" | "Swarm" | "Dht"
        | "Manifest" | "TransferCode" | "Relay" | "MultiTransfer" | "TransferCompress"
        | "ParallelConfig" | "BandwidthConfig" | "WatchSession"
        // Jobs module (roadmap #3 stage 1, 2026-09-05)
        | "jobs" | "Jobs"
        // Advisory feed (C5, 2026-09-05)
        | "advisory" | "Advisory")
}

/// Dispatch a method call on a stdlib object type.
///
/// Matches on the struct name of `Value::Struct` variants to route
/// method calls to the appropriate module. Returns `None` if the
/// object type is not a stdlib type.
///
/// Phase 11: All arms are placeholders returning None.
/// Phase 12-13 will add: FileInfo, JsonValue, Timestamp, Duration,
/// UrlParts, Regex, HttpClient, Process.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    // Int-backed stdlib types. `Timestamp` (epoch millis, from `time.now`/`time.parse_iso`) and
    // `Duration` (nanos) are declared as `struct`s in `stdlib/*.tl` but are plain Ints at runtime,
    // so a name-only struct match can never reach them — which is why every method declared
    // `// native:` in `stdlib/time.tl` was unreachable and died with
    // `unknown method: .to_iso() on int` while the implementation sat unused below.
    // `time` answers only its own instant methods and returns None otherwise, so this cannot
    // shadow the built-in Int methods: the interpreter tries this dispatcher first, and a `None`
    // here falls through to the built-in match exactly as before.
    if matches!(object, Value::Int(_)) {
        if let Some(result) = time::dispatch_method(object, method, args.clone()) {
            return Some(result);
        }
    }
    if let Value::Struct { name, .. } = object {
        match name.as_str() {
            // `url.parse` returns a struct named `URL`, but nothing ever routed that name here —
            // so every `URL` method declared `// native:` in stdlib/url.tl was unreachable (and
            // `u.to_string()` was silently answered by the interpreter's generic display-based
            // arm). The name is the dispatch key, exactly as for the types below.
            "URL" => url::dispatch_method(object, method, args),
            "FileInfo" => fs::dispatch_method(object, method, args),
            "FilterFileInfo" | "FilterProfile" | "FilterResult" | "FilterPredicate" => {
                filter::dispatch_method(object, method, args)
            }
            "FsWatcher" => fs::dispatch_method(object, method, args),
            "HtmlDocument" => html::dispatch_method(object, method, args),
            "HtmlElement" => html::dispatch_method(object, method, args),
            // json and url types are handled inline in interp.rs. `time` is NOT one of them any
            // more: its Int-backed receivers are routed above (see the note there).
            "Regex" => regex::dispatch_method(object, method, args),
            "HttpListener" | "Response" => http::dispatch_method(object, method, args),
            "ChildProcess" => process::dispatch_method(object, method, args),
            "IntelGraph" | "IntelEntity" | "IntelEdge" | "IntelReport" | "Finding" | "Target"
            | "SubdomainResult" | "TechStack" | "Technology" | "Provenance" | "DomainIntel"
            | "ASNIntel" | "EmailIntel" | "DocumentMeta" | "SpfResult" | "DmarcResult"
            | "BreachResult" | "ScanScope" | "ScanResult" | "IOCEnrichment"
            | "EnrichmentResult" | "WebArchive" | "Snapshot" | "ScanDB" | "ScanRecord" => {
                osint::dispatch_method(object, method, args)
            }
            // Phase 38: Digital Forensics struct types
            "EvidenceChain" | "EvidenceEntry" | "MemoryDump" | "DiskImage" | "CarvedFile"
            | "NetworkCapture" | "VolatileData" | "StixBundle" | "StixObject"
            | "AttackTechnique" | "Connection" | "ProcessInfo" => {
                forensics::dispatch_method(object, method, args)
            }
            // Phase 02: Copy + Verification engine struct types
            "CopyStats" | "MerkleTree" => copy::dispatch_method(object, method, args),
            // Phase 55: TallowTransfer struct types
            "ChunkInfo"
            | "FileEntry"
            | "DeltaResult"
            | "EncryptResult"
            | "DecryptResult"
            | "CompressibilityResult"
            | "ManifestInfo" => transfer::dispatch_method(object, method, args),
            // Phase 56: TallowTransfer Network struct types
            "TransferSession" | "TransferStream" | "TransferProgress" | "ErasureEncoded"
            | "ErasureDecoded" | "ErasureStatus" | "NetworkPath" | "PathEstimate" => {
                transfer::dispatch_method(object, method, args)
            }
            // Phase 57: Peer/Swarm/DHT struct types
            "Peer" | "AnnounceResult" | "Swarm" | "SwarmStatus" | "Schedule" | "Assignment"
            | "DhtNode" | "DhtAnnounce" | "DhtLookup" => {
                transfer::dispatch_method(object, method, args)
            }
            // Phase 59: QuicTransfer struct types
            "QuicServer" | "QuicConnection" | "QuicStatus" | "TransferResult" | "ReceiveResult"
            | "SendResult" => transfer_net::dispatch_method(object, method, args),
            // Phase 60: Code phrase, relay, resume struct types
            "TransferCode" | "CodeSession" | "RelayServer" | "RelaySendResult"
            | "RelayReceiveResult" => transfer_net::dispatch_method(object, method, args),
            // Phase 61: Multi-file, folder, compression, parallel, bandwidth, watch struct types
            "MultiTransferResult"
            | "DirTransferResult"
            | "CompressedTransfer"
            | "ParallelConfig"
            | "BandwidthConfig"
            | "WatchSession"
            | "WatchChanges"
            | "WatchEntry" => transfer_net::dispatch_method(object, method, args),
            // Document generator struct types
            "ExcelWorkbook" | "ExcelSheet" | "WordDocument" | "DocElement" => {
                docs::dispatch_method(object, method, args)
            }
            "BrowserSurfaceManifest" | "BrowserSurfaceEntry" | "BrowserPipeTransportStatus"
            | "BrowserFallbackBoundary" | "BrowserFallbackServiceStatus" => {
                browser::dispatch_method(object, method, args)
            }
            "MeshNode" | "PeerInfo" => mesh::dispatch_method(object, method, args),
            "GrpcServer" => net::dispatch_method(object, method, args),
            "GrpcClient" => net::dispatch_method(object, method, args),
            "QuicStream" => net::dispatch_method(object, method, args),
            // P1-fix (2026-09-16): both WebSocket shapes exist — net.ws_connect
            // structs (registry-backed, _ws_id field) and ws.connect structs
            // (RFC6455 client in ws.rs). Try the registry impl, then ws.rs.
            "WebSocket" => match net::dispatch_method(object, method, args.clone()) {
                Some(result) => Some(result),
                None => ws::dispatch_method(object, method, args),
            },
            "RelayRoom" | "RelayEvent" | "RelaySendOutcome" => {
                relay_room::dispatch_method(object, method, args)
            }
            "PacketCapture" => net::dispatch_method(object, method, args),
            "TorPool" => net::dispatch_method(object, method, args),
            "ProxyChain" => net::dispatch_method(object, method, args),
            "Tunnel" => net::dispatch_method(object, method, args),
            "OnionAddr" => net::dispatch_method(object, method, args),
            "TrafficShape" => net::dispatch_method(object, method, args),
            "Transport" => net::dispatch_method(object, method, args),
            "TcpServer" => net::dispatch_method(object, method, args),
            "UdpServer" => net::dispatch_method(object, method, args),
            "TcpConnection" => net::dispatch_method(object, method, args),
            // Sync concurrency primitives
            "SyncMutex" | "SyncRwLock" | "SyncBarrier" | "SyncOnce" | "AtomicI64" | "WaitGroup" => {
                sync::dispatch_method(object, method, args)
            }
            // SecretStore struct methods (set/get/delete/list/export)
            "SecretStore" => secrets::dispatch_method(object, method, args),
            // Phase 7 — Sync engine file sync structs
            "SyncPair" | "SyncStatus" | "SyncFileEntry" | "MeshConfig"
            | "Resolution" | "SyncHistoryEntry" => {
                sync::dispatch_method(object, method, args)
            }
            // FIX12 stdlib triage: orphaned modules registered (2026-08-27)
            "Alert" | "Playbook" => agent::dispatch_method(object, method, args),
            "App" | "Command" | "Context" | "Flag" => cli::dispatch_method(object, method, args),
            "CsrfSession" => csrf::dispatch_method(object, method, args),
            "Inbox" | "GuerrillaInbox" => email::dispatch_method(object, method, args),
            // P1-fix (2026-09-16): single-file stdlib object types — these carry
            // .tl declarations but had no dispatch_method routing, so object
            // calls (`jar.add(...)`, `tls.to_curl_args()`) never resolved.
            "CookieJar" => cookie_jar::dispatch_method(object, method, args),
            "RateLimiter" => rate_limit::dispatch_method(object, method, args),
            "TLSProfile" => tls_profile::dispatch_method(object, method, args),
            "CaptchaChallenge" => captcha::dispatch_method(object, method, args),
            "Token" => oauth::dispatch_method(object, method, args),
            // FIX12 batch 4: frame/graphql/ocr/pdf struct methods
            "Frame" => frame::dispatch_method(object, method, args),
            "GraphqlResult" => graphql::dispatch_method(object, method, args),
            "OcrTable" => ocr::dispatch_method(object, method, args),
            "PdfPage" => pdf::dispatch_method(object, method, args),
            // FIX12 batch 5: turnstile/warmup + sentinel type methods
            "TurnstileSolution" => turnstile::dispatch_method(object, method, args),
            "WarmupResult" => warmup::dispatch_method(object, method, args),
            "IacResult" | "IacFinding" | "CloudPolicy" | "PolicyResult" => {
                cloud::dispatch_method(object, method, args)
            }
            "SigmaRule" => detection::dispatch_method(object, method, args),
            "OtaPackage" => iot::dispatch_method(object, method, args),
            "HealthCheck" => otel::dispatch_method(object, method, args),
            "MigratedData" => pec::dispatch_method(object, method, args),
            "IcsSimulator" => safety::dispatch_method(object, method, args),
            // Collection-level provenance records (2026-09-05)
            "CollectionRecord" => provenance::dispatch_method(object, method, args),
            _ => None,
        }
    } else {
        let _ = method;
        let _ = args;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_module_dispatch_returns_some() {
        // fs.read_file is now implemented — returns an error for missing file (not "not yet")
        let result = dispatch(
            "fs",
            "read_file",
            vec![Value::String("__nonexistent__.txt".into())],
        );
        assert!(result.is_some(), "fs.read_file should be routable");
        let err = result.unwrap();
        assert!(err.is_err(), "reading nonexistent file should return Err");
        assert!(
            err.unwrap_err().contains("fs.read_file"),
            "error should mention fs.read_file"
        );
    }

    #[test]
    fn unknown_module_dispatch_returns_none() {
        let result = dispatch("unknown_module", "anything", vec![]);
        assert!(result.is_none(), "unknown module should return None");
    }

    #[test]
    fn unknown_function_in_known_module_returns_none() {
        let result = dispatch("fs", "nonexistent_function", vec![]);
        assert!(result.is_none(), "unknown function should return None");
    }

    #[test]
    fn stub_functions_return_not_yet_implemented() {
        // Functions that have NO inline interp.rs implementation — these return
        // Some(Err("not yet implemented")) to give users a descriptive error.
        // net.connect and http.server are now fully implemented — they are
        // routable (return Some) and no longer carry a "not yet implemented"
        // error message.
        //
        // net.connect with no args → Some(Err("missing argument"))
        let result = dispatch("net", "connect", vec![]);
        assert!(result.is_some(), "net.connect should be routable");
        assert!(
            result.unwrap().is_err(),
            "net.connect with no args should return Err"
        );

        // http.server is now routed to http_listen — verify it is routable.
        // Actual binding may fail in CI (port in use), but it should not return None.
        let result = dispatch("http", "server", vec![Value::Int(0)]); // port 0 = OS picks free port
        assert!(result.is_some(), "http.server should be routable");
    }

    #[test]
    fn inline_implemented_functions_fall_through() {
        // Functions already implemented inline in interp.rs — these return
        // None so the call falls through to the existing match block.
        let inline = [
            ("fs", "exists"),
            ("math", "sqrt"),
            // time.now now intercepted by stdlib (Phase 12-03, returns millis)
            ("env", "get"),
            ("log", "info"),
            ("json", "parse"),
            ("url", "parse"),
        ];

        for (module, function) in &inline {
            let result = dispatch(module, function, vec![]);
            assert!(
                result.is_none(),
                "{module}.{function} has inline impl — should return None for fallthrough"
            );
        }
    }

    #[test]
    fn dispatch_method_returns_none_for_non_stdlib_types() {
        let result = dispatch_method(&Value::String("test".into()), "method", vec![]);
        assert!(
            result.is_none(),
            "dispatch_method should return None for String values"
        );
    }

    #[test]
    fn dispatch_method_returns_none_for_unknown_struct() {
        let result = dispatch_method(
            &Value::Struct {
                name: "UnknownStruct".to_string(),
                fields: vec![],
            },
            "method",
            vec![],
        );
        assert!(
            result.is_none(),
            "dispatch_method should return None for unknown struct types"
        );
    }
}
