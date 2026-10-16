use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use tallow::browser::{BrowserPool, PoolConfig};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod datadome;
mod engine;
mod routes;

/// Central application state shared across all request handlers.
pub struct AppState {
    pub config: config::Config,
    pub start_time: Instant,
    pub pool: Arc<BrowserPool>,
    pub tor_pool: Arc<BrowserPool>,
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[derive(Parser)]
#[command(name = "tallow-reader", version, about = "Protected Tallow extraction daemon")]
struct Cli {
    /// Max concurrent browser instances in each warm pool (direct + Tor).
    #[arg(long, default_value_t = 4)]
    pool_size: usize,
}

/// The box's Tor SOCKS endpoint. The daemon has always spoken to the system
/// Tor on 9050; only the *identity* carried in the URL changed (see
/// [`identity_mint`]).
const TOR_SOCKS_PORT: u16 = 9050;

/// Per-launch egress identity for a warm pool (W1-E4).
///
/// Both pools previously carried a bare `socks5://127.0.0.1:9050`: one
/// credential-less URL shared by every browser and every task, i.e. a single
/// box-wide Tor circuit for the whole daemon — and a relaunched slot inherited
/// the circuit its predecessor had used.
///
/// `isolated_proxy_url` mints fresh `IsolateSOCKSAuth` credentials on every
/// call, so every launch gets its own circuit. The credentials are also what
/// make the engine's socks relay engage: Chromium cannot present SOCKS5
/// credentials (it fails navigation with `ERR_NO_SUPPORTED_PROXIES`, found on
/// the first live extraction, 2026-09-28), so `BrowserProcess::launch` sees the
/// userinfo, spawns a loopback relay and re-originates upstream with them
/// (`browser::socks_shim`). A credential-less URL silently falls back to the
/// shared circuit, which is exactly the state this replaces.
///
/// Residual: identity is per browser *launch*, not per request — a warm slot
/// serves up to `max_tasks_per_instance` tasks on the circuit it launched
/// with. Lower that to tighten the granularity, at the cost of a browser start.
fn identity_mint(pool: &'static str) -> tallow::browser::pool::ProxyMint {
    tallow::browser::pool::ProxyMint::new(move |slot: usize| {
        Some(tallow::tor::pool::isolated_proxy_url(
            &format!("tallow-reader-{pool}-{slot}"),
            TOR_SOCKS_PORT,
        ))
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tallow_reader=info")),
        )
        .init();

    // Load config (generates 64-hex bearer token on first run, 0600 perms)
    let mut cfg = config::Config::load_or_create()?;
    tracing::info!("Config loaded. Data dir: {:?}", cfg.data_dir);

    // Base browser config: headless + launch-level stealth flags. JS-level
    // evasion is applied per-page via StealthProfile in the engine.
    let stealth_browser = tallow::browser::BrowserConfig {
        stealth: true,
        ..Default::default()
    };

    // Default egress pool. NOTE (2026-09-28): this pool was originally
    // "direct (clear IP)", but the T-207 browser-zone lockdown resolves an
    // unproxied Chrome launch to the contract proxy, so the pool has always
    // ridden Tor. Consequence: `anon=false` no longer yields a clear-IP
    // origin — direct browser egress is zone-refused by policy — see the
    // 2026-09-28 deploy receipt.
    //
    // NOTE (2026-10-12): it used to ride the *bare* endpoint
    // (`socks5://127.0.0.1:9050`) — one credential-less URL for every browser
    // and every task. `identity_mint` replaces that with a fresh per-launch
    // identity; see its docs for why the credentials, not just the URL, are
    // what engage the engine's per-launch socks relay.
    let default_pool_config = PoolConfig {
        max_size: cli.pool_size,
        browser_config: stealth_browser.clone(),
        proxy_mint: Some(identity_mint("direct")),
        recycle_on_release: true,
        ..Default::default()
    };
    let pool = Arc::new(BrowserPool::new(default_pool_config).await?);

    // Tor egress pool (proxy-backed; selected per-request when anon=true).
    // Instances are created lazily on first acquire, so Tor only has to be up
    // when an anon request actually arrives.
    let tor_pool_config = PoolConfig {
        max_size: cli.pool_size,
        browser_config: stealth_browser,
        proxy_mint: Some(identity_mint("tor")),
        recycle_on_release: true,
        ..Default::default()
    };
    let tor_pool = Arc::new(BrowserPool::new(tor_pool_config).await?);

    tracing::info!(
        "Browser pools ready (direct max_size={}, tor max_size={})",
        cli.pool_size,
        cli.pool_size
    );

    // Shutdown channel (Ctrl-C or POST /shutdown)
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let state = Arc::new(AppState {
        config: cfg.clone(),
        start_time: Instant::now(),
        pool: Arc::clone(&pool),
        tor_pool: Arc::clone(&tor_pool),
        shutdown_tx: shutdown_tx.clone(),
    });

    let app = routes::create_router(state);

    // Bind to a random available port on 127.0.0.1 only (no network exposure).
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    cfg.port = local_addr.port();
    cfg.bind_addr = format!("127.0.0.1:{}", cfg.port);

    // Write port to file for CLI/Python discovery (mirrors tallow-daemon).
    std::fs::write(&cfg.port_file, local_addr.port().to_string())?;
    tracing::info!("Port {} written to {:?}", local_addr.port(), cfg.port_file);

    println!("tallow-reader v{}", env!("CARGO_PKG_VERSION"));
    println!("Listening on http://{}", local_addr);
    println!("Token file: {}", cfg.token_path.display());
    println!("Use: Authorization: Bearer <token from token file>");

    // Serve with graceful shutdown (Ctrl-C or API shutdown).
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = shutdown_rx.changed() => {},
            }
            tracing::info!("Shutdown signal received, draining connections...");
        })
        .await?;

    Ok(())
}
