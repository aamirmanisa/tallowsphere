use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use rand::Rng;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

mod auth;
mod catchup;
mod config;
mod conflict;
mod db;
mod delta;
mod executor;
mod ipc_auth;
mod job_kind;
mod mesh;
mod queue;
mod resume;
mod revocation_gate;
mod routes;
mod sessions;
mod service;
mod sse;
mod sync_executor;
mod throttle;
mod watcher;

/// Owner-only state-file hygiene (R-P9 / T-112): tighten a pre-existing
/// daemon state file to 0600 in place. Best-effort: failures are logged,
/// never fatal — the doctor probe reports the live state either way.
#[cfg(unix)]
fn tighten_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::metadata(path) else {
        return;
    };
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => tracing::warn!(
                path = ?path,
                mode = format!("{mode:o}"),
                "daemon state was not owner-only; tightened to 0600 (R-P9)"
            ),
            Err(e) => tracing::warn!(path = ?path, "failed to tighten daemon state to 0600: {e}"),
        }
    }
}

#[cfg(not(unix))]
fn tighten_owner_only(_path: &std::path::Path) {}

/// Create/rewrite a state file owner-only from the first write — no
/// create-then-chmod window (mirrors the token file's O_EXCL path in
/// `config.rs`).
fn write_owner_only(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

/// Central application state shared across all request handlers.
/// All fields wrapped in Arc to satisfy axum's State: Clone requirement.
pub struct AppState {
    pub config: config::Config,
    pub start_time: Instant,
    pub db: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    pub progress_tx: tokio::sync::broadcast::Sender<sse::ProgressEvent>,
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    pub device_id: String,
    /// Listener-lifetime `ipc_auth` replay guard: a handshake nonce is
    /// consumed at most once for the lifetime of the daemon process
    /// (populated by `POST /auth/handshake` — see `routes/handshake.rs`).
    pub ipc_auth_seen: std::sync::Mutex<ipc_auth::SeenNonces>,
    /// Sessions minted by accepted handshakes (id → `expires_ms`), for the
    /// daemon's lifetime: authenticated requests presenting an
    /// `X-Tallow-Session` value are validated against this registry
    /// (`crate::auth`).
    pub ipc_sessions: std::sync::Mutex<std::collections::HashMap<String, i64>>,
    /// Row #127: the revocation check-at-use gate consulted before a new
    /// session is minted (`crate::revocation_gate`; resolved from
    /// `<data_dir>/revocation/` + `TALLOW_DAEMON_REVOCATION`).
    pub revocation: Arc<revocation_gate::DaemonRevocationGate>,
}

#[derive(Parser)]
#[command(name = "tallow-daemon", version, about = "Tallow Copy background daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<DaemonCommand>,
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Run the daemon in the foreground (default)
    Run,
    /// Install as a system service
    Install,
    /// Uninstall the system service
    Uninstall,
    /// Start the system service
    Start,
    /// Stop the system service
    Stop,
    /// Show service status
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(DaemonCommand::Run) {
        DaemonCommand::Run => run_daemon().await?,
        DaemonCommand::Install => service::install_service(),
        DaemonCommand::Uninstall => service::uninstall_service(),
        DaemonCommand::Start => service::start_service(),
        DaemonCommand::Stop => service::stop_service(),
        DaemonCommand::Status => service::service_status(),
    }
    Ok(())
}

async fn run_daemon() -> anyhow::Result<()> {
    // Initialize tracing subscriber (reads RUST_LOG env var)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tallow_daemon=info")),
        )
        .init();

    // Load config (generates token if first run)
    let mut cfg = config::Config::load_or_create()?;
    tracing::info!("Config loaded. Data dir: {:?}", cfg.data_dir);

    // Load or generate device_id (persisted to ~/.tallow/daemon/device_id).
    // Identity-bearing state → owner-only: created at mode 0600 and a
    // pre-existing loose file is tightened on load (R-P9 hygiene, T-112).
    let device_id_path = cfg.data_dir.join("device_id");
    let device_id = if device_id_path.exists() {
        tighten_owner_only(&device_id_path);
        std::fs::read_to_string(&device_id_path)
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        let mut bytes = [0u8; 8];
        rand::rng().fill(&mut bytes);
        let id = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        write_owner_only(&device_id_path, id.as_bytes())?;
        tracing::info!("Generated new device_id: {}", id);
        id
    };

    // Open SQLite database with WAL mode and run migrations
    let conn = db::open(&cfg.db_path)?;
    tracing::info!("Database opened at {:?} (WAL mode)", cfg.db_path);

    // Wrap in Arc<Mutex<>> for shared access between API routes and executor
    let shared_db: Arc<tokio::sync::Mutex<rusqlite::Connection>> =
        Arc::new(tokio::sync::Mutex::new(conn));

    // Create broadcast channel for SSE progress events
    let (progress_tx, _) = tokio::sync::broadcast::channel::<sse::ProgressEvent>(256);

    // Create shutdown signal channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Build app state (clone DB Arc — same underlying connection)
    let state = Arc::new(AppState {
        config: cfg.clone(),
        start_time: Instant::now(),
        db: shared_db.clone(),
        progress_tx: progress_tx.clone(),
        shutdown_tx: shutdown_tx.clone(),
        device_id: device_id.clone(),
        ipc_auth_seen: std::sync::Mutex::new(ipc_auth::SeenNonces::new()),
        ipc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
        revocation: Arc::new(revocation_gate::DaemonRevocationGate::resolve(&cfg.data_dir)),
    });

    // G-07 (U-216): reload persisted ipc sessions; start the periodic sweep/persist task.
    let restored = sessions::restore_sessions(&state);
    if restored > 0 {
        tracing::info!("Restored {} ipc session(s) from disk", restored);
    }
    sessions::spawn_session_sweeper(
        state.clone(),
        sessions::SESSION_SWEEP_INTERVAL,
        shutdown_tx.subscribe(),
    );

    // Recover crashed jobs from previous run before starting the executor
    let recovered = resume::recover_crashed_jobs(&shared_db, &progress_tx).await;
    if recovered > 0 {
        tracing::info!("Recovered {} job(s) from previous run", recovered);
    }

    // Build throttle from config (bandwidth limit with optional time-of-day schedule)
    let throttle: Option<Arc<throttle::ScheduledThrottle>> =
        if cfg.bandwidth_limit_bytes_per_sec > 0 || !cfg.bandwidth_schedule.is_empty() {
            let st = throttle::ScheduledThrottle::new(
                cfg.bandwidth_limit_bytes_per_sec,
                &cfg.bandwidth_schedule,
            )?;
            tracing::info!(
                "Bandwidth throttle: {} bytes/sec default, {} schedule windows",
                cfg.bandwidth_limit_bytes_per_sec,
                cfg.bandwidth_schedule.len()
            );
            Some(Arc::new(st))
        } else {
            None
        };

    // Start the job executor (priority queue + retry engine)
    let executor_shutdown_rx = shutdown_tx.subscribe();
    let queue = Arc::new(queue::PriorityQueue::new(cfg.concurrency_limit));
    executor::JobExecutor::spawn_executor(
        queue,
        shared_db.clone(),
        progress_tx.clone(),
        executor_shutdown_rx,
        cfg.clone(),
        throttle,
    );
    tracing::info!(
        "Job executor started (concurrency: {})",
        cfg.concurrency_limit
    );

    // --- Offline catch-up: detect changes while daemon was stopped ---
    if !cfg.watch_dirs.is_empty() {
        let caught_up = catchup::catch_up_changes(&cfg, &progress_tx).await;
        if caught_up > 0 {
            tracing::info!("Caught up {} offline change(s)", caught_up);
        }

        // --- Spawn real-time filesystem watcher ---
        let watcher_shutdown_rx = shutdown_tx.subscribe();
        watcher::spawn_watcher(&cfg, progress_tx.clone(), watcher_shutdown_rx);
        tracing::info!(
            "Filesystem watcher started for {} director(y|ies)",
            cfg.watch_dirs.len()
        );

        // --- Spawn sync executor (reacts to FileChange events) ---
        let sync_shutdown_rx = shutdown_tx.subscribe();
        let sync_state = sync_executor::SyncState {
            db: shared_db.clone(),
            progress_tx: progress_tx.clone(),
            device_id: device_id.clone(),
        };
        sync_executor::spawn_sync_executor(sync_state, sync_shutdown_rx);
        tracing::info!("Sync executor started");
    }

    // Build router
    let app = routes::create_router(state);

    // Bind to a random available port on 127.0.0.1 only (no network exposure)
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    cfg.port = local_addr.port();
    cfg.bind_addr = format!("127.0.0.1:{}", cfg.port);

    // Write port to file for CLI discovery. Deliberately NOT owner-only:
    // the value is a port on the 127.0.0.1-only listener (bearer-token
    // gated API), so 0644 keeps the same-host discovery contract. No secret
    // ever lands here — the doctor probe classes this file as `Discovery`
    // (advisory only, never FAIL).
    std::fs::write(&cfg.port_file, local_addr.port().to_string())?;
    tracing::info!("Port {} written to {:?}", local_addr.port(), cfg.port_file);

    println!("tallow-daemon v{}", env!("CARGO_PKG_VERSION"));
    println!("Listening on http://{}", local_addr);
    println!("Token file: {}", cfg.token_path.display());

    // Serve with graceful shutdown (Ctrl-C or API shutdown)
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
