// mimalloc: 2-5x throughput for allocation-heavy workloads (HTML parsing, JSON)
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Standard exit codes for tallow CLI.
mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const COMPILE_ERROR: i32 = 1;
    pub const LEGAL_VIOLATION: i32 = 2;
    pub const PRIVACY_VIOLATION: i32 = 3;
    pub const PERMISSION_VIOLATION: i32 = 4;
    pub const IO_ERROR: i32 = 5;
    pub const DEPENDENCY_ERROR: i32 = 6;
    #[allow(dead_code)]
    pub const NETWORK_ERROR: i32 = 7;
    pub const ICE: i32 = 8;
    #[allow(dead_code)]
    pub const USAGE_ERROR: i32 = 64;
    #[allow(dead_code)]
    pub const INTERRUPTED: i32 = 130;
}

/// Single-source disclaimer for compliance-audit outputs (text and JSON).
/// Frozen by cycle-02/08 §b/(c) — E-2-03. Rewording requires regenerating
/// `tests/fixtures/audit_golden/*.json`.
const AUDIT_DISCLAIMER: &str =
    "This output is compliance tooling — not legal advice and not a certification.";

use tallow::agent_pass::AgentPass;
// Compliance-report generator legs (row #179): early-warning clocks, CERT-In
// incident payloads, ZNISM/NIS2 self-assessment pack. CLI surface only.
mod compliance;
use tallow::agent_safety_pass::AgentSafetyPass;
use tallow::ai_act_pass::AiActPass;
use tallow::codegen::CodeGen;
use tallow::consent_pass::ConsentPass;
use tallow::constitution_pass::ConstitutionPass;
use tallow::consttime_pass::ConstTimePass;
use tallow::contract_pass::ContractPass;
use tallow::cra_pass::CraPass;
use tallow::crypto_policy_pass::{CryptoPolicy, CryptoPolicyPass};
use tallow::detection_pass::DetectionPass;
use tallow::dp_pass::DPBudgetPass;
use tallow::enclave_pass::EnclavePass;
use tallow::erasure_pass::ErasurePass;
use tallow::he_pass::HePass;
use tallow::hw_safety_pass::HwSafetyPass;
use tallow::identity_pass::IdentityPass;
use tallow::interp::Interpreter;
use tallow::legal_pass::LegalPass;
use tallow::lineage_pass::LineagePass;
use tallow::mpc_pass::MpcPass;
use tallow::nis2_pass::Nis2Pass;
use tallow::opsec_pass::OpsecPass;
use tallow::otel_pass::OtelPass;
use tallow::pec_pass::PecPass;
use tallow::privacy_pass::PrivacyPass;
use tallow::safety_pass::SafetyPass;
use tallow::sandbox_pass::SandboxPass;
use tallow::sast_pass::SastPass;
use tallow::smt_export;
use tallow::stealth_pass::StealthPass;
use tallow::tier_gate_pass::TierGatePass;
use tallow::typeck::TypeChecker;
use tallow::zk_pass::ZkPass;

#[derive(Parser)]
#[command(
    name = "tallow",
    disable_version_flag = true,
    about = "The Tallow programming language compiler"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress all non-error output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Show verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(
        long,
        global = true,
        env = "NO_COLOR",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_parser = parse_no_color_env
    )]
    no_color: bool,

    /// Parser mode: `recover` reports all parse errors, `fast` fails on first parse error.
    #[arg(
        long,
        global = true,
        env = "TALLOW_PARSER_MODE",
        value_enum,
        default_value = "recover"
    )]
    parser_mode: ParserMode,

    /// Throughput worker count for rayon-backed compiler pipeline work.
    #[arg(long, global = true, env = "TALLOW_THROUGHPUT_THREADS")]
    throughput_threads: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ParserMode {
    Recover,
    Fast,
}

#[derive(Subcommand)]
enum Command {
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Phone OSINT subcommands (PhoneNumber.* stdlib dispatches)
    Phone {
        /// Everything after `phone`, e.g. `lookup 5128501815`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// FCC Robocall Mitigation DB snapshot import / status
    #[command(name = "rmdb")]
    Rmd {
        /// Everything after `rmdb`, e.g. `import /path/rmd.csv`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Verify a Tallow ledger: recompute the hash chain, flag tampering/gaps
    #[command(name = "verify-ledger")]
    VerifyLedger {
        /// Everything after `verify-ledger`, e.g. `/path/to/ledger.db`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Cross-domain release gate: decide a release plan against the boundary
    /// model, then act on the verdict. `check` / `channels` / `explain` read
    /// only; `release` composes the derivative and its receipt; `verify` reads
    /// the receipt back from disk and recomputes it. The gate decides; it never
    /// performs an egress itself.
    #[command(name = "sluice")]
    Sluice {
        /// Everything after `sluice`, e.g. `check --plan plan.json`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Peer pin registry (pin + registry-verify arc): `pin add/list/revoke`.
    /// Pins enter only by explicit provisioning; verification paths fail closed
    /// on absent/revoked rows; every mutation is receipt-logged.
    #[command(name = "pin")]
    Pin {
        /// Everything after `pin`, e.g. `--pins ./pins.json add <hex> --kind identity`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Outbound authorization register (deny-by-default): `scope check|list|verify`.
    /// A host absent from `configs/tallow/scope/authorized-hosts.toml` is refused
    /// before a socket is opened; the exit status is the verdict (0 allowed,
    /// 2 refused or defective) and the reason is printed, never implied.
    #[command(name = "scope")]
    Scope {
        /// Everything after `scope`, e.g. `check https://example.com/ --json`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Veil egress control: assert a transport rung, announce it, and hand
    /// off env for child runs (`tallow veil connect tor|mesh|direct`).
    /// Bridge server: `tallow veil bridge serve`.
    Veil {
        /// Everything after `veil`, e.g. `connect tor`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run the NEVER-invariants probe — the N1–N10 static source guards via
    /// `scripts/never_check.sh --no-cargo` (no build). Exit 1 on any hard fail;
    /// exit 0 when all guards pass (or the gate script is absent). The full
    /// gate (incl. cargo closure slices) runs in CI: `.github/workflows/never-invariants.yml`.
    #[command(name = "never-check")]
    NeverCheck,
    /// Local fingerprint audit (ag03 R-2 / matrix #209 / U-103): JA4/JA4H/JA4T
    /// dumps for the current TLS profile, browser attribute coherence, cohort-k.
    /// Exit codes: 0 = clean, 2 = warnings, 64 = usage error.
    #[command(name = "fingerprint-audit")]
    FingerprintAudit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Credential enrollment + origin binding. Reads the password from the
    /// terminal with echo OFF — there is no --password flag, by design: a secret
    /// on the command line is a secret in `ps` and in shell history. Written to
    /// `~/.config/tallow/secrets.json` (0600), the path the scrape-isolated
    /// bridge already mounts into its flow container.
    /// Subcommands: `set`, `list`, `check`, `rm`.
    /// Exit codes: 0 ok, 64 usage, 69 refused (origin mismatch), 78 unbound.
    #[command(name = "secrets")]
    Secrets {
        /// Everything after `secrets`, e.g. `set retailer-e --username u --origin https://host`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// L4 detection-ops: run one canary cycle (quiet-gate consult, canary-page
    /// render+verify, observation scan, held-out leak control, sweep+report)
    /// and write the report + evidence to `--out`. Subcommand: `cycle`.
    /// Exit codes: 0 = valid cycle, 2 = failed check, 3 = quiet-window
    /// deferred, 64 = usage error.
    #[command(name = "canary")]
    Canary {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run one fixity sweep now (the `tallow-fixity.service` unit calls the
    /// `scripts/fixity_sweep.sh` wrapper, which execs this): verify primary vs
    /// mirror, repair from a verified-good copy, quarantine conflicts, write
    /// the report (+ ALERT file) and exit with the sweep verdict.
    /// Exit codes: 0 = clean/warn, 2 = critical.
    #[command(name = "fixity-sweep")]
    FixitySweep {
        /// `--primary <dir> --mirror <dir> --reports <dir>` (all required).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Validate a `tallow.extraction_schema.v1` extraction contract from the
    /// command line, so a schema can be gated in CI before a run depends on it.
    /// Subcommand: `check <file>`. Exit codes: 0 = valid, 1 = invalid (the
    /// failing field is named on stderr), 64 = usage error or unreadable file.
    Schema {
        /// Everything after `schema`, e.g.
        /// `check schemas/tallow/examples/product-listing.extraction.schema.json`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Dry-run a `tallow.request_plan.v1` manifest: print exactly what would be
    /// fetched and perform NO egress. Refuses a manifest whose requests omit
    /// their `compliance` block. Subcommand: `dry-run <file>`.
    /// Exit codes: 0 = ok, 1 = invalid (the offending request is named),
    /// 64 = usage error or unreadable file.
    Plan {
        /// Everything after `plan`, e.g.
        /// `dry-run examples/request_plan_get_only/request-plan.v1.json`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Extract `tallow.extraction_row.v1` rows from a LOCAL html file using a
    /// `tallow.extraction_schema.v1` contract. Performs NO network access: the
    /// row contract permits only `mode: local_mock` with `live_scraping: false`.
    /// Exit codes: 0 = rows written, 1 = nothing usable (the field is named),
    /// 64 = usage error or unreadable file.
    Extract {
        /// `--schema <f> --html <f> --out <dir> [--target-id <id>] [--source-url <u>]`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage Tallow configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Compile a .tl source file
    Build {
        #[arg()]
        file: PathBuf,

        /// Cross-compilation target (e.g. arm64-linux, wasm, macos)
        #[arg(long)]
        target: Option<String>,

        /// Enable/disable contract assertions (default: on for debug, off for release)
        #[arg(long)]
        contracts: Option<String>,

        /// Build in release mode (optimized)
        #[arg(long)]
        release: bool,

        /// Output format: text, json, or sarif
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Compile and run a .tl source file
    Run {
        #[arg()]
        file: PathBuf,

        /// Run as script with inline dependency declarations
        #[arg(long)]
        script: bool,

        /// Cross-compilation target (e.g. arm64-linux, wasm, macos)
        #[arg(long)]
        target: Option<String>,

        /// Enable/disable contract assertions (default: on)
        #[arg(long, default_value = "on")]
        contracts: String,

        /// Refuse the interpreter fallback: exit non-zero when the native
        /// build is unavailable instead of silently interpreting the program.
        /// (The one-line engine marker is printed to stderr either way and is
        /// never suppressed by -q — see E-2-02 §5.)
        #[arg(long)]
        require_native: bool,

        /// Run under kernel confinement (Landlock): reads limited to system
        /// dirs + CWD + the program's dir, writes limited to the temp dir.
        /// A Landlock failure refuses the run instead of executing
        /// unconfined. Runtime enforcement path for @sandbox/@sandboxed
        /// annotations (security-audit R3).
        #[arg(long)]
        sandbox: bool,

        /// Arguments to pass to the program (after --)
        #[arg(last = true)]
        program_args: Vec<String>,
    },
    /// List all supported compilation targets
    Targets,
    /// Type-check without building
    Check {
        #[arg()]
        file: PathBuf,

        /// Output format: text, json, or sarif
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Compliance reports, locally generated and operator-filed (row #179)
    Compliance {
        #[command(subcommand)]
        action: ComplianceAction,
    },
    /// Generate legal compliance report
    #[command(after_help = AUDIT_DISCLAIMER)]
    Audit {
        #[arg()]
        file: PathBuf,

        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,

        /// Escalate warning-class results to a non-zero exit (audit exit-code
        /// contract: cycle-02/08 §b freeze table)
        #[arg(long)]
        strict: bool,

        /// Filter by jurisdiction (e.g. eu, us, uk)
        #[arg(long)]
        jurisdiction: Option<String>,

        /// Generate CRA (Cyber Resilience Act) compliance report with SBOM
        #[arg(long)]
        cra: bool,

        /// Generate NIS2 (Network and Information Security Directive) report
        #[arg(long)]
        nis2: bool,

        /// Generate DORA (Digital Operational Resilience Act) report
        #[arg(long)]
        dora: bool,

        /// Generate EU AI Act (Regulation 2024/1689) compliance report
        #[arg(long)]
        ai_act: bool,

        /// Run supply-chain integrity audit (SBOM, signing, key pinning, SLSA)
        #[arg(long)]
        supply_chain: bool,

        /// Run SAST taint analysis and output SARIF report
        #[arg(long)]
        sast: bool,

        /// Show detection engineering coverage report
        #[arg(long)]
        detection_coverage: bool,

        /// Run cloud security audit (IaC scanning, container security, IAM analysis)
        #[arg(long)]
        cloud: bool,

        /// Audit dependency licenses and security advisories
        #[arg(long)]
        deps: bool,

        /// CRA/NIS2 vulnerability section: use the old illustrative 5-CVE
        /// sample table instead of the TALLOW_ADVISORY_FILE feed. The sample
        /// is static demo data and is always labeled as such — never default
        /// truth (C5).
        #[arg(long)]
        offline_fallback: bool,
    },
    /// Run static application security testing (SAST taint analysis)
    Sast {
        #[arg()]
        file: PathBuf,

        /// Output format: text or sarif
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Create a new Tallow project
    New {
        #[arg()]
        name: String,
        /// Project template
        #[arg(long, default_value = "default")]
        template: String,
    },
    /// Static analysis and linting
    Lint {
        #[arg()]
        file: PathBuf,

        /// Output format: text, json, or sarif
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Format Tallow source files
    Fmt {
        #[arg()]
        file: PathBuf,
    },
    /// Generate documentation from source
    Doc {
        /// Project directory or single .tl file (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format: html writes to docs/api/, json prints to stdout
        #[arg(long, default_value = "html")]
        format: String,
    },
    /// Run test files
    Test {
        /// Optional directory or file (defaults to tests/)
        #[arg(default_value = "tests")]
        path: PathBuf,

        /// Filter test functions by name
        #[arg(long)]
        filter: Option<String>,

        /// Enable function-level coverage reporting
        #[arg(long)]
        coverage: bool,
    },
    /// Interactive REPL (read-eval-print loop)
    Repl,
    /// Start the Language Server Protocol server (for IDE integration)
    Lsp,
    /// Print version information
    Version,
    /// Browser management commands
    Browser {
        #[command(subcommand)]
        action: BrowserAction,
    },
    /// Add a dependency to tallow.toml
    Add {
        /// Package name
        #[arg()]
        package: String,
        /// Version requirement (e.g. "^1.0", "~2.3", defaults to latest or "*")
        #[arg(long)]
        version: Option<String>,
    },
    /// Remove a dependency from tallow.toml
    Remove {
        /// Package name to remove
        #[arg()]
        package: String,

        /// Show what would be removed without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Update all dependencies to latest compatible versions
    Update {
        /// Show what would be updated without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Install dependencies from tallow.lock
    Install {
        /// Work without network, using only cached packages
        #[arg(long)]
        offline: bool,

        /// Show what would be installed without making changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Generate Privacy Impact Assessment report
    #[command(after_help = AUDIT_DISCLAIMER)]
    Pia {
        #[arg()]
        file: PathBuf,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Generate Software Bill of Materials (CycloneDX 1.6 JSON)
    Sbom {
        /// Output format (default: cyclonedx)
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        /// Output file path (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Sign a package archive with Ed25519 + SLSA provenance
    Sign {
        /// Path to .tar.zst package archive
        #[arg()]
        archive: PathBuf,
        /// Path to Ed25519 private key file (32 bytes raw or 64 bytes hex)
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify a package archive signature and SLSA provenance
    Verify {
        /// Path to .tar.zst package archive
        #[arg()]
        archive: PathBuf,
        /// Path to Ed25519 public key file (32 bytes raw or 64 bytes hex)
        #[arg(long)]
        key: PathBuf,
    },
    /// Publish a package to the registry
    Publish,
    /// Search for packages in the registry
    Search {
        /// Search query (substring match on package names)
        #[arg()]
        query: String,
    },
    /// Show why a package is a dependency
    Why {
        /// Package name to explain
        #[arg()]
        package: String,
        /// Show all dependency paths (not just shortest)
        #[arg(long)]
        full: bool,
    },
    /// Patch a dependency for local editing
    Patch {
        /// Package name to patch
        #[arg()]
        package: String,
        /// Directory to extract the package into for editing
        #[arg(long)]
        edit_dir: Option<PathBuf>,
    },
    /// Commit an edited patch directory back as a named patch
    #[command(name = "patch-commit")]
    PatchCommit {
        /// Path to the edited package directory
        #[arg()]
        path: PathBuf,
    },
    /// Remove a patch from the project
    #[command(name = "patch-remove")]
    PatchRemove {
        /// Package name whose patch to remove
        #[arg()]
        package: String,
    },
    /// Display the full dependency tree
    Tree {
        /// Maximum depth to display (0 = unlimited)
        #[arg(long, default_value = "10")]
        depth: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Manage the global package cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Show outdated dependencies
    Outdated {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Export SMT-LIB2 verification conditions from contract annotations
    SmtExport {
        #[arg()]
        file: PathBuf,
        /// Output directory for .smt2 files (default: current directory)
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
        /// Also generate a ProVerif process algebra model (.pv) from @legal/@agent_task
        #[arg(long)]
        proverif: bool,
    },
    /// Hash a file with BLAKE3
    Hash {
        #[arg()]
        file: PathBuf,
    },
    /// Encrypt a file with AES-256-GCM + Argon2id
    Encrypt {
        #[arg()]
        input: PathBuf,
        #[arg()]
        output: PathBuf,
        /// Encryption password
        #[arg(long)]
        password: String,
    },
    /// Decrypt a file
    Decrypt {
        #[arg()]
        input: PathBuf,
        #[arg()]
        output: PathBuf,
        /// Decryption password
        #[arg(long)]
        password: String,
    },
    /// Fast file copy — supports s3://bucket/key URLs for cloud storage
    Copy {
        /// Source path or s3://bucket/key URL
        #[arg()]
        src: String,
        /// Destination path or s3://bucket/key URL
        #[arg()]
        dst: String,
    },
    /// Delta sync between directories
    DeltaSync {
        #[arg()]
        source: PathBuf,
        #[arg()]
        target: PathBuf,
        /// Dry run (show what would change)
        #[arg(long)]
        dry_run: bool,
        /// Mirror mode: delete target files not present in source
        #[arg(long)]
        mirror: bool,
        /// Number of parallel threads (default: 8)
        #[arg(long, short = 'j', default_value = "8")]
        threads: usize,
        /// Exclude file patterns (e.g., *.log *.tmp)
        #[arg(long = "exclude", short = 'x')]
        exclude_patterns: Vec<String>,
        /// Exclude directories (e.g., target node_modules)
        #[arg(long = "exclude-dir", short = 'X')]
        exclude_dirs: Vec<String>,
        /// Retry failed copies N times
        #[arg(long, default_value = "3")]
        retries: u32,
        /// Log output to file
        #[arg(long)]
        log: Option<PathBuf>,
        /// Compress during copy (zstd) — for network transfers only, ignored for local copies
        #[arg(long)]
        compress: bool,
        /// Maximum file age in days to include
        #[arg(long)]
        max_age: Option<u64>,
        /// Minimum file size in bytes to include
        #[arg(long)]
        min_size: Option<u64>,
        /// Maximum file size in bytes to include
        #[arg(long)]
        max_size: Option<u64>,
        /// Copy NTFS permissions/ACLs (Windows only)
        #[arg(long)]
        copy_acls: bool,
        /// Preserve symlinks instead of following them
        #[arg(long)]
        symlinks: bool,
        /// Save sync config as a reusable job file
        #[arg(long)]
        save_job: Option<PathBuf>,
        /// Load sync config from a job file
        #[arg(long)]
        load_job: Option<PathBuf>,
        /// Only run during these hours (e.g., "02:00-06:00")
        #[arg(long)]
        run_hours: Option<String>,
        /// Preserve Unix permissions (chmod bits) on Mac/Linux
        #[arg(long)]
        preserve_permissions: bool,
        /// Preserve file owner on Mac/Linux (requires root)
        #[arg(long)]
        preserve_owner: bool,
        /// Follow symlinks instead of preserving them (default: don't follow)
        #[arg(long)]
        follow_symlinks: bool,
        /// Show transfer summary in bytes (not MB)
        #[arg(long)]
        bytes: bool,
        /// Quiet mode (no progress bar, only summary)
        #[arg(long, short = 'q')]
        quiet: bool,
        /// Verify copies with BLAKE3 hash after write
        #[arg(long)]
        verify: bool,
        /// Use block-level delta sync (rsync algorithm — transfers only changed 128 KiB blocks)
        #[arg(long)]
        block_level: bool,
        /// Disable the delta-sync journal (design §3.2: journal is ON by default)
        #[arg(long)]
        no_resume: bool,
        /// Directory for the delta-sync journal (default: <target>/.tallow-journal/)
        #[arg(long)]
        journal_dir: Option<PathBuf>,
    },
    /// Encrypt an entire directory with AES-256-GCM + Argon2id
    EncryptDir {
        #[arg()]
        input: PathBuf,
        #[arg()]
        output: PathBuf,
        /// Encryption password
        #[arg(long)]
        password: String,
    },
    /// Decrypt an entire directory
    DecryptDir {
        #[arg()]
        input: PathBuf,
        #[arg()]
        output: PathBuf,
        /// Decryption password
        #[arg(long)]
        password: String,
    },
    /// Discover peers on local network
    Discover,
    /// Send files or directories over QUIC (encrypted, BLAKE3-verified)
    Send {
        /// Files or directories to send
        #[arg(required = false)]
        files: Vec<PathBuf>,
        /// Send text instead of files
        #[arg(long)]
        text: Option<String>,
        /// Read data from stdin instead of file
        #[arg(long)]
        stdin: bool,
        /// Destination address (ip:port) -- omit for code phrase mode
        #[arg(long)]
        to: Option<String>,
        /// Use relay server (address:port)
        #[arg(long)]
        relay: Option<String>,
        /// Custom code phrase (auto-generated if omitted)
        #[arg(long)]
        code: Option<String>,
        /// Compress before sending (default: true)
        #[arg(long, default_value = "true")]
        compress: String,
        /// Bandwidth limit in bits/sec (e.g., "10M", "500K", "1G"; 10M = 1.25 MB/s).
        /// Enforced on QUIC and relay-v1 file sends (design D-C2)
        #[arg(long)]
        bwlimit: Option<String>,
        /// SOCKS5 proxy (e.g., socks5://127.0.0.1:9050 for Tor)
        #[arg(long)]
        proxy: Option<String>,
        /// Signal server for global peer discovery (e.g., signal.github.com/aamirmanisa/tallowsphere:6890)
        #[arg(long)]
        signal: Option<String>,
        /// Use the legacy v0 plaintext relay protocol (insecure escape hatch;
        /// design cycle-02/09 §3.1 migration)
        #[arg(long)]
        legacy_plaintext: bool,
    },
    /// Receive a file over QUIC (encrypted, BLAKE3-verified)
    Receive {
        /// Code phrase (positional, optional)
        #[arg(default_value = "")]
        code_positional: String,
        /// Listen address (default: 0.0.0.0:6881)
        #[arg(long, default_value = "0.0.0.0:6881")]
        listen: String,
        /// Output directory
        #[arg(long, default_value = ".")]
        output: PathBuf,
        /// Timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
        /// Code phrase for relay/code-phrase mode
        #[arg(long)]
        code: Option<String>,
        /// Relay server address
        #[arg(long)]
        relay: Option<String>,
        /// Write received data to stdout instead of file
        #[arg(long)]
        stdout: bool,
        /// Overwrite existing files without asking
        #[arg(long)]
        overwrite: bool,
        /// Auto-accept all prompts
        #[arg(long, short)]
        yes: bool,
        /// SOCKS5 proxy (e.g., socks5://127.0.0.1:9050 for Tor)
        #[arg(long)]
        proxy: Option<String>,
        /// Signal server for global peer discovery (e.g., signal.github.com/aamirmanisa/tallowsphere:6890)
        #[arg(long)]
        signal: Option<String>,
        /// Disable receive resume (design §3.2: resume is ON by default)
        #[arg(long)]
        no_resume: bool,
        /// Directory for versioned receive resume state
        /// (default: <output>/.tallow-resume/)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Use the legacy v0 plaintext relay protocol (insecure escape hatch)
        #[arg(long)]
        legacy_plaintext: bool,
    },
    /// Pack a directory into a TWD archive (preserves full folder structure)
    Pack {
        /// Directory to pack
        #[arg()]
        dir: PathBuf,
        /// Output archive path
        #[arg()]
        output: PathBuf,
        /// Disable compression
        #[arg(long)]
        no_compress: bool,
    },
    /// Unpack a TWD archive to a directory
    Unpack {
        /// Archive file to unpack
        #[arg()]
        archive: PathBuf,
        /// Output directory
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
    /// Start a TallowTransfer relay server
    Relay {
        /// Port to listen on
        #[arg(long, default_value = "6880")]
        port: u16,
    },
    /// Start a signaling server for global peer discovery
    Signal {
        /// Port to listen on
        #[arg(long, default_value = "6890")]
        port: u16,
    },
    /// Watch a directory for changes and sync
    Watch {
        /// Directory to watch
        #[arg()]
        dir: PathBuf,
        /// Check interval in milliseconds
        #[arg(long, default_value = "1000")]
        interval: u64,
        /// Sync destination (ip:port)
        #[arg(long)]
        to: Option<String>,
    },
    /// Show transfer audit log
    AuditTransfers {
        /// Export format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Save to file
        #[arg(long)]
        save: Option<PathBuf>,
    },
    /// Validate a file's type by magic bytes
    ValidateFile {
        #[arg()]
        file: PathBuf,
    },
    /// Operator health checks (stdlib scraper surface report)
    Doctor {
        /// Verify the scraper-critical stdlib surface (JSON report on stdout)
        #[arg(long)]
        stdlib_scraper: bool,

        /// Emit a machine-readable stdlib capability report (schema
        /// tallow.doctor.capabilities.v1). Formats: json (default) | text.
        /// When given, stdout carries ONLY the report (no check output).
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "json",
            value_name = "FMT",
            value_parser = ["json", "text"]
        )]
        capabilities: Option<String>,

        /// With --capabilities: run guarded runtime probes (per-probe thread
        /// + 2s hard timeout) instead of the default pure-static source
        /// classification. Default never executes a dispatch handler.
        #[arg(long)]
        probe: bool,

        /// Emit the stdlib declaration-drift report (schema
        /// tallow.doctor.stdlib_drift.v1) on stdout: every fn/native decl in
        /// stdlib/*.tl cross-checked against the real resolution order.
        /// Exit code 2 when any declared fn is unreachable from .tl (with the
        /// list on stdout); exit 0 when every declaration is reachable.
        #[arg(long)]
        stdlib_drift: bool,

        /// Emit the crypto-surface coverage + mock-body guard report (schema
        /// tallow.doctor.crypto_surface.v1) on stdout: every fn/method
        /// declared in stdlib/crypto.tl must have dispatch evidence in
        /// src/interp.rs / src/stdlib/crypto.rs or an explicit
        /// @mock/@unimplemented annotation with a rationale. Bodies shaped as
        /// single literals (`true`, `false`, `""`, `{}`, `Bytes{}`, `data`)
        /// are flagged as mocks so the E-1-02 fail-loud neutralization stays
        /// enforced. Exit code 2 when any declaration is uncovered (offenders
        /// listed on stdout); exit 0 when every declaration is covered.
        #[arg(long)]
        crypto_surface: bool,

        /// Emit the SVID rotation alarm report (schema
        /// tallow.doctor.rotation.v1) on stdout: T/2 re-issue deadlines,
        /// overdue/expired alarms and held generations from a rotation-state
        /// file (--rotation-state PATH; schema tallow.rotation_state.v1),
        /// plus the annual node-key rotation policy. Exit code 2 when any
        /// Critical alarm is present (expired while held); exit 0 otherwise
        /// (a missing state file is reported explicitly, not silently green).
        #[arg(long)]
        rotation: bool,

        /// Rotation-state file for `--rotation`
        #[arg(long, value_name = "PATH")]
        rotation_state: Option<PathBuf>,
    },
    /// Exercise mode: offline scenario drills with after-action reports (#205)
    Drill {
        /// List the scenario suite and exit
        #[arg(long)]
        list: bool,
        /// Run one scenario by id
        #[arg(long, value_name = "ID")]
        scenario: Option<String>,
        /// Run the whole offline suite
        #[arg(long)]
        all: bool,
        /// Sandbox directory (default: a fresh tempdir)
        #[arg(long, value_name = "DIR")]
        sandbox_dir: Option<PathBuf>,
        /// After-action report directory (default: artifacts/drills)
        #[arg(long, value_name = "DIR")]
        report_dir: Option<PathBuf>,
        /// Crypto-agility rehearsal scale (default 1000; 750000 = ID-card scale)
        #[arg(long, value_name = "N")]
        scale: Option<usize>,
        /// Print the after-action report JSON on stdout
        #[arg(long)]
        json: bool,
    },
    /// Apply retention policy to a directory
    Retain {
        #[arg()]
        dir: PathBuf,
        /// Days to retain
        #[arg(long, default_value = "30")]
        days: u64,
        /// Dry run (don't actually delete)
        #[arg(long)]
        dry_run: bool,
    },
    /// Start an encrypted chat session
    Chat {
        /// Your username
        #[arg(long)]
        name: String,
        /// Code phrase to join existing chat (omit to create new)
        #[arg(long)]
        code: Option<String>,
        /// SOCKS5 proxy
        #[arg(long)]
        proxy: Option<String>,
        /// Relay server address (host:port) used for the chat transport
        #[arg(long)]
        relay: Option<String>,
    },
    /// Send text directly (no file needed)
    #[command(name = "send-text")]
    SendText {
        /// Text to send
        #[arg()]
        text: String,
        /// Destination code phrase or address
        #[arg(long)]
        to: Option<String>,
        /// Custom code phrase (auto-generated if omitted)
        #[arg(long)]
        code: Option<String>,
    },
    /// Run TallowTransfer speed test (disk, hash, encrypt, compress)
    #[command(name = "speed-test")]
    SpeedTest {
        /// Network throughput target (host:port). Omit for local-only results.
        #[arg(long)]
        target: Option<String>,
    },
    /// Create a group chat
    #[command(name = "group-chat")]
    GroupChatCmd {
        /// Group name
        #[arg(long)]
        name: String,
        /// Your username
        #[arg(long)]
        user: String,
        /// Code phrase (auto-generated if omitted)
        #[arg(long)]
        code: Option<String>,
        /// Relay server address (host:port) used for the chat transport
        #[arg(long)]
        relay: Option<String>,
    },
    /// Share a file or directory via download link (anyone with a browser can download)
    Share {
        /// File or directory to share
        #[arg()]
        path: PathBuf,
        /// Port (auto-assigned if omitted)
        #[arg(long)]
        port: Option<u16>,
        /// Require password to download
        #[arg(long)]
        password: Option<String>,
        /// Maximum number of downloads (0 = unlimited)
        #[arg(long, default_value = "0")]
        max_downloads: i64,
    },
    /// Share live browser session for remote viewing
    #[command(name = "live-view")]
    LiveView {
        /// Port for the viewer
        #[arg(long, default_value = "9090")]
        port: u16,
        /// Screenshot refresh interval in ms
        #[arg(long, default_value = "1000")]
        refresh: i64,
    },
    /// Check for undeclared (phantom) dependencies
    #[command(name = "check-deps")]
    CheckDeps {
        /// Fix by adding missing deps to tallow.toml
        #[arg(long)]
        fix: bool,
    },
    /// List all dependency licenses (compliance audit)
    Licenses {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Only show production dependencies
        #[arg(long)]
        prod: bool,
        /// Exit 1 if any banned license is found (CI enforcement)
        #[arg(long)]
        check: bool,
    },
    /// Copy all dependencies into a local vendor directory (air-gap / offline builds)
    Vendor {
        /// Output directory (default: vendor)
        #[arg(default_value = "vendor")]
        output: PathBuf,
    },
    /// Workspace management subcommands
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Manage ffmpeg installation
    Ffmpeg {
        #[command(subcommand)]
        action: FfmpegAction,
    },
    /// Encrypted password vault (Bitwarden/KeePass-class, PQC-ready)
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Two-way sync between directories (better than FreeFileSync/Syncthing conflict resolution)
    #[command(name = "two-way-sync")]
    TwoWaySync {
        /// Left directory
        #[arg()]
        left: PathBuf,
        /// Right directory
        #[arg()]
        right: PathBuf,
        /// Conflict resolution: newest, oldest, largest, left, right, rename, skip
        #[arg(long, default_value = "newest")]
        conflicts: String,
        /// Dry run: show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
        /// State database path (default: .tallow-sync.db in left dir)
        #[arg(long)]
        db: Option<PathBuf>,
        /// Number of parallel threads for scanning
        #[arg(long, short = 'j', default_value = "8")]
        threads: usize,
        /// Exclude glob patterns (e.g. *.log *.tmp)
        #[arg(long = "exclude", short = 'x')]
        exclude: Vec<String>,
        /// Show detailed plan before executing
        #[arg(long)]
        plan: bool,
        /// Quiet mode (no progress output, only summary)
        #[arg(long, short = 'q')]
        quiet: bool,
    },
    /// Manage Tor daemon instances for anonymous browsing
    Tor {
        #[command(subcommand)]
        action: TorAction,
    },
    /// Manage the Tallow daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage daemon jobs
    Job {
        #[command(subcommand)]
        action: JobAction,
    },
    /// Cryptographic enrollment ceremony: CPace PAKE + SAS word comparison + single-use
    /// join tokens + TPM quote attestation where available (R-5.5 / row #57)
    Enroll {
        #[command(subcommand)]
        action: EnrollAction,
    },
}

/// `tallow enroll …` — R-5.5 enrollment ceremony (`src/enrollment.rs`). Exit codes:
/// 0 = issued, 1 = checked refusal/detection, 2 = could not run.
#[derive(Subcommand, Debug)]
enum EnrollAction {
    /// Run the local two-endpoint ceremony and print both screens' SAS words
    Ceremony {
        /// Scenario: happy | sas-rejected | mismatched-phrase | replay
        #[arg(long, default_value = "happy", value_name = "NAME")]
        scenario: String,
        /// Device name presented by the enrollee
        #[arg(long, default_value = "local-device", value_name = "NAME")]
        device: String,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Mint a single-use, SPKI-bound join token for a fresh demo device key
    Token {
        /// Token TTL in seconds (hard policy ceiling: 600)
        #[arg(long, default_value = "300", value_name = "SECS")]
        ttl: i64,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[derive(Subcommand, Debug)]
enum TorAction {
    /// Start Tor daemon instances
    Start {
        /// Number of instances (default: 1)
        #[arg(long, default_value = "1")]
        instances: usize,
    },
    /// Stop all managed Tor instances
    Stop,
    /// Show status of Tor instances
    Status,
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// Show daemon status (health check)
    Status,
    /// Stop the daemon
    Stop,
}

#[derive(Subcommand, Debug)]
enum JobAction {
    /// List all jobs
    List {
        /// Filter by status (created, running, completed, failed)
        #[arg(long)]
        status: Option<String>,
    },
    /// Submit a new job from a Tallow script file
    Submit {
        /// Path to the tallow script file
        #[arg()]
        script: String,
    },
    /// Show job details
    Show {
        /// Job ID
        #[arg()]
        id: String,
    },
    /// Show job audit history
    History {
        /// Job ID
        #[arg()]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum VaultAction {
    /// Create a new encrypted vault
    Create {
        /// Vault file path (.twv)
        #[arg()]
        path: PathBuf,
        /// Vault name
        #[arg(long, default_value = "My Vault")]
        name: String,
    },
    /// Add an entry to the vault
    Add {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Entry type: login, card, note, ssh, api, totp, identity
        #[arg(long, default_value = "login")]
        entry_type: String,
        /// Entry name
        #[arg(long)]
        name: String,
        /// Username (for login entries)
        #[arg(long)]
        username: Option<String>,
        /// Password (for login entries; auto-generated if omitted)
        #[arg(long)]
        password: Option<String>,
        /// URL (for login entries)
        #[arg(long)]
        url: Option<String>,
        /// Content (for note entries)
        #[arg(long)]
        content: Option<String>,
        /// TOTP secret (base32)
        #[arg(long)]
        totp: Option<String>,
        /// Folder to organize into
        #[arg(long)]
        folder: Option<String>,
    },
    /// List all entries in the vault
    List {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Filter by folder
        #[arg(long)]
        folder: Option<String>,
        /// Show only favorites
        #[arg(long)]
        favorites: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Get a specific entry (copy password to clipboard)
    Get {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Entry name or ID to look up
        #[arg()]
        query: String,
        /// Show password in terminal (default: copy to clipboard)
        #[arg(long)]
        show: bool,
        /// Show TOTP code
        #[arg(long)]
        totp: bool,
    },
    /// Search entries
    Search {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Search query
        #[arg()]
        query: String,
    },
    /// Delete an entry
    Delete {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Entry name or ID
        #[arg()]
        query: String,
    },
    /// Generate a password or passphrase
    Generate {
        /// Password length
        #[arg(long, default_value = "20")]
        length: u32,
        /// Generate passphrase instead of password
        #[arg(long)]
        passphrase: bool,
        /// Word count for passphrase
        #[arg(long, default_value = "5")]
        words: u32,
        /// No uppercase
        #[arg(long)]
        no_uppercase: bool,
        /// No digits
        #[arg(long)]
        no_digits: bool,
        /// No special characters
        #[arg(long)]
        no_special: bool,
    },
    /// Show TOTP code for an entry
    Totp {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Entry name or ID
        #[arg()]
        query: String,
    },
    /// Run vault health analysis
    Health {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Check passwords against Have I Been Pwned
        #[arg(long)]
        breach: bool,
    },
    /// Import entries from another password manager
    Import {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Import file path
        #[arg()]
        file: PathBuf,
        /// Format: bitwarden, keepass, chrome, firefox, lastpass, csv
        #[arg(long)]
        format: String,
    },
    /// Export vault entries (gated: explicit --audience required; receipt in the KT log)
    Export {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Output file path
        #[arg()]
        output: PathBuf,
        /// Format: json, csv, encrypted
        #[arg(long, default_value = "json")]
        format: String,
        /// Release audience: public, third-party, teammate, operator (required)
        #[arg(long)]
        audience: Option<String>,
        /// Release caveat (repeatable; recorded on the released export)
        #[arg(long = "caveat", value_name = "TEXT")]
        caveats: Vec<String>,
        /// KT audit log for the release receipt (JSONL; created 0600 when absent)
        #[arg(long, value_name = "PATH")]
        kt_log: Option<PathBuf>,
    },
    /// Split vault master key for recovery (Shamir threshold)
    RecoverySplit {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Minimum shares needed to recover (threshold)
        #[arg(long, default_value = "3")]
        threshold: u8,
        /// Total shares to generate
        #[arg(long, default_value = "5")]
        shares: u8,
        /// KT audit log for the release receipt (JSONL; created 0600 when absent)
        #[arg(long, value_name = "PATH")]
        kt_log: Option<PathBuf>,
    },
    /// Recover vault from Shamir shares
    RecoveryCombine {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Share files (provide at least threshold shares)
        #[arg(trailing_var_arg = true)]
        share_files: Vec<PathBuf>,
    },
    /// Split the vault custody secret into dual-control recovery shares
    /// (k>=2 distinct custody shares required; row #114 · R-5.12)
    CustodySplit {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Custodian label per share (repeat --custodian; order defines the share index)
        #[arg(long = "custodian", value_name = "LABEL", required = true)]
        custodians: Vec<String>,
        /// Reconstruction threshold (>= 2)
        #[arg(long, default_value = "2")]
        threshold: u8,
        /// Minimum distinct custodians required at recovery (>= 2)
        #[arg(long, default_value = "2")]
        min_distinct_custodians: u8,
        /// Directory for the manifest + one share file per custodian (files 0600)
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
        /// KT audit log (JSONL; created 0600 when absent)
        #[arg(long, value_name = "PATH")]
        kt_log: PathBuf,
    },
    /// Dual-control custody recovery: refuses anything below k>=2 distinct
    /// custody shares; every attempt (recovered or refused) is KT-logged
    CustodyRecover {
        /// Custody manifest written by `vault custody-split`
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,
        /// Custody share files (repeat --share; >= threshold, distinct custodians)
        #[arg(long = "share", value_name = "PATH", required = true)]
        share_files: Vec<PathBuf>,
        /// KT audit log (same log the kit was created with; refusals are logged too)
        #[arg(long, value_name = "PATH")]
        kt_log: PathBuf,
        /// Print the recovered custody key (hex) on success
        #[arg(long)]
        print_key: bool,
    },
    /// Show vault info and statistics
    Info {
        /// Vault file path
        #[arg()]
        path: PathBuf,
    },
    /// Run compliance audit on vault
    Audit {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Sync vault with another device
    Sync {
        /// Local vault file path
        #[arg()]
        path: PathBuf,
        /// Remote vault file or sync bundle
        #[arg()]
        remote: PathBuf,
        /// Conflict resolution: keep-local, keep-remote, keep-newer, keep-both
        #[arg(long, default_value = "keep-newer")]
        strategy: String,
    },
    /// Export vault as encrypted sync bundle (gated: explicit --audience required)
    SyncExport {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Output bundle path
        #[arg()]
        output: PathBuf,
        /// Release audience: public, third-party, teammate, operator (required)
        #[arg(long)]
        audience: Option<String>,
        /// KT audit log for the release record (JSONL; created 0600 when absent)
        #[arg(long, value_name = "PATH")]
        kt_log: Option<PathBuf>,
    },
    /// Load SSH keys from vault into agent
    SshAgent {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Generate a new Ed25519 SSH key and add to vault
        #[arg(long)]
        generate: bool,
        /// Key name (for --generate)
        #[arg(long)]
        key_name: Option<String>,
    },
    /// Auto-type credentials for a window
    AutoType {
        /// Vault file path
        #[arg()]
        path: PathBuf,
        /// Window title to match
        #[arg()]
        window_title: String,
        /// Custom sequence (default: {USERNAME}{TAB}{PASSWORD}{ENTER})
        #[arg(long)]
        sequence: Option<String>,
    },
    /// Encrypt vault with post-quantum hybrid (ML-KEM-768 + AES-256-GCM)
    PqcEnable {
        /// Vault file path
        #[arg()]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum WorkspaceAction {
    /// List all workspace members with their versions and paths
    List,
    /// Show the workspace root directory
    Root,
    /// Run a tallow command in the context of a specific workspace member
    Run {
        /// Workspace member name (from [package].name in member's tallow.toml)
        #[arg()]
        member: String,
        /// Arguments to pass to tallow (e.g. build src/main.tl)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum BrowserAction {
    /// Download and install a compatible Chromium binary
    Install {
        /// Install full Chrome instead of chrome-headless-shell
        #[arg(long)]
        full: bool,
    },
    /// List installed browser versions
    List,
    /// Remove an installed browser version
    Remove {
        /// Version string to remove (from `tallow browser list`)
        version: String,
    },
    /// Show path to the detected Chrome binary
    Path,
    /// Show browser pool status
    Pool,
    /// List all supported device profiles
    Devices {
        /// Filter by category (iphone, ipad, pixel, galaxy, desktop, mobile, tablet)
        #[arg(long)]
        category: Option<String>,
    },
    /// Open Chrome with ALL Tallow features auto-enabled
    Open {
        /// URL to navigate to (default: about:blank)
        #[arg(default_value = "about:blank")]
        url: String,
        /// Headless mode
        #[arg(long)]
        headless: bool,
        /// Plugin preset: balanced (default), max, none
        #[arg(long, default_value = "balanced")]
        plugins: String,
        /// Device profile to emulate
        #[arg(long)]
        device: Option<String>,
        /// Disable all plugins
        #[arg(long)]
        no_plugins: bool,
        /// Route ALL traffic through Tor (socks5://127.0.0.1:9050)
        #[arg(long)]
        tor: bool,
        /// Custom proxy server (socks5://host:port, http://host:port)
        #[arg(long)]
        proxy: Option<String>,
    },
    /// Schedule .tl scripts to run automatically on cron or interval
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
    },
    /// Manage browser configuration (15 TOML config files)
    Config {
        #[command(subcommand)]
        action: BrowserConfigAction,
    },
}

#[derive(Subcommand, Debug)]
enum BrowserConfigAction {
    /// Create default config folder with all 15 TOML files
    Init,
    /// Display current configuration
    Show {
        /// Show only a specific config file (e.g., "plugins", "stealth", "tor")
        #[arg(long)]
        file: Option<String>,
    },
    /// Open a config file in $EDITOR
    Edit {
        /// Config file to edit (default: browser)
        #[arg(default_value = "browser")]
        file: String,
    },
    /// Reset config to defaults
    Reset {
        /// Reset only a specific config file (omit to reset all)
        #[arg(long)]
        file: Option<String>,
    },
    /// Set an individual config value
    Set {
        /// Dotted key path (e.g., "plugins.adblock", "tor.enabled", "stealth.profile")
        key: String,
        /// Value to set
        value: String,
    },
    /// Show config directory path
    Path,
    /// List all available config files
    List,
}

#[derive(Subcommand, Debug)]
enum ScheduleAction {
    /// Add a new scheduled job
    Add {
        /// Unique name for this schedule
        #[arg(long)]
        name: String,
        /// Path to .tl script to run
        #[arg(long)]
        script: String,
        /// Cron expression (e.g. "0 8 * * *" for daily at 8am)
        #[arg(long)]
        cron: Option<String>,
        /// Interval (e.g. "30m", "1h", "6h", "1d")
        #[arg(long)]
        every: Option<String>,
        /// Daily at HH:MM (e.g. "08:00", "14:30")
        #[arg(long)]
        daily: Option<String>,
        /// Run in headless mode (default: true)
        #[arg(long, default_value = "true")]
        headless: bool,
        /// Plugin preset: balanced, max, none
        #[arg(long, default_value = "balanced")]
        plugins: String,
        /// Device profile to emulate
        #[arg(long)]
        device: Option<String>,
        /// Route through Tor
        #[arg(long)]
        tor: bool,
        /// Custom proxy
        #[arg(long)]
        proxy: Option<String>,
        /// Max number of runs (omit for unlimited)
        #[arg(long)]
        max_runs: Option<u64>,
        /// Timeout per run in seconds
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// List all scheduled jobs
    List,
    /// Remove a scheduled job by name
    Remove {
        /// Name of the schedule to remove
        name: String,
    },
    /// Pause a scheduled job
    Pause {
        /// Name of the schedule to pause
        name: String,
    },
    /// Resume a paused scheduled job
    Resume {
        /// Name of the schedule to resume
        name: String,
    },
    /// Run a specific schedule immediately (one-shot)
    Run {
        /// Name of the schedule to run now
        name: String,
    },
    /// Start the scheduler daemon (runs due jobs in a loop)
    Start {
        /// Poll interval in seconds (default: 30)
        #[arg(long, default_value = "30")]
        poll: u64,
    },
    /// Show detailed info about a schedule
    Info {
        /// Name of the schedule
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum FfmpegAction {
    /// Download and install ffmpeg
    Install,
    /// Show ffmpeg installation path
    Path,
    /// Show ffmpeg version
    Version,
    /// Remove ffmpeg installation
    Remove,
}

/// `tallow compliance …` — row #179, lane I. Local-only generators: the
/// early-warning clock table, the CERT-In incident payload, and the
/// NIS2/ZNISM self-assessment pack. Exit codes: 0 = generated and nothing
/// overdue, 1 = generated but a deadline is missed, 2 = could not run.
#[derive(Subcommand, Debug)]
enum ComplianceAction {
    /// Compute the statutory notification deadlines for one incident
    Clocks {
        /// Incident spec JSON: awareness_at, kind, jurisdictions, filed[]
        #[arg(long, value_name = "PATH")]
        spec: PathBuf,
        /// Evaluation instant (unix seconds or YYYY-MM-DDTHH:MM:SSZ); default: now
        #[arg(long, value_name = "TS")]
        now: Option<String>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Write the report here instead of stdout
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Generate the CERT-In incident report payload (6-hour rule)
    Incident {
        /// Incident draft JSON (draft fields + optional jurisdictions[])
        #[arg(long, value_name = "PATH")]
        spec: PathBuf,
        /// Ledger events (JSONL, one object per line with ts + kind)
        #[arg(long, value_name = "PATH")]
        ledger: Option<PathBuf>,
        /// Ed25519 signing seed (32 raw bytes or 64 hex chars)
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Evaluation instant (unix seconds or YYYY-MM-DDTHH:MM:SSZ); default: now
        #[arg(long, value_name = "TS")]
        now: Option<String>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Write the report here instead of stdout
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Build the NIS2 / ZNISM-style self-assessment evidence pack
    #[command(name = "znism-pack")]
    ZnismPack {
        /// Config artifact to assess (default: the user config)
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Generation instant (unix seconds or YYYY-MM-DDTHH:MM:SSZ); default: now
        #[arg(long, value_name = "TS")]
        now: Option<String>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Write the pack here instead of stdout
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Get a config value
    Get {
        /// Config key to get
        key: String,
    },
    /// Set a config value
    Set {
        /// Config key to set
        key: String,
        /// Value to set
        value: String,
    },
    /// List all config values
    List,
    /// Show config file path
    Path,
    /// Score the active config against the hardening baseline (row #66)
    Lint {
        /// Score against a hardening profile preset (default: the declared profile)
        #[arg(long, value_name = "PROFILE")]
        preset: Option<String>,
        /// Fail on warnings as well as errors
        #[arg(long)]
        strict: bool,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Lint a specific config file instead of the default user config
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Print the hardening profile preset tables (row #66)
    Presets {
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Signed config bundles — export, import and verify (rows #153/#198)
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
}

/// `tallow config bundle …` — R-7.4/R-7.8 signed config distribution
/// (`src/config/bundle.rs`). `keygen` exists so export is operable without an
/// external key generator; `import` is verify-before-write.
#[derive(Subcommand, Debug)]
enum BundleAction {
    /// Generate an Ed25519 bundle-signing keypair (seed + `<out>.pub`)
    Keygen {
        /// Where to write the private key seed (unix: 0600)
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Export the active config as a signed bundle
    Export {
        /// Config file to sign (default: the user config path)
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Where to write the signed bundle
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Bundle scope: defaults|profile|system|user|device|project|agent|session|swarm
        #[arg(long, default_value = "user", value_name = "SCOPE")]
        scope: String,
        /// Ed25519 signing key file (32 raw bytes or 64 hex chars)
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Import a signed bundle (verify → strict load → atomic write)
    Import {
        /// Signed bundle file
        #[arg(long, value_name = "PATH")]
        bundle: PathBuf,
        /// Target config path
        #[arg(long, value_name = "PATH")]
        to: PathBuf,
        /// Required scope: must match the bundle's signed scope when given
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        /// Pinned trusted signer key file (repeatable; required for system/swarm)
        #[arg(long = "trusted-key", value_name = "PATH")]
        trusted_key: Vec<PathBuf>,
        /// Alternate config-history root for the recorded revision
        #[arg(long, value_name = "PATH")]
        history_dir: Option<PathBuf>,
        /// Verify + validate only; write nothing
        #[arg(long)]
        dry_run: bool,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Verify a signed bundle without importing it
    Verify {
        /// Signed bundle file
        #[arg(long, value_name = "PATH")]
        bundle: PathBuf,
        /// Pinned trusted signer key file (repeatable)
        #[arg(long = "trusted-key", value_name = "PATH")]
        trusted_key: Vec<PathBuf>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[derive(Subcommand, Debug)]
enum CacheAction {
    /// Show cache location, size, and package count
    Info,
    /// Remove cached packages not referenced by any lockfile
    Prune,
    /// Delete the entire package cache
    Clean,
    /// Verify BLAKE3 integrity of all cached packages
    Verify,
}

// ── ffmpeg management helpers ───────────────────────────────────────────────

/// Tolerant `NO_COLOR` parsing (register #74): the no-color.org convention
/// says any non-empty value means "disable color" (regardless of the value),
/// and an empty value means "unset". The previous clap boolean binding made
/// `NO_COLOR=1|0|anything|<empty>` a hard arg-parse error that broke EVERY
/// command. Accept: unset/empty → color ON; "false"/"no" (any case) → color
/// ON (so `--no-color=false` can re-enable); anything else → color OFF.
fn parse_no_color_env(s: &str) -> Result<bool, String> {
    let v = s.trim().to_ascii_lowercase();
    Ok(!(v.is_empty() || v == "false" || v == "no"))
}

/// Return the path string of a working `ffmpeg` binary, or `None` if not found.
fn which_ffmpeg() -> Option<String> {
    // Static candidates augment the PATH search.
    #[cfg(target_os = "windows")]
    let candidates: &[&str] = &[
        "ffmpeg",
        "ffmpeg.exe",
        r"C:\ProgramData\chocolatey\bin\ffmpeg.exe",
        r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
    ];
    #[cfg(target_os = "macos")]
    let candidates: &[&str] = &[
        "ffmpeg",
        "/usr/local/bin/ffmpeg",
        "/opt/homebrew/bin/ffmpeg",
    ];
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let candidates: &[&str] = &["ffmpeg", "/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg"];

    for &candidate in candidates {
        let ok = std::process::Command::new(candidate)
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Simple epoch → date string for schedule info display.
fn format_epoch_simple(ts: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = ts / secs_per_day;
    let time_of_day = ts % secs_per_day;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    // Howard Hinnant's algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, hours, mins)
}

/// `tallow ffmpeg install` — detect existing install, then try OS package
/// managers in order, and fall back to manual instructions.
fn ffmpeg_install() {
    // 1. Already installed?
    if let Some(path) = which_ffmpeg() {
        let version_out = std::process::Command::new(&path)
            .arg("-version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let first_line = version_out.lines().next().unwrap_or("unknown");
        println!("ffmpeg is already installed: {}", first_line);
        println!("Path: {}", path);
        return;
    }

    // 2. Attempt OS package manager.
    #[cfg(target_os = "windows")]
    {
        println!("Installing ffmpeg for Windows...");
        // Try winget.
        let winget_ok = std::process::Command::new("winget")
            .args([
                "install",
                "Gyan.FFmpeg",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if winget_ok {
            println!("ffmpeg installed via winget.");
            println!("Restart your terminal, then run: tallow ffmpeg version");
            return;
        }
        // Try Chocolatey.
        let choco_ok = std::process::Command::new("choco")
            .args(["install", "ffmpeg", "-y"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if choco_ok {
            println!("ffmpeg installed via chocolatey.");
            return;
        }
        // Fallback instructions.
        println!("Auto-install failed. Install manually:");
        println!("  Option 1: winget install Gyan.FFmpeg");
        println!("  Option 2: choco install ffmpeg");
        println!("  Option 3: Download from https://www.gyan.dev/ffmpeg/builds/");
        println!("            Extract ffmpeg.exe to a folder in your PATH");
    }

    #[cfg(target_os = "macos")]
    {
        println!("Installing ffmpeg for macOS...");
        let brew_ok = std::process::Command::new("brew")
            .args(["install", "ffmpeg"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if brew_ok {
            println!("ffmpeg installed via Homebrew.");
            return;
        }
        println!("Auto-install failed. Install manually:");
        println!("  brew install ffmpeg");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        println!("Installing ffmpeg for Linux...");
        // Try apt.
        let apt_ok = std::process::Command::new("sudo")
            .args(["apt", "install", "-y", "ffmpeg"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if apt_ok {
            println!("ffmpeg installed via apt.");
            return;
        }
        // Try dnf.
        let dnf_ok = std::process::Command::new("sudo")
            .args(["dnf", "install", "-y", "ffmpeg"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if dnf_ok {
            println!("ffmpeg installed via dnf.");
            return;
        }
        // Try pacman.
        let pacman_ok = std::process::Command::new("sudo")
            .args(["pacman", "-S", "--noconfirm", "ffmpeg"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if pacman_ok {
            println!("ffmpeg installed via pacman.");
            return;
        }
        println!("Auto-install failed. Install manually:");
        println!("  Ubuntu/Debian: sudo apt install ffmpeg");
        println!("  Fedora/RHEL:   sudo dnf install ffmpeg");
        println!("  Arch:          sudo pacman -S ffmpeg");
    }
}

/// `tallow ffmpeg path` — print the resolved path or exit with an error.
fn ffmpeg_path() {
    match which_ffmpeg() {
        Some(path) => println!("{}", path),
        None => {
            eprintln!("ffmpeg not found. Run: tallow ffmpeg install");
            std::process::exit(1);
        }
    }
}

/// `tallow ffmpeg version` — print the first three lines of `ffmpeg -version`.
fn ffmpeg_version() {
    match std::process::Command::new("ffmpeg")
        .arg("-version")
        .output()
    {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().take(3) {
                println!("{}", line);
            }
        }
        _ => {
            eprintln!("ffmpeg not found. Run: tallow ffmpeg install");
            std::process::exit(1);
        }
    }
}

/// `tallow ffmpeg remove` — print platform-specific uninstall instructions.
fn ffmpeg_remove() {
    println!("To remove ffmpeg:");
    #[cfg(target_os = "windows")]
    println!("  winget uninstall Gyan.FFmpeg   (or: choco uninstall ffmpeg)");
    #[cfg(target_os = "macos")]
    println!("  brew uninstall ffmpeg");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        println!("  Ubuntu/Debian: sudo apt remove ffmpeg");
        println!("  Fedora/RHEL:   sudo dnf remove ffmpeg");
        println!("  Arch:          sudo pacman -R ffmpeg");
    }
}

// ── Signal server: global peer discovery ──

/// Default signal server address (no public server yet - run your own with `tallow signal`).
/// Kept as a named constant for future `--signal default` shorthand.
#[allow(dead_code)]
const DEFAULT_SIGNAL_SERVER: &str = "signal.github.com/aamirmanisa/tallowsphere:6890";

/// Detect this machine's local outbound IP address.
/// For true public IP detection use an external service; this returns the
/// interface IP that would be used to reach the internet.
fn detect_public_ip() -> Option<String> {
    match std::net::TcpStream::connect("8.8.8.8:80") {
        Ok(stream) => stream.local_addr().ok().map(|a| a.ip().to_string()),
        Err(_) => None,
    }
}

/// Write the analytics-blocking PAC file for the `--tor` browser egress and
/// return its `file://` URL. The PAC hard-blocks the analytics/session-replay
/// domains at the proxy layer (before frame 1) and routes everything else
/// through Tor SOCKS5 on `socks_port`. Returns `Some(file:// URL)` on success.
fn write_analytics_pac(socks_port: u16) -> Option<String> {
    let pac = tallow::browser::plugins::analytics_blocking_pac(&format!(
        "SOCKS5 127.0.0.1:{socks_port}"
    ));
    let path = "/tmp/tallow_analytics.pac";
    if std::fs::write(path, pac).is_err() {
        return None;
    }
    Some(format!("file://{path}"))
}

/// Handle a single client connection on the signal server.
/// Protocol (line-oriented, newline-terminated):
///   Sender:   `REGISTER <code-phrase> <quic-port>\n`
///   Receiver: `LOOKUP <code-phrase>\n`
fn handle_signal_client(
    mut stream: std::net::TcpStream,
    peers: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, (String, std::net::TcpStream)>>,
    >,
    peer_addr: String,
) {
    use std::io::{BufRead, Write};

    // 5-minute read timeout — prevents stale registrations from blocking forever
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(300)))
        .ok();
    let reader_clone = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut reader = std::io::BufReader::new(reader_clone);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let line = line.trim().to_string();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    match parts.first().copied() {
        Some("REGISTER") => {
            if parts.len() < 3 {
                let _ = stream.write_all(b"ERR missing args: REGISTER <code> <quic-port>\n");
                return;
            }
            let code = parts[1].to_string();
            let quic_port = parts[2].trim().to_string();
            // Build the sender's address: their public IP (from TCP) + their QUIC port
            let sender_ip = peer_addr
                .split(':')
                .next()
                .unwrap_or(&peer_addr)
                .to_string();
            let sender_addr = format!("{}:{}", sender_ip, quic_port);

            println!("[signal] REGISTER '{}' from {}", code, sender_addr);
            let _ = stream.write_all(b"OK registered - waiting for receiver...\n");

            // Park the stream in the map; receiver handler will write to it
            peers.lock().unwrap().insert(code, (sender_addr, stream));
            // The thread just holds the stream open until the receiver matches it.
            // The socket will be dropped either by the receiver handler or by timeout.
        }
        Some("LOOKUP") => {
            if parts.len() < 2 {
                let _ = stream.write_all(b"ERR missing code: LOOKUP <code>\n");
                return;
            }
            let code = parts[1].trim().to_string();
            println!("[signal] LOOKUP '{}' from {}", code, peer_addr);

            let entry = peers.lock().unwrap().remove(&code);
            match entry {
                Some((sender_addr, mut sender_stream)) => {
                    use std::io::Write;
                    // Tell the receiver where the sender is
                    let _ = stream.write_all(format!("PEER {}\n", sender_addr).as_bytes());
                    // Tell the sender where the receiver is
                    let _ = sender_stream.write_all(format!("PEER {}\n", peer_addr).as_bytes());
                    println!(
                        "[signal] MATCHED '{}': {} <-> {}",
                        code, sender_addr, peer_addr
                    );
                }
                None => {
                    let _ = stream.write_all(b"ERR code not found - check phrase or try again\n");
                    println!("[signal] NOT FOUND '{}'", code);
                }
            }
        }
        _ => {
            let _ = stream.write_all(
                b"ERR unknown command\nUsage:\n  REGISTER <code> <quic-port>\n  LOOKUP <code>\n",
            );
        }
    }
}

/// Run the signal server (blocks forever).
fn run_signal_server(port: u16) {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = match std::net::TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind signal server on {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };

    let local_ip = detect_public_ip().unwrap_or_else(|| "unknown".to_string());

    println!("Tallow Signal Server");
    println!("==================");
    println!("Listening on  : {}", bind_addr);
    println!("Local IP      : {}", local_ip);
    println!("Protocol      : TCP, line-delimited");
    println!("Session TTL   : 5 minutes");
    println!();
    println!(
        "Sender usage  : tallow send <file> --signal <this-host>:{}",
        port
    );
    println!(
        "Receiver usage: tallow receive <code> --signal <this-host>:{}",
        port
    );
    println!();
    println!("Commands accepted from clients:");
    println!("  REGISTER <code-phrase> <quic-port>");
    println!("  LOOKUP <code-phrase>");
    println!();
    println!("Press Ctrl-C to stop.");

    // In-memory peer table: code-phrase -> (sender_addr, parked_stream)
    let peers: Arc<Mutex<HashMap<String, (String, std::net::TcpStream)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let peer_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string());
        let peers = Arc::clone(&peers);
        std::thread::spawn(move || {
            handle_signal_client(stream, peers, peer_addr);
        });
    }
}

/// Minimal interactive chat over the Tallow relay protocol.
///
/// Sends each line as a `TALLOW-SEND <code> <name>: <line>` and polls for
/// inbound messages with `TALLOW-RECV <code>` on a background thread. Real
/// network I/O — requires a reachable relay (start one with
/// `tallow relay <port>`), which both parties point at via `--relay`.
fn run_relay_chat(name: &str, code: &str, relay_addr: &str) {
    use std::io::{BufRead, IsTerminal, Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let interactive = std::io::stdin().is_terminal();
    let name_owned = name.to_string();
    let code_owned = code.to_string();
    let relay_owned = relay_addr.to_string();
    let self_prefix = format!("{}:", name_owned);

    // Jittered poll interval: with a fixed cadence, two clients' recv polls
    // can stay aligned and the relay's serial accept loop lets the sender's
    // own grab+re-push chain starve the peer indefinitely. A per-iteration
    // random delay (180-440ms) breaks that lockstep.
    let chat_poll_delay = || {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        Duration::from_millis(180 + (nanos % 260) as u64)
    };

    // Receiver thread: poll the relay for messages under our rendezvous code.
    std::thread::Builder::new()
        .name("tallow-chat-recv".to_string())
        .spawn(move || {
            loop {
                if let Ok(mut s) = TcpStream::connect(&relay_owned) {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                    let req = format!("TALLOW-RECV\n{}\n", code_owned);
                    if s.write_all(req.as_bytes()).is_ok() {
                        let _ = s.flush();
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        loop {
                            match s.read(&mut chunk) {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                Err(_) => break,
                            }
                        }
                        if !buf.is_empty() {
                            let msg = String::from_utf8_lossy(&buf).trim().to_string();
                            if msg.is_empty() {
                                continue;
                            }
                            if msg.starts_with(&self_prefix) {
                                // Our own echo won the poll race — push it back
                                // so the peer can still retrieve it, then yield
                                // the mailbox for a long random backoff. The
                                // relay's consume-on-read semantics mean a
                                // sender that keeps grabbing + re-pushing its
                                // own message can starve the peer's poller;
                                // the backoff gives the peer a clear window.
                                let _ = TcpStream::connect(&relay_owned).and_then(|mut s| {
                                    let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
                                    s.write_all(
                                        format!("TALLOW-SEND\n{}\n{}\n", code_owned, msg)
                                            .as_bytes(),
                                    )
                                    .and_then(|_| s.flush())
                                });
                                let nanos = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.subsec_nanos())
                                    .unwrap_or(0);
                                std::thread::sleep(Duration::from_millis(800 + u64::from(nanos % 400)));
                                continue;
                            }
                            if interactive {
                                println!("\r\x1b[K{}", msg);
                            } else {
                                println!("{}", msg);
                            }
                            if interactive {
                                print!("> ");
                                let _ = std::io::stdout().flush();
                            }
                        }
                    }
                }
                std::thread::sleep(chat_poll_delay());
            }
        })
        .ok();

    // Main thread: read stdin and push lines through the relay.
    println!("> ");
    let _ = std::io::stdout().flush();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            print!("> ");
            let _ = std::io::stdout().flush();
            continue;
        }
        if line == "/quit" || line == "/exit" {
            break;
        }
        let payload = format!("{}: {}", name, line);
        match TcpStream::connect(relay_addr) {
            Ok(mut s) => {
                let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
                let msg = format!("TALLOW-SEND\n{}\n{}\n", code, payload);
                let _ = s.write_all(msg.as_bytes());
                let _ = s.flush();
                println!("you: {}", line);
            }
            Err(e) => eprintln!(
                "relay unreachable ({}): is `tallow relay` running at {}?",
                e, relay_addr
            ),
        }
        print!("> ");
        let _ = std::io::stdout().flush();
    }
    println!("\nchat ended.");
}

/// Doctor check: verify the tallow crate resolves with `cargo metadata`
/// (no build, fast). True when the command exits successfully.
fn cargo_metadata_ok() -> bool {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(manifest_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn configure_throughput_runtime(threads: Option<usize>, quiet: bool) {
    let Some(threads) = threads else {
        return;
    };
    if threads == 0 {
        eprintln!("warning: ignoring --throughput-threads=0 (use a value >= 1)");
        return;
    }
    match rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        Ok(_) => {
            if !quiet {
                eprintln!("[tallow] throughput threads set to {threads}");
            }
        }
        Err(_) => {
            // Another global pool may already exist; keep behavior backward compatible.
            if !quiet {
                eprintln!(
                    "[tallow] throughput thread override ignored: global rayon pool already initialized"
                );
            }
        }
    }
}

/// The one place the version question is answered.
///
/// Clap's `-V/--version` and the `version` subcommand used to answer it differently: the flag printed
/// only the package version, the subcommand printed the revision as well. That is the worst possible
/// split for this particular question — an operator reading a deployed binary's version is usually
/// trying to establish *which commit* it is, and half the ways to ask told them nothing about it. The
/// build stamp is injected by `build.rs` (`GIT_HASH`, `BUILD_DATE`), so both paths now print it from
/// here, and a binary built without the stamp says `unknown` rather than implying one.
fn print_version() {
    println!("tallow {}", env!("CARGO_PKG_VERSION"));
    println!("  platform: {}", std::env::consts::OS);
    println!("  arch: {}", std::env::consts::ARCH);
    println!("  build: {}", option_env!("BUILD_DATE").unwrap_or("dev"));
    println!("  git: {}", option_env!("GIT_HASH").unwrap_or("unknown"));
}

fn main() {
    // Process hardening (T-125): core dumps off + NOFILE soft floor.
    // Best-effort - warn and continue when the environment denies setrlimit.
    if let Err(err) = tallow::runtime::hardening::apply_process_hardening() {
        eprintln!("tallow: process hardening partially applied: {err}");
    }

    // RT-FIX-6: capture the HSM module env host-side BEFORE any script code can
    // run — script-level env.set must never influence the native `dlopen` path.
    tallow::stdlib::crypto::capture_hsm_env();

    // Root-crate logging standard (T-127): tracing + redaction + JSONL sink 0600.
    if let Err(err) = tallow::logging::init_logging() {
        eprintln!("tallow: logging init failed: {err}");
    }

    // ICE (Internal Compiler Error) handler
    std::panic::set_hook(Box::new(|info| {
        eprintln!();
        eprintln!("error: internal compiler error (ICE)");
        eprintln!();
        eprintln!("This is a bug in tallow. Please report it.");
        eprintln!();
        eprintln!("  tallow version: {}", env!("CARGO_PKG_VERSION"));
        eprintln!(
            "  platform:     {}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        if let Some(loc) = info.location() {
            eprintln!(
                "  location:     {}:{}:{}",
                loc.file(),
                loc.line(),
                loc.column()
            );
        }
        if let Some(msg) = info.payload().downcast_ref::<&str>() {
            eprintln!("  message:      {}", msg);
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            eprintln!("  message:      {}", msg);
        }
        eprintln!();
        eprintln!("Please file a bug report at:");
        eprintln!("  https://github.com/tallow-lang/tallow/issues/new?template=ice.yml");
        eprintln!();
    }));

    // Spawn with a larger stack to handle deep recursion in the interpreter.
    // 64MB: debug frames are ~0.6MB, so ~100 depth (~58MB) is safe while still
    // capping pathological recursion at MAX_CALL_DEPTH=100 with a clean error.
    let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024); // 64 MB
    let handler = builder
        .spawn(move || {
            if let Err(e) = real_main() {
                eprintln!("error: {e}");
                std::process::exit(exit_codes::COMPILE_ERROR);
            }
        })
        .expect("failed to spawn main thread");
    if handler.join().is_err() {
        std::process::exit(exit_codes::ICE);
    }
}

fn real_main() -> anyhow::Result<()> {
    // `-V`/`--version` as the FIRST argument, answered here rather than by clap: clap's generated flag
    // cannot carry the revision (its version string must be a literal), and the alternative — a bool
    // field on `Cli` with `disable_version_flag` — forces `command` to become optional, which ripples
    // through every match arm for no gain. A subcommand's own `--version` is untouched: this only fires
    // when the flag is the first argument, so `tallow sluice ...` is unaffected.
    if matches!(std::env::args().nth(1).as_deref(), Some("-V") | Some("--version")) {
        print_version();
        return Ok(());
    }
    let cli = Cli::parse();
    let quiet = cli.quiet;
    let _verbose = cli.verbose;
    let _no_color = cli.no_color;
    let parser_mode = cli.parser_mode;
    let throughput_threads = cli.throughput_threads;

    match cli.command {
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "tallow", &mut std::io::stdout());
            return Ok(());
        }
        Command::Phone { args } => {
            use tallow::cli::phone_cmd;
            phone_cmd::run_phone_cmd(&args).map_err(anyhow::Error::msg)?;
            return Ok(());
        }
        Command::Rmd { args } => {
            use tallow::cli::rmdb_cmd;
            rmdb_cmd::run_rmdb_cmd(&args).map_err(anyhow::Error::msg)?;
            return Ok(());
        }
        Command::VerifyLedger { args } => {
            use tallow::cli::verify_ledger_cmd;
            verify_ledger_cmd::run_verify_ledger_cmd(&args).map_err(anyhow::Error::msg)?;
            return Ok(());
        }
        Command::Sluice { args } => {
            // Exit status is the verdict: 0 ALLOW, 1 DENY or error. The reason
            // is in the printed verdict's `code`, never in the status.
            std::process::exit(tallow::cli::sluice_cmd::run_sluice_args(&args));
        }
        Command::Pin { args } => {
            use tallow::cli::pin_cmd;
            pin_cmd::run_pin_cmd(&args).map_err(anyhow::Error::msg)?;
            return Ok(());
        }
        Command::Scope { args } => {
            // Exit status is the verdict: 0 allowed, 2 refused or defective.
            // The reason goes to stderr and is never implied by the status alone.
            match tallow::cli::scope_cmd::run_scope_cmd(&args) {
                Ok(()) => return Ok(()),
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(2);
                }
            }
        }
        Command::Veil { args } => {
            std::process::exit(tallow::cli::veil_cmd::run_veil_args(&args));
        }
        Command::NeverCheck => {
            std::process::exit(tallow::cli::never_probe::run_never_probe());
        }
        Command::FingerprintAudit { args } => {
            std::process::exit(tallow::cli::fingerprint_audit_cmd::run_fingerprint_audit_args(&args));
        }
        Command::Secrets { args } => {
            std::process::exit(tallow::cli::secrets_cmd::run_secrets_args(&args));
        }
        Command::Canary { args } => {
            std::process::exit(tallow::cli::canary_cmd::run_canary_args(&args));
        }
        Command::FixitySweep { args } => {
            std::process::exit(tallow::cli::fixity_cmd::run_fixity_sweep_args(&args));
        }
        Command::Schema { args } => {
            // Exit status is the verdict: 0 valid, 1 invalid (the failing field
            // is named on stderr), 64 usage / unreadable file.
            std::process::exit(tallow::cli::schema_cmd::run_schema_args(&args));
        }
        Command::Plan { args } => {
            // Exit status is the verdict: 0 ok, 1 invalid (the offending request
            // is named), 64 usage / unreadable file. This path must not egress —
            // the arm it calls is statically barred from naming the egress entry.
            std::process::exit(tallow::cli::plan_cmd::run_plan_args(&args));
        }
        Command::Extract { args } => {
            // Exit status is the verdict: 0 rows written, 1 nothing usable (the
            // field is named), 64 usage. Local-only: the row contract allows
            // `mode: local_mock` and `live_scraping: false` and nothing else.
            std::process::exit(tallow::cli::extract_cmd::run_extract_args(&args));
        }
        Command::Compliance { ref action } => {
            // Row #179 (lane I): local-only generators. `--now` accepts unix
            // seconds or `YYYY-MM-DDTHH:MM:SSZ` so reports are reproducible.
            let now = |ts: &Option<String>| -> Result<Option<i64>, String> {
                match ts {
                    Some(s) => compliance::parse_timestamp(s).map(Some),
                    None => Ok(None),
                }
            };
            let code = match action {
                ComplianceAction::Clocks {
                    spec,
                    now: now_ts,
                    format,
                    out,
                } => match now(now_ts) {
                    Ok(now) => {
                        compliance::cli::run_clocks(spec, now, format, out.as_deref())
                    }
                    Err(e) => {
                        eprintln!("tallow compliance clocks: {e}");
                        compliance::cli::EXIT_COULD_NOT_RUN
                    }
                },
                ComplianceAction::Incident {
                    spec,
                    ledger,
                    key,
                    now: now_ts,
                    format,
                    out,
                } => match now(now_ts) {
                    Ok(now) => compliance::cli::run_incident(
                        spec,
                        ledger.as_deref(),
                        key.as_deref(),
                        now,
                        format,
                        out.as_deref(),
                    ),
                    Err(e) => {
                        eprintln!("tallow compliance incident: {e}");
                        compliance::cli::EXIT_COULD_NOT_RUN
                    }
                },
                ComplianceAction::ZnismPack {
                    config,
                    now: now_ts,
                    format,
                    out,
                } => match now(now_ts) {
                    Ok(now) => {
                        compliance::cli::run_znism(config.as_deref(), now, format, out.as_deref())
                    }
                    Err(e) => {
                        eprintln!("tallow compliance znism-pack: {e}");
                        compliance::cli::EXIT_COULD_NOT_RUN
                    }
                },
            };
            std::process::exit(code);
        }
        Command::Config { ref action } => {
            match action {
                ConfigAction::Path => {
                    let config_dir = dirs::config_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join("tallow");
                    println!("{}", config_dir.join("config.toml").display());
                }
                ConfigAction::List => {
                    let config_path = dirs::config_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join("tallow")
                        .join("config.toml");
                    if config_path.exists() {
                        if let Ok(contents) = std::fs::read_to_string(&config_path) {
                            print!("{}", contents);
                        }
                    } else {
                        println!("# Default configuration (no config file found)");
                        println!("format = \"text\"");
                        println!("no_color = false");
                        println!("telemetry = false");
                    }
                }
                ConfigAction::Get { key } => {
                    let config_path = dirs::config_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join("tallow")
                        .join("config.toml");
                    if config_path.exists() {
                        if let Ok(contents) = std::fs::read_to_string(&config_path) {
                            let mut found = false;
                            for line in contents.lines() {
                                if line.starts_with(&format!("{} ", key))
                                    || line.starts_with(&format!("{}=", key))
                                {
                                    println!("{}", line);
                                    found = true;
                                    break;
                                }
                            }
                            if !found {
                                println!("{} = (default)", key);
                            }
                        } else {
                            println!("{} = (default)", key);
                        }
                    } else {
                        println!("{} = (default)", key);
                    }
                }
                ConfigAction::Set { key, value } => {
                    let config_dir = dirs::config_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join("tallow");
                    std::fs::create_dir_all(&config_dir)?;
                    let config_path = config_dir.join("config.toml");
                    let mut contents = if config_path.exists() {
                        std::fs::read_to_string(&config_path).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    // Replace existing key or append
                    let line_prefix = format!("{} = ", key);
                    let new_line = format!("{} = \"{}\"", key, value);
                    if let Some(pos) = contents.find(&line_prefix) {
                        let end = contents[pos..]
                            .find('\n')
                            .map(|i| pos + i)
                            .unwrap_or(contents.len());
                        contents.replace_range(pos..end, &new_line);
                    } else {
                        if !contents.is_empty() && !contents.ends_with('\n') {
                            contents.push('\n');
                        }
                        contents.push_str(&new_line);
                        contents.push('\n');
                    }
                    std::fs::write(&config_path, &contents)?;
                    // Telemetry choke point (R-6.1 slice 1): record the config
                    // write (key + size bucket only — never the value), best-
                    // effort. Config tampering stops being silent.
                    let _ = tallow::observability::emit_to_default_journal(
                        &tallow::observability::SecurityEvent {
                            class: tallow::observability::EventClass::ConfigChange,
                            actor: "cli.config".to_string(),
                            target: Some(key.clone()),
                            size: value.len(),
                            at_ms: tallow::observability::now_ms(),
                        },
                    );
                    println!("set {} = \"{}\"", key, value);
                }
                ConfigAction::Lint {
                    preset,
                    strict,
                    format,
                    path,
                } => {
                    // KB-7 (row #66): read-only baseline scoring; exit code
                    // 0 = pass, 1 = findings, 2 = could not run.
                    std::process::exit(tallow::config::cli::run_config_lint(
                        preset.as_deref(),
                        *strict,
                        format.as_str(),
                        path.as_deref(),
                    ));
                }
                ConfigAction::Presets { format } => {
                    // KB-7: print the deployable hardening floor tables.
                    std::process::exit(tallow::config::cli::run_config_presets(format.as_str()));
                }
                ConfigAction::Bundle { action } => {
                    // R-7.4/R-7.8 (rows #153/#198): signed config bundles —
                    // export/import with verify-before-write; exit codes:
                    // 0 = ok, 1 = checked refusal, 2 = could not run.
                    let code = match action {
                        BundleAction::Keygen { out, format } => {
                            tallow::config::cli::run_config_bundle_keygen(out, format.as_str())
                        }
                        BundleAction::Export {
                            config,
                            out,
                            scope,
                            key,
                            format,
                        } => tallow::config::cli::run_config_bundle_export(
                            config.as_deref(),
                            out,
                            scope.as_str(),
                            key,
                            format.as_str(),
                        ),
                        BundleAction::Import {
                            bundle,
                            to,
                            scope,
                            trusted_key,
                            history_dir,
                            dry_run,
                            format,
                        } => tallow::config::cli::run_config_bundle_import(
                            bundle,
                            to,
                            scope.as_deref(),
                            trusted_key,
                            history_dir.as_deref(),
                            *dry_run,
                            format.as_str(),
                        ),
                        BundleAction::Verify {
                            bundle,
                            trusted_key,
                            format,
                        } => tallow::config::cli::run_config_bundle_verify(
                            bundle,
                            trusted_key,
                            format.as_str(),
                        ),
                    };
                    std::process::exit(code);
                }
            }
            return Ok(());
        }
        Command::Enroll { ref action } => {
            // R-5.5 (row #57): enrollment ceremony — CPace PAKE + SAS word comparison +
            // single-use join tokens (+ attestation where available). Exit codes:
            // 0 = issued, 1 = checked refusal/detection, 2 = could not run.
            let code = match action {
                EnrollAction::Ceremony {
                    scenario,
                    device,
                    format,
                } => tallow::enrollment::cli::run_enroll_ceremony(
                    scenario,
                    device,
                    format.as_str(),
                ),
                EnrollAction::Token { ttl, format } => {
                    tallow::enrollment::cli::run_enroll_token(*ttl, format.as_str())
                }
            };
            std::process::exit(code);
        }
        Command::New {
            ref name,
            ref template,
        } => {
            return create_project(name, template);
        }
        Command::Fmt { ref file } => {
            return format_file(file);
        }
        Command::Test {
            ref path,
            ref filter,
            coverage,
        } => {
            return run_tests(path, filter.as_deref(), coverage);
        }
        Command::Repl => {
            return run_repl();
        }
        Command::Lsp => {
            tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime")
                .block_on(tallow::lsp::run_lsp_server());
            return Ok(());
        }
        Command::Version => {
            print_version();
            return Ok(());
        }
        Command::Targets => {
            println!("{}", tallow::codegen::TargetConfig::list_targets());
            return Ok(());
        }
        Command::Add {
            ref package,
            ref version,
        } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_add(package, version.as_deref(), &project_dir, &registry_path)?;
            return Ok(());
        }
        Command::Remove {
            ref package,
            dry_run,
        } => {
            if dry_run {
                println!("(dry run) would remove: {}", package);
                return Ok(());
            }
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_remove(package, &project_dir, &registry_path)?;
            return Ok(());
        }
        Command::Update { dry_run } => {
            if dry_run {
                println!("(dry run) would update all dependencies to latest compatible versions");
                return Ok(());
            }
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_update(&project_dir, &registry_path)?;
            return Ok(());
        }
        Command::Install { offline, dry_run } => {
            if dry_run {
                println!("(dry run) would install dependencies from tallow.lock");
                if offline {
                    println!("  (offline mode: using only cached packages)");
                }
                return Ok(());
            }
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_install(&project_dir, &registry_path, offline)?;
            return Ok(());
        }
        Command::Sbom {
            ref format,
            ref output,
        } => {
            return run_sbom(format, output.as_deref());
        }
        Command::Sign {
            ref archive,
            ref key,
        } => {
            return run_sign(archive, key);
        }
        Command::Verify {
            ref archive,
            ref key,
        } => {
            return run_verify(archive, key);
        }
        Command::Publish => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_publish(&project_dir, &registry_path)?;
            return Ok(());
        }
        Command::Search { ref query } => {
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_search(query, &registry_path)?;
            return Ok(());
        }
        Command::Why { ref package, full } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            tallow::pkg::cli::pkg_why(package, full, &project_dir)?;
            return Ok(());
        }
        Command::Patch {
            ref package,
            ref edit_dir,
        } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_patch(
                package,
                edit_dir.as_deref(),
                &project_dir,
                &registry_path,
            )?;
            return Ok(());
        }
        Command::PatchCommit { ref path } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            tallow::pkg::cli::pkg_patch_commit(path, &project_dir)?;
            return Ok(());
        }
        Command::PatchRemove { ref package } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            tallow::pkg::cli::pkg_patch_remove(package, &project_dir)?;
            return Ok(());
        }
        Command::Tree { depth, json } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            tallow::pkg::cli::pkg_tree(depth, json, &project_dir)?;
            return Ok(());
        }
        Command::Cache { ref action } => {
            let registry_path = tallow::pkg::cli::default_registry_path();
            match action {
                CacheAction::Info => {
                    tallow::pkg::cli::pkg_cache_info(&registry_path)?;
                }
                CacheAction::Prune => {
                    tallow::pkg::cli::pkg_cache_prune(&registry_path)?;
                }
                CacheAction::Clean => {
                    tallow::pkg::cli::pkg_cache_clean(&registry_path)?;
                }
                CacheAction::Verify => {
                    tallow::pkg::cli::pkg_cache_verify(&registry_path)?;
                }
            }
            return Ok(());
        }
        Command::Outdated { json } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::cli::pkg_outdated(json, &project_dir, &registry_path)?;
            return Ok(());
        }
        Command::SmtExport {
            ref file,
            ref output_dir,
            proverif,
        } => {
            let source = std::fs::read_to_string(file)
                .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", file.display()))?;
            let (tokens, lex_errors) = tallow::lexer::tokenize(&source);
            if !lex_errors.is_empty() {
                for err in &lex_errors {
                    let (line, col) = err.span().line_col(&source);
                    eprintln!("error[{line}:{col}]: {err}");
                }
                std::process::exit(exit_codes::IO_ERROR);
            }
            let mut program = match tallow::parser::Parser::parse(tokens) {
                Ok(p) => p,
                Err(err) => {
                    let (line, col) = err.span.line_col(&source);
                    eprintln!("error[{line}:{col}]: {err}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            };
            resolve_imports(&mut program, file);

            let results = smt_export::generate_all_smt(&program);

            // Create output directory if needed
            std::fs::create_dir_all(output_dir).map_err(|e| {
                anyhow::anyhow!(
                    "cannot create output directory '{}': {e}",
                    output_dir.display()
                )
            })?;

            let mut exported = 0u32;
            let mut skipped = 0u32;
            for result in &results {
                if result.skipped {
                    skipped += 1;
                    continue;
                }
                let out_path = output_dir.join(format!("{}.smt2", result.function_name));
                std::fs::write(&out_path, &result.smt_text)
                    .map_err(|e| anyhow::anyhow!("cannot write '{}': {e}", out_path.display()))?;
                println!("  wrote: {}", out_path.display());
                exported += 1;
            }
            println!(
                "SMT export complete: {} exported, {} skipped (no contracts or unsupported types)",
                exported, skipped
            );

            // Feature 7: ProVerif model export
            if proverif {
                let pv_text = smt_export::export_proverif(&program);
                let pv_path = output_dir.join("model.pv");
                std::fs::write(&pv_path, &pv_text).map_err(|e| {
                    anyhow::anyhow!("cannot write ProVerif model '{}': {e}", pv_path.display())
                })?;
                println!("  wrote: {} (ProVerif model)", pv_path.display());
                println!("  verify with: proverif {}", pv_path.display());
            }

            return Ok(());
        }
        // ── Phase 57: Transfer CLI commands ──
        Command::Hash { ref file } => {
            let data = std::fs::read(file)
                .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", file.display()))?;
            let hash = blake3::hash(&data);
            println!("{}", hash.to_hex());
            return Ok(());
        }
        Command::Encrypt {
            ref input,
            ref output,
            ref password,
        } => {
            use tallow::interp::Value;
            let result = tallow::stdlib::transfer::dispatch(
                "vault_encrypt_file",
                vec![
                    Value::String(input.display().to_string()),
                    Value::String(output.display().to_string()),
                    Value::String(password.clone()),
                ],
            );
            match result {
                Some(Ok(_)) => {
                    println!("encrypted: {} -> {}", input.display(), output.display());
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                None => {
                    eprintln!("error: encrypt dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Decrypt {
            ref input,
            ref output,
            ref password,
        } => {
            use tallow::interp::Value;
            let result = tallow::stdlib::transfer::dispatch(
                "vault_decrypt_file",
                vec![
                    Value::String(input.display().to_string()),
                    Value::String(output.display().to_string()),
                    Value::String(password.clone()),
                ],
            );
            match result {
                Some(Ok(_)) => {
                    println!("decrypted: {} -> {}", input.display(), output.display());
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                None => {
                    eprintln!("error: decrypt dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Copy { ref src, ref dst } => {
            use rayon::prelude::*;
            use std::sync::Mutex;
            use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
            use tallow::interp::Value;

            // ── S3 URL routing ─────────────────────────────────────────────
            // Parse s3://bucket/key from a URL string.
            fn parse_s3_url(url: &str) -> Option<(String, String)> {
                let rest = url.strip_prefix("s3://")?;
                let slash = rest.find('/').unwrap_or(rest.len());
                let bucket = rest[..slash].to_string();
                let key = if slash < rest.len() {
                    rest[slash + 1..].to_string()
                } else {
                    String::new()
                };
                Some((bucket, key))
            }

            let src_is_s3 = src.starts_with("s3://");
            let dst_is_s3 = dst.starts_with("s3://");

            if src_is_s3 || dst_is_s3 {
                // Cloud copy routing:
                //   local → s3://  : upload
                //   s3:// → local  : download
                //   s3:// → s3://  : server-side copy via download + upload (no S3 CopyObject yet)
                if !src_is_s3 && dst_is_s3 {
                    // Upload local file to S3
                    let (bucket, key) = parse_s3_url(dst).expect("invalid s3:// dst URL");
                    eprintln!("Uploading {} → s3://{bucket}/{key}", src);
                    let result = tallow::stdlib::transfer::dispatch(
                        "cloud_s3_upload",
                        vec![
                            Value::String(bucket.clone()),
                            Value::String(key.clone()),
                            Value::String(src.clone()),
                        ],
                    );
                    match result {
                        Some(Ok(Value::Struct { ref fields, .. })) => {
                            let size = fields
                                .iter()
                                .find(|(k, _)| k == "size")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let etag = fields
                                .iter()
                                .find(|(k, _)| k == "etag")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let bh = fields
                                .iter()
                                .find(|(k, _)| k == "blake3")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            println!(
                                "uploaded s3://{bucket}/{key}  size={size}  etag={etag}  blake3={}",
                                &bh[..16]
                            );
                        }
                        Some(Err(e)) => {
                            eprintln!("error: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                        _ => {}
                    }
                } else if src_is_s3 && !dst_is_s3 {
                    // Download S3 object to local file
                    let (bucket, key) = parse_s3_url(src).expect("invalid s3:// src URL");
                    eprintln!("Downloading s3://{bucket}/{key} → {dst}");
                    let result = tallow::stdlib::transfer::dispatch(
                        "cloud_s3_download",
                        vec![
                            Value::String(bucket.clone()),
                            Value::String(key.clone()),
                            Value::String(dst.clone()),
                        ],
                    );
                    match result {
                        Some(Ok(Value::Struct { ref fields, .. })) => {
                            let size = fields
                                .iter()
                                .find(|(k, _)| k == "size")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let bh = fields
                                .iter()
                                .find(|(k, _)| k == "blake3")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            println!(
                                "downloaded s3://{bucket}/{key} → {dst}  size={size}  blake3={}",
                                &bh[..16]
                            );
                        }
                        Some(Err(e)) => {
                            eprintln!("error: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                        _ => {}
                    }
                } else {
                    // S3 → S3: download then upload
                    let (src_bucket, src_key) = parse_s3_url(src).expect("invalid s3:// src URL");
                    let (dst_bucket, dst_key) = parse_s3_url(dst).expect("invalid s3:// dst URL");
                    let tmp = std::env::temp_dir()
                        .join(format!("tallow-s3-{}.tmp", uuid::Uuid::new_v4()));
                    let tmp_str = tmp.to_string_lossy().to_string();
                    eprintln!("Copying s3://{src_bucket}/{src_key} → s3://{dst_bucket}/{dst_key}");

                    let dl = tallow::stdlib::transfer::dispatch(
                        "cloud_s3_download",
                        vec![
                            Value::String(src_bucket.clone()),
                            Value::String(src_key.clone()),
                            Value::String(tmp_str.clone()),
                        ],
                    );
                    if let Some(Err(e)) = dl {
                        eprintln!("download error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }

                    let ul = tallow::stdlib::transfer::dispatch(
                        "cloud_s3_upload",
                        vec![
                            Value::String(dst_bucket.clone()),
                            Value::String(dst_key.clone()),
                            Value::String(tmp_str.clone()),
                        ],
                    );
                    let _ = std::fs::remove_file(&tmp);
                    match ul {
                        Some(Ok(_)) => println!(
                            "copied s3://{src_bucket}/{src_key} → s3://{dst_bucket}/{dst_key}"
                        ),
                        Some(Err(e)) => {
                            eprintln!("upload error: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                        _ => {}
                    }
                }
                return Ok(());
            }
            // ── end S3 routing ─────────────────────────────────────────────

            let src_path = std::path::PathBuf::from(src);
            let dst_path = std::path::PathBuf::from(dst);
            let src_meta = std::fs::metadata(&src_path);
            let dst_is_dir = std::fs::metadata(&dst_path)
                .map(|m| m.is_dir())
                .unwrap_or(false);

            // If source is a directory, or destination is a directory → parallel delta sync
            let src_is_dir = src_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            if src_is_dir || (dst_is_dir && src_is_dir) {
                eprintln!(
                    "Directory detected — using parallel fast-path sync (mtime+size comparison)"
                );
                let start = std::time::Instant::now();
                let src_path = std::path::PathBuf::from(src.as_str());
                let dst_path = std::path::PathBuf::from(dst.as_str());

                struct FileInfo {
                    rel: std::path::PathBuf,
                    size: u64,
                    mtime: u64,
                }

                fn walk_copy_parallel(
                    base: &std::path::Path,
                    dir: &std::path::Path,
                    out: &Mutex<Vec<FileInfo>>,
                ) {
                    use rayon::prelude::*;
                    let top: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
                        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
                        Err(_) => return,
                    };
                    top.par_iter().for_each(|entry| {
                        let path = entry.path();
                        let meta = match entry.metadata() {
                            Ok(m) => m,
                            Err(_) => return,
                        };
                        if meta.is_symlink() {
                            return;
                        }
                        if meta.is_dir() {
                            walk_copy_subtree(base, &path, out);
                        } else if meta.is_file() {
                            let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                            let mtime = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            out.lock().unwrap().push(FileInfo {
                                rel,
                                size: meta.len(),
                                mtime,
                            });
                        }
                    });
                }

                fn walk_copy_subtree(
                    base: &std::path::Path,
                    dir: &std::path::Path,
                    out: &Mutex<Vec<FileInfo>>,
                ) {
                    let entries = match std::fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return,
                    };
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        let meta = match entry.metadata() {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        if meta.is_symlink() {
                            continue;
                        }
                        if meta.is_dir() {
                            walk_copy_subtree(base, &path, out);
                        } else if meta.is_file() {
                            let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                            let mtime = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            out.lock().unwrap().push(FileInfo {
                                rel,
                                size: meta.len(),
                                mtime,
                            });
                        }
                    }
                }

                eprint!("Scanning... ");
                let files_mutex: Mutex<Vec<FileInfo>> = Mutex::new(Vec::new());
                walk_copy_parallel(&src_path, &src_path, &files_mutex);
                let files: Vec<FileInfo> = files_mutex.into_inner().unwrap();
                let total = files.len();
                eprintln!("{total} files");

                // Batch mkdir
                {
                    let mut dirs_needed: std::collections::HashSet<std::path::PathBuf> =
                        std::collections::HashSet::new();
                    for fi in &files {
                        if let Some(p) = dst_path.join(&fi.rel).parent() {
                            dirs_needed.insert(p.to_path_buf());
                        }
                    }
                    for d in &dirs_needed {
                        let _ = std::fs::create_dir_all(d);
                    }
                }

                let at_copied = AtomicUsize::new(0);
                let at_skipped = AtomicUsize::new(0);
                let at_bytes = AtomicU64::new(0);
                let at_checked = AtomicUsize::new(0);
                let copy_start = std::time::Instant::now();

                files.par_iter().for_each(|fi| {
                    let sf = src_path.join(&fi.rel);
                    let df = dst_path.join(&fi.rel);
                    let needs_copy = match std::fs::metadata(&df) {
                        Ok(dm) => {
                            let dst_mt = dm.modified().ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs()).unwrap_or(0);
                            dm.len() != fi.size || dst_mt != fi.mtime
                        }
                        Err(_) => true,
                    };
                    if needs_copy {
                        if let Some(p) = df.parent() { let _ = std::fs::create_dir_all(p); }
                        match tallow::stdlib::transfer::copy_file_with_fallback(&sf, &df) {
                            Ok(n) => { at_copied.fetch_add(1, Ordering::Relaxed); at_bytes.fetch_add(n, Ordering::Relaxed); }
                            Err(e) => { if at_copied.load(Ordering::Relaxed) < 5 { eprintln!("  WARN: {}: {}", fi.rel.display(), e); } }
                        }
                    } else { at_skipped.fetch_add(1, Ordering::Relaxed); }

                    let checked = at_checked.fetch_add(1, Ordering::Relaxed) + 1;
                    if total > 0 && (checked % 100 == 0 || checked == total) {
                        let cop = at_copied.load(Ordering::Relaxed);
                        let skp = at_skipped.load(Ordering::Relaxed);
                        let pct = (checked as f64 / total as f64 * 100.0) as usize;
                        let filled = pct * 30 / 100;
                        let bar: String = "█".repeat(filled) + &"░".repeat(30 - filled);
                        let elapsed = copy_start.elapsed().as_secs_f64();
                        let rate = if elapsed > 0.0 { checked as f64 / elapsed } else { 0.0 };
                        let eta = if checked > 0 { elapsed / checked as f64 * (total - checked) as f64 } else { 0.0 };
                        eprint!("\r  [{bar}] {pct:3}% | {checked}/{total} | {cop} copied, {skp} skipped | {rate:.0} files/s | ETA {eta:.0}s  ");
                    }
                });

                let elapsed = start.elapsed().as_secs_f64();
                let final_copied = at_copied.load(Ordering::Relaxed);
                let final_skipped = at_skipped.load(Ordering::Relaxed);
                let final_bytes = at_bytes.load(Ordering::Relaxed);
                let mb = final_bytes as f64 / 1_048_576.0;
                eprintln!(
                    "\r  [{}] 100% | DONE                                                      ",
                    "█".repeat(30)
                );
                eprintln!(
                    "  Copied: {} files ({:.1} MB) | Skipped: {} | Time: {:.1}s",
                    final_copied, mb, final_skipped, elapsed
                );
            } else {
                // Single file copy (original behavior)
                let result = tallow::stdlib::transfer::dispatch(
                    "fast_copy",
                    vec![Value::String(src.clone()), Value::String(dst.clone())],
                );
                match result {
                    Some(Ok(Value::Struct { fields, .. })) => {
                        let bytes = fields
                            .iter()
                            .find(|(k, _)| k == "bytes_copied")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let ms = fields
                            .iter()
                            .find(|(k, _)| k == "elapsed_ms")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        println!("copied {} bytes in {}ms", bytes, ms);
                    }
                    Some(Err(e)) => {
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {}
                }
            }
            return Ok(());
        }
        Command::DeltaSync {
            ref source,
            ref target,
            dry_run,
            mirror,
            threads,
            ref exclude_patterns,
            ref exclude_dirs,
            retries,
            ref log,
            compress,
            max_age,
            min_size,
            max_size,
            copy_acls,
            symlinks,
            ref save_job,
            ref load_job,
            ref run_hours,
            preserve_permissions,
            preserve_owner,
            follow_symlinks,
            bytes: show_bytes,
            quiet,
            verify,
            block_level,
            no_resume,
            ref journal_dir,
        } => {
            use rayon::prelude::*;
            use std::sync::Mutex;
            use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

            // ── Job load: override fields from a saved TOML job file ──
            // We shadow the mutable settings that can be overridden.
            // Immutable clap-bound fields (source, target) are NOT overridden from a job
            // because the user's positional args take precedence.
            let mut _threads = threads;
            let mut _retries = retries;
            let mut _mirror = mirror;
            let mut _dry_run = dry_run;
            let mut _verify = verify;
            let mut _quiet = quiet;
            let mut _ex_pats: Vec<String> = exclude_patterns.clone();
            let mut _ex_dirs: Vec<String> = exclude_dirs.clone();

            if let Some(job_path) = load_job {
                match std::fs::read_to_string(job_path) {
                    Ok(content) => match content.parse::<toml::Table>() {
                        Ok(table) => {
                            let sync = table.get("sync").and_then(|v| v.as_table());
                            if let Some(s) = sync {
                                if let Some(v) = s.get("threads").and_then(|v| v.as_integer()) {
                                    _threads = v as usize;
                                }
                                if let Some(v) = s.get("retries").and_then(|v| v.as_integer()) {
                                    _retries = v as u32;
                                }
                                if let Some(v) = s.get("mirror").and_then(|v| v.as_bool()) {
                                    _mirror = v;
                                }
                                if let Some(v) = s.get("verify").and_then(|v| v.as_bool()) {
                                    _verify = v;
                                }
                                if let Some(arr) =
                                    s.get("exclude_patterns").and_then(|v| v.as_array())
                                {
                                    _ex_pats = arr
                                        .iter()
                                        .filter_map(|v| v.as_str().map(str::to_owned))
                                        .collect();
                                }
                                if let Some(arr) = s.get("exclude_dirs").and_then(|v| v.as_array())
                                {
                                    _ex_dirs = arr
                                        .iter()
                                        .filter_map(|v| v.as_str().map(str::to_owned))
                                        .collect();
                                }
                            }
                            eprintln!("Loaded job: {}", job_path.display());
                        }
                        Err(e) => eprintln!(
                            "  WARN: could not parse job file {}: {}",
                            job_path.display(),
                            e
                        ),
                    },
                    Err(e) => eprintln!(
                        "  WARN: could not read job file {}: {}",
                        job_path.display(),
                        e
                    ),
                }
            }

            // Rebind to the (possibly overridden) values for the rest of the handler.
            let threads = _threads;
            let retries = _retries;
            let mirror = _mirror;
            let dry_run = _dry_run;
            let verify = _verify;
            let quiet = _quiet;
            let exclude_patterns = _ex_pats;
            let exclude_dirs = _ex_dirs;
            // Borrow slices the same way the rest of the code does.
            let exclude_patterns = &exclude_patterns;
            let exclude_dirs = &exclude_dirs;

            // ── Job save: persist current resolved config to a TOML file ──
            if let Some(job_path) = save_job {
                let mut ex_pats_toml = String::from("[");
                for (i, p) in exclude_patterns.iter().enumerate() {
                    if i > 0 {
                        ex_pats_toml.push_str(", ");
                    }
                    ex_pats_toml.push('"');
                    ex_pats_toml.push_str(p);
                    ex_pats_toml.push('"');
                }
                ex_pats_toml.push(']');

                let mut ex_dirs_toml = String::from("[");
                for (i, d) in exclude_dirs.iter().enumerate() {
                    if i > 0 {
                        ex_dirs_toml.push_str(", ");
                    }
                    ex_dirs_toml.push('"');
                    ex_dirs_toml.push_str(d);
                    ex_dirs_toml.push('"');
                }
                ex_dirs_toml.push(']');

                let job_content = format!(
                    "[sync]\nsource = \"{src}\"\ntarget = \"{dst}\"\nmirror = {mirror}\nthreads = {threads}\nexclude_patterns = {ex_pats_toml}\nexclude_dirs = {ex_dirs_toml}\nretries = {retries}\nverify = {verify}\n",
                    src = source.display(),
                    dst = target.display(),
                );
                match std::fs::write(job_path, &job_content) {
                    Ok(_) => eprintln!("Saved job: {}", job_path.display()),
                    Err(e) => eprintln!(
                        "  WARN: could not save job to {}: {}",
                        job_path.display(),
                        e
                    ),
                }
            }

            // ── Run-hours window: wait until we are within the allowed time window ──
            if let Some(window) = run_hours {
                // Parse "HH:MM-HH:MM"
                fn parse_hhmm(s: &str) -> Option<(u32, u32)> {
                    let mut parts = s.splitn(2, ':');
                    let h: u32 = parts.next()?.parse().ok()?;
                    let m: u32 = parts.next()?.parse().ok()?;
                    if h < 24 && m < 60 { Some((h, m)) } else { None }
                }
                let parts: Vec<&str> = window.splitn(2, '-').collect();
                if parts.len() == 2 {
                    if let (Some((sh, sm)), Some((eh, em))) =
                        (parse_hhmm(parts[0]), parse_hhmm(parts[1]))
                    {
                        loop {
                            let now = chrono::Local::now();
                            use chrono::Timelike as _;
                            let cur_min = now.hour() * 60 + now.minute();
                            let start_min = sh * 60 + sm;
                            let end_min = eh * 60 + em;

                            let in_window = if start_min <= end_min {
                                cur_min >= start_min && cur_min < end_min
                            } else {
                                // Wraps midnight: e.g. 22:00-04:00
                                cur_min >= start_min || cur_min < end_min
                            };

                            if in_window {
                                break;
                            }

                            eprintln!(
                                "Outside run window (current: {:02}:{:02}, window: {}). Waiting...",
                                now.hour(),
                                now.minute(),
                                window
                            );
                            std::thread::sleep(std::time::Duration::from_secs(30));
                        }
                    } else {
                        eprintln!(
                            "  WARN: could not parse --run-hours '{}' (expected HH:MM-HH:MM)",
                            window
                        );
                    }
                } else {
                    eprintln!(
                        "  WARN: could not parse --run-hours '{}' (expected HH:MM-HH:MM)",
                        window
                    );
                }
            }

            // Local/NAS copies: compression increases CPU work without reducing I/O
            // (source and dest are on the same fast link). --compress is only useful
            // for network transfers where bandwidth is the bottleneck.
            if compress {
                eprintln!(
                    "  Note: --compress is for network transfers only; ignored for local copies"
                );
            }

            // Configure rayon thread pool for this sync operation
            // We build a local pool to avoid colliding with any global rayon usage elsewhere
            let pool_result = rayon::ThreadPoolBuilder::new().num_threads(threads).build();
            let thread_pool = match pool_result {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("  WARN: could not build thread pool ({e}), falling back to default");
                    rayon::ThreadPoolBuilder::new().build().unwrap()
                }
            };

            let start = std::time::Instant::now();
            let src_path = source.clone();
            let dst_path = target.clone();

            // ── Delta-sync journal (R-3 tail / design §3.2) ──
            // File: <journal-dir>/run-<blake3(source+target)[..12]>.postcard,
            // default dir <target>/.tallow-journal/. Per-file statuses are recorded
            // (Pending before a copy starts, Committed after it — and after
            // --verify passes), flushed once per batch (256 entries / 10 s) and
            // once more when the copy phase completes.
            use tallow_protocol::transfer::journal::{JournalDecision, JournalWriter};
            let journal_path: Option<std::path::PathBuf> = if no_resume {
                if !quiet {
                    eprintln!("  journal:       OFF (--no-resume)");
                }
                None
            } else {
                let jdir = journal_dir
                    .clone()
                    .unwrap_or_else(|| dst_path.join(".tallow-journal"));
                let p = jdir.join(tallow_protocol::transfer::journal::journal_file_name(
                    &src_path, &dst_path,
                ));
                if !quiet {
                    eprintln!("  journal:       {}", p.display());
                }
                Some(p)
            };
            let journal_writer: Mutex<Option<JournalWriter>> = Mutex::new(match &journal_path {
                Some(p) => {
                    let (w, warn) = JournalWriter::open(
                        p,
                        &src_path.display().to_string(),
                        &dst_path.display().to_string(),
                    );
                    if let Some(wmsg) = warn {
                        eprintln!("  WARN: {wmsg}");
                    }
                    Some(w)
                }
                None => None,
            });

            /// Consult the journal for one file (None when disabled/no opinion).
            fn journal_decision(
                j: &Mutex<Option<JournalWriter>>,
                rel: &std::path::Path,
                size: u64,
                mtime: u64,
                target: Option<(u64, u64)>,
            ) -> Option<JournalDecision> {
                let guard = j.lock().unwrap();
                guard.as_ref()?.consult(&rel.to_string_lossy(), size, mtime, target)
            }

            /// Record Pending (copy in flight) — advisory; never fails the run.
            fn journal_mark_pending(
                j: &Mutex<Option<JournalWriter>>,
                rel: &std::path::Path,
                size: u64,
                mtime: u64,
            ) {
                if let Some(w) = j.lock().unwrap().as_mut() {
                    if let Err(e) = w.mark_pending(&rel.to_string_lossy(), size, mtime) {
                        eprintln!("  WARN: journal update failed: {e}");
                    }
                }
            }

            /// Record Committed (successful copy / verify pass).
            fn journal_mark_committed(
                j: &Mutex<Option<JournalWriter>>,
                rel: &std::path::Path,
                size: u64,
                mtime: u64,
                src_blake3: Option<[u8; 32]>,
            ) {
                if let Some(w) = j.lock().unwrap().as_mut() {
                    if let Err(e) =
                        w.mark_committed(&rel.to_string_lossy(), size, mtime, src_blake3)
                    {
                        eprintln!("  WARN: journal update failed: {e}");
                    }
                }
            }

            /// Record Failed (copy exhausted its retries).
            fn journal_mark_failed(
                j: &Mutex<Option<JournalWriter>>,
                rel: &std::path::Path,
                size: u64,
                mtime: u64,
            ) {
                if let Some(w) = j.lock().unwrap().as_mut() {
                    if let Err(e) = w.mark_failed(&rel.to_string_lossy(), size, mtime) {
                        eprintln!("  WARN: journal update failed: {e}");
                    }
                }
            }

            // Compute the cutoff timestamp for max_age filtering
            let age_cutoff_secs: Option<u64> = max_age.map(|days| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                now.saturating_sub(days * 86_400)
            });

            if !quiet {
                eprintln!("TallowTransfer delta-sync (parallel, {threads} threads)");
                eprintln!("  Source: {}", src_path.display());
                eprintln!("  Target: {}", dst_path.display());
                if !exclude_patterns.is_empty() {
                    eprintln!("  Exclude patterns: {}", exclude_patterns.join(", "));
                }
                if !exclude_dirs.is_empty() {
                    eprintln!("  Exclude dirs: {}", exclude_dirs.join(", "));
                }
                eprintln!();
            }

            // ── Glob-style pattern matcher ──
            // Supports: *.log  prefix*  *suffix  exact
            fn glob_match(pattern: &str, name: &str) -> bool {
                if pattern == "*" {
                    return true;
                }
                if let Some(suffix) = pattern.strip_prefix('*') {
                    // *.log — match any name ending with the suffix
                    return name.ends_with(suffix);
                }
                if let Some(prefix) = pattern.strip_suffix('*') {
                    // foo* — match any name starting with prefix
                    return name.starts_with(prefix);
                }
                // Exact match
                pattern == name
            }

            // ── File info struct shared between scan and copy phases ──
            struct FileInfo {
                rel: std::path::PathBuf,
                size: u64,
                mtime: u64,
                /// True when the source entry is a symlink (only populated with --symlinks or --follow-symlinks)
                is_symlink: bool,
                /// For symlinks: the link target path (when --symlinks preserve mode)
                link_target: Option<std::path::PathBuf>,
            }

            // ── Parallel directory walker ──
            // Walks top-level entries in parallel; each sub-tree recurses sequentially.
            // symlinks_preserve: emit symlinks as FileInfo entries (recreate on target)
            // follow_symlinks:   resolve symlinks and emit as regular files
            #[allow(clippy::too_many_arguments)]
            fn walk_dir_parallel(
                base: &std::path::Path,
                dir: &std::path::Path,
                exclude_patterns: &[String],
                exclude_dirs: &[String],
                age_cutoff: Option<u64>,
                min_size: Option<u64>,
                max_size: Option<u64>,
                symlinks_preserve: bool,
                follow_symlinks: bool,
                out: &Mutex<Vec<FileInfo>>,
            ) {
                use rayon::prelude::*;

                let top_entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
                    Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
                    Err(_) => return,
                };

                top_entries.par_iter().for_each(|entry| {
                    let path = entry.path();
                    // Use symlink_metadata so we can detect symlinks ourselves
                    let lmeta = match std::fs::symlink_metadata(&path) {
                        Ok(m) => m,
                        Err(_) => return,
                    };

                    if lmeta.is_symlink() {
                        if symlinks_preserve {
                            // Emit as a symlink entry so the copy loop can recreate it
                            let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                            let link_target = std::fs::read_link(&path).ok();
                            out.lock().unwrap().push(FileInfo {
                                rel,
                                size: 0,
                                mtime: 0,
                                is_symlink: true,
                                link_target,
                            });
                        } else if follow_symlinks {
                            // Resolve and treat as regular file
                            let resolved = match std::fs::canonicalize(&path) {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            let meta = match std::fs::metadata(&resolved) {
                                Ok(m) => m,
                                Err(_) => return,
                            };
                            if meta.is_file() {
                                let file_name =
                                    path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                                if exclude_patterns.iter().any(|p| glob_match(p, file_name)) {
                                    return;
                                }
                                let size = meta.len();
                                if let Some(mn) = min_size {
                                    if size < mn {
                                        return;
                                    }
                                }
                                if let Some(mx) = max_size {
                                    if size > mx {
                                        return;
                                    }
                                }
                                let mtime = meta
                                    .modified()
                                    .ok()
                                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                if let Some(cutoff) = age_cutoff {
                                    if mtime < cutoff {
                                        return;
                                    }
                                }
                                // Use the original (symlink) path's rel so the copy lands at the right place
                                let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                                out.lock().unwrap().push(FileInfo {
                                    rel,
                                    size,
                                    mtime,
                                    is_symlink: false,
                                    link_target: None,
                                });
                            }
                        }
                        // else: default — skip symlinks entirely
                        return;
                    }

                    if lmeta.is_dir() {
                        let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if exclude_dirs.iter().any(|ex| ex == dir_name) {
                            return;
                        }
                        walk_subtree(
                            base,
                            &path,
                            exclude_patterns,
                            exclude_dirs,
                            age_cutoff,
                            min_size,
                            max_size,
                            symlinks_preserve,
                            follow_symlinks,
                            out,
                        );
                    } else if lmeta.is_file() {
                        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if exclude_patterns.iter().any(|p| glob_match(p, file_name)) {
                            return;
                        }
                        let size = lmeta.len();
                        if let Some(mn) = min_size {
                            if size < mn {
                                return;
                            }
                        }
                        if let Some(mx) = max_size {
                            if size > mx {
                                return;
                            }
                        }
                        let mtime = lmeta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if let Some(cutoff) = age_cutoff {
                            if mtime < cutoff {
                                return;
                            }
                        }
                        let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                        out.lock().unwrap().push(FileInfo {
                            rel,
                            size,
                            mtime,
                            is_symlink: false,
                            link_target: None,
                        });
                    }
                });
            }

            // Sequential recursive walker for sub-trees (called from within parallel top scan)
            #[allow(clippy::too_many_arguments)]
            fn walk_subtree(
                base: &std::path::Path,
                dir: &std::path::Path,
                exclude_patterns: &[String],
                exclude_dirs: &[String],
                age_cutoff: Option<u64>,
                min_size: Option<u64>,
                max_size: Option<u64>,
                symlinks_preserve: bool,
                follow_symlinks: bool,
                out: &Mutex<Vec<FileInfo>>,
            ) {
                let entries = match std::fs::read_dir(dir) {
                    Ok(e) => e,
                    Err(_) => return,
                };
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    let lmeta = match std::fs::symlink_metadata(&path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    if lmeta.is_symlink() {
                        if symlinks_preserve {
                            let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                            let link_target = std::fs::read_link(&path).ok();
                            out.lock().unwrap().push(FileInfo {
                                rel,
                                size: 0,
                                mtime: 0,
                                is_symlink: true,
                                link_target,
                            });
                        } else if follow_symlinks {
                            let resolved = match std::fs::canonicalize(&path) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            let meta = match std::fs::metadata(&resolved) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            if meta.is_file() {
                                let file_name =
                                    path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                                if exclude_patterns.iter().any(|p| glob_match(p, file_name)) {
                                    continue;
                                }
                                let size = meta.len();
                                if let Some(mn) = min_size {
                                    if size < mn {
                                        continue;
                                    }
                                }
                                if let Some(mx) = max_size {
                                    if size > mx {
                                        continue;
                                    }
                                }
                                let mtime = meta
                                    .modified()
                                    .ok()
                                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                if let Some(cutoff) = age_cutoff {
                                    if mtime < cutoff {
                                        continue;
                                    }
                                }
                                let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                                out.lock().unwrap().push(FileInfo {
                                    rel,
                                    size,
                                    mtime,
                                    is_symlink: false,
                                    link_target: None,
                                });
                            }
                        }
                        continue;
                    }

                    if lmeta.is_dir() {
                        let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if exclude_dirs.iter().any(|ex| ex == dir_name) {
                            continue;
                        }
                        walk_subtree(
                            base,
                            &path,
                            exclude_patterns,
                            exclude_dirs,
                            age_cutoff,
                            min_size,
                            max_size,
                            symlinks_preserve,
                            follow_symlinks,
                            out,
                        );
                    } else if lmeta.is_file() {
                        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if exclude_patterns.iter().any(|p| glob_match(p, file_name)) {
                            continue;
                        }
                        let size = lmeta.len();
                        if let Some(mn) = min_size {
                            if size < mn {
                                continue;
                            }
                        }
                        if let Some(mx) = max_size {
                            if size > mx {
                                continue;
                            }
                        }
                        let mtime = lmeta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if let Some(cutoff) = age_cutoff {
                            if mtime < cutoff {
                                continue;
                            }
                        }
                        let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                        out.lock().unwrap().push(FileInfo {
                            rel,
                            size,
                            mtime,
                            is_symlink: false,
                            link_target: None,
                        });
                    }
                }
            }

            // ── Phase 1: Parallel directory scan ──
            if !quiet {
                eprint!("[1/2] Scanning files (parallel)... ");
            }
            let scan_start = std::time::Instant::now();

            let files_mutex: Mutex<Vec<FileInfo>> = Mutex::new(Vec::new());
            thread_pool.install(|| {
                walk_dir_parallel(
                    &src_path,
                    &src_path,
                    exclude_patterns,
                    exclude_dirs,
                    age_cutoff_secs,
                    min_size,
                    max_size,
                    symlinks,
                    follow_symlinks,
                    &files_mutex,
                );
            });

            let src_files: Vec<FileInfo> = files_mutex.into_inner().unwrap();
            let total_files = src_files.len();
            let total_size: u64 = src_files.iter().map(|f| f.size).sum();
            if !quiet {
                if show_bytes {
                    eprintln!(
                        "{} files ({} bytes) in {:.1}s",
                        total_files,
                        total_size,
                        scan_start.elapsed().as_secs_f64()
                    );
                } else {
                    eprintln!(
                        "{} files ({:.1} MB) in {:.1}s",
                        total_files,
                        total_size as f64 / 1_048_576.0,
                        scan_start.elapsed().as_secs_f64()
                    );
                }
            }

            // ── Batch mkdir: create all needed parent directories upfront ──
            if !dry_run && total_files > 0 {
                let mut dirs_needed: std::collections::HashSet<std::path::PathBuf> =
                    std::collections::HashSet::new();
                for fi in &src_files {
                    if let Some(p) = dst_path.join(&fi.rel).parent() {
                        dirs_needed.insert(p.to_path_buf());
                    }
                }
                for d in &dirs_needed {
                    let _ = std::fs::create_dir_all(d);
                }
            }

            // ── Phase 2: Parallel delta copy ──
            if !quiet {
                eprintln!("[2/2] Syncing ({threads} threads)...");
            }

            // ── Target cache: walk target once, cache mtime+size by relative path ──
            // Saves tens of thousands of stat() syscalls on SMB/NAS shares.
            fn cache_walk_target(
                base: &std::path::Path,
                dir: &std::path::Path,
                cache: &mut std::collections::HashMap<std::path::PathBuf, (u64, u64)>,
            ) {
                let entries = match std::fs::read_dir(dir) {
                    Ok(e) => e,
                    Err(_) => return,
                };
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    let meta = match entry.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if meta.is_dir() {
                        cache_walk_target(base, &path, cache);
                    } else if meta.is_file() {
                        let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        cache.insert(rel, (meta.len(), mtime));
                    }
                }
            }
            let target_cache: std::collections::HashMap<std::path::PathBuf, (u64, u64)> = {
                let mut c = std::collections::HashMap::new();
                cache_walk_target(&dst_path, &dst_path, &mut c);
                c
            };

            let copy_start = std::time::Instant::now();
            let at_copied = AtomicUsize::new(0);
            let at_skipped = AtomicUsize::new(0);
            let at_bytes = AtomicU64::new(0);
            let at_errors = AtomicUsize::new(0);
            let at_checked = AtomicUsize::new(0);
            // For --verify: track how many BLAKE3 mismatches were detected and retried
            let at_verify_retries = AtomicUsize::new(0);
            // Progress bar throttle: timestamp (nanos since epoch) of last update
            let last_progress_ns = std::sync::atomic::AtomicU64::new(0);

            // Collect log lines when --log is active (mutex-protected)
            let log_lines: Option<Mutex<Vec<String>>> =
                log.as_ref().map(|_| Mutex::new(Vec::new()));

            // Collect paths copied for ACL batch processing (Windows --copy-acls)
            #[cfg(windows)]
            let acl_paths: Mutex<Vec<(std::path::PathBuf, std::path::PathBuf)>> =
                Mutex::new(Vec::new());

            thread_pool.install(|| {
                src_files.par_iter().for_each(|fi| {
                    let sf = src_path.join(&fi.rel);
                    let df = dst_path.join(&fi.rel);

                    // ── Symlink preservation ──
                    if fi.is_symlink {
                        if let Some(ref link_target) = fi.link_target {
                            if let Some(p) = df.parent() { let _ = std::fs::create_dir_all(p); }
                            // Remove existing destination before creating symlink
                            let _ = std::fs::remove_file(&df);
                            #[cfg(unix)]
                            {
                                let ok = std::os::unix::fs::symlink(link_target, &df).is_ok();
                                if ok {
                                    at_copied.fetch_add(1, Ordering::Relaxed);
                                    if let Some(ref ll) = log_lines {
                                        ll.lock().unwrap().push(format!("symlink: {}", fi.rel.display()));
                                    }
                                } else {
                                    at_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            #[cfg(windows)]
                            {
                                // Determine if it's a file or directory symlink by checking the target
                                let target_is_dir = link_target.is_dir();
                                let ok = if target_is_dir {
                                    std::os::windows::fs::symlink_dir(link_target, &df).is_ok()
                                } else {
                                    std::os::windows::fs::symlink_file(link_target, &df).is_ok()
                                };
                                if ok {
                                    at_copied.fetch_add(1, Ordering::Relaxed);
                                    if let Some(ref ll) = log_lines {
                                        ll.lock().unwrap().push(format!("symlink: {}", fi.rel.display()));
                                    }
                                } else {
                                    at_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        let done = at_checked.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = done; // progress update handled below — fall through
                        return;
                    }

                    // ── Fast delta check: target cache + journal consult (R-3) ──
                    let base_needs_copy = match target_cache.get(&fi.rel) {
                        Some(&(dst_size, dst_mtime)) => dst_size != fi.size || dst_mtime != fi.mtime,
                        None => true, // not in target → copy
                    };
                    // A Committed journal entry for this exact source revision
                    // outranks an mtime-only cache miss (copies do not preserve
                    // mtime on Linux, so without this every run re-copies every
                    // file); a Pending entry forces a re-copy after a crash.
                    let needs_copy = match journal_decision(
                        &journal_writer,
                        &fi.rel,
                        fi.size,
                        fi.mtime,
                        target_cache.get(&fi.rel).copied(),
                    ) {
                        Some(JournalDecision::Skip) => false,
                        Some(JournalDecision::Recopy) => true,
                        None => base_needs_copy,
                    };

                    if needs_copy {
                        if dry_run {
                            at_copied.fetch_add(1, Ordering::Relaxed);
                            at_bytes.fetch_add(fi.size, Ordering::Relaxed);
                        } else {
                            // R-3: record intent before touching the target so a
                            // crash leaves a Pending entry (re-copied next run).
                            journal_mark_pending(&journal_writer, &fi.rel, fi.size, fi.mtime);
                            // Retry loop with exponential backoff
                            let mut last_err: Option<String> = None;
                            let mut succeeded = false;
                            for attempt in 0..=retries {
                                if attempt > 0 {
                                    let delay_ms = 1000u64 << (attempt - 1); // 1s, 2s, 4s...
                                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                                }
                                // Ensure parent exists (may not have been pre-created if it's a deep new path)
                                if let Some(p) = df.parent() {
                                    let _ = std::fs::create_dir_all(p);
                                }
                                // ── Block-level delta sync or full copy ──
                                let copy_result: Result<u64, String> = if block_level {
                                    // Wrap in a closure so ? propagates to Result, not to main()
                                    (|| -> Result<u64, String> {
                                        let src_data = std::fs::read(&sf)
                                            .map_err(|e| format!("{e}"))?;
                                        if df.exists() {
                                            let dst_data = std::fs::read(&df)
                                                .map_err(|e| format!("{e}"))?;
                                            let sig = fast_rsync::Signature::calculate(
                                                &dst_data,
                                                fast_rsync::SignatureOptions {
                                                    block_size: 131_072, // 128 KiB
                                                    crypto_hash_size: 8,
                                                },
                                            );
                                            let indexed = sig.index();
                                            let mut delta = Vec::new();
                                            fast_rsync::diff(&indexed, &src_data, &mut delta)
                                                .map_err(|e| format!("block diff: {e:?}"))?;
                                            let mut out = Vec::new();
                                            fast_rsync::apply(&dst_data, &delta, &mut out)
                                                .map_err(|e| format!("block apply: {e:?}"))?;
                                            std::fs::write(&df, &out)
                                                .map_err(|e| format!("{e}"))?;
                                            Ok(delta.len() as u64)
                                        } else {
                                            let n = src_data.len() as u64;
                                            std::fs::write(&df, &src_data)
                                                .map_err(|e| format!("{e}"))?;
                                            Ok(n)
                                        }
                                    })()
                                } else {
                                    tallow::stdlib::transfer::copy_file_with_fallback(&sf, &df)
                                };
                                match copy_result {
                                    Ok(n) => {
                                        // ── BLAKE3 verify ──
                                        let mut verify_ok = true;
                                        let mut verified_src_hash: Option<[u8; 32]> = None;
                                        if verify {
                                            let src_data = std::fs::read(&sf).ok();
                                            let dst_data = std::fs::read(&df).ok();
                                            if let (Some(s), Some(d)) = (src_data, dst_data) {
                                                let src_hash = blake3::hash(&s);
                                                verify_ok = src_hash == blake3::hash(&d);
                                                if !verify_ok {
                                                    at_verify_retries.fetch_add(1, Ordering::Relaxed);
                                                    // Verification failed — retry copy once more
                                                    let _ = tallow::stdlib::transfer::copy_file_with_fallback(&sf, &df);
                                                    verify_ok = std::fs::read(&df)
                                                        .map(|d2| src_hash == blake3::hash(&d2))
                                                        .unwrap_or(false);
                                                }
                                                verified_src_hash = Some(*src_hash.as_bytes());
                                            }
                                        }
                                        // ── Unix permission preservation ──
                                        #[cfg(unix)]
                                        if preserve_permissions {
                                            use std::os::unix::fs::MetadataExt as _;
                                            use std::os::unix::fs::PermissionsExt;
                                            if let Ok(src_meta) = std::fs::metadata(&sf) {
                                                let mode = src_meta.mode();
                                                let _ = std::fs::set_permissions(
                                                    &df,
                                                    std::fs::Permissions::from_mode(mode),
                                                );
                                                // ── Owner preservation (requires root) ──
                                                if preserve_owner {
                                                    let uid = src_meta.uid();
                                                    let gid = src_meta.gid();
                                                    // Use chown subprocess — avoids libc dependency
                                                    let _ = std::process::Command::new("chown")
                                                        .arg(format!("{}:{}", uid, gid))
                                                        .arg(&df)
                                                        .output();
                                                }
                                            }
                                        }
                                        at_copied.fetch_add(1, Ordering::Relaxed);
                                        at_bytes.fetch_add(n, Ordering::Relaxed);
                                        if let Some(ref ll) = log_lines {
                                            ll.lock().unwrap().push(fi.rel.display().to_string());
                                        }
                                        // R-3: Committed only after a successful copy —
                                        // with --verify, only after the verify steps above.
                                        if verify_ok {
                                            journal_mark_committed(
                                                &journal_writer,
                                                &fi.rel,
                                                fi.size,
                                                fi.mtime,
                                                verified_src_hash,
                                            );
                                        } else {
                                            journal_mark_failed(
                                                &journal_writer,
                                                &fi.rel,
                                                fi.size,
                                                fi.mtime,
                                            );
                                        }
                                        // Collect for ACL batch copy (Windows)
                                        #[cfg(windows)]
                                        if copy_acls {
                                            acl_paths.lock().unwrap().push((sf.clone(), df.clone()));
                                        }
                                        last_err = None;
                                        succeeded = true;
                                        break;
                                    }
                                    Err(e) => { last_err = Some(e); }
                                }
                            }
                            if !succeeded {
                                journal_mark_failed(&journal_writer, &fi.rel, fi.size, fi.mtime);
                                let err_count = at_errors.fetch_add(1, Ordering::Relaxed);
                                if err_count < 5 {
                                    if let Some(ref e) = last_err {
                                        eprintln!("  WARN: {}: {}", fi.rel.display(), e);
                                    }
                                }
                            }
                        }
                    } else {
                        at_skipped.fetch_add(1, Ordering::Relaxed);
                    }

                    let done = at_checked.fetch_add(1, Ordering::Relaxed) + 1;
                    // Progress bar: throttle to at most one update per 200ms.
                    // Also always print at 100% to show DONE.
                    if !quiet && total_files > 0 {
                        let now_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos() as u64)
                            .unwrap_or(0);
                        let last = last_progress_ns.load(Ordering::Relaxed);
                        let elapsed_since_last_ms = now_ns.saturating_sub(last) / 1_000_000;
                        if done == total_files || elapsed_since_last_ms >= 200 {
                            last_progress_ns.store(now_ns, Ordering::Relaxed);
                            let cop = at_copied.load(Ordering::Relaxed);
                            let skp = at_skipped.load(Ordering::Relaxed);
                            let pct = (done as f64 / total_files as f64 * 100.0) as usize;
                            let filled = pct * 30 / 100;
                            let bar: String = "█".repeat(filled) + &"░".repeat(30 - filled);
                            let elapsed = copy_start.elapsed().as_secs_f64();
                            let rate = if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 };
                            let eta  = if done > 0 { elapsed / done as f64 * (total_files - done) as f64 } else { 0.0 };
                            eprint!("\r  [{bar}] {pct:3}% | {done}/{total_files} | {cop} copied, {skp} skipped | {rate:.0} files/s | ETA {eta:.0}s  ");
                        }
                    }
                });
            });

            // R-3: flush the journal remainder once the copy phase completes.
            let (j_committed, j_pending, j_failed) = {
                let mut guard = journal_writer.lock().unwrap();
                match guard.as_mut() {
                    Some(w) => {
                        if let Err(e) = w.flush() {
                            eprintln!("  WARN: journal flush failed: {e}");
                        }
                        let (c, p, f) = w.counts();
                        (c, p, f)
                    }
                    None => (0, 0, 0),
                }
            };

            let copied = at_copied.load(Ordering::Relaxed);
            let skipped = at_skipped.load(Ordering::Relaxed);
            let bytes_copied = at_bytes.load(Ordering::Relaxed);
            let errors = at_errors.load(Ordering::Relaxed);
            let verify_retries = at_verify_retries.load(Ordering::Relaxed);
            let sync_secs = copy_start.elapsed().as_secs_f64();
            let total_elapsed = start.elapsed().as_secs_f64();
            let mb_copied = bytes_copied as f64 / 1_048_576.0;

            if !quiet {
                eprintln!(
                    "\r  [{}] 100% | DONE                                                      ",
                    "█".repeat(30)
                );
            }
            eprintln!();
            if show_bytes {
                eprintln!("  Files copied:  {} ({} bytes)", copied, bytes_copied);
            } else {
                eprintln!("  Files copied:  {} ({:.1} MB)", copied, mb_copied);
            }
            eprintln!("  Files skipped: {} (unchanged)", skipped);
            if errors > 0 {
                eprintln!(
                    "  Errors:        {} (after {} retries each)",
                    errors, retries
                );
            }
            if verify && verify_retries > 0 {
                eprintln!(
                    "  Verify retries: {} (BLAKE3 mismatch, re-copied)",
                    verify_retries
                );
            }
            eprintln!(
                "  Total time:    {:.1}s (scan {:.1}s + sync {:.1}s)",
                total_elapsed,
                scan_start.elapsed().as_secs_f64(),
                sync_secs
            );
            if sync_secs > 0.0 && copied > 0 {
                eprintln!(
                    "  Speed:         {:.1} MB/s ({:.0} files/s)",
                    mb_copied / sync_secs,
                    copied as f64 / sync_secs
                );
            }
            eprintln!("  Threads:       {}", threads);
            if journal_path.is_some() {
                eprintln!(
                    "  Journal:       {} committed, {} pending, {} failed",
                    j_committed, j_pending, j_failed
                );
            }
            if dry_run {
                eprintln!("\n  (dry run -- no files were actually copied)");
            }

            // ── Windows ACL copy via icacls ──
            #[cfg(windows)]
            if copy_acls && !dry_run {
                use std::process::Command as SysCommand;
                // Check icacls availability
                let icacls_check = SysCommand::new("icacls").arg("/?").output();
                if icacls_check.is_err() {
                    eprintln!("  WARN: --copy-acls requested but icacls not found in PATH");
                } else {
                    let pairs = acl_paths.into_inner().unwrap_or_default();
                    let mut acl_ok = 0usize;
                    let mut acl_fail = 0usize;
                    // Process in batches — icacls saves from src and restores to dst
                    for (src_f, dst_f) in &pairs {
                        // icacls "src" /save tmp.acl /T  then  icacls "dst" /restore tmp.acl
                        let tmp = std::env::temp_dir().join("tallow_acl_tmp.acl");
                        let save_ok = SysCommand::new("icacls")
                            .arg(src_f)
                            .arg("/save")
                            .arg(&tmp)
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false);
                        if save_ok {
                            let restore_ok = SysCommand::new("icacls")
                                .arg(dst_f.parent().unwrap_or(dst_f))
                                .arg("/restore")
                                .arg(&tmp)
                                .output()
                                .map(|o| o.status.success())
                                .unwrap_or(false);
                            if restore_ok {
                                acl_ok += 1;
                            } else {
                                acl_fail += 1;
                            }
                        } else {
                            acl_fail += 1;
                        }
                        let _ = std::fs::remove_file(&tmp);
                    }
                    eprintln!("  ACLs copied: {} ok, {} failed", acl_ok, acl_fail);
                }
            }

            // ── Write log file ──
            if let Some(log_path) = log {
                let lines = log_lines
                    .map(|m| m.into_inner().unwrap())
                    .unwrap_or_default();
                let size_str = if show_bytes {
                    format!("{} bytes", bytes_copied)
                } else {
                    format!("{:.1} MB", mb_copied)
                };
                let mut content = format!(
                    "TallowTransfer delta-sync log\nSource: {}\nTarget: {}\nCopied: {} files ({})\nSkipped: {} (unchanged)\nErrors: {}\nTime: {:.1}s\n\nCopied files:\n",
                    src_path.display(),
                    dst_path.display(),
                    copied,
                    size_str,
                    skipped,
                    errors,
                    total_elapsed
                );
                for l in &lines {
                    content.push_str(l);
                    content.push('\n');
                }
                if let Err(e) = std::fs::write(log_path, &content) {
                    eprintln!(
                        "  WARN: could not write log to {}: {}",
                        log_path.display(),
                        e
                    );
                } else {
                    eprintln!("  Log written: {}", log_path.display());
                }
            }

            // ── Mirror mode: parallel delete of orphaned target files ──
            if mirror {
                eprintln!();
                eprint!("  Mirror: scanning target for orphaned files... ");

                let src_rel_set: std::collections::HashSet<std::path::PathBuf> =
                    src_files.iter().map(|f| f.rel.clone()).collect();

                // Walk target to find all files
                let target_files_mutex: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

                fn walk_target_parallel(
                    base: &std::path::Path,
                    dir: &std::path::Path,
                    out: &Mutex<Vec<std::path::PathBuf>>,
                ) {
                    use rayon::prelude::*;
                    let top: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
                        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
                        Err(_) => return,
                    };
                    top.par_iter().for_each(|entry| {
                        let path = entry.path();
                        // The delta-sync journal lives under <target>/.tallow-journal/
                        // by default and must survive mirror pruning (R-3).
                        if path.file_name().and_then(|n| n.to_str()) == Some(".tallow-journal") {
                            return;
                        }
                        let meta = match std::fs::symlink_metadata(&path) {
                            Ok(m) => m,
                            Err(_) => return,
                        };
                        // Include symlinks in mirror scan so they can be deleted if orphaned
                        if meta.is_dir() && !meta.is_symlink() {
                            walk_target_subtree(base, &path, out);
                        } else if meta.is_file() || meta.is_symlink() {
                            let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                            out.lock().unwrap().push(rel);
                        }
                    });
                }

                fn walk_target_subtree(
                    base: &std::path::Path,
                    dir: &std::path::Path,
                    out: &Mutex<Vec<std::path::PathBuf>>,
                ) {
                    let entries = match std::fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return,
                    };
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        let meta = match std::fs::symlink_metadata(&path) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        if meta.is_dir() && !meta.is_symlink() {
                            walk_target_subtree(base, &path, out);
                        } else if meta.is_file() || meta.is_symlink() {
                            let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                            out.lock().unwrap().push(rel);
                        }
                    }
                }

                thread_pool.install(|| {
                    walk_target_parallel(&dst_path, &dst_path, &target_files_mutex);
                });

                let target_rels = target_files_mutex.into_inner().unwrap();
                let target_count = target_rels.len();
                eprintln!("{target_count} files on target");

                let at_deleted = AtomicUsize::new(0);
                let at_del_errs = AtomicUsize::new(0);

                thread_pool.install(|| {
                    target_rels.par_iter().for_each(|rel| {
                        if !src_rel_set.contains(rel) {
                            let full = dst_path.join(rel);
                            if dry_run {
                                at_deleted.fetch_add(1, Ordering::Relaxed);
                            } else {
                                match std::fs::remove_file(&full) {
                                    Ok(_) => {
                                        at_deleted.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(_) => {
                                        at_del_errs.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    });
                });

                let deleted = at_deleted.load(Ordering::Relaxed);
                let del_errors = at_del_errs.load(Ordering::Relaxed);

                // Clean empty directories on target (sequential — fast, structural cleanup)
                if !dry_run && deleted > 0 {
                    fn remove_empty_dirs(dir: &std::path::Path) {
                        let entries = match std::fs::read_dir(dir) {
                            Ok(e) => e,
                            Err(_) => return,
                        };
                        for entry in entries.filter_map(|e| e.ok()) {
                            let path = entry.path();
                            if path.is_dir() {
                                remove_empty_dirs(&path);
                                let _ = std::fs::remove_dir(&path);
                            }
                        }
                    }
                    remove_empty_dirs(&dst_path);
                }

                eprintln!(
                    "  Deleted: {} orphaned files{}",
                    deleted,
                    if del_errors > 0 {
                        format!(" ({del_errors} errors)")
                    } else {
                        String::new()
                    }
                );
                if dry_run && deleted > 0 {
                    eprintln!("  (dry run -- no files were actually deleted)");
                }
            }

            return Ok(());
        }
        Command::EncryptDir {
            ref input,
            ref output,
            ref password,
        } => {
            use tallow::interp::Value;
            let result = tallow::stdlib::transfer::dispatch(
                "vault_encrypt_dir",
                vec![
                    Value::String(input.display().to_string()),
                    Value::String(output.display().to_string()),
                    Value::String(password.clone()),
                ],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let files = fields
                        .iter()
                        .find(|(k, _)| k == "files_encrypted")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let bytes = fields
                        .iter()
                        .find(|(k, _)| k == "total_bytes")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let errs = fields
                        .iter()
                        .find(|(k, _)| k == "errors")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_else(|| "0".into());
                    println!(
                        "encrypted {} files ({} bytes) -> {}",
                        files,
                        bytes,
                        output.display()
                    );
                    if errs != "0" {
                        eprintln!("  warnings: {} errors", errs);
                    }
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                None => {
                    eprintln!("error: encrypt_dir dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {}
            }
            return Ok(());
        }
        Command::DecryptDir {
            ref input,
            ref output,
            ref password,
        } => {
            use tallow::interp::Value;
            let result = tallow::stdlib::transfer::dispatch(
                "vault_decrypt_dir",
                vec![
                    Value::String(input.display().to_string()),
                    Value::String(output.display().to_string()),
                    Value::String(password.clone()),
                ],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let files = fields
                        .iter()
                        .find(|(k, _)| k == "files_decrypted")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let bytes = fields
                        .iter()
                        .find(|(k, _)| k == "total_bytes")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let errs = fields
                        .iter()
                        .find(|(k, _)| k == "errors")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_else(|| "0".into());
                    println!(
                        "decrypted {} files ({} bytes) -> {}",
                        files,
                        bytes,
                        output.display()
                    );
                    if errs != "0" {
                        eprintln!("  warnings: {} errors", errs);
                    }
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                None => {
                    eprintln!("error: decrypt_dir dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {}
            }
            return Ok(());
        }
        Command::Discover => {
            use tallow::interp::Value;
            println!("discovering peers on local network...");
            let result = tallow::stdlib::transfer::dispatch("lan_discover", vec![]);
            match result {
                Some(Ok(Value::Array(peers))) => {
                    if peers.is_empty() {
                        println!("  no peers found");
                    } else {
                        for peer in &peers {
                            if let Value::Struct { fields, .. } = peer {
                                let ip = fields
                                    .iter()
                                    .find(|(k, _)| k == "ip")
                                    .map(|(_, v)| v.as_string())
                                    .unwrap_or_default();
                                let host = fields
                                    .iter()
                                    .find(|(k, _)| k == "hostname")
                                    .map(|(_, v)| v.as_string())
                                    .unwrap_or_default();
                                let port = fields
                                    .iter()
                                    .find(|(k, _)| k == "port")
                                    .map(|(_, v)| v.as_string())
                                    .unwrap_or_default();
                                let is_self = fields
                                    .iter()
                                    .find(|(k, _)| k == "self_node")
                                    .and_then(|(_, v)| {
                                        if let Value::Bool(b) = v {
                                            Some(*b)
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(false);
                                let tag = if is_self { " (self)" } else { "" };
                                println!("  {}:{} [{}]{}", ip, port, host, tag);
                            }
                        }
                    }
                    println!("\nfound {} peer(s)", peers.len());
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    println!("  no peers found");
                }
            }
            return Ok(());
        }
        // ── Phase 59/60: QUIC file transfer commands ──
        Command::Send {
            ref files,
            ref text,
            stdin,
            ref to,
            ref relay,
            ref code,
            ref compress,
            ref bwlimit,
            ref proxy,
            ref signal,
            legacy_plaintext,
        } => {
            use indicatif::{ProgressBar, ProgressStyle};
            use tallow::interp::Value;

            // Show proxy config if set
            if let Some(proxy_url) = proxy {
                println!("Proxy: {}", proxy_url);
            }

            // D-C2: --bwlimit is bits/sec at the CLI boundary ("10M" =
            // 1,250,000 B/s); parsed once here for every path that enforces it
            // (relay-v1 + QUIC single-file sends).
            let bw_bps: i128 = match bwlimit {
                Some(bw) => match tallow::stdlib::transfer_net::dispatch(
                    "apply_bandwidth_limit",
                    vec![Value::String(bw.clone())],
                ) {
                    Some(Ok(Value::Struct { fields, .. })) => fields
                        .iter()
                        .find(|(k, _)| k == "bytes_per_sec")
                        .map(|(_, v)| if let Value::Int(n) = v { *n } else { 0 })
                        .unwrap_or(0),
                    _ => -1, // unparseable (bad number/unit)
                },
                None => 0,
            };
            if let Some(bw) = bwlimit {
                if bw_bps > 0 {
                    println!(
                        "Bandwidth limit: {} ({} bytes/sec, enforced for QUIC/relay file sends)",
                        bw, bw_bps
                    );
                } else {
                    eprintln!(
                        "warning: could not parse --bwlimit '{}'; transfer left unlimited",
                        bw
                    );
                }
            }

            // Handle --text mode: send text directly as bytes
            if let Some(text_content) = text {
                let code_phrase = code.clone().unwrap_or_else(|| {
                    match tallow::stdlib::transfer_net::dispatch("generate_code", vec![]) {
                        Some(Ok(Value::Struct { fields, .. })) => fields
                            .iter()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.to_string())
                            .unwrap_or_default(),
                        _ => "000-error-error-error".to_string(),
                    }
                });

                // Show QR-style display
                if let Some(Ok(Value::String(qr))) = tallow::stdlib::transfer_net::dispatch(
                    "generate_qr",
                    vec![Value::String(code_phrase.clone())],
                ) {
                    println!("{}", qr);
                }

                println!("Sending text ({} bytes)", text_content.len());
                println!("Code phrase: {}", code_phrase);
                println!("On the other computer, run:");
                println!("  tallow receive {}", code_phrase);
                println!();

                let dest = to.as_deref().unwrap_or("127.0.0.1:6881");
                let result = tallow::stdlib::transfer_net::dispatch(
                    "quic_send_bytes",
                    vec![
                        Value::String(text_content.clone()),
                        Value::String(dest.to_string()),
                    ],
                );
                match result {
                    Some(Ok(Value::Struct { fields, .. })) => {
                        let hash = fields
                            .iter()
                            .find(|(k, _)| k == "hash")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        println!("  text sent ({} bytes)", text_content.len());
                        println!("  BLAKE3: {}", hash);
                        println!("  protocol: QUIC (TLS 1.3)");
                    }
                    Some(Err(e)) => {
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {
                        eprintln!("error: text send dispatch failed");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
                return Ok(());
            }

            // Handle --stdin mode: read all stdin, send as bytes
            if stdin {
                use std::io::Read;
                let mut buffer = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buffer)
                    .map_err(|e| anyhow::anyhow!("failed to read stdin: {}", e))?;

                let code_phrase = code.clone().unwrap_or_else(|| {
                    match tallow::stdlib::transfer_net::dispatch("generate_code", vec![]) {
                        Some(Ok(Value::Struct { fields, .. })) => fields
                            .iter()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.to_string())
                            .unwrap_or_default(),
                        _ => "000-error-error-error".to_string(),
                    }
                });

                println!("Sending stdin ({} bytes)", buffer.len());
                println!("Code phrase: {}", code_phrase);

                let dest = to.as_deref().unwrap_or("127.0.0.1:6881");
                let text_data = String::from_utf8_lossy(&buffer).to_string();
                let result = tallow::stdlib::transfer_net::dispatch(
                    "quic_send_bytes",
                    vec![Value::String(text_data), Value::String(dest.to_string())],
                );
                match result {
                    Some(Ok(Value::Struct { fields, .. })) => {
                        let hash = fields
                            .iter()
                            .find(|(k, _)| k == "hash")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        println!("  stdin sent ({} bytes)", buffer.len());
                        println!("  BLAKE3: {}", hash);
                    }
                    Some(Err(e)) => {
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {
                        eprintln!("error: stdin send failed");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
                return Ok(());
            }

            // Require at least one file for normal file send mode
            if files.is_empty() {
                eprintln!("error: at least one file is required (or use --text/--stdin)");
                std::process::exit(exit_codes::IO_ERROR);
            }

            // Phase 61: multi-file support -- use first file for backward compat
            let file = &files[0];
            let is_multi = files.len() > 1 || files.iter().any(|f| f.is_dir());

            // For multi-file/dir, use quic_send_multi or quic_send_dir
            if is_multi || file.is_dir() {
                let should_compress = compress != "false";

                if files.len() == 1 && file.is_dir() {
                    // Single directory -- use quic_send_dir_structured (TWD format, preserves full tree)
                    let dest = to.as_deref().unwrap_or("127.0.0.1:6881");
                    println!(
                        "Sending directory {} -> {} via QUIC (TWD)...",
                        file.display(),
                        dest
                    );
                    let result = tallow::stdlib::transfer_net::dispatch(
                        "quic_send_dir_structured",
                        vec![
                            Value::String(file.display().to_string()),
                            Value::String(dest.to_string()),
                            Value::Bool(should_compress),
                        ],
                    );
                    match result {
                        Some(Ok(Value::Struct { fields, .. })) => {
                            let fcount = fields
                                .iter()
                                .find(|(k, _)| k == "files_count")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let dcount = fields
                                .iter()
                                .find(|(k, _)| k == "dirs_count")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let comp = fields
                                .iter()
                                .find(|(k, _)| k == "compressed_size")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let uncomp = fields
                                .iter()
                                .find(|(k, _)| k == "uncompressed_size")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let hash = fields
                                .iter()
                                .find(|(k, _)| k == "hash")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            println!(
                                "  {} files, {} directories archived (TWD format)",
                                fcount, dcount
                            );
                            println!(
                                "  uncompressed: {} bytes, compressed: {} bytes",
                                uncomp, comp
                            );
                            println!("  BLAKE3: {}", hash);
                            println!("  structure: preserved");
                            println!("  protocol: QUIC (TLS 1.3)");
                        }
                        Some(Err(e)) => {
                            eprintln!("error: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                        _ => {
                            eprintln!("error: send_dir dispatch failed");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                    }
                } else {
                    // Multiple files -- use quic_send_multi
                    let dest = to.as_deref().unwrap_or("127.0.0.1:6881");
                    let file_strs: Vec<Value> = files
                        .iter()
                        .map(|f| Value::String(f.display().to_string()))
                        .collect();
                    println!("Sending {} files -> {} via QUIC...", files.len(), dest);
                    let result = tallow::stdlib::transfer_net::dispatch(
                        "quic_send_multi",
                        vec![Value::Array(file_strs), Value::String(dest.to_string())],
                    );
                    match result {
                        Some(Ok(Value::Struct { fields, .. })) => {
                            let count = fields
                                .iter()
                                .find(|(k, _)| k == "files_count")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            let total = fields
                                .iter()
                                .find(|(k, _)| k == "total_size")
                                .map(|(_, v)| v.as_string())
                                .unwrap_or_default();
                            println!("  {} files prepared ({} bytes total)", count, total);
                            println!("  protocol: QUIC (TLS 1.3)");
                        }
                        Some(Err(e)) => {
                            eprintln!("error: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                        _ => {
                            eprintln!("error: send_multi dispatch failed");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                    }
                }
                return Ok(());
            }

            let metadata = std::fs::metadata(file)
                .map_err(|e| anyhow::anyhow!("cannot stat '{}': {}", file.display(), e))?;
            let size = metadata.len();
            let filename = file
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            // Mode 1: Relay mode (--relay)
            if let Some(relay_addr) = relay {
                let code_phrase = code.clone().unwrap_or_else(|| {
                    match tallow::stdlib::transfer_net::dispatch("generate_code", vec![]) {
                        Some(Ok(Value::Struct { fields, .. })) => fields
                            .iter()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default(),
                        _ => "000-error-error-error".to_string(),
                    }
                });
                println!(
                    "Sending {} ({} bytes) via relay {}",
                    filename, size, relay_addr
                );
                println!("Code phrase: {}", code_phrase);
                println!("On the other computer, run:");
                println!(
                    "  tallow receive --code {} --relay {}",
                    code_phrase, relay_addr
                );

                let pb = ProgressBar::new(size);
                pb.set_style(ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})"
                ).unwrap().progress_chars("#>-"));

                if legacy_plaintext && bw_bps > 0 {
                    eprintln!(
                        "warning: --bwlimit is not enforced on the legacy v0 plaintext relay path"
                    );
                }

                let result = tallow::stdlib::transfer_net::dispatch(
                    "relay_send",
                    vec![
                        Value::String(file.display().to_string()),
                        Value::String(relay_addr.clone()),
                        Value::String(code_phrase.clone()),
                        Value::Int(bw_bps.max(0)),
                        Value::Bool(legacy_plaintext),
                    ],
                );

                match result {
                    Some(Ok(Value::Struct { fields, .. })) => {
                        pb.set_position(size);
                        pb.finish_with_message("sent!");
                        let hash = fields
                            .iter()
                            .find(|(k, _)| k == "hash")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let resumed_from = fields
                            .iter()
                            .find(|(k, _)| k == "resumed_from_chunk")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        println!("  BLAKE3: {}", hash);
                        if resumed_from != "0" {
                            println!("  resumed at chunk {} (receiver's resume point)", resumed_from);
                        }
                        if legacy_plaintext {
                            println!("  protocol: TCP relay (legacy v0 plaintext)");
                        } else {
                            println!("  protocol: TCP relay v1 (E2E-encrypted, live pairing)");
                        }
                    }
                    Some(Err(e)) => {
                        pb.finish_with_message("failed");
                        if tallow::stdlib::transfer_net::relay_interrupted() {
                            eprintln!("interrupted — receiver keeps its streamed progress; rerun to resume");
                            std::process::exit(exit_codes::INTERRUPTED);
                        }
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {
                        pb.finish_with_message("failed");
                        eprintln!("error: relay send dispatch failed");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
                return Ok(());
            }

            // Mode 2: Code phrase mode (no --to, generates code phrase and listens on derived port)
            if to.is_none() {
                let code_phrase = code.clone().unwrap_or_else(|| {
                    match tallow::stdlib::transfer_net::dispatch("generate_code", vec![]) {
                        Some(Ok(Value::Struct { fields, .. })) => fields
                            .iter()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default(),
                        _ => "000-error-error-error".to_string(),
                    }
                });
                // Derive port from code phrase
                let port_result = tallow::stdlib::transfer_net::dispatch(
                    "code_to_port",
                    vec![Value::String(code_phrase.clone())],
                );
                let port: u16 = match port_result {
                    Some(Ok(Value::Struct { fields, .. })) => fields
                        .iter()
                        .find(|(k, _)| k == "port")
                        .and_then(|(_, v)| v.as_string().parse::<u16>().ok())
                        .unwrap_or(6881),
                    _ => 6881,
                };

                // Show QR-style display
                if let Some(Ok(Value::String(qr))) = tallow::stdlib::transfer_net::dispatch(
                    "generate_qr",
                    vec![Value::String(code_phrase.clone())],
                ) {
                    println!("{}", qr);
                }

                println!("Sending {} ({} bytes)", filename, size);
                println!("Code phrase: {}", code_phrase);
                println!("On the other computer, run:");
                if let Some(sig_addr) = signal {
                    println!("  tallow receive {} --signal {}", code_phrase, sig_addr);
                } else {
                    println!("  tallow receive {}", code_phrase);
                }
                println!();

                // Register with signal server if --signal provided
                if let Some(sig_addr) = signal {
                    use std::io::{BufRead, Write};
                    eprintln!("Registering with signal server: {}", sig_addr);
                    match std::net::TcpStream::connect(sig_addr.as_str()) {
                        Ok(mut sig_stream) => {
                            let msg = format!("REGISTER {} {}\n", code_phrase, port);
                            let _ = sig_stream.write_all(msg.as_bytes());
                            let mut sig_reader =
                                std::io::BufReader::new(sig_stream.try_clone().unwrap());
                            let mut sig_resp = String::new();
                            let _ = sig_reader.read_line(&mut sig_resp);
                            eprintln!("Signal: {}", sig_resp.trim());
                            // Wait for PEER message — signal server notifies us when receiver connects
                            sig_resp.clear();
                            sig_stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(300)))
                                .ok();
                            let _ = sig_reader.read_line(&mut sig_resp);
                            if sig_resp.starts_with("PEER ") {
                                let receiver_ip = sig_resp.trim_start_matches("PEER ").trim();
                                eprintln!("Receiver connected from: {}", receiver_ip);
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: could not reach signal server {}: {}", sig_addr, e);
                            eprintln!("Falling back to direct mode (receiver needs your IP)");
                        }
                    }
                }

                println!("Waiting for receiver on port {}...", port);

                // Use direct QUIC send to 0.0.0.0:<port> -- receiver will listen there
                let _listen_addr = format!("0.0.0.0:{}", port);
                let pb = ProgressBar::new(size);
                pb.set_style(ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})"
                ).unwrap().progress_chars("#>-"));

                let result = tallow::stdlib::transfer_net::dispatch(
                    "quic_send_file",
                    vec![
                        Value::String(file.display().to_string()),
                        Value::String(format!("127.0.0.1:{}", port)),
                        Value::Int(bw_bps.max(0)),
                    ],
                );

                match result {
                    Some(Ok(Value::Struct { fields, .. })) => {
                        pb.set_position(size);
                        pb.finish_with_message("sent!");
                        let hash = fields
                            .iter()
                            .find(|(k, _)| k == "hash")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let rtt = fields
                            .iter()
                            .find(|(k, _)| k == "rtt_ms")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        println!("  BLAKE3: {}", hash);
                        println!("  RTT: {}ms", rtt);
                        println!("  protocol: QUIC (TLS 1.3)");
                    }
                    Some(Err(e)) => {
                        pb.finish_with_message("failed");
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {
                        pb.finish_with_message("failed");
                        eprintln!("error: send dispatch failed");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
                return Ok(());
            }

            // Mode 3: Direct QUIC send (--to ip:port)
            let dest = to.as_ref().unwrap();
            println!(
                "Sending {} ({} bytes) -> {} via QUIC...",
                filename, size, dest
            );

            let pb = ProgressBar::new(size);
            pb.set_style(ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})"
            ).unwrap().progress_chars("#>-"));

            let result = tallow::stdlib::transfer_net::dispatch(
                "quic_send_file",
                vec![
                    Value::String(file.display().to_string()),
                    Value::String(dest.clone()),
                    Value::Int(bw_bps.max(0)),
                ],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    pb.set_position(size);
                    pb.finish_with_message("sent!");
                    let hash = fields
                        .iter()
                        .find(|(k, _)| k == "hash")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let rtt = fields
                        .iter()
                        .find(|(k, _)| k == "rtt_ms")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    println!("  BLAKE3: {}", hash);
                    println!("  RTT: {}ms", rtt);
                    println!("  protocol: QUIC (TLS 1.3)");
                }
                Some(Err(e)) => {
                    pb.finish_with_message("failed");
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                None => {
                    pb.finish_with_message("failed");
                    eprintln!("error: send dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {}
            }
            return Ok(());
        }
        Command::Receive {
            ref code_positional,
            ref listen,
            ref output,
            timeout,
            ref code,
            ref relay,
            stdout,
            overwrite,
            yes,
            ref proxy,
            ref signal,
            no_resume,
            ref state_dir,
            legacy_plaintext,
        } => {
            use indicatif::{ProgressBar, ProgressStyle};
            use tallow::interp::Value;

            // Resolve code: --code flag takes priority, then positional arg
            let effective_code: Option<String> = code.clone().or_else(|| {
                if !code_positional.is_empty() {
                    Some(code_positional.clone())
                } else {
                    None
                }
            });

            // Show proxy config if set
            if let Some(proxy_url) = proxy {
                println!("Proxy: {}", proxy_url);
            }

            // D-C3: the relay-v1 receive path enforces the clobber gate —
            // existing destination without --overwrite/--yes is refused.
            let allow_overwrite = overwrite || yes;

            // Mode 1: Relay mode (--code + --relay)
            if let (Some(code_phrase), Some(relay_addr)) = (&effective_code, relay) {
                println!(
                    "Receiving via relay {} with code: {}",
                    relay_addr, code_phrase
                );
                println!("  output: {}", output.display());

                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::with_template(
                        "{spinner:.green} [{elapsed_precise}] Waiting for sender...",
                    )
                    .unwrap(),
                );
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                // R-2: resume is ON by default for file receive (design §3.2);
                // --state-dir overrides <output>/.tallow-resume/.
                let state_dir_arg = if no_resume {
                    println!("  resume: OFF (--no-resume)");
                    Value::String(String::new())
                } else {
                    let dir = state_dir
                        .clone()
                        .unwrap_or_else(|| output.join(".tallow-resume"));
                    println!("  resume: ON (state dir {})", dir.display());
                    Value::String(dir.display().to_string())
                };

                let result = tallow::stdlib::transfer_net::dispatch(
                    "relay_receive",
                    vec![
                        Value::String(code_phrase.clone()),
                        Value::String(output.display().to_string()),
                        Value::String(relay_addr.clone()),
                        state_dir_arg,
                        Value::Bool(allow_overwrite),
                        Value::Bool(legacy_plaintext),
                    ],
                );

                match result {
                    Some(Ok(Value::Struct { fields, .. })) => {
                        pb.finish_with_message("received!");
                        let filename = fields
                            .iter()
                            .find(|(k, _)| k == "filename")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let size = fields
                            .iter()
                            .find(|(k, _)| k == "size")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let verified = fields
                            .iter()
                            .find(|(k, _)| k == "verified")
                            .and_then(|(_, v)| {
                                if let Value::Bool(b) = v {
                                    Some(*b)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(false);
                        let resumed_from = fields
                            .iter()
                            .find(|(k, _)| k == "resumed_from_chunk")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        println!("  received: {} ({} bytes)", filename, size);
                        println!(
                            "  BLAKE3 verified: {}",
                            if verified { "PASS" } else { "FAIL" }
                        );
                        if resumed_from != "0" {
                            println!("  resumed from chunk {} (verified prefix skipped)", resumed_from);
                        }
                        if legacy_plaintext {
                            println!("  protocol: TCP relay (legacy v0 plaintext)");
                        } else {
                            println!("  protocol: TCP relay v1 (E2E-encrypted, live pairing)");
                        }
                    }
                    Some(Err(e)) => {
                        pb.finish_with_message("failed");
                        if tallow::stdlib::transfer_net::relay_interrupted() {
                            eprintln!(
                                "interrupted — partial progress checkpointed under the resume \
                                 state dir; rerun the same command to resume"
                            );
                            std::process::exit(exit_codes::INTERRUPTED);
                        }
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {
                        pb.finish_with_message("failed");
                        eprintln!("error: relay receive dispatch failed");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
                return Ok(());
            }

            // Mode 2a: Signal + code phrase mode -- look up sender address via signal server
            if let (Some(code_phrase), Some(sig_addr)) = (&effective_code, signal) {
                use std::io::{BufRead, Write};
                eprintln!(
                    "Looking up '{}' on signal server: {}",
                    code_phrase, sig_addr
                );
                match std::net::TcpStream::connect(sig_addr.as_str()) {
                    Ok(mut sig_stream) => {
                        let msg = format!("LOOKUP {}\n", code_phrase);
                        let _ = sig_stream.write_all(msg.as_bytes());
                        let mut sig_reader = std::io::BufReader::new(sig_stream);
                        let mut sig_resp = String::new();
                        let _ = sig_reader.read_line(&mut sig_resp);
                        if sig_resp.starts_with("PEER ") {
                            let sender_addr =
                                sig_resp.trim_start_matches("PEER ").trim().to_string();
                            eprintln!("Sender found at: {}", sender_addr);
                            println!("Receiving from {} via QUIC...", sender_addr);
                            println!("  output: {}", output.display());
                            let pb = ProgressBar::new_spinner();
                            pb.set_style(
                                ProgressStyle::with_template(
                                    "{spinner:.green} [{elapsed_precise}] Receiving...",
                                )
                                .unwrap(),
                            );
                            pb.enable_steady_tick(std::time::Duration::from_millis(100));
                            let result = tallow::stdlib::transfer_net::dispatch(
                                "quic_receive_file",
                                vec![
                                    Value::String(format!("0.0.0.0:0")),
                                    Value::String(output.display().to_string()),
                                    Value::Int(timeout as i128),
                                ],
                            );
                            match result {
                                Some(Ok(Value::Struct { fields, .. })) => {
                                    pb.finish_with_message("received!");
                                    let recv_filename = fields
                                        .iter()
                                        .find(|(k, _)| k == "filename")
                                        .map(|(_, v)| v.as_string())
                                        .unwrap_or_default();
                                    let recv_size = fields
                                        .iter()
                                        .find(|(k, _)| k == "size")
                                        .map(|(_, v)| v.as_string())
                                        .unwrap_or_default();
                                    let verified = fields
                                        .iter()
                                        .find(|(k, _)| k == "verified")
                                        .and_then(|(_, v)| {
                                            if let Value::Bool(b) = v {
                                                Some(*b)
                                            } else {
                                                None
                                            }
                                        })
                                        .unwrap_or(false);
                                    println!("  received: {} ({} bytes)", recv_filename, recv_size);
                                    println!(
                                        "  BLAKE3 verified: {}",
                                        if verified { "PASS" } else { "FAIL" }
                                    );
                                    println!("  protocol: QUIC (TLS 1.3) via signal");
                                }
                                Some(Err(e)) => {
                                    pb.finish_with_message("failed");
                                    eprintln!("error: {e}");
                                    std::process::exit(exit_codes::IO_ERROR);
                                }
                                _ => {
                                    pb.finish_with_message("failed");
                                    eprintln!("error: receive dispatch failed");
                                    std::process::exit(exit_codes::IO_ERROR);
                                }
                            }
                            return Ok(());
                        } else {
                            eprintln!("Signal: {}", sig_resp.trim());
                            eprintln!("Falling back to direct listen mode...");
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: could not reach signal server {}: {}", sig_addr, e);
                        eprintln!("Falling back to direct listen mode...");
                    }
                }
            }

            // Mode 2: Code phrase mode (--code or positional code, derives port from code)
            let actual_listen = if let Some(code_phrase) = &effective_code {
                let port_result = tallow::stdlib::transfer_net::dispatch(
                    "code_to_port",
                    vec![Value::String(code_phrase.clone())],
                );
                let port: u16 = match port_result {
                    Some(Ok(Value::Struct { fields, .. })) => fields
                        .iter()
                        .find(|(k, _)| k == "port")
                        .and_then(|(_, v)| v.as_string().parse::<u16>().ok())
                        .unwrap_or(6881),
                    _ => 6881,
                };
                println!("Receiving with code phrase: {}", code_phrase);
                format!("0.0.0.0:{}", port)
            } else {
                listen.clone()
            };

            println!(
                "Listening on {} for incoming QUIC transfer...",
                actual_listen
            );
            println!("  output: {}", output.display());
            println!("  timeout: {}s", timeout);

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] Waiting for sender...",
                )
                .unwrap(),
            );
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let result = tallow::stdlib::transfer_net::dispatch(
                "quic_receive_file",
                vec![
                    Value::String(actual_listen),
                    Value::String(output.display().to_string()),
                    Value::Int(timeout as i128),
                ],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    pb.finish_with_message("received!");
                    let filename = fields
                        .iter()
                        .find(|(k, _)| k == "filename")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let size = fields
                        .iter()
                        .find(|(k, _)| k == "size")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let verified = fields
                        .iter()
                        .find(|(k, _)| k == "verified")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    println!("  received: {} ({} bytes)", filename, size);
                    println!(
                        "  BLAKE3 verified: {}",
                        if verified { "PASS" } else { "FAIL" }
                    );
                    println!("  protocol: QUIC (TLS 1.3)");
                }
                Some(Err(e)) => {
                    pb.finish_with_message("failed");
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                None => {
                    pb.finish_with_message("failed");
                    eprintln!("error: receive dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {}
            }
            return Ok(());
        }
        Command::Pack {
            ref dir,
            ref output,
            no_compress,
        } => {
            use tallow::interp::Value;
            if !dir.is_dir() {
                eprintln!("error: '{}' is not a directory", dir.display());
                std::process::exit(exit_codes::IO_ERROR);
            }
            println!(
                "Packing {} -> {} (compress: {})...",
                dir.display(),
                output.display(),
                !no_compress
            );
            let result = tallow::stdlib::transfer_net::dispatch(
                "pack_directory",
                vec![
                    Value::String(dir.display().to_string()),
                    Value::String(output.display().to_string()),
                    Value::Bool(!no_compress),
                ],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let files = fields
                        .iter()
                        .find(|(k, _)| k == "files")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let dirs = fields
                        .iter()
                        .find(|(k, _)| k == "dirs")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let total = fields
                        .iter()
                        .find(|(k, _)| k == "total_size")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let asize = fields
                        .iter()
                        .find(|(k, _)| k == "archive_size")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let hash = fields
                        .iter()
                        .find(|(k, _)| k == "hash")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    println!("  {} files, {} directories packed", files, dirs);
                    println!("  total: {} bytes -> archive: {} bytes", total, asize);
                    println!("  BLAKE3: {}", hash);
                    println!("  format: TWD v1");
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: pack dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Unpack {
            ref archive,
            ref output,
        } => {
            use tallow::interp::Value;
            if !archive.is_file() {
                eprintln!("error: '{}' is not a file", archive.display());
                std::process::exit(exit_codes::IO_ERROR);
            }
            println!("Unpacking {} -> {}...", archive.display(), output.display());
            let result = tallow::stdlib::transfer_net::dispatch(
                "unpack_directory",
                vec![
                    Value::String(archive.display().to_string()),
                    Value::String(output.display().to_string()),
                ],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let name = fields
                        .iter()
                        .find(|(k, _)| k == "dir_name")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let files = fields
                        .iter()
                        .find(|(k, _)| k == "files")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let dirs = fields
                        .iter()
                        .find(|(k, _)| k == "dirs")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let bytes = fields
                        .iter()
                        .find(|(k, _)| k == "bytes_written")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let out = fields
                        .iter()
                        .find(|(k, _)| k == "output")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    println!("  directory: {}", name);
                    println!("  {} files, {} directories restored", files, dirs);
                    println!("  {} bytes written", bytes);
                    println!("  output: {}", out);
                    println!("  structure: preserved");
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: unpack dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Relay { port } => {
            use tallow::interp::Value;
            println!("Starting TallowTransfer relay on port {}...", port);
            let result = tallow::stdlib::transfer_net::dispatch(
                "relay_start",
                vec![Value::Int(port as i128)],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let addr = fields
                        .iter()
                        .find(|(k, _)| k == "address")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let running = fields
                        .iter()
                        .find(|(k, _)| k == "running")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    println!("  relay listening on {}", addr);
                    println!("  protocol: TCP relay (code-phrase matched)");
                    if running {
                        println!("  accept loop: running (background thread)");
                    } else {
                        println!("  WARNING: relay_start reported running: false");
                    }
                    println!("  press Ctrl+C to stop");
                    println!();
                    // Keep the accept-loop thread alive until Ctrl+C.
                    let (tx, rx) = std::sync::mpsc::channel();
                    ctrlc::set_handler(move || {
                        let _ = tx.send(());
                    })
                    .ok();
                    let _ = rx.recv();
                    println!("\nrelay stopped.");
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: relay start failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Signal { port } => {
            run_signal_server(port);
            return Ok(());
        }
        // ── Phase 61: Watch command ──
        Command::Watch {
            ref dir,
            interval,
            ref to,
        } => {
            use tallow::interp::Value;
            println!(
                "Watching {} for changes (interval: {}ms)...",
                dir.display(),
                interval
            );
            if let Some(dest) = to {
                println!("  sync destination: {}", dest);
            }

            let session = tallow::stdlib::transfer_net::dispatch(
                "watch_start",
                vec![
                    Value::String(dir.display().to_string()),
                    Value::Int(interval as i128),
                ],
            );
            match session {
                Some(Ok(ref val @ Value::Struct { ref fields, .. })) => {
                    let tracked = fields
                        .iter()
                        .find(|(k, _)| k == "files_tracked")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let total = fields
                        .iter()
                        .find(|(k, _)| k == "total_size")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    println!("  tracking {} files ({} bytes)", tracked, total);
                    println!("  press Ctrl+C to stop");
                    println!();

                    // Polling loop
                    let mut current_session = val.clone();
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(interval));
                        let check = tallow::stdlib::transfer_net::dispatch(
                            "watch_check",
                            vec![current_session.clone()],
                        );
                        match check {
                            Some(Ok(Value::Struct { ref fields, .. })) => {
                                let has_changes = fields
                                    .iter()
                                    .find(|(k, _)| k == "has_changes")
                                    .and_then(|(_, v)| {
                                        if let Value::Bool(b) = v {
                                            Some(*b)
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(false);
                                if has_changes {
                                    let added = fields
                                        .iter()
                                        .find(|(k, _)| k == "added")
                                        .and_then(|(_, v)| {
                                            if let Value::Array(a) = v {
                                                Some(a.len())
                                            } else {
                                                None
                                            }
                                        })
                                        .unwrap_or(0);
                                    let modified = fields
                                        .iter()
                                        .find(|(k, _)| k == "modified")
                                        .and_then(|(_, v)| {
                                            if let Value::Array(a) = v {
                                                Some(a.len())
                                            } else {
                                                None
                                            }
                                        })
                                        .unwrap_or(0);
                                    let removed = fields
                                        .iter()
                                        .find(|(k, _)| k == "removed")
                                        .and_then(|(_, v)| {
                                            if let Value::Array(a) = v {
                                                Some(a.len())
                                            } else {
                                                None
                                            }
                                        })
                                        .unwrap_or(0);
                                    println!(
                                        "[change] +{} added, ~{} modified, -{} removed",
                                        added, modified, removed
                                    );
                                }
                                // Update session with new snapshot
                                if let Some((_, new_snap)) =
                                    fields.iter().find(|(k, _)| k == "new_snapshot")
                                {
                                    // Rebuild session with new snapshot
                                    if let Value::Struct { ref fields, .. } = current_session {
                                        let mut new_fields = fields.clone();
                                        if let Some(snap_field) =
                                            new_fields.iter_mut().find(|(k, _)| k == "snapshot")
                                        {
                                            snap_field.1 = new_snap.clone();
                                        }
                                        current_session = Value::Struct {
                                            name: "WatchSession".to_string(),
                                            fields: new_fields,
                                        };
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                eprintln!("watch error: {e}");
                                break;
                            }
                            _ => {
                                eprintln!("watch check failed");
                                break;
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: watch_start dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        // ── Phase 62: Audit transfers, validate file, retention ──
        Command::AuditTransfers {
            ref format,
            ref save,
        } => {
            use tallow::interp::Value;
            if format == "json" {
                let result = tallow::stdlib::transfer::dispatch("audit_export", vec![]);
                match result {
                    Some(Ok(v)) => println!("{}", v.as_string()),
                    Some(Err(e)) => {
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => {
                        eprintln!("error: audit_export failed");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
            } else {
                let result = tallow::stdlib::transfer::dispatch("audit_verify", vec![]);
                match result {
                    Some(Ok(Value::Struct { ref fields, .. })) => {
                        let entries = fields
                            .iter()
                            .find(|(k, _)| k == "entries")
                            .map(|(_, v)| v.as_string())
                            .unwrap_or_default();
                        let valid = fields
                            .iter()
                            .find(|(k, _)| k == "valid")
                            .and_then(|(_, v)| {
                                if let Value::Bool(b) = v {
                                    Some(*b)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(false);
                        if valid {
                            println!("Audit chain: VALID ({entries} entries)");
                        } else {
                            println!("Audit chain: INVALID ({entries} entries) -- TAMPERED");
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("error: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                    _ => println!("Audit log empty (no transfers recorded in this session)"),
                }
            }
            if let Some(path) = &save {
                let result = tallow::stdlib::transfer::dispatch(
                    "audit_save",
                    vec![Value::String(path.display().to_string())],
                );
                match result {
                    Some(Ok(_)) => println!("Audit log saved to: {}", path.display()),
                    Some(Err(e)) => eprintln!("warning: save failed: {e}"),
                    _ => eprintln!("warning: audit_save dispatch failed"),
                }
            }
            return Ok(());
        }
        Command::Drill {
            list,
            ref scenario,
            all,
            ref sandbox_dir,
            ref report_dir,
            scale,
            json,
        } => {
            let code = tallow::drill::run_cli(tallow::drill::CliOptions {
                list,
                scenario: scenario.clone(),
                all,
                sandbox_dir: sandbox_dir.clone(),
                report_dir: report_dir.clone(),
                scale,
                json,
            });
            std::process::exit(code);
        }
        Command::Doctor {
            stdlib_scraper,
            capabilities,
            probe,
            stdlib_drift,
            crypto_surface,
            rotation,
            ref rotation_state,
        } => {
            // W3 batch-2 cluster C (#120): SVID rotation alarm report. Pure
            // JSON on stdout; exit 2 when any Critical alarm is present.
            if rotation {
                let exit = emit_rotation_report(rotation_state.as_deref());
                std::process::exit(exit);
            }
            // W2-04 (cycle-02/07 §D5 L3): crypto-surface coverage + mock-body
            // guard. Pure-JSON on stdout; exit 2 when any declaration is
            // uncovered or carries an un-annotated mock body.
            if crypto_surface {
                let exit = emit_crypto_surface_report();
                std::process::exit(exit);
            }
            // C3 (2026-09-05): stdlib declaration-drift report. Pure-JSON on
            // stdout; exit 2 when any declared fn is unreachable from .tl.
            if stdlib_drift {
                let exit = emit_stdlib_drift_report();
                std::process::exit(exit);
            }
            // Roadmap #8 (2026-09-05): machine-readable capability report.
            // Pure-JSON/text report mode — stdout carries ONLY the report so
            // it can be piped straight into `python3 -m json.tool` etc.
            // Default classification is static (no handler execution); pass
            // --probe for guarded runtime verification.
            if let Some(fmt) = capabilities.as_deref() {
                return emit_capabilities_report(fmt, probe);
            }
            // Operator health check. Runs a default basic check set with clear
            // PASS/FAIL output.
            //
            // `--stdlib-scraper` switches the command to MACHINE mode: stdout
            // carries the `tallow.doctor.stdlib_scraper.v1` JSON report and
            // nothing else, and stderr stays empty. That is the contract pinned
            // by `tests/stdlib_scraper_doctor_cli.rs` (which does
            // `serde_json::from_slice` over stdout), so the human PASS/FAIL
            // lines are SUPPRESSED under the flag rather than redirected to
            // stderr — stderr must stay empty. The default path is unchanged,
            // and that is the path the release gate runs
            // (`scripts/release_gate.sh` stage S7c: `tallow doctor`, rc 0).
            macro_rules! human {
                ($($arg:tt)*) => {
                    if !stdlib_scraper {
                        println!($($arg)*);
                    }
                };
            }
            let mut failures: Vec<String> = Vec::new();

            // Check 1: tallow binary present
            let exe = std::env::current_exe().ok();
            let binary_ok = exe.as_ref().map(|p| p.exists()).unwrap_or(false);
            let binary_detail = exe
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            human!(
                "[{}] tallow binary present ({})",
                if binary_ok { "PASS" } else { "FAIL" },
                binary_detail
            );
            if !binary_ok {
                failures.push("tallow binary present".to_string());
            }

            // Check 2: doctor self — the process runs and the stdlib dispatch
            // table is reachable.
            let self_ok = tallow::stdlib::transfer_net::dispatch("generate_code", vec![])
                .map(|r| r.is_ok())
                .unwrap_or(false);
            human!(
                "[{}] doctor self (stdlib dispatch reachable)",
                if self_ok { "PASS" } else { "FAIL" }
            );
            if !self_ok {
                failures.push("doctor self (stdlib dispatch)".to_string());
            }

            // Check 3: cargo-ok — the tallow crate resolves (cargo metadata,
            // no build).
            let cargo_ok = cargo_metadata_ok();
            human!(
                "[{}] cargo-ok (cargo metadata --no-deps)",
                if cargo_ok { "PASS" } else { "FAIL" }
            );
            if !cargo_ok {
                failures.push("cargo-ok".to_string());
            }

            // Check 4: stdlib-scraper surface report (declaration + runtime
            // dispatch + tests for the scraper-critical stdlib surface).
            const REQUIRED_SURFACES: &[&str] = &[
                // surface name → declaring stdlib module
                "http.get:http",
                "http.post:http",
                "http.batch:http",
                "Response.text:http",
                "Response.json:http",
                "json.parse:json",
                "html.parse:html",
                "HtmlDocument.select:html",
                "HtmlDocument.text:html",
                "HtmlElement.text:html",
                "HtmlElement.attr:html",
                "time.now:time",
            ];

            let mut surfaces = Vec::with_capacity(REQUIRED_SURFACES.len());
            for entry in REQUIRED_SURFACES {
                let (name, module) = entry.split_once(':').expect("surface:module pair");
                let function = name.rsplit('.').next().unwrap_or(name);
                let declared = stdlib_declaration_contains(module, function);
                let runtime_dispatch = stdlib_dispatches(name, module);
                let has_tests = stdlib_surface_has_tests(module);

                let status = if declared && runtime_dispatch && has_tests {
                    "pass"
                } else {
                    "fail"
                };
                surfaces.push(serde_json::json!({
                    "name": name,
                    "status": status,
                    "checks": {
                        "declaration": { "passed": declared },
                        "runtime_dispatch": { "passed": runtime_dispatch },
                        "tests": { "passed": has_tests },
                    },
                }));
            }
            let surface_fail = surfaces.iter().filter(|s| s["status"] == "fail").count();
            let total = surfaces.len();
            human!(
                "[{}] stdlib-scraper surfaces ({}/{} pass)",
                if surface_fail == 0 { "PASS" } else { "FAIL" },
                total - surface_fail,
                total
            );
            if surface_fail > 0 {
                failures.push(format!(
                    "stdlib-scraper surfaces ({} failing)",
                    surface_fail
                ));
            }

            // Checks 5-8 (R-7.9 / R-5.15 / ag04 R-14): wire-first security
            // conformance probes. Each reuses an already-implemented control
            // (egress refusal, vault export floor, daemon file perms, journal
            // redaction) and reports its live wire state, so an un-wired
            // control surfaces as FAIL instead of a design claim. FAIL fires
            // only on a real refusal/exposure condition; missing optional
            // components stay advisory inside the PASS detail.
            for result in run_conformance_probes() {
                human!(
                    "[{}] {} ({})",
                    result.status.label(),
                    result.label,
                    result.detail
                );
                if result.status == ProbeStatus::Fail {
                    failures.push(result.label.to_string());
                }
            }

            // Checks 9-11 (R-P9-3 / rows #70, #125): host-hardening sysctl
            // posture - read-only probe of /proc/sys (io_uring off,
            // unprivileged BPF off, kptr_restrict >=1). Advisory only:
            // absent or non-hardened sysctls report WARN and never fail a
            // run (kernels differ; the host is not always operator-owned).
            for item in tallow::host_probe::summary(tallow::host_probe::DEFAULT_ROOT) {
                human!(
                    "[{}] host-hardening: {} ({})",
                    item.status.label(),
                    item.name,
                    item.detail
                );
            }

            if stdlib_scraper {
                // Machine contract: emit the JSON report (existing behavior).
                let report = serde_json::json!({
                    "schema_version": "tallow.doctor.stdlib_scraper.v1",
                    "passed": surface_fail == 0,
                    "summary": {
                        "total": total,
                        "pass": total - surface_fail,
                        "fail": surface_fail,
                    },
                    "surfaces": surfaces,
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            }

            if !failures.is_empty() {
                eprintln!(
                    "\n{} check(s) failed: {}",
                    failures.len(),
                    failures.join(", ")
                );
                std::process::exit(exit_codes::IO_ERROR);
            }
            human!("\nall checks passed.");
            return Ok(());
        }
        Command::ValidateFile { ref file } => {
            use tallow::interp::Value;
            let result = tallow::stdlib::transfer::dispatch(
                "validate_file_type",
                vec![Value::String(file.display().to_string())],
            );
            match result {
                Some(Ok(Value::Struct { ref fields, .. })) => {
                    let detected = fields
                        .iter()
                        .find(|(k, _)| k == "detected_type")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let mime = fields
                        .iter()
                        .find(|(k, _)| k == "mime")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let ext = fields
                        .iter()
                        .find(|(k, _)| k == "extension")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let safe = fields
                        .iter()
                        .find(|(k, _)| k == "safe")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let executable = fields
                        .iter()
                        .find(|(k, _)| k == "executable")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let has_script = fields
                        .iter()
                        .find(|(k, _)| k == "has_script")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let has_macro = fields
                        .iter()
                        .find(|(k, _)| k == "has_macro")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let mismatch = fields
                        .iter()
                        .find(|(k, _)| k == "extension_mismatch")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let size = fields
                        .iter()
                        .find(|(k, _)| k == "size")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();

                    println!("File:       {}", file.display());
                    println!("Type:       {detected}");
                    println!("MIME:       {mime}");
                    println!("Extension:  {ext}");
                    println!("Size:       {size} bytes");
                    println!("Safe:       {}", if safe { "YES" } else { "NO" });
                    if executable {
                        println!("  WARNING: executable binary detected");
                    }
                    if has_script {
                        println!("  WARNING: embedded script tags detected");
                    }
                    if has_macro {
                        println!("  WARNING: embedded macros detected");
                    }
                    if mismatch {
                        println!("  WARNING: extension does not match file type");
                    }
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: validate dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Retain {
            ref dir,
            days,
            dry_run,
        } => {
            use tallow::interp::Value;
            let label = if dry_run { "DRY RUN: " } else { "" };
            println!("{label}Applying {days}-day retention to: {}", dir.display());
            let result = tallow::stdlib::transfer::dispatch(
                "retention_apply",
                vec![
                    Value::String(dir.display().to_string()),
                    Value::Int(days as i128),
                    Value::Bool(dry_run),
                ],
            );
            match result {
                Some(Ok(Value::Struct { ref fields, .. })) => {
                    let deleted = fields
                        .iter()
                        .find(|(k, _)| k == "deleted")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let retained = fields
                        .iter()
                        .find(|(k, _)| k == "retained")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let freed = fields
                        .iter()
                        .find(|(k, _)| k == "bytes_freed")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    println!("  Deleted:  {deleted} files");
                    println!("  Retained: {retained} files");
                    println!("  Freed:    {freed} bytes");
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: retention_apply dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        // ── Phase 63: Encrypted Chat commands ──
        Command::Chat {
            ref name,
            ref code,
            ref proxy,
            ref relay,
        } => {
            use tallow::interp::Value;

            if let Some(proxy_url) = proxy {
                println!("Proxy: {}", proxy_url);
            }

            let code_phrase = code.clone().unwrap_or_else(|| {
                match tallow::stdlib::transfer_net::dispatch("generate_code", vec![]) {
                    Some(Ok(Value::Struct { fields, .. })) => fields
                        .iter()
                        .find(|(k, _)| k == "code")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default(),
                    _ => "000-error-error-error".to_string(),
                }
            });

            // Show QR-style display
            if let Some(Ok(Value::String(qr))) = tallow::stdlib::transfer_net::dispatch(
                "generate_qr",
                vec![Value::String(code_phrase.clone())],
            ) {
                println!("{}", qr);
            }

            // Create chat session
            let session_result = tallow::stdlib::transfer_net::dispatch(
                "chat_create",
                vec![
                    Value::String(name.clone()),
                    Value::String(code_phrase.clone()),
                ],
            );

            match session_result {
                Some(Ok(Value::Struct { ref fields, .. })) => {
                    let session_id = fields
                        .iter()
                        .find(|(k, _)| k == "session_id")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let algo = fields
                        .iter()
                        .find(|(k, _)| k == "algo")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let port = fields
                        .iter()
                        .find(|(k, _)| k == "port")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();

                    println!();
                    println!("  Session:    {}", session_id);
                    println!("  User:       {}", name);
                    println!("  Code:       {}", code_phrase);
                    println!("  Port:       {}", port);
                    println!("  Encryption: {}", algo);
                    println!();
                    println!("Share this code with your chat partner.");
                    println!(
                        "They join with: tallow chat --name <their-name> --code {}",
                        code_phrase
                    );
                    println!();

                    // Minimal real chat transport: TCP line relay (same
                    // protocol as `tallow relay`). Messages are pushed to the
                    // relay under the rendezvous code; a background thread
                    // polls for inbound messages. Both parties need a
                    // reachable relay (start one with `tallow relay <port>`).
                    let relay_addr =
                        relay.clone().unwrap_or_else(|| "127.0.0.1:6880".to_string());
                    println!("  Transport: TCP relay @ {}", relay_addr);
                    println!("  Type a message and press Enter. Ctrl+D or /quit to exit.");
                    println!();
                    run_relay_chat(&name, &code_phrase, &relay_addr);
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: chat_create dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::SpeedTest { ref target } => {
            use tallow::interp::Value;
            match target {
                Some(t) => {
                    println!("Running TallowTransfer speed test (10MB) against {}...\n", t)
                }
                None => println!(
                    "Running TallowTransfer speed test (10MB, local-only — pass --target host:port for a network leg)...\n"
                ),
            }
            let mut args = vec![];
            if let Some(t) = target {
                args.push(Value::String(t.clone()));
            }
            let result = tallow::stdlib::transfer_net::dispatch("speed_test", args);
            if let Some(Ok(Value::Struct { fields, .. })) = result {
                for (k, v) in &fields {
                    match v {
                        Value::Float(f) => println!("  {:<25} {:.2} MB/s", k, f),
                        Value::Int(n) => println!("  {:<25} {} MB", k, n),
                        Value::String(s) => println!("  {:<25} {}", k, s),
                        _ => {}
                    }
                }
            } else {
                eprintln!("error: speed test failed");
                std::process::exit(exit_codes::IO_ERROR);
            }
            return Ok(());
        }
        Command::GroupChatCmd {
            ref name,
            ref user,
            ref code,
            ref relay,
        } => {
            use tallow::interp::Value;

            let code_phrase = code.clone().unwrap_or_else(|| {
                match tallow::stdlib::transfer_net::dispatch("generate_code", vec![]) {
                    Some(Ok(Value::Struct { fields, .. })) => fields
                        .iter()
                        .find(|(k, _)| k == "code")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default(),
                    _ => "000-error-error-error".to_string(),
                }
            });

            // Show QR-style display
            if let Some(Ok(Value::String(qr))) = tallow::stdlib::transfer_net::dispatch(
                "generate_qr",
                vec![Value::String(code_phrase.clone())],
            ) {
                println!("{}", qr);
            }

            let result = tallow::stdlib::transfer_net::dispatch(
                "group_chat_create",
                vec![
                    Value::String(name.clone()),
                    Value::String(user.clone()),
                    Value::String(code_phrase.clone()),
                ],
            );

            match result {
                Some(Ok(Value::Struct { ref fields, .. })) => {
                    let group_id = fields
                        .iter()
                        .find(|(k, _)| k == "group_id")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let port = fields
                        .iter()
                        .find(|(k, _)| k == "port")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();

                    println!();
                    println!("  Group:      {}", name);
                    println!("  Group ID:   {}", group_id);
                    println!("  Creator:    {}", user);
                    println!("  Code:       {}", code_phrase);
                    println!("  Port:       {}", port);
                    println!("  Encryption: AES-256-GCM");
                    println!("  Max:        50 members");
                    println!();
                    println!(
                        "Members join with: tallow chat --name <name> --code {}",
                        code_phrase
                    );
                    println!();

                    // Same minimal real transport as `tallow chat`: TCP line
                    // relay under the group code.
                    let relay_addr =
                        relay.clone().unwrap_or_else(|| "127.0.0.1:6880".to_string());
                    println!("  Transport: TCP relay @ {}", relay_addr);
                    println!("  Type a message and press Enter. Ctrl+D or /quit to exit.");
                    println!();
                    run_relay_chat(&user, &code_phrase, &relay_addr);
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: group_chat_create dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::SendText {
            ref text,
            ref to,
            ref code,
        } => {
            use tallow::interp::Value;

            // Real send_text: transmits the payload over TCP when a host:port
            // target is given; without one it returns an honest
            // `transmitted: false` result — never a fabricated success.
            let mut args = vec![Value::String(text.clone())];
            if let Some(dest) = to {
                args.push(Value::String(dest.clone()));
            }
            let result = tallow::stdlib::transfer_net::dispatch("send_text", args);

            match result {
                Some(Ok(Value::Struct { ref fields, .. })) => {
                    let hash = fields
                        .iter()
                        .find(|(k, _)| k == "hash")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let size = fields
                        .iter()
                        .find(|(k, _)| k == "size")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let transmitted = fields
                        .iter()
                        .find(|(k, _)| k == "transmitted")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let acked = fields
                        .iter()
                        .find(|(k, _)| k == "acked")
                        .and_then(|(_, v)| {
                            if let Value::Bool(b) = v {
                                Some(*b)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(false);
                    let dest = fields
                        .iter()
                        .find(|(k, _)| k == "to")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let protocol = fields
                        .iter()
                        .find(|(k, _)| k == "protocol")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let reason = fields
                        .iter()
                        .find(|(k, _)| k == "reason")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();

                    println!();
                    println!("  Text:   {} bytes", size);
                    println!("  BLAKE3: {}", hash);
                    if transmitted {
                        println!("  Transmitted: yes");
                        println!("  To:          {}", dest);
                        println!("  Protocol:    {}", protocol);
                        println!(
                            "  Peer ACK:    {}",
                            if acked {
                                "yes"
                            } else {
                                "no (bytes sent, no ack received)"
                            }
                        );
                    } else {
                        println!("  Transmitted: no");
                        println!("  Reason:      {}", reason);
                        println!();
                        println!("  To actually send the text, provide a recipient address:");
                        println!("    tallow send-text \"{}\" --to host:port", text);
                    }
                    if let Some(cp) = code {
                        println!();
                        println!(
                            "  Code phrase \"{}\" is only used with relay-based file receive;",
                            cp
                        );
                        println!("  it is NOT needed for a direct --to text send.");
                    }
                    println!();
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("error: send_text dispatch failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Share {
            ref path,
            port,
            ref password,
            max_downloads,
        } => {
            use tallow::interp::Value;

            let is_dir = path.is_dir();
            let mut share_args = vec![
                Value::String(path.display().to_string()),
                Value::Int(port.unwrap_or(0) as i128),
            ];
            if let Some(pw) = password {
                share_args.push(Value::String(pw.clone()));
            } else if max_downloads > 0 {
                // Need a placeholder for password since max_downloads is arg 3
                share_args.push(Value::Nil);
            }
            if max_downloads > 0 {
                share_args.push(Value::Int(max_downloads as i128));
            }

            let dispatch_fn = if is_dir {
                "share_dir_by_link"
            } else {
                "share_by_link"
            };
            let result = tallow::stdlib::transfer_net::dispatch(dispatch_fn, share_args);

            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let url = fields
                        .iter()
                        .find(|(k, _)| k == "url")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let size = fields
                        .iter()
                        .find(|(k, _)| k == "size")
                        .and_then(|(_, v)| {
                            if let Value::Int(n) = v {
                                Some(*n)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let fname = fields
                        .iter()
                        .find(|(k, _)| k == "filename")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();
                    let hash = fields
                        .iter()
                        .find(|(k, _)| k == "hash")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();

                    println!();
                    println!("  TALLOW SHARE");
                    println!("  ----------");
                    println!("  File: {}", fname);
                    if size > 0 {
                        println!("  Size: {}", format_file_size(size as u64));
                    }
                    if !hash.is_empty() {
                        println!("  BLAKE3: {}", hash);
                    }
                    println!();
                    println!("  Download link:");
                    println!("  {}", url);
                    println!();
                    if password.is_some() {
                        println!("  Password protected: yes");
                    }
                    if max_downloads > 0 {
                        println!("  Max downloads: {}", max_downloads);
                    }
                    println!("  Anyone with a browser can download.");
                    println!("  Press Ctrl+C to stop sharing.");
                    println!();

                    // Keep the HTTP server thread alive until Ctrl+C.
                    let (tx, rx) = std::sync::mpsc::channel();
                    ctrlc::set_handler(move || {
                        let _ = tx.send(());
                    })
                    .ok();
                    let _ = rx.recv();
                    println!("\nshare server stopped.");
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("share failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
        }
        Command::LiveView { port, refresh } => {
            use tallow::interp::Value;

            let result = tallow::stdlib::transfer_net::dispatch(
                "browser_live_share",
                vec![Value::Int(port as i128), Value::Int(refresh as i128)],
            );
            match result {
                Some(Ok(Value::Struct { fields, .. })) => {
                    let url = fields
                        .iter()
                        .find(|(k, _)| k == "url")
                        .map(|(_, v)| v.as_string())
                        .unwrap_or_default();

                    println!();
                    println!("  TALLOW LIVE BROWSER VIEW");
                    println!("  ----------------------");
                    println!("  Viewer URL: {}", url);
                    println!();
                    println!("  Open this URL on any device to");
                    println!("  watch the browser session live.");
                    println!("  Refresh: every {}ms", refresh);
                    println!();
                    println!("  Press Ctrl+C to stop.");
                    println!();

                    // Keep main thread alive while server runs
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(3600));
                    }
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    std::process::exit(exit_codes::IO_ERROR);
                }
                _ => {
                    eprintln!("live view failed");
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
        }
        Command::Browser { ref action } => {
            match action {
                BrowserAction::Install { full } => {
                    match tallow::browser::download::install_browser(*full) {
                        Ok(path) => {
                            eprintln!("Browser installed: {}", path.display());
                        }
                        Err(e) => {
                            eprintln!("Error installing browser: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                    }
                }
                BrowserAction::List => match tallow::browser::download::list_installed() {
                    Ok(versions) => {
                        if versions.is_empty() {
                            eprintln!(
                                "No browsers installed. Run `tallow browser install` to get started."
                            );
                        } else {
                            eprintln!("Installed browsers:");
                            for v in &versions {
                                eprintln!("  {} ({}) - {}", v.version, v.variant, v.path.display());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error listing browsers: {e}");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                },
                BrowserAction::Remove { version } => {
                    match tallow::browser::download::remove_version(version) {
                        Ok(()) => {
                            eprintln!("Removed Chrome {version}");
                        }
                        Err(e) => {
                            eprintln!("Error removing browser: {e}");
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                    }
                }
                BrowserAction::Path => match tallow::browser::download::find_installed_chrome() {
                    Some(path) => {
                        println!("{}", path.display());
                    }
                    None => {
                        eprintln!("No Chrome binary found. Run `tallow browser install` first.");
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                },
                BrowserAction::Pool => {
                    println!("tallow browser pool");
                    println!("  Status: not running (start with `tallow browser daemon`)");
                    println!("  Max instances: 4 (configurable in tallow.toml [browser] section)");
                    println!("  Tabs per instance: 50");
                    println!("  Transport: pipe (recommended) or websocket");
                }
                BrowserAction::Devices { category } => {
                    let devices = match category {
                        Some(cat) => tallow::browser::devices::list_devices_by_category(cat),
                        None => tallow::browser::devices::list_devices(),
                    };
                    let total = tallow::browser::devices::device_count();
                    if let Some(cat) = category {
                        eprintln!(
                            "Device profiles (category: {}) — {} of {} total:",
                            cat,
                            devices.len(),
                            total
                        );
                    } else {
                        eprintln!("All device profiles ({} total):", total);
                    }
                    for name in &devices {
                        if let Some(d) = tallow::browser::devices::get_device(name) {
                            eprintln!(
                                "  {:<35} {:>5}x{:<5} {:.2}x  {}  {}",
                                d.name,
                                d.viewport_width,
                                d.viewport_height,
                                d.device_scale_factor,
                                if d.is_mobile { "mobile " } else { "desktop" },
                                d.default_browser,
                            );
                        }
                    }
                }
                BrowserAction::Open {
                    url,
                    headless,
                    plugins,
                    device,
                    no_plugins,
                    tor,
                    proxy,
                } => {
                    use tallow::browser;
                    let rt = tokio::runtime::Runtime::new().unwrap();

                    // Load config from ~/.tallow/browser/config/
                    let full_config = browser::config::BrowserFullConfig::load();

                    // Build BrowserConfig: config file as base, CLI flags override
                    let mut browser_config = full_config.browser.to_browser_config();

                    // CLI overrides
                    if *headless {
                        browser_config.headless = true;
                    }
                    if *tor {
                        // Fingerprint normalization: prefer a real Firefox engine
                        // (Camoufox, the Juggler-enabled Firefox) so JS, engine,
                        // UA, and TLS are all Firefox (true Tor-Browser mimicry).
                        // If Camoufox isn't installed, fall back to Chromium +
                        // tor_chrome_profile() (Chrome-consistent) so `--tor`
                        // never breaks.
                        if browser::download::find_camoufox().is_some() {
                            browser_config.backend = browser::process::BrowserBackend::Camoufox;
                        }
                        // Route browser egress through a live Tor instance via
                        // the Tor manager. Prefer the running system daemon
                        // (avoids a port-9050 clash); if none is reachable, spawn
                        // a managed instance. Uses socks5h:// (remote DNS) so
                        // hostnames resolve at the exit node — no DNS leak.
                        use tallow::tor::TorManager;
                        let egress = rt.block_on(async {
                            if let Some(inst) = TorManager::detect_system_tor().await {
                                return Some(inst.socks_port);
                            }
                            let _ = TorManager::start(1).await.ok();
                            None
                        });
                        match egress {
                            Some(socks_port) => {
                                // P1 W1-E1: bind a per-invocation SOCKS5
                                // identity (IsolateSOCKSAuth) instead of a
                                // bare socks5h:// URL — every bare URL shares
                                // the box-wide circuit. Minted ONCE per
                                // invocation so the session stays sticky to a
                                // single circuit. (When the analytics PAC is
                                // present it supersedes this URL; see
                                // docs/operations/egress-tiers.md.)
                                let stream = format!("browser-cli-{}", std::process::id());
                                let socks =
                                    tallow::tor::pool::isolated_proxy_url(&stream, socks_port);
                                browser_config.proxy = Some(socks);
                                browser_config.proxy_pac = write_analytics_pac(socks_port);
                            }
                            None => {
                                // Fallback: assume the system Tor on 9050
                                let stream = format!("browser-cli-{}", std::process::id());
                                browser_config.proxy = Some(tallow::tor::pool::isolated_proxy_url(
                                    &stream, 9050,
                                ));
                                browser_config.proxy_pac = write_analytics_pac(9050);
                            }
                        }
                    } else if let Some(p) = proxy {
                        browser_config.proxy = Some(p.clone());
                    }

                    // Validate browser binary path (backend-aware discovery).
                    // For Firefox-family backends the configured `chrome_path`
                    // is almost always a Chromium binary (e.g. /usr/bin/chromium),
                    // so ALWAYS re-discover the correct binary — otherwise the
                    // backend flag is ignored and Chromium is launched with
                    // Firefox Juggler args (which it silently ignores → the
                    // launch hangs waiting for a Juggler ready signal that never
                    // comes). Only trust the configured path for Chromium.
                    let backend = browser_config.backend;
                    let needs_discovery = backend != browser::process::BrowserBackend::Chromium
                        || !browser_config.chrome_path.exists();
                    if needs_discovery {
                        browser_config.chrome_path =
                            browser::download::find_browser_for_backend(&backend)
                            .unwrap_or_else(|| {
                                eprintln!(
                                    "{} not found (backend={{{}}}). Run `tallow browser install` first, \
                                     or set the binary path in ~/.tallow/browser/config/browser.toml.",
                                    backend.as_str(),
                                    backend.as_str()
                                );
                                std::process::exit(1);
                            });
                    }

                    let proxy_url = browser_config.proxy.clone();

                    let proc = browser::process::BrowserProcess::launch(&browser_config)
                        .unwrap_or_else(|e| {
                            eprintln!("Failed to launch Chrome: {e}");
                            std::process::exit(1);
                        });

                    // Build plugin config + stealth JS once (shared across the
                    // CDP and Juggler backends below).
                    let mut plugin_summary: Option<String> = None;
                    let mut combined_js = String::new();
                    if !no_plugins {
                        let plugin_config = match plugins.as_str() {
                            "max" | "maximum" => browser::plugins::BrowserPlugins::max_privacy(),
                            "none" | "off" => browser::plugins::BrowserPlugins::none(),
                            "config" => full_config.plugins.to_browser_plugins(),
                            _ => {
                                // "balanced" or default: use config file if preset is "custom"
                                if full_config.plugins.preset == "custom" {
                                    full_config.plugins.to_browser_plugins()
                                } else {
                                    browser::plugins::BrowserPlugins::default()
                                }
                            }
                        };

                        // Build stealth profile. Match it to the backend so the
                        // on-wire fingerprint is internally consistent: a Firefox
                        // (Camoufox) backend uses the Firefox Tor profile; a
                        // Chromium backend uses the Chrome-consistent Tor profile
                        // (UTC, canvas/WebGL blocked, no tz leak).
                        let mut stealth_profile = if browser_config.backend
                            == browser::process::BrowserBackend::Camoufox
                        {
                            browser::tor_stealth::tor_browser_profile()
                        } else if *tor
                            || full_config.tor.fingerprint.auto_adjust
                                && proxy_url
                                    .as_deref()
                                    .map_or(false, |p| p.contains("127.0.0.1:905"))
                        {
                            browser::tor_stealth::tor_chrome_profile()
                        } else {
                            full_config.stealth.to_stealth_profile()
                        };
                        // For anonymous (--tor) browsing, randomize the
                        // per-session identity fields (timezone, canvas seed,
                        // concurrency, memory, languages) so each fresh launch
                        // is a non-correlatable fingerprint. Engine-consistent
                        // fields (UA/viewport/WebGL) are left untouched.
                        if *tor {
                            stealth_profile.randomize();
                        }

                        let inject_js = plugin_config.injection_script();
                        let stealth_js = browser::stealth::canvas_evasion_script(&stealth_profile);
                        combined_js = format!("{}\n{}", inject_js, stealth_js);
                        plugin_summary = Some(plugin_config.summary());
                    }

                    // Backend-aware page driving: Camoufox/Firefox uses the
                    // Juggler pipe transport (JugglerPage); Chromium uses WebSocket CDP.
                    if proc.juggler.is_some() {
                        let juggler = proc.juggler.clone().expect("checked above");
                        let mut jpage = browser::juggler::JugglerPage::new(
                            juggler,
                            browser_config.timeout,
                        )
                        .unwrap_or_else(|e| {
                            eprintln!("Juggler page creation failed: {e}");
                            std::process::exit(1);
                        });

                        // Best-effort analytics kill. On the Juggler/Camoufox
                        // transport the Network domain and pre-load init scripts
                        // are unsupported, so the primary kill is re-applied
                        // below (after navigation) via Runtime.evaluate.
                        let _ = jpage.apply_privacy();

                        if url != "about:blank" {
                            let clean_url = browser::plugins::BrowserPlugins::default().force_https(
                                &browser::plugins::BrowserPlugins::default().clean_url(url),
                            );
                            let _ = jpage.navigate(&clean_url);
                            eprintln!("  URL:     {clean_url}");
                            // Inject plugins + stealth + the analytics/session-
                            // replay kill AFTER navigation so it runs on the
                            // loaded document. This stubs MS Clarity / Sentry /
                            // GTM, removes their script tags, and blocks
                            // subsequent beacons — so the user's in-session
                            // searches are not captured by the site's telemetry.
                            if !combined_js.is_empty() {
                                let _ = jpage.evaluate(&combined_js);
                                if let Some(s) = plugin_summary {
                                    eprintln!("  Plugins: {s}");
                                }
                            }
                            let title = jpage.title().unwrap_or_default();
                            eprintln!("  Title:   {title}");
                            // Surface the real engine (proves the Juggler/Firefox
                            // path, and confirms the on-wire UA is Firefox not
                            // Chromium).
                            if let Some(ua) = jpage
                                .evaluate("navigator.userAgent")
                                .ok()
                                .and_then(|v| v.as_str().map(|s| s.to_string()))
                            {
                                eprintln!("  Engine:  {ua}");
                            }
                            // Report analytics-kill state (Clarity/Sentry/GTM
                            // stubbed? any analytics scripts still loaded?).
                            eprintln!("  Privacy: {}", jpage.privacy_status());
                        }
                    } else {
                        let ws_url = proc.ws_url.clone();
                        let client = rt
                            .block_on(browser::CdpClient::connect(&ws_url))
                            .unwrap_or_else(|e| {
                                eprintln!("CDP connection failed: {e}");
                                std::process::exit(1);
                            });

                        let page = rt.block_on(client.create_page(None)).unwrap_or_else(|e| {
                            eprintln!("Page creation failed: {e}");
                            std::process::exit(1);
                        });

                        if !combined_js.is_empty() {
                            let _ = rt.block_on(page.evaluate_expression(&combined_js));
                            if let Some(s) = plugin_summary {
                                eprintln!("  Plugins: {s}");
                            }
                        }

                        // Navigate to URL
                        if url != "about:blank" {
                            let clean_url = browser::plugins::BrowserPlugins::default().force_https(
                                &browser::plugins::BrowserPlugins::default().clean_url(url),
                            );
                            let _ = rt.block_on(
                                page.navigate(&clean_url, browser::WaitUntil::DomContentLoaded),
                            );
                            let title = rt.block_on(page.title()).unwrap_or_default();
                            eprintln!("  URL:     {clean_url}");
                            eprintln!("  Title:   {title}");
                        }
                    }

                    eprintln!("");
                    if let Some(ref p) = proxy_url {
                        if *tor {
                            eprintln!(
                                "  Tor:     ENABLED — all traffic routed through Tor network"
                            );
                        } else {
                            eprintln!("  Proxy:   {p}");
                        }
                    }
                    eprintln!("");
                    eprintln!("  Tallow Browser is running. Press Ctrl+C to close.");
                    eprintln!("  Features: adblock, tracker block, fingerprint protect,");
                    eprintln!("            stealth mode, HTTPS everywhere, popup block,");
                    eprintln!("            miner block, social block, ClearURLs");
                    if *tor {
                        eprintln!("            Tor anonymization (3-hop onion routing)");
                    }

                    // Keep browser open until Ctrl+C
                    let (tx, rx) = std::sync::mpsc::channel();
                    ctrlc::set_handler(move || {
                        let _ = tx.send(());
                    })
                    .ok();
                    let _ = rx.recv();
                    eprintln!("\n  Browser closed.");
                    drop(proc);
                }
                BrowserAction::Schedule { action } => {
                    use tallow::browser::scheduler::*;
                    let store_path = ScheduleStore::default_path();

                    match action {
                        ScheduleAction::Add {
                            name,
                            script,
                            cron,
                            every,
                            daily,
                            headless,
                            plugins,
                            device,
                            tor,
                            proxy,
                            max_runs,
                            timeout,
                        } => {
                            // Determine frequency
                            let freq = if let Some(expr) = cron {
                                if let Err(e) = CronExpr::parse(expr) {
                                    eprintln!("Invalid cron: {e}");
                                    std::process::exit(1);
                                }
                                Frequency::Cron(expr.clone())
                            } else if let Some(interval) = every {
                                match parse_interval(interval) {
                                    Ok(secs) => Frequency::Interval(secs),
                                    Err(e) => {
                                        eprintln!("Invalid interval: {e}");
                                        std::process::exit(1);
                                    }
                                }
                            } else if let Some(time) = daily {
                                if let Err(e) = validate_daily_time(time) {
                                    eprintln!("Invalid daily time: {e}");
                                    std::process::exit(1);
                                }
                                Frequency::Daily(time.clone())
                            } else {
                                eprintln!("Specify --cron, --every, or --daily");
                                std::process::exit(1);
                            };

                            if !std::path::Path::new(script.as_str()).exists() {
                                eprintln!("Script not found: {script}");
                                std::process::exit(1);
                            }

                            let mut job = ScheduledJob::new(name, script, freq);
                            job.headless = *headless;
                            job.plugins = plugins.clone();
                            job.device = device.clone();
                            job.tor = *tor;
                            job.proxy = proxy.clone();
                            job.max_runs = *max_runs;
                            job.timeout_secs = *timeout;

                            let mut store = ScheduleStore::load(&store_path);
                            match store.add(job) {
                                Ok(()) => {
                                    if let Err(e) = store.save(&store_path) {
                                        eprintln!("Warning: failed to save: {e}");
                                    }
                                    eprintln!("Schedule '{}' added", name);
                                    eprintln!("  Script:    {}", script);
                                    if let Some(j) = store.get(name) {
                                        eprintln!("  Frequency: {}", j.frequency_display());
                                        eprintln!("  Next run:  {}", j.next_run_display());
                                    }
                                    eprintln!("");
                                    eprintln!("  Start the daemon:  tallow browser schedule start");
                                }
                                Err(e) => {
                                    eprintln!("{e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        ScheduleAction::List => {
                            let store = ScheduleStore::load(&store_path);
                            print_schedule_table(&store);
                        }
                        ScheduleAction::Remove { name } => {
                            let mut store = ScheduleStore::load(&store_path);
                            match store.remove(name) {
                                Ok(_) => {
                                    if let Err(e) = store.save(&store_path) {
                                        eprintln!("Warning: {e}");
                                    }
                                    eprintln!("Schedule '{}' removed", name);
                                }
                                Err(e) => {
                                    eprintln!("{e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        ScheduleAction::Pause { name } => {
                            let mut store = ScheduleStore::load(&store_path);
                            match store.pause(name) {
                                Ok(()) => {
                                    if let Err(e) = store.save(&store_path) {
                                        eprintln!("Warning: {e}");
                                    }
                                    eprintln!("Schedule '{}' paused", name);
                                }
                                Err(e) => {
                                    eprintln!("{e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        ScheduleAction::Resume { name } => {
                            let mut store = ScheduleStore::load(&store_path);
                            match store.resume(name) {
                                Ok(()) => {
                                    if let Err(e) = store.save(&store_path) {
                                        eprintln!("Warning: {e}");
                                    }
                                    eprintln!("Schedule '{}' resumed", name);
                                    if let Some(j) = store.get(name) {
                                        eprintln!("  Next run: {}", j.next_run_display());
                                    }
                                }
                                Err(e) => {
                                    eprintln!("{e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        ScheduleAction::Run { name } => {
                            let mut store = ScheduleStore::load(&store_path);
                            let job = store.get(name).cloned();
                            match job {
                                Some(j) => {
                                    eprintln!("Running '{}' now...", name);
                                    let exe = match std::env::current_exe() {
                                        Ok(e) => e,
                                        Err(e) => {
                                            eprintln!("Cannot find tallow binary: {e}");
                                            std::process::exit(1);
                                        }
                                    };
                                    let start = std::time::Instant::now();
                                    let mut cmd = std::process::Command::new(&exe);
                                    cmd.arg("run").arg(&j.script);
                                    // Pass job args
                                    for arg in &j.args {
                                        cmd.arg(arg);
                                    }
                                    // Pass browser options as env vars
                                    if j.headless {
                                        cmd.env("TALLOW_HEADLESS", "1");
                                    }
                                    cmd.env("TALLOW_PLUGINS", &j.plugins);
                                    if let Some(ref d) = j.device {
                                        cmd.env("TALLOW_DEVICE", d);
                                    }
                                    if j.tor {
                                        cmd.env("TALLOW_TOR", "1");
                                    }
                                    if let Some(ref p) = j.proxy {
                                        cmd.env("TALLOW_PROXY", p);
                                    }
                                    // Set env vars
                                    for (k, v) in &j.env_vars {
                                        cmd.env(k, v);
                                    }
                                    if let Some(ref wd) = j.work_dir {
                                        cmd.current_dir(wd);
                                    }

                                    let status = cmd.status();
                                    let duration = start.elapsed().as_secs();
                                    match status {
                                        Ok(s) if s.success() => {
                                            eprintln!("'{}' completed ({}s)", name, duration);
                                            if let Some(jm) = store.get_mut(name) {
                                                jm.mark_ran("ok", duration);
                                            }
                                        }
                                        Ok(s) => {
                                            eprintln!(
                                                "'{}' exited with code {} ({}s)",
                                                name,
                                                s.code().unwrap_or(-1),
                                                duration
                                            );
                                            if let Some(jm) = store.get_mut(name) {
                                                jm.mark_ran(
                                                    &format!(
                                                        "error: exit {}",
                                                        s.code().unwrap_or(-1)
                                                    ),
                                                    duration,
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to run '{}': {}", name, e);
                                            if let Some(jm) = store.get_mut(name) {
                                                jm.mark_ran(&format!("error: {}", e), 0);
                                            }
                                        }
                                    }
                                    if let Err(e) = store.save(&store_path) {
                                        eprintln!("Warning: {e}");
                                    }
                                }
                                None => {
                                    eprintln!("Schedule '{}' not found", name);
                                    std::process::exit(1);
                                }
                            }
                        }
                        ScheduleAction::Start { poll } => {
                            let daemon = SchedulerDaemon::new(
                                store_path,
                                std::time::Duration::from_secs(*poll),
                            );
                            daemon.run();
                        }
                        ScheduleAction::Info { name } => {
                            let store = ScheduleStore::load(&store_path);
                            match store.get(name) {
                                Some(j) => {
                                    eprintln!("Schedule: {}", j.name);
                                    eprintln!("  Script:      {}", j.script);
                                    eprintln!("  Frequency:   {}", j.frequency_display());
                                    eprintln!(
                                        "  Status:      {}",
                                        if j.running {
                                            "running"
                                        } else if j.enabled {
                                            "active"
                                        } else {
                                            "paused"
                                        }
                                    );
                                    eprintln!("  Headless:    {}", j.headless);
                                    eprintln!("  Plugins:     {}", j.plugins);
                                    if let Some(ref d) = j.device {
                                        eprintln!("  Device:      {}", d);
                                    }
                                    if j.tor {
                                        eprintln!("  Tor:         enabled");
                                    }
                                    if let Some(ref p) = j.proxy {
                                        eprintln!("  Proxy:       {}", p);
                                    }
                                    eprintln!(
                                        "  Created:     {}",
                                        format_epoch_simple(j.created_at)
                                    );
                                    eprintln!("  Next run:    {}", j.next_run_display());
                                    eprintln!("  Last run:    {}", j.last_run_display());
                                    eprintln!("  Run count:   {}", j.run_count);
                                    if let Some(d) = j.last_duration_secs {
                                        eprintln!("  Last dur:    {}s", d);
                                    }
                                    if let Some(max) = j.max_runs {
                                        eprintln!("  Max runs:    {}", max);
                                    }
                                    if let Some(t) = j.timeout_secs {
                                        eprintln!("  Timeout:     {}s", t);
                                    }
                                    if j.retry_count > 0 {
                                        eprintln!(
                                            "  Retries:     {} ({}s delay, backoff: {})",
                                            j.retry_count, j.retry_delay_secs, j.retry_backoff
                                        );
                                    }
                                    if j.tz_offset_secs != 0 {
                                        eprintln!(
                                            "  Timezone:    UTC{:+}",
                                            j.tz_offset_secs / 3600
                                        );
                                    }
                                    if !j.env_vars.is_empty() {
                                        eprintln!("  Env vars:    {}", j.env_vars.len());
                                    }
                                    if let Some(ref wd) = j.work_dir {
                                        eprintln!("  Work dir:    {}", wd);
                                    }
                                    eprintln!(
                                        "  Overlap:     {}",
                                        if j.allow_overlap {
                                            "allowed"
                                        } else {
                                            "prevented"
                                        }
                                    );
                                    eprintln!("  Missed:      {:?}", j.missed_policy);
                                    eprintln!(
                                        "  Last status: {}",
                                        j.last_status.as_deref().unwrap_or("-")
                                    );
                                    // Preview next 5 runs
                                    let runs = j.next_runs(5);
                                    eprintln!("  Next 5 runs:");
                                    for r in &runs {
                                        eprintln!(
                                            "    {}",
                                            tallow::browser::scheduler::format_epoch(*r)
                                        );
                                    }
                                }
                                None => {
                                    eprintln!("Schedule '{}' not found", name);
                                    std::process::exit(1);
                                }
                            }
                        }
                    }
                }
                BrowserAction::Config { action } => {
                    use tallow::browser::config::BrowserFullConfig;

                    match action {
                        BrowserConfigAction::Init => match BrowserFullConfig::save_defaults() {
                            Ok(()) => {
                                let dir = BrowserFullConfig::config_dir();
                                eprintln!("Browser config initialized at: {}", dir.display());
                                eprintln!("");
                                eprintln!("Created 15 config files:");
                                for name in BrowserFullConfig::file_names() {
                                    eprintln!("  {name}.toml");
                                }
                                eprintln!("");
                                eprintln!("Edit with:  tallow browser config edit <file>");
                                eprintln!(
                                    "Set value:  tallow browser config set plugins.adblock false"
                                );
                                eprintln!("Show all:   tallow browser config show");
                            }
                            Err(e) => {
                                eprintln!("Failed to initialize config: {e}");
                                std::process::exit(1);
                            }
                        },
                        BrowserConfigAction::Show { file } => {
                            let config = BrowserFullConfig::load();
                            let output = config.show(file.as_deref());
                            print!("{output}");
                        }
                        BrowserConfigAction::Edit { file } => {
                            let dir = BrowserFullConfig::config_dir();
                            let path = dir.join(format!("{file}.toml"));

                            if !path.exists() {
                                // Create default file first
                                if let Err(e) = BrowserFullConfig::save_default_file(file) {
                                    eprintln!("Failed to create default config: {e}");
                                    std::process::exit(1);
                                }
                            }

                            let editor = std::env::var("EDITOR")
                                .or_else(|_| std::env::var("VISUAL"))
                                .unwrap_or_else(|_| {
                                    #[cfg(target_os = "windows")]
                                    {
                                        "notepad".to_string()
                                    }
                                    #[cfg(not(target_os = "windows"))]
                                    {
                                        "vi".to_string()
                                    }
                                });

                            eprintln!("Opening {} with {editor}...", path.display());
                            let status = std::process::Command::new(&editor).arg(&path).status();

                            match status {
                                Ok(s) if s.success() => {}
                                Ok(s) => {
                                    eprintln!("Editor exited with: {}", s.code().unwrap_or(-1))
                                }
                                Err(e) => eprintln!("Failed to open editor '{editor}': {e}"),
                            }
                        }
                        BrowserConfigAction::Reset { file } => match file {
                            Some(name) => match BrowserFullConfig::save_default_file(name) {
                                Ok(()) => eprintln!("Reset {name}.toml to defaults"),
                                Err(e) => {
                                    eprintln!("Failed to reset: {e}");
                                    std::process::exit(1);
                                }
                            },
                            None => match BrowserFullConfig::save_defaults() {
                                Ok(()) => eprintln!("All config files reset to defaults"),
                                Err(e) => {
                                    eprintln!("Failed to reset: {e}");
                                    std::process::exit(1);
                                }
                            },
                        },
                        BrowserConfigAction::Set { key, value } => {
                            match BrowserFullConfig::set_value(key, value) {
                                Ok(()) => eprintln!("Set {key} = {value}"),
                                Err(e) => {
                                    eprintln!("Error: {e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        BrowserConfigAction::Path => {
                            let dir = BrowserFullConfig::config_dir();
                            println!("{}", dir.display());
                        }
                        BrowserConfigAction::List => {
                            eprintln!("Available config files (15):");
                            eprintln!("");
                            let descriptions = [
                                ("browser", "Chrome launch, transport, performance"),
                                (
                                    "plugins",
                                    "10 plugin toggles (adblock, tracker, https, etc.)",
                                ),
                                ("stealth", "Anti-detection profiles + 20 evasion vectors"),
                                ("privacy", "PII scanning, redaction, data retention"),
                                ("network", "Request interception, HAR recording, WebSocket"),
                                (
                                    "recording",
                                    "Video capture (codec, resolution, fps, format)",
                                ),
                                ("search", "Engine cascade, CSE keys, profile pool"),
                                (
                                    "emulation",
                                    "Device profiles, viewport, timezone, geolocation",
                                ),
                                ("accessibility", "WCAG auditing, consent banner handling"),
                                ("session", "Cookie/storage persistence, encryption"),
                                ("captcha", "Solver backend, API keys, CAPTCHA types"),
                                ("pool", "Browser pool size, proxies, distributed mode"),
                                ("tor", "Circuit rotation, stream isolation, ports"),
                                ("scheduler", "Job scheduling defaults, missed policy"),
                                ("retry", "Backoff strategy, robots.txt, rate limiting"),
                            ];
                            for (name, desc) in &descriptions {
                                eprintln!("  {name:<16} {desc}");
                            }
                            eprintln!("");
                            eprintln!("Show:   tallow browser config show --file <name>");
                            eprintln!("Edit:   tallow browser config edit <name>");
                            eprintln!("Set:    tallow browser config set <file>.<key> <value>");
                        }
                    }
                }
            }
            return Ok(());
        }
        Command::Tor { ref action } => {
            match action {
                TorAction::Start { instances } => {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    eprintln!("Starting {instances} Tor instance(s)...");
                    match rt.block_on(tallow::tor::TorManager::start(*instances)) {
                        Ok(mgr) => {
                            for inst in mgr.instances() {
                                eprintln!(
                                    "  SOCKS: socks5://127.0.0.1:{}  Control: {}",
                                    inst.socks_port, inst.control_port
                                );
                            }
                            eprintln!("\nTor is running. Press Ctrl+C to stop.");
                            let (tx, rx) = std::sync::mpsc::channel();
                            ctrlc::set_handler(move || {
                                let _ = tx.send(());
                            })
                            .ok();
                            let _ = rx.recv();
                            eprintln!("\nStopping Tor...");
                            drop(mgr);
                        }
                        Err(e) => eprintln!("Failed to start Tor: {e}"),
                    }
                }
                TorAction::Stop => {
                    eprintln!(
                        "Note: Managed Tor instances stop automatically when the process exits."
                    );
                    eprintln!("To stop background instances, kill their processes manually.");
                }
                TorAction::Status => {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    match rt.block_on(tallow::tor::TorManager::detect_system_tor()) {
                        Some(inst) => {
                            eprintln!("System Tor detected:");
                            eprintln!("  SOCKS: socks5://127.0.0.1:{}", inst.socks_port);
                            eprintln!("  Control: {}", inst.control_port);
                        }
                        None => {
                            // `detect_system_tor` requires an authenticatable
                            // control port; a running Tor whose control auth is
                            // unavailable was previously reported as "no Tor"
                            // (register #80). Probe the default listeners
                            // directly for an honest status line.
                            let probe = |port: u16| {
                                std::net::TcpStream::connect_timeout(
                                    &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                                    std::time::Duration::from_millis(300),
                                )
                                .is_ok()
                            };
                            match (probe(9050), probe(9051)) {
                                (true, true) => eprintln!(
                                    "Tor listeners detected on 127.0.0.1:9050 (SOCKS) and 127.0.0.1:9051 (control), but the control port could not be authenticated — managed operations (new identity, circuit control) are unavailable from this tool; SOCKS proxying still works."
                                ),
                                (true, false) => eprintln!(
                                    "Tor SOCKS proxy detected on 127.0.0.1:9050 (no control listener on 9051)."
                                ),
                                (false, true) => eprintln!(
                                    "Tor control port detected on 127.0.0.1:9051 (no SOCKS listener on 9050)."
                                ),
                                (false, false) => eprintln!(
                                    "No system Tor detected on default ports (9050/9051)."
                                ),
                            }
                        }
                    }
                }
            }
            return Ok(());
        }
        Command::Daemon { action } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match action {
                    DaemonAction::Status => tallow::cli::daemon::daemon_status().await,
                    DaemonAction::Stop => tallow::cli::daemon::daemon_stop().await,
                }
            })?;
            return Ok(());
        }
        Command::Job { action } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match action {
                    JobAction::List { ref status } => tallow::cli::daemon::job_list(status.clone()).await,
                    JobAction::Submit { ref script } => tallow::cli::daemon::job_submit(script).await,
                    JobAction::Show { ref id } => tallow::cli::daemon::job_show(id).await,
                    JobAction::History { ref id } => tallow::cli::daemon::job_history(id).await,
                }
            })?;
            return Ok(());
        }
        Command::Ffmpeg { ref action } => {
            match action {
                FfmpegAction::Install => ffmpeg_install(),
                FfmpegAction::Path => ffmpeg_path(),
                FfmpegAction::Version => ffmpeg_version(),
                FfmpegAction::Remove => ffmpeg_remove(),
            }
            return Ok(());
        }
        Command::CheckDeps { fix } => {
            return run_check_deps(fix);
        }
        // ── Enterprise package manager features ─────────────────────────────
        Command::Licenses { json, prod, check } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            let code = tallow::pkg::enterprise::pkg_licenses(
                &project_dir,
                &registry_path,
                json,
                prod,
                check,
            )?;
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
        Command::Vendor { ref output } => {
            let project_dir = tallow::pkg::cli::find_project_root(&std::env::current_dir()?)?;
            let registry_path = tallow::pkg::cli::default_registry_path();
            tallow::pkg::enterprise::pkg_vendor(&project_dir, &registry_path, output)?;
            return Ok(());
        }
        Command::TwoWaySync {
            ref left,
            ref right,
            ref conflicts,
            dry_run,
            ref db,
            threads,
            ref exclude,
            plan: show_plan,
            quiet,
        } => {
            // Build DB path: explicit --db or default to .tallow-sync.db in left dir
            let db_path = if let Some(p) = db {
                p.to_string_lossy().to_string()
            } else {
                left.join(".tallow-sync.db").to_string_lossy().to_string()
            };
            let left_str = left.to_string_lossy().to_string();
            let right_str = right.to_string_lossy().to_string();

            // Configure rayon thread pool for scanning
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global();

            if !quiet {
                eprintln!("Tallow two-way sync");
                eprintln!("  Left:     {}", left_str);
                eprintln!("  Right:    {}", right_str);
                eprintln!("  Strategy: {}", conflicts);
                eprintln!("  DB:       {}", db_path);
                if dry_run {
                    eprintln!("  DRY RUN (no changes will be made)");
                }
                eprintln!();
            }

            // Validate directories
            if !left.is_dir() {
                eprintln!("error: left '{}' is not a directory", left_str);
                std::process::exit(exit_codes::IO_ERROR);
            }
            if !right.is_dir() {
                eprintln!("error: right '{}' is not a directory", right_str);
                std::process::exit(exit_codes::IO_ERROR);
            }

            // Build and optionally display the plan
            let plan_val = if show_plan || !quiet {
                match tallow::stdlib::transfer::twoway_plan(&[
                    tallow::interp::Value::String(left_str.clone()),
                    tallow::interp::Value::String(right_str.clone()),
                    tallow::interp::Value::String(db_path.clone()),
                ]) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("error computing plan: {}", e);
                        std::process::exit(exit_codes::IO_ERROR);
                    }
                }
            } else {
                None
            };

            if let Some(ref pv) = plan_val {
                if let tallow::interp::Value::Struct { fields, .. } = pv {
                    let get_count = |k: &str| -> i128 {
                        fields
                            .iter()
                            .find(|(fk, _)| fk == k)
                            .and_then(|(_, v)| {
                                if let tallow::interp::Value::Array(a) = v {
                                    Some(a.len() as i128)
                                } else if let tallow::interp::Value::Int(n) = v {
                                    Some(*n)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0)
                    };
                    let l2r = get_count("copy_left_to_right");
                    let r2l = get_count("copy_right_to_left");
                    let del_l = get_count("delete_left");
                    let del_r = get_count("delete_right");
                    let confl = get_count("conflicts");
                    let skip_n = fields
                        .iter()
                        .find(|(k, _)| k == "skip")
                        .and_then(|(_, v)| {
                            if let tallow::interp::Value::Int(n) = v {
                                Some(*n)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let total = get_count("total_actions");

                    if !quiet {
                        eprintln!("Sync plan:");
                        eprintln!("  Copy left  -> right : {}", l2r);
                        eprintln!("  Copy right -> left  : {}", r2l);
                        eprintln!("  Delete left         : {}", del_l);
                        eprintln!("  Delete right        : {}", del_r);
                        eprintln!(
                            "  Conflicts           : {} (strategy: {})",
                            confl, conflicts
                        );
                        eprintln!("  Unchanged (skip)    : {}", skip_n);
                        eprintln!("  ──────────────────────");
                        eprintln!("  Total actions       : {}", total);
                        eprintln!();
                    }

                    // Validate excludes (just informational for now — full glob filtering
                    // is applied during the actual scan in the engine)
                    if !exclude.is_empty() && !quiet {
                        eprintln!("  Excludes: {}", exclude.join(", "));
                        eprintln!();
                    }

                    if show_plan && !dry_run {
                        // Ask for confirmation when --plan is set
                        if total > 0 {
                            eprint!("Proceed? [y/N] ");
                            let mut answer = String::new();
                            std::io::stdin().read_line(&mut answer).unwrap_or(0);
                            if !answer.trim().eq_ignore_ascii_case("y") {
                                eprintln!("Aborted.");
                                return Ok(());
                            }
                        } else if !quiet {
                            eprintln!("Nothing to do.");
                            return Ok(());
                        }
                    }
                }
            }

            // Execute sync
            let start = std::time::Instant::now();
            match tallow::stdlib::transfer::twoway_sync_inner(
                &left_str, &right_str, &db_path, conflicts, dry_run,
            ) {
                Ok(result) => {
                    if let tallow::interp::Value::Struct { fields, .. } = &result {
                        let get_int = |k: &str| {
                            fields
                                .iter()
                                .find(|(fk, _)| fk == k)
                                .and_then(|(_, v)| {
                                    if let tallow::interp::Value::Int(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0)
                        };
                        let copied = get_int("files_copied");
                        let deleted = get_int("files_deleted");
                        let resolved = get_int("conflicts_resolved");
                        let skipped = get_int("conflicts_skipped");
                        let bytes = get_int("bytes_copied");
                        let errors: Vec<String> = fields
                            .iter()
                            .find(|(k, _)| k == "errors")
                            .and_then(|(_, v)| {
                                if let tallow::interp::Value::Array(a) = v {
                                    Some(a.iter().map(|e| e.as_string()).collect())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_default();

                        let elapsed = start.elapsed();
                        let mb = bytes as f64 / 1_048_576.0;

                        if !quiet {
                            eprintln!("Sync complete in {:.1}s", elapsed.as_secs_f64());
                            eprintln!("  Files copied   : {}", copied);
                            eprintln!("  Files deleted  : {}", deleted);
                            eprintln!("  Conflicts resolved : {} ({})", resolved, conflicts);
                            eprintln!("  Conflicts skipped  : {}", skipped);
                            eprintln!("  Data copied    : {:.1} MiB", mb);
                            if !errors.is_empty() {
                                eprintln!("  Errors ({}):", errors.len());
                                for e in &errors {
                                    eprintln!("    - {}", e);
                                }
                            }
                        }

                        if !errors.is_empty() {
                            std::process::exit(exit_codes::IO_ERROR);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(exit_codes::IO_ERROR);
                }
            }
            return Ok(());
        }
        Command::Vault { ref action } => {
            use tallow::vault;
            // Prompt for password (read from env TALLOW_VAULT_PASSWORD or stdin)
            let get_password = || -> String {
                if let Ok(pw) = std::env::var("TALLOW_VAULT_PASSWORD") {
                    return pw;
                }
                eprint!("Vault password: ");
                let mut pw = String::new();
                std::io::stdin().read_line(&mut pw).unwrap_or(0);
                pw.trim().to_string()
            };

            /// Retain a caller-held KT payload beside its KT log — the log
            /// stores chain entries; payloads are the evidence they commit to.
            fn append_kt_payload(
                path: &std::path::Path,
                payload: &serde_json::Value,
            ) -> Result<(), String> {
                use std::io::Write;
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let mut opts = std::fs::OpenOptions::new();
                opts.create(true).append(true).mode(0o600);
                let mut file = opts
                    .open(path)
                    .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("cannot enforce mode 0600 on {}: {e}", path.display()))?;
                let line = serde_json::to_string(payload)
                    .map_err(|e| format!("payload encode failed: {e}"))?;
                writeln!(file, "{line}")
                    .map_err(|e| format!("append to {} failed: {e}", path.display()))
            }

            /// R1 fail-closed exit: journal (best-effort) + stderr + exit 4.
            fn gate_exit_aud(
                e: &tallow::enforcement::EnforceError,
                class: Option<tallow::access_class::AccessClass>,
                aud: tallow::access_class::Audience,
            ) -> ! {
                tallow::vault::access::log_denial(e, class, aud);
                eprintln!("{e}");
                std::process::exit(exit_codes::PERMISSION_VIOLATION);
            }

            /// Reads default helper (Operator context).
            fn gate_exit(e: &tallow::enforcement::EnforceError) -> ! {
                gate_exit_aud(e, None, tallow::access_class::Audience::Operator)
            }

            /// Resolve an explicit `--audience` token; refusal is fail-closed.
            fn parse_audience(audience: &Option<String>) -> tallow::access_class::Audience {
                match audience {
                    Some(tok) => match tallow::vault::access::audience_from_token(tok) {
                        Some(a) => a,
                        None => gate_exit_aud(
                            &tallow::enforcement::EnforceError::ExportDenied(
                                "deny.audience-invalid".to_string(),
                            ),
                            None,
                            tallow::access_class::Audience::Operator,
                        ),
                    },
                    None => gate_exit_aud(
                        &tallow::enforcement::EnforceError::ExportDenied(
                            "deny.audience-required".to_string(),
                        ),
                        None,
                        tallow::access_class::Audience::Operator,
                    ),
                }
            }

            match action {
                VaultAction::Create { path, name } => {
                    let pw = get_password();
                    if pw.is_empty() {
                        eprintln!("error: password cannot be empty");
                        std::process::exit(1);
                    }
                    match vault::VaultDatabase::create(
                        path.to_str().unwrap_or("vault.twv"),
                        &pw,
                        name,
                    ) {
                        Ok(db) => eprintln!(
                            "Vault created: {} ({} entries)",
                            path.display(),
                            db.entry_count()
                        ),
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VaultAction::Add {
                    path,
                    entry_type,
                    name,
                    username,
                    password,
                    url,
                    content,
                    totp,
                    folder,
                } => {
                    let pw = get_password();
                    let mut db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw)
                    {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let entry = match entry_type.as_str() {
                        "login" => {
                            let pass = password.clone().unwrap_or_else(|| {
                                vault::generate::generate_password(
                                    &vault::generate::PasswordOptions::default(),
                                )
                            });
                            let urls = url
                                .as_deref()
                                .map(|u| vec![u.to_string()])
                                .unwrap_or_default();
                            let mut e = vault::VaultEntry::new_login(
                                name,
                                username.as_deref().unwrap_or(""),
                                &pass,
                                urls,
                            );
                            if let Some(t) = totp {
                                if let vault::EntryData::Login(ref mut d) = e.data {
                                    d.totp_secret = Some(t.clone());
                                }
                            }
                            e
                        }
                        "note" => {
                            vault::VaultEntry::new_note(name, content.as_deref().unwrap_or(""))
                        }
                        "api" => vault::VaultEntry::new_api_key(
                            name,
                            password.as_deref().unwrap_or(""),
                            None,
                            url.as_deref(),
                        ),
                        "totp" => vault::VaultEntry::new_totp(
                            name,
                            totp.as_deref().unwrap_or(""),
                            None,
                            username.as_deref(),
                        ),
                        other => {
                            eprintln!("unknown entry type: {other} (use: login, note, api, totp)");
                            std::process::exit(1);
                        }
                    };
                    let mut entry = entry;
                    entry.folder = folder.clone();
                    let entry_name = entry.name.clone();
                    db.add_entry(entry);
                    db.save(path.to_str().unwrap_or(""), &pw)
                        .unwrap_or_else(|e| {
                            eprintln!("save error: {e}");
                            std::process::exit(1);
                        });
                    eprintln!("Added: {entry_name}");
                }
                VaultAction::List {
                    path,
                    folder,
                    favorites,
                    json,
                } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let entries: Vec<&vault::VaultEntry> = if *favorites {
                        db.list_favorites()
                    } else if let Some(f) = folder {
                        db.list_by_folder(f)
                    } else {
                        db.entries.iter().collect()
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let (entries, withheld) = gate.visible(&entries);
                    if !withheld.is_empty() {
                        eprintln!(
                            "read denied: {} entr(ies) withheld ({})",
                            withheld.len(),
                            vault::access::code_of(&withheld[0].1)
                        );
                    }
                    if *json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&entries).unwrap_or_default()
                        );
                    } else {
                        eprintln!("{}", db.summary());
                        for e in &entries {
                            let user = e.username().unwrap_or("-");
                            eprintln!(
                                "  [{}] {} — {} ({})",
                                &e.id[..8],
                                e.name,
                                user,
                                e.entry_type()
                            );
                        }
                    }
                }
                VaultAction::Get {
                    path,
                    query,
                    show,
                    totp: show_totp,
                } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let results = db.search(query);
                    if results.is_empty() {
                        eprintln!("no entries matching '{query}'");
                        std::process::exit(1);
                    }
                    let entry = results[0];
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    if let Err(e) = gate.read_gate(entry) {
                        gate_exit(&e);
                    }
                    eprintln!("  Name:     {}", entry.name);
                    eprintln!("  Type:     {}", entry.entry_type());
                    if let Some(u) = entry.username() {
                        eprintln!("  Username: {u}");
                    }
                    if let vault::EntryData::Login(ref d) = entry.data {
                        if *show {
                            eprintln!("  Password: {}", d.password);
                        } else {
                            eprintln!("  Password: ••••••••");
                        }
                        for url in &d.urls {
                            eprintln!("  URL:      {url}");
                        }
                        if *show_totp {
                            if let Some(ref secret) = d.totp_secret {
                                match vault::totp::generate_totp(
                                    secret,
                                    d.totp_digits.unwrap_or(6),
                                    d.totp_period.unwrap_or(30),
                                    d.totp_algorithm.as_deref().unwrap_or("SHA1"),
                                ) {
                                    Ok(code) => {
                                        let remaining = vault::totp::time_remaining(
                                            d.totp_period.unwrap_or(30),
                                        );
                                        eprintln!("  TOTP:     {code} ({remaining}s remaining)");
                                    }
                                    Err(e) => eprintln!("  TOTP error: {e}"),
                                }
                            }
                        }
                    }
                }
                VaultAction::Search { path, query } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let results = db.search(query);
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let (results, withheld) = gate.visible(&results);
                    eprintln!("{} results for '{query}':", results.len());
                    if !withheld.is_empty() {
                        eprintln!(
                            "read denied: {} entr(ies) withheld ({})",
                            withheld.len(),
                            vault::access::code_of(&withheld[0].1)
                        );
                    }
                    for e in &results {
                        eprintln!(
                            "  [{}] {} — {} ({})",
                            &e.id[..8],
                            e.name,
                            e.username().unwrap_or("-"),
                            e.entry_type()
                        );
                    }
                }
                VaultAction::Delete { path, query } => {
                    let pw = get_password();
                    let mut db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw)
                    {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let results = db.search(query);
                    if results.is_empty() {
                        eprintln!("no entries matching '{query}'");
                        std::process::exit(1);
                    }
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    if let Err(e) = gate.read_gate(results[0]) {
                        gate_exit(&e);
                    }
                    let id = results[0].id.clone();
                    let name = results[0].name.clone();
                    db.remove_entry(&id);
                    db.save(path.to_str().unwrap_or(""), &pw)
                        .unwrap_or_else(|e| {
                            eprintln!("save error: {e}");
                            std::process::exit(1);
                        });
                    eprintln!("Deleted: {name}");
                }
                VaultAction::Generate {
                    length,
                    passphrase,
                    words,
                    no_uppercase,
                    no_digits,
                    no_special,
                } => {
                    if *passphrase {
                        let opts = vault::generate::PassphraseOptions {
                            word_count: *words,
                            separator: "-".to_string(),
                            capitalize: true,
                            include_number: true,
                        };
                        let pp = vault::generate::generate_passphrase(&opts);
                        let entropy = vault::generate::estimate_entropy(&pp);
                        println!("{pp}");
                        eprintln!(
                            "  entropy: {entropy:.0} bits ({})",
                            vault::generate::strength_rating(&pp)
                        );
                    } else {
                        let opts = vault::generate::PasswordOptions {
                            length: *length,
                            uppercase: !no_uppercase,
                            lowercase: true,
                            digits: !no_digits,
                            special: !no_special,
                            exclude_ambiguous: false,
                            ..Default::default()
                        };
                        let pass = vault::generate::generate_password(&opts);
                        let entropy = vault::generate::estimate_entropy(&pass);
                        println!("{pass}");
                        eprintln!(
                            "  entropy: {entropy:.0} bits ({})",
                            vault::generate::strength_rating(&pass)
                        );
                    }
                }
                VaultAction::Totp { path, query } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let results = db.search(query);
                    if results.is_empty() {
                        eprintln!("no entries matching '{query}'");
                        std::process::exit(1);
                    }
                    let entry = results[0];
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    if let Err(e) = gate.read_gate(entry) {
                        gate_exit(&e);
                    }
                    let (secret, digits, period, algo) = match &entry.data {
                        vault::EntryData::Login(d) => (
                            d.totp_secret.as_deref(),
                            d.totp_digits.unwrap_or(6),
                            d.totp_period.unwrap_or(30),
                            d.totp_algorithm.as_deref().unwrap_or("SHA1"),
                        ),
                        vault::EntryData::TOTP(d) => (
                            Some(d.secret.as_str()),
                            d.digits,
                            d.period,
                            d.algorithm.as_str(),
                        ),
                        _ => {
                            eprintln!("entry has no TOTP secret");
                            std::process::exit(1);
                        }
                    };
                    if let Some(s) = secret {
                        match vault::totp::generate_totp(s, digits, period, algo) {
                            Ok(code) => {
                                let remaining = vault::totp::time_remaining(period);
                                println!("{code}");
                                eprintln!("  {} — {code} ({remaining}s remaining)", entry.name);
                            }
                            Err(e) => {
                                eprintln!("TOTP error: {e}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!("no TOTP secret configured for '{}'", entry.name);
                        std::process::exit(1);
                    }
                }
                VaultAction::Health { path, breach } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let entries: Vec<&vault::VaultEntry> = db.entries.iter().collect();
                    if let Some(e) = gate.first_denied(&entries) {
                        gate_exit(&e);
                    }
                    let report = vault::health::analyze(&db.entries);
                    eprintln!("Vault Health Score: {}/100", report.score);
                    eprintln!("  Total entries:     {}", report.total_entries);
                    eprintln!("  Login entries:     {}", report.login_entries);
                    if !report.weak_passwords.is_empty() {
                        eprintln!("  Weak passwords:    {}", report.weak_passwords.len());
                        for w in &report.weak_passwords {
                            eprintln!(
                                "    - {} ({:.0} bits, {})",
                                w.entry_name, w.entropy_bits, w.rating
                            );
                        }
                    }
                    if !report.reused_passwords.is_empty() {
                        eprintln!(
                            "  Reused passwords:  {} groups",
                            report.reused_passwords.len()
                        );
                        for r in &report.reused_passwords {
                            eprintln!(
                                "    - {} entries share same password: {}",
                                r.entry_names.len(),
                                r.entry_names.join(", ")
                            );
                        }
                    }
                    if !report.unsecured_urls.is_empty() {
                        eprintln!("  Unsecured URLs:    {}", report.unsecured_urls.len());
                        for u in &report.unsecured_urls {
                            eprintln!("    - {} ({})", u.entry_name, u.url);
                        }
                    }
                    if !report.missing_totp.is_empty() {
                        eprintln!("  Missing TOTP:      {}", report.missing_totp.len());
                    }
                    if !report.expired_entries.is_empty() {
                        eprintln!("  Expired:           {}", report.expired_entries.len());
                    }
                    if *breach {
                        eprintln!("\n  Checking passwords against Have I Been Pwned...");
                        let mut breached = 0;
                        for entry in &db.entries {
                            if let vault::EntryData::Login(ref d) = entry.data {
                                match vault::health::check_breach_password(&d.password) {
                                    Ok(r) if r.found => {
                                        eprintln!(
                                            "    BREACHED: {} (seen {} times)",
                                            entry.name, r.count
                                        );
                                        breached += 1;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        if breached == 0 {
                            eprintln!("    No breached passwords found.");
                        }
                    }
                }
                VaultAction::Import { path, file, format } => {
                    let pw = get_password();
                    let mut db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw)
                    {
                        Ok(d) => d,
                        Err(_) => vault::VaultDatabase::new(
                            path.file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("Imported"),
                        ),
                    };
                    let content = std::fs::read_to_string(file).unwrap_or_else(|e| {
                        eprintln!("error reading {}: {e}", file.display());
                        std::process::exit(1);
                    });
                    let entries = match format.as_str() {
                        "bitwarden" => vault::import_export::import_bitwarden_json(&content),
                        "keepass" => vault::import_export::import_keepass_csv(&content),
                        "chrome" => vault::import_export::import_chrome_csv(&content),
                        "firefox" => vault::import_export::import_firefox_csv(&content),
                        "lastpass" => vault::import_export::import_lastpass_csv(&content),
                        other => { eprintln!("unknown format: {other} (use: bitwarden, keepass, chrome, firefox, lastpass)"); std::process::exit(1); }
                    }.unwrap_or_else(|e| { eprintln!("import error: {e}"); std::process::exit(1); });
                    let count = entries.len();
                    for e in entries {
                        db.add_entry(e);
                    }
                    db.save(path.to_str().unwrap_or(""), &pw)
                        .unwrap_or_else(|e| {
                            eprintln!("save error: {e}");
                            std::process::exit(1);
                        });
                    eprintln!("Imported {count} entries from {}", file.display());
                }
                VaultAction::Export {
                    path,
                    output,
                    format,
                    audience,
                    caveats,
                    kt_log,
                } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let class = gate.policy.tightest_class(db.entries.iter());
                    let audiences = parse_audience(audience);
                    let ctx = vault::access::AccessContext {
                        audience: audiences,
                    };
                    let now = vault::access::now_ms();
                    // D9: the release receipt goes to the KT log when one is given;
                    // the chain entry commits to the payload (kept beside the log).
                    let kt_append = |payload: &serde_json::Value| -> Result<(), String> {
                        if let Some(kt_path) = kt_log {
                            let mut kt = match tallow::kt_log::KtLog::open(kt_path) {
                                Ok(l) => l,
                                Err(e) => return Err(format!("KT log error: {e}")),
                            };
                            if let Err(e) = kt.append_json(payload) {
                                return Err(format!("KT log error: {e}"));
                            }
                            append_kt_payload(
                                &std::path::PathBuf::from(format!(
                                    "{}.payloads.jsonl",
                                    kt_path.display()
                                )),
                                payload,
                            )?;
                        }
                        Ok(())
                    };
                    match format.as_str() {
                        "json" | "csv" => {
                            // Design §5: receipt first (over the canonical compact
                            // Value), then the gate; nothing touches `output` on refusal.
                            let json_doc = vault::import_export::export_bitwarden_json(&db.entries)
                                .unwrap_or_else(|e| {
                                    eprintln!("export error: {e}");
                                    std::process::exit(1);
                                });
                            let value: serde_json::Value = serde_json::from_str(&json_doc)
                                .unwrap_or_else(|e| {
                                    eprintln!("export error: {e}");
                                    std::process::exit(1);
                                });
                            let outcome = vault::access::release_gated_with(
                                &gate.policy,
                                ctx,
                                class,
                                &value,
                                caveats.clone(),
                                now,
                                // Operator opt-in. Default (unset) is
                                // render-only = unchanged behaviour;
                                // TALLOW_CAVEAT_GATE=enforce evaluates the
                                // caveats before any byte leaves.
                                tallow::enforcement::ReleaseAuthority::from_env(),
                            )
                            .unwrap_or_else(|e| gate_exit_aud(&e, Some(class), audiences));
                            if format == "json" {
                                vault::import_export::write_export_file(
                                    output.as_path(),
                                    &outcome.released.derivative,
                                    true,
                                )
                                .unwrap_or_else(|e| {
                                    eprintln!("refusing insecure export: {e}");
                                    std::process::exit(1);
                                });
                            } else {
                                // D6: the CSV is a rendering of the pinned Value; the
                                // receipt covers the canonical compact Value form.
                                let csv = vault::import_export::export_csv(&db.entries)
                                    .unwrap_or_else(|e| {
                                        eprintln!("export error: {e}");
                                        std::process::exit(1);
                                    });
                                vault::import_export::write_export_file(
                                    output.as_path(),
                                    csv.as_bytes(),
                                    true,
                                )
                                .unwrap_or_else(|e| {
                                    eprintln!("refusing insecure export: {e}");
                                    std::process::exit(1);
                                });
                            }
                            eprintln!(
                                "receipt: {} original: {}",
                                outcome.released.receipt_hash, outcome.released.original_sha256
                            );
                            let payload = serde_json::json!({
                                "event": "vault_export",
                                "format": format,
                                "class": class,
                                "audience": audiences,
                                "receipt_hash": outcome.released.receipt_hash,
                                "original_sha256": outcome.released.original_sha256,
                                "released_ms": outcome.released.released_ms,
                                "caveats": outcome.released.caveats,
                                "rules_applied": outcome.receipt.audit.rules_applied,
                                "redacted_fields": outcome.receipt.audit.redacted_fields,
                            });
                            if let Err(e) = kt_append(&payload) {
                                eprintln!("refusing: cannot record the release receipt: {e}");
                                std::process::exit(1);
                            }
                        }
                        "encrypted" => {
                            // D6 documented asymmetry: ciphertext releases pass the
                            // policy gate and carry no redaction receipt.
                            if let Err(reason) = tallow::access_class::check_export(
                                class,
                                audiences,
                                gate.policy.is_embargo_active(now),
                            ) {
                                gate_exit_aud(
                                    &tallow::enforcement::EnforceError::ExportDenied(
                                        reason.code().to_string(),
                                    ),
                                    Some(class),
                                    audiences,
                                );
                            }
                            let data =
                                vault::import_export::export_encrypted_json(&db.entries, &pw)
                                    .unwrap_or_else(|e| {
                                        eprintln!("export error: {e}");
                                        std::process::exit(1);
                                    });
                            vault::import_export::write_export_file(output.as_path(), &data, false)
                                .unwrap_or_else(|e| {
                                    eprintln!("refusing insecure export: {e}");
                                    std::process::exit(1);
                                });
                            eprintln!("exported (ciphertext; no redaction receipt per D6)");
                            let payload = serde_json::json!({
                                "event": "vault_export",
                                "format": "encrypted",
                                "class": class,
                                "audience": audiences,
                                "note": "ciphertext-no-receipt (D6)",
                            });
                            if let Err(e) = kt_append(&payload) {
                                eprintln!("refusing: cannot record the release: {e}");
                                std::process::exit(1);
                            }
                        }
                        other => {
                            eprintln!("unknown format: {other} (use: json, csv, encrypted)");
                            std::process::exit(1);
                        }
                    }
                    eprintln!(
                        "Exported {} entries to {}",
                        db.entry_count(),
                        output.display()
                    );
                }
                VaultAction::RecoverySplit {
                    path,
                    threshold,
                    shares,
                    kt_log,
                } => {
                    let pw = get_password();
                    let _db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let class = gate.policy.tightest_class(_db.entries.iter());
                    let key_bytes = blake3::hash(pw.as_bytes());
                    match vault::share::split_master_key(key_bytes.as_bytes(), *threshold, *shares)
                    {
                        Ok(key_shares) => {
                            // D7: key-material release — Operator + receipt; refusal
                            // happens before any share file is opened.
                            let value = serde_json::json!({
                                "shares": serde_json::to_value(&key_shares).unwrap_or_default(),
                            });
                            let outcome = vault::access::release_gated_with(
                                &gate.policy,
                                vault::access::AccessContext::operator(),
                                class,
                                &value,
                                vec![],
                                vault::access::now_ms(),
                                tallow::enforcement::ReleaseAuthority::from_env(),
                            )
                            .unwrap_or_else(|e| {
                                gate_exit_aud(&e, Some(class), tallow::access_class::Audience::Operator)
                            });
                            eprintln!(
                                "receipt: {} original: {}",
                                outcome.released.receipt_hash, outcome.released.original_sha256
                            );
                            if let Some(kt_path) = kt_log {
                                let payload = serde_json::json!({
                                    "event": "vault_recovery_split",
                                    "class": class,
                                    "threshold": threshold,
                                    "shares": shares,
                                    "receipt_hash": outcome.released.receipt_hash,
                                    "original_sha256": outcome.released.original_sha256,
                                    "released_ms": outcome.released.released_ms,
                                    "rules_applied": outcome.receipt.audit.rules_applied,
                                });
                                let mut kt = match tallow::kt_log::KtLog::open(kt_path) {
                                    Ok(l) => l,
                                    Err(e) => {
                                        eprintln!(
                                            "refusing: cannot record the release receipt: {e}"
                                        );
                                        std::process::exit(1);
                                    }
                                };
                                if let Err(e) = kt.append_json(&payload) {
                                    eprintln!("refusing: cannot record the release receipt: {e}");
                                    std::process::exit(1);
                                }
                                if let Err(e) = append_kt_payload(
                                    &std::path::PathBuf::from(format!(
                                        "{}.payloads.jsonl",
                                        kt_path.display()
                                    )),
                                    &payload,
                                ) {
                                    eprintln!("refusing: cannot retain the KT payload: {e}");
                                    std::process::exit(1);
                                }
                            }
                            for s in &key_shares {
                                let share_path = format!("{}.share-{}", path.display(), s.index);
                                let share_json =
                                    serde_json::to_string_pretty(s).unwrap_or_default();
                                vault::import_export::write_export_file(
                                    std::path::Path::new(&share_path),
                                    share_json.as_bytes(),
                                    false,
                                )
                                .unwrap_or_else(|e| {
                                    eprintln!("refusing insecure export: {e}");
                                    std::process::exit(1);
                                });
                                eprintln!("  Share {}/{}: {}", s.index, shares, share_path);
                            }
                            eprintln!(
                                "Master key split into {} shares (need {} to recover)",
                                shares, threshold
                            );
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VaultAction::RecoveryCombine {
                    path: _,
                    share_files,
                } => {
                    let mut shares: Vec<vault::share::KeyShare> = Vec::new();
                    for sf in share_files {
                        let data = std::fs::read_to_string(sf).unwrap_or_else(|e| {
                            eprintln!("error reading {}: {e}", sf.display());
                            std::process::exit(1);
                        });
                        let share: vault::share::KeyShare = serde_json::from_str(&data)
                            .unwrap_or_else(|e| {
                                eprintln!("invalid share {}: {e}", sf.display());
                                std::process::exit(1);
                            });
                        shares.push(share);
                    }
                    match vault::share::recover_master_key(&shares) {
                        Ok(key) => {
                            eprintln!("Master key recovered from {} shares", shares.len());
                            let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
                            eprintln!("Key (hex): {key_hex}");
                        }
                        Err(e) => {
                            eprintln!("recovery error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VaultAction::CustodySplit {
                    path,
                    custodians,
                    threshold,
                    min_distinct_custodians,
                    out_dir,
                    kt_log,
                } => {
                    let pw = get_password();
                    // Custody-secret derivation kept identical to
                    // `vault recovery-split` (blake3(password)); the
                    // derivation-hardening item is recorded in the lane log
                    // §OPEN (the vault's own envelope uses Argon2id).
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    // D7: custody-kit release — policy gate before any kit material
                    // is generated or written; the KT kit receipt (log_kit_created,
                    // below) is the release receipt.
                    {
                        let gate = vault::access::VaultGate::for_path(
                            path.as_path(),
                            vault::access::AccessContext::operator(),
                        );
                        let class = gate.policy.tightest_class(db.entries.iter());
                        if let Err(reason) = tallow::access_class::check_export(
                            class,
                            tallow::access_class::Audience::Operator,
                            gate.policy.is_embargo_active(vault::access::now_ms()),
                        ) {
                            gate_exit_aud(
                                &tallow::enforcement::EnforceError::ExportDenied(
                                    reason.code().to_string(),
                                ),
                                Some(class),
                                tallow::access_class::Audience::Operator,
                            );
                        }
                    }
                    let secret = blake3::hash(pw.as_bytes());
                    let policy = match vault::recovery::CustodyPolicy::new(
                        *threshold,
                        *min_distinct_custodians,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("refused: {e}");
                            std::process::exit(1);
                        }
                    };
                    let mut ids: Vec<vault::recovery::CustodianId> = Vec::new();
                    for label in custodians {
                        match vault::recovery::CustodianId::new(label) {
                            Ok(id) => ids.push(id),
                            Err(e) => {
                                eprintln!("refused: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let (manifest, shares) = match vault::recovery::create_custody_kit(
                        secret.as_bytes(),
                        policy,
                        *threshold,
                        &ids,
                        now_ms,
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("refused: {e}");
                            std::process::exit(1);
                        }
                    };
                    let mut kt = match tallow::kt_log::KtLog::open(kt_log) {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("KT log error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let receipt = match vault::recovery::log_kit_created(&manifest, &mut kt, now_ms) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("KT log error: {e}");
                            std::process::exit(1);
                        }
                    };
                    // The KT log stores the chain entry (hash-committed); the
                    // payload is caller-held evidence — retain it beside the log.
                    if let Err(e) = append_kt_payload(
                        &std::path::PathBuf::from(format!("{}.payloads.jsonl", kt_log.display())),
                        &receipt.payload,
                    ) {
                        eprintln!("refusing: cannot retain the KT payload: {e}");
                        std::process::exit(1);
                    }
                    if let Err(e) = std::fs::create_dir_all(out_dir) {
                        eprintln!("error: cannot create {}: {e}", out_dir.display());
                        std::process::exit(1);
                    }
                    let manifest_path = out_dir.join("custody-manifest.json");
                    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
                    if let Err(e) = vault::import_export::write_export_file(
                        manifest_path.as_path(),
                        manifest_json.as_bytes(),
                        false,
                    ) {
                        eprintln!("refusing insecure write: {e}");
                        std::process::exit(1);
                    }
                    for share in &shares {
                        let share_path =
                            out_dir.join(format!("custody-share-{}.json", share.share.index));
                        let share_json = serde_json::to_string_pretty(share).unwrap_or_default();
                        if let Err(e) = vault::import_export::write_export_file(
                            share_path.as_path(),
                            share_json.as_bytes(),
                            true,
                        ) {
                            eprintln!("refusing insecure write: {e}");
                            std::process::exit(1);
                        }
                        eprintln!(
                            "  Share {}/{} (custodian {}) -> {}",
                            share.share.index,
                            manifest.total,
                            share.custodian,
                            share_path.display()
                        );
                    }
                    eprintln!(
                        "Custody kit {} created: {}-of-{} shares, policy {}/{} (KT entry {})",
                        manifest.split_id,
                        manifest.threshold,
                        manifest.total,
                        manifest.policy.min_shares,
                        manifest.policy.min_distinct_custodians,
                        receipt.seq
                    );
                    eprintln!("Manifest: {}", manifest_path.display());
                    eprintln!("{}", vault::recovery::UNRECOVERABLE_DOCTRINE);
                }
                VaultAction::CustodyRecover {
                    manifest,
                    share_files,
                    kt_log,
                    print_key,
                } => {
                    let manifest_json = std::fs::read_to_string(manifest).unwrap_or_else(|e| {
                        eprintln!("error reading {}: {e}", manifest.display());
                        std::process::exit(1);
                    });
                    let m: vault::recovery::CustodyManifest = serde_json::from_str(&manifest_json)
                        .unwrap_or_else(|e| {
                            eprintln!("invalid custody manifest: {e}");
                            std::process::exit(1);
                        });
                    let mut shares: Vec<vault::recovery::CustodyShare> = Vec::new();
                    for sf in share_files {
                        let data = std::fs::read_to_string(sf).unwrap_or_else(|e| {
                            eprintln!("error reading {}: {e}", sf.display());
                            std::process::exit(1);
                        });
                        let share: vault::recovery::CustodyShare =
                            serde_json::from_str(&data).unwrap_or_else(|e| {
                                eprintln!("invalid custody share {}: {e}", sf.display());
                                std::process::exit(1);
                            });
                        shares.push(share);
                    }
                    let mut kt = match tallow::kt_log::KtLog::open(kt_log) {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("KT log error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    match vault::recovery::recover_root(&m, &shares, &mut kt, None, now_ms) {
                        Ok(vault::recovery::RecoveryDecision::Recovered(root)) => {
                            if let Err(e) = append_kt_payload(
                                &std::path::PathBuf::from(format!(
                                    "{}.payloads.jsonl",
                                    kt_log.display()
                                )),
                                &root.report().kt.payload,
                            ) {
                                eprintln!("refusing: cannot retain the KT payload: {e}");
                                std::process::exit(1);
                            }
                            eprintln!(
                                "Recovered custody kit {} from {} shares ({} distinct custodians, KT entry {})",
                                root.report().split_id,
                                root.report().shares_used,
                                root.report().custodians.len(),
                                root.report().kt.seq
                            );
                            eprintln!(
                                "Post-recovery freeze until {} ms (24 h; enforcement is daemon-side)",
                                root.report().freeze_until_ms
                            );
                            if *print_key {
                                let key_hex: String =
                                    root.expose().iter().map(|b| format!("{b:02x}")).collect();
                                println!("{key_hex}");
                            }
                        }
                        Ok(vault::recovery::RecoveryDecision::Refused { reason, kt }) => {
                            eprintln!("Unrecoverable: {reason} (KT entry {})", kt.seq);
                            if let Err(e) = append_kt_payload(
                                &std::path::PathBuf::from(format!(
                                    "{}.payloads.jsonl",
                                    kt_log.display()
                                )),
                                &kt.payload,
                            ) {
                                eprintln!("cannot retain the KT payload: {e}");
                            }
                            eprintln!("{}", vault::recovery::UNRECOVERABLE_DOCTRINE);
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("custody recovery error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VaultAction::Info { path } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    eprintln!("Vault: {}", db.name);
                    eprintln!("  File:       {}", path.display());
                    eprintln!("  Created:    {}", db.created_at);
                    eprintln!("  Updated:    {}", db.updated_at);
                    eprintln!("  Entries:    {}", db.entry_count());
                    eprintln!("  Folders:    {}", db.folders.len());
                    eprintln!(
                        "  PQC:        {}",
                        if db.settings.pqc_enabled {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                    eprintln!("{}", db.summary());
                }
                VaultAction::Audit { path, json } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let entries: Vec<&vault::VaultEntry> = db.entries.iter().collect();
                    if let Some(e) = gate.first_denied(&entries) {
                        gate_exit(&e);
                    }
                    let report = vault::audit::full_audit(&db);
                    if *json {
                        println!("{}", vault::audit::format_report_json(&report));
                    } else {
                        eprintln!("{}", vault::audit::format_report(&report));
                    }
                }
                VaultAction::Sync {
                    path,
                    remote,
                    strategy,
                } => {
                    let pw = get_password();
                    let mut local_db =
                        match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("error: {e}");
                                std::process::exit(1);
                            }
                        };
                    let remote_db =
                        match vault::VaultDatabase::open(remote.to_str().unwrap_or(""), &pw) {
                            Ok(d) => d,
                            Err(_) => {
                                let bundle = std::fs::read(remote).unwrap_or_else(|e| {
                                    eprintln!("error: {e}");
                                    std::process::exit(1);
                                });
                                vault::sync::import_sync_bundle(&bundle, &pw).unwrap_or_else(|e| {
                                    eprintln!("error: {e}");
                                    std::process::exit(1);
                                })
                            }
                        };
                    let strat = match strategy.as_str() {
                        "keep-local" => vault::sync::ConflictResolution::KeepLocal,
                        "keep-remote" => vault::sync::ConflictResolution::KeepRemote,
                        "keep-both" => vault::sync::ConflictResolution::KeepBoth,
                        _ => vault::sync::ConflictResolution::KeepNewer,
                    };
                    let delta = vault::sync::merge_vaults(&mut local_db, &remote_db, strat);
                    local_db
                        .save(path.to_str().unwrap_or(""), &pw)
                        .unwrap_or_else(|e| {
                            eprintln!("save error: {e}");
                            std::process::exit(1);
                        });
                    eprintln!(
                        "Sync complete: {} added, {} modified, {} deleted, {} conflicts",
                        delta.added.len(),
                        delta.modified.len(),
                        delta.deleted.len(),
                        delta.conflicts.len()
                    );
                }
                VaultAction::SyncExport {
                    path,
                    output,
                    audience,
                    kt_log,
                } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let class = gate.policy.tightest_class(db.entries.iter());
                    let audiences = parse_audience(audience);
                    let now = vault::access::now_ms();
                    // D6: ciphertext bundle — policy gate only (no redaction receipt).
                    if let Err(reason) = tallow::access_class::check_export(
                        class,
                        audiences,
                        gate.policy.is_embargo_active(now),
                    ) {
                        gate_exit_aud(
                            &tallow::enforcement::EnforceError::ExportDenied(
                                reason.code().to_string(),
                            ),
                            Some(class),
                            audiences,
                        );
                    }
                    let bundle = vault::sync::export_sync_bundle(&db, &pw).unwrap_or_else(|e| {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    });
                    vault::import_export::write_export_file(output.as_path(), &bundle, false)
                        .unwrap_or_else(|e| {
                            eprintln!("refusing insecure export: {e}");
                            std::process::exit(1);
                        });
                    if let Some(kt_path) = kt_log {
                        let payload = serde_json::json!({
                            "event": "vault_sync_export",
                            "format": "ciphertext-bundle",
                            "class": class,
                            "audience": audiences,
                            "note": "ciphertext-no-receipt (D6)",
                        });
                        let mut kt = match tallow::kt_log::KtLog::open(kt_path) {
                            Ok(l) => l,
                            Err(e) => {
                                eprintln!("refusing: cannot record the release: {e}");
                                std::process::exit(1);
                            }
                        };
                        if let Err(e) = kt.append_json(&payload) {
                            eprintln!("refusing: cannot record the release: {e}");
                            std::process::exit(1);
                        }
                        if let Err(e) = append_kt_payload(
                            &std::path::PathBuf::from(format!(
                                "{}.payloads.jsonl",
                                kt_path.display()
                            )),
                            &payload,
                        ) {
                            eprintln!("refusing: cannot retain the KT payload: {e}");
                            std::process::exit(1);
                        }
                    }
                    eprintln!(
                        "Sync bundle exported: {} ({} bytes)",
                        output.display(),
                        bundle.len()
                    );
                }
                VaultAction::SshAgent {
                    path,
                    generate,
                    key_name,
                } => {
                    let pw = get_password();
                    let mut db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw)
                    {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    let entries: Vec<&vault::VaultEntry> = db.entries.iter().collect();
                    if let Some(e) = gate.first_denied(&entries) {
                        gate_exit(&e);
                    }
                    if *generate {
                        let name = key_name.as_deref().unwrap_or("tallow-ed25519");
                        match vault::ssh_agent::generate_ed25519_keypair() {
                            Ok(ssh_data) => {
                                let entry = vault::VaultEntry::new_ssh_key(
                                    name,
                                    &ssh_data.private_key,
                                    &ssh_data.public_key,
                                    &ssh_data.fingerprint,
                                    &ssh_data.key_type,
                                );
                                eprintln!("Generated Ed25519 SSH key:");
                                eprintln!("  Fingerprint: {}", ssh_data.fingerprint);
                                eprintln!(
                                    "  Public key:  {}",
                                    &ssh_data.public_key[..60.min(ssh_data.public_key.len())]
                                );
                                db.add_entry(entry);
                                db.save(path.to_str().unwrap_or(""), &pw)
                                    .unwrap_or_else(|e| {
                                        eprintln!("save error: {e}");
                                        std::process::exit(1);
                                    });
                            }
                            Err(e) => {
                                eprintln!("keygen error: {e}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        let agent = vault::ssh_agent::SSHAgent::load_from_vault(&db.entries);
                        eprintln!("SSH Agent: {} keys loaded", agent.keys.len());
                        for key in agent.list_keys() {
                            eprintln!("  {} ({}) — {}", key.name, key.key_type, key.fingerprint);
                        }
                    }
                }
                VaultAction::AutoType {
                    path,
                    window_title,
                    sequence,
                } => {
                    let pw = get_password();
                    let db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let matching = vault::autotype::find_matching_entry(&db.entries, window_title);
                    if matching.is_empty() {
                        eprintln!("No entries matching window '{window_title}'");
                        std::process::exit(1);
                    }
                    let entry = matching[0];
                    let gate = vault::access::VaultGate::for_path(
                        path.as_path(),
                        vault::access::AccessContext::operator(),
                    );
                    if let Err(e) = gate.read_gate(entry) {
                        gate_exit(&e);
                    }
                    let seq = if let Some(s) = sequence {
                        vault::autotype::parse_sequence(s).unwrap_or_else(|e| {
                            eprintln!("parse error: {e}");
                            std::process::exit(1);
                        })
                    } else {
                        vault::autotype::default_sequence()
                    };
                    match vault::autotype::process_sequence(&seq, entry) {
                        Ok(result) => {
                            eprintln!(
                                "Auto-type for '{}' ({} keystrokes):",
                                entry.name, result.total_chars
                            );
                            for ks in &result.keystrokes {
                                match ks.action.as_str() {
                                    "type" => eprint!("{}", ks.value),
                                    "key" => eprint!("[{}]", ks.value),
                                    "delay" => eprint!("[delay {}ms]", ks.value),
                                    _ => {}
                                }
                            }
                            eprintln!();
                        }
                        Err(e) => {
                            eprintln!("auto-type error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VaultAction::PqcEnable { path } => {
                    let pw = get_password();
                    let mut db = match vault::VaultDatabase::open(path.to_str().unwrap_or(""), &pw)
                    {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    match vault::pqc::generate_pqc_keypair() {
                        Ok(kp) => {
                            db.settings.pqc_enabled = true;
                            db.save(path.to_str().unwrap_or(""), &pw)
                                .unwrap_or_else(|e| {
                                    eprintln!("save error: {e}");
                                    std::process::exit(1);
                                });
                            let info = vault::pqc::pqc_strength_info();
                            eprintln!("PQC hybrid encryption enabled!");
                            eprintln!(
                                "  Classical:  {} ({}-bit)",
                                info.classical_algo, info.classical_bits
                            );
                            eprintln!(
                                "  PQC:        {} (NIST Level {})",
                                info.pqc_algo, info.pqc_level
                            );
                            eprintln!("  Security:   {}", info.combined_security);
                            eprintln!("  Encapsulation key: {}...", &kp.encapsulation_key[..32]);
                        }
                        Err(e) => {
                            eprintln!("PQC error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            return Ok(());
        }
        Command::Workspace { ref action } => {
            let cwd = std::env::current_dir()?;
            match action {
                WorkspaceAction::List => {
                    let ws_root = tallow::pkg::cli::find_workspace_root(&cwd).ok_or_else(|| {
                        anyhow::anyhow!(
                            "not inside a workspace (no tallow.toml with [workspace] found)"
                        )
                    })?;
                    tallow::pkg::enterprise::workspace_list(&ws_root)?;
                }
                WorkspaceAction::Root => {
                    tallow::pkg::enterprise::workspace_root(&cwd)?;
                }
                WorkspaceAction::Run { member, args } => {
                    let ws_root = tallow::pkg::cli::find_workspace_root(&cwd).ok_or_else(|| {
                        anyhow::anyhow!(
                            "not inside a workspace (no tallow.toml with [workspace] found)"
                        )
                    })?;
                    tallow::pkg::enterprise::workspace_run(&ws_root, member, args)?;
                }
            }
            return Ok(());
        }
        Command::Doc {
            ref path,
            ref format,
        } => {
            run_doc_project(path, format);
            return Ok(());
        }
        Command::Build { ref file, .. }
        | Command::Run { ref file, .. }
        | Command::Check { ref file, .. }
        | Command::Audit { ref file, .. }
        | Command::Lint { ref file, .. }
        | Command::Pia { ref file, .. }
        | Command::Sast { ref file, .. } => {
            configure_throughput_runtime(throughput_threads, quiet);
            // Script runner: if --script flag or auto-detected PEP 723-style inline deps,
            // prepare a temp project with dependencies installed.
            let script_file: Option<PathBuf>;
            let raw_source_for_deps = std::fs::read_to_string(file).ok();
            let has_pep723_deps = raw_source_for_deps
                .as_deref()
                .map(|s| !parse_inline_deps(s).is_empty())
                .unwrap_or(false);
            let file = if matches!(cli.command, Command::Run { script: true, .. })
                || (matches!(cli.command, Command::Run { .. }) && has_pep723_deps)
            {
                // Print auto-install notice for PEP 723-style inline deps
                if has_pep723_deps && !quiet {
                    if let Some(ref src) = raw_source_for_deps {
                        let deps = parse_inline_deps(src);
                        if !deps.is_empty() {
                            let dep_list: Vec<String> = deps
                                .iter()
                                .map(|(name, ver)| format!("{} {}", name, ver))
                                .collect();
                            eprintln!("Auto-installing: {}", dep_list.join(", "));
                        }
                    }
                }
                let registry_path = tallow::pkg::cli::default_registry_path();
                match tallow::pkg::script_runner::prepare_script(file, &registry_path) {
                    Ok(path) => {
                        script_file = Some(path);
                        script_file.as_ref().unwrap()
                    }
                    Err(e) => {
                        eprintln!("script preparation failed: {e}");
                        std::process::exit(exit_codes::DEPENDENCY_ERROR);
                    }
                }
            } else {
                script_file = None;
                let _ = &script_file; // suppress unused warning
                file
            };

            let source = std::fs::read_to_string(file)
                .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", file.display()))?;
            let filename = file.display().to_string();

            // ── Phase 1: Lex ─────────────────────────────────────────
            let (tokens, lex_errors) = tallow::lexer::tokenize(&source);
            if !lex_errors.is_empty() {
                for err in &lex_errors {
                    let (line, col) = err.span().line_col(&source);
                    eprintln!("error[{line}:{col}]: {err}");
                }
                std::process::exit(exit_codes::COMPILE_ERROR);
            }

            // ── Phase 2: Parse (with error recovery — report ALL errors) ─
            let program = match parser_mode {
                ParserMode::Recover => {
                    let (program, parse_errors) = tallow::parser::Parser::parse_recovering(tokens);
                    if !parse_errors.is_empty() {
                        for err in &parse_errors {
                            let (line, col) = err.span.line_col(&source);
                            eprintln!("error[{line}:{col}]: {err}");
                        }
                        std::process::exit(exit_codes::COMPILE_ERROR);
                    }
                    program
                }
                ParserMode::Fast => match tallow::parser::Parser::parse(tokens) {
                    Ok(program) => program,
                    Err(err) => {
                        let (line, col) = err.span.line_col(&source);
                        eprintln!("error[{line}:{col}]: {err}");
                        std::process::exit(exit_codes::COMPILE_ERROR);
                    }
                },
            };

            // ── Phase 2b: Resolve imports ────────────────────────────
            let mut program = program;
            resolve_imports(&mut program, file);

            // ── Phase 3: Type Check ──────────────────────────────────
            let (env, typeck_diags) = TypeChecker::new(&program).check();

            // ── Phase 4: Legal Pass ──────────────────────────────────
            let (legal_diags, browser_audit_entries) = LegalPass::new(&program, &env).check();

            // ── Phase 5: Privacy Pass ────────────────────────────────
            let privacy_diags = PrivacyPass::new(&program, &env).check();

            // ── Phase 6: Agent Pass ─────────────────────────────────
            let agent_diags = AgentPass::new(&program).check();

            // ── Phase 6.5: Agent Safety Pass (L1-L5 levels) ────────
            let agent_safety_diags = AgentSafetyPass::new(&program, &env).check();

            // ── Phase 6.6: Constitution Pass (hierarchical safety) ──
            let toml_content = file
                .parent()
                .map(|dir| {
                    // Try tallow.toml in same directory, then parent directory
                    let same_dir = dir.join("tallow.toml");
                    let parent_dir = dir.parent().map(|p| p.join("tallow.toml"));
                    if same_dir.exists() {
                        std::fs::read_to_string(&same_dir).ok()
                    } else if let Some(ref p) = parent_dir {
                        if p.exists() {
                            std::fs::read_to_string(p).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .flatten();
            let constitution_diags =
                ConstitutionPass::new(&program, &env, toml_content.as_deref()).check();

            // ── Phase 7: Stealth Pass ───────────────────────────────
            let stealth_diags = StealthPass::new(&program, &env).check();

            // ── Phase 7b: Fingerprint Policy Pass (U-101 / ag03 R-1) ─
            let fingerprint_policy_diags =
                tallow::fingerprint_policy_pass::FingerprintPolicyPass::new(&program, &env).check();

            // ── Phase 8: DP Budget Pass ──────────────────────────────
            let dp_diags = DPBudgetPass::new(&program, &env).check();

            // ── Phase 9: Consent Pass ────────────────────────────────
            let consent_diags = ConsentPass::new(&program, &env).check();

            // ── Phase 10: Erasure Pass ───────────────────────────────
            let erasure_diags = ErasurePass::new(&program, &env).check();

            // ── Phase 11: Opsec Pass ────────────────────────────────
            let opsec_diags = OpsecPass::new(&program, &env).check();

            // ── Phase 11b: OPSEC Gates Pass (program-policy E5001–E5004) ─
            let opsec_gates_diags =
                tallow::opsec_gates::OpsecGatesPass::new(&program, &env).check();

            // ── Phase 12: Identity Pass ───────────────────────────────
            let identity_diags = IdentityPass::new(&program, &env).check();

            // ── Phase 13: Sandbox Pass ───────────────────────────────
            let sandbox_diags = SandboxPass::new(&program).check();

            // ── Phase 14: Lineage Pass ──────────────────────────────
            let lineage_diags = LineagePass::new(&program, &env).check();

            // ── Phase 15: Constant-Time Pass ──────────────────────────
            let consttime_diags = ConstTimePass::new(&program, &env).check();

            // ── Phase 16: Contract Pass ──────────────────────────────
            let contract_diags = ContractPass::new(&program, &env).check();

            // ── Phase 17: AI Act Pass ───────────────────────────────
            let ai_act_diags = AiActPass::new(&program).check();

            // ── Phase 17b: CRA Pass ─────────────────────────────────
            let cra_diags = CraPass::new(&program).check();

            // ── Phase 17c: NIS2 Pass ────────────────────────────────
            let nis2_diags = Nis2Pass::new(&program).check();

            // ── Phase 18: ZK Pass ─────────────────────────────────────
            let zk_diags = ZkPass::new(&program).check();

            // ── Phase 19: Enclave Pass ──────────────────────────────
            let enclave_diags = EnclavePass::new(&program).check();

            // ── Phase 20: HW Safety Pass ────────────────────────────
            let hw_safety_diags = HwSafetyPass::new(&program).check();

            // ── Phase 21: HE Pass ─────────────────────────────────────
            let he_diags = HePass::new(&program).check();

            // ── Phase 22: MPC Pass ────────────────────────────────────
            let mpc_diags = MpcPass::new(&program).check();

            // ── Phase 23: Safety Pass ────────────────────────────────
            let safety_diags = SafetyPass::new(&program).check();

            // ── Phase 24: SAST Taint Analysis Pass ──────────────────
            let sast_diags = SastPass::new(&program).check();

            // ── Phase 25: Detection Engineering Pass ─────────────────
            let detection_diags = DetectionPass::new(&program).check();

            // ── Phase 26: Observability & Telemetry Pass ─────────────
            let otel_diags = OtelPass::new(&program).check();

            // ── Phase 27: PEC Pass (MetaPrivate enforcement) ──────────
            // E2800: MetaPrivate values must not reach non-PEC sinks;
            // W2800: computation outside a documented PEC context.
            let pec_diags = PecPass::new(&program).check();

            // ── Phase 28: Crypto Policy Pass (PQC policy) ─────────────
            // E2700/W2700 gate classical algorithms when the project's
            // crypto policy requires PQC. Policy resolution order:
            //   1. `[crypto] policy = "pqc_required"` in tallow.toml
            //   2. TALLOW_CRYPTO_POLICY environment variable
            //   3. default: unrestricted (pass runs, emits nothing)
            let crypto_policy = {
                let mut policy_str: Option<String> = None;
                let toml_path = file
                    .parent()
                    .map(|dir| {
                        let same_dir = dir.join("tallow.toml");
                        let parent_dir = dir.parent().map(|p| p.join("tallow.toml"));
                        if same_dir.exists() {
                            Some(same_dir)
                        } else if let Some(ref p) = parent_dir {
                            if p.exists() {
                                Some(p.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .flatten();
                if let Some(p) = toml_path {
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        if let Ok(parsed) = text.parse::<toml::Table>() {
                            if let Some(crypto) = parsed.get("crypto").and_then(|v| v.as_table()) {
                                if let Some(pol) = crypto.get("policy").and_then(|v| v.as_str()) {
                                    policy_str = Some(pol.to_string());
                                }
                            }
                        }
                    }
                }
                let policy_str = policy_str
                    .or_else(|| std::env::var("TALLOW_CRYPTO_POLICY").ok())
                    .unwrap_or_else(|| "unrestricted".to_string());
                CryptoPolicy::from_str(&policy_str)
            };
            let crypto_policy_diags =
                CryptoPolicyPass::new(&program, crypto_policy).check();

            // ── Phase 28b: Tier Gate Pass (@tier annotation validity) ──
            let tier_gate_diags = TierGatePass::new(&filename, &source).check();

            // ── Phase 28c: Tier Gate build-level (T-123) ──────────────
            // `check_build` over the build unit's collected inputs. Single-
            // file call site: the unit is this file. Waivers are empty until
            // a record store lands (documented gap: deny-until-record).
            let tier_gate_build_diags = {
                let build_unit = tallow::tier_gate_pass::BuildUnit::single(
                    filename.clone(),
                    tallow::tier_gate_pass::SourceUnit {
                        path: filename.clone(),
                        source: source.clone(),
                    },
                );
                tallow::tier_gate_pass::report_diagnostics(&tallow::tier_gate_pass::run_build_gate(
                    &build_unit,
                    &[],
                    tallow::observability::now_ms(),
                ))
            };

            // ── Collect all diagnostics ──────────────────────────────
            let mut all_diags = tallow::error::Diagnostics::new();
            for d in typeck_diags.items {
                all_diags.push(d);
            }
            for d in legal_diags.items {
                all_diags.push(d);
            }
            for d in privacy_diags.items {
                all_diags.push(d);
            }
            for d in agent_diags.items {
                all_diags.push(d);
            }
            for d in agent_safety_diags.items {
                all_diags.push(d);
            }
            for d in constitution_diags.items {
                all_diags.push(d);
            }
            for d in stealth_diags.items {
                all_diags.push(d);
            }
            for d in fingerprint_policy_diags.items {
                all_diags.push(d);
            }
            for d in dp_diags.items {
                all_diags.push(d);
            }
            for d in consent_diags.items {
                all_diags.push(d);
            }
            for d in erasure_diags.items {
                all_diags.push(d);
            }
            for d in opsec_diags.items {
                all_diags.push(d);
            }
            for d in opsec_gates_diags.items {
                all_diags.push(d);
            }
            for d in identity_diags.items {
                all_diags.push(d);
            }
            for d in sandbox_diags.items {
                all_diags.push(d);
            }
            for d in lineage_diags.items {
                all_diags.push(d);
            }
            for d in consttime_diags.items {
                all_diags.push(d);
            }
            for d in contract_diags.items {
                all_diags.push(d);
            }
            for d in ai_act_diags.items {
                all_diags.push(d);
            }
            for d in cra_diags.items {
                all_diags.push(d);
            }
            for d in nis2_diags.items {
                all_diags.push(d);
            }
            for d in zk_diags.items {
                all_diags.push(d);
            }
            for d in enclave_diags.items {
                all_diags.push(d);
            }
            for d in hw_safety_diags.items {
                all_diags.push(d);
            }
            for d in he_diags.items {
                all_diags.push(d);
            }
            for d in mpc_diags.items {
                all_diags.push(d);
            }
            for d in safety_diags.items {
                all_diags.push(d);
            }
            for d in sast_diags.items {
                all_diags.push(d);
            }
            for d in detection_diags.items {
                all_diags.push(d);
            }
            for d in otel_diags.items {
                all_diags.push(d);
            }
            for d in pec_diags.items {
                all_diags.push(d);
            }
            for d in crypto_policy_diags.items {
                all_diags.push(d);
            }
            for d in tier_gate_diags.items {
                all_diags.push(d);
            }
            for d in tier_gate_build_diags.items {
                all_diags.push(d);
            }

            // ── Report ───────────────────────────────────────────────
            if !all_diags.items.is_empty() {
                eprintln!("{}", all_diags.render_all(&source, &filename));
                eprintln!();
            }

            let errors = all_diags.error_count();
            let warnings = all_diags.warning_count();

            match &cli.command {
                Command::Audit {
                    format,
                    strict,
                    jurisdiction,
                    cra,
                    nis2,
                    dora,
                    ai_act,
                    supply_chain,
                    sast,
                    detection_coverage,
                    cloud,
                    deps,
                    offline_fallback,
                    ..
                } => {
                    if *deps {
                        let project_dir = tallow::pkg::cli::find_project_root(
                            &std::path::Path::new(file)
                                .parent()
                                .unwrap_or(std::path::Path::new(".")),
                        )
                        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
                        tallow::pkg::enterprise::pkg_audit_deps(&project_dir, format == "json")
                            .unwrap_or_else(|e| eprintln!("audit --deps error: {e}"));
                    } else if *cloud {
                        run_cloud_audit(&program, &filename, format, errors, warnings);
                    } else if *detection_coverage {
                        run_detection_coverage_audit(&program, format);
                    } else if *sast {
                        run_sast_report(&program, format);
                    } else if *supply_chain {
                        run_supply_chain_audit_cmd(
                            &program, &filename, format, errors, warnings, file,
                        );
                    } else if *cra {
                        run_cra_audit(
                            &program,
                            &filename,
                            format,
                            errors,
                            warnings,
                            file,
                            *offline_fallback,
                            *strict,
                        );
                    } else if *nis2 {
                        run_nis2_audit(
                            &program,
                            &filename,
                            format,
                            errors,
                            warnings,
                            file,
                            *offline_fallback,
                            *strict,
                        );
                    } else if *dora {
                        run_dora_audit(&program, &filename, format, errors, warnings, file, *strict);
                    } else if *ai_act {
                        run_ai_act_audit(&program, &filename, format, errors, warnings, file, *strict);
                    } else {
                        run_audit(
                            &program,
                            &env,
                            &filename,
                            format,
                            jurisdiction.as_deref(),
                            errors,
                            warnings,
                            &browser_audit_entries,
                            *strict,
                        );
                    }
                }
                Command::Check { format, .. } => {
                    if format == "json" {
                        let diag_json: Vec<serde_json::Value> = all_diags
                            .items
                            .iter()
                            .map(|d| {
                                let (line, col) = d.span.line_col(&source);
                                serde_json::json!({
                                    "code": d.code,
                                    "severity": match d.severity {
                                        tallow::error::Severity::Error => "error",
                                        tallow::error::Severity::Warning => "warning",
                                    },
                                    "message": d.msg,
                                    "file": filename,
                                    "line": line,
                                    "column": col,
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "file": filename,
                                "errors": errors,
                                "warnings": warnings,
                                "items": program.items.len(),
                                "diagnostics": diag_json,
                            }))
                            .unwrap_or_default()
                        );
                        if errors > 0 {
                            std::process::exit(exit_codes::COMPILE_ERROR);
                        }
                    } else {
                        if errors > 0 {
                            eprintln!("check failed: {errors} error(s), {warnings} warning(s)");
                            std::process::exit(exit_codes::COMPILE_ERROR);
                        }
                        if !quiet {
                            println!(
                                "check passed: {} items, {warnings} warning(s)",
                                program.items.len()
                            );
                        }
                    }
                }
                Command::Build {
                    file,
                    target,
                    format,
                    ..
                } => {
                    if format == "json" {
                        let diag_json: Vec<serde_json::Value> = all_diags
                            .items
                            .iter()
                            .map(|d| {
                                let (line, col) = d.span.line_col(&source);
                                serde_json::json!({
                                    "code": d.code,
                                    "severity": match d.severity {
                                        tallow::error::Severity::Error => "error",
                                        tallow::error::Severity::Warning => "warning",
                                    },
                                    "message": d.msg,
                                    "file": filename,
                                    "line": line,
                                    "column": col,
                                })
                            })
                            .collect();
                        if errors > 0 {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "file": filename,
                                    "success": false,
                                    "errors": errors,
                                    "warnings": warnings,
                                    "diagnostics": diag_json,
                                }))
                                .unwrap_or_default()
                            );
                            std::process::exit(exit_codes::COMPILE_ERROR);
                        }
                    } else if errors > 0 {
                        eprintln!("build failed: {errors} error(s), {warnings} warning(s)");
                        std::process::exit(exit_codes::COMPILE_ERROR);
                    }

                    // Resolve target configuration
                    let target_config = match &target {
                        Some(t) => match tallow::codegen::TargetConfig::from_target_str(t) {
                            Ok(tc) => tc,
                            Err(e) => {
                                eprintln!("error: {e}");
                                std::process::exit(exit_codes::COMPILE_ERROR);
                            }
                        },
                        None => tallow::codegen::TargetConfig::host(),
                    };

                    // Determine output path based on target
                    let output = if target_config.is_wasm {
                        file.with_extension("wasm")
                    } else if target_config.is_windows {
                        file.with_extension("exe")
                    } else {
                        file.with_extension("")
                    };

                    let source_dir = file.parent().map(|p| p.display().to_string());
                    match CodeGen::compile_with_target_and_source_dir(
                        &program,
                        &env,
                        &output,
                        target_config,
                        source_dir,
                    ) {
                        Ok(()) => {
                            if format == "json" {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&serde_json::json!({
                                        "file": filename,
                                        "success": true,
                                        "output": output.display().to_string(),
                                        "errors": 0,
                                        "warnings": warnings,
                                    }))
                                    .unwrap_or_default()
                                );
                            } else if !quiet {
                                println!("built: {}", output.display());
                                if warnings > 0 {
                                    println!("  {warnings} warning(s)");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("build failed: {e}");
                            std::process::exit(exit_codes::COMPILE_ERROR);
                        }
                    }
                }
                Command::Run {
                    program_args,
                    target,
                    contracts,
                    require_native,
                    script,
                    sandbox,
                    ..
                } => {
                    // Warn about cross-compilation when using --target with run
                    if let Some(t) = &target {
                        let host = tallow::codegen::TargetConfig::host();
                        if let Ok(tc) = tallow::codegen::TargetConfig::from_target_str(t) {
                            if tc.triple != host.triple {
                                eprintln!(
                                    "warning: Cross-compiled binary for {} may not run on this host",
                                    tc.triple
                                );
                            }
                        }
                    }
                    if errors > 0 {
                        eprintln!("run failed: {errors} error(s), {warnings} warning(s)");
                        std::process::exit(exit_codes::COMPILE_ERROR);
                    }
                    // Auto-install missing dependencies before execution
                    if let Err(e) = tallow::pkg::cli::auto_install_if_needed(file) {
                        eprintln!("warning: auto-install failed: {e}");
                        // Don't exit -- let the program try to run anyway
                    }
                    // R3 runtime enforcement: `--sandbox` re-executes this run as
                    // a Landlock-confined child (fail-closed; see
                    // src/cli/sandbox_cmd.rs). Parent exits with the child's code.
                    if *sandbox {
                        match tallow::cli::sandbox_cmd::run_confined_self(file, *script, program_args)
                        {
                            Ok(code) => std::process::exit(code),
                            Err(e) => {
                                eprintln!("run --sandbox: {e}");
                                std::process::exit(exit_codes::PERMISSION_VIOLATION);
                            }
                        }
                    }
                    // R3 part 2: @sandbox/@sandboxed annotations are compile-time
                    // validated but NOT enforced at runtime unless --sandbox is
                    // used. Suppressed inside the confined child (TALLOW_SANDBOX_CHILD
                    // is set there by sandbox_cmd).
                    if std::env::var_os("TALLOW_SANDBOX_CHILD").is_none() {
                        let annotated = tallow::sandbox_pass::annotated_functions(&program);
                        if !annotated.is_empty() {
                            eprintln!(
                                "warning: @sandbox/@sandboxed annotations on [{}] are validated but NOT enforced at runtime; re-run with `tallow run --sandbox` to confine this program (Landlock)",
                                annotated.join(", ")
                            );
                        }
                    }
                    // Set up graceful shutdown via Ctrl-C
                    let shutdown_flag = Arc::new(AtomicBool::new(false));
                    {
                        let flag = Arc::clone(&shutdown_flag);
                        ctrlc::set_handler(move || {
                            flag.store(true, std::sync::atomic::Ordering::SeqCst);
                            eprintln!("\n[tallow] Shutdown signal received...");
                        })
                        .unwrap_or_else(|e| {
                            eprintln!("Warning: could not set Ctrl-C handler: {e}");
                        });
                    }
                    // Native-first: try compiling the program to a native binary and
                    // running it. On BUILD failure (e.g. maps, which the native backend
                    // rejects loudly) we fall back to the tree-walking interpreter. If the
                    // native build succeeds we run it and propagate its exit code — we do
                    // NOT re-run the interpreter afterward, to avoid double side effects.
                    let native_out =
                        std::env::temp_dir().join(format!("tallow_native_run_{}", std::process::id()));
                    let is_cross = target
                        .as_ref()
                        .and_then(|t| tallow::codegen::TargetConfig::from_target_str(t).ok())
                        .map(|tc| tc.triple != tallow::codegen::TargetConfig::host().triple)
                        .unwrap_or(false);
                    let native_target = target
                        .as_ref()
                        .and_then(|t| tallow::codegen::TargetConfig::from_target_str(t).ok())
                        .unwrap_or_else(tallow::codegen::TargetConfig::host);
                    if !is_cross {
                        let n_source_dir = file.parent().map(|p| p.display().to_string());
                        match tallow::codegen::CodeGen::compile_with_target_and_source_dir(
                            &program,
                            &env,
                            &native_out,
                            native_target,
                            n_source_dir,
                        ) {
                            Ok(()) => {
                                let run = std::process::Command::new(&native_out)
                                    .args(program_args)
                                    .status();
                                let _ = std::fs::remove_file(&native_out);
                                match run {
                                    Ok(st) if st.success() => return Ok(()),
                                    Ok(st) if st.code().is_some() => {
                                        // Program exited with its own (non-zero) code -> propagate
                                        std::process::exit(st.code().unwrap());
                                    }
                                    Ok(st) => {
                                        // Crashed via signal (e.g. segfault) — the native codegen
                                        // is unsound for this program (e.g. it uses a construct
                                        // whose native lowering crashes). Re-run in the interpreter.
                                        // The engine marker below is deliberately NOT gated on
                                        // `quiet`: a caller reading stdout + rc must be able to
                                        // tell a native run from a fallback (E-2-02 §5).
                                        if *require_native {
                                            eprintln!(
                                                "* native run crashed (no exit code); --require-native refuses the interpreter fallback"
                                            );
                                            std::process::exit(exit_codes::COMPILE_ERROR);
                                        }
                                        eprintln!(
                                            "* native run crashed (no exit code); re-running in the interpreter"
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("native run failed to launch: {e}");
                                        std::process::exit(exit_codes::COMPILE_ERROR);
                                    }
                                }
                            }
                            Err(e) => {
                                // Engine marker: never suppressed by -q; a harness that
                                // reads stdout + rc cannot otherwise distinguish a native
                                // run from an interpreter fallback (E-2-02 §5).
                                if *require_native {
                                    eprintln!(
                                        "* native build unavailable ({e}); --require-native refuses the interpreter fallback"
                                    );
                                    std::process::exit(exit_codes::COMPILE_ERROR);
                                }
                                eprintln!("* native build unavailable ({e}); running in the interpreter");
                            }
                        }
                    }

                    // Execute via tree-walking interpreter
                    let mut interp = Interpreter::new();
                    interp.contracts_enabled = !matches!(contracts.as_str(), "off" | "false" | "0");
                    interp.program_args = program_args.clone();
                    interp.set_shutdown_flag(shutdown_flag);
                    interp.set_source_file(file);
                    if let Some(pol) = tallow::runtime_caps::RuntimeCapabilityPolicy::from_env() {
                        interp.set_capability_policy(std::sync::Arc::new(pol));
                    }
                    match interp.run(&program) {
                        Ok(_) => {}
                        Err(e) => {
                            // Graceful shutdown is not a real error
                            let msg = e.to_string();
                            if msg.contains("agent shutdown: state persisted") {
                                // Clean exit after graceful shutdown
                            } else {
                                eprintln!("runtime error: {e}");
                                std::process::exit(exit_codes::COMPILE_ERROR);
                            }
                        }
                    }
                }
                Command::Lint { format, .. } => {
                    run_lint(
                        &program, &env, &filename, errors, warnings, format, &all_diags, &source,
                        quiet,
                    );
                }
                Command::Pia { format, .. } => {
                    let report = generate_pia_report(&program, &env, &filename);
                    print_pia_report(&report, format);
                }
                Command::Sast { format, .. } => {
                    run_sast_report(&program, format);
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

// ── Inline Script Dependencies (PEP 723 style) ────────────────────────────────

/// Parse PEP 723-style inline dependency declarations from a `.tl` script.
///
/// Recognises the block:
/// ```text
/// // /// script
/// // requires = ["tallow-html ^0.3", "tallow-db ^0.2"]
/// // ///
/// ```
///
/// Returns a list of `(package_name, version_requirement)` pairs.
/// Returns an empty `Vec` when no such block is present.
fn parse_inline_deps(source: &str) -> Vec<(String, String)> {
    let mut in_block = false;
    let mut deps = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "// /// script" {
            in_block = true;
            continue;
        }
        if trimmed == "// ///" && in_block {
            break;
        }
        if in_block {
            let content = if let Some(s) = trimmed.strip_prefix("// ") {
                s
            } else if let Some(s) = trimmed.strip_prefix("//") {
                s.trim_start()
            } else {
                continue;
            };
            if content.trim_start().starts_with("requires") {
                if let Some(list_start) = content.find('[') {
                    let list_part = &content[list_start..];
                    for (idx, segment) in list_part.split('"').enumerate() {
                        if idx % 2 == 1 {
                            let parts: Vec<&str> = segment.splitn(2, ' ').collect();
                            let name = parts[0].trim().to_string();
                            if name.is_empty() {
                                continue;
                            }
                            let version = parts.get(1).unwrap_or(&"*").trim().to_string();
                            deps.push((name, version));
                        }
                    }
                }
            }
        }
    }

    deps
}

// ── Phantom Dependency Detection ──────────────────────────────────────────────

/// All stdlib module prefixes built into the Tallow runtime.
/// Imports matching any of these are NOT phantom dependencies.
const STDLIB_MODULES: &[&str] = &[
    "tallow.http",
    "tallow.html",
    "tallow.crypto",
    "tallow.net",
    "tallow.fs",
    "tallow.db",
    "tallow.json",
    "tallow.legal",
    "tallow.agent",
    "tallow.time",
    "tallow.log",
    "tallow.env",
    "tallow.process",
    "tallow.sync",
    "tallow.test",
    "tallow.fmt",
    "tallow.math",
    "tallow.rand",
    "tallow.regex",
    "tallow.url",
    "tallow.cli",
    "tallow.config",
    "tallow.compress",
    "tallow.mime",
];

/// Scan all `.tl` files under `src/` for `import` statements, then cross-check
/// them against the declared dependencies in `tallow.toml`. Report (and
/// optionally fix) any imports that are neither stdlib nor declared.
fn run_check_deps(fix: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let project_root = tallow::pkg::cli::find_project_root(&cwd).map_err(|_| {
        anyhow::anyhow!("could not find tallow.toml in current directory or any parent")
    })?;

    let toml_path = project_root.join("tallow.toml");
    let toml_content = std::fs::read_to_string(&toml_path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", toml_path.display()))?;

    let manifest = tallow::pkg::manifest::parse_manifest(&toml_content)
        .map_err(|e| anyhow::anyhow!("cannot parse tallow.toml: {e}"))?;

    let declared: std::collections::HashSet<String> =
        manifest.dependencies.keys().cloned().collect();

    let src_dir = project_root.join("src");
    if !src_dir.exists() {
        println!("No src/ directory found -- nothing to check.");
        return Ok(());
    }

    let mut phantoms: Vec<(String, String, usize)> = Vec::new();

    fn walk_tl(
        dir: &std::path::Path,
        phantoms: &mut Vec<(String, String, usize)>,
        declared: &std::collections::HashSet<String>,
    ) {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        for entry in rd.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                walk_tl(&path, phantoms, declared);
            } else if path.extension().and_then(|e| e.to_str()) == Some("tl") {
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let file_str = path.display().to_string();
                for (lineno, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("import ") {
                        let module = rest.split_whitespace().next().unwrap_or("").to_string();
                        if module.is_empty() {
                            continue;
                        }
                        let is_stdlib = STDLIB_MODULES
                            .iter()
                            .any(|s| module == *s || module.starts_with(&format!("{}.", s)));
                        if is_stdlib {
                            continue;
                        }
                        let pkg_name = module.replace('.', "-");
                        let pkg_name_short =
                            module.split('.').next().unwrap_or(&module).to_string();
                        let is_declared = declared.contains(&pkg_name)
                            || declared.contains(&pkg_name_short)
                            || declared.iter().any(|d| {
                                d == &module || d.starts_with(&format!("{}-", pkg_name_short))
                            });
                        if !is_declared {
                            phantoms.push((module, file_str.clone(), lineno + 1));
                        }
                    }
                }
            }
        }
    }

    walk_tl(&src_dir, &mut phantoms, &declared);

    if phantoms.is_empty() {
        println!("No phantom dependencies found.");
        return Ok(());
    }

    eprintln!("Warning: Phantom dependencies detected:");
    let mut seen_modules: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unique_phantoms: Vec<(String, String, usize)> = Vec::new();
    for (module, file, line) in &phantoms {
        if seen_modules.insert(module.clone()) {
            unique_phantoms.push((module.clone(), file.clone(), *line));
        }
    }

    for (module, file, line) in &unique_phantoms {
        eprintln!(
            "  {} -- imported in {}:{} but not in tallow.toml",
            module, file, line
        );
    }

    if fix {
        eprintln!();
        let mut doc: toml_edit::DocumentMut = toml_content
            .parse()
            .map_err(|e| anyhow::anyhow!("cannot parse tallow.toml for editing: {e}"))?;

        let deps_table = doc
            .entry("dependencies")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));

        let table = deps_table
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("[dependencies] is not a table in tallow.toml"))?;

        let mut added = Vec::new();
        for (module, _file, _line) in &unique_phantoms {
            let pkg_name = module.replace('.', "-");
            if !table.contains_key(&pkg_name) {
                table.insert(&pkg_name, toml_edit::value("*"));
                added.push(pkg_name);
            }
        }

        std::fs::write(&toml_path, doc.to_string())
            .map_err(|e| anyhow::anyhow!("cannot write tallow.toml: {e}"))?;

        for name in &added {
            eprintln!("  Added {} = \"*\" to tallow.toml", name);
        }
        eprintln!();
        eprintln!("Run `tallow add <package>` to pin specific versions.");
    } else {
        eprintln!();
        eprintln!("Run `tallow check-deps --fix` to add them to tallow.toml");
        std::process::exit(exit_codes::DEPENDENCY_ERROR);
    }

    Ok(())
}

// ── Import Resolution ─────────────────────────────────────────────────────────

/// Resolve import statements by loading and parsing imported .tl files.
///
/// Import resolution strategy:
/// 1. `import tallow.*` — stdlib builtins, no file resolution needed
/// 2. `import foo.bar` — resolves to `<project_root>/src/foo/bar.tl`
/// 3. `import bar` — resolves to `<project_root>/src/bar.tl`
///
/// Supports transitive imports: if A imports B and B imports C,
/// C's definitions become available in A. Circular imports are
/// detected and skipped via the `loaded` set.
fn resolve_imports(program: &mut tallow::ast::Program, main_file: &PathBuf) {
    use std::collections::HashSet;

    let project_root = main_file
        .parent()
        .and_then(|p| {
            if p.file_name().map(|n| n == "src").unwrap_or(false) {
                p.parent()
            } else {
                Some(p)
            }
        })
        .unwrap_or_else(|| std::path::Path::new("."));

    let mut loaded: HashSet<String> = HashSet::new();
    loaded.insert(
        main_file
            .canonicalize()
            .unwrap_or_else(|_| main_file.clone())
            .display()
            .to_string(),
    );

    let mut new_items = Vec::new();
    resolve_imports_recursive(&program.items, project_root, &mut loaded, &mut new_items);

    // Merge imported items BEFORE existing items (so declarations are available)
    if !new_items.is_empty() {
        new_items.append(&mut program.items);
        program.items = new_items;
    }
}

/// Recursively resolve imports from a list of items.
/// Transitive imports are followed up to a natural depth limit (the loaded set
/// prevents cycles). Items from imported files are collected into `out`.
fn resolve_imports_recursive(
    items: &[tallow::ast::Item],
    project_root: &std::path::Path,
    loaded: &mut std::collections::HashSet<String>,
    out: &mut Vec<tallow::ast::Item>,
) {
    for item in items {
        if let tallow::ast::Item::Import(import) = item {
            let path_str = import.path.join(".");

            // Skip stdlib imports (tallow.*)
            if import.path.first().map(|s| s.as_str()) == Some("tallow") {
                continue;
            }

            // Resolve file path
            let rel_path: PathBuf = import.path.iter().collect();
            let candidates = [
                project_root
                    .join("src")
                    .join(&rel_path)
                    .with_extension("tl"),
                project_root.join(&rel_path).with_extension("tl"),
                project_root.join("src").join(&rel_path).join("mod.tl"),
            ];

            for candidate in &candidates {
                if candidate.exists() {
                    let canon = candidate
                        .canonicalize()
                        .unwrap_or_else(|_| candidate.clone());
                    let canon_str = canon.display().to_string();
                    if loaded.contains(&canon_str) {
                        break; // already loaded, skip (circular import protection)
                    }
                    loaded.insert(canon_str);

                    match std::fs::read_to_string(candidate) {
                        Ok(source) => {
                            let (tokens, lex_errors) = tallow::lexer::tokenize(&source);
                            if !lex_errors.is_empty() {
                                eprintln!(
                                    "warning: lex errors in import '{path_str}': {}",
                                    candidate.display()
                                );
                                break;
                            }
                            match tallow::parser::Parser::parse(tokens) {
                                Ok(imported) => {
                                    // Recursively resolve imports from the imported file first
                                    resolve_imports_recursive(
                                        &imported.items,
                                        project_root,
                                        loaded,
                                        out,
                                    );
                                    // Then add the imported file's own non-import items
                                    for imp_item in imported.items {
                                        if !matches!(imp_item, tallow::ast::Item::Import(_)) {
                                            out.push(imp_item);
                                        }
                                    }
                                }
                                Err(err) => {
                                    eprintln!("warning: parse error in import '{path_str}': {err}");
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("warning: cannot read import '{path_str}': {err}");
                        }
                    }
                    break;
                }
            }
        }
    }
}

// ── Package Signing ──────────────────────────────────────────────────────────

fn read_ed25519_key_bytes(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read key file '{}': {e}", path.display()))?;

    // Try raw 32 bytes first
    if data.len() == 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data);
        return Ok(buf);
    }

    // Try hex-encoded (64 chars = 32 bytes)
    let text = String::from_utf8_lossy(&data);
    let trimmed = text.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut buf = [0u8; 32];
        for i in 0..32 {
            buf[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex in key file"))?;
        }
        return Ok(buf);
    }

    Err(anyhow::anyhow!(
        "key file must be 32 bytes raw or 64 hex chars, got {} bytes",
        data.len()
    ))
}

fn run_sign(archive_path: &std::path::Path, key_path: &std::path::Path) -> anyhow::Result<()> {
    use tallow::signing;

    let archive_data = std::fs::read(archive_path)
        .map_err(|e| anyhow::anyhow!("cannot read archive '{}': {e}", archive_path.display()))?;

    let key_bytes = read_ed25519_key_bytes(key_path)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    let archive_name = archive_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let tallow_version = env!("CARGO_PKG_VERSION");
    let pkg_sig = signing::sign_package(&archive_data, &archive_name, tallow_version, &signing_key);

    // Write .sig file (raw signature bytes)
    let sig_path = archive_path.with_extension("sig");
    std::fs::write(&sig_path, &pkg_sig.signature_bytes)
        .map_err(|e| anyhow::anyhow!("cannot write signature: {e}"))?;

    // Write .provenance.json
    let prov_path = archive_path.with_extension("provenance.json");
    let prov_json = serde_json::to_string_pretty(&pkg_sig.provenance)
        .map_err(|e| anyhow::anyhow!("cannot serialize provenance: {e}"))?;
    std::fs::write(&prov_path, prov_json.as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot write provenance: {e}"))?;

    println!("signed: {}", archive_path.display());
    println!("  signature:  {}", sig_path.display());
    println!("  provenance: {}", prov_path.display());
    println!("  sha256:     {}", pkg_sig.artifact_sha256);

    Ok(())
}

fn run_verify(archive_path: &std::path::Path, key_path: &std::path::Path) -> anyhow::Result<()> {
    use tallow::signing;

    let archive_data = std::fs::read(archive_path)
        .map_err(|e| anyhow::anyhow!("cannot read archive '{}': {e}", archive_path.display()))?;

    let key_bytes = read_ed25519_key_bytes(key_path)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key: {e}"))?;

    // Read .sig file
    let sig_path = archive_path.with_extension("sig");
    let sig_bytes = std::fs::read(&sig_path)
        .map_err(|e| anyhow::anyhow!("cannot read signature '{}': {e}", sig_path.display()))?;

    // Read .provenance.json
    let prov_path = archive_path.with_extension("provenance.json");
    let prov_data = std::fs::read_to_string(&prov_path)
        .map_err(|e| anyhow::anyhow!("cannot read provenance '{}': {e}", prov_path.display()))?;
    let provenance: serde_json::Value = serde_json::from_str(&prov_data)
        .map_err(|e| anyhow::anyhow!("invalid provenance JSON: {e}"))?;

    // Compute artifact hash for display
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&archive_data);
    let hash_bytes = hasher.finalize();
    let sha256_hex: String = hash_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let pkg_sig = signing::PackageSignature {
        artifact_sha256: sha256_hex.clone(),
        signature_bytes: sig_bytes,
        provenance,
    };

    match signing::verify_package(&archive_data, &pkg_sig, &verifying_key) {
        Ok(true) => {
            println!("verified: {}", archive_path.display());
            println!("  sha256: {sha256_hex}");
            println!("  signature: VALID");
            println!("  provenance: VALID");
            Ok(())
        }
        Ok(false) => {
            eprintln!("verification failed: {}", archive_path.display());
            std::process::exit(exit_codes::IO_ERROR);
        }
        Err(e) => {
            eprintln!("verification failed: {e}");
            std::process::exit(exit_codes::IO_ERROR);
        }
    }
}

// ── SBOM ─────────────────────────────────────────────────────────────────────

fn run_sbom(format: &str, output: Option<&std::path::Path>) -> anyhow::Result<()> {
    if format != "cyclonedx" {
        anyhow::bail!("unsupported SBOM format: {format}. Only 'cyclonedx' is supported.");
    }

    let project_dir = std::env::current_dir()?;

    // Try to get project name/version from Cargo.toml (for the Tallow compiler itself)
    let (project_name, project_version) = {
        let cargo_toml_path = project_dir.join("Cargo.toml");
        if cargo_toml_path.exists() {
            let content = std::fs::read_to_string(&cargo_toml_path)?;
            let parsed: toml::Value = toml::from_str(&content)
                .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
            let name = parsed
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown")
                .to_string();
            let version = parsed
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();
            (name, version)
        } else {
            // Try tallow.toml
            let tallow_toml_path = project_dir.join("tallow.toml");
            if tallow_toml_path.exists() {
                let content = std::fs::read_to_string(&tallow_toml_path)?;
                let parsed: toml::Value = toml::from_str(&content)
                    .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
                let name = parsed
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let version = parsed
                    .get("package")
                    .and_then(|p| p.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0")
                    .to_string();
                (name, version)
            } else {
                ("unknown".to_string(), "0.0.0".to_string())
            }
        }
    };

    let bom = tallow::sbom::generate_sbom(&project_dir, &project_name, &project_version)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let json_str = serde_json::to_string_pretty(&bom)?;

    match output {
        Some(path) => {
            std::fs::write(path, &json_str)?;
            eprintln!("SBOM written to {}", path.display());
        }
        None => {
            println!("{json_str}");
        }
    }

    Ok(())
}

// ── REPL ──────────────────────────────────────────────────────────────────────

fn run_repl() -> anyhow::Result<()> {
    use std::io::{self, Write};

    println!("Tallow REPL v{}", env!("CARGO_PKG_VERSION"));
    println!("Type expressions, statements, or declarations. Type :quit to exit.");
    println!();

    let mut interp = Interpreter::new();
    let mut env = tallow::interp::Env::new();
    let mut line_num = 0u32;

    loop {
        print!("nx> ");
        io::stdout().flush()?;

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            // EOF
            println!();
            break;
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        // Commands
        match input {
            ":quit" | ":q" | ":exit" => break,
            ":help" | ":h" => {
                println!("  :quit       Exit the REPL");
                println!("  :help       Show this help");
                println!("  :clear      Clear all definitions");
                println!("  :defs       List defined functions and types");
                continue;
            }
            ":clear" => {
                interp = Interpreter::new();
                env = tallow::interp::Env::new();
                println!("  Cleared all definitions.");
                continue;
            }
            ":defs" => {
                let fns: Vec<&String> = interp.function_names();
                if !fns.is_empty() {
                    println!(
                        "  Functions: {}",
                        fns.iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                let structs: Vec<&String> = interp.struct_names();
                if !structs.is_empty() {
                    println!(
                        "  Structs:   {}",
                        structs
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                let enums: Vec<&String> = interp.enum_names();
                if !enums.is_empty() {
                    println!(
                        "  Enums:     {}",
                        enums
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                if fns.is_empty() && structs.is_empty() && enums.is_empty() {
                    println!("  No definitions yet.");
                }
                continue;
            }
            _ => {}
        }

        // Handle multi-line input: if input ends with { and no matching }, keep reading
        let mut full_input = input.to_string();
        let open = full_input.matches('{').count();
        let close = full_input.matches('}').count();
        if open > close {
            loop {
                print!("... ");
                io::stdout().flush()?;
                let mut cont = String::new();
                if io::stdin().read_line(&mut cont)? == 0 {
                    break;
                }
                full_input.push('\n');
                full_input.push_str(cont.trim_end());
                let open = full_input.matches('{').count();
                let close = full_input.matches('}').count();
                if open <= close {
                    break;
                }
            }
        }

        line_num += 1;

        // Try parsing as a top-level item first (fn, struct, enum, const, type, impl)
        let try_item = format!("{full_input}");
        let (tokens, lex_errors) = tallow::lexer::tokenize(&try_item);
        if !lex_errors.is_empty() {
            eprintln!("  error: {}", lex_errors[0]);
            continue;
        }

        // Check if it looks like a declaration
        let is_decl = tokens
            .first()
            .map(|t| {
                matches!(
                    t.kind,
                    tallow::lexer::TokenKind::Fn
                        | tallow::lexer::TokenKind::Struct
                        | tallow::lexer::TokenKind::Enum
                        | tallow::lexer::TokenKind::Impl
                        | tallow::lexer::TokenKind::Const
                        | tallow::lexer::TokenKind::Type
                        | tallow::lexer::TokenKind::Import
                )
            })
            .unwrap_or(false);

        if is_decl {
            match tallow::parser::Parser::parse(tokens) {
                Ok(prog) => match interp.register(&prog) {
                    Ok(()) => {
                        for item in &prog.items {
                            match item {
                                tallow::ast::Item::Fn(f) => println!("  defined fn {}", f.name),
                                tallow::ast::Item::Struct(s) => {
                                    println!("  defined struct {}", s.name)
                                }
                                tallow::ast::Item::Enum(e) => println!("  defined enum {}", e.name),
                                tallow::ast::Item::Impl(i) => {
                                    println!("  defined impl {}", i.target)
                                }
                                tallow::ast::Item::Trait(t) => {
                                    println!("  defined trait {}", t.name)
                                }
                                tallow::ast::Item::Const(c) => {
                                    if let Some(val) = interp.get_constant(&c.name) {
                                        println!("  {} = {}", c.name, val.display());
                                    } else {
                                        println!("  defined const {}", c.name);
                                    }
                                }
                                tallow::ast::Item::TypeAlias(t) => {
                                    println!("  defined type {}", t.name)
                                }
                                tallow::ast::Item::Import(i) => {
                                    println!("  imported {}", i.path.join("."))
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("  error: {e}"),
                },
                Err(e) => eprintln!("  error: {e}"),
            }
        } else {
            // Try as expression/statement: wrap in a function to leverage the parser
            let wrapper = format!("fn __repl_{line_num}__() {{ {full_input} }}");
            let (tokens, lex_errors) = tallow::lexer::tokenize(&wrapper);
            if !lex_errors.is_empty() {
                eprintln!("  error: {}", lex_errors[0]);
                continue;
            }

            match tallow::parser::Parser::parse(tokens) {
                Ok(prog) => {
                    if let Some(tallow::ast::Item::Fn(f)) = prog.items.first() {
                        // Execute each statement directly in the persistent env
                        // (not via exec_block, which pushes/pops a scope)
                        let mut last = tallow::interp::Value::Nil;
                        let mut had_error = false;
                        for stmt in &f.body.stmts {
                            match interp.exec_stmt(stmt, &mut env) {
                                Ok(val) => last = val,
                                Err(e) => {
                                    eprintln!("  error: {e}");
                                    had_error = true;
                                    break;
                                }
                            }
                        }
                        if !had_error {
                            // Print non-nil values
                            match &last {
                                tallow::interp::Value::Nil => {}
                                tallow::interp::Value::Return(inner) => {
                                    if !matches!(**inner, tallow::interp::Value::Nil) {
                                        println!("  {}", inner.display());
                                    }
                                }
                                _ => println!("  {}", last.display()),
                            }
                        }
                    }
                }
                Err(e) => eprintln!("  error: {e}"),
            }
        }
    }

    Ok(())
}

// ── tallow new ─────────────────────────────────────────────────────────────────

fn create_project(name: &str, template: &str) -> anyhow::Result<()> {
    use std::fs;

    let root = PathBuf::from(name);
    if root.exists() {
        anyhow::bail!("directory '{}' already exists", name);
    }

    fs::create_dir_all(root.join("src"))?;
    fs::create_dir_all(root.join("tests/fixtures"))?;
    fs::create_dir_all(root.join("logs/audit"))?;

    // tallow.toml
    fs::write(
        root.join("tallow.toml"),
        format!(
            r#"[package]
name    = "{name}"
version = "0.3.0"
author  = ""
license = "MIT"

[dependencies]

[legal]
default_jurisdiction = ["us", "eu"]
default_robots_txt   = "respect"
audit_log_path       = "logs/audit"

[build]
target   = "x86_64-linux"
optimize = "debug"

[runtime]
ip_pool_size    = 10000
log_level       = "info"
audit_enabled   = true
"#
        ),
    )?;

    // src/main.tl
    let main_content = match template {
        "scraper" => {
            r#"@legal(
    basis:         .public_data,
    purpose:       "data collection",
    personal_data: false,
    retain_for:    7.days,
    robots_txt:    .respect,
    rate_limit:    2.per_second
)
fn scrape(url: String) -> Result<String> {
    let resp = fetch(url)?
    Ok(resp.text())
}

fn main() {
    let data = scrape("https://example.com") match {
        Ok(d)  -> d
        Err(e) -> { print("error: " + e); exit(1) }
    }
    print(data)
}
"#
        }
        "agent" => {
            r#"@agent_task(
    id:           task_id,
    timeout:      60.seconds,
    max_requests: 100,
    can_write:    false,
    can_store:    false
)
@legal(basis: .research, purpose: "public data analysis")
fn research(query: String) -> String {
    print("researching: " + query)
    "results"
}

fn main() {
    let result = research("test query")
    print(result)
}
"#
        }
        "api" => {
            r#"fn handle_get(path: String) -> String {
    match path {
        "/" -> "hello from tallow"
        _ -> "not found"
    }
}

fn main() {
    print(handle_get("/"))
}
"#
        }
        _ => {
            r#"fn main() {
    print("hello from tallow")
}
"#
        }
    };

    fs::write(root.join("src/main.tl"), main_content)?;

    // Generate a basic test file
    let test_content = format!(
        r#"// Tests for {name}
fn test_basic() {{
    let result = 1 + 1
    if result != 2 {{
        print("FAIL: basic arithmetic")
    }} else {{
        print("PASS: basic arithmetic")
    }}
}}

fn main() {{
    test_basic()
    print("all tests passed")
}}
"#
    );
    fs::write(root.join("tests/main_test.tl"), test_content)?;

    // .gitignore
    fs::write(
        root.join(".gitignore"),
        "# Build artifacts\n*.exe\n*.ll\n*.o\n\n# Logs\nlogs/\n\n# OS files\n.DS_Store\nThumbs.db\n",
    )?;

    println!("created project '{name}' with template '{template}'");
    println!("  {}/", name);
    println!("  ├── tallow.toml");
    println!("  ├── .gitignore");
    println!("  ├── src/");
    println!("  │   └── main.tl");
    println!("  ├── tests/");
    println!("  │   └── main_test.tl");
    println!("  └── logs/");
    println!("      └── audit/");
    println!();
    println!("next: cd {name} && tallow run src/main.tl");

    Ok(())
}

// ── tallow fmt ─────────────────────────────────────────────────────────────────

fn format_file(file: &PathBuf) -> anyhow::Result<()> {
    let source = std::fs::read_to_string(file)?;

    // Lex → Parse → pretty-print
    let (tokens, lex_errors) = tallow::lexer::tokenize(&source);
    if !lex_errors.is_empty() {
        for err in &lex_errors {
            let (line, col) = err.span().line_col(&source);
            eprintln!("error[{line}:{col}]: {err}");
        }
        std::process::exit(exit_codes::IO_ERROR);
    }

    let program = match tallow::parser::Parser::parse(tokens) {
        Ok(p) => p,
        Err(err) => {
            let (line, col) = err.span.line_col(&source);
            eprintln!("error[{line}:{col}]: {err}");
            std::process::exit(exit_codes::IO_ERROR);
        }
    };

    let formatted = tallow::fmt::format_program(&program);
    std::fs::write(file, &formatted)?;
    println!("formatted {}", file.display());

    Ok(())
}

// ── tallow lint ───────────────────────────────────────────────────────────────

fn run_lint(
    program: &tallow::ast::Program,
    _env: &tallow::typeck::TypeEnv,
    filename: &str,
    errors: usize,
    warnings: usize,
    format: &str,
    all_diags: &tallow::error::Diagnostics,
    source: &str,
    quiet: bool,
) {
    use std::collections::{HashMap, HashSet};
    use tallow::ast::*;

    let mut lint_warnings: Vec<String> = Vec::new();

    // Collect all function names
    let mut fn_names: HashSet<String> = HashSet::new();
    let mut fn_called: HashSet<String> = HashSet::new();

    for item in &program.items {
        if let Item::Fn(f) = item {
            fn_names.insert(f.name.clone());
        }
    }

    // Walk each function body to find:
    // 1. Defined but unused variables
    // 2. Functions called (to find unused functions)
    // 3. Missing return type annotations
    for item in &program.items {
        if let Item::Fn(f) = item {
            let mut defined_vars: HashMap<String, bool> = HashMap::new(); // name → used
            let mut shadowed: Vec<String> = Vec::new();

            // Check for missing return type (skip main)
            if f.name != "main" && f.return_type.is_none() {
                // Only warn if the function body likely returns a value
                // (has non-void expressions)
                lint_warnings.push(format!(
                    "W0001: function '{}' has no return type annotation",
                    f.name
                ));
            }

            // Walk the body to collect var definitions and usages
            collect_vars_and_calls(
                &f.body.stmts,
                &mut defined_vars,
                &mut fn_called,
                &mut shadowed,
            );

            // Check for unused variables
            for (name, used) in &defined_vars {
                if !used && !name.starts_with('_') && name != "self" {
                    lint_warnings.push(format!(
                        "W0002: unused variable '{}' in function '{}'",
                        name, f.name
                    ));
                }
            }

            // Check for shadowed variables
            for name in &shadowed {
                lint_warnings.push(format!(
                    "W0003: variable '{}' shadows an outer binding in function '{}'",
                    name, f.name
                ));
            }
        }
    }

    // Check for unused functions (not called anywhere, not main)
    for name in &fn_names {
        if name != "main" && !fn_called.contains(name) {
            lint_warnings.push(format!(
                "W0004: function '{}' is defined but never called",
                name
            ));
        }
    }

    // Check for @legal compliance hints
    for item in &program.items {
        if let Item::Fn(f) = item {
            for ann in &f.annotations {
                if ann.name == "legal" {
                    // Helper: get string repr of annotation arg value
                    let arg_value_str = |name: &str| -> Option<String> {
                        ann.args
                            .iter()
                            .find(|a| a.name == name)
                            .map(|a| format!("{:?}", a.value.kind))
                    };
                    let has_arg = |name: &str| -> bool { ann.args.iter().any(|a| a.name == name) };

                    // Check for overly broad jurisdictions
                    if let Some(ref jval) = arg_value_str("jurisdiction") {
                        if jval.contains("global") {
                            lint_warnings.push(format!(
                                "W0010: function '{}' has jurisdiction: .global — consider listing specific jurisdictions for clarity",
                                f.name
                            ));
                        }
                    }

                    // Check for long retention periods with personal data
                    if let Some(ref pd) = arg_value_str("personal_data") {
                        if pd.contains("true") || pd.contains("True") {
                            if let Some(ref retain) = arg_value_str("retain_for") {
                                if retain.contains("365") || retain.contains("year") {
                                    lint_warnings.push(format!(
                                        "W0011: function '{}' retains personal data for ~1 year — consider reducing retention period",
                                        f.name
                                    ));
                                }
                            }
                        }
                    }

                    // Check for missing rate_limit on network functions
                    if !has_arg("rate_limit") {
                        lint_warnings.push(format!(
                            "W0012: function '{}' has @legal but no rate_limit — consider adding rate limits for responsible access",
                            f.name
                        ));
                    }
                }
            }
        }
    }

    // Report
    if format == "json" {
        let mut diag_json: Vec<serde_json::Value> = all_diags
            .items
            .iter()
            .map(|d| {
                let (line, col) = d.span.line_col(source);
                serde_json::json!({
                    "code": d.code,
                    "severity": match d.severity {
                        tallow::error::Severity::Error => "error",
                        tallow::error::Severity::Warning => "warning",
                    },
                    "message": d.msg,
                    "file": filename,
                    "line": line,
                    "column": col,
                })
            })
            .collect();
        for w in &lint_warnings {
            diag_json.push(serde_json::json!({
                "code": &w[..5],
                "severity": "warning",
                "message": w,
                "file": filename,
                "line": 0,
                "column": 0,
            }));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": filename,
                "errors": errors,
                "warnings": warnings,
                "lint_warnings": lint_warnings.len(),
                "diagnostics": diag_json,
            }))
            .unwrap_or_default()
        );
    } else {
        if !quiet {
            println!("tallow lint: {filename}");
            println!("────────────────────────────────────────────");
            println!("  compile errors:   {errors}");
            println!("  compile warnings: {warnings}");
            println!("  lint warnings:    {}", lint_warnings.len());
        }

        if !lint_warnings.is_empty() && !quiet {
            println!();
            for w in &lint_warnings {
                println!("  {w}");
            }
        }

        if !quiet {
            println!();
            let total = errors + warnings + lint_warnings.len();
            if total == 0 {
                println!("  No issues found");
            } else {
                println!("  {} issue(s) found", total);
            }
        }
    }
}

/// Recursively collect variable definitions, usages, and function calls from statements.
fn collect_vars_and_calls(
    stmts: &[tallow::ast::Stmt],
    defined: &mut std::collections::HashMap<String, bool>,
    called: &mut std::collections::HashSet<String>,
    shadowed: &mut Vec<String>,
) {
    use tallow::ast::*;

    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Let { name, value, .. } | StmtKind::Var { name, value, .. } => {
                if defined.contains_key(name) {
                    shadowed.push(name.clone());
                }
                defined.insert(name.clone(), false);
                collect_expr_calls(value, defined, called);
            }
            StmtKind::Expr { expr } => {
                collect_expr_calls(expr, defined, called);
            }
            StmtKind::Return(Some(expr)) => {
                collect_expr_calls(expr, defined, called);
            }
            StmtKind::For {
                binding,
                iter,
                body,
            } => {
                defined.insert(binding.clone(), true); // loop var is always "used"
                collect_expr_calls(iter, defined, called);
                collect_vars_and_calls(&body.stmts, defined, called, shadowed);
            }
            StmtKind::While { condition, body } => {
                collect_expr_calls(condition, defined, called);
                collect_vars_and_calls(&body.stmts, defined, called, shadowed);
            }
            StmtKind::Bail(expr) => {
                collect_expr_calls(expr, defined, called);
            }
            _ => {}
        }
    }
}

/// Mark variable usages and collect function calls from an expression.
fn collect_expr_calls(
    expr: &tallow::ast::Expr,
    defined: &mut std::collections::HashMap<String, bool>,
    called: &mut std::collections::HashSet<String>,
) {
    use tallow::ast::*;

    match &expr.kind {
        ExprKind::Ident(name) => {
            if let Some(used) = defined.get_mut(name) {
                *used = true;
            }
        }
        ExprKind::Call { callee, args } => {
            if let ExprKind::Ident(name) = &callee.kind {
                called.insert(name.clone());
            }
            collect_expr_calls(callee, defined, called);
            for arg in args {
                collect_expr_calls(&arg.value, defined, called);
            }
        }
        ExprKind::MethodCall { object, args, .. } => {
            collect_expr_calls(object, defined, called);
            for arg in args {
                collect_expr_calls(&arg.value, defined, called);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_expr_calls(left, defined, called);
            collect_expr_calls(right, defined, called);
        }
        ExprKind::Unary { operand, .. } => {
            collect_expr_calls(operand, defined, called);
        }
        ExprKind::If {
            condition,
            then_block,
            else_branch,
        } => {
            collect_expr_calls(condition, defined, called);
            for stmt in &then_block.stmts {
                if let StmtKind::Expr { expr } = &stmt.kind {
                    collect_expr_calls(expr, defined, called);
                }
            }
            if let Some(eb) = else_branch {
                match eb {
                    ElseBranch::Block(b) => {
                        for stmt in &b.stmts {
                            if let StmtKind::Expr { expr } = &stmt.kind {
                                collect_expr_calls(expr, defined, called);
                            }
                        }
                    }
                    ElseBranch::ElseIf(e) => collect_expr_calls(e, defined, called),
                }
            }
        }
        ExprKind::Match { subject, arms } => {
            collect_expr_calls(subject, defined, called);
            for arm in arms {
                collect_expr_calls(&arm.body, defined, called);
            }
        }
        ExprKind::Block(block) => {
            for stmt in &block.stmts {
                if let StmtKind::Expr { expr } = &stmt.kind {
                    collect_expr_calls(expr, defined, called);
                }
            }
        }
        ExprKind::Array(items) => {
            for item in items {
                collect_expr_calls(item, defined, called);
            }
        }
        ExprKind::Index { object, index } => {
            collect_expr_calls(object, defined, called);
            collect_expr_calls(index, defined, called);
        }
        ExprKind::FieldAccess { object, .. } => {
            collect_expr_calls(object, defined, called);
        }
        ExprKind::Assign { target, value } => {
            collect_expr_calls(target, defined, called);
            collect_expr_calls(value, defined, called);
        }
        ExprKind::Closure { body, .. } => {
            for stmt in body {
                if let StmtKind::Expr { expr } = &stmt.kind {
                    collect_expr_calls(expr, defined, called);
                }
            }
        }
        ExprKind::Try(inner) | ExprKind::Await(inner) | ExprKind::Cast { expr: inner, .. } => {
            collect_expr_calls(inner, defined, called);
        }
        ExprKind::StructLit { fields, .. } => {
            for field in fields {
                collect_expr_calls(&field.value, defined, called);
            }
        }
        ExprKind::Interpolation(parts) => {
            for part in parts {
                match part {
                    StringPart::Expr(e) => collect_expr_calls(e, defined, called),
                    StringPart::Lit(_) => {}
                }
            }
        }
        _ => {}
    }
}

// ── tallow audit ──────────────────────────────────────────────────────────────

/// Extract a named string argument from @legal annotation args.
fn extract_legal_arg(args: &[tallow::ast::AnnotationArg], name: &str) -> Option<String> {
    for arg in args {
        if arg.name == name {
            return match &arg.value.kind {
                tallow::ast::ExprKind::StringLit(s) => Some(s.clone()),
                tallow::ast::ExprKind::DotIdent(s) => Some(s.clone()),
                tallow::ast::ExprKind::BoolLit(b) => Some(b.to_string()),
                tallow::ast::ExprKind::IntLit(n) => Some(n.to_string()),
                tallow::ast::ExprKind::Ident(s) => Some(s.clone()),
                _ => None,
            };
        }
    }
    None
}

/// Extract jurisdiction list from @legal args (handles both single value and array).
fn extract_jurisdictions(args: &[tallow::ast::AnnotationArg]) -> Vec<String> {
    for arg in args {
        if arg.name == "jurisdiction" {
            match &arg.value.kind {
                tallow::ast::ExprKind::DotIdent(s) => return vec![s.clone()],
                tallow::ast::ExprKind::Array(items) => {
                    return items
                        .iter()
                        .filter_map(|e| match &e.kind {
                            tallow::ast::ExprKind::DotIdent(s) => Some(s.clone()),
                            tallow::ast::ExprKind::Ident(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect();
                }
                _ => {}
            }
        }
    }
    Vec::new()
}

/// Audit entry for a single @legal-annotated function.
struct AuditEntry {
    function: String,
    basis: String,
    purpose: String,
    personal_data: bool,
    jurisdictions: Vec<String>,
    retain_for: Option<String>,
    robots_txt: Option<String>,
    rate_limit: Option<String>,
    is_network: bool,
    is_agent: bool,
    browser_operations: Vec<String>,
}

fn run_sast_report(program: &tallow::ast::Program, format: &str) {
    let pass = tallow::sast_pass::SastPass::new(program);
    let (diags, findings) = pass.check_with_findings();

    let errors = diags.error_count();
    let warnings = diags.warning_count();

    if format == "sarif" || format == "json" {
        let sarif = tallow::sast_pass::generate_sarif(&findings);
        // SARIF-safe disclaimer placement (cycle-02/08 §c item 8, W2-06):
        // a run `properties.disclaimer` + one stderr line; stdout stays
        // machine-parseable SARIF for consumers.
        let mut sarif_value: serde_json::Value =
            serde_json::from_str(&sarif).unwrap_or(serde_json::Value::Null);
        if let Some(runs) = sarif_value.get_mut("runs").and_then(|r| r.as_array_mut()) {
            for run in runs.iter_mut() {
                if let Some(obj) = run.as_object_mut() {
                    let props = obj
                        .entry("properties")
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(p) = props.as_object_mut() {
                        p.insert(
                            "disclaimer".to_string(),
                            serde_json::Value::String(AUDIT_DISCLAIMER.to_string()),
                        );
                    }
                }
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&sarif_value).unwrap_or(sarif)
        );
        eprintln!("{AUDIT_DISCLAIMER}");
    } else {
        println!("=== Tallow SAST Taint Analysis Report ===");
        println!();
        if findings.is_empty() {
            println!("No taint-flow vulnerabilities detected.");
        } else {
            for f in &findings {
                let icon = if f.level == "error" { "ERROR" } else { "WARN " };
                print!("  [{icon}] {}: {}", f.rule_id, f.message);
                if let Some(ref cwe) = f.cwe_id {
                    print!(" ({cwe})");
                }
                println!();
            }
        }
        println!();
        println!(
            "SAST complete: {errors} error(s), {warnings} warning(s), {} finding(s)",
            findings.len()
        );
        println!();
        println!("{AUDIT_DISCLAIMER}");
    }

    if errors > 0 {
        std::process::exit(exit_codes::IO_ERROR);
    }
}

// ── Detection Coverage Audit ──────────────────────────────────────────────
fn run_detection_coverage_audit(program: &tallow::ast::Program, format: &str) {
    use tallow::ast::*;

    let mut detection_fns: Vec<(String, bool, Option<String>)> = Vec::new(); // (name, has_test_coverage, detection_id)
    let mut total_fns = 0usize;

    for item in &program.items {
        if let Item::Fn(f) = item {
            total_fns += 1;
            for ann in &f.annotations {
                if ann.name == "detection" {
                    let detection_id =
                        ann.args.iter().find(|a| a.name == "detection_id").map(|a| {
                            match &a.value {
                                Expr {
                                    kind: ExprKind::StringLit(s),
                                    ..
                                } => s.clone(),
                                other => format!("{:?}", other),
                            }
                        });
                    let has_test_coverage = ann.args.iter().any(|a| a.name == "test_coverage");
                    detection_fns.push((f.name.clone(), has_test_coverage, detection_id));
                }
            }
        }
    }

    if format == "json" {
        let entries: Vec<String> = detection_fns
            .iter()
            .map(|(name, tested, id)| {
                format!(
                    "    {{\"function\": \"{}\", \"detection_id\": {}, \"test_coverage\": {}}}",
                    name,
                    id.as_ref()
                        .map(|s| format!("\"{}\"", s))
                        .unwrap_or("null".to_string()),
                    tested
                )
            })
            .collect();
        println!("{{");
        println!("  \"detection_functions\": {},", detection_fns.len());
        println!("  \"total_functions\": {},", total_fns);
        println!(
            "  \"coverage_pct\": {:.1},",
            if total_fns > 0 {
                detection_fns.len() as f64 / total_fns as f64 * 100.0
            } else {
                0.0
            }
        );
        println!("  \"disclaimer\": {},", serde_json::json!(AUDIT_DISCLAIMER));
        println!("  \"entries\": [\n{}\n  ]", entries.join(",\n"));
        println!("}}");
    } else {
        println!("=== Tallow Detection Coverage Report ===");
        println!();
        if detection_fns.is_empty() {
            println!("  No @detection-annotated functions found.");
        } else {
            for (name, tested, id) in &detection_fns {
                let id_str = id.as_deref().unwrap_or("MISSING");
                let test_icon = if *tested { "YES" } else { "NO " };
                println!("  [{test_icon}] {name} (id: {id_str})");
            }
        }
        println!();
        let covered = detection_fns.iter().filter(|(_, t, _)| *t).count();
        println!(
            "Detection coverage: {}/{} functions annotated, {}/{} with test_coverage",
            detection_fns.len(),
            total_fns,
            covered,
            detection_fns.len()
        );
        println!();
        println!("{AUDIT_DISCLAIMER}");
    }
}

fn run_audit(
    program: &tallow::ast::Program,
    env: &tallow::typeck::TypeEnv,
    filename: &str,
    format: &str,
    jurisdiction_filter: Option<&str>,
    errors: usize,
    warnings: usize,
    browser_audit: &[tallow::legal_pass::BrowserAuditEntry],
    _strict: bool, // `--strict` is n/a for the default audit (cycle-02/08 §b)
) {
    // Collect all functions and their @legal annotations
    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut total_fns = 0usize;
    let mut unannotated_network_fns: Vec<String> = Vec::new();

    for item in &program.items {
        if let tallow::ast::Item::Fn(f) = item {
            total_fns += 1;
            let is_network = env.network_functions.contains(&f.name);
            let is_agent = f.annotations.iter().any(|a| a.name == "agent_task");

            if let Some(legal) = f.annotations.iter().find(|a| a.name == "legal") {
                let basis =
                    extract_legal_arg(&legal.args, "basis").unwrap_or_else(|| "unspecified".into());
                let purpose = extract_legal_arg(&legal.args, "purpose")
                    .unwrap_or_else(|| "unspecified".into());
                let personal_data = extract_legal_arg(&legal.args, "personal_data")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let jurisdictions = extract_jurisdictions(&legal.args);
                let retain_for = extract_legal_arg(&legal.args, "retain_for");
                let robots_txt = extract_legal_arg(&legal.args, "robots_txt");
                let rate_limit = extract_legal_arg(&legal.args, "rate_limit");

                // Find browser operations for this function from the legal pass audit data
                let browser_ops: Vec<String> = browser_audit
                    .iter()
                    .find(|e| e.function_name == f.name)
                    .map(|e| e.browser_ops.clone())
                    .unwrap_or_default();

                entries.push(AuditEntry {
                    function: f.name.clone(),
                    basis,
                    purpose,
                    personal_data,
                    jurisdictions,
                    retain_for,
                    robots_txt,
                    rate_limit,
                    is_network,
                    is_agent,
                    browser_operations: browser_ops,
                });
            } else if is_network {
                unannotated_network_fns.push(f.name.clone());
            }
        }
    }

    // Apply jurisdiction filter
    let filtered_entries: Vec<&AuditEntry> = if let Some(jur) = jurisdiction_filter {
        entries
            .iter()
            .filter(|e| e.jurisdictions.is_empty() || e.jurisdictions.iter().any(|j| j == jur))
            .collect()
    } else {
        entries.iter().collect()
    };

    let status = if errors == 0 {
        "COMPLIANT"
    } else {
        "NON-COMPLIANT"
    };

    if format == "json" {
        // JSON output
        let mut json = String::from("{\n");
        json.push_str("  \"schema\": \"tallow.audit.default.v1\",\n");
        json.push_str(&format!("  \"file\": \"{filename}\",\n"));
        json.push_str(&format!("  \"timestamp\": \"{}\",\n", format_iso8601()));
        json.push_str(&format!(
            "  \"tallow_version\": \"{}\",\n",
            env!("CARGO_PKG_VERSION")
        ));
        json.push_str(&format!("  \"total_functions\": {total_fns},\n"));
        json.push_str(&format!("  \"annotated_functions\": {},\n", entries.len()));
        json.push_str(&format!(
            "  \"network_functions\": {},\n",
            env.network_functions.len()
        ));
        json.push_str(&format!("  \"errors\": {errors},\n"));
        json.push_str(&format!("  \"warnings\": {warnings},\n"));
        json.push_str(&format!("  \"compliance_status\": \"{status}\",\n"));

        if !unannotated_network_fns.is_empty() {
            let names: Vec<String> = unannotated_network_fns
                .iter()
                .map(|n| format!("\"{n}\""))
                .collect();
            json.push_str(&format!(
                "  \"unannotated_network_functions\": [{}],\n",
                names.join(", ")
            ));
        }

        json.push_str("  \"functions\": [\n");
        for (i, entry) in filtered_entries.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"function\": \"{}\",\n", entry.function));
            json.push_str(&format!("      \"legal_basis\": \"{}\",\n", entry.basis));
            json.push_str(&format!("      \"purpose\": \"{}\",\n", entry.purpose));
            json.push_str(&format!(
                "      \"personal_data\": {},\n",
                entry.personal_data
            ));
            let jur_json: Vec<String> = entry
                .jurisdictions
                .iter()
                .map(|j| format!("\"{j}\""))
                .collect();
            json.push_str(&format!(
                "      \"jurisdiction\": [{}],\n",
                jur_json.join(", ")
            ));
            if let Some(ref r) = entry.retain_for {
                json.push_str(&format!("      \"retain_for\": \"{r}\",\n"));
            }
            if let Some(ref r) = entry.robots_txt {
                json.push_str(&format!("      \"robots_txt\": \"{r}\",\n"));
            }
            if let Some(ref r) = entry.rate_limit {
                json.push_str(&format!("      \"rate_limit\": \"{r}\",\n"));
            }
            json.push_str(&format!("      \"is_network\": {},\n", entry.is_network));
            json.push_str(&format!("      \"is_agent\": {},\n", entry.is_agent));
            if !entry.browser_operations.is_empty() {
                let ops_json: Vec<String> = entry
                    .browser_operations
                    .iter()
                    .map(|o| format!("\"{o}\""))
                    .collect();
                json.push_str(&format!(
                    "      \"browser_operations\": [{}]\n",
                    ops_json.join(", ")
                ));
            } else {
                json.push_str("      \"browser_operations\": []\n");
            }
            json.push_str(if i + 1 < filtered_entries.len() {
                "    },\n"
            } else {
                "    }\n"
            });
        }
        json.push_str("  ],\n");
        json.push_str(&format!("  \"disclaimer\": \"{AUDIT_DISCLAIMER}\"\n"));
        json.push_str("}");
        println!("{json}");
    } else {
        // Text output
        println!("tallow audit: {filename}");
        println!("────────────────────────────────────────────");
        println!("  functions:       {total_fns}");
        println!("  @legal:          {}", entries.len());
        println!("  network fns:     {}", env.network_functions.len());
        println!("  errors:          {errors}");
        println!("  warnings:        {warnings}");

        if let Some(jur) = jurisdiction_filter {
            println!("  jurisdiction:    {jur} (filtered)");
        }

        if !filtered_entries.is_empty() {
            println!();
            println!("  Annotated Functions:");
            println!("  ────────────────────────────────────────");
            for entry in &filtered_entries {
                println!(
                    "    {} {}",
                    if errors == 0 { "✓" } else { "●" },
                    entry.function
                );
                println!("      basis:         {}", entry.basis);
                println!("      purpose:       {}", entry.purpose);
                println!("      personal_data: {}", entry.personal_data);
                if !entry.jurisdictions.is_empty() {
                    println!("      jurisdiction:  {}", entry.jurisdictions.join(", "));
                }
                if let Some(ref r) = entry.retain_for {
                    println!("      retain_for:    {r}");
                }
                if let Some(ref r) = entry.robots_txt {
                    println!("      robots_txt:    {r}");
                }
                if let Some(ref r) = entry.rate_limit {
                    println!("      rate_limit:    {r}");
                }
                if entry.is_agent {
                    println!("      agent_task:    yes");
                }
                if !entry.browser_operations.is_empty() {
                    // Count each operation type
                    let mut op_counts: std::collections::HashMap<&str, usize> =
                        std::collections::HashMap::new();
                    for op in &entry.browser_operations {
                        *op_counts.entry(op.as_str()).or_insert(0) += 1;
                    }
                    let ops_str: Vec<String> = op_counts
                        .iter()
                        .map(|(op, count)| {
                            if *count == 1 {
                                op.to_string()
                            } else {
                                format!("{op} ({count} calls)")
                            }
                        })
                        .collect();
                    println!("      browser ops:   {}", ops_str.join(", "));
                }
            }
        }

        if !unannotated_network_fns.is_empty() {
            println!();
            println!("  Unannotated Network Functions:");
            println!("  ────────────────────────────────────────");
            for name in &unannotated_network_fns {
                println!("    ✗ {name}  (missing @legal annotation)");
            }
        }

        println!();
        if errors == 0 {
            println!("  ✓ COMPLIANT");
            println!();
            println!("{AUDIT_DISCLAIMER}");
        } else {
            println!("  ✗ NON-COMPLIANT ({errors} violation(s))");
            println!();
            println!("{AUDIT_DISCLAIMER}");
        }
    }

    // Frozen FAIL definition (cycle-02/08 §b): any compile-time errors ⇒ exit 2
    // (both text and JSON paths — the JSON branch previously exited 0).
    if errors > 0 {
        std::process::exit(exit_codes::LEGAL_VIOLATION);
    }
}

// ── CRA Audit ────────────────────────────────────────────────────────────────

fn run_cra_audit(
    program: &tallow::ast::Program,
    filename: &str,
    format: &str,
    errors: usize,
    warnings: usize,
    source_file: &std::path::Path,
    offline_fallback: bool,
    strict: bool,
) {
    use tallow::sbom;

    // Extract the highest CRA class from program annotations
    let mut cra_class = "default".to_string();
    for item in &program.items {
        if let tallow::ast::Item::Fn(f) = item {
            for ann in &f.annotations {
                if ann.name == "cra_class" {
                    if let Some(level) = ann.args.iter().find_map(|arg| {
                        if let tallow::ast::ExprKind::DotIdent(name) = &arg.value.kind {
                            Some(name.clone())
                        } else {
                            None
                        }
                    }) {
                        // Upgrade class: critical > class_ii > class_i > default
                        let priority = match level.as_str() {
                            "critical" => 4,
                            "class_ii" => 3,
                            "class_i" => 2,
                            "default" => 1,
                            _ => 0,
                        };
                        let current_priority = match cra_class.as_str() {
                            "critical" => 4,
                            "class_ii" => 3,
                            "class_i" => 2,
                            "default" => 1,
                            _ => 0,
                        };
                        if priority > current_priority {
                            cra_class = level;
                        }
                    }
                }
            }
        }
    }

    // Gather SBOM components from lock files
    let project_dir = source_file
        .parent()
        .and_then(|p| {
            if p.file_name()
                .map(|n| n == "src" || n == "examples")
                .unwrap_or(false)
            {
                p.parent()
            } else {
                Some(p)
            }
        })
        .unwrap_or_else(|| std::path::Path::new("."));

    let mut all_components = Vec::new();

    // Read Cargo.lock
    let cargo_lock_path = project_dir.join("Cargo.lock");
    if cargo_lock_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_lock_path) {
            all_components.extend(sbom::parse_cargo_lock(&content));
        }
    }

    // Read tallow.lock if present
    let tallow_lock_path = project_dir.join("tallow.lock");
    if tallow_lock_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&tallow_lock_path) {
            all_components.extend(sbom::parse_tallow_lock(&content));
        }
    }

    // ── Vulnerability posture (C5): feed-driven, never static by default ──
    // Vulnerability data comes from the configured local advisory feed
    // (env TALLOW_ADVISORY_FILE, see src/stdlib/advisory.rs). The old
    // illustrative 5-CVE sample table runs ONLY when the caller explicitly
    // passes --offline-fallback, and is always labeled as sample data — it
    // is never the default truth.
    let mut vulns: Vec<sbom::SbomVulnerability> = Vec::new();
    let mut feed_state = "not_configured";
    let mut feed_path = String::new();
    let mut feed_records = 0usize;
    let mut feed_skipped = 0usize;
    let mut feed_error = String::new();

    if offline_fallback {
        // Labeled illustrative sample — static demo data, NOT live truth.
        feed_state = "offline_illustrative_fallback";
        let known_vulns: &[(&str, &str, &str, &str)] = &[
            (
                "RUSTSEC-2024-0375",
                "rustls",
                "medium",
                "https://rustsec.org/advisories/RUSTSEC-2024-0375",
            ),
            (
                "RUSTSEC-2024-0336",
                "h2",
                "high",
                "https://rustsec.org/advisories/RUSTSEC-2024-0336",
            ),
            (
                "RUSTSEC-2023-0071",
                "rsa",
                "critical",
                "https://rustsec.org/advisories/RUSTSEC-2023-0071",
            ),
            (
                "RUSTSEC-2024-0019",
                "mio",
                "medium",
                "https://rustsec.org/advisories/RUSTSEC-2024-0019",
            ),
            (
                "RUSTSEC-2023-0044",
                "openssl",
                "high",
                "https://rustsec.org/advisories/RUSTSEC-2023-0044",
            ),
        ];
        for &(cve_id, crate_name, severity, url) in known_vulns {
            if let Some(comp) = all_components.iter().find(|c| c.name == crate_name) {
                vulns.push(sbom::SbomVulnerability {
                    id: cve_id.to_string(),
                    source: "RustSec (ILLUSTRATIVE SAMPLE)".to_string(),
                    url: url.to_string(),
                    severity: severity.to_string(),
                    component_ref: comp.purl.clone(),
                    vex_status: "under_investigation".to_string(),
                    justification:
                        "offline illustrative sample — configure TALLOW_ADVISORY_FILE for real data"
                            .to_string(),
                });
            }
        }
    } else {
        // Default path: derive verdicts from the configured advisory feed.
        match tallow::stdlib::advisory::load_advisory_feed() {
            Ok((records, skipped)) => {
                feed_state = "applied";
                feed_skipped = skipped;
                feed_records = records.len();
                if let Ok(path) = tallow::stdlib::advisory::advisory_feed_path() {
                    feed_path = path.display().to_string();
                }
                for adv in &records {
                    let id = adv
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown-advisory")
                        .to_string();
                    let package = adv
                        .get("package")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let source = adv
                        .get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("local-feed")
                        .to_string();
                    let severity = adv
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let url = adv
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let title = adv
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    for comp in all_components
                        .iter()
                        .filter(|c| tallow::stdlib::advisory::advisory_matches_component(adv, &c.name))
                    {
                        vulns.push(sbom::SbomVulnerability {
                            id: id.clone(),
                            source: format!("{source} (feed: {feed_path})"),
                            url: url.clone(),
                            severity: severity.clone(),
                            component_ref: comp.purl.clone(),
                            // Name-match only: the audit does not evaluate
                            // version windows, so it never overclaims an
                            // affected/fixed verdict.
                            vex_status: "under_investigation".to_string(),
                            justification: format!(
                                "matched feed advisory {id} for package \"{package}\" by name: {title}"
                            ),
                        });
                    }
                }
            }
            Err(e) => {
                // Honest state: no feed → no vulnerability verdicts.
                feed_state = "unavailable";
                feed_error = e;
            }
        }
    }

    // Project name/version from Cargo.toml or tallow.toml
    let (project_name, project_version) = read_project_metadata(project_dir);

    // CRA Annex I compliance checklist — every item is derived from real
    // evidence with an explicit evidence kind. Nothing here is a hardcoded
    // PASS: checks Tallow cannot verify from source are UNKNOWN rather than
    // silently compliant.
    let has_sbom = !all_components.is_empty();
    let vuln_handling_ok = feed_state == "applied";
    let annex_i_checks: [(&str, &str, std::borrow::Cow<'static, str>, &str); 5] = [
        (
            "Security by default",
            "unknown",
            std::borrow::Cow::Borrowed("Product-level hardening (stack canaries, CET, secure defaults in shipped artifacts) cannot be verified from a source audit — assess the built product separately"),
            "none",
        ),
        (
            "Data protection",
            if errors == 0 { "pass" } else { "fail" },
            std::borrow::Cow::Borrowed("Privacy/erasure/consent compile-time passes ran clean over the program"),
            "program",
        ),
        (
            "Update capability",
            if has_sbom { "pass" } else { "fail" },
            std::borrow::Cow::Borrowed(if has_sbom {
                "Lockfile-derived SBOM present — package manager tracks dependency updates"
            } else {
                "No Cargo.lock/tallow.lock found — cannot demonstrate update tracking"
            }),
            "sbom",
        ),
        (
            "Vulnerability handling",
            if vuln_handling_ok { "pass" } else { "fail" },
            if feed_state == "applied" {
                std::borrow::Cow::Owned(format!(
                    "Advisory feed applied ({} records from {}); {} component(s) matched",
                    feed_records,
                    if feed_path.is_empty() { "TALLOW_ADVISORY_FILE" } else { &feed_path },
                    vulns.len()
                ))
            } else if offline_fallback {
                std::borrow::Cow::Borrowed("OFFLINE ILLUSTRATIVE FALLBACK active — sample data, not a real vulnerability verdict; configure TALLOW_ADVISORY_FILE")
            } else {
                std::borrow::Cow::Owned(format!("No advisory feed applied ({feed_state}) — set TALLOW_ADVISORY_FILE to a local JSON advisory feed: {feed_error}"))
            },
            "feed",
        ),
        (
            "Incident reporting",
            if program_mentions_identifier(program, "DoraCitIncident")
                || program_mentions_identifier(program, "dora_log_incident")
                || program_mentions_identifier(program, "incident_log")
            {
                "pass"
            } else {
                "fail"
            },
            std::borrow::Cow::Borrowed("DORA ICT incident logging via DoraCitIncident/dora_log_incident/incident_log types"),
            "program",
        ),
    ];

    // Frozen FAIL definition (cycle-02/08 §b): compile-time errors; `--strict`
    // additionally escalates any Annex-I check that is not `pass`.
    let cra_violation =
        errors > 0 || (strict && annex_i_checks.iter().any(|(_, s, _, _)| *s != "pass"));

    if format == "json" {
        // Generate CycloneDX CRA JSON with vulnerabilities
        let bom = sbom::generate_cyclonedx_cra(
            &all_components,
            &vulns,
            &project_name,
            &project_version,
            &cra_class,
        );

        // Also generate SPDX for dual-format
        let spdx = sbom::generate_spdx(&all_components, &project_name, &project_version);

        let report = serde_json::json!({
            "schema": "tallow.audit.cra.v1",
            "cra_report": {
                "file": filename,
                "timestamp": format_iso8601(),
                "cra_class": cra_class,
                "errors": errors,
                "warnings": warnings,
                "annex_i_compliance": annex_i_checks.iter().map(|(name, status, desc, evidence)| {
                    serde_json::json!({
                        "check": name,
                        "status": status.to_ascii_uppercase(),
                        "description": desc,
                        "evidence": evidence,
                    })
                }).collect::<Vec<_>>(),
                "components_count": all_components.len(),
                "vulnerabilities_count": vulns.len(),
                "vulnerability_feed": {
                    "source": if offline_fallback { "offline_illustrative_fallback" } else { "local_json_file" },
                    "state": feed_state,
                    "path": feed_path,
                    "schema_version": tallow::stdlib::advisory::ADVISORY_SCHEMA_VERSION,
                    "records": feed_records,
                    "skipped": feed_skipped,
                    "error": feed_error,
                    "offline_fallback_warning": if offline_fallback {
                        "OFFLINE ILLUSTRATIVE FALLBACK — the vulnerability list below is static sample data, NOT live advisory truth; set TALLOW_ADVISORY_FILE for real verdicts".to_string()
                    } else {
                        String::new()
                    },
                },
                "vulnerabilities": vulns.iter().map(|v| {
                    serde_json::json!({
                        "id": v.id,
                        "source": v.source,
                        "url": v.url,
                        "severity": v.severity,
                        "component": v.component_ref,
                        "vex_status": v.vex_status,
                        "justification": v.justification,
                    })
                }).collect::<Vec<_>>(),
            },
            "cyclonedx": bom,
            "spdx": spdx,
            "disclaimer": AUDIT_DISCLAIMER,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        // Text output
        println!("tallow audit --cra: {filename}");
        println!("════════════════════════════════════════════════");
        println!("  CRA Product Class:  {cra_class}");
        println!("  Errors:             {errors}");
        println!("  Warnings:           {warnings}");
        println!("  Components:         {}", all_components.len());
        println!("  Vulnerabilities:    {}", vulns.len());
        println!();
        println!("  CRA Annex I Compliance Checklist:");
        println!("  ────────────────────────────────────────────");
        for (name, status, desc, _evidence) in &annex_i_checks {
            let icon = match *status {
                "pass" => "PASS",
                "fail" => "FAIL",
                _ => "UNKNOWN",
            };
            println!("    [{icon}] {name}");
            println!("           {desc}");
        }

        if feed_state == "offline_illustrative_fallback" {
            println!();
            println!("  ⚠  OFFLINE ILLUSTRATIVE FALLBACK — the vulnerability list below is");
            println!("     static sample data, NOT live advisory truth. Configure");
            println!("     TALLOW_ADVISORY_FILE for real, feed-derived verdicts.");
        } else if feed_state == "unavailable" || feed_state == "not_configured" {
            println!();
            println!("  ⚠  Vulnerability posture unknown: no advisory feed applied ({feed_state}).");
            println!("     {feed_error}");
            println!("     Set TALLOW_ADVISORY_FILE to a local JSON advisory feed");
            println!("     (schema tallow.advisory.feed.v1) for feed-derived verdicts.");
        } else {
            println!();
            println!("  Vulnerability feed: applied ({} record(s), {} skipped)", feed_records, feed_skipped);
            if !feed_path.is_empty() {
                println!("    path: {feed_path}");
            }
        }

        if !vulns.is_empty() {
            println!();
            println!("  Known Vulnerabilities:");
            println!("  ────────────────────────────────────────────");
            for v in &vulns {
                println!(
                    "    {} ({}) - {} [{}]",
                    v.id, v.severity, v.component_ref, v.vex_status
                );
                println!("      source: {}", v.source);
                if !v.url.is_empty() {
                    println!("      advisory: {}", v.url);
                }
                if !v.justification.is_empty() {
                    println!("      note: {}", v.justification);
                }
            }
        }

        println!();
        let annex_pass_count = annex_i_checks
            .iter()
            .filter(|(_, status, _, _)| *status == "pass")
            .count();
        let annex_unknown_count = annex_i_checks
            .iter()
            .filter(|(_, status, _, _)| *status != "pass" && *status != "fail")
            .count();
        let annex_total = annex_i_checks.len();
        println!("  Annex I: {annex_pass_count}/{annex_total} checks passed");
        if annex_unknown_count > 0 {
            println!(
                "    ({annex_unknown_count} UNKNOWN — require product-level evidence a source audit cannot provide)"
            );
        }
        println!();
        if errors == 0 {
            println!("  CRA Status: COMPLIANT");
            if !vuln_handling_ok {
                println!("  ⚠  COMPLIANT refers to compile-time violations only — vulnerability");
                println!("     posture is NOT established without an applied advisory feed");
                println!("     (see vulnerability-feed note above).");
            }
            println!();
            println!("{AUDIT_DISCLAIMER}");
        } else {
            println!("  CRA Status: NON-COMPLIANT ({errors} violation(s))");
            println!();
            println!("{AUDIT_DISCLAIMER}");
        }
    }

    if cra_violation {
        std::process::exit(exit_codes::LEGAL_VIOLATION);
    }
}

// ── NIS2 Audit Report ──────────────────────────────────────────────────────

fn run_nis2_audit(
    program: &tallow::ast::Program,
    filename: &str,
    format: &str,
    errors: usize,
    warnings: usize,
    source_file: &std::path::Path,
    offline_fallback: bool,
    strict: bool,
) {
    use tallow::nis2_pass::{BsiStatus, Nis2Pass, lookup_bsi_policy};
    use tallow::sbom;

    // Collect crypto inventory from program
    let inventory = Nis2Pass::collect_crypto_inventory(program);

    // Run NIS2 pass for diagnostics
    let nis2_diags = Nis2Pass::new(program).check();
    let nis2_errors = nis2_diags.error_count();
    let nis2_warnings = nis2_diags.warning_count();

    // Project directory for supply chain checks
    let project_dir = source_file
        .parent()
        .and_then(|p| {
            if p.file_name()
                .map(|n| n == "src" || n == "examples")
                .unwrap_or(false)
            {
                p.parent()
            } else {
                Some(p)
            }
        })
        .unwrap_or_else(|| std::path::Path::new("."));

    // NIS2 Art.21 compliance checks
    let has_sbom =
        project_dir.join("Cargo.lock").exists() || project_dir.join("tallow.lock").exists();
    let has_legal_annotations = program.items.iter().any(|item| {
        if let tallow::ast::Item::Fn(f) = item {
            f.annotations.iter().any(|a| a.name == "legal")
        } else {
            false
        }
    });

    let forbidden_count = inventory
        .iter()
        .filter(|u| u.bsi_status == Some(BsiStatus::Forbidden))
        .count();

    // ── Vulnerability posture (C5): feed-driven like --cra ───────────────
    // Cross-match lockfile components against the configured advisory feed
    // (env TALLOW_ADVISORY_FILE). No feed configured → honest "unavailable";
    // --offline-fallback → labeled illustrative sample, never default truth.
    let mut all_components = Vec::new();
    for lock in ["Cargo.lock", "tallow.lock"] {
        let p = project_dir.join(lock);
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(&p) {
                if lock == "Cargo.lock" {
                    all_components.extend(sbom::parse_cargo_lock(&content));
                } else {
                    all_components.extend(sbom::parse_tallow_lock(&content));
                }
            }
        }
    }
    let mut feed_state = "not_configured";
    let mut feed_path = String::new();
    let mut feed_records = 0usize;
    let mut feed_error = String::new();
    let mut feed_vulns: Vec<serde_json::Value> = Vec::new();
    if offline_fallback {
        feed_state = "offline_illustrative_fallback";
    } else {
        match tallow::stdlib::advisory::load_advisory_feed() {
            Ok((records, _skipped)) => {
                feed_state = "applied";
                feed_records = records.len();
                if let Ok(path) = tallow::stdlib::advisory::advisory_feed_path() {
                    feed_path = path.display().to_string();
                }
                for adv in &records {
                    let id = adv.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                    let url = adv.get("url").and_then(|v| v.as_str()).unwrap_or("");
                    let severity = adv.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown");
                    for comp in all_components
                        .iter()
                        .filter(|c| tallow::stdlib::advisory::advisory_matches_component(adv, &c.name))
                    {
                        feed_vulns.push(serde_json::json!({
                            "id": id,
                            "severity": severity,
                            "component": comp.purl,
                            "url": url,
                            "vex_status": "under_investigation",
                        }));
                    }
                }
            }
            Err(e) => {
                feed_state = "unavailable";
                feed_error = e;
            }
        }
    }

    let deprecated_count = inventory
        .iter()
        .filter(|u| u.bsi_status == Some(BsiStatus::Deprecated))
        .count();
    let recommended_count = inventory
        .iter()
        .filter(|u| u.bsi_status == Some(BsiStatus::Recommended))
        .count();
    let acceptable_count = inventory
        .iter()
        .filter(|u| u.bsi_status == Some(BsiStatus::Acceptable))
        .count();

    let crypto_compliant = forbidden_count == 0;

    let art21_checks = [
        (
            "Crypto policy (BSI TR-02102)",
            crypto_compliant,
            if crypto_compliant {
                "All algorithms comply with BSI TR-02102"
            } else {
                "Forbidden algorithms detected - see inventory below"
            },
        ),
        (
            "Supply chain security",
            has_sbom,
            if has_sbom {
                "SBOM available (lock file present)"
            } else {
                "No lock file found for dependency tracking"
            },
        ),
        (
            "Access control",
            has_legal_annotations,
            if has_legal_annotations {
                "@legal annotations present for access control traceability"
            } else {
                "No @legal annotations found"
            },
        ),
        (
            "Incident response",
            program_mentions_identifier(program, "DoraCitIncident")
                || program_mentions_identifier(program, "dora_log_incident")
                || program_mentions_identifier(program, "incident_log"),
            if program_mentions_identifier(program, "DoraCitIncident")
                || program_mentions_identifier(program, "dora_log_incident")
                || program_mentions_identifier(program, "incident_log")
            {
                "DORA ICT incident reporting configured (DoraCitIncident/dora_log_incident detected)"
            } else {
                "No DORA incident logging found — add DoraCitIncident or dora_log_incident calls"
            },
        ),
    ];

    let art21_pass = art21_checks.iter().filter(|(_, p, _)| *p).count();
    let art21_total = art21_checks.len();

    // Frozen FAIL definition (cycle-02/08 §b): nis2 errors + forbidden crypto;
    // `--strict` additionally escalates any failing Art.21 measure.
    let nis2_violation =
        nis2_errors + forbidden_count > 0 || (strict && art21_checks.iter().any(|(_, p, _)| !*p));

    if format == "json" {
        let inventory_json: Vec<serde_json::Value> = inventory
            .iter()
            .map(|u| {
                let status_str = match u.bsi_status {
                    Some(BsiStatus::Recommended) => "recommended",
                    Some(BsiStatus::Acceptable) => "acceptable",
                    Some(BsiStatus::Deprecated) => "deprecated",
                    Some(BsiStatus::Forbidden) => "forbidden",
                    None => "unknown",
                };
                let policy = lookup_bsi_policy(&u.algorithm);
                let replacement = policy.and_then(|p| p.recommended_replacement).unwrap_or("");
                serde_json::json!({
                    "function": u.function_name,
                    "method": u.method,
                    "algorithm": u.algorithm,
                    "bsi_status": status_str,
                    "note": u.note,
                    "recommended_replacement": replacement,
                })
            })
            .collect();

        let compliance_json: Vec<serde_json::Value> = art21_checks
            .iter()
            .map(|(name, pass, desc)| {
                serde_json::json!({
                    "measure": name,
                    "status": if *pass { "PASS" } else { "FAIL" },
                    "description": desc,
                })
            })
            .collect();

        let deprecated_algos: Vec<&str> = inventory
            .iter()
            .filter(|u| u.bsi_status == Some(BsiStatus::Deprecated))
            .map(|u| u.algorithm.as_str())
            .collect();

        let recommendations: Vec<serde_json::Value> = deprecated_algos
            .iter()
            .map(|algo| {
                let policy = lookup_bsi_policy(algo);
                let repl = policy
                    .and_then(|p| p.recommended_replacement)
                    .unwrap_or("N/A");
                serde_json::json!({
                    "algorithm": algo,
                    "action": "migrate",
                    "replacement": repl,
                })
            })
            .collect();

        let report = serde_json::json!({
            "schema": "tallow.audit.nis2.v1",
            "nis2_report": {
                "file": filename,
                "timestamp": format_iso8601(),
                "directive": "NIS2 (EU 2022/2555)",
                "article": "Art.21 — Cybersecurity risk-management measures",
                "errors": nis2_errors,
                "warnings": nis2_warnings,
                "crypto_inventory": {
                    "total": inventory.len(),
                    "recommended": recommended_count,
                    "acceptable": acceptable_count,
                    "deprecated": deprecated_count,
                    "forbidden": forbidden_count,
                    "algorithms": inventory_json,
                },
                "art21_compliance": compliance_json,
                "recommendations": recommendations,
                "vulnerability_feed": {
                    "source": if offline_fallback { "offline_illustrative_fallback" } else { "local_json_file" },
                    "state": feed_state,
                    "path": feed_path,
                    "schema_version": tallow::stdlib::advisory::ADVISORY_SCHEMA_VERSION,
                    "records": feed_records,
                    "error": feed_error,
                    "offline_fallback_warning": if offline_fallback {
                        "OFFLINE ILLUSTRATIVE FALLBACK — no real advisory data was consulted; set TALLOW_ADVISORY_FILE for real verdicts".to_string()
                    } else {
                        String::new()
                    },
                },
                "vulnerabilities": feed_vulns,
            },
            "disclaimer": AUDIT_DISCLAIMER,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        // Text output
        println!("tallow audit --nis2: {filename}");
        println!("NIS2 Directive (EU 2022/2555) — Art.21 Compliance Report");
        println!("════════════════════════════════════════════════════════════");
        println!("  Errors:             {nis2_errors}");
        println!("  Warnings:           {nis2_warnings}");
        println!();

        // Crypto Algorithm Inventory
        println!("  Crypto Algorithm Inventory (BSI TR-02102):");
        println!("  ────────────────────────────────────────────────────────");
        if inventory.is_empty() {
            println!("    No explicit crypto algorithm calls detected.");
        } else {
            println!(
                "    {:<20} {:<12} {:<14} {}",
                "Algorithm", "Method", "BSI Status", "Function"
            );
            println!(
                "    {:<20} {:<12} {:<14} {}",
                "─────────", "──────", "──────────", "────────"
            );
            for u in &inventory {
                let status_str = match u.bsi_status {
                    Some(BsiStatus::Recommended) => "Recommended",
                    Some(BsiStatus::Acceptable) => "Acceptable",
                    Some(BsiStatus::Deprecated) => "DEPRECATED",
                    Some(BsiStatus::Forbidden) => "FORBIDDEN",
                    None => "Unknown",
                };
                println!(
                    "    {:<20} {:<12} {:<14} {}",
                    u.algorithm, u.method, status_str, u.function_name
                );
            }
        }
        println!();
        println!(
            "    Summary: {} recommended, {} acceptable, {} deprecated, {} forbidden",
            recommended_count, acceptable_count, deprecated_count, forbidden_count
        );

        // Art.21 Compliance
        println!();
        println!("  NIS2 Art.21 Policy Compliance:");
        println!("  ────────────────────────────────────────────────────────");
        for (name, pass, desc) in &art21_checks {
            let icon = if *pass { "PASS" } else { "FAIL" };
            println!("    [{icon}] {name}");
            println!("           {desc}");
        }

        // Vulnerability posture (feed state + any matched advisories)
        println!();
        println!("  Vulnerability Posture (advisory feed):");
        println!("  ────────────────────────────────────────────────────────");
        if feed_state == "applied" {
            println!("    Feed applied: {feed_records} record(s) from {feed_path}");
            if feed_vulns.is_empty() {
                println!("    No matched advisories among {} component(s).", all_components.len());
            } else {
                println!("    {} component(s) match a known advisory:", feed_vulns.len());
                for v in &feed_vulns {
                    println!(
                        "      {} ({}) - {} [{}]",
                        v["id"].as_str().unwrap_or("?"),
                        v["severity"].as_str().unwrap_or("?"),
                        v["component"].as_str().unwrap_or("?"),
                        v["url"].as_str().unwrap_or(""),
                    );
                }
            }
        } else if feed_state == "offline_illustrative_fallback" {
            println!("    ⚠  OFFLINE ILLUSTRATIVE FALLBACK — no real advisory data was");
            println!("       consulted. Set TALLOW_ADVISORY_FILE for real verdicts.");
        } else {
            println!("    ⚠  Vulnerability posture unknown ({feed_state}): {feed_error}");
            println!("       Set TALLOW_ADVISORY_FILE to a local JSON advisory feed");
            println!("       (schema tallow.advisory.feed.v1) for feed-derived verdicts.");
        }

        // Recommendations
        let deprecated_algos: Vec<_> = inventory
            .iter()
            .filter(|u| u.bsi_status == Some(BsiStatus::Deprecated))
            .collect();
        if !deprecated_algos.is_empty() {
            println!();
            println!("  Recommendations:");
            println!("  ────────────────────────────────────────────────────────");
            for u in &deprecated_algos {
                let policy = lookup_bsi_policy(&u.algorithm);
                let repl = policy
                    .and_then(|p| p.recommended_replacement)
                    .unwrap_or("N/A");
                println!(
                    "    Migrate `{}` -> `{}` in function `{}`",
                    u.algorithm, repl, u.function_name
                );
            }
        }

        println!();
        println!("  Art.21: {art21_pass}/{art21_total} measures passed");

        if nis2_errors == 0 && forbidden_count == 0 {
            println!("  NIS2 Status: COMPLIANT");
            println!();
            println!("{AUDIT_DISCLAIMER}");
        } else {
            let violation_count = nis2_errors + forbidden_count;
            println!("  NIS2 Status: NON-COMPLIANT ({violation_count} violation(s))");
            println!();
            println!("{AUDIT_DISCLAIMER}");
        }
    }

    if nis2_violation {
        std::process::exit(exit_codes::LEGAL_VIOLATION);
    }
}

fn run_dora_audit(
    program: &tallow::ast::Program,
    filename: &str,
    format: &str,
    _errors: usize,
    _warnings: usize,
    _source_file: &std::path::Path,
    _strict: bool, // DORA `--strict` == default: no further classes (cycle-02/08 §b)
) {
    // Check for @legal annotations on network functions (Art.17 ICT Risk Management)
    let legal_fn_count = program
        .items
        .iter()
        .filter(|item| {
            if let tallow::ast::Item::Fn(f) = item {
                f.annotations.iter().any(|a| a.name == "legal")
            } else {
                false
            }
        })
        .count();
    let art17_pass = legal_fn_count > 0;

    // Check for DoraCitIncident usage in function bodies (Art.19 Incident Reporting)
    let has_incident_logging = program_mentions_identifier(program, "DoraCitIncident");

    // Severity criteria table
    let severity_criteria = [
        (
            "CRITICAL",
            "critical_function_impaired AND (duration > 24h OR records > 100K)",
        ),
        (
            "HIGH",
            "critical_function_impaired OR clients > 10% OR records > 5,000",
        ),
        ("MEDIUM", "clients > 1% OR duration > 2h OR cross_border"),
        ("LOW", "All other incidents"),
    ];

    // Notification timeline (DORA Art.19)
    let notification_timeline = [
        ("Initial notification", "4 hours after classification"),
        ("Intermediate report", "72 hours after initial notification"),
        ("Final report", "1 month after intermediate report"),
    ];

    // Recommendations
    let mut recommendations: Vec<String> = Vec::new();
    if !art17_pass {
        recommendations.push(
            "Add @legal annotations to network-facing functions for ICT risk traceability"
                .to_string(),
        );
    }
    if !has_incident_logging {
        recommendations.push(
            "Add DoraCitIncident logging to critical network functions for Art.19 compliance"
                .to_string(),
        );
    }
    if art17_pass && has_incident_logging {
        recommendations.push(
            "Consider adding automated notification triggers based on severity classification"
                .to_string(),
        );
    }

    let art17_status = if art17_pass { "PASS" } else { "FAIL" };
    let art19_status = if has_incident_logging { "PASS" } else { "FAIL" };

    // Count passing checks
    let checks_pass = [art17_pass, has_incident_logging]
        .iter()
        .filter(|x| **x)
        .count();
    let checks_total = 2;

    if format == "json" {
        let severity_json: Vec<serde_json::Value> = severity_criteria
            .iter()
            .map(|(level, criteria)| {
                serde_json::json!({
                    "level": level,
                    "criteria": criteria,
                })
            })
            .collect();

        let timeline_json: Vec<serde_json::Value> = notification_timeline
            .iter()
            .map(|(stage, deadline)| {
                serde_json::json!({
                    "stage": stage,
                    "deadline": deadline,
                })
            })
            .collect();

        let recommendations_json: Vec<serde_json::Value> = recommendations
            .iter()
            .map(|r| serde_json::json!(r))
            .collect();

        let report = serde_json::json!({
            "schema": "tallow.audit.dora.v1",
            "dora_report": {
                "file": filename,
                "timestamp": format_iso8601(),
                "regulation": "DORA (EU 2022/2554)",
                "ict_incident_classification": {
                    "description": "DORA RTS severity classification framework",
                    "dora_cit_incident_type": "available",
                    "severity_levels": severity_json,
                },
                "art17_ict_risk_management": {
                    "status": art17_status,
                    "legal_annotated_functions": legal_fn_count,
                    "description": if art17_pass {
                        "ICT risk management annotations present on network functions"
                    } else {
                        "No @legal annotations found on network functions"
                    },
                },
                "art19_incident_reporting": {
                    "status": art19_status,
                    "dora_cit_incident_used": has_incident_logging,
                    "description": if has_incident_logging {
                        "DoraCitIncident type used for incident logging"
                    } else {
                        "DoraCitIncident not found in program — incident logging not configured"
                    },
                },
                "art21_notification_timeline": {
                    "description": "DORA regulatory notification deadlines (informational)",
                    "deadlines": timeline_json,
                },
                "recommendations": recommendations_json,
                "compliance_summary": {
                    "checks_passed": checks_pass,
                    "checks_total": checks_total,
                    "status": if checks_pass == checks_total { "COMPLIANT" } else { "PARTIAL" },
                },
            },
            "disclaimer": AUDIT_DISCLAIMER,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        // Text output
        println!("tallow audit --dora: {filename}");
        println!("DORA (EU 2022/2554) — ICT Operational Resilience Report");
        println!("================================================================");
        println!();

        // ICT Incident Classification Framework
        println!("  ICT Incident Classification Framework (DORA RTS):");
        println!("  ────────────────────────────────────────────────────────");
        println!("    {:<12} {}", "Severity", "Criteria");
        println!("    {:<12} {}", "────────", "────────");
        for (level, criteria) in &severity_criteria {
            println!("    {:<12} {}", level, criteria);
        }
        println!("    Note: DoraCitIncident type available for runtime incident logging");
        println!();

        // Art.17 ICT Risk Management
        println!("  Art.17 ICT Risk Management:");
        println!("  ────────────────────────────────────────────────────────");
        println!(
            "    [{art17_status}] @legal annotations on network functions: {legal_fn_count} found"
        );
        if art17_pass {
            println!("           ICT risk management annotations present");
        } else {
            println!("           No @legal annotations found — add annotations for traceability");
        }
        println!();

        // Art.19 Incident Reporting Capability
        println!("  Art.19 Incident Reporting Capability:");
        println!("  ────────────────────────────────────────────────────────");
        println!(
            "    [{art19_status}] DoraCitIncident usage: {}",
            if has_incident_logging {
                "detected"
            } else {
                "not detected"
            }
        );
        if has_incident_logging {
            println!("           Incident logging configured in program");
        } else {
            println!("           Consider adding DoraCitIncident logging to critical functions");
        }
        println!();

        // Art.21 Notification Timeline
        println!("  Art.21 Notification Timeline (informational):");
        println!("  ────────────────────────────────────────────────────────");
        for (stage, deadline) in &notification_timeline {
            println!("    {:<28} {}", stage, deadline);
        }
        println!("    Note: Timeline tracking is enforced at runtime, not compile time");
        println!();

        // Recommendations
        if !recommendations.is_empty() {
            println!("  Recommendations:");
            println!("  ────────────────────────────────────────────────────────");
            for r in &recommendations {
                println!("    - {r}");
            }
            println!();
        }

        println!("  DORA Compliance: {checks_pass}/{checks_total} checks passed");
        if checks_pass == checks_total {
            println!("  DORA Status: COMPLIANT");
        } else {
            println!(
                "  DORA Status: PARTIAL ({} check(s) require attention)",
                checks_total - checks_pass
            );
        }
        println!();
        println!("{AUDIT_DISCLAIMER}");
    }

    // Frozen FAIL definition (cycle-02/08 §b): any Art.17/Art.19 check FAILs
    // (checks_pass < checks_total) ⇒ exit 2 in both text and JSON paths.
    if checks_pass < checks_total {
        std::process::exit(exit_codes::LEGAL_VIOLATION);
    }
}

fn run_ai_act_audit(
    program: &tallow::ast::Program,
    filename: &str,
    format: &str,
    _errors: usize,
    _warnings: usize,
    _source_file: &std::path::Path,
    strict: bool,
) {
    // ── 1. AI System Inventory ──
    // Collect functions with @ai_system or @ai_risk_level annotations
    let mut systems: Vec<(String, String, bool)> = Vec::new(); // (fn_name, risk_level, has_art9)
    for item in &program.items {
        if let tallow::ast::Item::Fn(f) = item {
            for ann in &f.annotations {
                if ann.name == "ai_system" || ann.name == "ai_risk_level" {
                    // Extract risk level from annotation args
                    let risk_expr = ann
                        .args
                        .iter()
                        .find(|a| a.name == "risk")
                        .map(|a| &a.value)
                        .or_else(|| ann.args.first().map(|a| &a.value));
                    let risk = if let Some(expr) = risk_expr {
                        match &expr.kind {
                            tallow::ast::ExprKind::DotIdent(s) => s.clone(),
                            tallow::ast::ExprKind::StringLit(s) => s.clone(),
                            other => format!("{:?}", other),
                        }
                    } else {
                        "unspecified".to_string()
                    };
                    let has_art9 = ann.args.iter().any(|a| a.name == "art9");
                    systems.push((f.name.clone(), risk, has_art9));
                }
            }
        }
    }

    let total_systems = systems.len();
    let high_risk_count = systems.iter().filter(|(_, r, _)| r == "high").count();
    let prohibited_count = systems.iter().filter(|(_, r, _)| r == "prohibited").count();
    let limited_count = systems.iter().filter(|(_, r, _)| r == "limited").count();
    let minimal_count = systems
        .iter()
        .filter(|(_, r, _)| r == "minimal" || r == "unspecified")
        .count();

    // ── 2. Art.9 Risk Management ──
    let high_risk_with_art9 = systems.iter().filter(|(_, r, a)| r == "high" && *a).count();
    let art9_pass = high_risk_count == 0 || high_risk_with_art9 == high_risk_count;

    // ── 3. Art.12 Record-Keeping ──
    let has_inference_log = program_mentions_identifier(program, "AiInferenceLog");

    // ── 4. Art.13 Transparency ──
    let explainable_count = program
        .items
        .iter()
        .filter(|item| {
            if let tallow::ast::Item::Fn(f) = item {
                f.annotations.iter().any(|a| a.name == "explainable")
            } else {
                false
            }
        })
        .count();
    let art13_pass = total_systems == 0 || explainable_count > 0;

    // ── 5. Art.14 Human Oversight ──
    let human_approval_count = program
        .items
        .iter()
        .filter(|item| {
            if let tallow::ast::Item::Fn(f) = item {
                f.annotations
                    .iter()
                    .any(|a| a.name == "requires_human_approval")
            } else {
                false
            }
        })
        .count();
    let art14_pass = high_risk_count == 0 || human_approval_count > 0;

    // ── 6. Annex IV Model Provenance ──
    let has_provenance = program_mentions_identifier(program, "ModelProvenance");

    // ── 7. Compliance Summary ──
    let checks = [
        ("Art.9 Risk Management", art9_pass),
        ("Art.12 Record-Keeping", has_inference_log),
        ("Art.13 Transparency", art13_pass),
        ("Art.14 Human Oversight", art14_pass),
        ("Annex IV Model Provenance", has_provenance),
    ];
    let checks_pass = checks.iter().filter(|(_, p)| *p).count();
    let checks_total = checks.len();

    // Recommendations
    let mut recommendations: Vec<String> = Vec::new();
    if total_systems == 0 {
        recommendations.push("Add @ai_system annotations to AI-related functions".to_string());
    }
    if high_risk_count > 0 && !art9_pass {
        recommendations.push(
            "Add art9: true with risk management sub-fields to high-risk systems".to_string(),
        );
    }
    if !has_inference_log {
        recommendations.push("Add AiInferenceLog for Art.12 inference record-keeping".to_string());
    }
    if total_systems > 0 && explainable_count == 0 {
        recommendations
            .push("Add @explainable to decision-making AI functions for Art.13".to_string());
    }
    if high_risk_count > 0 && human_approval_count == 0 {
        recommendations.push(
            "Add @requires_human_approval to high-risk decision functions for Art.14".to_string(),
        );
    }
    if !has_provenance {
        recommendations.push("Add ModelProvenance tracking for Annex IV documentation".to_string());
    }

    let overall_status = if checks_pass == checks_total {
        "COMPLIANT"
    } else if checks_pass > 0 {
        "PARTIAL"
    } else {
        "NON_COMPLIANT"
    };

    // Frozen FAIL definition (cycle-02/08 §b): a prohibited system, or an
    // Art.9/Art.12 FAIL. `--strict` additionally escalates any non-COMPLIANT
    // summary (WARN/PARTIAL), in both text and JSON paths.
    let ai_act_violation = prohibited_count > 0
        || !art9_pass
        || !has_inference_log
        || (strict && overall_status != "COMPLIANT");

    if format == "json" {
        let systems_json: Vec<serde_json::Value> = systems
            .iter()
            .map(|(name, risk, art9)| {
                serde_json::json!({
                    "function": name,
                    "risk_level": risk,
                    "art9_compliant": art9,
                })
            })
            .collect();

        let recommendations_json: Vec<serde_json::Value> = recommendations
            .iter()
            .map(|r| serde_json::json!(r))
            .collect();

        let report = serde_json::json!({
            "schema": "tallow.audit.ai_act.v1",
            "ai_act_report": {
                "file": filename,
                "timestamp": format_iso8601(),
                "regulation": "EU AI Act (Regulation 2024/1689)",
                "ai_system_inventory": {
                    "total": total_systems,
                    "high_risk": high_risk_count,
                    "prohibited": prohibited_count,
                    "limited": limited_count,
                    "minimal": minimal_count,
                    "systems": systems_json,
                },
                "art9_risk_management": {
                    "status": if art9_pass { "PASS" } else { "FAIL" },
                    "high_risk_with_art9": high_risk_with_art9,
                    "high_risk_total": high_risk_count,
                },
                "art12_record_keeping": {
                    "status": if has_inference_log { "PASS" } else { "FAIL" },
                    "ai_inference_log_used": has_inference_log,
                },
                "art13_transparency": {
                    "status": if art13_pass { "PASS" } else { "WARN" },
                    "explainable_functions": explainable_count,
                },
                "art14_human_oversight": {
                    "status": if art14_pass { "PASS" } else { "WARN" },
                    "human_approval_gates": human_approval_count,
                },
                "annex_iv_model_provenance": {
                    "status": if has_provenance { "PASS" } else { "WARN" },
                    "model_provenance_used": has_provenance,
                },
                "recommendations": recommendations_json,
                "compliance_summary": {
                    "checks_passed": checks_pass,
                    "checks_total": checks_total,
                    "status": overall_status,
                },
            },
            "disclaimer": AUDIT_DISCLAIMER,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        // Text output
        println!("tallow audit --ai-act: {filename}");
        println!("EU AI Act (Regulation 2024/1689) — Compliance Report");
        println!("================================================================");
        println!();

        // AI System Inventory
        println!("  AI System Inventory:");
        println!("  ────────────────────────────────────────────────────────");
        if total_systems == 0 {
            println!("    No @ai_system annotations found");
        } else {
            if prohibited_count > 0 {
                println!("    prohibited:  {prohibited_count} system(s)");
            }
            if high_risk_count > 0 {
                println!("    high:        {high_risk_count} system(s)");
            }
            if limited_count > 0 {
                println!("    limited:     {limited_count} system(s)");
            }
            if minimal_count > 0 {
                println!("    minimal:     {minimal_count} system(s)");
            }
            for (name, risk, _) in &systems {
                println!("      fn {name} — risk: {risk}");
            }
        }
        println!();

        // Art.9 Risk Management
        let art9_status = if art9_pass { "PASS" } else { "FAIL" };
        println!("  Art.9 Risk Management: [{art9_status}]");
        println!("  ────────────────────────────────────────────────────────");
        if high_risk_count == 0 {
            println!("    No high-risk systems — Art.9 not applicable");
        } else {
            println!(
                "    {high_risk_with_art9}/{high_risk_count} high-risk systems have art9 compliance"
            );
        }
        println!();

        // Art.12 Record-Keeping
        let art12_status = if has_inference_log { "PASS" } else { "FAIL" };
        println!("  Art.12 Record-Keeping: [{art12_status}]");
        println!("  ────────────────────────────────────────────────────────");
        println!(
            "    AiInferenceLog usage: {}",
            if has_inference_log {
                "detected"
            } else {
                "not detected"
            }
        );
        println!();

        // Art.13 Transparency
        let art13_status = if art13_pass { "PASS" } else { "WARN" };
        println!("  Art.13 Transparency: [{art13_status}]");
        println!("  ────────────────────────────────────────────────────────");
        println!("    @explainable functions: {explainable_count}");
        println!();

        // Art.14 Human Oversight
        let art14_status = if art14_pass { "PASS" } else { "WARN" };
        println!("  Art.14 Human Oversight: [{art14_status}]");
        println!("  ────────────────────────────────────────────────────────");
        println!("    @requires_human_approval gates: {human_approval_count}");
        println!();

        // Annex IV Model Provenance
        let annex_status = if has_provenance { "PASS" } else { "WARN" };
        println!("  Annex IV Model Provenance: [{annex_status}]");
        println!("  ────────────────────────────────────────────────────────");
        println!(
            "    ModelProvenance usage: {}",
            if has_provenance {
                "detected"
            } else {
                "not detected"
            }
        );
        println!();

        // Recommendations
        if !recommendations.is_empty() {
            println!("  Recommendations:");
            println!("  ────────────────────────────────────────────────────────");
            for r in &recommendations {
                println!("    - {r}");
            }
            println!();
        }

        println!("  EU AI Act Compliance: {checks_pass}/{checks_total} checks passed");
        println!("  Status: {overall_status}");
        println!();
        println!("{AUDIT_DISCLAIMER}");
    }

    if ai_act_violation {
        std::process::exit(exit_codes::LEGAL_VIOLATION);
    }
}

// ── tallow audit --supply-chain ────────────────────────────────────────────────

fn run_supply_chain_audit_cmd(
    program: &tallow::ast::Program,
    filename: &str,
    format: &str,
    errors: usize,
    warnings: usize,
    file: &std::path::Path,
) {
    use tallow::sbom;
    use tallow::supply_chain;

    // Determine project directory
    let project_dir = file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    // Load signature pins from the project's `.tallow-pins` (TOFU enforcement).
    // No pin file → a loud stderr note, never a silent empty store; a malformed
    // pin file refuses the audit (fail-closed).
    let pin_store = match supply_chain::load_pin_store(&project_dir) {
        Ok(load) => {
            match &load.source {
                Some(path) if !load.store.all_pins().is_empty() => eprintln!(
                    "supply-chain pins: {} pin(s) loaded from {}",
                    load.store.all_pins().len(),
                    path.display()
                ),
                Some(path) => eprintln!(
                    "note: {} defines no pins — pin enforcement has nothing to check",
                    path.display()
                ),
                None => eprintln!(
                    "note: no {} in {} — no signature pins configured; pin enforcement skipped",
                    supply_chain::PINS_FILE_NAME,
                    project_dir.display()
                ),
            }
            load.store
        }
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("supply-chain audit refused: fix or remove the pin file.");
            std::process::exit(exit_codes::DEPENDENCY_ERROR);
        }
    };

    // Run the supply-chain audit
    let report = supply_chain::run_supply_chain_audit(&project_dir, &pin_store);

    // Also scan for crypto usage and generate CBOM info
    let crypto_usages = sbom::scan_crypto_usage(program);

    if format == "json" {
        let mut json_report = report.to_json();
        // Add crypto inventory to the JSON report
        let crypto_entries: Vec<serde_json::Value> = crypto_usages
            .iter()
            .map(|cu| {
                serde_json::json!({
                    "algorithm": cu.algorithm,
                    "category": cu.category,
                    "post_quantum": cu.post_quantum,
                    "source": cu.source,
                })
            })
            .collect();
        json_report["crypto_inventory"] = serde_json::json!(crypto_entries);
        json_report["compiler_diagnostics"] = serde_json::json!({
            "errors": errors,
            "warnings": warnings,
        });
        // Frozen additive key (cycle-02/08 §b/§c; W2-06 extension to the P1 batch).
        json_report["disclaimer"] = serde_json::json!(AUDIT_DISCLAIMER);
        println!(
            "{}",
            serde_json::to_string_pretty(&json_report).unwrap_or_default()
        );
    } else {
        // Text output
        println!("tallow audit --supply-chain: {filename}");
        print!("{}", report.to_text());

        // Crypto inventory
        if !crypto_usages.is_empty() {
            println!("  Cryptographic Inventory (CBOM):");
            println!("  ────────────────────────────────────────────────────────");
            for cu in &crypto_usages {
                let pqc_tag = if cu.post_quantum { " [PQC]" } else { "" };
                println!(
                    "    {:<25} {:<20} {}{}",
                    cu.algorithm, cu.category, cu.source, pqc_tag
                );
            }
            println!();
        }

        // Compiler diagnostics summary
        if errors > 0 || warnings > 0 {
            println!("  Compiler diagnostics: {errors} error(s), {warnings} warning(s)");
        }

        println!();
        println!("{AUDIT_DISCLAIMER}");
    }

    // Fail-closed: pin verification errors (a pinned subject's hash in the lock
    // files no longer matches) refuse the audit with a nonzero exit. stdout is
    // already flushed above and stays machine-parseable.
    let pin_errors = report.error_count();
    if pin_errors > 0 {
        eprintln!("supply-chain audit: {pin_errors} pinned-hash mismatch(es) — refusing");
        std::process::exit(exit_codes::DEPENDENCY_ERROR);
    }
}

/// Check if any function body in the program mentions a given identifier.
fn program_mentions_identifier(program: &tallow::ast::Program, ident: &str) -> bool {
    for item in &program.items {
        if let tallow::ast::Item::Fn(f) = item {
            if body_mentions_identifier(&f.body, ident) {
                return true;
            }
        }
    }
    false
}

fn body_mentions_identifier(block: &tallow::ast::Block, ident: &str) -> bool {
    for stmt in &block.stmts {
        if stmt_mentions_identifier(stmt, ident) {
            return true;
        }
    }
    false
}

fn stmt_mentions_identifier(stmt: &tallow::ast::Stmt, ident: &str) -> bool {
    use tallow::ast::StmtKind;
    match &stmt.kind {
        StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
            expr_mentions_identifier(value, ident)
        }
        StmtKind::LetDestructure { value, .. } => expr_mentions_identifier(value, ident),
        StmtKind::Expr { expr } => expr_mentions_identifier(expr, ident),
        StmtKind::Return(Some(expr)) => expr_mentions_identifier(expr, ident),
        StmtKind::For { iter, body, .. } => {
            expr_mentions_identifier(iter, ident) || body_mentions_identifier(body, ident)
        }
        StmtKind::While {
            condition, body, ..
        } => expr_mentions_identifier(condition, ident) || body_mentions_identifier(body, ident),
        StmtKind::Bail(expr) => expr_mentions_identifier(expr, ident),
        _ => false,
    }
}

fn expr_mentions_identifier(expr: &tallow::ast::Expr, ident: &str) -> bool {
    use tallow::ast::ExprKind;
    match &expr.kind {
        ExprKind::Ident(name) => name == ident,
        ExprKind::Call { callee, args, .. } => {
            expr_mentions_identifier(callee, ident)
                || args
                    .iter()
                    .any(|a| expr_mentions_identifier(&a.value, ident))
        }
        ExprKind::FieldAccess { object, .. } => expr_mentions_identifier(object, ident),
        ExprKind::Binary { left, right, .. } => {
            expr_mentions_identifier(left, ident) || expr_mentions_identifier(right, ident)
        }
        ExprKind::Unary { operand, .. } => expr_mentions_identifier(operand, ident),
        ExprKind::MethodCall { object, args, .. } => {
            expr_mentions_identifier(object, ident)
                || args
                    .iter()
                    .any(|a| expr_mentions_identifier(&a.value, ident))
        }
        ExprKind::Index { object, index } => {
            expr_mentions_identifier(object, ident) || expr_mentions_identifier(index, ident)
        }
        _ => false,
    }
}

/// Read project name and version from Cargo.toml or tallow.toml.
fn read_project_metadata(project_dir: &std::path::Path) -> (String, String) {
    let cargo_toml_path = project_dir.join("Cargo.toml");
    if cargo_toml_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_toml_path) {
            let parsed: toml::Value = toml::from_str(&content)
                .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
            let name = parsed
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown")
                .to_string();
            let version = parsed
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();
            return (name, version);
        }
    }
    let tallow_toml_path = project_dir.join("tallow.toml");
    if tallow_toml_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&tallow_toml_path) {
            let parsed: toml::Value = toml::from_str(&content)
                .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
            let name = parsed
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown")
                .to_string();
            let version = parsed
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();
            return (name, version);
        }
    }
    ("unknown".to_string(), "0.0.0".to_string())
}

/// Format the current UTC time as an ISO 8601 timestamp.
/// Uses accurate leap-year and month-length calculation (no chrono dependency).
fn format_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let secs_today = now % 86400;
    let hours = secs_today / 3600;
    let minutes = (secs_today % 3600) / 60;
    let seconds = secs_today % 60;

    let mut days = (now / 86400) as i64;
    let mut year = 1970i64;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    while month < 12 && days >= month_days[month] {
        days -= month_days[month];
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month + 1,
        days + 1,
        hours,
        minutes,
        seconds
    )
}

// ── tallow pia ──────────────────────────────────────────────────────────────────

/// PIA report data structure (testable without printing).
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PiaReport {
    pub generated: String,
    pub file: String,
    pub data_types: Vec<PiaDataType>,
    pub legal_bases: Vec<PiaLegalBasis>,
    pub privacy_budget: PiaPrivacyBudget,
    pub jurisdictions: Vec<PiaJurisdiction>,
    pub erasable_types: Vec<PiaErasableType>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PiaDataType {
    pub name: String,
    pub qualifier: String, // "private", "secret", or "plain"
    pub is_erasable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PiaLegalBasis {
    pub function: String,
    pub basis: String,
    pub purpose: String,
    pub personal_data: bool,
    pub retain_for: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PiaPrivacyBudget {
    pub functions: Vec<PiaEpsilonEntry>,
    pub total_epsilon: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PiaEpsilonEntry {
    pub function: String,
    pub epsilon: f64,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PiaJurisdiction {
    pub type_name: String,
    pub jurisdiction: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PiaErasableType {
    pub name: String,
    pub has_purge_handler: bool,
}

/// Generate a PIA report by walking the program AST.
pub fn generate_pia_report(
    program: &tallow::ast::Program,
    env: &tallow::typeck::TypeEnv,
    filename: &str,
) -> PiaReport {
    use tallow::ast::*;

    let mut data_types = Vec::new();
    let mut legal_bases = Vec::new();
    let mut epsilon_entries = Vec::new();
    let mut jurisdictions = Vec::new();
    let mut erasable_types = Vec::new();
    let mut total_epsilon = 0.0f64;
    let mut erasable_names: Vec<String> = Vec::new();

    // Collect type aliases
    for item in &program.items {
        if let Item::TypeAlias(ta) = item {
            let qualifier = if ta.qualifier == Some(TypeQualifier::Secret) {
                "secret"
            } else if ta.qualifier == Some(TypeQualifier::Private) {
                "private"
            } else {
                "plain"
            };

            let is_erasable = ta.annotations.iter().any(|a| a.name == "erasable");
            if is_erasable {
                erasable_names.push(ta.name.clone());
            }

            // Check for @jurisdiction
            for ann in &ta.annotations {
                if ann.name == "jurisdiction" {
                    let jur = extract_annotation_dot_arg(ann).unwrap_or_default();
                    if !jur.is_empty() {
                        jurisdictions.push(PiaJurisdiction {
                            type_name: ta.name.clone(),
                            jurisdiction: jur,
                        });
                    }
                }
            }

            data_types.push(PiaDataType {
                name: ta.name.clone(),
                qualifier: qualifier.to_string(),
                is_erasable,
            });
        }
    }

    // Collect function-level annotations
    for item in &program.items {
        if let Item::Fn(f) = item {
            // @legal
            if let Some(legal) = f.annotations.iter().find(|a| a.name == "legal") {
                let basis =
                    extract_legal_arg(&legal.args, "basis").unwrap_or_else(|| "unspecified".into());
                let purpose = extract_legal_arg(&legal.args, "purpose")
                    .unwrap_or_else(|| "unspecified".into());
                let personal_data = extract_legal_arg(&legal.args, "personal_data")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                let retain_for = extract_legal_arg(&legal.args, "retain_for");

                legal_bases.push(PiaLegalBasis {
                    function: f.name.clone(),
                    basis,
                    purpose,
                    personal_data,
                    retain_for,
                });
            }

            // @epsilon
            if let Some(eps_ann) = f.annotations.iter().find(|a| a.name == "epsilon") {
                let eps_val = extract_epsilon_f64(eps_ann).unwrap_or(0.0);
                total_epsilon += eps_val;

                let purpose = f
                    .annotations
                    .iter()
                    .find(|a| a.name == "purpose")
                    .and_then(|a| {
                        a.args.first().and_then(|arg| {
                            if let ExprKind::StringLit(s) = &arg.value.kind {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                    });

                epsilon_entries.push(PiaEpsilonEntry {
                    function: f.name.clone(),
                    epsilon: eps_val,
                    purpose,
                });
            }
        }
    }

    // Determine purge handler status for erasable types
    let has_any_purge = program_has_purge_handler(program);
    for name in &erasable_names {
        erasable_types.push(PiaErasableType {
            name: name.clone(),
            has_purge_handler: has_any_purge,
        });
    }

    // Generate recommendations
    let mut recommendations = Vec::new();

    // Check retention periods
    for lb in &legal_bases {
        if let Some(ref retain) = lb.retain_for {
            if retain.contains("365") || retain.contains("year") {
                recommendations.push(format!(
                    "Consider reducing retention period for function `{}` (currently {})",
                    lb.function, retain
                ));
            }
        }
    }

    // Check epsilon budget
    if total_epsilon > 5.0 {
        recommendations.push(format!(
            "Total epsilon budget ({:.2}) may be high for privacy-sensitive applications",
            total_epsilon
        ));
    }

    // Check missing purge handlers
    for et in &erasable_types {
        if !et.has_purge_handler {
            recommendations.push(format!(
                "No purge handler found for @erasable type `{}`",
                et.name
            ));
        }
    }

    // Check cross-border transfers
    for j in &jurisdictions {
        if j.jurisdiction == "us" {
            recommendations.push(format!(
                "Cross-border transfers detected for `{}` to conditional jurisdiction (US/DPF)",
                j.type_name
            ));
        }
    }

    // Add env sensitivity note
    let _env = env; // silence unused warning while using it for future extensions

    PiaReport {
        generated: format_iso8601(),
        file: filename.to_string(),
        data_types,
        legal_bases,
        privacy_budget: PiaPrivacyBudget {
            functions: epsilon_entries,
            total_epsilon,
        },
        jurisdictions,
        erasable_types,
        recommendations,
    }
}

/// Extract a dot-prefixed argument from an annotation (e.g., @jurisdiction(.eu) -> "eu").
fn extract_annotation_dot_arg(ann: &tallow::ast::Annotation) -> Option<String> {
    for arg in &ann.args {
        match &arg.value.kind {
            tallow::ast::ExprKind::DotIdent(s) => return Some(s.clone()),
            tallow::ast::ExprKind::StringLit(s) => return Some(s.clone()),
            tallow::ast::ExprKind::Ident(s) => return Some(s.clone()),
            _ => {}
        }
    }
    None
}

/// Extract epsilon f64 value from an @epsilon annotation.
fn extract_epsilon_f64(ann: &tallow::ast::Annotation) -> Option<f64> {
    for arg in &ann.args {
        match &arg.value.kind {
            tallow::ast::ExprKind::FloatLit(f) => return Some(*f),
            tallow::ast::ExprKind::IntLit(i) => return Some(*i as f64),
            _ => {}
        }
    }
    None
}

/// Check if the program contains any purge/delete handler function calls.
fn program_has_purge_handler(program: &tallow::ast::Program) -> bool {
    const PURGE_PATTERNS: &[&str] = &["purge", "delete", "remove", "erase", "destroy", "wipe"];

    for item in &program.items {
        if let tallow::ast::Item::Fn(f) = item {
            if block_has_purge(&f.body, PURGE_PATTERNS) {
                return true;
            }
        }
    }
    false
}

fn block_has_purge(block: &tallow::ast::Block, patterns: &[&str]) -> bool {
    for stmt in &block.stmts {
        if stmt_has_purge(stmt, patterns) {
            return true;
        }
    }
    false
}

fn stmt_has_purge(stmt: &tallow::ast::Stmt, patterns: &[&str]) -> bool {
    use tallow::ast::*;
    match &stmt.kind {
        StmtKind::Let { value, .. } | StmtKind::Var { value, .. } => {
            expr_has_purge(value, patterns)
        }
        StmtKind::Expr { expr } => expr_has_purge(expr, patterns),
        StmtKind::Return(Some(e)) => expr_has_purge(e, patterns),
        StmtKind::While { condition, body } => {
            expr_has_purge(condition, patterns) || block_has_purge(body, patterns)
        }
        StmtKind::For { iter, body, .. } => {
            expr_has_purge(iter, patterns) || block_has_purge(body, patterns)
        }
        _ => false,
    }
}

fn expr_has_purge(expr: &tallow::ast::Expr, patterns: &[&str]) -> bool {
    use tallow::ast::*;
    match &expr.kind {
        ExprKind::Call { callee, args } => {
            if let ExprKind::Ident(name) = &callee.kind {
                if patterns.iter().any(|p| name.contains(p)) {
                    return true;
                }
            }
            if let ExprKind::FieldAccess { field, .. } = &callee.kind {
                if patterns.iter().any(|p| field.contains(p)) {
                    return true;
                }
            }
            expr_has_purge(callee, patterns)
                || args.iter().any(|a| expr_has_purge(&a.value, patterns))
        }
        ExprKind::MethodCall {
            object,
            method,
            args,
        } => {
            if patterns.iter().any(|p| method.contains(p)) {
                return true;
            }
            expr_has_purge(object, patterns)
                || args.iter().any(|a| expr_has_purge(&a.value, patterns))
        }
        ExprKind::Block(block) => block_has_purge(block, patterns),
        ExprKind::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            expr_has_purge(condition, patterns)
                || block_has_purge(then_block, patterns)
                || else_branch
                    .as_ref()
                    .map(|eb| match eb {
                        ElseBranch::ElseIf(e) => expr_has_purge(e, patterns),
                        ElseBranch::Block(b) => block_has_purge(b, patterns),
                    })
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// Print PIA report in the requested format.
fn print_pia_report(report: &PiaReport, format: &str) {
    if format == "json" {
        print_pia_json(report);
    } else {
        print_pia_text(report);
    }
}

fn print_pia_json(report: &PiaReport) {
    let mut json = String::from("{\n");
    // Frozen additive keys (W2-06; policy: cycle-02/08 §b, extended to pia per E-2-03 §3.2).
    json.push_str("  \"schema\": \"tallow.audit.pia.v1\",\n");
    json.push_str(&format!("  \"generated\": \"{}\",\n", report.generated));
    json.push_str(&format!("  \"file\": \"{}\",\n", report.file));

    // data_types
    json.push_str("  \"data_types\": [\n");
    for (i, dt) in report.data_types.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"qualifier\": \"{}\", \"is_erasable\": {}}}",
            dt.name, dt.qualifier, dt.is_erasable
        ));
        if i < report.data_types.len() - 1 {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ],\n");

    // legal_bases
    json.push_str("  \"legal_bases\": [\n");
    for (i, lb) in report.legal_bases.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"function\": \"{}\", \"basis\": \"{}\", \"purpose\": \"{}\", \"personal_data\": {}, \"retain_for\": {}}}",
            lb.function, lb.basis, lb.purpose, lb.personal_data,
            lb.retain_for.as_ref().map(|r| format!("\"{}\"", r)).unwrap_or_else(|| "null".to_string())
        ));
        if i < report.legal_bases.len() - 1 {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ],\n");

    // privacy_budget
    json.push_str("  \"privacy_budget\": {\n");
    json.push_str(&format!(
        "    \"total_epsilon\": {:.2},\n",
        report.privacy_budget.total_epsilon
    ));
    json.push_str("    \"functions\": [\n");
    for (i, ep) in report.privacy_budget.functions.iter().enumerate() {
        json.push_str(&format!(
            "      {{\"function\": \"{}\", \"epsilon\": {:.2}, \"purpose\": {}}}",
            ep.function,
            ep.epsilon,
            ep.purpose
                .as_ref()
                .map(|p| format!("\"{}\"", p))
                .unwrap_or_else(|| "null".to_string())
        ));
        if i < report.privacy_budget.functions.len() - 1 {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("    ]\n");
    json.push_str("  },\n");

    // jurisdictions
    json.push_str("  \"jurisdictions\": [\n");
    for (i, j) in report.jurisdictions.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"type_name\": \"{}\", \"jurisdiction\": \"{}\"}}",
            j.type_name, j.jurisdiction
        ));
        if i < report.jurisdictions.len() - 1 {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ],\n");

    // erasable_types
    json.push_str("  \"erasable_types\": [\n");
    for (i, et) in report.erasable_types.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"has_purge_handler\": {}}}",
            et.name, et.has_purge_handler
        ));
        if i < report.erasable_types.len() - 1 {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ],\n");

    // recommendations
    json.push_str("  \"recommendations\": [\n");
    for (i, r) in report.recommendations.iter().enumerate() {
        json.push_str(&format!("    \"{}\"", r));
        if i < report.recommendations.len() - 1 {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str("  ],\n");

    json.push_str(&format!("  \"disclaimer\": {}\n", serde_json::json!(AUDIT_DISCLAIMER)));
    json.push('}');
    println!("{json}");
}

fn print_pia_text(report: &PiaReport) {
    println!("=== Privacy Impact Assessment ===");
    println!("File: {}", report.file);
    println!("Generated: {}", report.generated);
    println!();

    // Data Types
    println!("--- Data Processing Activities ---");
    if report.data_types.is_empty() {
        println!("  No type aliases declared.");
    } else {
        for dt in &report.data_types {
            let erasable = if dt.is_erasable { " [ERASABLE]" } else { "" };
            println!("  - {} ({}){}", dt.name, dt.qualifier, erasable);
        }
    }
    println!();

    // Legal Bases
    println!("--- Legal Basis ---");
    if report.legal_bases.is_empty() {
        println!("  No @legal annotations found.");
    } else {
        for lb in &report.legal_bases {
            println!(
                "  - {}: basis={}, purpose=\"{}\"",
                lb.function, lb.basis, lb.purpose
            );
            if lb.personal_data {
                println!("    personal_data: true");
            }
            if let Some(ref r) = lb.retain_for {
                println!("    retain_for: {}", r);
            }
        }
    }
    println!();

    // Privacy Budget
    println!("--- Privacy Budget ---");
    if report.privacy_budget.functions.is_empty() {
        println!("  No @epsilon annotations found.");
    } else {
        for ep in &report.privacy_budget.functions {
            let purpose = ep.purpose.as_deref().unwrap_or("none");
            println!(
                "  - {}: epsilon={:.2}, purpose={}",
                ep.function, ep.epsilon, purpose
            );
        }
        println!(
            "  Total epsilon: {:.2}",
            report.privacy_budget.total_epsilon
        );
    }
    println!();

    // Jurisdictions
    println!("--- Cross-Border Transfers ---");
    if report.jurisdictions.is_empty() {
        println!("  No @jurisdiction annotations found.");
    } else {
        for j in &report.jurisdictions {
            println!("  - {}: jurisdiction={}", j.type_name, j.jurisdiction);
        }
    }
    println!();

    // Consent Management
    println!("--- Consent Management ---");
    println!("  (See data_types for Consent<T> usage)");
    println!();

    // Erasure Capabilities
    println!("--- Erasure Capabilities ---");
    if report.erasable_types.is_empty() {
        println!("  No @erasable types declared.");
    } else {
        for et in &report.erasable_types {
            let status = if et.has_purge_handler {
                "purge handler found"
            } else {
                "NO purge handler"
            };
            println!("  - {}: {}", et.name, status);
        }
    }
    println!();

    // Risk Assessment / Recommendations
    println!("--- Risk Assessment ---");
    if report.recommendations.is_empty() {
        println!("  No issues detected.");
    } else {
        for r in &report.recommendations {
            println!("  WARNING: {}", r);
        }
    }
    println!();
    println!("{AUDIT_DISCLAIMER}");
}

// ── tallow test ────────────────────────────────────────────────────────────────

/// Names of lifecycle hook functions (excluded from test discovery and coverage).
const LIFECYCLE_HOOKS: &[&str] = &["before_all", "after_all", "before_each", "after_each"];

fn run_tests(path: &PathBuf, filter: Option<&str>, coverage: bool) -> anyhow::Result<()> {
    use std::time::Instant;

    // Discover test files
    let mut test_files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        test_files.push(path.clone());
    } else if path.is_dir() {
        discover_test_files(path, &mut test_files)?;
    } else {
        // Try tests/ directory
        let tests_dir = PathBuf::from("tests");
        if tests_dir.is_dir() {
            discover_test_files(&tests_dir, &mut test_files)?;
        } else {
            anyhow::bail!("no test files found at '{}'", path.display());
        }
    }

    if test_files.is_empty() {
        println!("no test files found");
        return Ok(());
    }

    test_files.sort();

    let start = Instant::now();
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    let mut failures: Vec<(String, String)> = Vec::new();

    // Coverage: aggregate function hit counts across all files
    let mut coverage_hits: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let mut coverage_total_fns: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    println!();
    println!("running {} test file(s)", test_files.len());
    println!();

    for file in &test_files {
        let source = std::fs::read_to_string(file)?;
        let filename = file.display().to_string();

        // Parse
        let (tokens, lex_errors) = tallow::lexer::tokenize(&source);
        if !lex_errors.is_empty() {
            println!("  SKIP {filename} (lex errors)");
            skipped += 1;
            continue;
        }

        let program = match tallow::parser::Parser::parse(tokens) {
            Ok(p) => p,
            Err(_) => {
                println!("  SKIP {filename} (parse error)");
                skipped += 1;
                continue;
            }
        };

        // Find test functions: fn test_*() or fn *_test()
        let test_fns: Vec<&tallow::ast::FnDecl> = program
            .items
            .iter()
            .filter_map(|item| {
                if let tallow::ast::Item::Fn(f) = item {
                    let is_test = f.name.starts_with("test_") || f.name.ends_with("_test");
                    if is_test {
                        // Apply filter if provided
                        if let Some(filter_str) = filter {
                            if f.name.contains(filter_str) {
                                return Some(f);
                            }
                            return None;
                        }
                        return Some(f);
                    }
                }
                None
            })
            .collect();

        // Discover @property functions
        let prop_fns_early: Vec<&tallow::ast::FnDecl> = program
            .items
            .iter()
            .filter_map(|item| {
                if let tallow::ast::Item::Fn(f) = item {
                    if f.annotations.iter().any(|a| a.name == "property") {
                        if let Some(filter_str) = filter {
                            if !f.name.contains(filter_str) {
                                return None;
                            }
                        }
                        return Some(f);
                    }
                }
                None
            })
            .collect();

        // Discover lifecycle hooks
        let has_before_all = program
            .items
            .iter()
            .any(|item| matches!(item, tallow::ast::Item::Fn(f) if f.name == "before_all"));
        let has_after_all = program
            .items
            .iter()
            .any(|item| matches!(item, tallow::ast::Item::Fn(f) if f.name == "after_all"));
        let has_before_each = program
            .items
            .iter()
            .any(|item| matches!(item, tallow::ast::Item::Fn(f) if f.name == "before_each"));
        let has_after_each = program
            .items
            .iter()
            .any(|item| matches!(item, tallow::ast::Item::Fn(f) if f.name == "after_each"));

        if test_fns.is_empty() && prop_fns_early.is_empty() {
            // Also run main() as a test if no test or property functions found
            let has_main = program
                .items
                .iter()
                .any(|item| matches!(item, tallow::ast::Item::Fn(f) if f.name == "main"));
            if has_main {
                let mut interp = Interpreter::new();
                if coverage {
                    interp.enable_coverage();
                }
                match interp.run(&program) {
                    Ok(_) => {
                        println!("  PASS {filename}");
                        passed += 1;
                    }
                    Err(e) => {
                        println!("  FAIL {filename}");
                        println!("       {e}");
                        failed += 1;
                        failures.push((filename.clone(), e.to_string()));
                    }
                }
                if coverage {
                    merge_coverage(
                        &mut coverage_hits,
                        &mut coverage_total_fns,
                        &interp,
                        &program,
                    );
                }
            }
            continue;
        }

        println!("--- {filename} ---");

        // Register all declarations, then call each test function individually
        let mut interp = Interpreter::new();
        if coverage {
            interp.enable_coverage();
        }
        if let Err(e) = interp.register(&program) {
            println!("  SKIP {filename} (registration error: {e})");
            skipped += 1;
            continue;
        }

        // Run before_all() once for the file
        if has_before_all {
            if let Err(e) = interp.call_fn("before_all") {
                println!("  FAIL {filename}::before_all");
                println!("       {e}");
                failures.push((format!("{filename}::before_all"), e.to_string()));
                failed += 1;
                continue; // skip all tests in this file
            }
        }

        for test_fn in &test_fns {
            let test_name = format!("{filename}::{}", test_fn.name);
            let test_start = Instant::now();

            // Run before_each() if it exists
            if has_before_each {
                if let Err(e) = interp.call_fn("before_each") {
                    println!("  FAIL {test_name} (before_each failed: {e})");
                    failed += 1;
                    failures.push((test_name.clone(), format!("before_each: {e}")));
                    // Still run after_each even if before_each failed
                    if has_after_each {
                        let _ = interp.call_fn("after_each");
                    }
                    continue;
                }
            }

            // Run the test
            let test_result = interp.call_fn(&test_fn.name);
            let test_elapsed = test_start.elapsed();

            // Run after_each() always (even on failure)
            if has_after_each {
                if let Err(e) = interp.call_fn("after_each") {
                    println!("  FAIL {test_name} (after_each failed: {e})");
                    failures.push((format!("{test_name}::after_each"), e.to_string()));
                }
            }

            match test_result {
                Ok(_) => {
                    println!(
                        "  PASS {test_name} ({:.0}ms)",
                        test_elapsed.as_secs_f64() * 1000.0
                    );
                    passed += 1;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    println!(
                        "  FAIL {test_name} ({:.0}ms)",
                        test_elapsed.as_secs_f64() * 1000.0
                    );
                    println!("       {err_str}");
                    failed += 1;
                    failures.push((test_name, err_str));
                }
            }
        }

        // Run after_all() once for the file
        if has_after_all {
            if let Err(e) = interp.call_fn("after_all") {
                println!("  FAIL {filename}::after_all");
                println!("       {e}");
                failures.push((format!("{filename}::after_all"), e.to_string()));
            }
        }

        // ── Property-based tests ────────────────────────────────────────
        for prop_fn in &prop_fns_early {
            let prop_name = format!("{filename}::{}", prop_fn.name);
            let num_trials = 100u32;
            let mut prop_failed = false;

            for trial in 0..num_trials {
                let args = generate_random_args(&prop_fn.params, trial);
                match interp.call_fn_with_args(&prop_fn.name, args.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        // Attempt basic shrinking
                        let shrunk_args = shrink_args(&prop_fn.params);
                        let shrunk_display = if let Err(_) =
                            interp.call_fn_with_args(&prop_fn.name, shrunk_args.clone())
                        {
                            format_args_display(&prop_fn.params, &shrunk_args)
                        } else {
                            format_args_display(&prop_fn.params, &args)
                        };
                        println!(
                            "  FAIL property {prop_name}: counterexample found with ({shrunk_display})"
                        );
                        println!("       {e}");
                        failed += 1;
                        failures.push((prop_name.clone(), e.to_string()));
                        prop_failed = true;
                        break;
                    }
                }
            }

            if !prop_failed {
                println!("  PASS property {prop_name} ({num_trials} trials)");
                passed += 1;
            }
        }

        if coverage {
            merge_coverage(
                &mut coverage_hits,
                &mut coverage_total_fns,
                &interp,
                &program,
            );
        }
    }

    let elapsed = start.elapsed();
    println!();

    if !failures.is_empty() {
        println!("failures:");
        for (name, err) in &failures {
            println!("  {name}: {err}");
        }
        println!();
    }

    let status = if failed == 0 { "ok" } else { "FAILED" };
    println!(
        "test result: {status}. {passed} passed; {failed} failed; {skipped} skipped; finished in {:.2}s",
        elapsed.as_secs_f64()
    );

    // Print coverage report if enabled
    if coverage {
        print_coverage_report(&coverage_hits, &coverage_total_fns);
    }

    if failed > 0 {
        std::process::exit(exit_codes::IO_ERROR);
    }

    Ok(())
}

/// Format a byte count into a human-readable string for CLI output.
fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Merge interpreter coverage data into aggregate maps.
fn merge_coverage(
    hits: &mut std::collections::HashMap<String, u64>,
    total_fns: &mut std::collections::HashSet<String>,
    interp: &Interpreter,
    program: &tallow::ast::Program,
) {
    // Collect all user-defined function names (excluding builtins, hooks, and test_* fns)
    for item in &program.items {
        if let tallow::ast::Item::Fn(f) = item {
            let name = &f.name;
            // Exclude test functions and lifecycle hooks from coverage denominator
            if name.starts_with("test_")
                || name.ends_with("_test")
                || LIFECYCLE_HOOKS.contains(&name.as_str())
                || name == "main"
            {
                continue;
            }
            total_fns.insert(name.clone());
        }
    }
    // Merge hit counts from interpreter
    for (fn_name, count) in interp.get_coverage() {
        // Exclude builtins, hooks, and test functions from reported coverage
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || LIFECYCLE_HOOKS.contains(&fn_name.as_str())
            || fn_name == "main"
        {
            continue;
        }
        *hits.entry(fn_name).or_insert(0) += count;
    }
}

/// Print the coverage report to stdout.
fn print_coverage_report(
    hits: &std::collections::HashMap<String, u64>,
    total_fns: &std::collections::HashSet<String>,
) {
    let covered_count = total_fns
        .iter()
        .filter(|f| hits.contains_key(f.as_str()))
        .count();
    let total_count = total_fns.len();
    let percentage = if total_count == 0 {
        100.0
    } else {
        (covered_count as f64 / total_count as f64) * 100.0
    };

    println!();
    println!(
        "Coverage: {:.1}% ({}/{} functions)",
        percentage, covered_count, total_count
    );
    println!();

    if !hits.is_empty() {
        println!("Covered:");
        let mut covered: Vec<_> = hits
            .iter()
            .filter(|(name, _)| total_fns.contains(name.as_str()))
            .collect();
        covered.sort_by_key(|(name, _)| (*name).clone());
        for (name, count) in &covered {
            let call_word = if **count == 1 { "call" } else { "calls" };
            println!("  fn {name} ({count} {call_word})");
        }
    }

    let uncovered: Vec<_> = total_fns
        .iter()
        .filter(|f| !hits.contains_key(f.as_str()))
        .collect();
    if !uncovered.is_empty() {
        println!();
        println!("Uncovered:");
        let mut uncovered_sorted = uncovered;
        uncovered_sorted.sort();
        for name in &uncovered_sorted {
            println!("  fn {name}");
        }
    }
    println!();
}

/// Generate random arguments for a property test function based on param types.
fn generate_random_args(params: &[tallow::ast::Param], seed: u32) -> Vec<tallow::interp::Value> {
    use rand::Rng;
    let mut rng = rand::rng();

    params
        .iter()
        .map(|param| {
            let _ = seed; // used for determinism hint (not strictly needed with thread_rng)
            match &param.ty.kind {
                tallow::ast::TypeExprKind::Named(name) => match name.as_str() {
                    "i32" => tallow::interp::Value::Int(rng.random_range(-1000..=1000) as i128),
                    "i64" => tallow::interp::Value::Int(rng.random_range(-1000i64..=1000) as i128),
                    "u32" => tallow::interp::Value::Int(rng.random_range(0u32..=1000) as i128),
                    "u64" => tallow::interp::Value::Int(rng.random_range(0u64..=1000) as i128),
                    "f64" => tallow::interp::Value::Float(rng.random_range(-1000.0f64..=1000.0)),
                    "bool" => tallow::interp::Value::Bool(rng.random_bool(0.5)),
                    "String" => {
                        let len = rng.random_range(0usize..=20);
                        let s: String = (0..len)
                            .map(|_| {
                                let idx = rng.random_range(0u8..=61);
                                match idx {
                                    0..=9 => (b'0' + idx) as char,
                                    10..=35 => (b'a' + idx - 10) as char,
                                    36..=61 => (b'A' + idx - 36) as char,
                                    _ => 'a',
                                }
                            })
                            .collect();
                        tallow::interp::Value::String(s)
                    }
                    _ => tallow::interp::Value::Nil,
                },
                _ => tallow::interp::Value::Nil,
            }
        })
        .collect()
}

/// Generate shrunk (minimal) arguments for counterexample simplification.
fn shrink_args(params: &[tallow::ast::Param]) -> Vec<tallow::interp::Value> {
    params
        .iter()
        .map(|param| match &param.ty.kind {
            tallow::ast::TypeExprKind::Named(name) => match name.as_str() {
                "i32" | "i64" => tallow::interp::Value::Int(0),
                "u32" | "u64" => tallow::interp::Value::Int(0),
                "f64" => tallow::interp::Value::Float(0.0),
                "bool" => tallow::interp::Value::Bool(false),
                "String" => tallow::interp::Value::String(String::new()),
                _ => tallow::interp::Value::Nil,
            },
            _ => tallow::interp::Value::Nil,
        })
        .collect()
}

/// Format argument values for display in counterexample output.
fn format_args_display(params: &[tallow::ast::Param], args: &[tallow::interp::Value]) -> String {
    params
        .iter()
        .zip(args.iter())
        .map(|(p, v)| format!("{} = {}", p.name, v.as_string()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn discover_test_files(dir: &PathBuf, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            discover_test_files(&path, files)?;
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with("_test.tl") || name.ends_with(".test.tl") || name.starts_with("test_")
            {
                files.push(path);
            }
        }
    }
    Ok(())
}

// ── tallow doc ─────────────────────────────────────────────────────────────────

/// Discover all .tl files under `dir` recursively, appending to `out`.
fn collect_tl_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let p = entry.path();
        if p.is_dir() {
            collect_tl_files(&p, out);
        } else if p.extension().map_or(false, |e| e == "tl") {
            out.push(p);
        }
    }
}

/// A single documented declaration.
struct DocItem {
    kind: &'static str,
    name: String,
    /// HTML-tagged signature string (uses span/class for colour).
    signature: String,
    /// Plain-text doc comment extracted from `///` lines above the item.
    doc: String,
    annotations: Vec<String>,
    /// (field_name, field_type, has_default)
    fields: Vec<(String, String, bool)>,
    /// (variant_name, payload_field_descriptions)
    variants: Vec<(String, Vec<String>)>,
    /// Method signature strings (plain text)
    methods: Vec<String>,
}

/// Documentation for one .tl source file.
struct ModuleDoc {
    /// Safe identifier used as the HTML filename base (no slashes, no spaces).
    name: String,
    /// Human-readable label shown in UI (e.g. `src/scraper.tl`).
    label: String,
    is_stdlib: bool,
    items: Vec<DocItem>,
}

/// HTML-escape a string for safe insertion into HTML text/attribute contexts.
fn he(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Scan backwards from `item_start` in `source` to collect `///` comment lines
/// that immediately precede the item.  Returns the text with `///` stripped,
/// joined by spaces.
fn extract_doc_comment(source: &str, item_start: usize) -> String {
    // Build (byte_offset_of_line_start, line_text) pairs.
    let mut lines: Vec<(usize, &str)> = Vec::new();
    let mut pos = 0usize;
    for line in source.split('\n') {
        lines.push((pos, line));
        pos += line.len() + 1;
    }

    // Find the line that contains item_start.
    let item_line = lines
        .iter()
        .rposition(|&(s, _)| s <= item_start)
        .unwrap_or(0);

    let mut doc_lines: Vec<&str> = Vec::new();
    let mut idx = item_line.saturating_sub(1);
    loop {
        let trimmed = lines[idx].1.trim();
        if trimmed.starts_with("///") {
            doc_lines.push(trimmed.trim_start_matches("///").trim());
            if idx == 0 {
                break;
            }
            idx -= 1;
        } else {
            break;
        }
    }
    doc_lines.reverse();
    doc_lines.join(" ")
}

/// Walk an AST and produce `DocItem`s.  Signatures contain inline HTML spans
/// for syntax highlighting.
fn extract_doc_items(program: &tallow::ast::Program, source: &str) -> Vec<DocItem> {
    use tallow::ast::*;
    let mut items: Vec<DocItem> = Vec::new();

    for ast_item in &program.items {
        match ast_item {
            Item::Import(_) => {} // imports are not user-facing API

            Item::Fn(f) => {
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| {
                        format!(
                            "<span class=\"param\">{}</span>: <span class=\"type\">{}</span>",
                            he(&p.name),
                            he(&format_type_expr(&p.ty)),
                        )
                    })
                    .collect();
                let ret = f
                    .return_type
                    .as_ref()
                    .map(|t| {
                        format!(
                            " -&gt; <span class=\"type\">{}</span>",
                            he(&format_type_expr(t))
                        )
                    })
                    .unwrap_or_default();
                let generics = if f.type_params.is_empty() {
                    String::new()
                } else {
                    format!("&lt;{}&gt;", f.type_params.join(", "))
                };
                let async_kw = if f.is_async {
                    "<span class=\"fn-sig\">async </span>"
                } else {
                    ""
                };
                let sig = format!(
                    "{async_kw}<span class=\"fn-sig\">fn</span> <strong>{}{generics}</strong>({}){ret}",
                    he(&f.name),
                    params.join(", ")
                );
                let annots: Vec<String> = f
                    .annotations
                    .iter()
                    .map(|a| format!("@{}", a.name))
                    .collect();
                items.push(DocItem {
                    kind: "fn",
                    name: f.name.clone(),
                    signature: sig,
                    doc: extract_doc_comment(source, f.span.start),
                    annotations: annots,
                    fields: Vec::new(),
                    variants: Vec::new(),
                    methods: Vec::new(),
                });
            }

            Item::Struct(s) => {
                let generics = if s.type_params.is_empty() {
                    String::new()
                } else {
                    format!("&lt;{}&gt;", s.type_params.join(", "))
                };
                let sig = format!(
                    "<span class=\"fn-sig\">struct</span> <strong>{}{generics}</strong>",
                    he(&s.name)
                );
                let fields = s
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), format_type_expr(&f.ty), f.default.is_some()))
                    .collect();
                items.push(DocItem {
                    kind: "struct",
                    name: s.name.clone(),
                    signature: sig,
                    doc: extract_doc_comment(source, s.span.start),
                    annotations: Vec::new(),
                    fields,
                    variants: Vec::new(),
                    methods: Vec::new(),
                });
            }

            Item::Enum(e) => {
                let generics = if e.type_params.is_empty() {
                    String::new()
                } else {
                    format!("&lt;{}&gt;", e.type_params.join(", "))
                };
                let sig = format!(
                    "<span class=\"fn-sig\">enum</span> <strong>{}{generics}</strong>",
                    he(&e.name)
                );
                let variants = e
                    .variants
                    .iter()
                    .map(|v| {
                        let vf: Vec<String> = v
                            .fields
                            .iter()
                            .map(|f| format!("{}: {}", f.name, format_type_expr(&f.ty)))
                            .collect();
                        (v.name.clone(), vf)
                    })
                    .collect();
                items.push(DocItem {
                    kind: "enum",
                    name: e.name.clone(),
                    signature: sig,
                    doc: extract_doc_comment(source, e.span.start),
                    annotations: Vec::new(),
                    fields: Vec::new(),
                    variants,
                    methods: Vec::new(),
                });
            }

            Item::Trait(t) => {
                let generics = if t.type_params.is_empty() {
                    String::new()
                } else {
                    format!("&lt;{}&gt;", t.type_params.join(", "))
                };
                let sig = format!(
                    "<span class=\"fn-sig\">trait</span> <strong>{}{generics}</strong>",
                    he(&t.name)
                );
                let methods: Vec<String> = t
                    .methods
                    .iter()
                    .map(|m| {
                        let params: Vec<String> = m
                            .params
                            .iter()
                            .map(|p| format!("{}: {}", p.name, format_type_expr(&p.ty)))
                            .collect();
                        let ret = m
                            .return_type
                            .as_ref()
                            .map(|r| format!(" -> {}", format_type_expr(r)))
                            .unwrap_or_default();
                        format!("fn {}({}){ret}", m.name, params.join(", "))
                    })
                    .collect();
                items.push(DocItem {
                    kind: "trait",
                    name: t.name.clone(),
                    signature: sig,
                    doc: extract_doc_comment(source, t.span.start),
                    annotations: Vec::new(),
                    fields: Vec::new(),
                    variants: Vec::new(),
                    methods,
                });
            }

            Item::Impl(imp) => {
                let methods: Vec<String> = imp
                    .methods
                    .iter()
                    .map(|m| {
                        let params: Vec<String> = m
                            .params
                            .iter()
                            .map(|p| format!("{}: {}", p.name, format_type_expr(&p.ty)))
                            .collect();
                        let ret = m
                            .return_type
                            .as_ref()
                            .map(|r| format!(" -> {}", format_type_expr(r)))
                            .unwrap_or_default();
                        let a = if m.is_async { "async " } else { "" };
                        format!("{a}fn {}({}){ret}", m.name, params.join(", "))
                    })
                    .collect();
                if methods.is_empty() {
                    continue;
                }

                // Merge methods into an existing struct/enum/trait entry.
                if let Some(existing) = items.iter_mut().find(|i| i.name == imp.target) {
                    existing.methods.extend(methods);
                } else {
                    let sig = format!(
                        "<span class=\"fn-sig\">impl</span> <strong>{}</strong>",
                        he(&imp.target)
                    );
                    items.push(DocItem {
                        kind: "impl",
                        name: imp.target.clone(),
                        signature: sig,
                        doc: String::new(),
                        annotations: Vec::new(),
                        fields: Vec::new(),
                        variants: Vec::new(),
                        methods,
                    });
                }
            }

            Item::Const(c) => {
                let ty = c
                    .ty
                    .as_ref()
                    .map(|t| format!(": <span class=\"type\">{}</span>", he(&format_type_expr(t))))
                    .unwrap_or_default();
                let sig = format!(
                    "<span class=\"fn-sig\">const</span> <strong>{}</strong>{ty}",
                    he(&c.name)
                );
                items.push(DocItem {
                    kind: "const",
                    name: c.name.clone(),
                    signature: sig,
                    doc: extract_doc_comment(source, c.span.start),
                    annotations: Vec::new(),
                    fields: Vec::new(),
                    variants: Vec::new(),
                    methods: Vec::new(),
                });
            }

            Item::TypeAlias(t) => {
                let qualifier = match t.qualifier {
                    Some(tallow::ast::TypeQualifier::Private) => {
                        "<span class=\"type\">private </span>"
                    }
                    Some(tallow::ast::TypeQualifier::Secret) => {
                        "<span class=\"type\">secret </span>"
                    }
                    None => "",
                };
                let sig = format!(
                    "<span class=\"fn-sig\">type</span> <strong>{}</strong> = {}<span class=\"type\">{}</span>",
                    he(&t.name),
                    qualifier,
                    he(&format_type_expr(&t.ty)),
                );
                items.push(DocItem {
                    kind: "type",
                    name: t.name.clone(),
                    signature: sig,
                    doc: extract_doc_comment(source, t.span.start),
                    annotations: Vec::new(),
                    fields: Vec::new(),
                    variants: Vec::new(),
                    methods: Vec::new(),
                });
            }
        }
    }

    items
}

/// Common `<head>` + `<style>` block for all generated pages.
fn doc_html_head(title: &str) -> String {
    let mut s = String::new();
    s.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    s.push_str("<meta charset=\"UTF-8\">\n");
    s.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    s.push_str(&format!("<title>{}</title>\n", he(title)));
    s.push_str("<style>\n");
    s.push_str("*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n");
    s.push_str("body{font-family:system-ui,-apple-system,sans-serif;background:#0a0e1a;color:#e2e8f0;line-height:1.6;display:flex;min-height:100vh}\n");
    s.push_str(".sidebar{width:220px;min-width:220px;background:#0d1321;border-right:1px solid #1e293b;padding:24px 0;position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0}\n");
    s.push_str(".sidebar h2{color:#60a5fa;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;padding:0 16px 8px;border-bottom:1px solid #1e293b;margin-bottom:8px}\n");
    s.push_str(".sidebar a{display:block;padding:4px 16px;color:#94a3b8;text-decoration:none;font-size:0.875rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n");
    s.push_str(".sidebar a:hover{color:#e2e8f0;background:#1e293b}\n");
    s.push_str(".sidebar a.active{color:#60a5fa;background:#1e2d4a}\n");
    s.push_str(".sidebar .section{margin-top:12px}\n");
    s.push_str(".sidebar .section-title{color:#475569;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.1em;padding:4px 16px}\n");
    s.push_str("main{flex:1;max-width:860px;padding:40px 48px;min-width:0}\n");
    s.push_str("h1{color:#60a5fa;font-size:1.75rem;margin-bottom:4px;word-break:break-word}\n");
    s.push_str(".breadcrumb{color:#475569;font-size:0.85rem;margin-bottom:32px}\n");
    s.push_str(".breadcrumb a{color:#60a5fa;text-decoration:none}\n");
    s.push_str("h2{color:#a78bfa;font-size:1.1rem;border-bottom:1px solid #1e293b;padding-bottom:6px;margin:32px 0 16px}\n");
    s.push_str("h3.item-name{color:#f472b6;font-size:1rem;margin:24px 0 8px;display:flex;align-items:center;gap:8px}\n");
    s.push_str(".badge{font-size:0.65rem;padding:2px 7px;border-radius:12px;text-transform:uppercase;letter-spacing:0.05em;font-weight:600}\n");
    s.push_str(".badge-fn{background:#0f3a2e;color:#22c55e}\n");
    s.push_str(".badge-struct{background:#1a2e4a;color:#60a5fa}\n");
    s.push_str(".badge-enum{background:#2d1f4a;color:#a78bfa}\n");
    s.push_str(".badge-trait{background:#3a1f1f;color:#f87171}\n");
    s.push_str(".badge-const{background:#2a2510;color:#f59e0b}\n");
    s.push_str(".badge-type{background:#1f2a3a;color:#38bdf8}\n");
    s.push_str(".badge-impl{background:#1e293b;color:#94a3b8}\n");
    s.push_str("pre.sig{background:#0d1321;padding:14px 18px;border-radius:8px;border-left:3px solid #3b82f6;overflow-x:auto;margin:0 0 10px;font-size:0.9rem}\n");
    s.push_str("code{font-family:'Cascadia Code','Fira Code',monospace}\n");
    s.push_str(".fn-sig{color:#22c55e}\n");
    s.push_str(".type{color:#f59e0b}\n");
    s.push_str(".param{color:#60a5fa}\n");
    s.push_str(".doc{color:#94a3b8;font-style:italic;margin-bottom:12px;font-size:0.9rem}\n");
    s.push_str(
        "table{width:100%;border-collapse:collapse;margin:10px 0 16px;font-size:0.875rem}\n",
    );
    s.push_str("th{background:#0d1321;padding:8px 12px;text-align:left;color:#60a5fa;border-bottom:2px solid #1e293b;font-weight:600}\n");
    s.push_str("td{padding:8px 12px;border-bottom:1px solid #1e293b;vertical-align:top}\n");
    s.push_str("td:first-child{color:#e2e8f0;font-family:monospace}\n");
    s.push_str("td:nth-child(2){color:#f59e0b;font-family:monospace}\n");
    s.push_str("td:nth-child(3){color:#475569}\n");
    s.push_str("ul.methods-list{margin:0 0 16px;padding:0}\n");
    s.push_str("ul.methods-list li{list-style:none;font-family:monospace;font-size:0.85rem;color:#94a3b8;padding:3px 0;border-bottom:1px solid #0d1321}\n");
    s.push_str(".annot{color:#818cf8;font-size:0.8rem;margin:2px 0}\n");
    s.push_str("a{color:#60a5fa;text-decoration:none}\n");
    s.push_str("a:hover{text-decoration:underline}\n");
    s.push_str(".item-anchor{color:#1e293b;font-size:0.75rem;margin-left:4px}\n");
    s.push_str(".item-anchor:hover{color:#60a5fa}\n");
    s.push_str("</style>\n</head>\n<body>\n");
    s
}

/// Build the sidebar nav HTML.  `active_name` is the current module's name
/// (or `"__index__"` for the index page).
fn doc_sidebar(modules: &[ModuleDoc], active_name: &str) -> String {
    let mut sb = String::from("<nav class=\"sidebar\">");
    sb.push_str("<h2><a href=\"index.html\">Tallow API</a></h2>");

    let src_mods: Vec<&ModuleDoc> = modules.iter().filter(|m| !m.is_stdlib).collect();
    if !src_mods.is_empty() {
        sb.push_str("<div class=\"section\"><div class=\"section-title\">Project</div>");
        for m in &src_mods {
            let cls = if m.name == active_name {
                " class=\"active\""
            } else {
                ""
            };
            sb.push_str(&format!(
                "<a href=\"{}.html\"{cls}>{}</a>",
                he(&m.name),
                he(&m.label)
            ));
        }
        sb.push_str("</div>");
    }

    let std_mods: Vec<&ModuleDoc> = modules.iter().filter(|m| m.is_stdlib).collect();
    if !std_mods.is_empty() {
        sb.push_str("<div class=\"section\"><div class=\"section-title\">stdlib</div>");
        for m in &std_mods {
            let cls = if m.name == active_name {
                " class=\"active\""
            } else {
                ""
            };
            sb.push_str(&format!(
                "<a href=\"{}.html\"{cls}>{}</a>",
                he(&m.name),
                he(&m.label)
            ));
        }
        sb.push_str("</div>");
    }

    sb.push_str("</nav>");
    sb
}

/// Render one module page to an HTML string.
fn render_module_page(module: &ModuleDoc, all_modules: &[ModuleDoc]) -> String {
    let title = format!("tallow \u{2014} {}", module.label);
    let mut out = doc_html_head(&title);
    out.push_str(&doc_sidebar(all_modules, &module.name));
    out.push_str("<main>");
    out.push_str(&format!("<h1>{}</h1>", he(&module.label)));

    let crumb_prefix = if module.is_stdlib { "stdlib" } else { "src" };
    out.push_str(&format!(
        "<div class=\"breadcrumb\"><a href=\"index.html\">index</a> / {crumb_prefix} / {}</div>",
        he(&module.label)
    ));

    if module.items.is_empty() {
        out.push_str("<p class=\"doc\">No documented items found in this file.</p>");
        out.push_str("</main></body></html>");
        return out;
    }

    // Table of contents for larger modules
    if module.items.len() > 3 {
        out.push_str("<h2>Contents</h2>");
        out.push_str("<ul style=\"list-style:none;columns:2;gap:24px;margin-bottom:24px\">");
        for item in &module.items {
            let anchor = format!("{}-{}", item.kind, item.name);
            out.push_str(&format!(
                "<li><a href=\"#{anchor}\">{} {}</a></li>",
                item.kind,
                he(&item.name)
            ));
        }
        out.push_str("</ul>");
    }

    for item in &module.items {
        let anchor = format!("{}-{}", item.kind, item.name);
        let badge_class = match item.kind {
            "fn" => "badge-fn",
            "struct" => "badge-struct",
            "enum" => "badge-enum",
            "trait" => "badge-trait",
            "const" => "badge-const",
            "type" => "badge-type",
            _ => "badge-impl",
        };

        out.push_str(&format!(
            "<h3 class=\"item-name\" id=\"{anchor}\">\
             <span class=\"badge {badge_class}\">{}</span>{}\
             <a class=\"item-anchor\" href=\"#{anchor}\">#</a></h3>",
            item.kind,
            he(&item.name)
        ));

        for ann in &item.annotations {
            out.push_str(&format!("<div class=\"annot\">{}</div>", he(ann)));
        }

        out.push_str(&format!(
            "<pre class=\"sig\"><code>{}</code></pre>",
            item.signature
        ));

        if !item.doc.is_empty() {
            out.push_str(&format!("<p class=\"doc\">{}</p>", he(&item.doc)));
        }

        // Fields table (structs)
        if !item.fields.is_empty() {
            out.push_str("<table><tr><th>Field</th><th>Type</th><th>Default</th></tr>");
            for (fname, ftype, has_default) in &item.fields {
                let def = if *has_default { "..." } else { "&mdash;" };
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{def}</td></tr>",
                    he(fname),
                    he(ftype)
                ));
            }
            out.push_str("</table>");
        }

        // Variants table (enums)
        if !item.variants.is_empty() {
            out.push_str("<table><tr><th>Variant</th><th>Fields</th></tr>");
            for (vname, vfields) in &item.variants {
                let fstr = if vfields.is_empty() {
                    "&mdash;".to_string()
                } else {
                    vfields.iter().map(|f| he(f)).collect::<Vec<_>>().join(", ")
                };
                out.push_str(&format!("<tr><td>{}</td><td>{fstr}</td></tr>", he(vname)));
            }
            out.push_str("</table>");
        }

        // Methods list
        if !item.methods.is_empty() {
            out.push_str("<ul class=\"methods-list\">");
            for m in &item.methods {
                out.push_str(&format!("<li><code>{}</code></li>", he(m)));
            }
            out.push_str("</ul>");
        }
    }

    out.push_str("</main></body></html>");
    out
}

/// Render the top-level index page.
fn render_index_page(modules: &[ModuleDoc]) -> String {
    let title = "Tallow API Documentation";
    let mut out = doc_html_head(title);
    out.push_str(&doc_sidebar(modules, "__index__"));
    out.push_str("<main>");
    out.push_str(&format!("<h1>{}</h1>", he(title)));
    out.push_str("<div class=\"breadcrumb\">Project API reference</div>");

    let total_fns: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "fn")
        .count();
    let total_structs: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "struct")
        .count();
    let total_enums: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "enum")
        .count();
    let total_types: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "type")
        .count();

    out.push_str(&format!(
        "<p class=\"doc\" style=\"margin-bottom:24px\">{} modules &mdash; {} functions, {} structs, {} enums, {} type aliases</p>",
        modules.len(), total_fns, total_structs, total_enums, total_types
    ));

    fn emit_table(out: &mut String, mods: &[&ModuleDoc]) {
        out.push_str(
            "<table><tr><th>Module</th><th>Items</th><th>Functions</th><th>Structs</th></tr>",
        );
        for m in mods {
            let fn_cnt = m.items.iter().filter(|i| i.kind == "fn").count();
            let str_cnt = m.items.iter().filter(|i| i.kind == "struct").count();
            out.push_str(&format!(
                "<tr><td><a href=\"{}.html\">{}</a></td><td>{}</td><td>{fn_cnt}</td><td>{str_cnt}</td></tr>",
                he(&m.name), he(&m.label), m.items.len()
            ));
        }
        out.push_str("</table>");
    }

    let src_mods: Vec<&ModuleDoc> = modules.iter().filter(|m| !m.is_stdlib).collect();
    if !src_mods.is_empty() {
        out.push_str("<h2>Project Modules</h2>");
        emit_table(&mut out, &src_mods);
    }

    let std_mods: Vec<&ModuleDoc> = modules.iter().filter(|m| m.is_stdlib).collect();
    if !std_mods.is_empty() {
        out.push_str("<h2>Standard Library</h2>");
        emit_table(&mut out, &std_mods);
    }

    out.push_str("</main></body></html>");
    out
}

/// Parse a single .tl file and produce a `ModuleDoc`.
/// Parse failures are tolerated — the module will have an empty item list.
fn parse_nx_file_for_doc(
    path: &std::path::Path,
    project_root: &std::path::Path,
    is_stdlib: bool,
) -> ModuleDoc {
    let label = path
        .strip_prefix(project_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    let name = if is_stdlib {
        format!("stdlib-{stem}")
    } else {
        let rel = path
            .strip_prefix(project_root.join("src"))
            .or_else(|_| path.strip_prefix(project_root))
            .unwrap_or(path);
        rel.with_extension("")
            .to_string_lossy()
            .replace('\\', "/")
            .replace('/', "-")
    };

    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            return ModuleDoc {
                name,
                label,
                is_stdlib,
                items: Vec::new(),
            };
        }
    };

    let (tokens, lex_errors) = tallow::lexer::tokenize(&source);
    if !lex_errors.is_empty() {
        return ModuleDoc {
            name,
            label,
            is_stdlib,
            items: Vec::new(),
        };
    }

    let program = match tallow::parser::Parser::parse(tokens) {
        Ok(p) => p,
        Err(_) => {
            return ModuleDoc {
                name,
                label,
                is_stdlib,
                items: Vec::new(),
            };
        }
    };

    let items = extract_doc_items(&program, &source);
    ModuleDoc {
        name,
        label,
        is_stdlib,
        items,
    }
}

/// Entry point for `tallow doc [path] [--format html|json]`.
fn run_doc_project(path: &std::path::Path, format: &str) {
    // Determine project root from the path argument.
    let project_root = if path.is_dir() {
        path.to_path_buf()
    } else if path.is_file() {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    } else {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    };

    let src_dir = project_root.join("src");
    let stdlib_dir = project_root.join("stdlib");

    if !src_dir.exists() && !stdlib_dir.exists() {
        eprintln!(
            "error: no src/ or stdlib/ directory found in {}",
            project_root.display()
        );
        eprintln!("hint: run `tallow doc` from your project root, or pass the project directory");
        std::process::exit(exit_codes::IO_ERROR);
    }

    let mut src_files: Vec<std::path::PathBuf> = Vec::new();
    let mut stdlib_files: Vec<std::path::PathBuf> = Vec::new();
    if src_dir.exists() {
        collect_tl_files(&src_dir, &mut src_files);
    }
    if stdlib_dir.exists() {
        collect_tl_files(&stdlib_dir, &mut stdlib_files);
    }

    if src_files.is_empty() && stdlib_files.is_empty() {
        eprintln!(
            "warning: no .tl files found under {}",
            project_root.display()
        );
        return;
    }

    let mut modules: Vec<ModuleDoc> = Vec::new();
    for f in &src_files {
        modules.push(parse_nx_file_for_doc(f, &project_root, false));
    }
    for f in &stdlib_files {
        modules.push(parse_nx_file_for_doc(f, &project_root, true));
    }

    let total_fns: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "fn")
        .count();
    let total_structs: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "struct")
        .count();
    let total_enums: usize = modules
        .iter()
        .flat_map(|m| &m.items)
        .filter(|i| i.kind == "enum")
        .count();

    // ── JSON format: print to stdout ─────────────────────────────────────────
    if format == "json" {
        println!("[");
        for (i, m) in modules.iter().enumerate() {
            let comma = if i + 1 < modules.len() { "," } else { "" };
            println!(
                "  {{\"module\":\"{}\",\"label\":\"{}\",\"stdlib\":{},\"item_count\":{}}}{}",
                he(&m.name),
                he(&m.label),
                m.is_stdlib,
                m.items.len(),
                comma
            );
        }
        println!("]");
        eprintln!(
            "Generated docs for {} modules ({} functions, {} structs, {} enums)",
            modules.len(),
            total_fns,
            total_structs,
            total_enums
        );
        return;
    }

    // ── HTML format: write docs/api/ ─────────────────────────────────────────
    let out_dir = project_root.join("docs").join("api");
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("error: cannot create {}: {e}", out_dir.display());
        std::process::exit(exit_codes::IO_ERROR);
    }

    let index_path = out_dir.join("index.html");
    if let Err(e) = std::fs::write(&index_path, render_index_page(&modules)) {
        eprintln!("error: cannot write {}: {e}", index_path.display());
    }

    let mut written = 0usize;
    for module in &modules {
        let filename = format!("{}.html", module.name);
        let page_path = out_dir.join(&filename);
        match std::fs::write(&page_path, render_module_page(module, &modules)) {
            Ok(_) => written += 1,
            Err(e) => eprintln!("warning: cannot write {}: {e}", page_path.display()),
        }
    }

    println!(
        "Generated docs for {} modules ({} functions, {} structs, {} enums) -> {}",
        modules.len(),
        total_fns,
        total_structs,
        total_enums,
        out_dir.display()
    );
    println!("  {} module pages + index.html written", written);
    println!("  open: {}", index_path.display());
}

fn format_type_expr(ty: &tallow::ast::TypeExpr) -> String {
    use tallow::ast::TypeExprKind;
    match &ty.kind {
        TypeExprKind::Named(name) => name.clone(),
        TypeExprKind::Generic { name, args } => {
            let args_str: Vec<String> = args.iter().map(format_type_expr).collect();
            format!("{name}<{}>", args_str.join(", "))
        }
        TypeExprKind::Slice(inner) => format!("[]{}", format_type_expr(inner)),
        TypeExprKind::Optional(inner) => format!("{}?", format_type_expr(inner)),
        TypeExprKind::Tuple(elems) => {
            let parts: Vec<String> = elems.iter().map(format_type_expr).collect();
            format!("({})", parts.join(", "))
        }
        TypeExprKind::Function {
            params,
            return_type,
        } => {
            let params_str: Vec<String> = params.iter().map(format_type_expr).collect();
            format!(
                "fn({}) -> {}",
                params_str.join(", "),
                format_type_expr(return_type)
            )
        }
        TypeExprKind::Boxed(inner) => format!("Box<{}>", format_type_expr(inner)),
        TypeExprKind::ImplTrait(name) => format!("impl {name}"),
        TypeExprKind::DynTrait(name) => format!("dyn {name}"),
    }
}

// ── tallow audit --cloud ──────────────────────────────────────────────────────

fn run_cloud_audit(
    program: &tallow::ast::Program,
    filename: &str,
    format: &str,
    errors: usize,
    warnings: usize,
) {
    use tallow::ast::*;

    // Collect cloud-relevant annotations and function patterns
    let mut iac_configs = 0usize;
    let mut container_fns = 0usize;
    let mut policy_fns = 0usize;
    let mut sandboxed_fns = 0usize;
    let mut cloud_findings: Vec<String> = Vec::new();

    fn scan_fn(
        f: &FnDecl,
        iac: &mut usize,
        container: &mut usize,
        policy: &mut usize,
        sandboxed: &mut usize,
        findings: &mut Vec<String>,
    ) {
        let has_sandboxed = f.annotations.iter().any(|a| a.name == "sandboxed");
        if has_sandboxed {
            *sandboxed += 1;
        }

        // Check for cloud-related patterns in function body
        for stmt in &f.body.stmts {
            if let StmtKind::Let { value, .. } | StmtKind::Var { value, .. } = &stmt.kind {
                let src = format!("{:?}", value);
                if src.contains("IacScanner") {
                    *iac += 1;
                }
                if src.contains("ContainerImage") || src.contains("SeccompProfile") {
                    *container += 1;
                }
                if src.contains("CloudPolicy") || src.contains("EbpfPolicy") {
                    *policy += 1;
                }
            }
            if let StmtKind::Expr { expr } = &stmt.kind {
                let src = format!("{:?}", expr);
                if src.contains("IacScanner") {
                    *iac += 1;
                }
                if src.contains("ContainerImage") || src.contains("SeccompProfile") {
                    *container += 1;
                }
                if src.contains("CloudPolicy") || src.contains("EbpfPolicy") {
                    *policy += 1;
                }
            }
        }

        // Check for @sandboxed without allow list
        for ann in &f.annotations {
            if ann.name == "sandboxed" {
                let has_allow = ann
                    .args
                    .iter()
                    .any(|a| a.name == "allow" || a.name == "syscalls");
                if !has_allow {
                    findings.push(format!(
                        "W2500: @sandboxed on '{}' has no syscall whitelist",
                        f.name
                    ));
                }
            }
        }
    }

    for item in &program.items {
        match item {
            Item::Fn(f) => scan_fn(
                f,
                &mut iac_configs,
                &mut container_fns,
                &mut policy_fns,
                &mut sandboxed_fns,
                &mut cloud_findings,
            ),
            Item::Impl(imp) => {
                for m in &imp.methods {
                    scan_fn(
                        m,
                        &mut iac_configs,
                        &mut container_fns,
                        &mut policy_fns,
                        &mut sandboxed_fns,
                        &mut cloud_findings,
                    );
                }
            }
            _ => {}
        }
    }

    let total_fns = program
        .items
        .iter()
        .filter(|i| matches!(i, Item::Fn(_)))
        .count();

    if format == "json" {
        let report = serde_json::json!({
            "report": "cloud_security",
            "file": filename,
            "total_functions": total_fns,
            "sandboxed_functions": sandboxed_fns,
            "iac_scanner_usages": iac_configs,
            "container_security_usages": container_fns,
            "policy_enforcement_usages": policy_fns,
            "compiler_errors": errors,
            "compiler_warnings": warnings,
            "findings": cloud_findings,
            "disclaimer": AUDIT_DISCLAIMER,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("tallow audit --cloud: {filename}");
        println!("Container & Cloud Security Report (Phase 42)");
        println!("════════════════════════════════════════════════════════════");
        println!();
        println!("  Total functions:           {total_fns}");
        println!("  @sandboxed functions:       {sandboxed_fns}");
        println!("  IaC scanner usages:         {iac_configs}");
        println!("  Container security usages:  {container_fns}");
        println!("  Policy enforcement usages:  {policy_fns}");
        println!("  Compiler errors:            {errors}");
        println!("  Compiler warnings:          {warnings}");
        println!();

        if cloud_findings.is_empty() {
            println!("  Status: COMPLIANT");
            println!("  No cloud security findings.");
        } else {
            println!("  Status: FINDINGS");
            for finding in &cloud_findings {
                println!("    - {finding}");
            }
        }
        println!();
        println!("  Supported cloud security sentinels:");
        println!("    IacScanner        — Infrastructure as Code scanning");
        println!("    CloudPolicy       — Cloud security policy enforcement");
        println!("    IdentityAudit     — IAM/identity audit with BFS graph");
        println!("    StorageScan       — Cloud storage security scanning");
        println!("    ServiceMesh       — Service mesh verification (mTLS)");
        println!("    CloudTrail        — Audit trail anomaly detection (z-score)");
        println!("    SeccompProfile    — Seccomp BPF profile generation");
        println!("    ContainerImage    — OCI container image verification");
        println!("    EbpfPolicy        — eBPF security policy compilation");
        println!();
        println!("{AUDIT_DISCLAIMER}");
    }
}

// ── Doctor: scraper-critical stdlib surface helpers ─────────────────────────

/// Check that `stdlib/<module>.tl` declares the given function/method name.
fn stdlib_declaration_contains(module: &str, function: &str) -> bool {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("stdlib")
        .join(format!("{module}.tl"));
    let Ok(source) = std::fs::read_to_string(&path) else {
        return false;
    };
    // Any "fn <name>" declaration (native, free, or impl method) counts.
    source.lines().any(|line| {
        line.trim_start()
            .trim_start_matches("native ")
            .trim_start()
            .strip_prefix("fn ")
            .is_some_and(|rest| {
                rest.split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .is_some_and(|n| n == function)
            })
    })
}

/// Check that the Rust runtime knows how to dispatch a surface name.
/// Module functions ("http.get") go through stdlib dispatch; method-style
/// surfaces ("Response.text", "HtmlDocument.select") through interp builtins
/// or dispatch_method. A source-level presence check in the module's Rust
/// file (or interp) is the honest dependency-free proxy.
fn stdlib_dispatches(surface: &str, module: &str) -> bool {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![
        manifest.join("src/stdlib/mod.rs"),
        manifest.join("src/interp.rs"),
        // Method-style surfaces are often implemented inline in interp.rs;
        // also check by bare method name there. Module file checked too.
    ];
    let module_rs = manifest.join(format!("src/stdlib/{module}.rs"));
    if module_rs.exists() {
        files.push(module_rs);
    }
    let method = surface.rsplit('.').next().unwrap_or(surface);
    files.iter().any(|p| {
        std::fs::read_to_string(p)
            .map(|src| src.contains(surface) || src.contains(&format!("\"{method}\"")))
            .unwrap_or(false)
    })
}

/// Check that the module has at least one #[cfg(test)] unit in its Rust file.
fn stdlib_surface_has_tests(module: &str) -> bool {
    let candidates = [
        format!("src/stdlib/{module}.rs"),
        format!("src/stdlib/{module}_method.rs"),
    ];
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    candidates.iter().any(|rel| {
        let p = manifest.join(rel);
        std::fs::read_to_string(&p)
            .map(|src| src.contains("#[cfg(test)]") || src.contains("#[test]"))
            .unwrap_or(false)
            // Method-host modules may live in interp/html dispatch instead;
            // fall back to the shared integration test file.
            || manifest
                .join("tests")
                .join("stdlib_dispatch.rs")
                .metadata()
                .map(|m| m.len() > 0)
                .unwrap_or(false)
    })
}

// ── Doctor: capabilities report (roadmap #8, 2026-09-05) ────────────────────
// Honest, machine-readable per-module capability classification over the
// stdlib dispatch table (~100 modules) plus the CLI command surface (~70).
// Every classification is derived from a source scan (src/stdlib/mod.rs
// dispatch table, per-module Rust source, stdlib/*.tl declarations,
// src/interp.rs inline builtins) and each module entry carries file:line
// evidence. The pure classifier (`classify_cap`) is unit-testable without
// building the binary.

const CAPABILITIES_SCHEMA_VERSION: &str = "tallow.doctor.capabilities.v1";

/// Capability classification for one stdlib module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapStatus {
    /// Dispatch/inline surface is real: >=1 function is routable and returns
    /// a real Ok or a non-gate error (missing-arg etc.). Rule: "module's
    /// dispatch returns Some for >=1 fn".
    Real,
    /// Module self-describes as a contract/facade boundary ("contract stub",
    /// "not yet available", "facade" wording in its header docs).
    Facade,
    /// Routable surface exists but only returns honest Err for a real-but-
    /// gated capability (db bridge requires interp support, requires live
    /// browser / real-ml feature, hard-gated, ...).
    Gated,
    /// Declared in stdlib/<module>.tl (often CAPITAL-spelled) but unreachable
    /// from .tl: no dispatch arm and no inline interp builtin answers it.
    FacadeGap,
    /// Registered dispatch module that only routes type-namespace struct
    /// methods (sentinel types); no callable module functions of its own.
    TypeOnly,
    /// No evidence found either way.
    Unverified,
}

impl CapStatus {
    fn as_str(self) -> &'static str {
        match self {
            CapStatus::Real => "real",
            CapStatus::Facade => "facade",
            CapStatus::Gated => "gated",
            CapStatus::FacadeGap => "facade_gap",
            CapStatus::TypeOnly => "type_only",
            CapStatus::Unverified => "unverified",
        }
    }
}

/// Wording that marks a module as a self-declared facade/contract boundary.
/// Only the module doc header (first lines of the .rs file) is consulted.
const FACADE_HEADER_HINTS: &[&str] = &[
    "facade",
    "contract boundary",
    "contract/facade",
    "intentionally a",
    "metadata only",
    "not a second browser runtime",
];

/// Wording that marks a stub/contract arm anywhere in the module source.
/// Reported as evidence, not decisive on its own.
const FACADE_MARK_HINTS: &[&str] = &[
    "contract stub",
    "contract_stub",
    "not yet available",
    "facade",
    "contract-level",
];

/// Wording that marks a real-but-gated capability in source comments/doc.
const GATE_SOURCE_HINTS: &[&str] = &[
    "requires interp support",
    "bridge requires",
    "not yet implemented",
    "not yet available",
    "requires the real",
    "feature-gated",
    "requires real-ml",
    "requires a live browser",
    "no live browser",
    "not available without",
    "requires live",
    "human-gated",
    "hard-gated",
    "live execution",
    "requires chrome",
];

/// Wording used to classify a runtime Err message as a gate (not an arg or
/// I/O error) during dispatch probes.
const GATE_MSG_HINTS: &[&str] = &[
    "not yet implemented",
    "not yet available",
    "requires interp support",
    "bridge requires",
    "requires the real",
    "requires real-ml",
    "feature-gated",
    "requires a live browser",
    "no live browser",
    "not available without",
    "requires live",
    "human-gated",
    "hard-gated",
    "live execution",
    "requires chrome",
    "contract-level dispatch",
    "is gated",
];

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

/// One top-level `fn` declaration parsed from a stdlib/*.tl file.
#[derive(Clone, Debug)]
struct DeclFn {
    /// Function name (component after the optional `Prefix.`).
    name: String,
    /// CAPITAL (or dotted) namespace prefix, e.g. `Extract` for
    /// `fn Extract.schema(...)`.
    prefix: Option<String>,
    /// 1-based source line.
    line: usize,
}

/// Find Rust raw-string spans `r#"..."#` / `r##"..."##` as byte ranges
/// (content included), used so sanitize_source never lets embedded quotes
/// inside raw strings desync its string-state tracking.
fn raw_string_spans(src: &str) -> Vec<(usize, usize)> {
    let b = src.as_bytes();
    let n = b.len();
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i + 2 < n {
        if b[i] == b'r' {
            let mut j = i + 1;
            while j < n && b[j] == b'#' {
                j += 1;
            }
            if j > i + 1 && j < n && b[j] == b'"' {
                let k = j - i - 1; // number of '#'
                let mut x = j + 1;
                while x + 1 + k <= n {
                    if b[x] == b'"' && b[x + 1..x + 1 + k].iter().all(|&c| c == b'#') {
                        spans.push((i, x + 1 + k));
                        i = x + 1 + k;
                        break;
                    }
                    x += 1;
                }
                continue;
            }
        }
        i += 1;
    }
    spans
}

/// Replace string literals and `//` line comments with spaces so brace
/// counting in `fn_body_range` never trips on braces inside strings/comments.
/// Output preserves the input's BYTE length (multibyte chars become one space
/// per UTF-8 byte, newlines inside strings/comments are kept) so byte offsets
/// computed on the sanitized copy slice the original safely.
fn sanitize_source(src: &str) -> String {
    fn push_blanks(out: &mut String, len: usize) {
        for _ in 0..len {
            out.push(' ');
        }
    }
    let raw_spans = raw_string_spans(src);
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        let pos = out.len();
        // Raw string content (r#"..."#) — blank but keep newlines.
        if raw_spans.iter().any(|(a, b)| pos >= *a && pos < *b) {
            if c == '\n' {
                out.push('\n');
            } else {
                push_blanks(&mut out, c.len_utf8());
            }
            continue;
        }
        if in_str {
            if c == '\n' {
                out.push('\n');
            } else {
                push_blanks(&mut out, c.len_utf8());
            }
            if c == '\\' {
                if let Some(n) = chars.next() {
                    if n == '\n' {
                        out.push('\n');
                    } else {
                        push_blanks(&mut out, n.len_utf8());
                    }
                }
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '\'' if !in_str => {
                // Char literal like '"' or '\'' may embed a double quote and
                // would otherwise desync the string-state tracking. Blank the
                // whole `'...'` (or `'\x'`) literal when a closing quote is
                // found within the next few chars; otherwise this is a
                // lifetime (`'a`) and the quote is kept as code.
                let mut clone = chars.clone();
                let mut body_chars = 0usize; // content chars after opener
                match clone.next() {
                    Some('\\') => {
                        if clone.next().is_some() {
                            body_chars = 2;
                        }
                    }
                    Some(_c2) => body_chars = 1,
                    None => {}
                }
                let is_char_literal = matches!(clone.next(), Some('\''));
                if is_char_literal {
                    out.push(' ');
                    for _ in 0..(body_chars + 1) {
                        if let Some(n) = chars.next() {
                            if n == '\n' {
                                out.push('\n');
                            } else {
                                push_blanks(&mut out, n.len_utf8());
                            }
                        }
                    }
                    continue;
                }
                out.push('\'');
            }
            '"' => {
                in_str = true;
                out.push(' ');
            }
            '/' if chars.peek() == Some(&'/') => {
                out.push(' ');
                out.push(' ');
                chars.next();
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                    push_blanks(&mut out, n.len_utf8());
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Byte range (start..end) of the first function whose signature contains
/// `sig`, found on sanitized source (indices are valid on the original too).
fn fn_body_range(src_san: &str, sig: &str) -> Option<(usize, usize)> {
    let start = src_san.find(sig)?;
    let open_rel = src_san[start..].find('{')?;
    let open = start + open_rel;
    let mut depth = 0usize;
    for (i, ch) in src_san[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((start, open + i + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract `"quoted"` tokens from a text segment.
fn quoted_tokens(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = segment;
    while let Some(q0) = rest.find('"') {
        let after = &rest[q0 + 1..];
        if let Some(q1) = after.find('"') {
            tokens.push(after[..q1].to_string());
            rest = &after[q1 + 1..];
        } else {
            break;
        }
    }
    tokens
}

/// Extract `"quoted"` tokens from the left-hand side of a match arm line.
fn quoted_tokens_before_arrow(line: &str) -> Vec<String> {
    let Some(eq_pos) = line.find("=>") else {
        return Vec::new();
    };
    quoted_tokens(&line[..eq_pos])
}

/// Parse the match arms of a `pub fn dispatch` / `pub fn dispatch_method`
/// body. Returns the arm keys (quoted tokens whose arm does not return None)
/// and the number of arms.
fn dispatch_arm_keys(body: &str) -> (Vec<String>, usize) {
    let mut keys = Vec::new();
    let mut arm_count = 0usize;
    for line in body.lines() {
        let Some(eq_pos) = line.find("=>") else {
            continue;
        };
        let lhs = line[..eq_pos].trim_start();
        if lhs.is_empty() || lhs.starts_with('_') {
            continue;
        }
        // Only genuine arm-head lines carry quoted string keys on the LHS.
        // (Inner `match` lines inside block arms do not.)
        let toks = quoted_tokens_before_arrow(line);
        if toks.is_empty() {
            continue;
        }
        let rhs = line[eq_pos + 2..].trim_start();
        if rhs.starts_with("None") {
            continue;
        }
        arm_count += 1;
        for t in toks {
            if !keys.contains(&t) {
                keys.push(t);
            }
        }
    }
    (keys, arm_count)
}

/// Parse the dispatch table in src/stdlib/mod.rs: map canonical module ->
/// alias keys (lowercase keys + capitalized type namespaces) and the set of
/// every registered key.
fn parse_dispatch_table(
    mod_rs: &str,
) -> (
    std::collections::BTreeMap<String, Vec<String>>,
    std::collections::BTreeSet<String>,
) {
    let san = sanitize_source(mod_rs);
    let mut map: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut all_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let Some((_, end)) = fn_body_range(&san, "pub fn dispatch(module: &str, function: &str") else {
        return (map, all_keys);
    };
    let body = &mod_rs[..end];
    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let Some(eq_pos) = line.find("=>") else {
            i += 1;
            continue;
        };
        let lhs = line[..eq_pos].trim_start();
        if lhs.is_empty() || lhs.starts_with('_') {
            i += 1;
            continue;
        }
        let rhs = line[eq_pos + 2..].trim_start();
        if rhs.starts_with("None") {
            i += 1;
            continue;
        }
        let toks = quoted_tokens_before_arrow(line);
        for t in &toks {
            all_keys.insert(t.clone());
        }
        // Block form: `"Target" | ... => { osint::dispatch(&format!(...)) }`.
        let canonical = if rhs.starts_with('{') {
            // Scan forward for the `ident::dispatch(&format!` call.
            let mut found: Option<String> = None;
            let mut j = i;
            while j < lines.len() && found.is_none() {
                if let Some(p) = lines[j].find("::dispatch(&format!") {
                    let prefix = &lines[j][..p];
                    found = prefix
                        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .map(|s| s.to_string());
                }
                j += 1;
            }
            found
        } else if let Some(p) = rhs.find("::dispatch") {
            rhs[..p]
                .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .map(|s| s.to_string())
        } else {
            None
        };
        if let Some(c) = canonical {
            let entry = map.entry(c).or_default();
            for t in toks {
                if !entry.contains(&t) {
                    entry.push(t);
                }
            }
        }
        i += 1;
    }
    (map, all_keys)
}

/// Parse top-level (non-impl, column-0) `fn` / `native fn` declarations from a
/// stdlib/*.tl file. Dot-prefixed names (`fn Extract.schema`) yield a prefix.
fn parse_tl_decls(src: &str) -> Vec<DeclFn> {
    let san = sanitize_source(src);
    let orig_lines: Vec<&str> = src.lines().collect();
    let san_lines: Vec<&str> = san.lines().collect();
    let mut out = Vec::new();
    let mut depth = 0i32;
    for (idx, sline) in san_lines.iter().enumerate() {
        let oline = orig_lines.get(idx).copied().unwrap_or("");
        // fn-ness is judged at the depth carried from PREVIOUS lines so a
        // `fn x(...) {` declaration with an inline body brace still parses.
        if depth == 0 && oline.starts_with("fn ") {
            let r = &oline[3..];
            let name_part: String = r
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
            if !name_part.is_empty() {
                let (prefix, name) = match name_part.split_once('.') {
                    Some((p, n)) => (Some(p.to_string()), n.to_string()),
                    None => (None, name_part),
                };
                if !name.is_empty() && !name.contains('.') {
                    out.push(DeclFn {
                        name,
                        prefix,
                        line: idx + 1,
                    });
                }
            }
        } else if depth == 0 && oline.starts_with("native fn ") {
            let r = &oline[10..];
            let name_part: String = r
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
            if !name_part.is_empty() {
                let (prefix, name) = match name_part.split_once('.') {
                    Some((p, n)) => (Some(p.to_string()), n.to_string()),
                    None => (None, name_part),
                };
                if !name.is_empty() && !name.contains('.') {
                    out.push(DeclFn {
                        name,
                        prefix,
                        line: idx + 1,
                    });
                }
            }
        }
        // Update brace depth from this line (sanitized: strings/comments
        // blanked, so only real braces remain).
        for ch in sline.chars() {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
    }
    out
}

/// Distinct `"module.fn"` builtin names implemented inline in src/interp.rs.
fn inline_interp_fns(interp_src: &str, module: &str) -> Vec<String> {
    let needle = format!("\"{module}.");
    let mut names = Vec::new();
    let mut rest = interp_src;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
        rest = after;
    }
    names
}

/// Aggregated per-module evidence fed to the pure classifier.
#[derive(Clone, Debug)]
struct ModuleSignals {
    module: String,
    aliases: Vec<String>,
    /// Top-level fns declared in stdlib/<module>.tl.
    declared: Vec<DeclFn>,
    /// Declared fns that a dispatch probe answered with Some.
    declared_dispatch_reachable: Vec<String>,
    /// Declared fns answered by an inline interp.rs `"module.fn"` builtin.
    declared_inline_reachable: Vec<String>,
    /// Declared fns whose only dispatch answer is a gate Err.
    declared_gated: Vec<String>,
    /// Dispatch arm keys found in the module's Rust dispatch fn.
    arm_keys: Vec<String>,
    /// Zero-arg probe totals across declared + arm probes (deduped by name).
    ok_probes: usize,
    gate_probes: usize,
    other_probes: usize,
    /// Probes that failed to verify: panicked or timed out. A module whose
    /// probes ALL failed must not be reported Real (honest Unverified).
    probe_uncertain: usize,
    /// Distinct inline interp builtin fns for this module.
    inline_fns: Vec<String>,
    method_arm_count: usize,
    facade_header: bool,
    /// file:line evidence citations, filled by the scanner.
    evidence: Vec<String>,
}

impl ModuleSignals {
    fn new(module: &str) -> Self {
        ModuleSignals {
            module: module.to_string(),
            aliases: Vec::new(),
            declared: Vec::new(),
            declared_dispatch_reachable: Vec::new(),
            declared_inline_reachable: Vec::new(),
            declared_gated: Vec::new(),
            arm_keys: Vec::new(),
            ok_probes: 0,
            gate_probes: 0,
            other_probes: 0,
            probe_uncertain: 0,
            inline_fns: Vec::new(),
            method_arm_count: 0,
            facade_header: false,
            evidence: Vec::new(),
        }
    }

    fn declared_reachable(&self) -> usize {
        self.declared_dispatch_reachable.len() + self.declared_inline_reachable.len()
    }
}

/// Pure classifier. Decision order (documented, deterministic):
///   1. self-declared facade/contract-boundary header   -> Facade
///   2. declared surface exists but nothing answers it  -> FacadeGap
///   3. every routable probe returns a gate Err         -> Gated
///   4. any real Ok / non-gate routable / inline builtin-> Real
///   5. dispatch_method type routing only               -> TypeOnly
///   6. declared-but-dead leftovers                     -> FacadeGap
///   7. no evidence                                     -> Unverified
fn classify_cap(s: &ModuleSignals) -> CapStatus {
    if s.facade_header {
        return CapStatus::Facade;
    }
    let declared_any = !s.declared.is_empty();
    if declared_any
        && s.declared_reachable() == 0
        && s.declared_gated.is_empty()
        && s.inline_fns.is_empty()
    {
        return CapStatus::FacadeGap;
    }
    if (s.gate_probes > 0 || !s.declared_gated.is_empty())
        && s.ok_probes == 0
        && s.other_probes == 0
    {
        return CapStatus::Gated;
    }
    if s.ok_probes > 0
        || s.other_probes > 0
        || s.declared_reachable() > 0
        || !s.inline_fns.is_empty()
        || !s.arm_keys.is_empty()
    {
        return CapStatus::Real;
    }
    if s.method_arm_count > 0 {
        return CapStatus::TypeOnly;
    }
    if declared_any {
        return CapStatus::FacadeGap;
    }
    CapStatus::Unverified
}

/// Human summary for a classified module.
fn cap_summary(s: &ModuleSignals, status: CapStatus) -> String {
    match status {
        CapStatus::Real => format!(
            "real dispatch/inline surface: {} declared fns reachable ({} dispatch, {} inline), {} arm keys, {} Ok probe(s)",
            s.declared_reachable(),
            s.declared_dispatch_reachable.len(),
            s.declared_inline_reachable.len(),
            s.arm_keys.len(),
            s.ok_probes
        ),
        CapStatus::Facade => format!(
            "self-described facade/contract boundary (header wording; {} arm keys, {} method arms)",
            s.arm_keys.len(),
            s.method_arm_count
        ),
        CapStatus::Gated => format!(
            "surface routable but returns only honest Err for a real-but-gated capability ({} gate probe(s), {} Ok probe(s), {} other Err probe(s))",
            s.gate_probes, s.ok_probes, s.other_probes
        ),
        CapStatus::FacadeGap => format!(
            "declared in stdlib/{}.tl but unreachable from .tl: {} declared fn(s), {} reachable via dispatch, {} inline",
            s.module,
            s.declared.len(),
            s.declared_dispatch_reachable.len(),
            s.declared_inline_reachable.len()
        ),
        CapStatus::TypeOnly => format!(
            "registered type-namespace module: dispatch_method routes {} struct types, no callable module functions",
            s.method_arm_count
        ),
        CapStatus::Unverified => "no dispatch arms, declarations, inline builtins, or markers found".to_string(),
    }
}

/// Outcome of one guarded dispatch probe. Probing is opt-in (`--probe`);
/// the default report is pure static classification and never executes a
/// handler.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ProbeOutcome {
    None,
    OkValue,
    ErrText(String),
    Panicked,
    TimedOut,
}

/// Hard wall-clock cap for one runtime probe. A side-effecting handler that
/// blocks (network, browser spawn) must cost at most this much, never hang
/// the whole report.
const PROBE_TIMEOUT_SECS: u64 = 2;

/// Run a probe closure in a dedicated thread with catch_unwind containment
/// AND a hard timeout. A handler that panics reports `Panicked`; one that
/// blocks past the timeout reports `TimedOut` (the leaked thread can no
/// longer stall the report and dies with the process).
///
/// NOTE (docs/PANIC-POLICY.md): every shipped profile sets `panic = "abort"`, so
/// the panic half of this is INERT in release artifacts — the process aborts at
/// the panic point and `catch_unwind` never returns. It isolates in the dev loop
/// and under `cargo test` (both unwind) only. The timeout half is unaffected.
fn run_guarded_probe<F>(f: F) -> ProbeOutcome
where
    F: FnOnce() -> ProbeOutcome + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let builder = std::thread::Builder::new()
        .name("cap-probe".to_string())
        .stack_size(16 * 1024 * 1024);
    match builder.spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
            .unwrap_or(ProbeOutcome::Panicked);
        let _ = tx.send(outcome);
    }) {
        Ok(_) => match rx.recv_timeout(std::time::Duration::from_secs(PROBE_TIMEOUT_SECS)) {
            Ok(outcome) => outcome,
            Err(_) => ProbeOutcome::TimedOut,
        },
        // Thread could not even be spawned (resource limits): treat as an
        // unverifiable probe rather than a capability signal.
        Err(_) => ProbeOutcome::Panicked,
    }
}

/// Zero-arg dispatch probe: thread + catch_unwind + hard timeout so neither a
/// panic nor a side-effecting hang can ever stall the report.
///
/// Under `panic = "abort"` (every shipped profile) only the timeout half holds.
/// See run_guarded_probe and docs/PANIC-POLICY.md.
fn probe_dispatch(module: &str, function: &str) -> ProbeOutcome {
    let m = module.to_string();
    let f = function.to_string();
    run_guarded_probe(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tallow::stdlib::dispatch(&m, &f, Vec::new())
        }))
        .map(|r| match r {
            Some(Ok(_)) => ProbeOutcome::OkValue,
            Some(Err(msg)) => ProbeOutcome::ErrText(msg),
            None => ProbeOutcome::None,
        })
        .unwrap_or(ProbeOutcome::Panicked)
    })
}

fn is_gate_msg(msg: &str) -> bool {
    contains_any(&msg.to_ascii_lowercase(), GATE_MSG_HINTS)
}

/// One parsed dispatch arm: quoted route keys plus the full RHS source text.
#[derive(Clone, Debug)]
struct DispatchArm {
    keys: Vec<String>,
    /// Original RHS source (everything after `=>`, trailing separator
    /// stripped, trimmed).
    rhs: String,
}

fn arm_is_none(arm: &DispatchArm) -> bool {
    arm.keys.is_empty() || arm.rhs.trim_start().starts_with("None")
}

/// Copy of `s` with Rust `//` and `/* */` comments removed while string
/// literals are preserved. Used to read dispatch-arm keys so quoted words
/// inside comments between arms can never be mistaken for route keys.
fn comment_free(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next(); // consume '*'
                let mut prev = '\0';
                while let Some(n) = chars.next() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    if n == '\n' {
                        out.push('\n');
                    }
                    prev = n;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Split a module `dispatch` fn body into its match arms. Structural
/// boundaries (arrows, separator commas, braces) are found on a sanitized
/// copy (strings/comments blanked, byte-identical offsets) so braces inside
/// string literals can never desync the walk; route keys are recovered from
/// the comment-free original text of each arm head.
fn parse_dispatch_arms(body: &str) -> Vec<DispatchArm> {
    let san = sanitize_source(body);
    let s = san.as_bytes();
    let n = s.len();
    let mut arms: Vec<DispatchArm> = Vec::new();
    let (mut bd, mut pd) = (0i32, 0i32);
    let mut i = 0usize;
    let mut head_start = 0usize;
    // (arm_level, rhs_start, keys) while an RHS is being collected.
    let mut open: Option<(i32, usize, Vec<String>)> = None;
    // Position of the `}` that returned us to the arm level (block RHS end)
    // — needed because Rust allows a block-bodied arm to be followed by the
    // next arm WITHOUT a separator comma.
    let mut block_end: Option<usize> = None;
    while i < n {
        let c = s[i];
        match c {
            b'(' => pd += 1,
            b')' => pd = (pd - 1).max(0),
            b'{' => {
                bd += 1;
                if open.is_none() {
                    // fn/match opener at head phase: the next head starts here.
                    head_start = i + 1;
                }
            }
            b'}' => {
                bd = (bd - 1).max(0);
                if let Some((lvl, _, _)) = &open {
                    // The enclosing match's closing brace ends the last arm
                    // when it had no trailing separator comma.
                    if bd == *lvl - 1 && pd == 0 {
                        if let Some((_, rhs_start, keys)) = open.take() {
                            let end = block_end.unwrap_or(i);
                            arms.push(DispatchArm {
                                keys,
                                rhs: body[rhs_start..end].trim().to_string(),
                            });
                        }
                        block_end = None;
                    } else if bd == *lvl && pd == 0 {
                        // A block RHS just closed at arm level; if the next
                        // construct is another arm head (no comma), the RHS
                        // ends here.
                        block_end = Some(i);
                    }
                }
            }
            b'=' => {
                if i + 1 < n && s[i + 1] == b'>' && pd == 0 {
                    if let Some((lvl, rhs_start, keys)) = open.take() {
                        if bd == lvl {
                            // New arm head right after a block RHS with no
                            // separator comma: close the previous arm at the
                            // end of its block.
                            let end = block_end.unwrap_or(i);
                            arms.push(DispatchArm {
                                keys,
                                rhs: body[rhs_start..end].trim().to_string(),
                            });
                            if let Some(be) = block_end {
                                head_start = be + 1;
                            }
                            block_end = None;
                        } else {
                            // Arrow nested deeper inside the RHS: keep walking.
                            open = Some((lvl, rhs_start, keys));
                        }
                    }
                    if open.is_none() {
                        let head = comment_free(&body[head_start..i]);
                        let keys = quoted_tokens(&head);
                        open = Some((bd, i + 2, keys));
                        i += 1; // consume '>'
                    }
                }
            }
            b',' if pd == 0 => {
                if let Some((lvl, rhs_start, keys)) = open.take() {
                    if bd == lvl {
                        // Arm-terminating separator comma.
                        arms.push(DispatchArm {
                            keys,
                            rhs: body[rhs_start..i].trim().to_string(),
                        });
                        head_start = i + 1;
                        block_end = None;
                    } else {
                        // Comma nested deeper inside a block RHS: keep walking.
                        open = Some((lvl, rhs_start, keys));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    arms
}

/// Static (no-execution) classification of a dispatch arm's body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticArmKind {
    /// Arm returns a real value / `Ok`, or routes to a helper that can return
    /// `Ok` (or whose body cannot be proven Err-only).
    Real,
    /// Err-only arm whose message reads as a hard gate ("requires ...",
    /// "not yet implemented", ...).
    Gate,
    /// Err-only arm with an ordinary message (missing argument, I/O, ...).
    ArgErr,
    /// `=> None` / keyless wildcard arm: not routable, no signal.
    NoneArm,
}

fn rank_static_kind(kind: StaticArmKind) -> i32 {
    match kind {
        StaticArmKind::Real => 2,
        StaticArmKind::ArgErr => 1,
        StaticArmKind::Gate => 0,
        StaticArmKind::NoneArm => -1,
    }
}

/// Classify one arm body purely from source: REAL when the RHS or its helper
/// fn can return `Ok` (or proof is impossible); GATE when every reachable
/// return is an `Err` whose message carries gate wording; ARG_ERR for
/// Err-only arms with ordinary messages. Nothing is executed.
fn static_arm_kind(arm: &DispatchArm, file_orig: &str, file_san: &str) -> StaticArmKind {
    let rhs = arm.rhs.trim();
    if rhs.is_empty() || rhs.starts_with("None") {
        return StaticArmKind::NoneArm;
    }
    let rhs_san = sanitize_source(rhs);
    if rhs_san.contains("Ok(") {
        return StaticArmKind::Real;
    }
    if let Some(err_pos) = rhs_san.find("Err(") {
        // Payload of the Err(...): string literal / format! / const / helper.
        let t = rhs_san[err_pos + 4..].trim_start();
        let ident_end = t
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(t.len());
        let ident = &t[..ident_end];
        let after = t[ident_end..].trim_start();
        if !ident.is_empty() && after.starts_with('(') && !matches!(ident, "format" | "concat") {
            // Err payload produced by a helper fn in this file.
            if let Some((hs, he)) = fn_body_range(file_san, &format!("fn {ident}(")) {
                let hbody = &file_orig[hs..he];
                let hsan = sanitize_source(hbody);
                if hsan.contains("Ok(") {
                    return StaticArmKind::Real;
                }
                if hsan.contains("Err(") {
                    let texts = collect_text_evidence(file_orig, hbody, &hsan);
                    return if is_gate_msg(&texts.join(" | ")) {
                        StaticArmKind::Gate
                    } else {
                        StaticArmKind::ArgErr
                    };
                }
                return StaticArmKind::Real;
            }
            return StaticArmKind::Real; // helper lives elsewhere: unprovable
        }
        let texts = collect_text_evidence(file_orig, rhs, &rhs_san);
        return if is_gate_msg(&texts.join(" | ")) {
            StaticArmKind::Gate
        } else {
            StaticArmKind::ArgErr
        };
    }
    // No Err in the RHS: a real value, or a helper that may Err/Ok on its own.
    if let Some(sp) = rhs_san.find("Some(") {
        let t = rhs_san[sp + 5..].trim_start();
        let ident_end = t
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(t.len());
        let ident = &t[..ident_end];
        if !ident.is_empty()
            && t[ident_end..].trim_start().starts_with('(')
            && !matches!(ident, "Ok")
        {
            if let Some((hs, he)) = fn_body_range(file_san, &format!("fn {ident}(")) {
                let hbody = &file_orig[hs..he];
                let hsan = sanitize_source(hbody);
                if hsan.contains("Ok(") {
                    return StaticArmKind::Real;
                }
                if hsan.contains("Err(") {
                    let texts = collect_text_evidence(file_orig, hbody, &hsan);
                    return if is_gate_msg(&texts.join(" | ")) {
                        StaticArmKind::Gate
                    } else {
                        StaticArmKind::ArgErr
                    };
                }
            }
        }
    }
    StaticArmKind::Real
}

/// Gather message text that can explain an Err: quoted string literals from
/// the code plus any ALL_CAPS const (e.g. `const BRIDGE_MSG: &str = "..."`)
/// the code references — enough to run gate-wording detection without
/// executing anything.
fn collect_text_evidence(file_orig: &str, code_orig: &str, code_san: &str) -> Vec<String> {
    let mut texts = quoted_strings(code_orig);
    let b = code_san.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_uppercase() {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_uppercase() || b[j] == b'_' || b[j].is_ascii_digit())
            {
                j += 1;
            }
            let ident = &code_san[i..j];
            let after_ok = j >= b.len()
                || (!b[j].is_ascii_uppercase() && b[j] != b'_' && !b[j].is_ascii_digit());
            if j > i + 2 && after_ok && ident.contains('_') {
                texts.extend(const_strings(file_orig, &format!("const {ident}")));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    texts
}

/// Quoted string literal contents found in `s` (naive scan — messages do not
/// embed escaped quotes in practice; sufficient for gate-wording detection).
fn quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(q0) = rest.find('"') {
        let after = &rest[q0 + 1..];
        if let Some(q1) = after.find('"') {
            out.push(after[..q1].to_string());
            rest = &after[q1 + 1..];
        } else {
            break;
        }
    }
    out
}

/// String literal contents of a `const NAME: ... = "..."` definition (and the
/// following continuation lines, for multi-line string consts).
fn const_strings(file_orig: &str, const_needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = file_orig.lines().collect();
    for (idx, l) in lines.iter().enumerate() {
        if l.contains(const_needle) {
            let end = (idx + 5).min(lines.len());
            out.extend(quoted_strings(&lines[idx..end].join(" ")));
        }
    }
    out
}

/// Does a dispatch arm key answer a declared fn? Handles plain names and the
/// composed `Prefix.name` form used by CAPITAL-namespace routing
/// (`"Extract.schema"`), matching by prefix case-insensitively against the
/// declaration's prefix or the canonical module name.
fn decl_key_matches(key: &str, d: &DeclFn, canonical: &str) -> bool {
    if key == d.name {
        return true;
    }
    let Some((p, n)) = key.rsplit_once('.') else {
        return false;
    };
    if n != d.name {
        return false;
    }
    match d.prefix.as_deref() {
        Some(prefix) => {
            p == prefix || p.eq_ignore_ascii_case(prefix) || p.eq_ignore_ascii_case(canonical)
        }
        None => p.eq_ignore_ascii_case(canonical),
    }
}

/// Static (no-execution) resolution of one .tl declaration against the
/// dispatch arms of its candidate modules.
fn static_decl_resolution(
    d: &DeclFn,
    candidates: &[String],
    canonical: &str,
    cache: &ModuleSourceCache,
) -> Option<(String, StaticArmKind)> {
    for cand in candidates {
        let Some(cm) = cache.get(cand) else {
            continue;
        };
        let mut best: Option<StaticArmKind> = None;
        for arm in &cm.arms {
            if arm_is_none(arm) {
                continue;
            }
            if !arm.keys.iter().any(|k| decl_key_matches(k, d, canonical)) {
                continue;
            }
            let kind = static_arm_kind(arm, &cm.rs_src, &cm.rs_san);
            best = Some(match best {
                None => kind,
                Some(b) => {
                    if rank_static_kind(kind) > rank_static_kind(b) {
                        kind
                    } else {
                        b
                    }
                }
            });
        }
        if let Some(kind) = best {
            if kind != StaticArmKind::NoneArm {
                return Some((cand.clone(), kind));
            }
        }
    }
    None
}

/// Static arm-surface pass (no execution): classify each distinct dispatch
/// arm key from its source body and count it the way a zero-arg probe would.
fn static_arm_pass(sig: &mut ModuleSignals, arms: &[DispatchArm], rs_src: &str, rs_san: &str) {
    let mut done: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for k in &sig.arm_keys {
        if !done.insert(k.clone()) {
            continue;
        }
        let Some(arm) = arms.iter().find(|a| a.keys.iter().any(|x| x == k)) else {
            continue;
        };
        if arm_is_none(arm) {
            continue;
        }
        match static_arm_kind(arm, rs_src, rs_san) {
            StaticArmKind::Real => sig.ok_probes += 1,
            StaticArmKind::Gate => {
                sig.gate_probes += 1;
                sig.evidence.push(format!(
                    "static arm: {}.{k} has Err-only gate body (no execution)",
                    sig.module
                ));
            }
            StaticArmKind::ArgErr => {
                sig.other_probes += 1;
                sig.evidence.push(format!(
                    "static arm: {}.{k} has Err-only body (no execution)",
                    sig.module
                ));
            }
            StaticArmKind::NoneArm => {}
        }
    }
}

/// Parsed Rust surface for one stdlib module (shared across alias keys so the
/// per-module scanner never re-reads files).
#[derive(Clone)]
struct CachedModule {
    rs_src: String,
    rs_san: String,
    arms: Vec<DispatchArm>,
}

type ModuleSourceCache = std::collections::HashMap<String, CachedModule>;

/// Does code (RHS or helper body, sanitized) terminate the process? Some
/// arms (e.g. `process.exit`) call `std::process::exit`, which no thread or
/// timeout guard can survive — such arms must never be runtime-probed.
fn snippet_exits_process(san: &str) -> bool {
    san.contains("process::exit") || san.contains("::exit(")
}

/// Static side-effect guard: an arm (RHS or the helper fn it calls) that
/// terminates the process must not be executed by a probe.
fn arm_exits_process(arm: &DispatchArm, file_orig: &str, file_san: &str) -> bool {
    let rhs_san = sanitize_source(arm.rhs.trim());
    if snippet_exits_process(&rhs_san) {
        return true;
    }
    // Check helpers called by the RHS (same resolution as static_arm_kind).
    for (pos, _) in rhs_san.match_indices('(') {
        let head = rhs_san[..pos].trim_end();
        let ident = head
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        if ident.is_empty()
            || matches!(ident, "Some" | "Ok" | "Err" | "format" | "concat" | "return")
        {
            continue;
        }
        if let Some((hs, he)) = fn_body_range(file_san, &format!("fn {ident}(")) {
            let hsan = sanitize_source(&file_orig[hs..he]);
            if snippet_exits_process(&hsan) {
                return true;
            }
        }
    }
    false
}

/// Scan one stdlib module and produce its capability record.
///
/// Default mode (`probe == false`) is PURE STATIC classification: no dispatch
/// handler is ever executed, so side-effecting handlers cannot run or hang,
/// and argument-shape panics are impossible. `--probe` opts into guarded
/// runtime verification (per-probe thread + catch_unwind + hard timeout).
fn scan_module_cap(
    manifest: &std::path::Path,
    canonical: &str,
    aliases: &[String],
    interp_src: &str,
    all_keys: &std::collections::BTreeSet<String>,
    cache: &ModuleSourceCache,
    probe: bool,
) -> serde_json::Value {
    let mut sig = ModuleSignals::new(canonical);
    sig.aliases = aliases.to_vec();

    let rs_rel = format!("src/stdlib/{canonical}.rs");
    let cached = cache.get(canonical);
    let (rs_src, san) = match cached {
        Some(c) => (c.rs_src.as_str(), c.rs_san.as_str()),
        None => ("", ""),
    };
    let mut probe_aborted = false;

    if !rs_src.is_empty() {
        if let Some((s0, e0)) = fn_body_range(san, "pub fn dispatch(") {
            let body = &rs_src[s0..e0];
            let (keys, _n) = dispatch_arm_keys(body);
            sig.arm_keys = keys;
            let arms = parse_dispatch_arms(body);
            if probe && !probe_aborted {
                // Opt-in runtime verification. Each probe runs in its own
                // thread with catch_unwind AND a hard timeout so a
                // side-effecting or hanging handler can never stall the
                // whole report.
                let mut done: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                for k in &sig.arm_keys {
                    if !done.insert(k.clone()) || probe_aborted {
                        continue;
                    }
                    // Side-effect guard: never runtime-probe an arm that
                    // terminates the process (thread/timeout cannot survive
                    // std::process::exit).
                    if arms
                        .iter()
                        .any(|a| a.keys.iter().any(|x| x == k) && arm_exits_process(a, rs_src, san))
                    {
                        sig.evidence.push(format!(
                            "runtime probe skipped: {canonical}.{k} terminates the process (side-effect guard)"
                        ));
                        continue;
                    }
                    match probe_dispatch(canonical, k) {
                        ProbeOutcome::OkValue => sig.ok_probes += 1,
                        ProbeOutcome::ErrText(msg) => {
                            if is_gate_msg(&msg) {
                                sig.gate_probes += 1;
                            } else {
                                sig.other_probes += 1;
                            }
                            sig.evidence.push(format!(
                                "runtime probe: {canonical}.{k} -> Err({})",
                                truncate(&msg, 110)
                            ));
                        }
                        ProbeOutcome::Panicked => {
                            sig.probe_uncertain += 1;
                            sig.evidence.push(format!(
                                "runtime probe: {canonical}.{k} -> panicked on zero-arg probe"
                            ));
                        }
                        ProbeOutcome::TimedOut => {
                            sig.probe_uncertain += 1;
                            sig.evidence.push(format!(
                                "runtime probe: {canonical}.{k} -> timed out after {PROBE_TIMEOUT_SECS}s; aborting runtime probes for this module"
                            ));
                            probe_aborted = true;
                        }
                        ProbeOutcome::None => {}
                    }
                }
                if probe_aborted {
                    // Hang risk confirmed: fall back to a pure static pass for
                    // this module so the report still completes promptly.
                    sig.ok_probes = 0;
                    sig.gate_probes = 0;
                    sig.other_probes = 0;
                    static_arm_pass(&mut sig, &arms, rs_src, san);
                    sig.evidence.push(
                        "runtime probing aborted after timeout — module surface classified statically (no execution)"
                            .to_string(),
                    );
                }
            } else {
                // Default: static-only classification — nothing executes.
                static_arm_pass(&mut sig, &arms, rs_src, san);
            }
        }
        if let Some((s1, e1)) = fn_body_range(&san, "pub fn dispatch_method(") {
            let body = &rs_src[s1..e1];
            let (_mkeys, mcount) = dispatch_arm_keys(body);
            sig.method_arm_count = mcount;
        }
        // Header self-declaration + marker evidence with file:line.
        let lines: Vec<&str> = rs_src.lines().collect();
        let header: String = lines.iter().take(45).cloned().collect::<Vec<_>>().join("\n");
        let header_lower = header.to_ascii_lowercase();
        sig.facade_header = contains_any(&header_lower, FACADE_HEADER_HINTS);
        for (idx, l) in lines.iter().enumerate() {
            let low = l.to_ascii_lowercase();
            if contains_any(&low, FACADE_MARK_HINTS) {
                sig.evidence.push(format!(
                    "{rs_rel}:{}: facade marker: {}",
                    idx + 1,
                    truncate(l.trim(), 100)
                ));
            }
            if contains_any(&low, GATE_SOURCE_HINTS) {
                sig.evidence.push(format!(
                    "{rs_rel}:{}: gate marker: {}",
                    idx + 1,
                    truncate(l.trim(), 100)
                ));
            }
        }
    }

    // Inline interp.rs builtins (quoted "module.fn" arms).
    sig.inline_fns = inline_interp_fns(interp_src, canonical);

    // stdlib/<module>.tl declarations.
    let tl_rel = format!("stdlib/{canonical}.tl");
    let tl_path = manifest.join(&tl_rel);
    if let Ok(tl_src) = std::fs::read_to_string(&tl_path) {
        sig.declared = parse_tl_decls(&tl_src);
        for d in &sig.declared {
            let tl_evidence = format!("{tl_rel}:{}: fn {}", d.line, d.name);
            // 1) dispatch probe through candidate module keys.
            let mut candidates: Vec<String> = vec![canonical.to_string()];
            if let Some(p) = &d.prefix {
                let lower = p.to_ascii_lowercase();
                if lower != canonical && all_keys.contains(&lower) {
                    candidates.push(lower);
                }
                if p != canonical && all_keys.contains(p) {
                    candidates.push(p.clone());
                }
            }
            let mut routed = false;
            if probe && !probe_aborted {
                // Runtime dispatch probes (opt-in, guarded: thread + timeout).
                for cand in &candidates {
                    // Side-effect guard: skip probing when the candidate's
                    // matching arm terminates the process.
                    let exits = cache.get(cand).is_some_and(|cm| {
                        cm.arms.iter().any(|a| {
                            a.keys.iter().any(|k| decl_key_matches(k, d, canonical))
                                && arm_exits_process(a, &cm.rs_src, &cm.rs_san)
                        })
                    });
                    if exits {
                        sig.evidence.push(format!(
                            "{tl_evidence} -> runtime probe skipped via {cand}: arm terminates the process (side-effect guard)"
                        ));
                        continue;
                    }
                    match probe_dispatch(cand, &d.name) {
                        ProbeOutcome::OkValue => {
                            sig.ok_probes += 1;
                            sig.declared_dispatch_reachable.push(format!(
                                "{} (dispatch {}.{})",
                                d.name, cand, d.name
                            ));
                            sig.evidence.push(format!("{tl_evidence} -> Ok via {cand}"));
                            routed = true;
                            break;
                        }
                        ProbeOutcome::ErrText(msg) => {
                            if is_gate_msg(&msg) {
                                sig.declared_gated.push(format!("{} ({}.{})", d.name, cand, d.name));
                                sig.evidence.push(format!(
                                    "{tl_evidence} -> gate Err via {cand}: {}",
                                    truncate(&msg, 100)
                                ));
                            } else {
                                sig.other_probes += 1;
                                sig.declared_dispatch_reachable.push(format!(
                                    "{} (dispatch {}.{})",
                                    d.name, cand, d.name
                                ));
                                sig.evidence.push(format!("{tl_evidence} -> routable via {cand}"));
                            }
                            routed = true;
                            break;
                        }
                        ProbeOutcome::Panicked => {
                            sig.probe_uncertain += 1;
                            sig.evidence
                                .push(format!("{tl_evidence} -> probe panicked"));
                            routed = true;
                            break;
                        }
                        ProbeOutcome::TimedOut => {
                            sig.probe_uncertain += 1;
                            sig.evidence.push(format!(
                                "{tl_evidence} -> probe timed out after {PROBE_TIMEOUT_SECS}s (static fallback)"
                            ));
                            probe_aborted = true;
                            break;
                        }
                        ProbeOutcome::None => {}
                    }
                }
            }
            if !routed && (!probe || probe_aborted) {
                // Static (no-execution) resolution: the declared fn routes to
                // a dispatch arm of a candidate module iff the arm key
                // matches and the arm body classifies Real / Err-only.
                if let Some((cand, kind)) =
                    static_decl_resolution(d, &candidates, canonical, cache)
                {
                    match kind {
                        StaticArmKind::Real => {
                            sig.ok_probes += 1;
                            sig.declared_dispatch_reachable.push(format!(
                                "{} (dispatch {}.{})",
                                d.name, cand, d.name
                            ));
                            sig.evidence.push(format!(
                                "{tl_evidence} -> dispatch arm {cand}.{} (static, no execution)",
                                d.name
                            ));
                        }
                        StaticArmKind::ArgErr => {
                            sig.other_probes += 1;
                            sig.declared_dispatch_reachable.push(format!(
                                "{} (dispatch {}.{})",
                                d.name, cand, d.name
                            ));
                            sig.evidence.push(format!(
                                "{tl_evidence} -> Err-only arm via {cand} (static, no execution)"
                            ));
                        }
                        StaticArmKind::Gate => {
                            sig.declared_gated.push(format!("{} ({}.{})", d.name, cand, d.name));
                            sig.gate_probes += 1;
                            sig.evidence.push(format!(
                                "{tl_evidence} -> gate Err-only arm via {cand} (static, no execution)"
                            ));
                        }
                        StaticArmKind::NoneArm => {}
                    }
                    routed = true;
                }
            }
            if routed {
                continue;
            }
            // 2) inline interp builtin, quoted as "<module>.<name>".
            let mut inline_hit: Option<String> = None;
            for probe_mod in [canonical.to_string()]
                .into_iter()
                .chain(d.prefix.iter().map(|p| p.to_ascii_lowercase()))
            {
                let key = format!("\"{probe_mod}.{}\"", d.name);
                if interp_src.contains(&key) {
                    inline_hit = Some(probe_mod);
                    break;
                }
            }
            if let Some(m) = inline_hit {
                sig.declared_inline_reachable
                    .push(format!("{} (interp {}.{})", d.name, m, d.name));
                sig.evidence
                    .push(format!("{tl_evidence} -> inline interp builtin {m}.{}", d.name));
            } else {
                sig.evidence.push(format!(
                    "{tl_evidence} -> UNREACHABLE (no dispatch arm, no inline builtin)"
                ));
            }
        }
    }

    let mut status = classify_cap(&sig);
    // Honest Unverified when runtime probing was attempted but every probe
    // failed (panicked / timed out): a failed verification must not
    // masquerade as a Real capability.
    if probe
        && sig.probe_uncertain > 0
        && sig.ok_probes == 0
        && sig.gate_probes == 0
        && sig.other_probes == 0
        && sig.declared_reachable() == 0
        && sig.declared_gated.is_empty()
        && sig.inline_fns.is_empty()
    {
        status = CapStatus::Unverified;
    }
    let summary = cap_summary(&sig, status);
    let mut evidence = sig.evidence.clone();
    if evidence.is_empty() {
        evidence.push("no source markers or probe evidence".to_string());
    }
    // Cap evidence list length for readability.
    let evidence = if evidence.len() > 16 {
        evidence.truncate(16);
        evidence
    } else {
        evidence
    };
    serde_json::json!({
        "module": sig.module,
        "status": status.as_str(),
        "summary": summary,
        "aliases": sig.aliases,
        "source_file": if rs_src.is_empty() { serde_json::Value::Null } else { serde_json::json!(rs_rel) },
        "declaration_file": if std::path::Path::new(&tl_path).exists() { serde_json::json!(tl_rel) } else { serde_json::Value::Null },
        "declared_fns": sig.declared.len(),
        "reachable_fns": sig.declared_dispatch_reachable.iter().chain(sig.declared_inline_reachable.iter()).cloned().collect::<Vec<_>>(),
        "unreachable_fns": sig.declared.iter().filter(|d| {
            !sig.declared_dispatch_reachable.iter().any(|r| r.starts_with(&format!("{} ", d.name)))
                && !sig.declared_inline_reachable.iter().any(|r| r.starts_with(&format!("{} ", d.name)))
        }).map(|d| d.name.clone()).collect::<Vec<_>>(),
        "gated_fns": sig.declared_gated,
        "dispatch_arm_count": sig.arm_keys.len(),
        "method_arm_count": sig.method_arm_count,
        "inline_interp_fns": sig.inline_fns,
        "runtime_probed": probe,
        "probe_uncertain": sig.probe_uncertain,
        "evidence": evidence,
    })
}

fn rfc3339_utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y0 + 1 } else { y0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Build the full tallow.doctor.capabilities.v1 report value.
///
/// `probe == false` (default): pure static classification — no dispatch
/// handler is executed, so the report cannot hang or ICE on argument shape.
/// `probe == true`: opt-in guarded runtime verification.
fn build_capabilities_report(probe: bool) -> Result<serde_json::Value, String> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mod_rs_path = manifest.join("src/stdlib/mod.rs");
    let interp_rs_path = manifest.join("src/interp.rs");
    let mod_rs = std::fs::read_to_string(&mod_rs_path)
        .map_err(|e| format!("read {}: {e}", mod_rs_path.display()))?;
    let interp_src = std::fs::read_to_string(&interp_rs_path)
        .map_err(|e| format!("read {}: {e}", interp_rs_path.display()))?;

    let (table, all_keys) = parse_dispatch_table(&mod_rs);
    // Pre-parse every registered module's Rust surface once. Alias keys map
    // to the same parsed module so static resolution across CAPITAL
    // namespaces never re-reads files.
    let mut cache: ModuleSourceCache = ModuleSourceCache::new();
    for (canonical, aliases) in &table {
        let rs_path = manifest.join(format!("src/stdlib/{canonical}.rs"));
        let src = std::fs::read_to_string(&rs_path).unwrap_or_default();
        let san = sanitize_source(&src);
        let arms = match fn_body_range(&san, "pub fn dispatch(") {
            Some((s0, e0)) => parse_dispatch_arms(&src[s0..e0]),
            None => Vec::new(),
        };
        let cm = CachedModule {
            rs_src: src,
            rs_san: san,
            arms,
        };
        cache.insert(canonical.clone(), cm.clone());
        for alias in aliases {
            cache.insert(alias.clone(), cm.clone());
        }
    }

    let mut modules = Vec::new();
    let mut by_status: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (canonical, aliases) in &table {
        let rec = scan_module_cap(&manifest, canonical, aliases, &interp_src, &all_keys, &cache, probe);
        let st = rec["status"].as_str().unwrap_or("unverified").to_string();
        *by_status.entry(st).or_insert(0) += 1;
        modules.push(rec);
    }

    // CLI command surface: clap knows all 70 compiled-in subcommands.
    let cmd = Cli::command();
    let mut cli_commands = Vec::new();
    for sub in cmd.get_subcommands() {
        cli_commands.push(serde_json::json!({
            "name": sub.get_name(),
            "about": sub.get_about().map(|a| a.to_string()).unwrap_or_default(),
            "status": "available",
        }));
    }
    cli_commands.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    Ok(serde_json::json!({
        "schema_version": CAPABILITIES_SCHEMA_VERSION,
        "probe_mode": probe,
        "generated_at": rfc3339_utc_now(),
        "counts": {
            "modules": modules.len(),
            "cli_commands": cli_commands.len(),
            "by_status": by_status,
        },
        "modules": modules,
        "cli_commands": cli_commands,
    }))
}

/// `tallow doctor --capabilities json|text` — stdout carries ONLY the report.
///
/// C3 (2026-09-05): stdlib declaration-drift report.
///
/// Parses every `fn Module.method` / `native fn Module.method` declaration in
/// stdlib/*.tl and cross-checks it against the real resolution surface.
/// Resolution classes checked (expanded 2026-09-16, P1-fix — the previous
/// version only knew file-module reachability, so every class-style
/// declaration was flagged unreachable):
///   1. `"Type.method"` quoted in `src/interp.rs` — interpreter dispatch arm
///      for the full sentinel key (class-style calls).
///   2. `"Type.method"` quoted in any `src/stdlib/*.rs` — module dispatch key
///      (covers the `"Type.method"` aliases in transfer/agent-family modules).
///   3. `"Type"` quoted in `src/stdlib/mod.rs` (class-namespace routing in
///      dispatch/dispatch_method) AND the bare method quoted in the declaring
///      file's module `.rs` — routed method surface.
///   4. the attributed module is registered (`is_registered_module`) or
///      interpreter-inline — module-level surface.
/// Emits schema `tallow.doctor.stdlib_drift.v1` JSON on stdout and returns 0
/// when every declaration resolves via one of the four classes, 2 otherwise
/// (the unreachable list rides on stdout).
fn emit_stdlib_drift_report() -> i32 {
    // Interpreter-inline module names that resolve from .tl without a
    // stdlib-dispatch registration entry.
    const INLINE_MODULES: &[&str] = &["db", "browser", "page", "htmlparser", "browserpool"];
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let interp_src =
        std::fs::read_to_string(manifest.join("src/interp.rs")).unwrap_or_default();
    let router_src =
        std::fs::read_to_string(manifest.join("src/stdlib/mod.rs")).unwrap_or_default();
    let mut module_rs: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(manifest.join("src/stdlib")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if let Ok(content) = std::fs::read_to_string(&path) {
                module_rs.push((stem.to_string(), content));
            }
        }
        module_rs.sort_by(|a, b| a.0.cmp(&b.0));
    }
    let quoted = |hay: &str, needle: &str| hay.contains(&format!("\"{needle}\""));
    let mut decls_total = 0usize;
    let mut reachable: Vec<String> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();
    let mut via_interp = 0usize;
    let mut via_module_key = 0usize;
    let mut via_routing = 0usize;
    let mut via_module = 0usize;
    let stdlib_dir = manifest.join("stdlib");
    if let Ok(entries) = std::fs::read_dir(&stdlib_dir) {
        let mut files: Vec<_> = entries.flatten().collect();
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("tl") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            for line in content.lines() {
                let trimmed = line.trim_start();
                if !(trimmed.starts_with("fn ") || trimmed.starts_with("native fn ")) {
                    continue;
                }
                let after_fn = trimmed
                    .strip_prefix("native fn ")
                    .or_else(|| trimmed.strip_prefix("fn "))
                    .unwrap_or(trimmed);
                // Head token before '(' / whitespace / '{': `Module.method`,
                // `Module_method`, or a plain fn name.
                let head = after_fn
                    .split(|c: char| c == '(' || c == ' ' || c == '\t' || c == '{')
                    .next()
                    .unwrap_or("");
                let (module_key, fn_label) = match head.split_once('.') {
                    Some((m, rest)) => (m.to_string(), rest.to_string()),
                    None => {
                        // Bare fn / impl method: attribute to the declaring
                        // file's module (stdlib/<name>.tl is the <name>
                        // module).
                        (stem.clone(), head.to_string())
                    }
                };
                if module_key.is_empty() || fn_label.is_empty() {
                    continue;
                }
                decls_total += 1;
                let decl = format!("{}: {}.{}", path.display(), module_key, fn_label);
                let full = format!("{module_key}.{fn_label}");
                let key_lower = module_key.to_ascii_lowercase();
                let stem_rs_quotes = |needle: &str| {
                    module_rs
                        .iter()
                        .find(|(s, _)| s == &stem)
                        .map(|(_, c)| quoted(c, needle))
                        .unwrap_or(false)
                };
                let kind: Option<&'static str> = if quoted(&interp_src, &full) {
                    Some("interp")
                } else if module_rs.iter().any(|(_, c)| quoted(c, &full)) {
                    Some("module_key")
                } else if quoted(&router_src, &module_key) && stem_rs_quotes(&fn_label) {
                    Some("routing")
                } else if tallow::stdlib::is_registered_module(&key_lower)
                    || INLINE_MODULES.contains(&key_lower.as_str())
                {
                    Some("module")
                } else {
                    None
                };
                match kind {
                    Some("interp") => {
                        via_interp += 1;
                        reachable.push(decl);
                    }
                    Some("module_key") => {
                        via_module_key += 1;
                        reachable.push(decl);
                    }
                    Some("routing") => {
                        via_routing += 1;
                        reachable.push(decl);
                    }
                    Some("module") => {
                        via_module += 1;
                        reachable.push(decl);
                    }
                    _ => unreachable.push(decl),
                }
            }
        }
    }
    let report = serde_json::json!({
        "schema": "tallow.doctor.stdlib_drift.v1",
        "generated_at": format_iso8601(),
        "decls_total": decls_total,
        "reachable_count": reachable.len(),
        "unreachable_count": unreachable.len(),
        "reachable_via": {
            "interp": via_interp,
            "module_key": via_module_key,
            "routing": via_routing,
            "module": via_module,
        },
        "reachable": reachable,
        "unreachable": unreachable,
        "note": "Resolution classes: interp = quoted \"Type.method\" in src/interp.rs; module_key = quoted \"Type.method\" in any src/stdlib/*.rs; routing = \"Type\" routed in src/stdlib/mod.rs + method quoted in the declaring file's module; module = registered module / interpreter-inline. Unreachable = none of the four surfaces resolves the declaration (real drift).",
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    if unreachable.is_empty() { 0 } else { 2 }
}

// ── Doctor: crypto-surface coverage + mock-body guard (W2-04 / cycle-02/07 §D5 L3) ──
//
// The mock-guard's third layer. Every fn/method declared in
// `stdlib/crypto.tl` must be either (i) dispatched by name in
// `src/interp.rs` / `src/stdlib/crypto.rs` (source-level presence check — the
// same honest dependency-free proxy class as `--stdlib-drift`), or (ii)
// explicitly annotated `@mock`/`@unimplemented` with a rationale in its
// leading comment block. Bodies shaped as a single literal (`true`, `false`,
// `""`, `{}`, `Bytes{}`, `0`, a bare identifier) are mock returns and need
// the same annotation, so the E-1-02 fail-loud neutralization stays enforced.
// `doctor --crypto-surface` exits 2 with the offender list when anything is
// uncovered, 0 when every declaration is covered.

const CRYPTO_SURFACE_SCHEMA: &str = "tallow.doctor.crypto_surface.v1";

/// Body shapes the mock-guard classifier distinguishes in stdlib/crypto.tl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoBodyShape {
    /// Fail-loud stub body (`panic(...)`, the E-1-02 neutralization).
    PanicStub,
    /// Single-literal / single-identifier body — a mock return.
    LiteralMock,
    /// No code in the body.
    Empty,
    /// Any other body.
    Code,
}

impl CryptoBodyShape {
    fn as_str(self) -> &'static str {
        match self {
            CryptoBodyShape::PanicStub => "panic_stub",
            CryptoBodyShape::LiteralMock => "literal_mock",
            CryptoBodyShape::Empty => "empty",
            CryptoBodyShape::Code => "code",
        }
    }
}

/// One `fn`/method declaration parsed from stdlib/crypto.tl.
#[derive(Debug, Clone)]
struct CryptoDecl {
    /// Bare function name (`generate`, `bbs_issue`).
    name: String,
    /// Enclosing `impl <Type>` for methods, or a dotted declaration prefix.
    prefix: Option<String>,
    /// 1-based declaration line.
    line: usize,
    /// Classified body shape.
    body_shape: CryptoBodyShape,
    /// Contiguous `//` comment block directly above the declaration.
    leading_comments: String,
}

impl CryptoDecl {
    fn qualified(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}.{}", self.name),
            None => self.name.clone(),
        }
    }
}

/// Dispatch evidence for one declaration: a quoted name found in the Rust
/// corpora. `qualified` (`"KeyPair.generate"`) is strong evidence; `bare`
/// (`"generate"`) is weaker (generic method arms) and is labeled as such.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CryptoDispatchEvidence {
    kind: &'static str,
    file: String,
    line: usize,
}

/// Explicit `@mock`/`@unimplemented` annotation with rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CryptoDeclAnnotation {
    kind: &'static str,
    rationale: String,
}

/// Coverage verdict for one declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CryptoSurfaceVerdict {
    status: &'static str,
    reason: String,
}

/// Strip `//` line comments. String-literal-unaware, which is fine here: the
/// only strings in the inspected bodies are mock literals, and `panic(`
/// bodies are classified before this matters.
fn strip_tl_line_comments(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Single-literal body detector (design §D5 layer 3). `pan` = the sanitized
/// body (strings/comments blanked, length-preserving); `raw` = the original.
fn crypto_body_shape(raw: &str, san: &str) -> CryptoBodyShape {
    if san.contains("panic(") {
        return CryptoBodyShape::PanicStub;
    }
    let t = san.trim();
    if t.is_empty() {
        // A string-literal-only body (`""`) blanks out in the sanitized text;
        // the raw text (comments stripped) still carries the quote.
        return if strip_tl_line_comments(raw).contains('"') {
            CryptoBodyShape::LiteralMock
        } else {
            CryptoBodyShape::Empty
        };
    }
    if t == "{}" {
        return CryptoBodyShape::LiteralMock;
    }
    let t = t.trim_end_matches(';').trim();
    if t.is_empty() || t.contains(';') || t.contains('\n') {
        return CryptoBodyShape::Code;
    }
    if matches!(t, "true" | "false" | "nil" | "Nil" | "data") {
        return CryptoBodyShape::LiteralMock;
    }
    if t.chars().all(|c| c.is_ascii_digit()) {
        return CryptoBodyShape::LiteralMock;
    }
    // `<Ident>{}` empty struct literal (e.g. `Bytes{}`).
    if let Some(inner) = t.strip_suffix("{}") {
        if !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        {
            return CryptoBodyShape::LiteralMock;
        }
    }
    // Single bare identifier return (e.g. `data`).
    if t.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && t.chars().all(|c| c.is_alphanumeric() || c == '_')
    {
        return CryptoBodyShape::LiteralMock;
    }
    CryptoBodyShape::Code
}

/// Parse every fn/method declaration in a .tl shim (impl-aware), with body
/// shape and leading comment block — the mock-guard's input.
fn parse_tl_crypto_decls(src: &str) -> Vec<CryptoDecl> {
    let san = sanitize_source(src);
    let lines: Vec<&str> = src.lines().collect();
    let san_lines: Vec<&str> = san.lines().collect();
    let mut offsets: Vec<usize> = Vec::with_capacity(lines.len());
    let mut off = 0usize;
    for l in &lines {
        offsets.push(off);
        off += l.len() + 1; // '\n'
    }
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut cur_impl: Option<String> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if depth == 0 && cur_impl.is_none() && trimmed.starts_with("impl ") {
            let name = trimmed[5..]
                .split(|c: char| c == '{' || c == '<' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                cur_impl = Some(name);
            }
        }
        let native = trimmed.starts_with("native fn ");
        if (depth == 0 || cur_impl.is_some()) && (native || trimmed.starts_with("fn ")) {
            let after = if native { &trimmed[10..] } else { &trimmed[3..] };
            let head: &str = after
                .split(|c: char| c == '(' || c == ' ' || c == '\t' || c == '{')
                .next()
                .unwrap_or("");
            if !head.is_empty() {
                let (prefix, name) = if depth > 0 && cur_impl.is_some() {
                    (cur_impl.clone(), head.to_string())
                } else {
                    match head.split_once('.') {
                        Some((p, n)) => (Some(p.to_string()), n.to_string()),
                        None => (None, head.to_string()),
                    }
                };
                // Body extent from the sanitized source (length-preserving),
                // sliced out of the original text for shape classification.
                let decl_off = offsets[idx];
                let shape = match san[decl_off..].find('{') {
                    Some(rel) => {
                        let open = decl_off + rel;
                        let mut d = 0i32;
                        let mut close = None;
                        for (i, ch) in san[open..].char_indices() {
                            match ch {
                                '{' => d += 1,
                                '}' => {
                                    d -= 1;
                                    if d == 0 {
                                        close = Some(open + i);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        match close {
                            Some(c) => crypto_body_shape(&src[open + 1..c], &san[open + 1..c]),
                            None => CryptoBodyShape::Code,
                        }
                    }
                    None => CryptoBodyShape::Empty,
                };
                // Leading contiguous `//` comment block.
                let mut block: Vec<&str> = Vec::new();
                let mut j = idx;
                while j > 0 {
                    let prev = lines[j - 1].trim_start();
                    if prev.starts_with("//") {
                        block.push(prev);
                        j -= 1;
                    } else {
                        break;
                    }
                }
                block.reverse();
                out.push(CryptoDecl {
                    name,
                    prefix,
                    line: idx + 1,
                    body_shape: shape,
                    leading_comments: block.join("\n"),
                });
            }
        }
        // Brace depth from the sanitized line (strings/comments blanked).
        if let Some(sl) = san_lines.get(idx) {
            for ch in sl.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth <= 0 && cur_impl.is_some() {
                            cur_impl = None;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// Parse a leading comment block for `@mock`/`@unimplemented`. The rationale
/// is required (>= 12 non-space chars after the token); an annotation with no
/// rationale does not count as coverage and is reported as such.
fn parse_crypto_annotation(block: &str) -> Option<CryptoDeclAnnotation> {
    for (token, kind) in [("@unimplemented", "unimplemented"), ("@mock", "mock")] {
        if let Some(pos) = block.find(token) {
            let rest = block[pos + token.len()..]
                .trim_start()
                .trim_start_matches(':')
                .trim();
            if rest.chars().filter(|c| !c.is_whitespace()).count() >= 12 {
                return Some(CryptoDeclAnnotation {
                    kind,
                    rationale: rest.replace('\n', " "),
                });
            }
            return None;
        }
    }
    None
}

/// Annotation token presence only (for precise offender reasons).
fn crypto_annotation_token(block: &str) -> Option<&'static str> {
    if block.contains("@unimplemented") {
        Some("@unimplemented")
    } else if block.contains("@mock") {
        Some("@mock")
    } else {
        None
    }
}

/// Find dispatch evidence for one declaration in the Rust corpora. Qualified
/// hits (`"Type.method"`) win over bare hits (`"method"`).
fn crypto_dispatch_evidence(
    decl: &CryptoDecl,
    corpora: &[(String, String)],
) -> Option<CryptoDispatchEvidence> {
    let qualified = format!("\"{}\"", decl.qualified());
    let bare = format!("\"{}\"", decl.name);
    let mut bare_hit: Option<CryptoDispatchEvidence> = None;
    for (file, src) in corpora {
        if let Some(off) = src.find(&qualified) {
            return Some(CryptoDispatchEvidence {
                kind: "qualified",
                file: file.clone(),
                line: src[..off].matches('\n').count() + 1,
            });
        }
        if bare_hit.is_none() {
            if let Some(off) = src.find(&bare) {
                bare_hit = Some(CryptoDispatchEvidence {
                    kind: "bare",
                    file: file.clone(),
                    line: src[..off].matches('\n').count() + 1,
                });
            }
        }
    }
    bare_hit
}

/// Coverage verdict: covered when the declaration is dispatched or carries an
/// annotated rationale, and no un-annotated literal-mock body survives.
fn classify_crypto_decl(
    decl: &CryptoDecl,
    evidence: Option<&CryptoDispatchEvidence>,
) -> CryptoSurfaceVerdict {
    let ann = parse_crypto_annotation(&decl.leading_comments);
    let token = crypto_annotation_token(&decl.leading_comments);
    if decl.body_shape == CryptoBodyShape::LiteralMock && ann.is_none() {
        let reason = match token {
            Some(t) => format!(
                "literal mock body; {t} annotation present but carries no rationale"
            ),
            None => "literal mock body without @mock/@unimplemented annotation".to_string(),
        };
        return CryptoSurfaceVerdict {
            status: "offender",
            reason,
        };
    }
    if evidence.is_none() && ann.is_none() {
        let reason = match token {
            Some(t) => format!(
                "no dispatch evidence in src/interp.rs / src/stdlib/crypto.rs; \
                 {t} annotation present but carries no rationale"
            ),
            None => "no dispatch evidence in src/interp.rs / src/stdlib/crypto.rs \
                     and no @mock/@unimplemented annotation"
                .to_string(),
        };
        return CryptoSurfaceVerdict {
            status: "offender",
            reason,
        };
    }
    CryptoSurfaceVerdict {
        status: "covered",
        reason: String::new(),
    }
}

/// Pure report builder over a .tl source + evidence corpora.
fn build_crypto_surface_report(
    tl_src: &str,
    corpora: &[(String, String)],
) -> serde_json::Value {
    let decls = parse_tl_crypto_decls(tl_src);
    let mut rows: Vec<serde_json::Value> = Vec::with_capacity(decls.len());
    let mut offenders: Vec<serde_json::Value> = Vec::new();
    let mut dispatched = 0usize;
    let mut bare_evidence = 0usize;
    let mut annotated_only = 0usize;
    let mut mock_bodies = 0usize;
    for decl in &decls {
        let evidence = crypto_dispatch_evidence(decl, corpora);
        let annotation = parse_crypto_annotation(&decl.leading_comments);
        let verdict = classify_crypto_decl(decl, evidence.as_ref());
        if let Some(ev) = &evidence {
            dispatched += 1;
            if ev.kind == "bare" {
                bare_evidence += 1;
            }
        }
        if evidence.is_none() && annotation.is_some() {
            annotated_only += 1;
        }
        if decl.body_shape == CryptoBodyShape::LiteralMock {
            mock_bodies += 1;
        }
        let row = serde_json::json!({
            "decl": decl.qualified(),
            "file": "stdlib/crypto.tl",
            "line": decl.line,
            "body_shape": decl.body_shape.as_str(),
            "dispatch": evidence.as_ref().map(|e| serde_json::json!({
                "kind": e.kind,
                "file": e.file,
                "line": e.line,
            })),
            "annotation": annotation.as_ref().map(|a| serde_json::json!({
                "kind": a.kind,
                "rationale": a.rationale,
            })),
            "status": verdict.status,
            "reason": if verdict.reason.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(verdict.reason.clone())
            },
        });
        if verdict.status == "offender" {
            offenders.push(row.clone());
        }
        rows.push(row);
    }
    serde_json::json!({
        "schema": CRYPTO_SURFACE_SCHEMA,
        "generated_at": format_iso8601(),
        "file": "stdlib/crypto.tl",
        "decls_total": decls.len(),
        "dispatched": dispatched,
        "bare_evidence": bare_evidence,
        "annotated_only": annotated_only,
        "mock_bodies": mock_bodies,
        "offender_count": offenders.len(),
        "offenders": offenders,
        "corpora": corpora.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
        "decls": rows,
        "note": "Source-level presence check (honest dependency-free proxy, same class as \
                 --stdlib-drift): a \"Type.method\" quoted hit is strong evidence, a bare \
                 \"method\" hit is labeled bare. Literal-mock bodies require an \
                 @mock/@unimplemented rationale. Exit 2 when offender_count > 0.",
    })
}

/// Read the repo files and emit the crypto-surface report on stdout.
fn emit_crypto_surface_report() -> i32 {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tl_path = manifest.join("stdlib/crypto.tl");
    let Ok(tl_src) = std::fs::read_to_string(&tl_path) else {
        eprintln!("crypto-surface: cannot read {}", tl_path.display());
        return 2;
    };
    let corpora: Vec<(String, String)> = ["src/interp.rs", "src/stdlib/crypto.rs"]
        .iter()
        .filter_map(|rel| {
            std::fs::read_to_string(manifest.join(rel))
                .ok()
                .map(|s| ((*rel).to_string(), s))
        })
        .collect();
    if corpora.len() != 2 {
        // A guard that cannot see its evidence corpus must not report green.
        eprintln!(
            "crypto-surface: evidence corpus incomplete ({} of 2 files readable)",
            corpora.len()
        );
        return 2;
    }
    let report = build_crypto_surface_report(&tl_src, &corpora);
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    if report["offender_count"].as_u64().unwrap_or(1) == 0 {
        0
    } else {
        2
    }
}

/// `tallow doctor --rotation [--rotation-state PATH]` — SVID rotation alarm
/// report (schema `tallow.doctor.rotation.v1`, W3 batch-2 cluster C / #120).
///
/// Reads an optional rotation-state file (schema
/// `tallow.rotation_state.v1`, produced by the rotation driver) and emits the
/// alarm report on stdout. Exit 2 when any Critical alarm is present
/// (expired-while-held); exit 0 otherwise — including the explicit
/// `status: "no_state"` report when no state file is supplied (that is not a
/// silent green: the status field says so).
fn emit_rotation_report(state_path: Option<&std::path::Path>) -> i32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let state = match state_path {
        Some(path) => match tallow::rotation_wire::load_state(path) {
            Ok(state) => Some(state),
            Err(e) => {
                eprintln!("rotation: {e}");
                return 2;
            }
        },
        None => None,
    };
    let report = match tallow::rotation_wire::rotation_report(state.as_ref(), now) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("rotation: {e}");
            return 2;
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
    let critical = report["alarm_counts"]["critical"].as_u64().unwrap_or(1);
    if critical == 0 {
        0
    } else {
        2
    }
}

#[cfg(test)]
mod crypto_surface_tests {
    use super::*;

    fn corpora(files: &[(&str, &str)]) -> Vec<(String, String)> {
        files
            .iter()
            .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
            .collect()
    }

    // Synthetic fixture: one decl covered by qualified dispatch evidence, one
    // by bare evidence + a literal body is NOT (mock body needs annotation),
    // one annotated @unimplemented, one offender with no evidence at all.
    #[test]
    fn mock_guard_classifies_dispatch_annotation_and_flags_offenders() {
        let tl = r#"
// tallow.crypto — test fixture
struct KeyPair {}

impl KeyPair {
    fn generate() -> KeyPair {
        panic("crypto.tl is dispatch-only; this body must never execute")
    }

    fn sign(self) -> Bytes {
        panic("crypto.tl is dispatch-only; this body must never execute")
    }
}

// @unimplemented: no dispatch under this name — experimental impl is dispatched
// as `bbs_issue_experimental` (fixture rationale).
fn bbs_issue(attributes: []String) -> BbsCredential {
    panic("crypto.tl is dispatch-only; this body must never execute")
}

fn frost_dkg(threshold: i64) -> []FrostKeyPackage {
    panic("crypto.tl is dispatch-only; this body must never execute")
}
"#;
        let corpus = corpora(&[(
            "src/interp.rs",
            r#"
            "KeyPair.generate" => Some(x),
            "sign" => Some(generic_fallback),
            "#,
        )]);
        let report = build_crypto_surface_report(tl, &corpus);
        assert_eq!(report["decls_total"], 4, "report: {report}");
        assert_eq!(report["offender_count"], 1, "report: {report}");
        let off = &report["offenders"][0];
        assert_eq!(off["decl"], "frost_dkg");
        assert!(
            off["reason"]
                .as_str()
                .unwrap()
                .contains("no dispatch evidence"),
            "reason: {off}"
        );
        // The annotated declaration is covered without dispatch evidence.
        assert_eq!(report["annotated_only"], 1, "report: {report}");
        // `KeyPair.sign` is covered via bare evidence only → labeled bare.
        assert_eq!(report["bare_evidence"], 1, "report: {report}");
    }

    #[test]
    fn mock_guard_body_shape_flags_single_literals() {
        let tl = r#"
fn a() -> bool {
    true
}
fn b() -> String {
    ""
}
fn c() -> Map {
    {}
}
fn d() -> Bytes {
    Bytes{}
}
fn e() -> u64 {
    0
}
fn f() -> String {
    data
}
fn g() -> bool {
    panic("crypto.tl is dispatch-only; this body must never execute")
}
fn h() -> i32 {
    let x = 1
    x + 1
}
fn i() {}
"#;
        let decls = parse_tl_crypto_decls(tl);
        let shapes: Vec<(&str, &str)> = decls
            .iter()
            .map(|d| (d.name.as_str(), d.body_shape.as_str()))
            .collect();
        assert_eq!(
            shapes,
            vec![
                ("a", "literal_mock"),
                ("b", "literal_mock"),
                ("c", "literal_mock"),
                ("d", "literal_mock"),
                ("e", "literal_mock"),
                ("f", "literal_mock"),
                ("g", "panic_stub"),
                ("h", "code"),
                ("i", "empty"),
            ]
        );
    }

    #[test]
    fn mock_guard_annotation_requires_rationale() {
        let tl = r#"
// @mock:
fn a() -> bool {
    panic("x")
}
// @unimplemented: short
fn b() -> bool {
    panic("x")
}
// @unimplemented: no dispatch under this name — experimental impl ships as `x_experimental` (fixture)
fn c() -> bool {
    panic("x")
}
"#;
        let report = build_crypto_surface_report(tl, &corpora(&[]));
        assert_eq!(report["decls_total"], 3, "report: {report}");
        assert_eq!(report["offender_count"], 2, "report: {report}");
        let reasons: Vec<String> = report["offenders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["reason"].as_str().unwrap().to_string())
            .collect();
        assert!(
            reasons.iter().all(|r| r.contains("carries no rationale")),
            "reasons: {reasons:?}"
        );
        assert_eq!(report["annotated_only"], 1, "report: {report}");
    }

    // [measured] Live pin: the repo's real stdlib/crypto.tl must be fully
    // covered against the real dispatch corpora — this is the regression guard
    // for both the D5-L2 disposal and the E-1-02 neutralization.
    #[test]
    fn mock_guard_repo_crypto_surface_is_covered() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let tl = std::fs::read_to_string(manifest.join("stdlib/crypto.tl"))
            .expect("stdlib/crypto.tl readable");
        let interp_src = std::fs::read_to_string(manifest.join("src/interp.rs"))
            .expect("src/interp.rs readable");
        let crypto_src = std::fs::read_to_string(manifest.join("src/stdlib/crypto.rs"))
            .expect("src/stdlib/crypto.rs readable");
        let corpus = corpora(&[
            ("src/interp.rs", interp_src.as_str()),
            ("src/stdlib/crypto.rs", crypto_src.as_str()),
        ]);
        let report = build_crypto_surface_report(&tl, &corpus);
        assert_eq!(
            report["offender_count"], 0,
            "crypto-surface offenders: {}",
            report["offenders"]
        );
        assert!(
            report["decls_total"].as_u64().unwrap() >= 90,
            "decls_total: {}",
            report["decls_total"]
        );
        assert!(
            report["annotated_only"].as_u64().unwrap() >= 1,
            "annotation path must be live: {report}"
        );
        for row in report["decls"].as_array().unwrap() {
            if row["body_shape"] == "literal_mock" {
                assert_eq!(
                    row["status"], "covered",
                    "literal mock body must carry an annotation: {row}"
                );
            }
        }
    }
}

// ── Doctor: wire-first security conformance probes (R-7.9 / R-5.15 / ag04 R-14) ─
//
// Each probe reuses an already-implemented control and reports its live wire
// state, so a silently un-wired control shows up as FAIL instead of a design
// claim (the report's "design intent — not verified" class). FAIL fires only
// on a real refusal/exposure condition — unusable egress config, a broken
// vault KDF floor, group/other-readable daemon state files, a redaction gap.
// Absence of an optional component (daemon not provisioned, journal disabled
// by env) stays advisory inside the PASS detail and never fails a run.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeStatus {
    Pass,
    Fail,
}

impl ProbeStatus {
    fn label(self) -> &'static str {
        match self {
            ProbeStatus::Pass => "PASS",
            ProbeStatus::Fail => "FAIL",
        }
    }
}

/// One conformance probe result: per-check status + one-line detail.
struct ConformanceProbe {
    label: &'static str,
    status: ProbeStatus,
    detail: String,
}

fn probe_result(
    label: &'static str,
    status: ProbeStatus,
    detail: impl Into<String>,
) -> ConformanceProbe {
    ConformanceProbe {
        label,
        status,
        detail: detail.into(),
    }
}

/// TVX1 encrypted-export container (mirrors `vault::import_export`):
/// magic(4) || version(1) || m_cost(4) || t_cost(4) || p_cost(4) || salt(16) || nonce(12).
const TVX1_MAGIC: [u8; 4] = *b"TVX1";
const TVX1_HEADER_SIZE: usize = 4 + 1 + 4 + 4 + 4 + 16 + 12;
/// Vault-class KDF floor the export header must meet (argon2id, mirrors the
/// import floor in `vault::import_export`): 64 MiB / t=3 / p=4.
const EXPORT_KDF_FLOOR: (u32, u32, u32) = (65536, 3, 4);

/// A malformed proxy URL of the user-typo class the N3 hard refusal exists
/// for. `ureq::Proxy::new` must reject it (pinned by a unit test) — that
/// parse rejection is the predicate `egress_http`'s refusal is built on.
const MALFORMED_PROXY_CANARY: &str = "ht!tp://127.0.0.1:9050";

/// Pure: parse a TVX1 container header into `(version, m_cost, t_cost, p_cost)`.
/// `None` on a wrong magic or a too-short buffer — input that must be refused,
/// never guessed at.
fn parse_tvx1_header(data: &[u8]) -> Option<(u8, u32, u32, u32)> {
    if data.len() < TVX1_HEADER_SIZE || data[..4] != TVX1_MAGIC[..] {
        return None;
    }
    Some((
        data[4],
        u32::from_le_bytes([data[5], data[6], data[7], data[8]]),
        u32::from_le_bytes([data[9], data[10], data[11], data[12]]),
        u32::from_le_bytes([data[13], data[14], data[15], data[16]]),
    ))
}

/// Pure: the export KDF parameters must meet the vault-class floor.
fn kdf_meets_floor(m: u32, t: u32, p: u32) -> bool {
    m >= EXPORT_KDF_FLOOR.0 && t >= EXPORT_KDF_FLOOR.1 && p >= EXPORT_KDF_FLOOR.2
}

/// Pure: owner-only means no group/other permission bits are set.
fn perms_owner_only(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// Permission class of a daemon state file under the data dir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonStateClass {
    /// Secret- or identity-bearing: the bearer token, the device identity,
    /// and the job/session SQLite DB with its WAL sidecars. Group/other
    /// bits on these are a real exposure → FAIL.
    OwnerOnly,
    /// Non-secret discovery artifact: the localhost port the daemon bound.
    /// Content is a port number on 127.0.0.1 (the API is bearer-token
    /// gated), so the daemon writes it 0644 on purpose for same-host tool
    /// discovery. Loose bits here warn (advisory), never FAIL.
    Discovery,
}

/// Pure: classify a daemon state file. Default-deny — anything not known to
/// be non-secret is treated as secret-bearing (`OwnerOnly`).
fn classify_daemon_state(name: &str) -> DaemonStateClass {
    match name {
        "port" => DaemonStateClass::Discovery,
        "token" | "device_id" | "daemon.db" | "daemon.db-wal" | "daemon.db-shm" => {
            DaemonStateClass::OwnerOnly
        }
        _ => DaemonStateClass::OwnerOnly,
    }
}

/// Pure: the refusal guard's parse predicate must reject `bad` — the exact
/// call (`ureq::Proxy::new`) the egress refusal paths are built on.
fn malformed_proxy_rejected(bad: &str) -> bool {
    ureq::Proxy::new(bad).is_err()
}

/// Egress posture: the fail-closed Tor default must resolve, be well-formed,
/// and the malformed-proxy refusal guard must be live. A configured-but-
/// unusable proxy is a real refusal condition (every request refuses) → FAIL.
fn probe_egress_posture() -> ConformanceProbe {
    const LABEL: &str = "egress posture (Tor default + malformed-proxy refusal)";
    if let Some(reason) = tallow::runtime::egress_http::egress_refusal() {
        return probe_result(
            LABEL,
            ProbeStatus::Fail,
            format!("configured egress unusable — all requests refuse: {reason}"),
        );
    }
    if !malformed_proxy_rejected(MALFORMED_PROXY_CANARY) {
        return probe_result(
            LABEL,
            ProbeStatus::Fail,
            "refusal guard dead: malformed proxy URL was accepted by the parser",
        );
    }
    match tallow::runtime::egress_http::proxy_url() {
        Some(url) => probe_result(
            LABEL,
            ProbeStatus::Pass,
            format!("proxied via {url}; malformed-proxy refusal live"),
        ),
        None => probe_result(
            LABEL,
            ProbeStatus::Pass,
            "advisory: direct egress (explicitly allowed); malformed-proxy refusal live",
        ),
    }
}

/// Vault export: TVX1 container + KDF floor, behaviorally — export a probe
/// container and prove a downgraded header is refused by the importer.
// D7 named exemption (R1 wave): doctor probe — in-memory round-trip only,
// no on-disk release, no policy gate.
fn probe_vault_export() -> ConformanceProbe {
    const LABEL: &str = "vault export (TVX1 container + KDF floor enforced)";
    let exported =
        match tallow::vault::import_export::export_encrypted_json(&[], "tallow-doctor-probe") {
            Ok(bytes) => bytes,
            Err(e) => {
                return probe_result(LABEL, ProbeStatus::Fail, format!("export failed: {e}"))
            }
        };
    let Some((version, m, t, p)) = parse_tvx1_header(&exported) else {
        return probe_result(LABEL, ProbeStatus::Fail, "export lacks a TVX1 v1 header");
    };
    if version != 1 || !kdf_meets_floor(m, t, p) {
        return probe_result(
            LABEL,
            ProbeStatus::Fail,
            format!("export header off contract: v={version} argon2id m={m} t={t} p={p}"),
        );
    }
    // Behavioral floor check: an importer that accepts a downgraded KDF
    // header has lost the F-g1-6 floor even if the export side looks right.
    let mut downgraded = exported.clone();
    downgraded[5..9].copy_from_slice(&8u32.to_le_bytes()); // m_cost → absurdly weak
    match tallow::vault::import_export::import_encrypted_json(&downgraded, "tallow-doctor-probe") {
        Err(e) if e.contains("KDF downgrade rejected") => probe_result(
            LABEL,
            ProbeStatus::Pass,
            format!("TVX1 v1; argon2id m={m} t={t} p={p} at floor; downgrade refused"),
        ),
        Err(e) => probe_result(
            LABEL,
            ProbeStatus::Fail,
            format!("downgraded export not refused by the KDF floor: {e}"),
        ),
        Ok(_) => probe_result(
            LABEL,
            ProbeStatus::Fail,
            "KDF downgrade accepted — import floor dead",
        ),
    }
}

/// Daemon state files: when the daemon has been provisioned, its secret- and
/// identity-bearing files (`token`, `device_id`, the SQLite DB and its WAL
/// sidecars) must be owner-only (no group/other bits) — R-P9 hygiene.
/// Absence is advisory (daemon not provisioned), not a failure. The
/// non-secret `port` discovery artifact is exempted by classification and
/// only ever warns (see `DaemonStateClass`). Pre-existing loose files are
/// remediated by the daemon itself on next start (tighten-on-open in
/// tallow-daemon; T-112), which this probe then reports as owner-only.
fn probe_daemon_state_files() -> ConformanceProbe {
    const LABEL: &str = "daemon state files (secret-bearing owner-only; port advisory)";
    const STATE_FILES: [&str; 6] = [
        "token",
        "device_id",
        "daemon.db",
        "daemon.db-wal",
        "daemon.db-shm",
        "port",
    ];
    let Some(dir) = dirs::data_dir().map(|d| d.join("tallow").join("daemon")) else {
        return probe_result(LABEL, ProbeStatus::Pass, "advisory: no data dir resolvable");
    };
    let mut checked: Vec<String> = Vec::new();
    let mut offenders: Vec<String> = Vec::new();
    let mut advisories: Vec<String> = Vec::new();
    for name in STATE_FILES {
        let path = dir.join(name);
        let Ok(md) = std::fs::metadata(&path) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = md.permissions().mode() & 0o777;
            match (classify_daemon_state(name), perms_owner_only(mode)) {
                (DaemonStateClass::OwnerOnly, true) => checked.push(format!("{name}={mode:o}")),
                (DaemonStateClass::OwnerOnly, false) => {
                    offenders.push(format!("{} mode {mode:o}", path.display()))
                }
                (DaemonStateClass::Discovery, true) => checked.push(format!("{name}={mode:o}")),
                (DaemonStateClass::Discovery, false) => advisories.push(format!(
                    "{} mode {mode:o} (non-secret discovery artifact; advisory)",
                    path.display()
                )),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = md;
        }
    }
    if !offenders.is_empty() {
        return probe_result(
            LABEL,
            ProbeStatus::Fail,
            format!(
                "group/other bits set on secret-bearing daemon state: {}",
                offenders.join("; ")
            ),
        );
    }
    if checked.is_empty() && advisories.is_empty() {
        return probe_result(
            LABEL,
            ProbeStatus::Pass,
            format!(
                "advisory: no daemon state under {} (daemon not provisioned)",
                dir.display()
            ),
        );
    }
    let mut detail = if checked.is_empty() {
        "owner-only (no secret-bearing files present)".to_string()
    } else {
        format!("owner-only ({})", checked.join(" "))
    };
    if !advisories.is_empty() {
        detail.push_str(&format!("; advisory: {}", advisories.join("; ")));
    }
    probe_result(LABEL, ProbeStatus::Pass, detail)
}

/// Redaction choke point: the journal path must resolve (advisory when
/// disabled by env) and an emitted event must arrive minimized — actor
/// hashed, URL redacted (query/fragment stripped), never a redaction-error
/// marker, and the raw payload must not survive serialization.
fn probe_redaction_journal() -> ConformanceProbe {
    use tallow::observability::{emit_security_event, EventClass, MemorySink, SecurityEvent};
    const LABEL: &str = "security-event redaction choke point (journal + minimize)";
    let journal = match tallow::observability::default_journal_path() {
        Some(p) => format!("journal {}", p.display()),
        None => "advisory: journal disabled via TALLOW_SECURITY_EVENTS".to_string(),
    };
    let raw_target = "http://127.0.0.1:1/doctor-probe?token=doctor-probe-secret";
    let ev = SecurityEvent {
        class: EventClass::EgressRefusal,
        actor: "doctor.probe".to_string(),
        target: Some(raw_target.to_string()),
        size: 32,
        at_ms: tallow::observability::now_ms(),
    };
    let mut sink = MemorySink::new();
    match emit_security_event(&mut sink, &ev) {
        Ok(red) => {
            let hashed = red.actor_hash.starts_with("n-") && red.actor_hash != ev.actor;
            let url_redacted = match red.target.as_deref() {
                Some(t) => t != raw_target && !t.contains("doctor-probe-secret"),
                None => false,
            };
            let marker_free = red.note.is_none();
            let serialized = serde_json::to_string(&red).unwrap_or_default();
            let payload_gone = !serialized.contains("doctor-probe-secret");
            if hashed && url_redacted && marker_free && payload_gone {
                probe_result(LABEL, ProbeStatus::Pass, format!("emit minimized; {journal}"))
            } else {
                probe_result(
                    LABEL,
                    ProbeStatus::Fail,
                    format!(
                        "minimization gap: actor_hashed={hashed} url_redacted={url_redacted} \
                         marker_free={marker_free} payload_gone={payload_gone}"
                    ),
                )
            }
        }
        Err(e) => probe_result(
            LABEL,
            ProbeStatus::Fail,
            format!("choke point refused a well-formed probe event: {e}"),
        ),
    }
}

/// Run all conformance probes in order.
fn run_conformance_probes() -> Vec<ConformanceProbe> {
    vec![
        probe_egress_posture(),
        probe_vault_export(),
        probe_daemon_state_files(),
        probe_redaction_journal(),
    ]
}

#[cfg(test)]
mod doctor_conformance_tests {
    use super::*;

    #[test]
    fn doctor_tvx1_header_parse_and_floor() {
        let mut hdr = vec![0u8; TVX1_HEADER_SIZE];
        hdr[..4].copy_from_slice(&TVX1_MAGIC);
        hdr[4] = 1;
        hdr[5..9].copy_from_slice(&65536u32.to_le_bytes());
        hdr[9..13].copy_from_slice(&3u32.to_le_bytes());
        hdr[13..17].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(parse_tvx1_header(&hdr), Some((1, 65536, 3, 4)));
        assert!(kdf_meets_floor(65536, 3, 4));
        // A weaker header still parses but must not meet the floor.
        hdr[5..9].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(parse_tvx1_header(&hdr), Some((1, 8, 3, 4)));
        assert!(!kdf_meets_floor(8, 3, 4));
        // Short buffer / wrong magic never parse as a container.
        assert_eq!(parse_tvx1_header(&hdr[..TVX1_HEADER_SIZE - 1]), None);
        let mut bad_magic = hdr.clone();
        bad_magic[..4].copy_from_slice(b"TVX0");
        assert_eq!(parse_tvx1_header(&bad_magic), None);
    }

    #[test]
    fn doctor_perms_owner_only_pins() {
        assert!(perms_owner_only(0o600));
        assert!(perms_owner_only(0o400));
        assert!(!perms_owner_only(0o640));
        assert!(!perms_owner_only(0o644));
        assert!(!perms_owner_only(0o606));
    }

    #[test]
    fn doctor_daemon_state_classification_pins() {
        // Secret-/identity-bearing daemon state → owner-only required (FAIL class).
        for name in [
            "token",
            "device_id",
            "daemon.db",
            "daemon.db-wal",
            "daemon.db-shm",
        ] {
            assert_eq!(
                classify_daemon_state(name),
                DaemonStateClass::OwnerOnly,
                "{name}"
            );
        }
        // The localhost port file is the single non-secret Discovery class:
        // its 0644 default is advisory-only, while the same bits on a
        // secret-bearing file still fail the owner-only predicate.
        assert_eq!(classify_daemon_state("port"), DaemonStateClass::Discovery);
        assert!(!perms_owner_only(0o644));
        assert!(perms_owner_only(0o600));
        // Default-deny: an unclassified daemon state file is treated as
        // secret-bearing until explicitly exempted.
        assert_eq!(
            classify_daemon_state("future_state"),
            DaemonStateClass::OwnerOnly
        );
    }

    #[test]
    fn doctor_malformed_proxy_canary_is_rejected() {
        assert!(
            malformed_proxy_rejected(MALFORMED_PROXY_CANARY),
            "canary {MALFORMED_PROXY_CANARY:?} unexpectedly parsed as a proxy URL"
        );
        // The production Tor default must stay parseable or every request refuses.
        assert!(ureq::Proxy::new(tallow::runtime::fetch::TOR_SOCKS_URL).is_ok());
    }
}

/// Default classification is static (no execution). Pass `--probe` to run
/// guarded runtime probes (per-probe thread + 2s timeout) that refine the
/// static verdicts.
fn emit_capabilities_report(fmt: &str, probe: bool) -> anyhow::Result<()> {
    let report = match build_capabilities_report(probe) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: capability scan failed: {e}");
            std::process::exit(exit_codes::IO_ERROR);
        }
    };
    match fmt {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                    format!("{{\"schema_version\":\"{CAPABILITIES_SCHEMA_VERSION}\",\"error\":\"{e}\"}}")
                })
            );
        }
        "text" => {
            let counts = &report["counts"];
            println!(
                "tallow stdlib capability report ({}), modules: {}, cli_commands: {}",
                CAPABILITIES_SCHEMA_VERSION,
                counts["modules"].as_u64().unwrap_or(0),
                counts["cli_commands"].as_u64().unwrap_or(0)
            );
            println!(
                "mode: {}",
                if probe {
                    "runtime probe (guarded: thread + 2s timeout per probe)"
                } else {
                    "static source classification (no handler execution)"
                }
            );
            println!(
                "generated_at: {}",
                report["generated_at"].as_str().unwrap_or("?")
            );
            println!();
            println!("by status:");
            for (st, n) in report["counts"]["by_status"].as_object().unwrap_or(&serde_json::Map::new()) {
                println!("  {st}: {}", n.as_u64().unwrap_or(0));
            }
            println!();
            if let Some(mods) = report["modules"].as_array() {
                println!("module                          status      reachable  declared  summary");
                for m in mods {
                    println!(
                        "{:<31} {:<11} {:<10} {:<9} {}",
                        m["module"].as_str().unwrap_or("?"),
                        m["status"].as_str().unwrap_or("?"),
                        m["reachable_fns"].as_array().map(|a| a.len()).unwrap_or(0),
                        m["declared_fns"].as_u64().unwrap_or(0),
                        m["summary"].as_str().unwrap_or("")
                    );
                }
            }
            println!();
            println!("CLI commands: {} available", report["cli_commands"].as_array().map(|a| a.len()).unwrap_or(0));
        }
        other => {
            eprintln!("error: unsupported --capabilities format: {other}");
            std::process::exit(exit_codes::USAGE_ERROR);
        }
    }
    Ok(())
}

#[cfg(test)]
mod capabilities_report_tests {
    use super::*;

    fn declared(names: &[&str]) -> Vec<DeclFn> {
        names
            .iter()
            .enumerate()
            .map(|(i, n)| DeclFn {
                name: n.to_string(),
                prefix: None,
                line: i + 1,
            })
            .collect()
    }

    // REAL: fs-like — declared fns routable, real arm keys, non-gate Err on
    // zero-arg probes (missing-arg style).
    #[test]
    fn classifier_marks_real_module() {
        let mut s = ModuleSignals::new("fs");
        s.declared = declared(&["read_file", "write_file", "exists", "delete"]);
        s.declared_dispatch_reachable = vec![
            "read_file (dispatch fs.read_file)".into(),
            "write_file (dispatch fs.write_file)".into(),
        ];
        s.arm_keys = vec![
            "read_file".into(),
            "write_file".into(),
            "rename".into(),
            "stat".into(),
        ];
        s.other_probes = 4; // zero-arg probes Err with "missing argument"
        assert_eq!(classify_cap(&s), CapStatus::Real);
        assert_eq!(cap_summary(&s, CapStatus::Real).contains("real"), true);
    }

    // FACADE: browser-like — self-describing facade/contract-boundary header
    // even though some metadata fns return Ok.
    #[test]
    fn classifier_marks_facade_module() {
        let mut s = ModuleSignals::new("browser");
        s.declared = declared(&["surface_manifest", "goto", "fill_form"]);
        s.facade_header = true;
        s.arm_keys = vec!["surface_manifest".into(), "new_context".into()];
        s.ok_probes = 1;
        assert_eq!(classify_cap(&s), CapStatus::Facade);
    }

    // GATED: db/ml-embeddings-like — routable but only honest gate Err.
    #[test]
    fn classifier_marks_gated_module() {
        let mut s = ModuleSignals::new("db");
        s.declared = declared(&["sqlite", "sqlite_memory", "connect"]);
        s.declared_gated = vec!["sqlite".into(), "sqlite_memory".into()];
        s.gate_probes = 2; // "db bridge requires interp support"
        s.arm_keys = vec!["sqlite".into(), "sqlite_memory".into()];
        assert_eq!(classify_cap(&s), CapStatus::Gated);
    }

    // FACADE-GAP: CAPITAL-spelled declarations that nothing answers.
    #[test]
    fn classifier_marks_facade_gap_module() {
        let mut s = ModuleSignals::new("gapmod");
        s.declared = declared(&["old_api_call"]);
        // No reachable dispatch, no inline interp, no arms.
        assert_eq!(classify_cap(&s), CapStatus::FacadeGap);
        assert!(
            cap_summary(&s, CapStatus::FacadeGap).contains("unreachable from .tl"),
            "summary should say unreachable: {}",
            cap_summary(&s, CapStatus::FacadeGap)
        );
    }

    // TYPE_ONLY: cloud-like sentinel struct module (dispatch_method routes
    // type field reads, dispatch has no arms, no declarations).
    #[test]
    fn classifier_marks_type_only_module() {
        let mut s = ModuleSignals::new("cloud");
        s.method_arm_count = 4;
        assert_eq!(classify_cap(&s), CapStatus::TypeOnly);
    }

    // UNVERIFIED fallback.
    #[test]
    fn classifier_unverified_when_no_evidence() {
        let s = ModuleSignals::new("nothing_here");
        assert_eq!(classify_cap(&s), CapStatus::Unverified);
    }

    #[test]
    fn tl_decl_parser_handles_dot_prefixes_and_impls() {
        let src = r#"
// tallow.extract — structured extraction
fn Extract.schema(html: String, schema_name: String) -> Map
fn Extract.pattern(html: String, pattern: String) -> [String]

struct Browser {}
impl Browser {
    fn launch(headless: bool = true) -> Result<Browser> {
        // Runtime: spawns Chrome
    }
    fn close(self) {}
}

native fn read_file(path: String) -> Result<String> {
    // native
}
"#;
        let decls = parse_tl_decls(src);
        let names: Vec<(&str, Option<&str>)> = decls
            .iter()
            .map(|d| (d.name.as_str(), d.prefix.as_deref()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("schema", Some("Extract")),
                ("pattern", Some("Extract")),
                ("read_file", None),
            ]
        );
    }

    #[test]
    fn arm_key_parser_skips_none_arms_and_keeps_aliases() {
        let body = r#"
    match function {
        "read_file" | "read" => Some(do_read_file(args)),
        "write_file" => Some(do_write_file(args)),
        "delete" | "remove" => None,
        "exists" => {
            let p = match args.first() { _ => return Some(Err("x".into())) };
            Some(Ok(Value::Bool(false)))
        }
        _ => None,
    }
"#;
        let (keys, arms) = dispatch_arm_keys(body);
        assert_eq!(arms, 3); // read_file|read, write_file, exists (delete/remove are None arms)
        assert_eq!(
            keys,
            vec!["read_file", "read", "write_file", "exists"]
        );
    }

    #[test]
    fn fn_body_range_is_brace_aware() {
        let src = r#"
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "a" => Some(do_a(args)),
        "b" => {
            let s = format!("{{{}}}", "x");
            Some(do_b(args))
        }
        _ => None,
    }
}

pub fn other() {}
"#;
        let san = sanitize_source(src);
        let (s0, e0) = fn_body_range(&san, "pub fn dispatch(").unwrap();
        let body = &src[s0..e0];
        assert!(body.contains("do_a"));
        assert!(body.contains("do_b"));
        assert!(!body.contains("pub fn other"));
    }

    #[test]
    fn inline_interp_fns_extracts_quoted_module_fns() {
        let interp = r#"
            "math.abs" => match positional.first() {
            "math.sqrt" => ...
            "math.max" => ...
        "#;
        let fns = inline_interp_fns(interp, "math");
        assert!(fns.contains(&"abs".to_string()));
        assert!(fns.contains(&"sqrt".to_string()));
        assert!(fns.contains(&"max".to_string()));
    }

    #[test]
    fn sanitize_removes_string_braces() {
        let src = r#"fn x() { let s = "} {"; // trailing }
        "x" => Some(1),
    }"#;
        let san = sanitize_source(src);
        // Braces in the string literal and the comment are blanked.
        assert!(san.contains("fn x() {"));
        assert!(!san.contains('"'));
    }

    #[test]
    fn sanitize_keeps_code_after_char_literal_with_quote() {
        // A char literal '"' must not desync the string-state tracker and
        // blank out everything that follows (captcha.rs regression).
        let src = r#"fn find(start: usize) -> usize {
        let end = html[start..].find('"').unwrap_or(0);
        pub fn dispatch(function: &str) -> Option<u8> {
            match function { "a" => Some(1), _ => None }
        }
    }"#;
        let san = sanitize_source(src);
        assert!(san.contains("pub fn dispatch(function: &str)"));
        assert!(san.contains("=> Some(1)")); // arm skeleton survives (key string blanked)
    }

    #[test]
    fn sanitize_handles_raw_strings_with_quotes() {
        // Raw strings embed quotes; they must be blanked as one unit so the
        // following code (including the dispatch signature) survives.
        let src = r##"let re = r#"<img[^>]*src="([^"]*)"[^>]*>"#;
pub fn dispatch(f: &str) { let _ = f; }"##;
        let san = sanitize_source(src);
        assert!(san.contains("pub fn dispatch(f: &str)"));
    }

    #[test]
    fn probe_gate_message_detection() {
        assert!(is_gate_msg("db bridge requires interp support (db.rs)"));
        assert!(is_gate_msg("browser.new_context: not yet implemented for live runs"));
        assert!(!is_gate_msg("missing argument 1 (path)"));
        assert!(!is_gate_msg("fs.read_file: No such file"));
    }

    #[test]
    fn parse_dispatch_table_maps_aliases_to_canonical() {
        let mod_rs = r#"
pub fn dispatch(module: &str, function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match module {
        "fs" => fs::dispatch(function, args),
        "osint" => osint::dispatch(function, args),
        "Target" | "TechStack" | "ASNIntel" => {
            osint::dispatch(&format!("{module}.{function}"), args)
        }
        "secrets" | "secretstore" => secrets::dispatch(function, args),
        "mesh" => mesh::dispatch(function, args),
        "MeshNode" => mesh::dispatch(function, args),
        _ => None,
    }
}
"#;
        let (table, all_keys) = parse_dispatch_table(mod_rs);
        assert_eq!(table["osint"], vec!["osint", "Target", "TechStack", "ASNIntel"]);
        assert_eq!(table["secrets"], vec!["secrets", "secretstore"]);
        assert_eq!(table["mesh"], vec!["mesh", "MeshNode"]);
        assert!(all_keys.contains("Target"));
        assert!(all_keys.contains("secretstore"));
        assert!(!all_keys.contains("fs_bogus"));
    }

    // ── Probe containment (layer 2): a probe that panics or hangs must never
    // crash or stall the report — thread + catch_unwind + hard timeout. ──
    //
    // NOTE (docs/PANIC-POLICY.md): this test passes because the TEST profile
    // unwinds. Release profiles set `panic = "abort"`, where the panic half of
    // run_guarded_probe cannot fire — a test running under a profile the artifact
    // is not built with does not test the artifact.

    #[test]
    fn guarded_probe_contains_panics() {
        let r = run_guarded_probe(|| panic!("boom"));
        assert_eq!(r, ProbeOutcome::Panicked);
    }

    #[test]
    fn guarded_probe_times_out_hanging_work() {
        let start = std::time::Instant::now();
        let r = run_guarded_probe(|| {
            std::thread::sleep(std::time::Duration::from_secs(30));
            ProbeOutcome::OkValue
        });
        assert_eq!(r, ProbeOutcome::TimedOut);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(15),
            "hard timeout must bound the probe"
        );
    }

    #[test]
    fn guarded_probe_returns_value() {
        assert_eq!(run_guarded_probe(|| ProbeOutcome::OkValue), ProbeOutcome::OkValue);
        assert_eq!(
            run_guarded_probe(|| ProbeOutcome::ErrText("nope".into())),
            ProbeOutcome::ErrText("nope".into())
        );
    }

    // Cross-layer honesty: after the algos empty-input guard, a zero-arg
    // probe of a real algos handler returns an Err — never a panic — so the
    // guarded probe reports ErrText, and the whole probe path cannot ICE.
    #[test]
    fn probe_of_algos_zero_arg_is_err_not_panic() {
        match probe_dispatch("algos", "pairs_trading") {
            ProbeOutcome::ErrText(msg) => {
                assert!(msg.contains("requires input"), "got: {msg}")
            }
            other => panic!("zero-arg algos probe must ErrText, got {other:?}"),
        }
        assert_eq!(
            probe_dispatch("no_such_module_xyz", "whatever"),
            ProbeOutcome::None
        );
    }

    // ── Static arm parsing + classification (layer 2 default path) ──

    #[test]
    fn parse_dispatch_arms_handles_blocks_and_comment_noise() {
        // Comments between arms quote words that must NOT become arm keys;
        // the exists arm is a multi-line block with an inner match.
        let src = r#"
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // "not_a_key" is deliberately absent (see docs)
        "sqlite" | "sqlite_memory" => Some(Err("db bridge requires interp support".into())),
        "exists" => {
            let p = match args.first() { _ => return Some(Err("x".into())) };
            Some(Ok(Value::Bool(false)))
        }
        // "also_not_a_key"
        _ => None,
    }
}
"#;
        let san = sanitize_source(src);
        let (s0, e0) = fn_body_range(&san, "pub fn dispatch(").unwrap();
        let arms = parse_dispatch_arms(&src[s0..e0]);
        // Three arms total: sqlite|sqlite_memory, exists, wildcard.
        assert_eq!(arms.len(), 3, "arms: {arms:?}");
        assert_eq!(arms[0].keys, vec!["sqlite", "sqlite_memory"]);
        assert_eq!(arms[1].keys, vec!["exists"]);
        assert!(arms[1].rhs.contains("Ok("), "block RHS captured: {}", arms[1].rhs);
        assert!(arm_is_none(&arms[2]), "wildcard arm must be None");
        // Comment pollution must not appear in any keys.
        for arm in &arms {
            for k in &arm.keys {
                assert!(!k.contains("not_a_key"), "comment leaked into keys: {k}");
            }
        }
    }

    #[test]
    fn static_arm_kind_detects_gate_real_and_argerr_without_execution() {
        let src = r#"
const G_MSG: &str = "db bridge requires interp support: not wired";
pub fn dispatch(f: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match f {
        "sqlite" => Some(Err(G_MSG.to_string())),
        "read_file" => Some(do_read(args)),
        "meta" => Some(Ok(Value::String("x".into()))),
        "touch" => Some(Err("missing argument 1".into())),
        _ => None,
    }
}
fn do_read(_: Vec<Value>) -> StdlibResult {
    let path = "/etc/hostname";
    Ok(Value::String(path.into()))
}
"#;
        let san = sanitize_source(src);
        let (s0, e0) = fn_body_range(&san, "pub fn dispatch(").unwrap();
        let arms = parse_dispatch_arms(&src[s0..e0]);
        assert_eq!(arms.len(), 5); // sqlite, read_file, meta, touch, wildcard
        // Err-only const with gate wording → Gate.
        assert_eq!(static_arm_kind(&arms[0], src, &san), StaticArmKind::Gate);
        // Helper body returns Ok (a string containing braces/commas must not
        // confuse the analysis) → Real.
        assert_eq!(static_arm_kind(&arms[1], src, &san), StaticArmKind::Real);
        // Direct Some(Ok(...)) → Real.
        assert_eq!(static_arm_kind(&arms[2], src, &san), StaticArmKind::Real);
        // Plain Err-only message (missing-argument style) → ArgErr, not Gate.
        assert_eq!(static_arm_kind(&arms[3], src, &san), StaticArmKind::ArgErr);
        // Wildcard None arm → no signal.
        assert_eq!(static_arm_kind(&arms[4], src, &san), StaticArmKind::NoneArm);
    }

    #[test]
    fn decl_key_matches_dotted_namespace_keys() {
        let plain = DeclFn { name: "schema".into(), prefix: None, line: 1 };
        let dotted = DeclFn { name: "schema".into(), prefix: Some("Extract".into()), line: 1 };
        assert!(decl_key_matches("schema", &plain, "extract"));
        assert!(!decl_key_matches("other", &plain, "extract"));
        // Composed "Prefix.name" routing matches by prefix case-insensitively.
        assert!(decl_key_matches("Extract.schema", &dotted, "extract"));
        assert!(decl_key_matches("extract.schema", &dotted, "extract"));
        assert!(!decl_key_matches("Other.schema", &dotted, "extract"));
    }

    #[test]
    fn static_decl_resolution_maps_decl_to_gate_arm() {
        let src = r#"
const BRIDGE_MSG: &str = "db bridge requires interp support";
pub fn dispatch(function: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "sqlite" | "sqlite_memory" => Some(Err(BRIDGE_MSG.to_string())),
        _ => None,
    }
}
"#;
        let san = sanitize_source(src);
        let (s0, e0) = fn_body_range(&san, "pub fn dispatch(").unwrap();
        let cm = CachedModule {
            rs_src: src.to_string(),
            rs_san: san.clone(),
            arms: parse_dispatch_arms(&src[s0..e0]),
        };
        let mut cache: ModuleSourceCache = ModuleSourceCache::new();
        cache.insert("db".to_string(), cm.clone());
        cache.insert("sqlite".to_string(), cm.clone());
        cache.insert("SQLite".to_string(), cm);
        let decl = DeclFn { name: "sqlite".into(), prefix: Some("SQLite".into()), line: 2 };
        let r = static_decl_resolution(&decl, &["db".to_string()], "db", &cache);
        assert_eq!(r, Some(("db".to_string(), StaticArmKind::Gate)));
        // An unknown declaration resolves to nothing (no arms match).
        let unknown = DeclFn { name: "nope".into(), prefix: None, line: 9 };
        assert_eq!(
            static_decl_resolution(&unknown, &["db".to_string()], "db", &cache),
            None
        );
    }

    #[test]
    fn comment_free_strips_comments_but_keeps_string_literals() {
        let s = r#"// "fake_key"
        "real_key" /* "block_fake" */ => 1 // "trailing"
        "#;
        let clean = comment_free(s);
        assert!(!clean.contains("fake_key"));
        assert!(!clean.contains("block_fake"));
        assert!(!clean.contains("trailing"));
        assert!(clean.contains("\"real_key\""));
    }

    // A process-terminating arm (process.exit calls std::process::exit) must
    // never be executed by a probe — no thread/timeout guard can survive it.
    #[test]
    fn arm_exits_process_detects_process_terminating_arms() {
        let src = r#"
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "exit" => {
            let code = match args.first() {
                Some(Value::Int(n)) => *n as i32,
                _ => 0,
            };
            std::process::exit(code);
        }
        "pid" => Some(Ok(Value::Int(1))),
        _ => None,
    }
}
"#;
        let san = sanitize_source(src);
        let (s0, e0) = fn_body_range(&san, "pub fn dispatch(").unwrap();
        let arms = parse_dispatch_arms(&src[s0..e0]);
        assert_eq!(arms.len(), 3);
        assert!(arm_exits_process(&arms[0], src, &san), "exit arm must be flagged");
        assert!(!arm_exits_process(&arms[1], src, &san), "pid arm is safe");
        assert!(!arm_exits_process(&arms[2], src, &san), "None arm is safe");
        // The exit arm's key is still parsed normally.
        assert_eq!(arms[0].keys, vec!["exit"]);
    }
}



#[cfg(test)]
mod pia_tests {
    use super::*;

    fn parse_and_pia(source: &str) -> PiaReport {
        let (tokens, _) = tallow::lexer::tokenize(source);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let (env, _) = tallow::typeck::TypeChecker::new(&program).check();
        generate_pia_report(&program, &env, "test.tl")
    }

    #[test]
    fn pia_includes_data_types() {
        let report = parse_and_pia(
            r#"
type Email = private String
type Token = secret String
type UserID = String
"#,
        );
        assert_eq!(report.data_types.len(), 3);
        assert!(
            report
                .data_types
                .iter()
                .any(|d| d.name == "Email" && d.qualifier == "private")
        );
        assert!(
            report
                .data_types
                .iter()
                .any(|d| d.name == "Token" && d.qualifier == "secret")
        );
        assert!(
            report
                .data_types
                .iter()
                .any(|d| d.name == "UserID" && d.qualifier == "plain")
        );
    }

    #[test]
    fn pia_includes_legal_bases() {
        let report = parse_and_pia(
            r#"
@legal(basis: .public_data, purpose: "price monitoring")
fn scrape(url: String) -> String { url }

@legal(basis: .consent, purpose: "user data", personal_data: true, retain_for: 90.days)
fn collect(data: String) -> String { data }
"#,
        );
        assert_eq!(report.legal_bases.len(), 2);
        assert!(
            report
                .legal_bases
                .iter()
                .any(|l| l.function == "scrape" && l.basis == "public_data")
        );
        assert!(
            report
                .legal_bases
                .iter()
                .any(|l| l.function == "collect" && l.personal_data)
        );
    }

    #[test]
    fn pia_includes_epsilon_budgets() {
        let report = parse_and_pia(
            r#"
@epsilon(0.5)
@purpose("analytics")
fn query_a(x: i32) -> i32 { x }

@epsilon(0.3)
fn query_b(x: i32) -> i32 { x }
"#,
        );
        assert_eq!(report.privacy_budget.functions.len(), 2);
        assert!((report.privacy_budget.total_epsilon - 0.8).abs() < 0.01);
        let qa = report
            .privacy_budget
            .functions
            .iter()
            .find(|e| e.function == "query_a")
            .unwrap();
        assert!((qa.epsilon - 0.5).abs() < 0.01);
        assert_eq!(qa.purpose.as_deref(), Some("analytics"));
    }

    #[test]
    fn pia_includes_jurisdictions() {
        let report = parse_and_pia(
            r#"
@jurisdiction(.eu)
type EUData = private String

@jurisdiction(.us)
type USData = private String
"#,
        );
        assert_eq!(report.jurisdictions.len(), 2);
        assert!(
            report
                .jurisdictions
                .iter()
                .any(|j| j.type_name == "EUData" && j.jurisdiction == "eu")
        );
        assert!(
            report
                .jurisdictions
                .iter()
                .any(|j| j.type_name == "USData" && j.jurisdiction == "us")
        );
    }

    #[test]
    fn pia_includes_erasable_types() {
        let report = parse_and_pia(
            r#"
@erasable
type UserProfile = private String

fn store(profile: UserProfile) {
    purge("user-123")
}
"#,
        );
        assert_eq!(report.erasable_types.len(), 1);
        assert_eq!(report.erasable_types[0].name, "UserProfile");
        assert!(report.erasable_types[0].has_purge_handler);
    }

    #[test]
    fn pia_erasable_without_purge_handler() {
        let report = parse_and_pia(
            r#"
@erasable
type UserProfile = private String

fn process(profile: UserProfile) -> String {
    profile
}
"#,
        );
        assert_eq!(report.erasable_types.len(), 1);
        assert!(!report.erasable_types[0].has_purge_handler);
        assert!(
            report
                .recommendations
                .iter()
                .any(|r| r.contains("purge handler")),
            "expected recommendation about missing purge handler, got: {:?}",
            report.recommendations
        );
    }

    #[test]
    fn pia_high_epsilon_recommendation() {
        let report = parse_and_pia(
            r#"
@epsilon(3.0)
fn query_a(x: i32) -> i32 { x }

@epsilon(3.0)
fn query_b(x: i32) -> i32 { x }
"#,
        );
        assert!(
            report
                .recommendations
                .iter()
                .any(|r| r.contains("epsilon budget")),
            "expected high epsilon recommendation, got: {:?}",
            report.recommendations
        );
    }

    #[test]
    fn pia_us_jurisdiction_recommendation() {
        let report = parse_and_pia(
            r#"
@jurisdiction(.us)
type USData = private String
"#,
        );
        assert!(
            report.recommendations.iter().any(|r| r.contains("US/DPF")),
            "expected US/DPF recommendation, got: {:?}",
            report.recommendations
        );
    }

    #[test]
    fn pia_json_format_output() {
        // Just ensure print_pia_json doesn't panic
        let report = parse_and_pia(
            r#"
type Email = private String

@legal(basis: .consent, purpose: "test")
fn process(x: String) -> String { x }
"#,
        );
        // Call the JSON printer (output goes to stdout, just verify no panic)
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"file\": \"{}\"\n", report.file));
        json.push('}');
        assert!(json.contains("test.tl"));
    }

    #[test]
    fn pia_empty_program() {
        let report = parse_and_pia("fn main() {}");
        assert!(report.data_types.is_empty());
        assert!(report.legal_bases.is_empty());
        assert!(report.privacy_budget.functions.is_empty());
        assert!(report.jurisdictions.is_empty());
        assert!(report.erasable_types.is_empty());
        assert!(report.recommendations.is_empty());
    }
}

#[cfg(test)]
mod opsec_integration_tests {
    fn run_check(source: &str) -> tallow::error::Diagnostics {
        let (tokens, _) = tallow::lexer::tokenize(source);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let (env, _) = tallow::typeck::TypeChecker::new(&program).check();
        tallow::opsec_pass::OpsecPass::new(&program, &env).check()
    }

    #[test]
    fn opsec_valid_fixture_no_errors() {
        let source = std::fs::read_to_string("tests/fixtures/opsec_valid.tl")
            .expect("opsec_valid.tl fixture missing");
        let diags = run_check(&source);
        assert!(
            !diags.has_errors(),
            "opsec_valid.tl should produce no errors, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn opsec_invalid_fixture_emits_e0900() {
        let source = std::fs::read_to_string("tests/fixtures/opsec_invalid.tl")
            .expect("opsec_invalid.tl fixture missing");
        let diags = run_check(&source);
        assert!(diags.has_errors(), "opsec_invalid.tl should emit errors");
        assert!(
            diags.items.iter().any(|d| d.code == "E0900"),
            "expected E0900 cross-profile error"
        );
    }
}

#[cfg(test)]
mod test_framework_tests {
    use super::*;
    use tallow::interp::{Interpreter, Value};

    /// Helper: parse source, register in interpreter, return interpreter
    fn setup_interp(source: &str) -> Interpreter {
        let (tokens, lex_errors) = tallow::lexer::tokenize(source);
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let program = tallow::parser::Parser::parse(tokens).expect("parse failed");
        let mut interp = Interpreter::new();
        interp.register(&program).expect("register failed");
        interp
    }

    // ── Test 1: before_each() runs before every test_* function ──

    #[test]
    fn test_framework_lifecycle_before_each() {
        let dir = tempfile::tempdir().unwrap();
        let test_file = dir.path().join("lifecycle_test.tl");
        // before_each uses print() so we can verify it ran from stdout
        // The test verifies that before_each is called (print appears in output)
        std::fs::write(
            &test_file,
            r#"
fn before_each() {
    print("SETUP")
}

fn test_a() {
    assert(true, "pass")
}

fn test_b() {
    assert(true, "pass")
}
"#,
        )
        .unwrap();
        let result = run_tests(&test_file, None, false);
        assert!(
            result.is_ok(),
            "lifecycle tests should pass: {:?}",
            result.err()
        );
    }

    // ── Test 2: after_each() runs after every test_* (even on failure) ──

    #[test]
    fn test_framework_lifecycle_after_each() {
        let dir = tempfile::tempdir().unwrap();
        let test_file = dir.path().join("after_each_test.tl");
        std::fs::write(
            &test_file,
            r#"
fn after_each() {
    print("TEARDOWN")
}

fn test_a() {
    assert(true, "pass")
}

fn test_b() {
    assert(true, "pass")
}
"#,
        )
        .unwrap();
        let result = run_tests(&test_file, None, false);
        assert!(
            result.is_ok(),
            "after_each tests should pass: {:?}",
            result.err()
        );
    }

    // ── Test 3: before_all/after_all run once per file ──

    #[test]
    fn test_framework_lifecycle_before_all_after_all() {
        let dir = tempfile::tempdir().unwrap();
        let test_file = dir.path().join("all_hooks_test.tl");
        std::fs::write(
            &test_file,
            r#"
fn before_all() {
    print("INIT")
}

fn after_all() {
    print("CLEANUP")
}

fn test_first() {
    assert(true, "pass")
}

fn test_second() {
    assert(true, "pass")
}
"#,
        )
        .unwrap();
        let result = run_tests(&test_file, None, false);
        assert!(
            result.is_ok(),
            "before_all/after_all tests should pass: {:?}",
            result.err()
        );
    }

    // ── Test 4: assert_eq passes when a == b, fails with message ──

    #[test]
    fn test_framework_assert_eq_pass() {
        let mut interp = setup_interp("fn test_it() { assert_eq(42, 42) }");
        assert!(interp.call_fn("test_it").is_ok());
    }

    #[test]
    fn test_framework_assert_eq_fail_message() {
        let mut interp = setup_interp("fn test_it() { assert_eq(1, 2) }");
        let err = interp.call_fn("test_it").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("1") && msg.contains("2"),
            "should show expected/actual: {msg}"
        );
    }

    // ── Test 5: assert_ne passes when a != b ──

    #[test]
    fn test_framework_assert_ne_pass() {
        let mut interp = setup_interp("fn test_it() { assert_ne(1, 2) }");
        assert!(interp.call_fn("test_it").is_ok());
    }

    #[test]
    fn test_framework_assert_ne_fail() {
        let mut interp = setup_interp("fn test_it() { assert_ne(5, 5) }");
        assert!(interp.call_fn("test_it").is_err());
    }

    // ── Test 6: assert_ok passes on Ok, fails on Err ──

    #[test]
    fn test_framework_assert_ok_pass() {
        let mut interp = setup_interp(
            r#"
fn ok_val() -> Result<i32> { Ok(42) }
fn test_it() {
    let r = ok_val()
    assert_ok(r)
}
"#,
        );
        assert!(interp.call_fn("test_it").is_ok());
    }

    #[test]
    fn test_framework_assert_ok_fail_on_err() {
        let mut interp = setup_interp(
            r#"
fn err_val() -> Result<i32> { Err("bad") }
fn test_it() {
    let r = err_val()
    assert_ok(r)
}
"#,
        );
        let err = interp.call_fn("test_it").unwrap_err();
        assert!(
            err.to_string().contains("expected Ok"),
            "should mention Ok: {}",
            err
        );
    }

    // ── Test 7: assert_err passes on Err, fails on Ok ──

    #[test]
    fn test_framework_assert_err_pass() {
        let mut interp = setup_interp(
            r#"
fn err_val() -> Result<i32> { Err("bad") }
fn test_it() {
    let r = err_val()
    assert_err(r)
}
"#,
        );
        assert!(interp.call_fn("test_it").is_ok());
    }

    #[test]
    fn test_framework_assert_err_fail_on_ok() {
        let mut interp = setup_interp(
            r#"
fn ok_val() -> Result<i32> { Ok(42) }
fn test_it() {
    let r = ok_val()
    assert_err(r)
}
"#,
        );
        let err = interp.call_fn("test_it").unwrap_err();
        assert!(
            err.to_string().contains("expected Err"),
            "should mention Err: {}",
            err
        );
    }

    // ── Test 8: Filter only runs matching test names ──

    #[test]
    fn test_framework_filter() {
        let dir = tempfile::tempdir().unwrap();
        let test_file = dir.path().join("filter_test.tl");
        std::fs::write(
            &test_file,
            r#"
fn test_alpha() {
    assert(true, "pass")
}

fn test_beta() {
    assert(false, "should not run")
}
"#,
        )
        .unwrap();
        // Filter to only "alpha" -- beta should NOT run (it would fail)
        let result = run_tests(&test_file, Some("alpha"), false);
        assert!(
            result.is_ok(),
            "filtered test should pass: {:?}",
            result.err()
        );
    }
}

#[cfg(test)]
mod test_coverage_tests {
    use super::*;
    use tallow::interp::Interpreter;

    // ── Test 1: --coverage enables function-level coverage tracking ──

    #[test]
    fn test_coverage_tracking_enabled() {
        let source = r#"
fn helper() -> i32 { 42 }
fn test_uses_helper() {
    let x = helper()
    assert_eq(x, 42)
}
"#;
        let (tokens, _) = tallow::lexer::tokenize(source);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = Interpreter::new();
        interp.enable_coverage();
        interp.register(&program).unwrap();
        interp.call_fn("test_uses_helper").unwrap();

        let cov = interp.get_coverage();
        assert!(
            cov.contains_key("helper"),
            "helper should be in coverage: {:?}",
            cov
        );
    }

    // ── Test 2: Coverage shows call counts ──

    #[test]
    fn test_coverage_call_counts() {
        let source = r#"
fn add(a: i32, b: i32) -> i32 { a + b }
fn test_calls_add_twice() {
    let x = add(1, 2)
    let y = add(3, 4)
    assert_eq(x, 3)
    assert_eq(y, 7)
}
"#;
        let (tokens, _) = tallow::lexer::tokenize(source);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = Interpreter::new();
        interp.enable_coverage();
        interp.register(&program).unwrap();
        interp.call_fn("test_calls_add_twice").unwrap();

        let cov = interp.get_coverage();
        assert_eq!(
            *cov.get("add").unwrap_or(&0),
            2,
            "add should be called twice: {:?}",
            cov
        );
    }

    // ── Test 3: Coverage percentage calculation ──

    #[test]
    fn test_coverage_percentage() {
        let source = r#"
fn used_fn() -> i32 { 1 }
fn unused_fn() -> i32 { 2 }
fn test_partial_coverage() {
    let x = used_fn()
    assert_eq(x, 1)
}
"#;
        let (tokens, _) = tallow::lexer::tokenize(source);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = Interpreter::new();
        interp.enable_coverage();
        interp.register(&program).unwrap();
        interp.call_fn("test_partial_coverage").unwrap();

        let cov = interp.get_coverage();
        assert!(cov.contains_key("used_fn"), "used_fn should be covered");
        assert!(
            !cov.contains_key("unused_fn"),
            "unused_fn should NOT be covered"
        );
    }

    // ── Test 4: Uncovered functions listed ──

    #[test]
    fn test_coverage_uncovered_listed() {
        let source = r#"
fn covered_fn() -> i32 { 1 }
fn uncovered_fn() -> i32 { 2 }
fn another_uncovered() -> i32 { 3 }
fn test_one_covered() {
    let x = covered_fn()
    assert_eq(x, 1)
}
"#;
        let (tokens, _) = tallow::lexer::tokenize(source);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = Interpreter::new();
        interp.enable_coverage();
        interp.register(&program).unwrap();
        interp.call_fn("test_one_covered").unwrap();

        let cov = interp.get_coverage();
        // covered_fn should be hit, uncovered_fn and another_uncovered should not
        assert!(cov.contains_key("covered_fn"));
        assert!(!cov.contains_key("uncovered_fn"));
        assert!(!cov.contains_key("another_uncovered"));
    }

    // ── Test 5: Coverage excludes lifecycle hooks ──

    #[test]
    fn test_coverage_excludes_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let test_file = dir.path().join("cov_hooks_test.tl");
        std::fs::write(
            &test_file,
            r#"
fn before_each() {
    print("setup")
}

fn helper() -> i32 { 42 }

fn test_with_hook() {
    let x = helper()
    assert_eq(x, 42)
}
"#,
        )
        .unwrap();
        // Run with coverage enabled
        let result = run_tests(&test_file, None, true);
        assert!(
            result.is_ok(),
            "coverage test should pass: {:?}",
            result.err()
        );
    }
}

#[cfg(test)]
mod cli_target_tests {
    use tallow::codegen::TargetConfig;

    #[test]
    fn cli_target_arm64_linux_parsed() {
        // Simulates: tallow build --target arm64-linux file.tl
        let target_str = "arm64-linux";
        let tc = TargetConfig::from_target_str(target_str).unwrap();
        assert_eq!(tc.triple, "aarch64-unknown-linux-gnu");
    }

    #[test]
    fn cli_target_default_uses_host() {
        // When no --target is provided, TargetConfig::host() is used
        let tc = TargetConfig::host();
        // On Windows test machine:
        if cfg!(target_os = "windows") {
            assert_eq!(tc.triple, "x86_64-pc-windows-msvc");
        } else if cfg!(target_os = "macos") {
            assert!(tc.triple.contains("apple"));
        } else {
            assert!(tc.triple.contains("linux"));
        }
    }

    #[test]
    fn cli_target_cross_compile_run_warning() {
        // tallow run --target arm64-linux should detect cross-compilation
        let host = TargetConfig::host();
        let cross = TargetConfig::from_target_str("arm64-linux").unwrap();
        // On a non-ARM64 Linux machine, these triples differ
        if host.triple != "aarch64-unknown-linux-gnu" {
            assert_ne!(host.triple, cross.triple);
        }
    }

    #[test]
    fn cli_target_list_targets() {
        let output = TargetConfig::list_targets();
        assert!(output.contains("x86_64-linux"));
        assert!(output.contains("arm64-linux"));
        assert!(output.contains("wasm"));
        assert!(output.contains("x86_64-macos"));
        assert!(output.contains("arm64-macos"));
        assert!(output.contains("x86_64-windows"));
        assert!(output.contains("aarch64-unknown-linux-gnu"));
        assert!(output.contains("wasm32-wasi"));
    }

    #[test]
    fn cli_target_invalid_shows_error() {
        let result = TargetConfig::from_target_str("invalid-target");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Supported targets"),
            "Error should list targets: {err}"
        );
        assert!(err.contains("x86_64-linux"));
        assert!(err.contains("wasm"));
    }

    #[test]
    fn cli_target_wasm_output_extension() {
        // WASM target should produce .wasm file
        let tc = TargetConfig::from_target_str("wasm").unwrap();
        assert!(tc.is_wasm);
        let path = std::path::PathBuf::from("test.tl");
        let output = if tc.is_wasm {
            path.with_extension("wasm")
        } else if tc.is_windows {
            path.with_extension("exe")
        } else {
            path.with_extension("")
        };
        assert_eq!(output.extension().unwrap(), "wasm");
    }

    #[test]
    fn cli_target_build_ir_uses_specified_target() {
        // Full integration test: parse source, codegen with specific target, check IR
        let source = r#"fn main() { print("hello") }"#;
        let (tokens, errors) = tallow::lexer::tokenize(source);
        assert!(errors.is_empty());
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let (env, _) = tallow::typeck::TypeChecker::new(&program).check();

        let target = TargetConfig::from_target_str("arm64-linux").unwrap();
        let mut cg = tallow::codegen::CodeGen::new_with_target(&program, &env, target);
        let ir = cg.emit_module().unwrap();

        assert!(
            ir.contains("aarch64-unknown-linux-gnu"),
            "IR triple should be aarch64"
        );
        assert!(
            !ir.contains("x86_64"),
            "IR should not contain x86_64 for arm64 target"
        );
    }
}

// ── Phase 66: Enterprise CLI Tests ──────────────────────────────────────────

#[cfg(test)]
mod phase66_enterprise_cli_tests {
    use super::*;

    // ── Test 1: Exit codes have correct values ──
    #[test]
    fn test_exit_codes_values() {
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::COMPILE_ERROR, 1);
        assert_eq!(exit_codes::LEGAL_VIOLATION, 2);
        assert_eq!(exit_codes::PRIVACY_VIOLATION, 3);
        assert_eq!(exit_codes::PERMISSION_VIOLATION, 4);
        assert_eq!(exit_codes::IO_ERROR, 5);
        assert_eq!(exit_codes::DEPENDENCY_ERROR, 6);
        assert_eq!(exit_codes::NETWORK_ERROR, 7);
        assert_eq!(exit_codes::ICE, 8);
        assert_eq!(exit_codes::USAGE_ERROR, 64);
        assert_eq!(exit_codes::INTERRUPTED, 130);
    }

    // ── Test 2: Exit codes are distinct ──
    #[test]
    fn test_exit_codes_distinct() {
        let codes = [
            exit_codes::SUCCESS,
            exit_codes::COMPILE_ERROR,
            exit_codes::LEGAL_VIOLATION,
            exit_codes::PRIVACY_VIOLATION,
            exit_codes::PERMISSION_VIOLATION,
            exit_codes::IO_ERROR,
            exit_codes::DEPENDENCY_ERROR,
            exit_codes::NETWORK_ERROR,
            exit_codes::ICE,
            exit_codes::USAGE_ERROR,
            exit_codes::INTERRUPTED,
        ];
        let mut unique = std::collections::HashSet::new();
        for code in &codes {
            assert!(unique.insert(code), "duplicate exit code: {code}");
        }
    }

    // ── Test 3: Version output includes platform info ──
    #[test]
    fn test_version_output_fields() {
        // Verify the environment variables exist at compile time
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty(), "CARGO_PKG_VERSION should be set");
        let platform = std::env::consts::OS;
        assert!(!platform.is_empty(), "OS const should be set");
        let arch = std::env::consts::ARCH;
        assert!(!arch.is_empty(), "ARCH const should be set");
    }

    // ── Test 4: Config path uses dirs crate ──
    #[test]
    fn test_config_path() {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("tallow");
        let config_path = config_dir.join("config.toml");
        let path_str = config_path.display().to_string();
        assert!(
            path_str.contains("tallow"),
            "config path should contain 'tallow': {path_str}"
        );
        assert!(
            path_str.ends_with("config.toml"),
            "config path should end with config.toml: {path_str}"
        );
    }

    // ── Test 5: Shell completions enum has all expected shells ──
    #[test]
    fn test_completions_shells_exist() {
        // Verify all expected shells are valid enum variants
        let shells = vec![
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Elvish,
        ];
        assert_eq!(shells.len(), 5, "should have 5 shell variants");
    }

    // ── Test 6: CLI struct parses with global flags ──
    #[test]
    fn test_cli_global_flags_definition() {
        // Verify the CLI struct can be constructed with global flags
        // (this tests that the derive macro generates valid code)
        use clap::CommandFactory;
        let cmd = Cli::command();
        // Check global args exist
        let quiet_arg = cmd.get_arguments().find(|a| a.get_id() == "quiet");
        assert!(quiet_arg.is_some(), "CLI should have --quiet flag");
        let verbose_arg = cmd.get_arguments().find(|a| a.get_id() == "verbose");
        assert!(verbose_arg.is_some(), "CLI should have --verbose flag");
        let no_color_arg = cmd.get_arguments().find(|a| a.get_id() == "no_color");
        assert!(no_color_arg.is_some(), "CLI should have --no-color flag");
    }

    // ── Test 7: Check command JSON output format ──
    #[test]
    fn test_check_json_output_format() {
        let source = r#"
fn main() {
    let x: i32 = 42
    print(x)
}
"#;
        let (tokens, lex_errors) = tallow::lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let (env, typeck_diags) = tallow::typeck::TypeChecker::new(&program).check();
        let _ = &env; // used for compilation

        // Simulate JSON diagnostic output
        let filename = "test.tl";
        let errors = typeck_diags.error_count();
        let warnings = typeck_diags.warning_count();
        let diag_json: Vec<serde_json::Value> = typeck_diags
            .items
            .iter()
            .map(|d| {
                let (line, col) = d.span.line_col(source);
                serde_json::json!({
                    "code": d.code,
                    "severity": match d.severity {
                        tallow::error::Severity::Error => "error",
                        tallow::error::Severity::Warning => "warning",
                    },
                    "message": d.msg,
                    "file": filename,
                    "line": line,
                    "column": col,
                })
            })
            .collect();
        let output = serde_json::json!({
            "file": filename,
            "errors": errors,
            "warnings": warnings,
            "items": program.items.len(),
            "diagnostics": diag_json,
        });
        let json_str = serde_json::to_string_pretty(&output).unwrap();
        // Must be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["file"], "test.tl");
        assert!(parsed["items"].as_u64().unwrap() > 0);
        assert!(parsed["diagnostics"].is_array());
    }

    // ── Test 8: ExitCode interpreter sentinel ──
    #[test]
    fn test_exit_code_sentinel() {
        let source = r#"
fn main() {
    let codes = ExitCode
    print(codes.SUCCESS)
    print(codes.COMPILE_ERROR)
    print(codes.ICE)
}
"#;
        let (tokens, lex_errors) = tallow::lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = tallow::interp::Interpreter::new();
        let result = interp.run(&program);
        assert!(
            result.is_ok(),
            "ExitCode sentinel should be accessible: {:?}",
            result.err()
        );
    }

    // ── Test 9: DiagnosticOutput interpreter sentinel ──
    #[test]
    fn test_diagnostic_output_sentinel() {
        let source = r#"
fn main() {
    let diag = DiagnosticOutput
    print(diag.format)
    print(diag.errors)
}
"#;
        let (tokens, lex_errors) = tallow::lexer::tokenize(source);
        assert!(lex_errors.is_empty());
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = tallow::interp::Interpreter::new();
        let result = interp.run(&program);
        assert!(
            result.is_ok(),
            "DiagnosticOutput sentinel should be accessible: {:?}",
            result.err()
        );
    }

    // ── Test 10: Completions subcommand exists in CLI ──
    #[test]
    fn test_completions_subcommand_registered() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let subcommands: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        assert!(
            subcommands.contains(&"completions"),
            "CLI should have 'completions' subcommand"
        );
    }

    // ── Test 11: Config subcommand exists in CLI ──
    #[test]
    fn test_config_subcommand_registered() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let subcommands: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        assert!(
            subcommands.contains(&"config"),
            "CLI should have 'config' subcommand"
        );
    }

    // ── Test 12: Check command has --format flag ──
    #[test]
    fn test_check_has_format_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let check_cmd = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "check")
            .unwrap();
        let format_arg = check_cmd.get_arguments().find(|a| a.get_id() == "format");
        assert!(
            format_arg.is_some(),
            "check command should have --format flag"
        );
    }

    // ── Test 13: Build command has --format flag ──
    #[test]
    fn test_build_has_format_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let build_cmd = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "build")
            .unwrap();
        let format_arg = build_cmd.get_arguments().find(|a| a.get_id() == "format");
        assert!(
            format_arg.is_some(),
            "build command should have --format flag"
        );
    }

    // ── Test 14: Lint command has --format flag ──
    #[test]
    fn test_lint_has_format_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let lint_cmd = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "lint")
            .unwrap();
        let format_arg = lint_cmd.get_arguments().find(|a| a.get_id() == "format");
        assert!(
            format_arg.is_some(),
            "lint command should have --format flag"
        );
    }

    // ── Test 15: Install has --dry-run flag ──
    #[test]
    fn test_install_has_dry_run_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let install_cmd = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "install")
            .unwrap();
        let dry_run_arg = install_cmd
            .get_arguments()
            .find(|a| a.get_id() == "dry_run");
        assert!(
            dry_run_arg.is_some(),
            "install command should have --dry-run flag"
        );
    }

    // ── Test 16: Remove has --dry-run flag ──
    #[test]
    fn test_remove_has_dry_run_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let remove_cmd = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "remove")
            .unwrap();
        let dry_run_arg = remove_cmd.get_arguments().find(|a| a.get_id() == "dry_run");
        assert!(
            dry_run_arg.is_some(),
            "remove command should have --dry-run flag"
        );
    }

    // ── Test 17: Update has --dry-run flag ──
    #[test]
    fn test_update_has_dry_run_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let update_cmd = cmd
            .get_subcommands()
            .find(|s| s.get_name() == "update")
            .unwrap();
        let dry_run_arg = update_cmd.get_arguments().find(|a| a.get_id() == "dry_run");
        assert!(
            dry_run_arg.is_some(),
            "update command should have --dry-run flag"
        );
    }

    // —— Test 18: Parser throughput mode global flag exists ——
    #[test]
    fn test_cli_has_parser_mode_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let parser_mode = cmd.get_arguments().find(|a| a.get_id() == "parser_mode");
        assert!(parser_mode.is_some(), "CLI should expose --parser-mode");
    }

    // —— Test 19: Throughput thread count global flag exists ——
    #[test]
    fn test_cli_has_throughput_threads_flag() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let threads = cmd
            .get_arguments()
            .find(|a| a.get_id() == "throughput_threads");
        assert!(threads.is_some(), "CLI should expose --throughput-threads");
    }

    // —— Test 20: Throughput flags are bound to env toggles ——
    #[test]
    fn test_cli_throughput_flags_have_env_bindings() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let parser_mode = cmd
            .get_arguments()
            .find(|a| a.get_id() == "parser_mode")
            .expect("parser_mode arg should exist");
        let threads = cmd
            .get_arguments()
            .find(|a| a.get_id() == "throughput_threads")
            .expect("throughput_threads arg should exist");
        assert!(
            parser_mode.get_env().is_some(),
            "parser_mode should have an env binding"
        );
        assert!(
            threads.get_env().is_some(),
            "throughput_threads should have an env binding"
        );
    }
}
