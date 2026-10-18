# TALLOW v1.0.0 — Complete Capability Reference

> **Privacy-first systems language**
> Single binary. 20.5 MB (unverified — no release-build measurement). 130 direct crate dependencies (root Cargo.toml, 2026-09-16). 500,404 lines of Rust in src/ (recount 2026-09-27; see docs/claims-ledger.yaml R-M1/R-M2).
> Post-quantum cryptography by default. Legal compliance at compile time.

---

## Table of Contents

1. [Language & Compiler](#1-language--compiler)
2. [CLI Commands (82)](#2-cli-commands-82)
3. [Cryptography (42+ stdlib algorithms; 18 registry-governed primitives)](#3-cryptography-42-stdlib-algorithms-18-registry-governed-primitives)
4. [Browser Automation (270 Features)](#4-browser-automation-270-features)
5. [TallowTransfer (104 Functions)](#5-tallowtransfer-104-functions)
6. [Package Manager (15 Modules)](#6-package-manager-15-modules)
7. [Compliance & Audit](#7-compliance--audit)
8. [Self-Hosted Compiler](#8-self-hosted-compiler)
9. [Standard Library (89 Modules)](#9-standard-library-89-modules)
10. [Documentation & Examples](#10-documentation--examples)
11. [By the Numbers](#11-by-the-numbers)

---

## 1. Language & Compiler

### Syntax

Tallow uses a Rust-inspired syntax designed for clarity and safety:

```nx
// Immutable by default
let name = "tallow"
var count = 0

// Functions with implicit return
fn add(a: i32, b: i32) -> i32 {
    a + b
}

// Privacy-tracked types
type Email = private String    // GDPR personal data
type Password = secret String  // zero-wiped on scope exit

// Legal annotations required on network functions
@legal(basis: .public_data, purpose: "price monitoring")
fn scrape(url: URL) -> Result<Data> {
    fetch(url)?
}

// Agent tasks with enforced permission boundaries
@agent_task(timeout: 60.seconds, can_write: false)
async fn research(query: String) -> EncryptedResult {
    ...
}
```

### Type System

| Type Category | Types |
|--------------|-------|
| **Integers** | `i8`, `i16`, `i32`, `i64`, `i128`, `u8`, `u16`, `u32`, `u64`, `u128`, `isize`, `usize` |
| **Floats** | `f32`, `f64` |
| **Text** | `String`, `char`, `Bytes` |
| **Logic** | `bool` |
| **Collections** | `[]T`, `[N]T`, `Map<K,V>`, `Set<T>`, `Queue<T>`, `Chan<T>` |
| **Error Handling** | `Result<T>`, `Option<T>` (also `T?`) |
| **Privacy** | `private T` (GDPR tracked), `secret T` (zero-wiped, never logged) |

### Privacy Type Enforcement

The compiler **rejects** unsafe operations on privacy types at compile time:

```nx
fn bad(email: Email) {
    print(email)           // ❌ COMPILE ERROR: Email is private
    print(email.redact())  // ✅ "e***@***.com"
    print(email.hash())    // ✅ SHA-256 of email
}

fn bad(key: APIKey) {
    db.insert("key", key)  // ❌ COMPILE ERROR: APIKey is secret
    conn.send(key)         // ❌ COMPILE ERROR: cannot transmit secret types
}
```

### 31 Compiler Passes

Every Tallow program is analyzed by 31 specialized compiler passes (35 construction sites across 32 pass types — recount 2026-09-16) before code generation:

> Count note (2026-09-13): fresh count — 31 `*_pass.rs` implementations in `src/` (method: `rg --files src -g '*_pass.rs'`), 37 pass constructions in `src/main.rs`; the table below tabulates the 29 named passes documented at the 2026-03 snapshot (not yet listed: `fingerprint_policy`, `tier_gate`). **Update (2026-09-16): the "37" does not reproduce — recount gives 35 `Pass::new(` sites / 32 distinct types; see claims-ledger R-M2.**

| # | Pass | Error Codes | Purpose |
|---|------|------------|---------|
| 1 | `legal` | E01xx | `@legal` annotation validation, GDPR Art.6 basis checking |
| 2 | `privacy` | E02xx | Privacy type flow analysis (`private`/`secret` tracking) |
| 3 | `agent` | E03xx | `@agent_task` permission boundary enforcement |
| 4 | `agent_safety` | E06xx | Agent sandboxing and resource limit verification |
| 5 | `constitution` | E08xx | Constitutional law constraint checking |
| 6 | `consent` | E09xx | User consent tracking and management |
| 7 | `erasure` | E10xx | Data erasure and retention period enforcement |
| 8 | `dp` | E11xx | Differential privacy budget tracking |
| 9 | `identity` | E12xx | Identity management and authentication patterns |
| 10 | `lineage` | E13xx | Data lineage and provenance tracking |
| 11 | `opsec` | E14xx | Operational security (key management, encryption) |
| 12 | `stealth` | E15xx | Anonymity features (Tor, I2P integration) |
| 13 | `contract` | E16xx | Contract assertions and formal specifications |
| 14 | `consttime` | E12xx | Constant-time cryptographic operation verification |
| 15 | `sandbox` | E11xx | Process sandboxing and isolation |
| 16 | `zk` | E15xx | Zero-knowledge proof generation |
| 17 | `enclave` | E16xx | Hardware enclave integration (Intel SGX) |
| 18 | `hw_safety` | E17xx | Hardware safety and side-channel mitigation |
| 19 | `he` | E26xx | Homomorphic encryption integration |
| 20 | `mpc` | E18xx | Multi-party computation and secret sharing |
| 21 | `ai_act` | E14xx | EU AI Act (Regulation 2024/1689) compliance |
| 22 | `nis2` | E20xx | Network & Information Security Directive 2 |
| 23 | `sast` | E21xx | Static application security testing (taint analysis) |
| 24 | `cra` | E19xx | Cyber Resilience Act (EU) compliance |
| 25 | `crypto_policy` | E22xx | Cryptography policy enforcement (NIST/FIPS) |
| 26 | `detection` | E23xx | Detection engineering and indicator coverage |
| 27 | `otel` | E24xx | OpenTelemetry instrumentation |
| 28 | `safety` | E25xx | Memory safety and runtime checks |
| 29 | `pec` | E27xx | Probabilistic error correction |

### Compilation Pipeline

```
Source (.tl)
    ↓ Lexer (tokenization + error recovery)
    ↓ Parser (recursive descent + Pratt, 13 precedence levels)
    ↓ Type Checker (privacy qualifiers, generics, inference)
    ↓ 31 Compiler Passes (parallel analysis)
    ↓ Constant Folding (codegen; no comptime feature)
    ↓ LLVM IR Generation
    ↓ LLVM Optimization
    ↓ Native Binary / WASM
```

### Compilation Targets

| Target | Status |
|--------|--------|
| x86-64 Linux | Primary |
| x86-64 Windows | Primary |
| ARM64 Linux | Supported |
| ARM64 macOS (Apple Silicon) | Supported |
| WebAssembly (WASI) | Supported |
| RISC-V | Planned |

---

## 2. CLI Commands (80 documented invocations)

### Core Language Commands

| Command | Description |
|---------|------------|
| `tallow build <file>` | Compile to native binary (with `--target`, `--release`, `--contracts`) |
| `tallow run <file>` | Compile and execute (with `--script`, program args) |
| `tallow check` | Type-check without building |
| `tallow test` | Run test files (with `--filter`, `--coverage`) |
| `tallow fmt` | Format source code (opinionated) |
| `tallow lint` | Static analysis and linting |
| `tallow doc` | Generate HTML API documentation |
| `tallow repl` | Interactive Read-Eval-Print Loop |
| `tallow lsp` | Language Server Protocol (VSCode, Neovim) |
| `tallow new <name>` | Create project from template (`--template scraper/agent/api`) |
| `tallow targets` | List all supported compilation targets |
| `tallow version` | Print version information |
| `tallow completions <shell>` | Generate shell completions (bash, zsh, fish, powershell, elvish) |

### Package Management

| Command | Description |
|---------|------------|
| `tallow add <pkg>` | Add dependency to tallow.toml |
| `tallow remove <pkg>` | Remove dependency (`--dry-run`) |
| `tallow update` | Update all dependencies (`--dry-run`) |
| `tallow install` | Install from tallow.lock (`--offline`, `--dry-run`) |
| `tallow why <pkg>` | Explain why a package is a dependency (`--full`) |
| `tallow tree` | Display dependency tree (`--depth`, `--json`) |
| `tallow outdated` | Show outdated dependencies (`--json`) |
| `tallow patch <pkg>` | Patch dependency for local editing |
| `tallow patch-commit <name>` | Commit edited patch |
| `tallow patch-remove <name>` | Remove a patch |
| `tallow publish` | Publish package to registry |
| `tallow search <query>` | Search packages in registry |
| `tallow cache info` | Show cache location, size, package count |
| `tallow cache prune` | Remove unused cached packages |
| `tallow cache clean` | Delete entire cache |
| `tallow cache verify` | Verify BLAKE3 integrity of all cached packages |
| `tallow check-deps` | Check for undeclared dependencies (`--fix`) |
| `tallow licenses` | List dependency licenses (`--json`, `--prod`, `--check`) |
| `tallow vendor` | Copy dependencies into vendor directory (air-gap builds) |
| `tallow workspace list\|root\|run` | Manage multi-module workspaces |
| `tallow pins` | Author package pins (`.tallow-pins`): `add`, `list`, `remove` — distinct from the peer registry written by `tallow pin` |

### Compliance & Audit

| Command | Description |
|---------|------------|
| `tallow audit` | Legal compliance report (`--cra`, `--nis2`, `--dora`, `--ai-act`, `--deps`, `--supply-chain`) |
| `tallow sast` | Static application security testing (SARIF output) |
| `tallow sbom` | Software Bill of Materials (CycloneDX 1.6 JSON) |
| `tallow pia` | Privacy Impact Assessment report |
| `tallow sign` | Sign package archive (Ed25519 + SLSA provenance) |
| `tallow verify` | Verify package signature and SLSA provenance |
| `tallow smt-export` | Export SMT-LIB2 verification conditions (`--proverif`) |

### Cryptography

| Command | Description |
|---------|------------|
| `tallow hash <file>` | BLAKE3 hash of file |
| `tallow encrypt <file>` | Encrypt with AES-256-GCM + Argon2id |
| `tallow decrypt <file>` | Decrypt file |
| `tallow encrypt-dir <dir>` | Encrypt entire directory |
| `tallow decrypt-dir <dir>` | Decrypt entire directory |
| `tallow speed-test` | Benchmark disk, BLAKE3, AES-GCM, zstd performance |

### File Transfer

| Command | Description |
|---------|------------|
| `tallow send <file>` | Send file over QUIC with code phrase |
| `tallow receive <code>` | Receive file using code phrase |
| `tallow copy <src> <dst>` | Fast parallel file copy |
| `tallow delta-sync <src> <dst>` | Delta sync with 24 flags (see below) |
| `tallow share <file>` | Share file via download link |
| `tallow chat` | Start encrypted real-time chat |
| `tallow send-text <msg>` | Send text message directly |
| `tallow group-chat` | Create encrypted group chat |
| `tallow discover` | Discover peers on local network |
| `tallow relay` | Start TallowTransfer relay server |
| `tallow signal` | Start signaling server for global peer discovery |
| `tallow watch <src> <dst>` | Watch directory for changes and sync |
| `tallow pack <dir> <out>` | Pack directory into TWD archive |
| `tallow unpack <archive>` | Unpack TWD archive |
| `tallow audit-transfers` | Show transfer audit log |
| `tallow validate-file <file>` | Validate file type by magic bytes |
| `tallow retain <dir>` | Apply retention policy to directory |
| `tallow live-view` | Share live browser session for remote viewing |

### Delta-Sync Flags (23)

> Count note (2026-09-13, W2-08): the CLI defines **23 named flags** (25 `#[arg]` fields including the two positional path arguments; verified against `src/main.rs` at W2-08). This quick list shows all 23 — `--vss` was removed in W2-08 (design D-C1: the flag was dead; automatic VSS fallback on Windows remains).

```
--mirror          Mirror mode (delete files not in source)
-j <N>            Parallel workers (default: CPU count)
--dry-run         Show what would change without copying
--exclude <pat>   Exclude file pattern
--exclude-dir     Exclude directory pattern
--retries <N>     Retry failed copies N times
--log <file>      Write log to file
--compress        Compress during transfer (zstd)
--max-age <days>  Only sync files newer than N days
--min-size <N>    Only sync files larger than N bytes
--max-size <N>    Only sync files smaller than N bytes
--copy-acls       Copy file access control lists
--symlinks        Follow symbolic links
--save-job <name> Save sync job for later replay
--load-job <name> Load and run saved sync job
--run-hours <H-H> Only run during specified hours
--preserve-permissions  Preserve file permissions
--preserve-owner  Preserve file ownership
--follow-symlinks Follow symbolic links
--bytes           Show progress in bytes
-q                Quiet mode
--verify          Verify copies with BLAKE3
--block-level     Use block-level delta sync (rsync algorithm, 128 KiB blocks)
```

### Browser Management

| Command | Description |
|---------|------------|
| `tallow browser install` | Download and install Chromium (`--full` for Chrome) |
| `tallow browser list` | List installed browser versions |
| `tallow browser remove` | Remove browser version |
| `tallow browser path` | Show path to Chrome binary |
| `tallow browser pool` | Show browser pool status |
| `tallow browser devices` | List 163 device profiles (`--category` filter) |
| `tallow ffmpeg install` | Install ffmpeg for video recording |
| `tallow ffmpeg path` | Show ffmpeg installation path |
| `tallow ffmpeg version` | Show ffmpeg version |
| `tallow ffmpeg remove` | Remove ffmpeg installation |

### Extraction

| Command | Description |
|---------|-------------|
| `tallow schema check <file>` | Validate a `tallow.extraction_schema.v1` extraction contract; exit 0 = valid, 1 = invalid (the failing field is named on stderr), 64 = usage or unreadable file |
| `tallow plan dry-run <file>` | Print what a `tallow.request_plan.v1` manifest would fetch, with **no egress**; refuses a manifest whose requests omit their `compliance` block. Exit 0 = ok, 1 = invalid (the offending request is named), 64 = usage |

### Configuration

| Command | Description |
|---------|------------|
| `tallow config get <key>` | Get configuration value |
| `tallow config set <key> <val>` | Set configuration value |
| `tallow config list` | List all configuration values |
| `tallow config path` | Show config file path |

---

## 3. Cryptography (42+ stdlib algorithms; 18 registry-governed primitives)

Every algorithm uses **real cryptographic implementations** — zero simulations, zero BLAKE3 fakes.

> **Status:** internal review only — **no external audit; not FIPS-validated**. "42+" counts the advertised stdlib surface; the CBOM registry governs 18 primitives (`scripts/crypto-inventory.json`). FIPS references below name algorithm standards, not validated modules.

### Post-Quantum Cryptography (NIST Standards)

| Algorithm | Standard | Crate | Use Case |
|-----------|----------|-------|----------|
| **ML-KEM-512** | FIPS 203 | `ml-kem` | Key encapsulation (Level 1) |
| **ML-KEM-768** | FIPS 203 | `ml-kem` | Key encapsulation (Level 3) — **DEFAULT** |
| **ML-KEM-1024** | FIPS 203 | `ml-kem` | Key encapsulation (Level 5, CNSA 2.0) |
| **ML-DSA-44** | FIPS 204 | `ml-dsa` | Digital signature (Level 2) |
| **ML-DSA-65** | FIPS 204 | `ml-dsa` | Digital signature (Level 3) — **DEFAULT** |
| **ML-DSA-87** | FIPS 204 | `ml-dsa` | Digital signature (Level 5, CNSA 2.0) |
| **SLH-DSA** (SPHINCS+) | FIPS 205 | `pqcrypto-sphincsplus` | Hash-based signature (6 parameter sets) |
| **FALCON-512** | NIST selected (standardization in progress) | `pqcrypto-falcon` | Compact lattice signature |
| **FALCON-1024** | NIST selected (standardization in progress) | `pqcrypto-falcon` | Compact lattice signature (Level 5) |
| **FrodoKEM-640/976/1344** | NIST Alt | `pqcrypto-frodo` | Conservative LWE-based KEM |
| **Classic McEliece** | NIST Round 4 candidate | `pqcrypto-classicmceliece` | Code-based KEM (261KB public keys) |

> **Build-gate note (W5 decision C, 2026-09-26):** the four *legacy* families above — SLH-DSA, FALCON, FrodoKEM, Classic McEliece — are **optional: build with `--features pq-legacy`**. Default builds expose ML-KEM/ML-DSA only; the legacy entry points return honest "not enabled" errors (no silent fallback). Rationale: the frozen PQClean wrappers carry audit findings and have zero in-tree callers.

*"DEFAULT" markers describe the `.tl`/stdlib surface (ML-KEM-768 / ML-DSA-65; the vault independently pins ML-KEM-768). The Rust `tallow-crypto` crate ships ML-KEM-1024 / ML-DSA-87 — the parameter-set divergence is a tracked open item (cycle-01/07 FIX-3).*

> **Note:** **HQC** — selected by NIST in 2025 for ongoing standardization; **not implemented** in Tallow (tracked as a KEM hedge only, roadmap S1). Classic McEliece remains a Round-4 candidate (not yet selected).

### Classical Cryptography

| Algorithm | Crate | Use Case |
|-----------|-------|----------|
| **AES-256-GCM** | `aes-gcm` | Symmetric encryption — **DEFAULT** |
| **AES-256-GCM-SIV** | `aes-gcm-siv` | Misuse-resistant encryption |
| **ChaCha20-Poly1305** | `chacha20poly1305` | Stream cipher (RFC 8439) |
| **XChaCha20-Poly1305** | `chacha20poly1305` | Extended nonce (192-bit) |
| **Ed25519** | `ed25519-dalek` | Digital signatures |
| **X25519** | `x25519-dalek` | Elliptic curve Diffie-Hellman |
| **AES-256-KW** | `aes-kw` | Key wrapping (SP 800-38F) |

### Hash Functions

| Algorithm | Crate | Output |
|-----------|-------|--------|
| **BLAKE3** | `blake3` | 256-bit — **DEFAULT** (fastest) |
| **SHA-256** | `sha2` | 256-bit (FIPS 180-4) |
| **SHA-384** | `sha2` | 384-bit (CNSA 2.0 minimum) |
| **SHA-512** | `sha2` | 512-bit |
| **SHA3-256/384/512** | `sha3` | FIPS 202 |
| **SHAKE128/256** | `sha3` | Extendable output (XOF) |
| **SM3** | `sm3` | 256-bit (Chinese OSCCA standard) |
| **GOST Streebog** | `streebog` | 256-bit (Russian GOST R 34.11-2012) |

### Password Hashing

| Algorithm | Crate | Notes |
|-----------|-------|-------|
| **Argon2id** | `argon2` | Memory-hard — **DEFAULT** (OWASP recommended) |
| **Bcrypt** | `bcrypt` | Legacy support |
| **Scrypt** | `scrypt` | Memory-hard alternative |
| **PBKDF2-SHA256** | `pbkdf2` | SP 800-132 (600K iterations) |

### Advanced Signature Schemes

| Algorithm | Implementation | Use Case |
|-----------|---------------|----------|
| **BLS12-381** | `blst` (C/asm) | Aggregate signatures (Ethereum consensus) |
| **Threshold signing** (experimental — **NOT FROST**) | Ed25519 + Shamir GF(256) share split | t-of-n share signing; no DKG/aggregation — not RFC 9591 FROST |
| **BBS+ Credentials** | Ed25519 commitment-based | Anonymous credentials, selective disclosure |
| **Blind Signatures** | Ed25519 + BLAKE3 keyed hash | Unlinkable signatures |
| **ECVRF** | Ed25519 ECVRF | Verifiable random functions |

### Key Exchange & Authentication

| Protocol | Implementation | Use Case |
|----------|---------------|----------|
| **X25519 + ML-KEM-768 Hybrid** | Real combined KEM | TLS 1.3 hybrid (classical + PQC) |
| **SPAKE2** | `spake2` crate | Password-authenticated key exchange |
| **OPAQUE** | Argon2id + Ed25519 | Augmented PAKE (password never sent) |
| **Noise Framework** | `snow` crate | Flexible authenticated key exchange |
| **Double Ratchet** | X25519 + HKDF + AES-GCM | Signal Protocol messaging |
| **PASETO v4** | XChaCha20-Poly1305 + Ed25519 | Secure token format |

### Secret Sharing & Formal

| Algorithm | Implementation | Use Case |
|-----------|---------------|----------|
| **Shamir Secret Sharing** | GF(256) field arithmetic | Split secrets into shares |
| **Feldman VSS** | Shamir + BLAKE3 commitments | Verifiable secret sharing |
| **FF1 FPE** | Feistel-based (SP 800-38G) | Format-preserving encryption |
| **OPRF** | BLAKE3 keyed hash | Oblivious pseudorandom function |

### National Standards

| Standard | Algorithm | Crate | Country |
|----------|-----------|-------|---------|
| **OSCCA** | SM4-CBC | `sm4` + `cbc` | China |
| **OSCCA** | SM3 | `sm3` | China |
| **OSCCA** | SM2 | Ed25519-backed | China |
| **GOST R 34.12-2015** | Kuznyechik-CBC | `kuznyechik` + `cbc` | Russia |
| **GOST R 34.11-2012** | Streebog-256 | `streebog` | Russia |

### X.509 & PKI

| Feature | Implementation |
|---------|---------------|
| **Certificate Generation** | `rcgen` crate (real self-signed X.509, Ed25519) |
| **Certificate Chain Verification** | PEM parsing + DER validation |
| **HSM/PKCS#11** | Simulated (requires physical HSM hardware) |
| **TPM 2.0** | Simulated (requires TPM chip) |
| **FIDO2/Passkey** | Ed25519-based (requires USB authenticator for full) |

---

## 4. Browser Automation (270 Features)

### Architecture

108 modules controlling real Chrome via the Chrome DevTools Protocol (CDP):

| Module | Purpose |
|--------|---------|
| `cdp.rs` | WebSocket CDP client connection |
| `page.rs` | Page/tab lifecycle management |
| `element.rs` | DOM element selection and interaction |
| `frame.rs` | Frame/iframe handling |
| `network.rs` | Network interception, HAR recording |
| `session.rs` | Cookies, localStorage, sessionStorage |
| `stealth.rs` | Anti-detection (7 profiles) |
| `devices.rs` | Device emulation (163 profiles) |
| `emulation.rs` | Viewport, throttling, geolocation |
| `process.rs` | Chromium process lifecycle |
| `recording.rs` | Video/screenshot recording (4K) |
| `download.rs` | Download interception |
| `auth.rs` | Basic, digest, certificate auth |
| `captcha.rs` | CAPTCHA detection integration |
| `privacy.rs` | Privacy controls, tracking prevention |
| `robots.rs` | robots.txt parsing and respecting |
| `interaction.rs` | Click, type, scroll, hover |
| `visual.rs` | Visual regression detection |
| `accessibility.rs` | a11y tree, ARIA labels |
| `retry.rs` | Exponential backoff retry |
| `pool.rs` | Multiple browser instance management |
| `trace.rs` | Performance tracing |
| `html_parser.rs` | HTML parsing (via scraper) |
| `error.rs` | Error types |

### Device Profiles (163+)

| Category | Profiles |
|----------|---------|
| **iPhone** | XS, 11, 12, 13, 14, 15, 15 Pro Max |
| **iPad** | Air, Pro, Mini (multiple generations) |
| **Google Pixel** | 3, 4, 5, 6, 7, 8 series |
| **Samsung Galaxy** | S20, S21, S22, S23, S24 |
| **Desktop** | Chrome, Firefox, Safari (multiple resolutions) |
| **Custom** | Any user-agent + viewport combination |

### Stealth Profiles (7)

1. Headless detection bypass
2. WebDriver property hiding (`navigator.webdriver = false`)
3. Chrome user-agent spoofing
4. DevTools detection bypass
5. Automation flags stripping
6. Plugins array manipulation
7. Navigator.permissions spoofing

### Recording Capabilities

- **4K video** (up to 3840x2160 at 60fps)
- **Screenshot** (PNG, full page or viewport)
- **PDF export** (print-quality)
- **Console capture** (all `console.log` events)
- **Network HAR** recording
- **Performance trace** recording
- **ffmpeg integration** (auto-install, AVI MJPEG + MP4 conversion)

### Browser Example

```nx
import tallow.browser

fn main() {
    let browser = Browser.launch(headless: false)
    let page = browser.new_page()

    // Navigate with stealth
    page.set_stealth(.residential)
    page.set_device(.iphone_15_pro)
    page.goto("https://example.com")

    // Record video
    page.start_recording(resolution: .uhd_4k, fps: 60)

    // Interact
    let items = page.query_all(".product")
    for item in items {
        let price = item.text()
        print("Price: {price}")
    }

    page.stop_recording("output.mp4")
    browser.close()
}
```

---

## 5. TallowTransfer (104 Functions)

### Transfer Modes

| Mode | Protocol | Use Case |
|------|----------|----------|
| **P2P Send/Receive** | QUIC (quinn) | Direct encrypted file transfer with code phrases |
| **Delta-Sync** | Custom (rayon parallel) | Incremental directory synchronization |
| **Fast Copy** | OS-native + rayon | High-speed parallel file copying |
| **Relay** | QUIC + TLS | NAT traversal for firewalled peers |
| **Share by Link** | HTTP server | Generate download link for any file |
| **Live View** | WebSocket | Share live browser session remotely |
| **Chat** | QUIC encrypted | Real-time encrypted text messaging |
| **Group Chat** | QUIC multicast | Encrypted group messaging |
| **Cloud Sync** | S3/GCS/Azure APIs | Cloud storage integration |
| **Air-Gap QR** | Visual encoding | Transfer data via QR codes (no network) |
| **Air-Gap Audio** | FSK modem (BFSK) | Transfer data via audio (no network) |

### Security Features

| Feature | Implementation |
|---------|---------------|
| **Encryption** | AES-256-GCM + Argon2id key derivation |
| **Integrity** | BLAKE3 checksums per chunk |
| **Erasure Coding** | Reed-Solomon-SIMD (data redundancy) |
| **mTLS** | Mutual TLS authentication |
| **RBAC** | Role-based access control |
| **Malware Scanning** | YARA rules + built-in scanner |
| **Audit Logging** | Tamper-evident transfer logs |
| **Signed Manifests** | Ed25519 cryptographic signatures |
| **Expiry/Retention** | Automatic file expiry and cleanup |

### Enterprise Features

| Feature | Description |
|---------|------------|
| **Locked-File Copy** | Windows locked-file copy with automatic VSS (Volume Shadow Copy) fallback (Outlook, SQL Server, Exchange) |
| **23-Flag Delta-Sync** | Mirror, parallel workers, ACLs, symlinks, compression, scheduling |
| **Target Cache** | Skip unchanged files using mtime+size fast-path |
| **Checkpoint/Resume** | Save and resume interrupted transfers |
| **Bandwidth Throttling** | Per-transfer bandwidth limits (`--bwlimit`, bits/sec, enforced on QUIC/relay sends) |
| **Progress Bars** | Real-time indicatif progress with ETA |
| **Job Scheduling** | Save/load/replay sync jobs, run-hours restriction |
| **Webhooks** | HTTP callbacks on transfer events |

### Performance

| Operation | Speed |
|-----------|-------|
| Disk throughput | 2,621 MB/s — unverified (no producing bench) |
| BLAKE3 hashing | 2,621 MB/s — unverified (no producing bench) |
| AES-256-GCM encryption | 699 MB/s |
| Zstd compression | 2,621 MB/s — unverified (no producing bench) |
| Delta-sync (80K files, second run) | ~3 seconds |

*Unverified rows: no benchmark in this repository produces these numbers; all three share one unsourced value from the v1.0.0 import commit (verified 2026-09-12).*

### Cloud Storage Integration

| Provider | Operations |
|----------|-----------|
| **AWS S3** | list, upload, download |
| **Google Cloud Storage** | list, upload, download |
| **Azure Blob** | list, upload, download |

### TWD Archive Format

Tallow's native archive format preserves complete directory structure:

```bash
tallow pack ./my-project archive.twd   # Pack with metadata
tallow unpack archive.twd ./output     # Restore exact structure
```

Features: BLAKE3 integrity, zstd compression, permission preservation, symlink support.

---

## 6. Package Manager (15 Modules)

### Architecture

| Module | Purpose |
|--------|---------|
| `manifest.rs` | Parse/write `tallow.toml` dependency specifications |
| `lockfile.rs` | BLAKE3-based deterministic lockfile generation |
| `resolver.rs` | PubGrub SAT-based dependency resolution |
| `registry.rs` | Hosted registry client (publish, search, auth) |
| `hosted_registry.rs` | Self-hosted registry server |
| `cache.rs` | Content-addressed package cache (BLAKE3 integrity) |
| `archive.rs` | `.tar.zst` package format |
| `enterprise.rs` | License compliance, hardlink store, workspace |
| `legal_propagation.rs` | `@legal` annotation propagation across dependencies |
| `interface_gen.rs` | Generate `.d.tl` interface files |
| `script_runner.rs` | Pre/post-install script execution |
| `semver_req.rs` | Semantic versioning requirement parsing |
| `workspace.rs` | Monorepo workspace management |
| `cli.rs` | CLI integration |

### Key Features

| Feature | Details |
|---------|---------|
| **Dependency Resolution** | PubGrub algorithm with minimal conflict diagnosis |
| **Lockfile** | BLAKE3-based integrity, deterministic, transitive recording |
| **Cache** | Content-addressed hardlink store (space-efficient) |
| **Private Registries** | Authentication tokens, rate limiting |
| **License Compliance** | Automatic license detection and policy enforcement |
| **Vendoring** | Air-gap builds with `tallow vendor` |
| **Workspace** | Monorepo support with shared lockfile |
| **Legal Propagation** | `@legal` basis inheritance across dependency graph |
| **Package Signing** | Ed25519 signatures with SLSA provenance |
| **Dependency Explanation** | `tallow why <pkg>` traces dependency chain |

### Project Manifest (`tallow.toml`)

```toml
[package]
name = "my-project"
version = "0.1.0"
author = "Developer"
license = "MIT"

[dependencies]
tallow-html = "0.3"
tallow-db = "0.2"

[legal]
default_jurisdiction = ["us", "eu"]
default_robots_txt = "respect"
audit_log_path = "logs/audit"

[build]
target = "x86_64-linux"
optimize = "release"
```

---

## 7. Compliance & Audit

> **What these artifacts are (and are not):** Tallow produces compliance *engineering evidence* — compile-time checks active on `@legal`-annotated code, source-level reports, and opt-in runtime trails. It is not a certification body; no output constitutes legal advice; court-facing reliance requires your own chain-of-custody.
> *This report is engineering evidence from static analysis of source code — it is not legal advice, not a certification, and not a substitute for review by qualified counsel.*

### Supported Regulations

| Regulation | Region | What Tallow Enforces |
|-----------|--------|---------------------|
| **GDPR** | EU | `@legal` basis required, retention limits, erasure rights, consent tracking, purpose limitation |
| **CRA** (Cyber Resilience Act) | EU | SBOM generation, vulnerability disclosure timeline, automatic update mechanisms |
| **NIS2** (Network Security Directive) | EU | Incident reporting, BSI C5 alignment, supply chain security audit |
| **DORA** (Digital Operational Resilience) *(pass maturity: partial — report-only heuristic audit (`tallow audit --dora`); no compile-time pass)* | EU | ICT incident classification, severity mapping, recovery time objectives |
| **AI Act** (Regulation 2024/1689) *(pass maturity: compile-time pass enforced (E1400–E1406); audit report partial)* | EU | Risk classification, transparency requirements, human oversight |
| **CCPA** *(target — not yet implemented)* | US (California) | Consumer data rights, opt-out mechanisms |
| **LGPD** *(target — not yet implemented)* | Brazil | Data processing basis, DPO requirements |
| **PIPEDA** *(target — not yet implemented)* | Canada | Consent and purpose limitation |
| **APPI** *(target — not yet implemented)* | Japan | Personal information handling |
| **PIPL** *(target — not yet implemented)* | China | Cross-border transfer restrictions |

*GDPR, CRA, NIS2 and AI Act have compile-time passes; DORA is a heuristic audit report only (no compile-time pass). Maturity varies per pass (labels above). The five jurisdictions marked target-only have zero implementation in the compiler (verified 2026-09-12).*

### Legal Basis Values (GDPR Art. 6)

```nx
.public_data         // Publicly available data (hiQ v. LinkedIn)
.consent             // Explicit user consent (requires consent_ref)
.legitimate_interest // Requires lia_completed: true
.research            // Academic, journalistic, public interest
.contract            // Necessary for contract performance
.vital_interests     // Emergency situations only
.legal_obligation    // Required by law
```

### Audit Command

```bash
tallow audit                    # Full compliance report
tallow audit --cra              # Cyber Resilience Act specific
tallow audit --nis2             # NIS2 Directive specific
tallow audit --dora             # DORA specific
tallow audit --ai-act           # AI Act specific
tallow audit --deps             # Dependency audit
tallow audit --supply-chain     # Supply chain integrity
tallow audit --format json      # Machine-readable output
tallow audit --jurisdiction eu  # EU-specific checks
```

*Reports are engineering evidence — not legal advice, not a certification (see the note at the top of this section).*

### Compiler-Generated Audit Logs *(partial)*

Auto-emission today is partial: the self-hosted compiler emits plain `[AUDIT] fn=… basis=… purpose=…` text lines; the native toolchain only declares the audit FFI, and structured JSONL logging is opt-in via `tallow.legal.log_audit`. The sample below is illustrative — fields such as `records_processed`/`compliance_status` are not produced by shipped code today:

```json
{
  "timestamp": "2026-03-20T14:23:11Z",
  "function": "scrape_prices",
  "legal_basis": "public_data",
  "purpose": "competitive price monitoring",
  "personal_data": false,
  "jurisdiction": ["us", "eu"],
  "robots_txt": "respected",
  "rate_limit": "2/sec",
  "retain_until": "2026-03-31",
  "records_processed": 4821,
  "compliance_status": "COMPLIANT",
  "tallow_version": "0.4.0"
}
```

---

## 8. Self-Hosted Compiler

Tallow can compile itself. The self-hosted compiler is 9,798 lines of Tallow:

| File | LOC | Purpose |
|------|-----|---------|
| `types.tl` | 901 | Type system (Token, AST, Arena) with 87 token kinds, 29 AST node kinds |
| `lexer.tl` | 541 | Complete tokenizer with string interpolation |
| `parser.tl` | 1,881 | Recursive descent + Pratt parsing, 13 precedence levels |
| `typeck.tl` | 1,443 | Type checker with privacy qualifier tracking, generic inference |
| `codegen.tl` | 4,250 | LLVM IR emitter (match, enums, closures, struct methods, `@legal` audit, secret wipe) |
| `main.tl` | 595 | CLI entry point (build, run, check, emit-ir, version) |
| `stdlib.tl` | 187 | Runtime support and platform detection |

### Self-Hosted Compilation Pipeline

```
Source (.tl) → Lexer → Parser → Type Checker → Code Generator → LLVM IR → Native Binary
```

### Compile-Time Features in Self-Host

- `@legal` audit log emission at function entry (**self-hosted compiler only — plain-text `printf` line**)
- `secret` type zero-wipe via `llvm.memset` at scope exit
- Privacy qualifier tracking (`QUAL_SECRET`, `QUAL_PRIVATE`)
- Secret types blocked from string interpolation (error E0201)
- `.redact()`, `.hash()`, `.mask()` method recognition

---

## 9. Standard Library (89 Modules)

| Module | Functions | Purpose |
|--------|----------|---------|
| `tallow.crypto` | 113 | All cryptographic primitives (see Section 3) |
| `tallow.transfer` | 104 | File transfer, sync, encryption (see Section 5) |
| `tallow.http` | ~20 | HTTP client/server, fetch, routing |
| `tallow.html` | ~15 | HTML parsing, CSS selectors (via scraper) |
| `tallow.json` | ~10 | JSON encode/decode (serde_json) |
| `tallow.fs` | ~25 | Filesystem operations, directory traversal, ACLs |
| `tallow.net` | ~30 | Sockets, DNS, TLS (rustls/quinn), Tor, I2P, WireGuard |
| `tallow.log` | ~10 | Structured logging with automatic privacy redaction |
| `tallow.time` | ~15 | Time, duration, timezone (chrono) |
| `tallow.env` | ~5 | Environment variables, command-line args |
| `tallow.process` | ~10 | Process spawning, pipes, exit codes |
| `tallow.regex` | ~5 | Regular expression matching |
| `tallow.math` | ~20 | Math functions (sqrt, sin, cos, log, pow, etc.) |
| `tallow.rand` | ~10 | Cryptographically secure random generation |
| `tallow.url` | ~10 | URL parsing, encoding, manipulation |
| `tallow.compress` | ~10 | gzip, zstd, brotli, lz4 compression |
| `tallow.osint` | ~50 | OSINT techniques (DNS, WHOIS, IP lookup, email validation) |
| `tallow.forensics` | ~20 | Digital forensics (file carving, metadata extraction) |
| `tallow.mesh` | ~15 | Mesh networking, DHT, peer discovery |

### Privacy-Aware Logging

```nx
import tallow.log

// Private types are automatically redacted
log.info("processing user {email}")  // logs "processing user e***@***.com"
log.info("request from {ip}")        // logs "request from ***.***.***.***"

// Explicit control
log.info("user hash: {email.hash()}")    // logs SHA-256
log.info("masked: {phone.mask()}")       // logs "***-***-1234"
```

---

## 10. Documentation & Examples

### HTML Documentation (40 files)

| Document | Content |
|----------|---------|
| `tallow-complete-reference.html` | Full language reference (2,800 lines) |
| `getting-started.html` | Beginner tutorial |
| `browser-reference.html` | Browser automation guide (20 sections) |
| `transfer-reference.html` | File transfer guide (13 sections) |
| `tallow-transfer-browser-guide.html` | Quick overview |
| `api/` (34 pages) | Auto-generated API docs: 159 functions, 92 structs, 11 enums |

### Example Programs (63 programs)

```
examples/
├── hello_simple.tl           # Hello world
├── structs.tl                # Struct and method syntax
├── enums.tl                  # Enum and match patterns
├── error_handling.tl         # Result and ? operator
├── interpolation.tl          # String interpolation
├── legal_valid.tl            # @legal annotation examples
├── privacy_valid.tl          # Privacy type examples
├── agent_valid.tl            # @agent_task examples
├── pqc_crypto.tl             # Post-quantum crypto demo
├── browser_demo.tl           # Browser automation
└── ... (48 more)

tests/fixtures/               # five programs from the original list live here,
├── closures.tl               # as compiler fixtures rather than examples
├── contracts.tl
├── ai_act.tl
├── anonymize.tl
└── stealth_net.tl
```

---

## 11. By the Numbers

| Metric | Value |
|--------|-------|
| **Rust source code** | 500,404 lines in src/ (recount 2026-09-27; src+crates+tests = 595,264) |
| **Self-hosted Tallow code** | 9,798 lines |
| **Total implementation** | 192,126 lines |
| **CLI commands** | 82 (counted from `tallow --help`, 2026-10-17; includes the built-in `help` subcommand) |
| **Compiler passes** | 31 (*_pass.rs files; 32 pass types constructed in src/main.rs, 35 construction sites — recount 2026-09-16) |
| **Crypto dispatch functions** | 113 (all real implementations) |
| **Transfer dispatch functions** | 104 |
| **Browser modules** | 108 |
| **Device profiles** | 163 |
| **Stealth profiles** | 7 |
| **Standard library modules** | 89 |
| **Package manager modules** | 15 |
| **Test sites (static count, not executed)** | 10,215 #[test] attributes (src 8,837 · crates 942 · tests 436; +238 #[tokio::test]) — recount 2026-09-16 |
| **Crypto tests** | Per-surface `#[test]` counts (2026-09-13): 206 (tallow-crypto) · 126 (src/stdlib/crypto.rs) · 218 (src/vault) · 5 (crypto_policy_pass) — there is no single "124" suite |
| **Crate dependencies** | 130 direct (root Cargo.toml, 2026-09-16) |
| **Documentation files** | 40 |
| **Example programs** | 63 `.tl` programs (2026-10-17 re-measure; the previous 85 was the top-level file count, not the program count) |
| **Compiled binary size** | 20.5 MB — **unverified** (no release-build measurement; the `#[ignore]`d `perf_binary_size` test asserts <12 MB for the release binary — one of the two is stale — cycle-01/03 §6) |
| **Startup time** | <1ms (unmeasured — no process-level measurement; treat as target) |
| **NIST crypto algorithms** | 42+ (stdlib surface; 18 registry-governed primitives; no external audit, not FIPS-validated) |
| **PQC algorithms (real)** | 11 (ML-KEM, ML-DSA default; SLH-DSA, FALCON, FrodoKEM, McEliece behind `--features pq-legacy`) |
| **Supported jurisdictions** | 10 declared (US, EU, UK, CA, AU, BR, JP, SG, CN, Global); compiler enforcement for the EU set only — CCPA/LGPD/PIPEDA/APPI/PIPL target-only |
| **EU regulations enforced** | 5 (GDPR, CRA, NIS2, DORA, AI Act) |

---

## Quick Start

```bash
# Install
powershell -ExecutionPolicy Bypass -File install.ps1

# Verify
tallow version

# Create a project
tallow new my-project
cd my-project

# Run
tallow run src/main.tl

# Build native binary
tallow build src/main.tl --release

# Send a file
tallow send myfile.txt

# Encrypt a directory
tallow encrypt-dir ./secrets --password "passphrase"

# Sync to NAS
tallow delta-sync ./project \\NAS\backup --mirror -j 16

# Launch browser automation
tallow run examples/browser_demo.tl

# Generate compliance report
tallow audit --cra --nis2

# Run tests
tallow test --coverage
```

---

## Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Windows 10/11 x64 (primary), Linux x64/ARM64, macOS ARM64 |
| **Disk** | 25 MB (binary + stdlib + docs) |
| **RAM** | 64 MB minimum, 256 MB recommended |
| **Optional** | LLVM/Clang (for `tallow build`): `winget install LLVM.LLVM` |
| **Optional** | Chrome (for browser automation): `tallow browser install` |
| **Optional** | ffmpeg (for video recording): `tallow ffmpeg install` |

---

## License

MIT (see `Cargo.toml` `license`).

---

*Generated: 2026-03-20*
*Tallow v1.0.0 — Privacy-first systems language*
*500,404 lines of Rust in src/ (recount 2026-09-27). Test sites: 10,215 #[test] + 238 #[tokio::test] (static count, not executed). 31 *_pass.rs files. 42+ stdlib crypto algorithms (18 registry-governed; no external audit).*
