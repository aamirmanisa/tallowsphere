# TALLOW Language — Compiler Build Spec
> Feed this to Claude Code to build the compiler

## WHAT WE'RE BUILDING
A privacy-first systems programming language with:
- Compiler-enforced legal compliance (`@legal` annotations)
- Privacy type qualifiers (`private`, `secret`) tracked through type system  
- PQC cryptography as default (ML-KEM-768, Argon2id)
- First-class `IPPool` for 10K-10M+ concurrent connections
- `@agent_task` for sandboxed autonomous execution

## IMPLEMENTATION PLAN

### Phase 1: Bootstrap Compiler (Rust)
Build in this order:

1. **Lexer** (`src/lexer.rs`)
   - Tokenize `.tl` source files
   - Tokens: keywords, identifiers, literals, operators, annotations (`@legal`, `@agent_task`)

2. **Parser** (`src/parser.rs`)
   - Recursive descent
   - Produces typed AST
   - Handle: fn, let, var, struct, enum, impl, match, for, while, if

3. **Type Checker** (`src/typeck.rs`)
   - Privacy type flow analysis (`private`, `secret` qualifiers)
   - Enforce: secret types never logged, never serialized, zero-wiped
   - Enforce: private types require `.redact()` or `.hash()` before logging

4. **@legal Pass** (`src/legal_pass.rs`)
   - Collect all functions touching network/storage
   - Reject unannotated functions
   - Validate legal basis vs return types
   - Generate audit log schema per annotated function

5. **IR Generation** (`src/codegen.rs`)
   - Lower AST to LLVM IR
   - Insert zero-wipe calls for `secret` type scope exits
   - Insert audit log calls for `@legal` functions

6. **LLVM Backend**
   - Target: x86-64-linux first
   - Use `inkwell` crate for LLVM bindings

### Directory Structure for Claude Code
```
tallow/
├── Cargo.toml
├── CLAUDE.md          ← this file
├── TALLOW_COMPLETE.md   ← full design doc
├── src/
│   ├── main.rs        ← CLI entry point
│   ├── lexer.rs
│   ├── parser.rs
│   ├── ast.rs
│   ├── typeck.rs
│   ├── legal_pass.rs
│   ├── privacy_pass.rs
│   ├── codegen.rs
│   └── error.rs
├── tests/
│   ├── lexer_tests.rs
│   ├── parser_tests.rs
│   └── fixtures/
│       ├── hello.tl
│       ├── legal_valid.tl
│       └── legal_invalid.tl
└── stdlib/            ← Tallow standard library (written in Tallow)
    ├── http.tl
    ├── crypto.tl
    └── net.tl
```

## KEY SYNTAX RULES (for parser)

```
program     := item*
item        := fn_decl | struct_decl | enum_decl | impl_block | const_decl
fn_decl     := annotation* 'fn' IDENT '(' params ')' ('->' type)? block
annotation  := '@legal' '(' legal_args ')' | '@agent_task' '(' agent_args ')'
params      := (param (',' param)*)?
param       := IDENT ':' type
block       := '{' stmt* expr? '}'
stmt        := let_stmt | var_stmt | expr_stmt | return_stmt
let_stmt    := 'let' IDENT (':' type)? '=' expr
type        := IDENT | IDENT '<' type '>' | '[' ']' type | type '?'
expr        := literal | IDENT | call | method_call | match_expr | if_expr | block
```

## PRIVACY TYPES (for type checker)

```rust
// Type qualifiers to track
enum TypeQualifier {
    Normal,
    Private,   // GDPR personal data
    Secret,    // Credentials — zero-wipe on scope exit
}

// Built-in private types
const PRIVATE_TYPES: &[&str] = &[
    "Email", "IPAddress", "Name", "Phone", "Location", "SSN"
];

// Violations to catch:
// 1. private/secret value passed to print/log without .redact()/.hash()
// 2. secret value in string interpolation
// 3. secret value serialized to disk/network
// 4. secret value returned from public function
```

## @legal ANNOTATION (for legal_pass.rs)

```rust
struct LegalAnnotation {
    basis: LegalBasis,         // required
    purpose: String,           // required  
    personal_data: bool,       // default false
    jurisdiction: Vec<Jurisdiction>,
    retain_for: Option<Duration>,
    robots_txt: RobotsTxt,     // default: Respect
    rate_limit: Option<RateLimit>,
    lia_completed: bool,       // required if basis == LegitimateInterest
}

enum LegalBasis {
    PublicData,
    Consent,
    LegitimateInterest,
    Research,
    Contract,
    VitalInterests,
    LegalObligation,
}

// Compile errors to emit:
// - Network function missing @legal annotation
// - personal_data: true without retain_for
// - retain_for: .forever
// - basis: .legitimate_interest without lia_completed: true
// - function returns Email/Name/etc. but personal_data: false
```

## IPPOOL RUNTIME

```rust
// IPPool config maps to:
struct IPPoolConfig {
    size: PoolSize,           // Auto | Fixed(n)
    backend: Backend,         // Epoll | IoUring | Dpdk
    rotation: Rotation,       // PerRequest | PerSession | Manual
    protocol: Protocol,       // Socks5 | Http | Https
}

// Backend selection:
// size <= 10K     → epoll
// size <= 1M      → io_uring  
// size > 1M       → DPDK (requires root + DPDK setup)
// .auto           → detect at runtime
```

## CRYPTO DEFAULTS

```
Key exchange:  ML-KEM-768 (NIST FIPS 203)
Signatures:    ML-DSA-65  (NIST FIPS 204)  
Symmetric:     AES-256-GCM
Stream cipher: ChaCha20-Poly1305
Hashing:       BLAKE3 (data), Argon2id (passwords)
TLS:           1.3 minimum, hybrid X25519+ML-KEM
```

## TEST FIXTURES TO CREATE

### `tests/fixtures/hello.tl`
```nx
fn main() {
    print("hello from tallow")
}
```

### `tests/fixtures/legal_valid.tl`
```nx
@legal(basis: .public_data, purpose: "test", retain_for: 7.days)
fn fetch_data(url: URL) -> Result<String> {
    let resp = fetch(url)?
    Ok(resp.text())
}
```

### `tests/fixtures/legal_invalid.tl`
```nx
// Should fail: missing @legal
fn fetch_data(url: URL) -> Result<String> {
    let resp = fetch(url)?
    Ok(resp.text())
}
```

### `tests/fixtures/privacy_valid.tl`
```nx
fn log_user(email: Email) {
    print(email.redact())    // ok
}
```

### `tests/fixtures/privacy_invalid.tl`
```nx
fn log_user(email: Email) {
    print(email)             // should fail: private type logged raw
}
```

## CARGO.TOML STARTING POINT

```toml
[package]
name = "tallow"
version = "0.1.0"
edition = "2021"

[dependencies]
inkwell = { version = "0.4", features = ["llvm17-0"] }
clap    = { version = "4", features = ["derive"] }
anyhow  = "1"
thiserror = "1"
logos   = "0.14"   # lexer generator (optional)

[dev-dependencies]
insta = "1"        # snapshot testing
```

## CLI INTERFACE (src/main.rs)

```
tallow build <file.tl>        → compile to binary
tallow run <file.tl>          → compile + run
tallow check <file.tl>        → type-check only
tallow audit <file.tl>        → generate compliance report
tallow fmt <file.tl>          → format source
```

---
*Start with lexer → parser → type checker. Get `hello.tl` compiling first.*
*Then add `@legal` pass. Then privacy types.*
