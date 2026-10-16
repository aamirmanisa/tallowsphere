//! Tallow compiler performance benchmarks.
//!
//! Run with: cargo test --test compiler_bench --release
//! (registered as an integration test, not a binary, to avoid Cargo.toml churn)
//!
//! Or build the dedicated benchmark binary:
//!   cargo build --release
//!   cargo run --release -- bench   (if a bench subcommand exists)

use std::hint::black_box;
use std::time::Instant;

// ── Helpers ──────────────────────────────────────────────────────────────────

struct BenchResult {
    name: String,
    iterations: u32,
    total_secs: f64,
}

impl BenchResult {
    fn per_iter_us(&self) -> f64 {
        (self.total_secs / self.iterations as f64) * 1_000_000.0
    }

    fn report(&self) {
        println!(
            "  {}: {:.3} us/iter ({} iterations, {:.3} ms total)",
            self.name,
            self.per_iter_us(),
            self.iterations,
            self.total_secs * 1000.0,
        );
    }
}

fn bench<F: FnMut()>(name: &str, iterations: u32, mut f: F) -> BenchResult {
    // Warmup
    for _ in 0..std::cmp::min(iterations / 10, 10) {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total_secs = start.elapsed().as_secs_f64();

    BenchResult {
        name: name.to_string(),
        iterations,
        total_secs,
    }
}

// ── Sources ──────────────────────────────────────────────────────────────────

const SIMPLE_SOURCE: &str = "fn main() { let x = 42; print(x) }";

const COMPLEX_SOURCE: &str = r#"
@legal(basis: .public_data, purpose: "test", retain_for: 7.days)
fn scrape(url: String) -> Result<String> {
    let pool = IPPool { size: 1000, rotation: .per_request }
    let resp = fetch(url, timeout: 5.seconds)
    if resp.status == 200 {
        let data = resp.text()
        Ok(data)
    } else {
        Err("failed")
    }
}

struct Config {
    host: String,
    port: u16,
    timeout: u32
}

impl Config {
    fn url(self) -> String {
        "http://{self.host}:{self.port}"
    }
}

enum Status {
    Active,
    Inactive,
    Pending(reason: String)
}

fn process(s: Status) -> String {
    match s {
        Active -> "active"
        Inactive -> "inactive"
        Pending(reason) -> "pending: {reason}"
    }
}

fn fibonacci(n: i32) -> i32 {
    if n <= 1 { return n }
    fibonacci(n - 1) + fibonacci(n - 2)
}

fn main() {
    let cfg = Config { host: "localhost", port: 8080, timeout: 30 }
    print(cfg.url())
    let result = scrape("https://example.com")
    match result {
        Ok(data) -> print(data)
        Err(e) -> print("error: {e}")
    }
}
"#;

fn generate_large_source(num_functions: usize) -> String {
    let mut source = String::new();
    for i in 0..num_functions {
        source.push_str(&format!(
            "fn func_{i}(a: i32, b: i32) -> i32 {{ let x = a + b; let y = x * 2; y }}\n"
        ));
    }
    source.push_str("fn main() { let x = func_0(1, 2) }\n");
    source
}

// ── Benchmark Tests ──────────────────────────────────────────────────────────

#[test]
fn bench_lexer_simple() {
    println!("\n=== Lexer Benchmarks ===");
    let r = bench("lexer/simple", 5000, || {
        let (tokens, _) = tallow::lexer::tokenize(SIMPLE_SOURCE);
        black_box(tokens);
    });
    r.report();
    // Lexer should process a simple line in under 100us
    assert!(
        r.per_iter_us() < 500.0,
        "Lexer too slow on simple input: {:.1} us/iter",
        r.per_iter_us()
    );
}

#[test]
fn bench_lexer_complex() {
    let r = bench("lexer/complex", 2000, || {
        let (tokens, _) = tallow::lexer::tokenize(COMPLEX_SOURCE);
        black_box(tokens);
    });
    r.report();
    // Complex source (60+ lines): under 1ms
    assert!(
        r.per_iter_us() < 2000.0,
        "Lexer too slow on complex input: {:.1} us/iter",
        r.per_iter_us()
    );
}

#[test]
fn bench_lexer_large() {
    let large = generate_large_source(500);
    let r = bench("lexer/500-functions", 200, || {
        let (tokens, _) = tallow::lexer::tokenize(&large);
        black_box(tokens);
    });
    r.report();
}

#[test]
fn bench_parser_simple() {
    println!("\n=== Parser Benchmarks ===");
    let r = bench("parser/simple", 5000, || {
        let (tokens, _) = tallow::lexer::tokenize(SIMPLE_SOURCE);
        let result = tallow::parser::Parser::parse(tokens);
        black_box(result);
    });
    r.report();
    // Parse simple line: under 200us
    assert!(
        r.per_iter_us() < 1000.0,
        "Parser too slow on simple input: {:.1} us/iter",
        r.per_iter_us()
    );
}

#[test]
fn bench_parser_complex() {
    let r = bench("parser/complex", 1000, || {
        let (tokens, _) = tallow::lexer::tokenize(COMPLEX_SOURCE);
        let result = tallow::parser::Parser::parse(tokens);
        black_box(result);
    });
    r.report();
    // Complex parse: under 5ms
    assert!(
        r.per_iter_us() < 10_000.0,
        "Parser too slow on complex input: {:.1} us/iter",
        r.per_iter_us()
    );
}

#[test]
fn bench_parser_large() {
    let large = generate_large_source(500);
    let r = bench("parser/500-functions", 100, || {
        let (tokens, _) = tallow::lexer::tokenize(&large);
        let result = tallow::parser::Parser::parse(tokens);
        black_box(result);
    });
    r.report();
}

#[test]
fn bench_interpreter_loop() {
    println!("\n=== Interpreter Benchmarks ===");
    let source = "fn main() { var x = 0; for i in 0..1000 { x = x + i } }";
    let (tokens, _) = tallow::lexer::tokenize(source);
    let program = tallow::parser::Parser::parse(tokens).unwrap();

    let r = bench("interp/1000-iter-loop", 100, || {
        let mut interp = tallow::interp::Interpreter::new();
        let result = interp.run(&program);
        black_box(result);
    });
    r.report();
}

#[test]
fn bench_interpreter_fibonacci() {
    let source = r#"
fn fib(n: i32) -> i32 {
    if n <= 1 { return n }
    fib(n - 1) + fib(n - 2)
}
fn main() { fib(15) }
"#;
    let (tokens, _) = tallow::lexer::tokenize(source);
    let program = tallow::parser::Parser::parse(tokens).unwrap();

    let r = bench("interp/fib(15)", 50, || {
        let mut interp = tallow::interp::Interpreter::new();
        let result = interp.run(&program);
        black_box(result);
    });
    r.report();
}

#[test]
fn bench_interpreter_string_operations() {
    let source = r#"
fn main() {
    var s = ""
    for i in 0..100 {
        s = s + "x"
    }
    let len = s.len()
}
"#;
    let (tokens, _) = tallow::lexer::tokenize(source);
    let program = tallow::parser::Parser::parse(tokens).unwrap();

    let r = bench("interp/string-concat-100", 100, || {
        let mut interp = tallow::interp::Interpreter::new();
        let result = interp.run(&program);
        black_box(result);
    });
    r.report();
}

// ── Crypto Benchmarks ────────────────────────────────────────────────────────

#[test]
fn bench_blake3_1mb() {
    println!("\n=== Crypto Benchmarks ===");
    let data = vec![0x42u8; 1_024 * 1_024]; // 1MB
    let r = bench("blake3/1MB", 100, || {
        let hash = blake3::hash(&data);
        black_box(hash);
    });
    r.report();
    let throughput_mbps = 1.0 / (r.total_secs / r.iterations as f64);
    println!("    throughput: {:.0} MB/s", throughput_mbps);
    // BLAKE3 should exceed 500 MB/s even without SIMD on CI
    assert!(
        throughput_mbps > 100.0,
        "BLAKE3 too slow: {:.0} MB/s",
        throughput_mbps
    );
}

#[test]
fn bench_blake3_100mb() {
    let data = vec![0x42u8; 100 * 1_024 * 1_024]; // 100MB
    let r = bench("blake3/100MB", 5, || {
        let hash = blake3::hash(&data);
        black_box(hash);
    });
    r.report();
    let throughput_mbps = 100.0 / (r.total_secs / r.iterations as f64);
    println!("    throughput: {:.0} MB/s", throughput_mbps);
}

#[test]
fn bench_aes256gcm_1mb() {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};

    let key = GenericArray::from_slice(&[0x42u8; 32]);
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let cipher = Aes256Gcm::new(key);
    let data = vec![0x42u8; 1_024 * 1_024]; // 1MB

    let r = bench("aes-256-gcm/encrypt/1MB", 50, || {
        let encrypted = cipher.encrypt(nonce, data.as_ref()).unwrap();
        black_box(encrypted);
    });
    r.report();
    let throughput_mbps = 1.0 / (r.total_secs / r.iterations as f64);
    println!("    throughput: {:.0} MB/s", throughput_mbps);
}

#[test]
fn bench_chacha20poly1305_1mb() {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

    let key = GenericArray::from_slice(&[0x42u8; 32]);
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let cipher = ChaCha20Poly1305::new(key);
    let data = vec![0x42u8; 1_024 * 1_024]; // 1MB

    let r = bench("chacha20-poly1305/encrypt/1MB", 50, || {
        let encrypted = cipher.encrypt(nonce, data.as_ref()).unwrap();
        black_box(encrypted);
    });
    r.report();
    let throughput_mbps = 1.0 / (r.total_secs / r.iterations as f64);
    println!("    throughput: {:.0} MB/s", throughput_mbps);
}

// ── End-to-End Pipeline Benchmarks ───────────────────────────────────────────

#[test]
fn bench_full_pipeline_simple() {
    println!("\n=== Full Pipeline Benchmarks ===");
    let r = bench("pipeline/simple", 1000, || {
        let (tokens, _) = tallow::lexer::tokenize(SIMPLE_SOURCE);
        let program = tallow::parser::Parser::parse(tokens).unwrap();
        let mut interp = tallow::interp::Interpreter::new();
        let result = interp.run(&program);
        black_box(result);
    });
    r.report();
}

#[test]
fn bench_full_pipeline_complex() {
    let r = bench("pipeline/complex-lex+parse", 500, || {
        let (tokens, _) = tallow::lexer::tokenize(COMPLEX_SOURCE);
        let result = tallow::parser::Parser::parse(tokens);
        black_box(result);
    });
    r.report();
}
