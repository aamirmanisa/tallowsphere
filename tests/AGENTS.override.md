# AGENTS.override.md

## Scope

This directory holds root Tallow integration, regression, performance, and fixture-backed tests.

## Test Workflow

- Start with the smallest affected target: `cargo test --lib <name> -- --nocapture` for unit coverage or `cargo test --test <file> <name> -- --nocapture` for integration coverage.
- Prefer the test file that matches the subsystem (`pkg_*`, `browser_*`, `stdlib_*`, parser/typecheck-related coverage) instead of broad `cargo test`.
- Use `cargo test --lib` or `cargo check` as the wider smoke test only when the change crosses multiple modules or phases.

## Perf And Regression Caution

- `tests/perf_*.rs`, `tests/compiler_bench.rs`, and `tests/fuzz_safety.rs` are specialized checks, not default smoke tests.
- Run perf suites when touching startup, install, parser/codegen throughput, or benchmarked behavior; note that some paths are slow or `#[ignore]`.
- Run `tests/fuzz_safety.rs` when changing lexer, parser, or interpreter panic surfaces.
- Keep `tests/fixtures/` edits minimal and only when the behavior change requires them.

## Done Means

- At least one targeted Rust test relevant to the change was run, or the reason it was skipped is stated explicitly.
- Diagnostics, pass behavior, and runtime semantics changes have focused coverage for the affected path.
- No unrelated fixture, benchmark, or regression-test churn was introduced.
