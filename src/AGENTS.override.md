# AGENTS.override.md

## Scope

This directory contains the root Tallow compiler, interpreter, codegen, and runtime implementation.

## Compiler Structure

- `src/main.rs` is the pipeline entrypoint for `build`, `check`, `run`, `audit`, and related commands.
- Follow the existing phase order: lex -> parse (`recover` or `fast`) -> import resolution -> typecheck -> policy/safety passes -> codegen or interpreter/runtime execution.
- Keep fixes in the narrowest owning layer. If the bug is a rule in one pass, change that pass before touching shared parser, type checker, or runtime code.
- When behavior exists in both compiled and interpreted execution, keep `src/interp.rs`, `src/codegen.rs`, and `src/runtime/` aligned.

## Verification Loops

- Parser, AST, typecheck, or pass edits: start with the narrowest Rust test by name, usually `cargo test --lib <name> -- --nocapture`.
- CLI or full-pipeline behavior: prefer a targeted integration test such as `cargo test --test browser_codegen_integration <name> -- --nocapture` or another relevant `tests/*.rs` target.
- Codegen or runtime FFI changes: pair a targeted parity/integration test with `cargo check`.
- Widen to `cargo test --lib` only after the focused loop passes or when the change crosses several compiler stages.

## Do Not

- Do not treat `src/` as one monolith; preserve pass boundaries and avoid unrelated churn across many `*_pass.rs` files.
- Do not reorder passes in `src/main.rs` unless the task explicitly requires it and verification covers the downstream impact.
