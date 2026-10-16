# Contributing to Tallow

## Getting Started

```bash
git clone https://github.com/tallow-lang/tallow.git
cd tallow
cargo build
cargo test --lib
```

## Development Requirements

- Rust 1.93+ (2024 edition)
- 8GB+ RAM (large test suite)
- Git

## Running Tests

```bash
# Full test suite (requires large stack)
RUST_MIN_STACK=8388608 cargo test --lib

# Specific module
cargo test --lib -- safety_pass

# With output
cargo test --lib -- test_name --nocapture
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` -- fix all warnings
- Follow existing patterns in the codebase
- Every new feature needs tests
- Every new error code needs documentation

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(phase): description
fix(module): description
docs(section): description
test(module): description
refactor(module): description
```

## Error Codes

Error codes follow the pattern `E{NN}xx` where `NN` is the pass number:
- E01xx: Legal pass
- E02xx: Privacy pass
- E03xx: Agent pass
- E04xx: Browser pass
- ...

See `CLAUDE.md` for the complete error code registry.

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes with tests
4. Run `cargo fmt && cargo clippy && cargo test --lib`
5. Commit with conventional commit message
6. Open a PR against `main`

## Architecture

- `src/lexer.rs` -- Hand-written lexer
- `src/parser.rs` -- Recursive descent + Pratt parser
- `src/ast.rs` -- Full AST definitions
- `src/typeck.rs` -- Type checker
- `src/*_pass.rs` -- Compiler passes (18+)
- `src/interp.rs` -- Tree-walking interpreter
- `src/codegen.rs` -- LLVM IR emitter
- `src/stdlib/` -- Standard library modules
- `src/browser/` -- Browser automation (CDP)
- `src/pkg/` -- Package manager
