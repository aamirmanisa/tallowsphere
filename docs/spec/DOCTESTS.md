# Doctests

Status: **normative for Tallow 2.0**. Backlog row G14.

## Why

A doc comment that shows code is a claim. `docs_examples.py` (G59) already executes
the claims in `docs/`, but the examples a user actually reads are the ones beside the
function in `.tl` source. Those rot first, because nothing runs them.

## Form

A doctest is a fenced block inside a `///` doc comment on an item:

```tallow skip:illustrative; this document defines the form
/// Doubles a value.
///
/// ```tallow run
/// print(double(2))
/// ```
pub fn double(x: Int) -> Int { x * 2 }
```

The fence grammar is **exactly** the one `scripts/docs_examples.py` enforces, so
there is one vocabulary in the repository, not two:

| Marker | Meaning |
|---|---|
| `run` | compile and execute; must exit 0 |
| `run:fail:E0153` | must exit non-zero *and* print every listed code |
| `skip:<reason>` | not executed; the reason is required |
| *(none)* | error — silence is how an example rots |

A `tallow` or `tl` fence inside a `///` comment with no marker is a **doctest
failure**, reported with file and line, the same rule the docs gate uses.

## Execution

`tallow test --doc <path>`:

1. Reads every `.tl` file under `path` (file, directory, or `tests/` by default).
2. Extracts `///` fenced blocks, recording `file:line` for each.
3. Writes each `run` / `run:fail:` block to a temporary file and executes it twice:
   `--interpret` and `--require-native`. **Both must agree** — same exit status,
   same stdout — or the doctest fails and the divergence is printed.
   This is the same two-plane rule the conformance corpus uses; a doctest that
   passes on one plane lies about the other.
4. Prints one line per doctest and a summary; exit status is non-zero if any failed.

A block that cannot compile natively (module with no lowering) reports the refusal
text and fails, rather than silently falling back to the interpreter. No `ignore`
marker exists: an example that cannot be run does not belong in a fence.

## Isolation

Each block runs standalone: no imports from the enclosing file, no access to the
item under test. A doctest that needs a helper declares it inside the block.

This is a deliberate limitation. It keeps the escape hatch (importing the module
under test) out of reach until there is a namespace to import *into* — which is
what G09's visibility work just made thinkable, not what it delivered.

## Gates

- `tests/doctest.rs`: a passing block, a failing block (`run:fail:`), an unmarked
  block, a `skip:` block, and a block whose two planes disagree (must fail).
- `--lib parser` unchanged; no parser change is expected.
- `scripts/docs_examples.py` keeps enforcing the same grammar over `docs/`.
