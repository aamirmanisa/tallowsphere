# Stub / fake census — 2026-10-16

Read-only census of the published engine tree, on the operator's brief: *"make sure there are no stubs, fakes,
anywhere."* That brief is a **hypothesis under test**, not a target to hit, so what follows is what was
measured — including the parts that contradict a clean bill of health, and the sites this census could not
settle without a probe.

Scope: `/home/aamir/tallowsphere` (the published engine). Excluded: `.git/`, `target/`-style build output,
`docs/**` marker hits (history describing old work), `vendor/`. Method: the three passes from the
`incomplete-implementation-audit` procedure — precise markers → classify against the project's own inventory
(`docs/operations/stub-register.md`) → probe where loud-versus-silent is the question.

## Headline

- **`todo!()` 0 · `unimplemented!()` 0** across `src/`, `crates/`, `stdlib/`, `scripts/`.
- **`TODO` 2 mentions, both disclosures** — `crates/tallow-admission/src/lib.rs:42` (a doc comment *pointing at*
  a TODO list) and `crates/tallow-admission/README.md:95` (its own "TODO (remaining v1 hardening)" section).
  Neither sits on unfinished code.
- **Declared-not-wired: 0 of 142.** Every top-level `native fn` in `stdlib/*.tl` has a quoted occurrence in
  `src/` or `crates/`. No orphan declarations.
- **Every `.tl` body fails loud by construction**: `panic("crypto.tl is dispatch-only; this body must never
  execute")` is the uniform body across `stdlib/crypto.tl`. The `.tl` files are declaration surfaces; the
  implementations live behind dispatch arms. Verified by reading 60 lines of `crypto.tl` and the `simulated`
  comments inside it.
- **The project's own claims ledger is RED — and not for the reason its CI comment implies.** `bash
  scripts/claims_ledger_check.sh` → rc=1: **15 rows / 33 findings, every one `[FAIL R1] missing source file`**
  (`CLAUDE.md`, `.planning/**`, `docs/mega/tallow-2.0-spec.md`, `tallow_1000x_upgrade_prompt.md`). So the
  redness is a **publication-filter artifact** — the ledger cites files this filtered tree excludes — not
  evidence of over-claimed capability. Reported separately below: 40 `WARN R4` entries, which *are* substantive.

## Actionable / unregistered

| # | Site | Snippet | Class | Impact |
|---|---|---|---|---|
| 1 | `src/stdlib/net.rs:237` | `// Simulation: returns typed structs with correct shape.` | **unsettled** | If the structs are fabricated rather than captured, this is the Fake class; if they mirror a real capture recorded above it, it is a documented constructor. **Needs a body read or probe — not inferred here.** |
| 2 | `stdlib/transfer.tl:344,399,424,431,436` — DHT | `// native: simulated DHT announce`; `// ── DHT (simulated Kademlia) ──` | **unsettled** | A DHT surface that does not do DHT. The `.tl` body panics loud, so the question is again the Rust handler. Register has **no DHT row**. |
| 3 | `stdlib/detection.tl:6` — YaraRule | `// ── YaraRule — Simulated YARA-X rule execution ──` | **unsettled** | A detection engine that simulates detection. No register row for YARA. |
| 4 | `stdlib/otel.tl:34` — OtelExporter | `// ── OtelExporter — Simulated OTLP/Prometheus export ──` | **unsettled** | Telemetry that claims export but may not emit. No register row for otel. |
| 5 | `stdlib/iot.tl:58` | `// Note: In the interpreter, lightweight crypto is simulated via BLAKE3` | **unsettled** | Same shape as #6 below (a crypto name standing for a non-standard construction) but narrower. |
| 6 | `stdlib/crypto.tl:566,594` — TPM 2.0 | `// TPM 2.0 Attestation (Phase 43) — simulated via BLAKE3` / `// Simulated TPM quote with PCR values and BLAKE3 signature` | **stale comment (low)** | The comment understates real code — see Verified below. A reader trusts this comment and would report a fake that does not exist. Fix the comment. |
| 7 | `crates/tallow-daemon/src/routes/sync.rs:240` | `// For now: if any device has a different version, count as pending` | **imprecise logic (low)** | A provisional heuristic, honestly labelled in place. Not a stub; worth a tracking comment or a row. |
| 8 | `src/main.rs:16235-16280` | `"contract stub"` / `"contract_stub"` recognised as a module self-description | **registered-by-idiom** | This is a *checker*: the tree has machinery that recognises the contract-stub idiom. Sites using it (`src/stdlib/deals.rs:759,773,1503,1508,1888`) return an explicit `"status": "contract_stub"` field — visible, not silent. |

## Verified — real, disclosed, or correctly non-live

- **TPM attestation is REAL.** `src/stdlib/crypto.rs:6363 crypto_tpm_quote` → `tpm_present()` (6126),
  `tpm2_pcr_read_command` (6200), `tpm2_transact(device, cmd)` (6223), `tpm2_pcr_read` → `Result<Vec<[u8;32]>,
  String>` (6246), `tpm2_pcr_extend` (6291), `tpm2_quote_info_marshal` (6305) documented against **TPM 2.0 spec
  Part 2 §12.4.4**. This is device I/O with error propagation, not a simulation. Item 6 is the comment's fault.
- **`src/stdlib/mesh.rs` is the model treatment** — and the answer to "are there fakes": its module header says
  it is in-memory simulation, and it carries an explicit honesty marker at two sites
  (`("simulated", Value::Bool(true))`, lines 174-175 and 339-340) with the comment *"so callers can never
  mistake simulation"*. A limitation that labels itself is not a fake.
- **`src/stdlib/orders.rs:11,81`** — `Simulate a fill event on an order` is the *name of the API*, documented at
  the module header. A simulator that says it simulates.
- **The register** (`docs/operations/stub-register.md`, 124 table rows, latest #92) is the intentional-gate
  inventory, and it states its own test: an entry is registered when a path deliberately refuses, caps or defers
  work **and the refusal is visible**, never a silent fake success. Its own recent history shows the standard
  being enforced against itself — #90's 9 unwired crypto names are now all implemented and tested against
  published vectors; #91 and #92 were closed with the decorative encryption *removed* rather than documented.
  Only the cheap rows were re-derived here; the rest were read, not re-executed.

## False positives — excluded by name and reason

- `crates/tallow-net/src/transport/ech.rs:46,67,69` — `GREASE ECH … placeholder key`, *"deliberately
  meaningless"*. RFC 9849 §6.1.6 requires a meaningless placeholder; the placeholder **is** the implementation.
- `src/vault/autotype.rs:111-170` — `placeholder` is the *syntax* of the autotype string language, not a stub.
- `#[cfg(test)]` / test-body simulations: `crates/tallow-admission/src/io.rs:311` ("Simulate 60 s of
  dripping"), `src/stdlib/transfer_net.rs:789,5458` (injected QUIC failure to simulate a UDP-blocked network),
  `src/stdlib/escalation.rs:221` (proxy simulation inside a retry ladder).
- `stdlib/crypto.tl` empty-looking bodies — they `panic`, which is the dispatch-only convention, not silence.
- EFF wordlist data in `crates/tallow-crypto` containing "deflected"/"pretended"; `src/codegen.rs
  ::async_stub_source()` (a real threaded runtime despite the name); `#[cfg(not(unix))]` no-ops;
  `docs/**` marker hits (history, not code).

## The substantive claim-hygiene set (from the ledger, not from markers)

The ledger's **40 `WARN R4` entries are unregistered numeric/absolute claims in text** — e.g.
`docs/plans/2026-05-12-tallow-ultrafast-copy-tool.md:29,585 "1000x faster"`, `docs/transfer-reference.html`
`"2.8 GB/s"`, `"3.4 GB/s"`, `"1.8 GB/s"`, `src/browser/traffic_morph.rs` (`1950ms`, `1952ms`, `36s`), and
`docs/TALLOW-330-TOOLS.md:229,621` `Military`. These are **performance and capability numbers asserted in prose
with no registered measurement behind them** — the same defect class as a fake, one layer up: the code may be
real while the *claim* is unbacked. This is where "no fakes" is actually unsettled in this tree, and it is a
citation problem, not a missing implementation.

## Method limitations

- **This is a census, not a fix wave.** Nothing was edited; the work list is the table above.
- Items 1–5 and 7 are **classified by reading, not by execution**. The skill's rule is probe-never-infer for
  loud-versus-silent, and these were not probed on a binary — so they are stated as *unsettled* rather than as
  findings. Probing them means three-line `.tl` programs calling the suspect names and reading `rc` bare.
- The register's 124 rows were **not** re-executed. Cheap rows were re-derived (the `.tl` dispatch-only
  convention, the TPM path, the contract-stub idiom, the mesh honesty markers); the remainder are read.
- Scans are line-oriented, so a fabrication split across lines can hide from the string patterns.
