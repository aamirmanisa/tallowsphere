# The Tallow Directorate: five desks, one execution plane

Status: architecture. Date: 2026-10-23. Engine: v1.3.0 (`9ef844f`).

This document defines a five-agent intelligence organization whose coordination is
executed by Tallow's own mesh plane, and whose tools are Tallow standard-library
modules that already ship. It is written against the engine as it exists, not
against an imagined one: every module named below is present in `stdlib/`, every
coordination primitive is real code, and the places where "agent" means "an LLM
call" are named as such rather than quietly simulated.

---

## 1. What "integrated" can honestly mean

Three things are commonly conflated. Keeping them apart is the difference between
an architecture and a slide.

| Layer | What it is | Status in Tallow |
| --- | --- | --- |
| **Coordination** | task graph, waves, leases, retries, deterministic checkpoints, replay | **Real.** `src/mesh/*`, `@mesh`, `Mesh.plan`, `Mesh.replay`, `tallow mesh worker` (v1.3.0) |
| **Tools** | HTTP, browser, crypto, files, DNS, extraction, storage, egress control | **Real.** 86 stdlib modules, each with a Rust implementation |
| **Cognition** | deciding *what* to do next in an open-ended situation | **Not in the engine.** An LLM provider supplies it; Tallow supplies the contract, the tools and the audit trail |

So "100% native integration, no simulation" is achievable for coordination and
tools — and it is *not* achievable for cognition without a model endpoint, because
no engine contains one. An agent here is therefore: **a Tallow function annotated
with `@agent_task`, whose tools are stdlib calls, whose steps are mesh tasks, and
whose every decision is journalled.** The model, when attached, is a tool like any
other — and its outputs are recorded, so a run can be replayed without it.

That is the honest definition, and everything below is built on it.

---

## 2. The organization

Five desks, a directorate, and no shared mutable state: desks hand off through the
journal, exactly as mesh waves do.

```
                    ┌─────────────────────────────┐
                    │  DIRECTORATE (operator)     │
                    │  approves: egress, releases │
                    └──────────────┬──────────────┘
        ┌───────────────┬──────────┼───────────┬───────────────┐
     SENTINEL        ORACLE      GHOST    CARTOGRAPHER   QUARTERMASTER
   security &      crypto &    privacy &   markets,       technology &
   threat intel    quantum     egress      competitors,   integration
                                          languages
```

Why five and not three or nine: each desk owns a *distinct evidence type* (threat
observables, cryptographic guarantees, network identity, market and language
facts, infrastructure state). Two desks sharing an evidence type would produce
duplicate work; six would force a committee per decision. Five is the smallest
count where every domain in the brief has an owner and no two owners collide.

### 2.1 SENTINEL — Security & Threat Intelligence

**Charter.** Know what is trying to get in, and what it would do if it did.

**Borrowed from:** national intelligence agencies (collection → analysis →
dissemination separation; the analyst does not collect their own tasking
evidence), DEF CON / Black Hat practice (adversary emulation, not compliance
theatre), and OSINT tradecraft (provenance before assertion).

**Real tools.** `detection` (playbooks, IOC scanners, alert triage/escalation),
`forensics` (artifact handling), `provenance` (source grading), `osint`,
`sitescan`, `captcha`/`turnstile` (recognising hostile surfaces), `rate_limit`
(politeness as a control), `log`/`otel` (evidence emission).

**Mesh shape.** Wave 1 collection (parallel, independent, `pure` where parsing,
`io` with idempotency keys where fetching); wave 2 correlation; wave 3 triage;
wave 4 escalation — a desk cannot escalate a finding it has not correlated.

**Refusals.** No exploitation, no credential attacks, no target the operator does
not own. `@legal` is mandatory on every collection function, and the egress plane
refuses non-allowlisted hosts before the request is made.

### 2.2 ORACLE — Cryptography & Quantum

**Charter.** Say what is actually secret, for how long, and what breaks first.

**Borrowed from:** standards bodies (NIST PQC migration order), national posture
analysis (who is harvesting now to decrypt later), and the language's own
zero-trust surface.

**Real tools.** `crypto` (hashing, AEAD, signatures), `tls_profile` (cipher and
version posture), `jwt`, `secrets`, `random` (`rand`), `provenance` (supply-chain
attestation), `signing` (Ed25519 package signatures), SBOM/CBOM gates in CI.

**Mesh shape.** Inventory → classify (harvest-now-decrypt-later exposure) →
recommend → verify migration. Each wave's output is a hash, so an audit can prove
the recommendation came from the inventory it cites.

**Refusals.** No key generation for third parties, no "military-grade" claims —
only named primitives with named parameters, and a measured bit-security figure.

### 2.3 GHOST — Privacy, Identity & Counter-Piracy

**Charter.** Keep the operator's footprint measured and stated, and defend the
artifacts the organization ships.

**Borrowed from:** privacy engineering (data minimisation, unlinkability),
anonymity-network operations (Tor circuits, exit rotation), and anti-piracy
practice (watermarking, licence enforcement, takedown evidence) — used
defensively, against theft of the organization's own output.

**Real tools.** `browser` over Tor (via the sandbox plane), `tls_profile`
(fingerprint coherence), `fingerprint`, `secrets`, `safety`, `legal`
(`@legal` basis/purpose/personal-data gates), `provenance` (watermark and origin).

**Mesh shape.** Classify data → choose plane (direct / sandbox / Tor) → execute →
prove the plane (the target sees a Tor exit, never the box IP) → record the proof.

**Refusals.** No claim of "undetected" or "untraceable" — only measured planes.
No deanonymisation of third parties. High-blast-radius egress changes wait for
operator approval.

### 2.4 CARTOGRAPHER — Markets, Competitors & Languages

**Charter.** Map the terrain: who else is building this, in what language, with
what advantage — including Tallow itself.

**Borrowed from:** competitive intelligence (public-source only, no deception of
third parties), programming-language comparison (semantics, memory model,
concurrency, toolchain, ecosystem), and the Tallow language's own specification.

**Real tools.** `http`, `browser`, `extract`, `html`, `json`, `csv`, `markdown`,
`finance`/`market`/`ohlcv` (where the competitor is public), `graphql`, `entity`
(record linkage), `sentiment`, and `tallow check` / the spec generator
(`Tallow-Language/spec/generated.json`) for language facts.

**Mesh shape.** Enumerate → fetch (rate-limited, robots-respecting) → extract →
compare on named axes → grade evidence → publish a briefing.

**Refusals.** No acquisition of non-public competitor material, no scraping behind
authentication without authorization, no claim about a competitor that a cited
public source does not support.

### 2.5 QUARTERMASTER — Technology, Infrastructure & Integration

**Charter.** Keep the machine that does all of the above actually working, and own
the integration backlog.

**Borrowed from:** national technology-posture analysis (what supply chains and
platforms a country depends on), SRE practice (SLOs, capacity, failure budgets),
and language-runtime engineering (what the engine can and cannot lower natively).

**Real tools.** `process`, `fs`, `net`, `db`, `config`, `env`, `otel`, `jobs`,
`mesh` (this desk runs the fleet), `pkg`/release tooling, CI gates
(`check_test_coverage`, SBOM drift, panic policy, release body).

**Mesh shape.** Observe → diagnose → plan → execute → verify, with the rule that
**a verification task may not cite an artifact older than the change it verifies**.

**Refusals.** No "looks healthy" without a live process check; a redirected log
that stays empty is reported as buffered-or-blocked, never as progress.

---

## 3. Where the eleven research domains land

| Domain | Owner | Concrete expression |
| --- | --- | --- |
| Top intelligence agencies | SENTINEL | collection/analysis/dissemination separation; analyst ≠ collector |
| Hidden mercenaries / covert tactics | SENTINEL + GHOST | autonomous task behaviour under lease fencing; deniability is a *stated* property, never a claim of untraceability |
| Top countries | QUARTERMASTER + ORACLE | supply-chain dependency map; PQC migration order by national posture |
| Security communities (OSINT/Black Hat/DEF CON) | SENTINEL | adversary emulation, IOC pipelines, provenance grading |
| Competitors | CARTOGRAPHER | public-source competitive brief with cited evidence |
| Cryptography & quantum | ORACLE | PQC inventory, harvest-now-decrypt-later exposure, AEAD/signature posture |
| Privacy & piracy | GHOST | data minimisation, Tor plane, watermark/takedown evidence |
| General security | SENTINEL | threat model per desk, least privilege, signed artifacts |
| Technologies | QUARTERMASTER | stack inventory, capacity, failure budgets |
| Programming languages | CARTOGRAPHER | comparison on named axes; Tallow facts from the spec generator |
| Tallow language | CARTOGRAPHER + QUARTERMASTER | `stdlib/` and `spec/generated.json` are the source of truth, not memory |

---

## 4. Integration plan (each step has a gate)

**Phase D0 — Desks as task graphs (no model required).**
Each desk's workflow is expressed as `MeshTask` values with real dependencies and
classes. Gate: `Mesh.plan` returns the expected wave layout, and re-running it
produces an identical layout.

**Phase D1 — Tools bound per desk.**
Every desk function is annotated `@agent_task(...)` and calls only real stdlib
modules. Gate: `tallow check` on the desk program; `@legal` present on every
collection function; a desk calling a module outside its charter fails review.

**Phase D2 — Execution and journaling.**
Desks run through the coordinator (in-process, or `tallow mesh worker` across
hosts). Gate: identical checkpoint hashes at 1, 4 and 8 workers; one commit per
task; a frozen worker's late answer discarded.

**Phase D3 — Model attachment (cognition).**
A model is attached as a tool: its prompt and response are recorded in the journal
as an `llm`-class task, never retried silently. Gate: replay with the model
detached reproduces the run from recorded responses.

**Phase D4 — Directorate.**
A directorate function plans across desks: SENTINEL and CARTOGRAPHER first (they
produce evidence), ORACLE and GHOST second (they judge exposure), QUARTERMASTER
last (it acts on the machine). Gate: a full directorate plan is one graph, and its
journal shows the handoffs.

---

## 5. What is deliberately not built

- **No deception of third parties.** Covert tradecraft is studied for defensive
  design (compartmentation, least privilege, evidence handling), not to run
  operations against people who did not ask for them.
- **No deanonymisation.** GHOST measures the organization's own plane; it does not
  attempt to unmask others.
- **No piracy facilitation.** The counter-piracy desk protects the organization's
  own artifacts; it does not remove protections from anyone else's.
- **No "autonomous" claim.** Autonomy is bounded by leases, attempt caps, and the
  operator's approval gate for egress and release.

## 6. Acceptance

An agent is "operational" when a run of its task graph produces a journal whose
checkpoints recompute, whose evidence cites sources that exist, and whose refusals
fire when tested. Anything less is a diagram.
