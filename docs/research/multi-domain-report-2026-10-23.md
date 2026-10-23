# Multi-domain intelligence and technology report

Date: 2026-10-23. Prepared for the Tallow platform (engine `9cd968d`, v1.4.0; spec
`9a7fd3d`). Eleven domains, each researched, executed against available evidence, and
cross-checked against a second source where one existed. Claims carry a source tag —
**[P]** primary/official, **[V]** vendor engineering, **[R]** reporting, **[B]**
independent research/field investigation, **[C]** analysis/opinion. Anything that could
not be verified is labelled *unverified* rather than smoothed over.

---

## 1. Top intelligence agencies

Structure is public; activity is mostly inferred from official statements, indictments and
reporting.

**United States.** The CIA is one of 18 IC elements under the DNI, organised into five
directorates plus mission centres [P: cia.gov/about/organization]. The 2025 Annual Threat
Assessment names China "the most comprehensive and robust military threat" and describes
Russian espionage, cyber and gray-zone activity [P: ODNI ATA-2025]. In mid-2026 the agency
reorganised, replacing the Digital Innovation Directorate with a Mission Systems
Directorate and standing up a Cyber Mission Center [C: NYT, 2026-07-01].

**United Kingdom.** SIS operates under the Intelligence Services Act 1994, accountable to
the Foreign Secretary [P: sis.gov.uk]. Blaise Metreweli became Chief in 2025 and the
government added £600m to the intelligence community [P: gov.uk]. The outgoing Chief's
September 2025 speech ranked Russia, China and Iran as the principal threats and argued
for partnership over deeper secrecy [P: gov.uk speech].

**Israel.** Mossad's stated remit is clandestine collection, counter-threat work and
special operations [P: mossad.gov.il]. Its role in Operation Rising Lion (June 2025) rests
on Israeli official claims amplified by reporting, not independent verification [C: ABC].

**Russia.** SVR is the civilian foreign service (including SolarWinds); GRU is military
intelligence with spetsnaz and proxy forces; the two overlap and compete, and observers
assess reporting is sometimes shaped toward leadership preference [P/B: CRS IF12865]. The
EU sanctioned three GRU Unit 29155 officers in January 2025 [P: Council of the EU].

**China.** MSS is the civilian service whose public profile rose under Xi [C]. The May
2025 white paper sets a "holistic" doctrine centred on political security [P: SCIO]. The
March 2025 US indictment of 12 contract hackers alleges MSS/MPS use of private firms such
as i-Soon to obscure state involvement — court allegations, untested [P: DOJ].

**Structural lesson.** Every service separates collection, analysis and dissemination, and
the defensible ones bind the *product*: ICD 203's five analytic standards and ICD 206's
source descriptors are the mechanism. Provenance as a gate, not a formatting habit.

## 2. Hidden mercenaries / private military companies

Rebranding preserves capability while diluting legal identity.

**Mali.** Wagner announced withdrawal in June 2025; the GRU-overseen Africa Corps stayed
at roughly similar strength with many former Wagner personnel [R: Reuters; B: CRS
IF12389]. HRW documented Africa Corps-led forces summarily killing nine civilians,
including four children, in Bombori in July 2026 [B: HRW 2026-08-20], and airstrikes
killing civilians [B: HRW 2026-07-31].

**Sahel.** Africa Corps expanded into Burkina Faso, Niger and Equatorial Guinea, mixing
state, ex-Wagner and other PMC personnel, with reported basing ambitions in Sudan and
Libya [B: CNS Occasional Paper 67, Sep 2025].

**Sudan.** The US ambassador to the UN accused Russia of funding both sides in January
2025; Washington did not elaborate, so it remains an official allegation [C: Reuters].

**Gaza.** A former UG Solutions contractor told PBS he witnessed live ammunition fired
near aid-seekers at GHF sites — a first-person allegation corroborated in outline by other
contractors [C: PBS].

**Surveillance contractors.** Sandvine was Entity-Listed in February 2024 for
deep-packet inspection used in mass censorship, then removed in October 2024 after
governance reform and sales restrictions [P: State/BIS].

**Pattern.** Contractor chains disperse responsibility (MSS → i-Soon; GHF → UG Solutions),
and scrutiny arrives through courts, sanctions panels or NGOs rather than the contracting
state. The governance answer is a named authority chain, not a vendor name.

## 3. Top countries — posture as a four-dimensional perimeter

Assessed on where data is processed, who the customer is, what the model does, and who can
compel disclosure.

- **United States** pairs CHIPS subsidies with export controls that have reached NSO
  Group; a 2026 executive order sets PQC deadlines for federal systems [P: White House,
  2026-06-22].
- **China** asserts extraterritorial reach through the Data Security Law and has built a
  domestic model stack under export pressure [P].
- **EU** regulates by function: AI Act prohibitions bite on manipulation, social scoring
  and untargeted facial-recognition scraping, not on technology category [P].
- **India** restricts transfers by notification under the DPDP Rules (notified 2025-11-14)
  rather than banning them [P].
- **Russia** uses energy and information leverage; sanctions have pushed its tech stack
  toward parallel import and domestic substitution [C].

Military spending context: world total reached **$2.718 trillion in 2024**, with the US at
**$997 billion** (SIPRI, April 2025 release) [P]. These are the only figures quoted here;
national capability rankings beyond them are judgements, not measurements.

## 4. OSINT, blackhat and DEF CON communities

**Evidence handling.** RFC 3227 orders acquisition by volatility and requires hashing at
capture; the Berkeley Protocol is the public-source equivalent — collection, preservation,
verification, metadata alongside content, audit trail, minimisation [P: OHCHR].

**Provenance is machine-readable.** STIX 2.1 carries `confidence`, `created_by_ref`,
`object_marking_refs`, `external_references` [P: OASIS]. "Source: Twitter" is provenance
theatre.

**Reproducibility is a detection property.** The Pyramid of Pain ranks indicators by
adversary cost; MITRE CTID's Summiting the Pyramid converts that into graded, re-runnable
analytics [B: CTID].

**Frameworks are vocabularies, not proofs.** CSF 2.0 is a management taxonomy, ATT&CK a
technique vocabulary, D3FEND a countermeasure vocabulary that explicitly "does not
characterize effectiveness" [P: MITRE]. Only ASVS is testable against the platform itself
[P: OWASP].

**Ten failure modes, each now a rule:** over-collection → per-task field allowlist;
base-rate blindness → publish posteriors, not match counts; credential leakage → per-call
short-lived tokens; prompt/tool injection → collected content is typed as data and can
never originate a tool call; unbounded write autonomy → dry-run default and two-key for
irreversible actions; confident fabrication → no claim without artifact hash and timestamp;
cross-desk privilege accumulation → deny-by-default capability ceiling; tool supply-chain
trust → pinned, hashed, human-reviewed manifests; unbounded retry → per-target egress
budget with stop-on-403/429; non-reproducible verdicts → store model, prompt and tool
versions plus input hashes and make replay a CI job.

## 5. Competitors

Twelve, across three segments; prices are published list prices, excluding tax and
committed-use discounts.

**Orchestration.** *Temporal* — durable execution by event-history replay, **$50/M
actions** ($25/M at volume) [P: temporal.io/pricing]; determinism is a discipline imposed
on the author, and the platform models no evidence or credentials. *LangGraph/LangSmith* —
checkpointed graphs, **$39/seat/month** plus LSU metering; its own docs state replay
"re-executes nodes … LLM calls, API requests and interrupts fire again and may return
different results" [P: docs.langchain.com]. *n8n* — node automation at **€20–€667/mo**,
execution-metered, credentials in a vault. *CrewAI* — crews plus Studio, free to 50
executions/month, governance an enterprise add-on. *Bedrock AgentCore* — microVM runtime
with Cedar policy, per-second metering (**$0.0895/vCPU-hr**), AWS-resident.

**Threat intelligence.** *Recorded Future* (Mastercard) — Intelligence Graph over "over a
million sources", quote-only, closed derivation. *Maltego* — transforms plus link analysis,
**€3,000–€7,500/yr**. *Silent Push* — IOFA infrastructure data, free tier at 100
requests/month. *MISP* — open sharing with galaxies and STIX export, stores but does not
compute.

**Policy/runtime.** *OPA/Rego* — CNCF policy decoupling; `time.now_ns` is documented
"SDK-dependent", so identical inputs can decide differently across hosts. *Cedar* —
analysable authorization, allow/deny only, now behind AgentCore. *Wasmtime* — hardened
sandbox with no policy, provenance or orchestration semantics.

**Where the opening is.** Everyone sells execution or data; nobody sells *replayability as
an evaluator property* plus provenance-first evidence plus local model routing plus
credentials that never enter the program text. **Where not to compete:** a threat-intel
corpus (capital problem), a 99.99% cloud durability SLA (ops business), a no-code canvas
(integration-count competition), SIEM/SOAR/case management (certification business), or
OPA/Cedar in admission control (distribution decides it — consume their decisions
instead).

## 6. Cryptography and quantum

**PQC is a scheduling problem.** FIPS 203/204/205 are final: ML-KEM-768 has a 1,184-byte
encapsulation key and 1,088-byte ciphertext; ML-DSA-65 a 1,952-byte key and 3,309-byte
signature [P: NIST]. NIST IR 8547 deprecates 112-bit classical signatures after 2030 and
disallows them after 2035 [P]. X25519MLKEM768 is now a Standards-Track TLS 1.3 group (RFC
10024, Aug 2026) [P] and default in current browsers [P/V].

**Harvest-now-decrypt-later is a retention problem.** The exposure window is retention +
legal hold + backup generations + derived copies, not "time to Q-day". A seven-year audit
log under ECDH is already lost if Q-day lands inside those seven years — retention
schedules are cryptographic controls.

**Migration order, cheapest first:** inventory (CBOM with data lifetime) → symmetric layer
(AES-256/SHA-384 are adequate) → edge TLS hybrid → KMS key wrapping → signature migration
→ archive re-encryption → retire classical.

**Churn is real.** HAWK was withdrawn from standardisation in 2026 after an AI-assisted
cryptanalysis result [P: NIST] — a reminder that agility, not commitment to one
construction, is the durable property.

## 7. Security — architectures, threat landscape, defences

**Identity is the control plane.** Short-lived workload identity beats long-lived API
keys; NIST SP 800-207 treats the network as hostile by default [P].

**Supply chain is the attack surface that keeps winning.** SLSA provenance, pinned and
hashed dependencies, and SBOMs at release time are table stakes; `cargo deny` in CI is the
minimum, not the ceiling [P: slsa.dev].

**Injection moved up the stack.** Prompt injection is not solvable by filtering text; it
is solved by making collected content a *typed data* value that cannot originate a tool
call without a policy grant the content cannot supply [B: OWASP LLM Top 10].

**Detection must be re-runnable.** An analytic that cannot be replayed against recorded
telemetry is a story. Grade analytics, store the inputs, and treat a changed verdict on
unchanged inputs as a defect [B: MITRE CTID].

**Autonomy needs doctrine.** DoD Directive 3000.09 distinguishes autonomous engagement from
human-supervised systems with a halt capability; the software analogue is autonomy bounded
by verb — read automatic, write confirmed, destructive/publishing two-key — plus budget
ceilings and expiry on every delegation [P].

## 8. Privacy and piracy

**Privacy techniques have measured limits.** Privacy Pass gives unlinkability for tokens,
not traffic. Tor hides the client from the destination; it does not hide that a client
exists, and traffic correlation against a global adversary is documented (DeepCorr ~96% at
~900 packets; "Users Get Routed" ~80% over six months) [B]. Metadata survives content
encryption.

*Consequence:* claims are measured planes — "the target sees a Tor exit" — never
"undetected". Exits rotate, so a pinned exit is never current.

**DRM is not a boundary.** Widevine L3 recovery (WOOT 2022) demonstrates the class of
break [B]. The practical posture for an organisation's *own* artifacts: signed
entitlements, Build-ID plus SLSA provenance, collusion-resistant watermarking
(Boneh–Shaw bounds), and takedown evidence meeting DMCA §512(c)(3) / DSA Art. 16
elements [P]. Out of scope by design: removing protections from anyone else's work.

**Piracy networks are distribution systems.** They optimise resilience of delivery
(mirrors, caches, re-encoding pipelines), which is why enforcement against individual
endpoints has poor returns; entitlement and provenance attack the economics instead.

## 9. Different technologies

Eight areas with shipped evidence in the last 12–18 months.

- **AI inference.** KV cache became tiered and shareable across nodes (vLLM, 2026-09-10);
  speculative decoding became scheduler-driven (SGLang/DSpark, 2026-07-06); Dynamo 1.0 GA
  disaggregates prefill/decode [V]. Consequence: capacity planning moves from GPU count to
  cache-tier bandwidth — but shared KV tiers are a tenant-isolation problem with no
  documented encryption, so self-hosting means single-tenant cache or weight-only
  quantisation.
- **Post-quantum.** Deadlines hardened (see §6); key establishment is a library upgrade,
  signatures a format migration.
- **Confidential computing.** Intel TDX on Xeon 6 and composite CPU+GPU attestation
  (Intel Trust Authority with H100/B200, 2026-06-16) make attested inference deployable;
  entitlement licensing is the real blocker [V].
- **WebAssembly/WASI.** WASI 0.3.0 (2026-06-11) moves async into the Component Model —
  `async func`, `stream<T>`, `future<T>` as canonical ABI primitives; Wasmtime 46+ enables
  it; every 0.2 interface changed shape [P: wasi.dev].
- **Edge runtimes.** Cloudflare Containers and Sandboxes GA (2026-04-13) with active-CPU
  pricing; edge is now a credible host for untrusted agent tools [V].
- **eBPF.** Linux 7.3 (2026-10-18) completes sched_ext; cilium/ebpf v0.22.0 adds BPF-token
  delegation, removing the run-as-root tax [S/V].
- **RISC-V.** Server Platform Specification 1.0 ratified 2026-05-06 (RVA23 + UEFI/ACPI/RAS);
  Ubuntu 26.04 LTS supports RVA23 [P/V]. No hyperscaler instance type yet.
- **Data sovereignty.** AWS European Sovereign Cloud GA in Brandenburg (2026-01-15); a
  Commission package proposes an EU-wide sovereignty assessment framework (2026-06-03)
  [P/V].

**Ignore for now:** WASI 1.0/component-first architecture (churn), RISC-V server migration
(no procurement path), FP4 KV-cache quantisation (hardware-gated), PQC signatures
everywhere (key establishment first), GPU TEEs outside regulated workloads, custom
sched_ext schedulers.

## 10. Programming languages

Compared on the axes that matter for a policy-heavy agent platform: memory safety,
concurrency model, supply chain, and reviewability of policy.

- **Rust** — memory safety without a GC; Android reports memory-safety vulnerabilities
  falling from 76% to 24% of the total after adoption [V: Google]; predictable
  concurrency; mature supply-chain tooling (`cargo deny`, SBOM). Cost: compile times,
  steep onboarding.
- **Go** — simplest operations and deployment; GC pauses are a non-issue at this scale;
  weaker type-level guarantees for taint/privacy.
- **Python / TypeScript** — ecosystem reach; safety pushed into process boundaries;
  TypeScript's type layer is erased at runtime, so it cannot carry a policy proof.
- **Java/Kotlin** — strongest incremental-concurrency story after JEP 444 (virtual
  threads); JVM footprint.
- **C/C++** — largest memory-safety debt; unsuitable as the policy boundary.
- **Zig** — explicitness and comptime; ecosystem too thin for production.

**Decision.** Rust for the engine; policy expressed as data with a documented, analysable
evaluation model — the Cedar/Starlark lesson is that policy must be non-Turing-complete or
review is impossible. Tallow's annotations count as policy only where lowered to
compile-time effects; an annotation merely attached is documentation.

## 11. Tallow language — technical analysis

Measured from the repository, not from documentation: **36 keywords, 51 operator tokens,
176 error codes, 87 stdlib modules, 1,130 function declarations** (`spec/generated.json` at
`9cd968d`). `tallow check` passes **87/87** modules; the conformance corpus runs **21 cases
with 0 failures** against the released v1.4.0 binary; the lib suite is **9,212 passed / 0
failed / 33 ignored**.

**Syntax and semantics.** The keyword set is small — `let var const struct enum impl trait
match if else for while in return import async await type self mut as bail bail_if break
continue catch loop defer private secret`. `bail`/`bail_if` make refusal a first-class
statement; `defer` gives deterministic cleanup; `private` and `secret` are type-level
privacy qualifiers, so taint is part of the type rather than a convention. A bound variable
shadows a module name (§4.13, added after a lowercase module sentinel silently rewrote
`let llm = h.llm_calls`).

**Policy as annotations.** `@legal` and `@agent_task` (314 uses each in stdlib sources)
gate compilation: a function touching personal data without a declared basis fails the
build, and an agent task declares request budget and write scope. This is the structural
difference from "prompt + tools" frameworks — the policy is checked before execution.

**Execution model.** Two engines — a tree-walking interpreter and a native C backend — that
must agree. Measured gap: 16 of 41 `page_*` browser helpers have native arms;
`Mesh.plan`/`Mesh.replay` and the four `llm` functions are interpreter-only and print
"native build unavailable … running in the interpreter" rather than faking parity. The
refusal is why the gap is knowable.

**Determinism.** Mesh seeds derive from content (`BLAKE3(mesh_seed ‖ wave ‖ id ‖
attempt)`); checkpoints hash id-sorted results; the same plan yields identical checkpoints
at 1, 4 and 8 workers, and again across TCP in `tests/mesh_remote.rs`. `pure` tasks keep
attempt-independent seeds so a partitioned run commits the same checkpoint as an
uninterrupted one.

**Model access.** `llm.providers/models/complete/verify` cover 20 providers over five wire
protocols, models discovered from each provider's own `/models`; credentials resolve from
`key_env`/`key_file` at call time and an inline key in config is refused by name. Four
providers are declared unavailable with the reason and the working route.

**Applications.** Best fit: policy-bound automation (compliance checks, evidence handling,
release gating), deterministic batch execution where replay must be provable, and agent
systems whose audit trail must survive inspection. Weakest fit today: latency-critical
native paths and topology-level federation — the mesh topology plane is simulated and
`Mesh.run` is not yet published.

**Limits.** Ownership instead of GC means long-lived agent loops need explicit lifetimes;
the native backend lags the interpreter; there is no package registry comparable to
crates.io — distribution is the binary plus `stdlib/`.

---

## Consolidated summary

**Three cross-domain synergies worth building on.**

1. **Provenance is the same primitive in every domain.** ICD 206 source descriptors, the
   Berkeley Protocol, STIX `external_references`, SLSA provenance and the directorate's
   evidence record are five names for one structure: artifact + hash + timestamp + grade.
   Implementing it once in the engine serves intelligence analysis, supply-chain
   attestation and AI-output auditing simultaneously.
2. **Determinism is the competitive wedge.** Competitors sell execution (Temporal) or data
   (Recorded Future); none sells replay as an evaluator property. The mesh already proves
   identical checkpoints across worker counts and across a socket — a claim competitors
   cannot make without rebuilding their runtime.
3. **Local-first model routing is a compliance feature, not a cost feature.** With
   attested inference (TDX + GPU attestation) deployable and sovereignty frameworks
   formalising "who can compel disclosure", routing private-class content to a local model
   and public-class content to a vendor becomes the defensible default.

**Five critical risks.**

1. **Simulation debt.** The topology plane is simulated and `Mesh.run` is unpublished;
   every public claim about "mesh" must stay scoped to planning, journaling and the
   execution wire until R5/R6 land.
2. **Native/interpreter divergence.** 25 interpreter-only helpers plus `Mesh`/`llm` mean
   program behaviour depends on the build flag. Parity tests per function are the only
   defence.
3. **Spec drift.** The spec has no CI; a stale `generated.json` is currently undetectable.
   Cheapest risk to close (R1), and the one that most damages credibility if a reader
   finds it first.
4. **Credential handling at scale.** The language refuses inline keys, but operator key
   files, shell history and CI secrets remain outside the type system. Key-file permission
   checks at load plus a documented rotation path are required before multi-user use.
5. **Attribution and authorisation without an audit trail.** §1–2 show the failure mode:
   rebranded capability, dispersed responsibility, scrutiny arriving years later. A
   private platform must ship the signed scope manifest and ombuds channel *before* it
   ships collection features, not after.

**Next, in order:** R1 (spec CI) → R6 (`Mesh.run`) → R9 (journalled `llm` tasks) → R5
(real topology) → R13 (scope manifest, egress ledger, jurisdiction check, ombuds). The
first three convert proven components into a reproducible pipeline; the last two convert a
capable system into a defensible one.
