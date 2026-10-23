# Directorate research: what the eleven domains actually changed

Date: 2026-10-23. Feeds `docs/architecture/tallow-directorate-2026-10-23.md`.

Three sourced briefs were commissioned before the desks were fixed. This document
records their findings, the design decisions each one forced, and — separately —
what was *not* adopted and why. Sources are listed per brief; quality is marked at
the claim where it matters.

Method note: the language facts below were extracted from the repository
(`Tallow-Language/spec/generated.json`, `spec/01-lexical.md`), not from memory:
**36 keywords, 51 operator tokens, 176 error codes, 86 stdlib modules, 1,126
function declarations**, generated against engine `fb5bab5`.

---

## 1. Intelligence structures, covert practice, state posture

**Collection, analysis and dissemination are separate roles, not separate people.**
The US IC runs a six-step cycle and splits analysis from clandestine collection in
different directorates, but under one Director — so the binding constraint is the
*product*, not the org chart: ICD 203 fixes five analytic standards and mandates
training and review; ICD 206 requires every disseminated product to carry source
descriptors sufficient for a reader to judge and retrieve the underlying
reporting. The UK separates assessment (JIC) from collection (statutory agencies);
France interposes an ex-ante reviewer (CNCTR) between authorisation and
collection; Germany's Constitutional Court struck down BND foreign surveillance
for lacking specific purposes and comprehensive independent oversight.

*Design consequence (adopted).* Provenance is a **gate**, not a formatting
convention: SENTINEL/CARTOGRAPHER emit evidence records with URL, retrieval
timestamp, content hash and a two-axis Admiralty grade (source reliability A–F,
information credibility 1–6); the renderer refuses a claim missing any of them.
Collapsing the two axes into one "confidence" score is the most common OSINT
analytic error and is now a review failure.

**Authorisation precedes execution, and names participants.** Covert action
requires a written finding reported to Congress *before* the action, enumerating
every entity authorised to participate and whether third parties will take part.

*Design consequence (adopted).* Every directorate run carries a **signed scope
manifest** naming tools, data classes, targets and third parties. No manifest, no
run; revoking it invalidates derived tokens and queued tasks — a runtime
primitive, not a runbook.

**Compartmentation and cut-outs protect a sponsor by destroying the audit trail.**
That is exactly the property a defensible system must not have. Outsourced force
without an authorisation gate produced both the Nisour Square prosecutions (eight
years from act to judgment) and the Wagner pattern (atrocity without an
enforceable chain). The Montreux Document's answer is a governance checklist:
decide what may not be contracted out, license, train, supervise, require
transparency.

*Design consequence (adopted).* No compartment without an audit path: every
handoff is journalled, and the directorate's own ombuds channel reports outside
the analytic chain (mirroring ODNI's Analytic Ombuds).

**Autonomy has a doctrinal template.** DoD Directive 3000.09 distinguishes
weapons that engage without further human intervention from human-supervised
systems whose operators can halt engagement — the kill switch in doctrine form.

*Design consequence (adopted).* Autonomy is bounded by verb: read = automatic,
write = confirmation, destructive or publishing = two-key. Plus hard halt, budget
ceiling and expiry on every delegation (NIST SP 800-53 AC-5/AC-6).

**State posture is a four-dimensional perimeter** — where data is processed, who
the customer is, what the model does, who can compel disclosure. Concrete edges:
EU AI Act prohibitions bite on *functionality* (manipulation, social scoring,
untargeted facial-recognition scraping); China's DSL asserts extraterritorial
reach; India's DPDP Rules (notified 14 Nov 2025) restrict transfers by
notification rather than banning them; the US combines CHIPS subsidies with
export controls that reached NSO Group.

*Design consequence (adopted).* A jurisdiction check runs at task creation, not
at delivery: prohibited-use and recipient screening before a collection task is
planned.

## 2. Security-community practice and agent failure modes

**Evidence handling is capture discipline.** RFC 3227 orders acquisition by
volatility and requires documenting every action and hashing at acquisition; the
Berkeley Protocol is the public-source equivalent (collection → preservation →
verification, metadata alongside content, audit trail, data minimisation).

**Provenance is machine-readable.** STIX 2.1 carries `confidence`,
`created_by_ref`, `object_marking_refs`, `external_references`. "source: Twitter"
is provenance theatre.

**Reproducibility is a detection property.** The Pyramid of Pain ranks indicators
by adversary cost; MITRE CTID's Summiting the Pyramid converts that into graded,
re-runnable analytics.

**Frameworks are vocabularies, not proofs.** CSF 2.0 is a management taxonomy,
ATT&CK a technique vocabulary, D3FEND a countermeasure vocabulary that explicitly
"does not characterize effectiveness". Only ASVS is testable against the platform
itself.

*Design consequence (adopted).* The directorate's QA is ASVS-shaped (verifiable
requirements) with ATT&CK only as a coverage grid. A desk may claim "behaviour
consistent with T####"; it may not claim coverage.

**Ten failure modes, each now a rule.** Over-collection → per-task field
allowlist. Base-rate blindness → publish posterior probability, never raw match
counts. Credential leakage → per-call short-lived tokens and secret scanning on
every egress path *including model context*. Prompt/tool injection → collected
content is typed as data and can never originate a tool call; a tool call needs a
policy grant content cannot supply. Unbounded write autonomy → dry-run default,
two-key for irreversible. Confident fabrication → no claim without artifact hash
and timestamp; ABSTAIN is a valid verdict. Cross-desk privilege accumulation →
deny-by-default capability ceiling per desk. Tool supply-chain trust → pinned,
hashed, human-reviewed tool manifests. Unbounded retry → per-target egress budget,
stop on 403/429. Non-reproducible verdicts → store model, prompt and tool
versions plus input hashes; replay is a CI job.

**Scope line, stated as code.** Legitimate public-source work: publicly accessible
content, no authentication bypass, no exploitation, purpose-limited, minimised.
Prohibited and gated: credential use, access-control circumvention, and
aggregation intended to locate or expose a person — doxxing is not "OSINT with bad
manners", it defeats the Berkeley Protocol's harm principle.

## 3. Cryptography, quantum, privacy, anti-piracy, languages

**PQC is a scheduling problem, not a maths problem.** FIPS 203/204/205 are final
(ML-KEM-768: 1,184-byte encapsulation key, 1,088-byte ciphertext; ML-DSA-65:
1,952-byte key, 3,309-byte signature). NIST IR 8547 deprecates 112-bit classical
signatures after 2030 and disallows them after 2035; CNSA 2.0 (US NSS only, but
the schedule vendors build to) requires exclusive signing/networking by 2030 and
completion by 2035. Hybrid TLS (X25519MLKEM768) is already default in Chrome 124+
and most human traffic at Cloudflare by October 2025.

**Harvest-now-decrypt-later is a retention problem.** The exposure window is
retention + legal hold + backup generations + derived copies, not "time until
Q-day". A seven-year audit log under ECDH is already lost if Q-day lands inside
those seven years — so retention schedules are cryptographic controls.

*Design consequence (adopted for ORACLE).* Migration order, cheapest first:
inventory (crypto bill of materials with data lifetime) → symmetric layer
(AES-256/SHA-384 are fine) → edge TLS hybrid → KMS key wrapping → signature
migration → archive re-encryption → retire classical. ORACLE's first deliverable is
the inventory, not a recommendation.

**Privacy techniques have measured limits.** Privacy Pass gives unlinkability for
tokens, not for traffic. Tor hides the client from the destination; it does not
hide that a client exists, and traffic correlation against a global adversary is
a documented attack (DeepCorr ~96% at ~900 packets; "Users Get Routed" ~80% over
six months). Metadata is the leak that survives content encryption.

*Design consequence (adopted for GHOST).* Claims are measured planes ("the target
sees a Tor exit"), never "undetected". Egress budgets and stop-on-403/429 are
enforced at the plane, not by convention.

**DRM is not a security boundary; entitlements and provenance are.** Widevine L3
recovery (WOOT 2022) demonstrates the class of break. Practical posture for the
organisation's *own* artifacts: signed entitlements, Build-ID + SLSA provenance
fingerprinting, collusion-resistant watermarking (Boneh–Shaw bounds), and takedown
evidence meeting DMCA §512(c)(3) / DSA Art. 16 elements. Out of scope by design:
removing protections from anyone else's work.

**Language comparison points one way for a policy-heavy agent platform.** Rust
wins on memory safety without a GC (Android: 76% → 24% of vulnerabilities after
adoption), predictable concurrency, and a mature supply-chain story with real
incident handling. Go is simpler operationally; Python and TypeScript win on
ecosystem reach but push safety into process boundaries; Java/Kotlin has the
strongest incremental-concurrency story after JEP 444; C/C++ carry the largest
memory-safety debt; Zig trades ecosystem for explicitness.

*Design consequence (adopted).* The engine stays Rust; policy is expressed as
data with a documented evaluation model (the Cedar/Starlark lesson: policy must be
analysable and non-Turing-complete, or review is impossible). Tallow's annotations
count as policy only where they are **lowered to compile-time effects** — an
annotation that is merely attached is documentation.

---

## 4. Domain coverage

| Domain | Evidence used | Where it lives |
| --- | --- | --- |
| Top intelligence agencies | ICD 203/206, CIA/ODNI org, JIC, CNCTR, BVerfG | SENTINEL charter; provenance gate; ombuds |
| Hidden mercenaries / covert | CIA glossary, Nisour Square, Montreux, Wagner reporting | audit-path rule; authorisation manifest |
| Top countries | CHIPS/BIS, EU Chips Act & AI Act, China DSL/MLPS, India DPDP, Israel AI program | QUARTERMASTER + ORACLE; jurisdiction gate |
| Security communities | RFC 3227, Berkeley Protocol, STIX, Pyramid of Pain, CTID, DEF CON AI Village | SENTINEL evidence schema; reproducibility rule |
| Competitors | public-source CI method | CARTOGRAPHER |
| Crypto & quantum | FIPS 203/204/205, SP 800-227, IR 8547, CNSA 2.0 | ORACLE migration order |
| Privacy & piracy | GDPR 5(1)(c), Privacy Pass, onion services, DeepCorr, Widevine L3, DMCA/DSA | GHOST plane discipline; anti-piracy posture |
| Security (general) | CSF 2.0, ASVS 5.0, ATT&CK/D3FEND, kill chain, diamond model | gate design; vocabulary-only rule |
| Technologies | language/runtime comparison, supply-chain incidents | QUARTERMASTER |
| Programming languages | Rust/Go/Python/TS/Java/C++/Zig/Swift matrix | CARTOGRAPHER; engine choice |
| Tallow language | `spec/generated.json`, `spec/01-lexical.md`, stdlib tree | CARTOGRAPHER + QUARTERMASTER |

## 5. Rejected, with reasons

- **Deception operations against third parties.** Studied for defensive design
  (compartmentation, cover, cut-outs) and explicitly not implemented: the audit
  trail is the point of this system.
- **"Undetectable" / "untraceable" claims.** No source supports them; the measured
  plane is the only claim that survives scrutiny.
- **D3FEND as coverage proof.** Its own FAQ disclaims effectiveness
  characterisation.
- **DRM as protection.** Treated as deterrence plus evidence, never as a boundary.
- **A general-purpose policy language inside Tallow.** Policy must stay analysable;
  the design keeps it data-shaped.

## Sources

Brief 1 (intelligence structure, covert practice, state posture): intelligence.gov
IC cycle; cia.gov organisation & spy glossary; ICD 203 and ICD 206 (dni.gov);
gov.uk JIC; sis.gov.uk; cnctr.fr; BVerfG 1 BvR 2835/17 (2020); 50 U.S.C. §3093;
ATP 3-21.8 (PMESII-PT); MCCMOS CPB (ASCOPE); justice.gov Nisour Square;
montreuxdocument.org; HRW Mali/Wagner; CRS IF11150 (DoD 3000.09); NIST SP 800-53r5;
FIRST TLP 2.0; commerce.gov NSO Entity List; congress.gov CHIPS; 88 FR 73424;
nist.gov AI RMF; EU Chips Act; EU AI Act 2024/1689; China DSL (npc.gov.cn); MLPS
2.0; India DPDP Act 2023 + 2025 Rules (meity.gov.in, pib.gov.in); Israel National
AI Program 2024.

Brief 2 (security practice): RFC 3227; NIST SP 800-86; OHCHR Berkeley Protocol
2022; Admiralty code; OASIS STIX 2.1; SANS Pyramid of Pain; MITRE CTID Summiting
the Pyramid; DEF CON 31 AI Village GRT; Black Hat USA 2025 briefings; MITRE ATT&CK;
MITRE CALDERA; Atomic Red Team; ECB TIBER-EU; ISO/IEC 29147; CERT/CC CVD guide;
Project Zero disclosure policy; GDPR Art. 5; DOJ CFAA policy 2022; NIST CSF 2.0;
SP 800-61r3; OWASP ASVS 5.0; D3FEND FAQ; Lockheed kill chain; Diamond Model;
Axelsson 2000 (base rates); AWS-2025-015; Socket Nx postmortem; Greshake et al.
2023 (indirect injection); EchoLeak CVE-2025-32711; OECD AI incident 2025-07-19;
Moffatt v. Air Canada; Invariant Labs MCP advisory.

Brief 3 (crypto, privacy, piracy, languages): FIPS 203/204/205; SP 800-227; NIST
IR 8547 (draft); CNSA 2.0; SP 800-57 Pt.1 r5; GDPR Art. 5; RFC 9576 Privacy Pass;
Tor onion-services docs; DeepCorr (arXiv 1808.07285); "Users Get Routed"
(Georgetown); EFF SSD metadata; Census TopDown (Kenny et al.); RFC 8032; Microsoft
Ten Immutable Laws; Widevine analysis (arXiv 2204.09298, WOOT); Schneier on copy
prevention; SLSA v1.2; Boneh–Shaw; 17 U.S.C. §512; DSA 2022/2065; MSRC CVE share;
Android memory-safety data 2024; crates.io malware postmortem; Python free
threading docs; TypeScript docs; npm event-stream postmortem; JEP 444; WG21 P3081;
CISA memory-safety advisory; ziglang.org; Cedar paper (arXiv 2407.01688); Starlark
spec; Temporal determinism docs.

Full text of brief 3: `/home/aamir/Nixe/research/security-brief-crypto-privacy-languages.md`.
