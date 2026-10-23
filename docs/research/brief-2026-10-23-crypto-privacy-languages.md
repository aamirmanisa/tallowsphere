# Cryptography, Privacy and Language Foundations for a Small Policy Platform

References resolve in the table at the end with URL and quality note; no figure appears that its source does not state.

## 1. Cryptography and the quantum transition

**Standards.** NIST finalised FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA) in August 2024 [1][2][3]. Sizes drive budgets: ML-KEM-768 uses a 1,184-byte encapsulation key and 1,088-byte ciphertext; ML-DSA-65 a 1,952-byte key and 3,309-byte signature [1][2]. SLH-DSA signatures are far larger, suiting low-volume, long-lived roots [3]. SP 800-227 (2025) covers KEM use and approved hybrid combiners [4].

**Deployment.** Hybrid key establishment is already default: X25519MLKEM768 is specified for TLS 1.3 [5], Chrome shipped a hybrid by default in version 124 [6], and Cloudflare reported most human-initiated traffic post-quantum protected by October 2025 [7].

**Timelines.** NIST IR 8547 (draft) deprecates 112-bit classical signatures after 2030, disallows classical signatures after 2035, and disallows 112-bit symmetric algorithms in 2030 [8]. CNSA 2.0 binds only US national security systems but is the schedule vendors build to: signing and networking exclusive by 2030, browsers, servers, cloud and operating systems by 2033, legacy applications replaced by 2033, complete by 2035 [9].

**Harvest-now-decrypt-later.** An adversary records ciphertext now and decrypts it once a cryptographically relevant quantum computer exists. The window is not "until Q-day" but *retention + legal hold + backup generations + derived copies*: a seven-year audit log under ECDH is already lost if Q-day lands inside those seven years. Hence retention schedules are cryptographic controls, and shortening them cuts exposure more cheaply than any algorithm swap. Key wrapping at rest matters as much as TLS, because archives outlive sessions.

**Migration order**, cheapest first:

1. Inventory — crypto bill of materials: algorithm, key size, owner, data lifetime.
2. Symmetric layer — AES-256 and SHA-384 are fine [8].
3. Edge TLS — enable X25519MLKEM768; configuration, not code [5][7].
4. Key wrapping — ML-KEM envelope encryption in the KMS.
5. Artifact signing — ML-DSA-65; SLH-DSA for root keys only [2][3].
6. Tokens — EdDSA/RS256 JWTs to ML-DSA, hybrid verifier during overlap.
7. Certificates last — PKI lag is the long pole; plan hybrid certificates, not a flag day.

**Choice.** Default ML-DSA-65 (category 3); never hand-roll combiners [4]. Rotate on cryptoperiod — signing keys annually, KEM keys shorter — and retain verification keys while any signature must verify [10].

## 2. Privacy techniques deployable today

**Minimisation beats anonymisation.** GDPR Art. 5(1)(c) permits only data adequate, relevant and limited to what is necessary [11]. Engineering form: every field carries an owner, a purpose and a deletion job, or is not stored.

**Anonymisation is not a safe harbour.** Narayanan and Shmatikov re-identified Netflix Prize subscribers by linking "anonymised" ratings to public IMDb profiles [12]. Pseudonymisation is risk reduction, never de-identification.

**Unlinkability.** Privacy Pass (RFC 9576/9578) proves entitlement — paid tier, rate-limit quota — without issuer and relying site linking the token to a user [13].

**Onion services.** They hide service location (IP addresses are not used in the protocol), authenticate end-to-end because the address *is* the public key, and need no inbound ports [14]. Good fits: admin planes, tip lines, unroutable internal APIs.

**Measured limits.** Traffic correlation is strong: DeepCorr reported 96% correlation accuracy from roughly 900 packets per flow against a 4% baseline [15], and "Users Get Routed" found 80% of modelled user types deanonymisable by a moderate relay-level adversary within six months [16]. Tor defends against local observers, not an adversary seeing both ends or controlling relays. Metadata behaves likewise: who, when, how often and how much is often sufficient alone [17].

**Differential privacy has a price.** The 2020 US Census TopDown system cut injected noise, yet independent evaluation found errors "relatively substantial for geographies with small total populations" [18]. Publish aggregates with a stated budget; small cells stay unusable.

## 3. Anti-piracy for your own artifacts

Enforcement is deterrence plus evidence, never confidentiality.

**Licence enforcement.** Issue signed entitlements (Ed25519 today [19], ML-DSA-65 next), keep them short-lived, gate value server-side. Any check on a machine the customer controls can be patched, as Microsoft's security canon concedes [20]: client checks buy time and contractual hooks, not secrecy.

**DRM is not a security boundary.** Academic tooling recovered the root-of-trust of Widevine's software-only L3 level [21]; the pattern is old [22]. DRM still earns its place for licence terms and anti-circumvention law, not for keeping bits secret.

**Watermarking and fingerprinting.** Per-customer build identifiers plus signed provenance [23] give attribution without pretending to prevent copying. Fingerprinting collapses under collusion: Boneh–Shaw coding bounds how many colluders stay traceable [24]. A watermark is evidence, not a lock.

**Takedown evidence.** Pack an artefact hash, signed build manifest, the watermarked diff, distribution URLs and timestamped captures. US notice-and-takedown requires identifying the work, the infringing material and its location, contact details, a good-faith statement and a statement under penalty of perjury [25]; the EU equivalent is DSA notice-and-action [26].

**Boundary.** Your own artifacts only; stripping others' protections is out of scope.

## 4. Language comparison

Memory unsafety dominates defect classes: Microsoft reports roughly 70% of assigned CVEs are memory-safety issues [27], Android cut its share from 76% to 24% after moving new code to memory-safe languages [28], and CISA presses manufacturers for memory-safety roadmaps [35].

| | Memory safety | Concurrency | Toolchain | Ecosystem | Supply-chain risk |
|---|---|---|---|---|---|
| **Rust** | Checked; `unsafe` explicit | async, `Send`/`Sync`, no runtime | cargo, clippy, editions | Strong; async still fragmenting | Malicious crates real; lockfile + audit [29] |
| **Go** | Safe, GC; races possible | goroutines, channels, race detector | Fast, no build scripts | Large stdlib, modest types | Proxy-mediated, low build-time exec |
| **Python** | Safe; C extensions are not | GIL; free-threaded build 3.13+ [30] | pip/uv, no runtime types | Largest | Typosquats, deep trees |
| **TypeScript** | Safe; types erased [31] | Event loop, workers | tsc/esbuild | Largest web | npm, highest volume [32] |
| **Java/Kotlin** | Safe, GC | Virtual threads [33], coroutines | Maven/Gradle | Enterprise depth | Curated, transitive risk |
| **C/C++** | Unsafe by default; profiles contested [34] | `std::thread`, manual | CMake, fragmented | Huge, legacy | No build isolation; vendored blobs |
| **Swift** | Safe by default, ARC | async/await, actors | SwiftPM, Xcode | Apple-centric | Few deps; toolchain lock-in |
| **Zig** | Explicit allocators, no hidden control flow [36] | Threads; async unstable | `zig build`, cross-compiles | Pre-1.0, small | Few deps, thin review |

**Recommendation.** Rust for the policy core, compiler and crypto; TypeScript or Python for adapters, UI and operator tooling; C/C++ only at FFI edges behind reviewed `unsafe`. A policy platform must *prove* memory safety, deterministic execution and auditable data flow, and Rust delivers all three without a garbage collector or managed runtime; Cedar shows a policy language can be built that way, with a small verified core and machine-checked semantics [37]. Interpreted policy is a liability in an agent runtime: Starlark's determinism comes from having no I/O or clock [38], and Temporal requires deterministic workflow code to replay history [39]. Tallow-style annotations mean something only if they lower into an effect system enforced at compile time — not runtime string checks, and not a spec outrunning its implementation.

## Sources

| # | Source and URL | Quality note |
|---|---|---|
| 1 | FIPS 203 ML-KEM — csrc.nist.gov/pubs/fips/203/final | Primary standard |
| 2 | FIPS 204 ML-DSA — csrc.nist.gov/pubs/fips/204/final | Primary standard |
| 3 | FIPS 205 SLH-DSA — csrc.nist.gov/pubs/fips/205/final | Primary standard |
| 4 | SP 800-227 KEMs — nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf | Primary guidance |
| 5 | IETF TLS hybrid ECDHE-MLKEM (RFC 10024) — datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem | IETF standard-track |
| 6 | Chromium Kyber default — blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html | Vendor blog |
| 7 | Cloudflare PQ report — blog.cloudflare.com/pq-2025/ | Vendor telemetry |
| 8 | NIST IR 8547 — nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf | Draft federal guidance |
| 9 | NSA CNSA 2.0 — media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF | Government policy; read via Wayback copy |
| 10 | SP 800-57 Pt.1 r5 — csrc.nist.gov/pubs/sp/800/57/pt1/r5/final | Primary guidance |
| 11 | GDPR Art. 5 — gdpr-info.eu/art-5-gdpr/ | Legal text, informal mirror |
| 12 | Narayanan & Shmatikov — arxiv.org/abs/cs/0610105 | Peer-reviewed, IEEE S&P |
| 13 | RFC 9576 Privacy Pass — rfc-editor.org/rfc/rfc9576.html | IETF standard-track |
| 14 | Tor onion services — community.torproject.org/onion-services/overview/ | Project documentation |
| 15 | DeepCorr — arxiv.org/abs/1808.07285 | Peer-reviewed, CCS |
| 16 | Users Get Routed — seclab.cs.georgetown.edu/papers/users-get-routed.pdf | Peer-reviewed, CCS |
| 17 | EFF SSD metadata — ssd.eff.org/module/why-metadata-matters | Advocacy, technically sound |
| 18 | Kenny et al. Census DAS — imai.fas.harvard.edu/research/files/DASeval.pdf | Peer-reviewed, Sci. Adv. |
| 19 | RFC 8032 Ed25519 — rfc-editor.org/rfc/rfc8032 | IETF standard-track |
| 20 | Microsoft Ten Immutable Laws — learn.microsoft.com/en-us/previous-versions/cc722487(v=technet.10) | Vendor canon |
| 21 | Widevine analysis — arxiv.org/abs/2204.09298 | Peer-reviewed, WOOT |
| 22 | Schneier, copy prevention — schneier.com/essays/archives/2001/01/gimmicks_wont_protec.html | Expert essay |
| 23 | SLSA v1.2 — slsa.dev/spec/v1.2/ | OpenSSF spec |
| 24 | Boneh & Shaw — ieeexplore.ieee.org/document/705568 | Peer-reviewed |
| 25 | 17 U.S.C. §512 — law.cornell.edu/uscode/text/17/512 | Statute, LII mirror |
| 26 | DSA 2022/2065 — eur-lex.europa.eu/eli/reg/2022/2065/oj | Primary legislation |
| 27 | MSRC CVE share — microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/ | Vendor disclosure |
| 28 | Android 76%→24% — security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html | Vendor data |
| 29 | crates.io postmortem — blog.rust-lang.org/inside-rust/2023/09/01/crates-io-malware-postmortem/ | Incident report |
| 30 | Python free threading — docs.python.org/3/howto/free-threading-python.html | Official docs |
| 31 | TypeScript — typescriptlang.org | Official site |
| 32 | npm event-stream — blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident.html | Incident report |
| 33 | JEP 444 — openjdk.org/jeps/444 | Accepted JDK spec |
| 34 | WG21 P3081 — wg21.link/p3081 | Proposal; contested |
| 35 | CISA memory safety — cisa.gov/news-events/news/urgent-need-memory-safety-software-products | Government advisory |
| 36 | Zig — ziglang.org | Official site |
| 37 | How We Built Cedar — arxiv.org/html/2407.01688v1 | Industry paper |
| 38 | Starlark spec — github.com/bazelbuild/starlark/blob/master/spec.md | Reference spec |
| 39 | Temporal determinism — docs.temporal.io/workflow-execution/workflowid-runid | Vendor docs |
