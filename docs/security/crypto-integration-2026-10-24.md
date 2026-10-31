# Cryptographic Integration: Survey, Curated Stack, and Plan

**Date:** 2026-10-24 · **Scope:** Tallow Language (`tallowsphere`) engine + stdlib surface
**Method:** measured baseline in this tree, then public standards and library releases.
Nothing in §1 is inferred; every count below came from the working tree at `8887e39`.

---

## 0. Three premises corrected before the survey

**(a) "Operational stealth / undetected" is not a property cryptography provides.**
Cryptography gives confidentiality, integrity, authenticity, forward secrecy and
post-compromise security. Whether an exchange is *noticed* is decided by traffic
analysis, endpoint state, key custody, timing, and deployment — none of which a
cipher changes. A cryptographic stack that claims "undetectable" is making a claim
it cannot measure. The measurable substitutes, which this plan targets, are:

| Claim people want | Property that can actually be measured |
|---|---|
| "undetectable" | ciphertext indistinguishable from random under a stated model (IND-CCA2) |
| "no one sees who talks" | metadata minimisation + onion routing + cover traffic (a **network** property) |
| "looks like normal traffic" | TLS fingerprint uniformity, record-size padding, timing shaping |
| "no keys on the server" | client-side encryption with per-file keys and wrapped key material |
| "safe if a key leaks" | forward secrecy + post-compromise security, with rotation depth per session |

Tallow already has the network half of this (Tor egress, scope manifests, fingerprint
normalisation, egress budgets). The crypto work below strengthens the other half; it
does not and cannot make anything undetectable.

**(b) "What intelligence agencies use" is only knowable where it is public.** The
unclassified half is real and specified: NSA's CNSA 2.0, Germany's BSI TR-02102-1,
France's ANSSI rules, Russia's GOST R 34.10/34.11/34.12, China's SM2/SM3/SM4. The
classified half is, by definition, unpublished — adopting an algorithm on the strength
of "an agency uses it" buys no public cryptanalysis, no test vectors and no audit, which
is the opposite of a security upgrade. Everything recommended here is publicly specified
and independently implemented.

**(c) "Blackhat forums" are not a source.** They carry unverifiable claims, no vectors,
and frequently the artefacts themselves. The transferable equivalent is public research:
IACR ePrint, USENIX Security, CHES, Real World Crypto, and the public conference track
at DEF CON / Black Hat (e.g. DEF CON 33's "Post Quantum Panic: When Will the Cracking
Begin, & Can We Detect it?"). Those are cited in §2.5 and used the same way as any other
paper.

---

## 1. Measured baseline in this tree

| Fact | Value | Where |
|---|---|---|
| Crypto declarations in the language surface | **28** | `stdlib/crypto.tl` |
| Dispatch arms in the runtime | **197** | `src/stdlib/crypto.rs` |
| Declared names without an arm | **0** | measured by set difference |
| Arms explicitly marked `_experimental` | **9** | BBS+, threshold, blind signatures |
| Direct dependencies | **178** | `Cargo.toml` |

Already implemented, with the crate that does the work:

* **AEAD** — `aes-gcm` (AES-256-GCM), `aes-gcm-siv` (nonce-misuse resistant), `chacha20poly1305`
* **Hashes / KDF** — `sha2`, `sha3`, `blake3`, `hmac`, `hkdf`, `argon2` (Argon2id)
* **Signatures / DH** — `ed25519-dalek` 2.2, `curve25519-dalek` 4.1, `x25519-dalek` 2.0
* **Post-quantum** — `ml-kem` 0.2 (FIPS 203), `ml-dsa` 0.1 (FIPS 204); optional `pqcrypto-sphincsplus`,
  `pqcrypto-falcon`, `pqcrypto-frodo`, `pqcrypto-classicmceliece`
* **Protocols** — `snow` 0.10 (Noise rev 34 patterns NN…IX), `spake2` 0.4 (PAKE), OPAQUE arms,
  `rustls` 0.23 (ring provider), `rcgen`, `webpki-roots`
* **Key handling** — `aes-kw` (RFC 3394 wrapping), `zeroize`

Nine arms are honestly labelled approximations, e.g.
`// EXPERIMENTAL Ed25519-commitment approximation (NOT BBS+; no pairing-based security)`
and `// EXPERIMENTAL Shamir-split Ed25519 (NOT FROST; no DKG/aggregation; threshold property absent)`.
That labelling is the right instinct and this plan preserves it.

**Correction (2026-10-24, measured after the first draft).** Three items in the original gap
list were wrong, because the `*_experimental` arms and their comments were read as the state of
the code:

* **FROST is real.** `src/frost.rs` implements FROST(Ed25519, SHA-512) per **RFC 9591**, embeds
  the RFC's Appendix E.1 vectors and asserts each stage against them. `cargo test --lib frost::`
  → **14/14**, including *"signature shares and the aggregate match the vectors"* and a fresh
  group signing at its threshold. The `threshold_*_experimental` arms are a **stale Shamir
  approximation** that still sits in the dispatch table next to the real implementation.
* **BBS+ is real.** `src/bbs.rs` (79 KB) implements signing, proof generation and verification
  with the draft's published vectors — `cargo test --lib bbs::` → **24/24**, including
  *"the second proof vector matches its published t1 and t2"*.
* **SLH-DSA is implemented**, not missing: it is behind the optional `pq-legacy` feature and the
  default build returns a named refusal.

**Real gaps**, re-measured:

1. **No HPKE (RFC 9180).** Every hybrid-encryption use case is hand-rolled per call site.
2. **No MLS (RFC 9420)** — group key agreement is absent; pairwise Noise cannot substitute at scale.
3. **No PQ-hybrid key exchange in the transport** — `rustls` is built with the `ring` provider and
   nothing in-tree asserts the negotiated group, let alone a PQ one.
4. **Stale duplicate arms.** Nine `*_experimental` constructions remain dispatchable alongside the
   real implementations they predate; calling one is not an error, which is worse than one.
5. **No per-function capability report.** The doctor report classified `crypto` as a module
   ("real", 28 declared, 156 arms) but not which *function* is implemented, gated by a feature, or
   a stale approximation — the gap that produced the two errors above. **Closed by P0** (below).

---

## 2. Survey

### 2.1 National / agency suites (public half)

* **NSA CNSA 2.0** — AES-256; **ML-KEM-1024** for key establishment; **ML-DSA-87** for signatures;
  SHA-384/512; LMS/XMSS permitted for firmware/software signing. Timeline: prefer CNSA 2.0 in new
  acquisitions from **2027**, mandated **2031**, transition complete **2035**; software signing
  migrating immediately, exclusively by 2030. Hybrids are accepted only where a protocol forces them,
  and HashML-DSA is *not* approved. ([CNSA 2.0 CSA](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF), [FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF))
* **BSI TR-02102-1 (2026-01)** — 120-bit floor; classical-only key agreement recommended only until
  **2031-12-31** (2030 for very high protection); hybrid KEMs (ML-KEM, FrodoKEM, Classic McEliece)
  combined with CatKDF/HKDF/KMAC or NIST SP 800-227 `KeyCombine`; signatures migrate by 2035.
  ([TR-02102-1](https://bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf))
* **NIST** — FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), approved 2024-08-13. FIPS 206 (FN-DSA)
  still pending; HQC selected as the code-based backup KEM (2025) but not yet standardised.
  ([NIST announcement](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards))

**What transfers:** parameter targets (ML-KEM-1024 / ML-DSA-87 for a "CNSA 2.0 profile"), the
hybrid-combiner rule (bind algorithm IDs, public keys, ciphertexts into the KDF), and the
migration dates as *policy*, not as cryptographic properties.

### 2.2 Sovereign profiles (interoperability, not superiority)

* **Russia** — GOST R 34.10-2012 (signatures), 34.11-2012 Streebog (hash), 34.12-2015
  Kuznyechik/Magma (block), 34.13-2015 MGM (AEAD); TLS 1.3 suites drafted but not an RFC.
  ([RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986), [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091))
* **China** — SM2 (GB/T 32918), SM3 (GB/T 32905), SM4 (GB/T 32907); **RFC 8998** defines the
  TLS 1.3 profile, so it is interoperable rather than obscure.
  ([RFC 8998](https://www.rfc-editor.org/info/rfc8998/))

**What transfers:** support them as *named profiles* selected per jurisdiction, never as defaults.
Each is a political mandate, not a stronger primitive, and neither has a post-quantum migration
path published yet.

### 2.3 Private military / specialised teams

No public doctrine exists, and any claim to the contrary is marketing. The observable, auditable
practice in high-assurance commercial work is unglamorous: FIPS-validated modules, HSM or
hardware-backed key custody, split knowledge and dual control, short key lifetimes with tested
rotation, out-of-band identity verification, and threshold signing so no single operator can
sign a release. **What transfers is custody and ceremony, not exotic algorithms** — which is
exactly what §4's P5 addresses.

### 2.4 Competitors and reference designs

| System | Construction | What to copy |
|---|---|---|
| **age** (C2SP) | X25519 recipient stanza, HKDF-SHA-256, ChaCha20-Poly1305 in 64 KiB chunks, scrypt for passphrases | Simple, auditable container format; streaming AEAD with a final-chunk flag ([spec](https://github.com/C2SP/C2SP/blob/main/age.md)) |
| **Signal** | PQXDH (X3DH + ML-KEM-1024) for the first key; Triple Ratchet (Double Ratchet + SPQR/ML-KEM-768) for ongoing | HNDL protection at handshake *and* ratchet; authentication still classical in PQXDH ([PQXDH](https://signal.org/docs/specifications/pqxdh/pqxdh.pdf)) |
| **MLS** (RFC 9420) | TreeKEM group key agreement, FS + PCS at group scale | The only standard answer for group E2EE ([RFC 9420](https://www.rfc-editor.org/info/rfc9420/)) |
| **Noise** (rev 34) | Pattern-based handshakes over DH + AEAD | What Tallow already uses via `snow` |
| **Tresorit / Proton Drive** | client-side AES-256 per-file keys, RSA-4096-OAEP or ECC key wrapping, scrypt-derived password key, zero-knowledge auth | Per-file keys + wrapped key material + no plaintext key on server ([whitepaper](https://cdn.tresorit.com/202208011608/tresorit-encryption-whitepaper.pdf)) |

### 2.5 Research and community (the usable substitute for "forums")

Transferable items, in order of practical value to this codebase:

1. **Formal verification of primitives** — `libcrux` (HACL*/hax) ships verified ML-KEM, ML-DSA,
   ChaCha20-Poly1305, AES-GCM and SHA-2/3 in Rust. ([repo](https://github.com/cryspen/libcrux))
2. **Constant-time discipline**, measured with `dudect`/`ctgrind`, not asserted in comments.
3. **KAT harnesses from NIST ACVP vectors** — the only way to know an implementation is the
   standard and not a lookalike.
4. **Side-channel work on lattice code** — the practical risk in ML-KEM/ML-DSA is implementation
   (rejection sampling, NTT masking), not the hardness assumption.
5. **Fuzzing every parser** that touches ciphertext, certificates, or key files.

### 2.6 Post-quantum, homomorphic, zero-knowledge — maturity check

| Technology | State | Verdict for Tallow |
|---|---|---|
| ML-KEM / ML-DSA | FIPS 203/204, shipping in browsers and TLS | **Adopt now** (already present; wire into transport) |
| SLH-DSA | FIPS 205, large signatures (~7.8–49 KB) | Hedge for firmware/root keys, not for per-message use |
| FN-DSA (Falcon) | FIPS 206 pending | Wait |
| HQC | selected 2025, not standardised | Watch |
| FHE (`tfhe-rs` 1.x) | production-ready for integer/boolean circuits; **no side-channel mitigation yet**; patent licence required for commercial use | Opt-in feature only, never on the auth path |
| ZK (`arkworks`, `halo2`, `plonky3`, `gnark`, Noir) | mature frameworks, heavy circuits, per-scheme trusted setup caveats | Opt-in; use for verifiable computation, not for confidentiality |
| Threshold (FROST, RFC 9591) | standardised, 2-round Schnorr | **Adopt** — replaces the Shamir approximation for release signing |

### 2.7 Language ecosystems

| Language | Best-in-class | Verified / FIPS | Note |
|---|---|---|---|
| Rust | RustCrypto, dalek, `snow`, `rustls`, **libcrux**, **aws-lc-rs** (FIPS 140-3 cert #5314 static / #5298 dynamic on the v3 module) | libcrux: verified; aws-lc-rs: validated module | Best fit: memory safety + verification + FIPS path in one language |
| C | OpenSSL 3.x, BoringSSL, libsodium | OpenSSL/BoringSSL validated modules | Needed only for interop, not for new surface |
| Go | `crypto/*`, `gnark` (ZK) | limited FIPS story | Good for services, weaker for verified primitives |
| Python | `cryptography` (OpenSSL bindings) | via OpenSSL | Prototyping only; no constant-time guarantees in pure Python |

Tallow is Rust-native, so the recommendation is to stay in Rust and take the verified/FIPS
components rather than bind a C library.

---

## 3. Curated stack (deliverable 1)

Ordered by "what to add", not "what exists".

| # | Capability | Crate | Why this one | Cost |
|---|---|---|---|---|
| 1 | **HPKE (RFC 9180)** | `hpke` (RustCrypto) | The standard seal/open primitive; replaces per-call-site hybrid encryption; supports PQ ciphersuites as they land | low |
| 2 | **Verified primitives** | `libcrux-*` | Formally verified ML-KEM/ML-DSA/AES-GCM/ChaCha20; the single biggest assurance upgrade available in Rust | medium (build size) |
| 3 | **MLS group E2EE** | `openmls` | RFC 9420; no in-house alternative is defensible | medium |
| 4 | **FROST threshold** | `frost-ed25519` (ZF) | RFC 9591; replaces the Shamir approximation, gives real DKG + aggregation | low |
| 5 | **OPAQUE PAKE** | `opaque-ke` | Real aPAKE for credential auth; currently approximated | low |
| 6 | **PQ hybrid transport** | `rustls` + `aws-lc-rs` provider | `X25519MLKEM768` (codepoint `0x11EC`) where the provider exposes it; assert the negotiated group in tests | medium |
| 7 | **SLH-DSA** | `slh-dsa` (RustCrypto) | FIPS 205 hedge for long-lived signing keys | low |
| 8 | **age container** | `age` crate | Audited file format for the transfer path; avoids inventing a container | low |
| 9 | **Secret handling** | `zeroize`, `secrecy`, OS keystore (`keyring`) | Removes secrets from `Debug`, zeroes on drop | low |
| 10 | **FIPS profile** | `aws-lc-rs` `fips` feature | Only when a customer requires a validated module; separate build profile | medium |
| 11 | **FHE (opt-in)** | `tfhe` | Real capability, honest limits (no side-channel mitigation; patent licence) | high |
| 12 | **ZK (opt-in)** | `arkworks` (research), `plonky3` (production proofs) | Only for verifiable computation use cases | high |

Blind signatures: `voprf` (RFC 9497) is the standard construction; keep the experimental arm
until a real implementation replaces it. BBS+ requires pairings (`bbs` crate) — only if
selective disclosure is an actual requirement, since the security and complexity cost is real.

---

## 4. Integration plan (deliverable 2)

Each phase ends in a runnable check. Nothing is "done" because a file exists.

### P0 — Capability registry and honest surface — **DONE (2026-10-24)**
`tallow doctor --capabilities json` now carries a per-function `crypto` section: every declared
function with `status` (`implemented` | `gated` | `experimental` | `simulated` | `unavailable`),
the resolved handler, and a quoted source excerpt as the reason for anything that is not
`implemented`. Measured at HEAD 2026-10-24: **54 declared → 44 implemented, 7 gated, 3 unavailable**,
with **12 retired** approximation arms listed separately (each refusing and naming its replacement)
so none can be mistaken for a real implementation. The counts move whenever the surface grows; the
numbers here are a measurement with a date, not a constant.

**Verification (run):** `tests/crypto_capability_registry.rs` — **4/4 pass**, asserting
(a) the report and `stdlib/crypto.tl` agree name-for-name, (b) statuses come from a closed
vocabulary and every non-`implemented` status carries evidence (and a feature name when gated),
(c) FROST/BBS+/Noise/SPAKE2 do not regress to a stub, (d) the legacy arms stay visible.
Measured report: **28 implemented, 0 absent, 9 experimental arms**.

### P1 — HPKE — **DONE (2026-10-24), base mode, one suite**
`crypto.hpke_suite`, `crypto.hpke_generate_keypair`, `crypto.hpke_seal`, `crypto.hpke_open` are
implemented for DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, base mode, hex in/out.

**Why not the `hpke` crate:** it requires `kem ^0.3.0` (final) while this tree's `ml-kem 0.2`
requires `kem = 0.3.0-pre.0`; Cargo cannot resolve both, and upgrading ML-KEM is a separate change
to the post-quantum path. Everything HPKE needs was already in the graph, so the composition lives
in `src/hpke.rs` — X25519 + HKDF-SHA256 + AES-128-GCM, composed per RFC 9180 §4.1/§5.1.

Two bugs the vector caught, both silent-wrong-answer class: using the HPKE suite id inside the KEM
(it must be `"KEM" || kem_id`), and *expanding* the labeled extract instead of returning the PRK.
After the fix the intermediate values match the RFC exactly (`shared_secret fe0e18c9…`,
`key 4531685d…`, `base_nonce 56d890e5…`) and the ciphertext matches **byte for byte**.

**Verification (run):** `src/hpke.rs` 4/4 (RFC A.1.1 vector, tamper/AAD/info failures, all-zero
key refusal) and `tests/hpke_rfc9180.rs` 4/4 (the language surface opens the RFC vector unchanged;
seal→open round-trip; forged ciphertext refused with `authentication failed`; the compiled plane
refuses by name: `crypto.hpke_suite() has no native lowering`).

### P2 — PQ-hybrid transport — **DONE (2026-10-24), opt-in**
`src/net/tls_provider.rs` is now the single place a TLS provider is chosen. Every former local
`ring` install (`net.rs`, `transfer_net.rs`, `relay.rs` — five call sites) goes through it.

* **Default: unchanged.** ring provider, classical groups. Handshake bytes and fingerprints are
  exactly what 1.5.2 shipped.
* **`TALLOW_TLS_PQ=1`: aws-lc-rs**, which offers `X25519MLKEM768` (IANA `0x11EC`) and prefers it,
  with the classical groups still enabled so a peer without the group connects.
* `install()` is called once at process start when the variable is set, so every rustls consumer in
  the process — QUIC, transfer, relay — sees the same provider, and `info()` reports
  `{provider, pq_offered, groups}` instead of leaving it to assumption.

**Why opt-in, not default:** the ML-KEM key share adds ~1.2 KB to the ClientHello, which changes
the JA3/JA4 shape the browser-impersonation profiles reproduce. That is a fingerprint decision for
the operator, not a library default.

**Verification (run):** `tests/pq_tls_group.rs` **2/2** — a real TLS 1.3 handshake over loopback
(no mocks, no external network) asserts both ends report `X25519MLKEM768` with aws-lc-rs, and that
the ring provider negotiates a classical group and never claims ML-KEM. `net::tls_provider` unit
test 1/1 asserts the two providers' advertised group lists directly.

### P3 — Protocols: MLS and OPAQUE (**subtractive half DONE 2026-10-24**)
**Retired (done).** All nine `*_experimental` arms now refuse and name the standard
implementation: "crypto.threshold_sign_experimental is RETIRED: it was an approximation, not FROST
(RFC 9591). Use crypto.frost_sign". They keep their dispatch keys, so old code fails loudly instead
of silently getting an approximation that looks like a signature. `tallow doctor --capabilities`
reports them under `crypto.retired` with the replacement for each, and the gate test asserts the
mapping (`threshold_*` → `frost_*`, `bbs_*` → `bbs_*`).

**OPAQUE was never OPAQUE (retired).** `crypto.opaque_register/login/create_credential_response`
were an Argon2id + Ed25519 envelope: no oblivious protocol, no server-side credential, and the name
promised RFC 9807. They now refuse and point at `crypto.spake2_start` (SPAKE2, RFC 9382) as the real
PAKE available today. Twelve retired keys in total, each naming its replacement.

Two classifier defects surfaced while doing this, both fixed: a whole arm written as
`Some(Err("…"))` was reported as `implemented` (no `return Err(` to match), and the replacement
scanner read only the first 160 characters of the message, so long refusals lost the
"Use crypto.x" sentence.

**OPAQUE (RFC 9807) — DONE 2026-10-24.** Real `opaque-ke` 4.0.1, ristretto255 +
TripleDH/SHA-512, driven through a message-passing surface (`opaque_setup`,
`opaque_register_start/respond/finish/store`, `opaque_login_start/respond/finish/server_finish`),
messages and per-step state carried as hex. Proven: client and server derive the **same
64-byte session key**, a wrong password never reaches a session key, and a record registered
under one server setup cannot complete a login under another. `src/opaque.rs` 3/3,
`tests/opaque_flow.rs` 2/2 (the flow driven from Tallow source). KSF is `Identity` today —
a hardening parameter, documented at the call site, to be replaced with Argon2id before any
real credential store exists (it invalidates records, so it must be decided before first use).

**Native lowering: DONE 2026-10-24.** All ten OPAQUE steps lower through `src/runtime/opaque_ffi.rs`.
Multi-value steps return heap records whose field order the codegen layouts mirror, and the IR checks
the record pointer before loading any field, so an error aborts with the protocol message instead of
dereferencing null. One ABI defect was found and fixed during the work: `register_respond` returned a
bare string while the surface declares a one-field struct, so the generated code read the string as a
struct and crashed — the declared shape and the C shape must match, always.
`tests/opaque_native_parity.rs` (3/3) proves it: `--require-native` succeeds, a native registration
logs in from the interpreter, and an interpreter registration logs in natively, both agreeing on the
session key.

**MLS (RFC 9420) — SURFACE LANDED 2026-10-24, opt-in.** Seven functions
(`mls_key_package`, `mls_create_group`, `mls_add_member`, `mls_join`, `mls_encrypt`,
`mls_process`, `mls_info`) over openmls 0.7.4. Built with `--features mls`; a default build
refuses each call by name and the capability report marks all seven **gated** with the feature
named, rather than claiming them.

Verified from Tallow source (`tallow run --interpret`, `--features mls`):
`epoch_after_add=1`, `bob_epoch=1`, `kind=application`, plaintext `6869` recovered, `members=2`;
with the feature off the same program stops at
`crypto.mls_* requires building with --features mls`.

State is an in-process registry keyed by handle — an MLS group cannot be serialized without its
provider's key store, so cross-process persistence is open, not simulated.

**Native lowering: DONE 2026-10-24 (feature-gated).** All seven calls lower through
`src/runtime/mls_ffi.rs` when the build has `--features mls`; the records mirror the codegen structs
and every pointer is checked before use. Verified under `--require-native`: `1`, `1`, `application`,
`6869`, `2` — identical to the interpreter. In a build without the feature the arms refuse at compile
time with a message naming the feature, so no default build references a symbol it does not link.

**Known CI gap:** the `mls` feature path (FFI + native lowering) is not exercised by CI, which builds
the default feature set. A feature-build job is required to make that path gated rather than
hand-verified.

**Open for P3-MLS:** cross-process state, member removal / update path, commit handling for
multi-device clients.
**Check:** RFC 9591 vectors for FROST; an MLS two-client group round-trip; OPAQUE registration and
login across both planes; the old experimental arms still refuse-or-work as documented.

### P4 — age container — **container DONE (2026-10-24); transfer path open**
`crypto.age_keygen` / `age_encrypt` / `age_decrypt` produce and consume a **real age container**
via the `age` crate: X25519 recipient stanzas, HKDF-SHA-256, ChaCha20-Poly1305 in 64 KiB chunks,
header MAC. Payloads cross the language boundary as hex because the runtime has no byte-buffer value.

**Interoperability is verified in both directions against `age(1)`, not just round-tripped:**
the reference binary decrypts a container Tallow produced, and Tallow decrypts a container `age`
produced with the same identity. `tests/age_container.rs` **3/3** (round-trip, tamper → refusal,
reference-binary interop, the last skipped only where `age` is not installed).

**Native lowering: DONE 2026-10-24.** `crypto.age_keygen/age_encrypt/age_decrypt` now lower to the
native plane through `src/runtime/age_ffi.rs`; both planes call the same `src/age.rs`. Proven by
`tests/age_native_parity.rs` (2/2): `--require-native` succeeds with no fallback, a native container
opens in the interpreter and an interpreter container opens natively. Container sizes legitimately
differ between runs because the `age` crate inserts a random GREASE stanza — the test compares
behaviour, not bytes, so it cannot produce a false parity failure.

**Native lowering for `crypto.generate_keypair`: DONE 2026-10-24** (`ed25519`, `x25519`; any
other algorithm refuses by name and points at the interpreter). `tests/keypair_native_parity.rs`
(4/4): `--require-native` produces 32-byte keys, both planes report the same shape, and
whole-struct printing is refused with the fix named instead of reading the record as a string —
which it used to do, printing binary garbage.

**Chunked resumable transfer: DONE 2026-10-24** — as a *composition*, not a new format. `age`'s public
API writes one stream with no resume hook, and inventing a container would mean designing crypto, so a
transfer is a **directory of ordinary age containers**: one `.age` part (1 MiB default) plus a manifest
carrying the plaintext BLAKE3. Resume is "how many contiguous parts already exist"; each part has its
own ephemeral key, so no nonce is ever reused, and each part is decryptable by `age(1)` on its own.
Cost, stated: ~300 bytes of framing per part and one file per MiB (~0.03% overhead at 1 GiB).

`tests/age_stream.rs` (3/3): 2.5 MiB round-trip byte-identical; deleting a part resumes at exactly that
index (`resumed_from=2`); a tampered part fails the transfer; `age(1)` opens part 0 and returns exactly
the first MiB of the source.

**1 GiB run (the plan's own check), executed 2026-10-24:** 1,073,741,824 bytes, 1 MiB parts →
1,024 parts; the last part deleted, resumed at index 1023 in **20 s** against **410 s** for the full
encrypt (one part redone, not 1,024); decrypt **466 s**; `cmp` → **IDENTICAL**. Parts are atomic, so a
kill mid-transfer is the same recovery case as a deleted part.

**Native lowering: DONE 2026-10-24** — `age_encrypt_dir`/`age_decrypt_dir` lower through
`src/runtime/age_stream_ffi.rs`; `tests/age_stream.rs` is now 4/4, the fourth being
`--require-native` running the whole transfer (3 parts, 2.5 MB reassembled byte-identically, no
fallback message).

**Still open:** the optional ML-KEM recipient for the transfer path — those sit above this container in the transfer
module, not in the format.

### P5 — Key custody (3–5 days)
Keys never in argv or logs; `zeroize` on all secret types; OS keystore or HSM for long-lived keys;
release signing moved to a FROST threshold so no single operator holds the key; rotation drill.
**Display gate: DONE 2026-10-24** — and it found a live leak. `print()` of a struct rendered every
field, so `print(crypto.age_keygen())` wrote an `AGE-SECRET-KEY-1…` to stdout, and the same hole
exposed `KeyPair.private_key`, `MlDsaKeyPair`/`SlhDsaKeyPair`/`FalconKeyPair`/`FrodoKemKeyPair`/
`McElieceKeyPair`/`HpkeKeypair`/`VrfKeyPair`/`BlsKeyPair.secret_key` — nine struct types in total.
Redaction is now table-driven (`src/secret_fields.rs`), applied on both display paths, and
`tests/secret_display.rs` (5/5) proves: the private key never appears, `<redacted>` does, the public
half still prints, field access still returns the real value to the caller, and any *new* struct
with a secret-sounding field fails the gate until it is listed.

**Rotation drill: DONE 2026-10-24 (sandbox).** `docs/operations/key-rotation-runbook.md` covers every
key class the plan introduces, and `tests/rotation_drill.rs` (4/4) executes it against sandbox
material: the credential vault re-seals with a fresh nonce and the new secret (and refuses to invent
a missing entry); replacing an age keypair does **not** reopen containers sealed to the old identity,
which is what the retention-window step depends on; and an OPAQUE password change **without
re-registration yields a login that can never complete**, while re-registering restores it. That last
one is the failure an operator most needs warned about, so it is asserted rather than described.

**Not claimed:** this has not touched a production key. A real rotation still needs the operator's
secrets and confirmation that the downstream service accepted the new credential. Release signing is
out of automated scope for the same reason.

**Still open for P5:** `zeroize` coverage audit on the new types; release signing reproduced from a
clean checkout.

### P6 — Opt-in FHE/ZK (feature-gated, no schedule commitment)
`--features fhe` / `--features zk`. Default build stays small and auditable.
**Check:** feature builds pass the same lib suite; absent features refuse by name.

**ZK: DONE 2026-10-24.** `src/zk.rs` implements Bulletproofs range proofs over ristretto255 —
chosen over a bespoke construction because it needs no trusted setup and its security argument is
published. Surface: `crypto.zk_range_prove(value, bits, blinding)` → `{proof, commitment}` and
`crypto.zk_range_verify(proof, commitment, bits)` → `Bool`. `tests/zk_proof.rs` (4/4) proves:
round-trip with a compact proof, refusal to prove a value outside the stated range (a prover that
emitted a proof for a false statement would be a soundness hole, so it errors), commitment binding
(a proof does not verify against another value's commitment), and malformed input as `Err`, never a
panic. Domain-separated transcript `tallow.zk.range.v1`. Property-based cost: keygen is not needed,
proof generation is milliseconds at 32 bits. **Not claimed:** constant-time; the underlying dalek
arithmetic is variable-time in the documented places.

**FHE: built and measured 2026-10-24, behind `--features fhe`.** Backend `tfhe` 1.8.2 — the first
attempt failed because its integer API is behind a **non-default feature**, which is exactly the
class of assumption that breaks an ARM build silently. With `features = ["integer"]` the probe on
this box measured: keygen 1,436 ms, homomorphic add 174 ms, decrypt of 200+100 → **44** (modular
wraparound, as an unsigned byte should). Surface: `crypto.fhe_{keygen,encrypt,add,decrypt}` with an
in-process session handle; both halves refuse by name when the feature is off.

### P7 — Assurance (continuous)

**KATs: DONE for the hash, KDF and signature primitives 2026-10-24.** `tests/kats.rs` (5/5) checks
published vectors through the language surface: SHA-256 and SHA-384/SHA-512 against FIPS 180-4,
BLAKE3 against the specification (empty and `abc`), HKDF-SHA256 against RFC 5869 A.3, and Ed25519
against RFC 8032 §7.1 test 1 including the negative case. Two API facts fell out of writing them:
`crypto.verify` takes `(data, signature, public_key)`, and `hkdf_derive` takes `info` as a UTF-8
label while `ikm`/`salt` are hex — so a fixed binary `info` (RFC 5869 case 1) cannot be expressed,
and the suite uses case 3. Both are now documented at the declaration.

**cargo-fuzz harness: DONE 2026-10-24 (runs executed).** `fuzz/` is a detached crate
(`exclude = ["fuzz"]` in the workspace) with two libFuzzer targets over the crypto core:
`aead_decrypt` (attacker-controlled key, nonce, ciphertext and AAD against AES-GCM and XChaCha20) and
`sealed_object` (nonce + AES-KW-wrapped DEK parsed straight from the fuzzer). Both assert the same
load-bearing property: **a ciphertext that opens must round-trip** — so "accepted" can never mean
"returned mangled plaintext". Measured on this box: **2,358,971 executions / 101 s** (aead_decrypt)
and **1,587,576 executions / 101 s** (sealed_object), zero crashes, zero leaks.

Two deliberate scoping facts. First, the targets drive `crates/tallow-crypto`, not the monolithic
engine: building the engine's `tallow` lib under ASAN needs about **5.7 GB for a single codegen
unit**, which the cgroup OOM-killed three times on this 15 GB box — a fact worth writing down
because "just add a fuzz target" reads free and is not. Second, 100-second sessions exercise the
harness; they are not a substitute for a long-running corpus, which needs a dedicated runner.

**Mutation robustness sweep: DONE 2026-10-24.** `tests/mutation_robustness.rs` (2/2) mutates valid
inputs with a deterministic LCG and asserts nothing panics: 5,000 mutations of a real age container
(bit flips and truncation) and 3,000 of an OPAQUE setup/state. Measured: age accepted 2 of 5,000 — both
opened to the *original* plaintext, i.e. the flipped bytes were in the GREASE stanza that exists to be
ignored — and **0** authenticated different content; OPAQUE returned `Err` for 2,792 of 3,000. This is
the cheap half of fuzzing, not a replacement: a `cargo-fuzz` harness (nightly, corpus, coverage-guided)
is still owed.

**dudect-style AEAD timing harness: DONE (manual) 2026-10-24.** `tests/timing_aead.rs` runs two
input classes interleaved over 20,000 samples each and reports Welch's t on the wall-time
difference. Measured on this host: **mean 12,899.9 ns, welch t = -0.545** (|t| < 10 means the
timing is indistinguishable from noise). It is `#[ignore]`d deliberately: it measures a
distribution, and a shared VM's noise floor moves with unrelated builds — a gate that fails on
someone else's compile trains people to re-run until green. Blocking CI enforcement needs a
dedicated idle runner; until then the number is recorded here per release.
KATs from NIST ACVP; `dudect` timing harness on the AEAD/KEM paths; fuzzing on every parser;
SBOM and `cargo-deny` already exist and must include the new crates; signed SBOM in the release.

---

## 5. Assessment criteria (deliverable 3)

A release is "cryptographically acceptable" when every line below has a runnable check. Anything
that cannot be measured is not claimed.

**Correctness**
- KATs (NIST ACVP / RFC vectors) pass for every primitive exposed on the surface.
- Interpreter and native planes produce identical ciphertext *behaviour* (round-trip, refusal),
  under the existing `parity_runner` discipline.
- No algorithm confusion: the suite/algorithm ID is authenticated as associated data.

**Misuse resistance**
- AEAD APIs never expose unverified plaintext; nonce construction is internal.
- Reusing a key with a different algorithm is refused, not silently reinterpreted.
- Downgrade to classical-only is explicit and logged (negotiated group recorded).

**Secret hygiene**
- No secret in `Debug`, `Display`, panic messages, or error strings (the LLM path already redacts;
  this extends the same rule to all key material).
- `zeroize` on drop; keys never in argv; file permissions checked on key files.

**Side channels**
- Secret-dependent branches and table lookups absent from the primitives in use, or the exception
  is documented with a measurement.
- `dudect`-style timing test per AEAD/KEM path in CI (statistical pass, not a one-off run).

**Randomness**
- `getrandom` only; no userspace PRNG; startup self-check that the OS entropy source is available.

**Post-quantum readiness**
- Transport negotiates a hybrid group where both peers support it; `CNSA 2.0` profile selects
  ML-KEM-1024 / ML-DSA-87 / AES-256 / SHA-384.
- Signature migration path for release artefacts (ML-DSA alongside Ed25519 during transition).

**Supply chain**
- Pinned versions, `cargo-deny` clean, SBOM includes every crypto crate, release artefacts signed,
  reproducible build verified from a clean checkout.

**Honesty gate**
- The capability registry matches the dispatch table (P0 test); no arm may claim a standard
  construction it does not implement.

**Explicitly not claimed:** "undetectable", "unbreakable", "agency-grade". The measurable network
properties (padding, cover traffic, fingerprint uniformity, onion routing) are assessed separately
in the browser/egress docs, not here.

---

## 6. What not to do

* No proprietary or unpublished cipher, and no "agency secret" algorithm — unverifiable, unauditable.
* No Kyber draft parameters: FIPS 203 ML-KEM only (the wire formats differ).
* No home-grown threshold scheme: RFC 9591 or nothing.
* No FHE on an authentication path; no ZK proof standing in for a signature.
* No dual_EC-style opaque constants; every parameter comes from a published standard.
* No claim of stealth from a cipher — that claim belongs to the network layer and must be measured there.

---

## 7. Sources

* NSA, *Commercial National Security Algorithm Suite 2.0* — https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF
* NSA, *CNSA 2.0 and Quantum Computing FAQ* — https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
* NIST, FIPS 203/204/205 announcement — https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
* BSI, *TR-02102-1 Cryptographic Mechanisms* — https://bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf
* IETF, RFC 9180 (HPKE) — https://www.rfc-editor.org/info/rfc9180/
* IETF, RFC 9420 (MLS) — https://www.rfc-editor.org/info/rfc9420/
* IETF, RFC 9591 (FROST) — https://www.rfc-editor.org/info/rfc9591/
* IETF, RFC 8998 (SM2/SM3/SM4 in TLS 1.3) — https://www.rfc-editor.org/info/rfc8998/
* IETF, RFC 6986 / RFC 7091 (GOST Streebog / GOST R 34.10-2012)
* Signal, *The PQXDH Key Agreement Protocol* — https://signal.org/docs/specifications/pqxdh/pqxdh.pdf
* C2SP, *age* format — https://github.com/C2SP/C2SP/blob/main/age.md
* Tresorit, *Encryption Whitepaper* — https://cdn.tresorit.com/202208011608/tresorit-encryption-whitepaper.pdf
* Noise Protocol Framework, rev 34 — https://noiseprotocol.org/noise_rev34.html
* Cryspen, *libcrux* — https://github.com/cryspen/libcrux
* Zama, *TFHE-rs* — https://github.com/zama-ai/tfhe-rs/
* AWS, *aws-lc-rs* FIPS certificates #5314 / #5298 — https://github.com/aws/aws-lc-rs/releases/tag/v1.18.0
* SoK: *Understanding zk-SNARKs* — https://arxiv.org/html/2502.02387v2
* DEF CON 33, *Post Quantum Panic* — https://www.youtube.com/watch?v=OkVYJx1iLNs
