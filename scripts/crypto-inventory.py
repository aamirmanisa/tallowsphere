#!/usr/bin/env python3
"""crypto-inventory.py — crypto-agility registry + CBOM seed generator and drift gate (T-206, Nixe/Tallow).

Scoping refs: research/tallow-security-2026-09-12/final/20-future-architecture.md
(P4-8/P10-R04 "agility registry + alarms + CBOM", R-P9-15), final/04-new-features.md
("purpose x lifecycle-state x PQ-flag registry ... CI assertion that every use site
resolves to a registered id"), final/18-attack-surface.md ("downgrade alarms depend
on the agility registry that does not exist yet"), DISPOSITIONS.md #50-#56/#104.

This is the seed of the crypto-agility registry (P4-8): a static, deterministic
analyzer over the crypto source roots that emits "tallow-cbom-seed/1" JSON — a
CBOM-style inventory with, per algorithm: name, family, role (kem/sig/aead/
cipher/hash/mac/kdf/pake/group/keywrap/protocol), quantum-resistance class,
lifecycle-transition seed dates, and
usage sites (relative file -> lexical occurrence count). The embedded REGISTRY is
the allowlist: --check fails when

  (a) a crypto-shaped token found in source is not covered by any registered
      algorithm ("new algorithms must be consciously registered"), or
  (b) an active registered algorithm disappears from source (lifecycle drift), or
  (c) the committed artifact does not byte-match regeneration, or
  (d) a REJECTED primitive (Ed448/X448 — REJECTED_PRIMITIVES below) appears in
      the scanned roots; registering them is NOT a path (P10-R14 guardrail,
      matrix #172/#173: "no Ed448/X448"), or
  (e) a novel AEAD / unregistered cipher-suite token appears (AES modes beyond
      GCM, Ascon/Deoxys/NORX/... families): "no novel AEADs" (P10-R14) means
      any AEAD outside the registered set needs a conscious REGISTRY entry
      (with rationale) before the gate can pass, or
  (f) AEGIS (either registered variant — AEGIS-128L and AEGIS-256 each have
  their own entry since E-3-08) is referenced outside crates/tallow-crypto/:
  AEGIS is "optional at most" — feature-gated, never a default AEAD (report
  §10.6 item 8). Exactly one explicit, annotated exception exists
  (AEGIS_OUTSIDE_ALLOWLIST, E-2-01): the two stdlib entry points in
  src/stdlib/crypto.rs; any other site — file or scan root — still fails.
  W2-11 closes E-2-01 §1(c)/§3's dependency half with the narrower gate:
  the root-level `aegis` dependency is now optional behind the non-default
  `aegis` feature (root Cargo.toml), so default builds link no AEGIS code
  and the entry points compile to honest "not enabled" errors. The
  surviving file allowance is occurrence-ceilinged
  (AEGIS_ALLOWANCE_CEILING) so a second AEGIS endpoint in that file cannot
  land silently; raising the ceiling is a conscious, recorded edit.

POLICY / ONE PARAMS SOURCE (matrix #172/#173 → P10-R14): the primitive set is
deliberately small and this REGISTRY is its single source of truth. Per-use-site
parameters (key sizes, nonce lengths, KDF cost parameters, ...) must derive from
or be cross-checked against the central tallow-crypto definitions and REGISTRY
entries — never re-declared in a second algorithm/parameters table (P10-F6:
Argon2id constants were found duplicated ×4 across crate/vault plumbing; the fix
is one implementation + versioned container-header params, and this gate is the
alarm that surfaces a competing source). The machine-readable form of all of the
above is emitted in the artifact's "policy" object — an additive extension of
format "tallow-cbom-seed/1" (every pre-existing key is unchanged).

Counts are lexical mentions (identifiers/strings/comments) of the registered token
patterns per file — usage *sites*, not runtime call counts. Hybrid constructs count
each component algorithm (e.g. X25519MLKEM768 contributes to both X25519 and ML-KEM).

Conventions mirror scripts/sbom-gen.py (T-114): REPO_ROOT-relative paths, canonical
rendering, --write/--check PATH, exit codes 0=ok, 1=drift, 2=generator error. Fully
static: no build, no network, no cargo — safe for CI and cheap to run.

Usage (run from the repo root):
  python3 scripts/crypto-inventory.py                                       # print CBOM seed to stdout
  python3 scripts/crypto-inventory.py --write scripts/crypto-inventory.json # (re)write the artifact
  python3 scripts/crypto-inventory.py --check scripts/crypto-inventory.json # registry conformance + byte gate
  python3 scripts/crypto-inventory.py --check                               # registry conformance only
  python3 scripts/crypto-inventory.py --check --root /tmp/sim/crates/tallow-crypto/src \
                                             --root /tmp/sim/crates/tallow-net/src   # drift drill (test roots)
  python3 scripts/crypto-inventory.py --self-test                           # guardrail self-test (temp fixtures, no repo writes)

Registering a new algorithm (required whenever the gate reports an unregistered
or novel-AEAD token, or deliberately retiring one): add/edit its entry in
REGISTRY below (with rationale), run `--write scripts/crypto-inventory.json`,
and commit script + artifact together. Rejected primitives (REJECTED_PRIMITIVES)
can never be registered — remove the use site instead.

Exit codes: 0 = ok / no drift; 1 = registry or artifact drift; 2 = generator error.

Artifact shape ("tallow-cbom-seed/1"):

  {
    "format": "tallow-cbom-seed/1",
    "generator": "scripts/crypto-inventory.py",
    "registrySha256": "<sha256 of canonical embedded REGISTRY — changes when the registry changes>",
    "scanRoots": ["crates/tallow-crypto/src", "crates/tallow-net/src", "src/vault", "src/stdlib/crypto.rs"],
    "registryEntryCount": N,          # registered algorithm ids (allowlist size)
    "algorithmCount": M,             # registered algorithms actually present in source
    "totalOccurrences": T,           # sum of per-file lexical occurrence counts
    "unregisteredCandidates": [...], # crypto-shaped tokens found but not registered (must be empty to pass)
    "policy": {                      # registry-enforced primitive-set guardrail (U-106; additive key)
      "policyRef": [...],            # policy sources (P10-R14, matrix #172/#173, report §10.6)
      "policySha256": "...",         # sha256 of the canonical POLICY block (rule edits become visible)
      "oneParamsSource": {...},      # machine-readable "one params source" statement
      "rejectedPrimitives": [...],   # Ed448/X448 rule entries (name/reason/policyRef); never registerable
      "rejectedPrimitivesFound": [], # MUST be empty: rejected tokens present in source (name/occurrences/sites)
      "novelAeadCandidates": [],     # MUST be empty: AEAD/cipher-suite tokens outside the registered set
      "aegisStance": {...},          # "AEGIS optional at most" stance (feature-gated, never a default AEAD)
      "aegisSitesOutsideTallowCrypto": [],      # MUST be empty: unexcused AEGIS use outside crates/tallow-crypto/
      "aegisAllowedOutsideTallowCrypto": [],    # conscious single exception(s) (AEGIS_OUTSIDE_ALLOWLIST; E-2-01) — never blanket
      "aegisAllowanceCeiling": {...},           # per-allowed-file registered-variant occurrence ceiling (W2-11, E-2-01 §3 follow-up)
      "aegisAllowanceOccurrences": {...}        # measured census that the ceiling is checked against (W2-11)
    },
    "algorithms": [
      {"family":"...","name":"...","occurrences":K,"pqTransition":{...}|null,
       "quantumResistance":"...","role":"...","sites":[{"count":C,"file":"..."},...],"state":"active"},
      ...
    ]   # sorted by name; one line per algorithm so diffs are line-per-algorithm
  }
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# E-1-02 (2026-09-13): extended to cover the two previously-ungoverned crypto
# surfaces — src/vault (at-rest vault: .twv v1/v2, key custody, PQC layer) and
# src/stdlib/crypto.rs (the largest crypto TCB in the tree; file root).
# Design: research/tallow-v1/cycle-02/07-crypto-design.md §D4.
DEFAULT_ROOTS = (
    "crates/tallow-crypto/src",
    "crates/tallow-net/src",
    "src/vault",
    "src/stdlib/crypto.rs",
)

# Seed lifecycle-clock data (P4-8 / DISPOSITIONS #104): NIST IR 8547 classifies
# classical public-key algorithms as deprecated after 2030 and disallowed after 2035.
IR8547_CLASSICAL = {
    "source": "NIST IR 8547",
    "deprecate": "2030",
    "disallow": "2035",
}

# ---------------------------------------------------------------------------
# REGISTRY — the allowlist. A crypto token found in source that is not covered
# by one of these entries fails --check; an `active` entry with zero use sites
# also fails. Fields: name (canonical registry id seed), family (standard
# provenance), role in {kem,sig,aead,cipher,hash,mac,kdf,pake,group,keywrap,
# protocol} — `cipher` (symmetric ciphers / format-preserving encryption) and
# `protocol` (the Noise framework) were added by E-3-08,
# quantumResistance in {post-quantum, classical-vulnerable,
# symmetric-grover-halved}, state in {active, reserved}, pqTransition (seed
# migration dates or None), patterns (case-sensitive regexes detecting use sites).
# ---------------------------------------------------------------------------
REGISTRY = [
    {
        "name": "ML-KEM",
        "family": "ML-KEM (FIPS 203, ex-Kyber)",
        "role": "kem",
        "quantumResistance": "post-quantum",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"ML-?KEM(?:-?\d+)?", r"MlKem\d*", r"Kyber\d*"],
    },
    {
        "name": "ML-DSA",
        "family": "ML-DSA (FIPS 204, ex-Dilithium)",
        "role": "sig",
        "quantumResistance": "post-quantum",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"ML-?DSA(?:-?\d+)?", r"MlDsa\d*", r"Dilithium\d*"],
    },
    {
        "name": "SLH-DSA",
        "family": "SLH-DSA (FIPS 205, ex-SPHINCS+)",
        "role": "sig",
        "quantumResistance": "post-quantum",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SLH-?DSA\w*", r"SlhDsa\w*", r"SPHINCS\+?"],
    },
    {
        "name": "X25519",
        "family": "X25519 / Curve25519 (RFC 7748)",
        "role": "kem",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"X25519", r"Curve25519"],
    },
    {
        "name": "Ed25519",
        "family": "Ed25519 (RFC 8032)",
        "role": "sig",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"Ed25519"],
    },
    {
        "name": "AES-256-GCM",
        "family": "AES-256-GCM (FIPS 197 / SP 800-38D)",
        "role": "aead",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"AES-?256(?:-GCM)?", r"Aes256Gcm"],
    },
    {
        # Registered consciously when the ECHConfigList work (U-105) landed and
        # the gate reported this token: AES-128-GCM is the RFC 9849 ECH
        # mandatory HPKE suite (ECHConfig protection + GREASE-ECH placeholder,
        # via the rustls aws-lc-rs suite DH_KEM_X25519_HKDF_SHA256_AES_128).
        # It is NOT the payload AEAD (payloads stay AES-256-GCM /
        # ChaCha20-Poly1305). An active entry keeps the presence requirement:
        # if ECH leaves the tree, retire this entry consciously in the same
        # change (--write).
        "name": "AES-128-GCM",
        "family": "AES-128-GCM / TLS_AES_128_GCM_SHA256 (FIPS 197, SP 800-38D) — RFC 9849 ECH "
        "mandatory HPKE suite (ECHConfig + GREASE placeholder); not a payload-protection "
        "primitive",
        "role": "aead",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"AES[-_]?128(?:[-_]GCM)?\b"],
    },
    {
        "name": "ChaCha20-Poly1305",
        "family": "ChaCha20-Poly1305 (RFC 8439; XChaCha20: draft-irtf-cfrg-xchacha)",
        "role": "aead",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"XChaCha20(?:Poly1305)?", r"ChaCha20(?:Poly1305)?"],
    },
    {
        # E-3-08 granularity split (closes E-2-01 §3 item 4): the former catch-all
        # pattern `AEGIS-?\d*` silently covered every AEGIS spelling — including
        # AEGIS-128L, the DEFAULT variant of crypto.encrypt_aegis. The entry is
        # now variant-explicit; AEGIS-128L has its own entry below and the
        # outside-crate rule covers both variants (AEGIS_VARIANT_ENTRIES).
        "name": "AEGIS-256",
        "family": "AEGIS (AEGIS-256, IRTF CFRG draft) — variant-explicit entry "
        "(the stdlib crypto.encrypt_aegis default variant is AEGIS-128L; own entry)",
        "role": "aead",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"AEGIS-?256", r"Aegis256", r"aegis_?256"],
    },
    {
        # E-3-08: dedicated registry entry for the AEGIS-128L variant (the
        # default of crypto.encrypt_aegis / decrypt_aegis) — previously matched
        # the AEGIS-256 entry's catch-all scan pattern without being separately
        # registered. The superseded bare AEGIS-128 (non-L) spelling stays
        # deliberately OUT of the registry: it now alarms (see the self-test
        # negative case), instead of silently passing as "some AEGIS".
        "name": "AEGIS-128L",
        "family": "AEGIS-128L (IRTF CFRG draft) — default variant of the stdlib "
        "crypto.encrypt_aegis / crypto.decrypt_aegis entry points",
        "role": "aead",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"AEGIS-?128L\b", r"Aegis128L", r"aegis_?128l"],
    },
    {
        "name": "Argon2id",
        "family": "Argon2 (RFC 9106)",
        "role": "kdf",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"Argon2\w*"],
    },
    {
        "name": "HKDF",
        "family": "HKDF (RFC 5869)",
        "role": "kdf",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"HKDF(?:-SHA\d+)?"],
    },
    {
        "name": "BLAKE3",
        "family": "BLAKE3",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"BLAKE3"],
    },
    {
        "name": "SHA3-256",
        "family": "SHA-3 (FIPS 202)",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SHA3(?:-?\d+)?"],
    },
    {
        "name": "SHA-256",
        "family": "SHA-2 (FIPS 180-4)",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SHA-?256"],
    },
    {
        "name": "HMAC",
        "family": "HMAC (RFC 2104)",
        "role": "mac",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"HMAC"],
    },
    {
        "name": "Poly1305",
        "family": "Poly1305 (RFC 8439)",
        "role": "mac",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        # The lookbehind keeps the plain MAC distinct from the ChaCha20-Poly1305
        # AEAD suffix: only standalone Poly1305 mentions count here.
        "patterns": [r"(?<!ChaCha20)Poly1305"],
    },
    {
        "name": "Ristretto255",
        "family": "Ristretto255 (RFC 9496)",
        "role": "group",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"Ristretto\w*"],
    },
    {
        "name": "CPace",
        "family": "CPace (draft-irtf-cfrg-cpace)",
        "role": "pake",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"CPace"],
    },
    # ------------------------------------------------------------------
    # E-2-01 registration pass (2026-09-13) — clears the intentional red
    # delta recorded by E-1-02 (research/tallow-v1/exec/E-1-02-crypto-mechanicals.md
    # §2.5): 11 unregistered tokens + 4 AEAD-suite tokens found when the scan
    # roots were extended to src/vault + src/stdlib/crypto.rs. Skeletons per
    # research/tallow-v1/cycle-02/07-crypto-design.md §D4 step 3.
    # Registration (not rejection) rationale, one line per family: every entry
    # below has a live, real implementation or dispatch site in the extended
    # roots (never a mock body — E-1-02 neutralized those). Grouping follows the
    # registry house rule: spelling variants of one algorithm share an entry
    # (SHA-512=SHA512 spelling, AES-256-GCM-SIV suite); distinct functions /
    # security levels get their own (SHAKE128 vs SHAKE256). Falcon-512/1024 are
    # parameter sets of one family (cf. ML-KEM) -> one entry, whose family text
    # records the distinct C-backed trust class (cycle-01 P2#17).
    # ------------------------------------------------------------------
    {
        # Noise handshake-hash selection (src/stdlib/crypto.rs: "Noise_<pattern>_
        # 25519_ChaChaPoly_BLAKE2s"); the only BLAKE2 mention in the roots.
        "name": "BLAKE2s",
        "family": "BLAKE2s (RFC 7693) — Noise handshake-hash spelling "
        "(_25519_ChaChaPoly_BLAKE2s suite)",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"BLAKE2s"],
    },
    {
        # C-backed trust class (cycle-01 P2#17): pqcrypto-falcon is a PQClean C
        # implementation behind FFI (root Cargo.toml:121), unlike the pure-Rust
        # FIPS 203/204/205 crates. Real dispatch: crypto.generate_keypair_falcon/
        # sign_falcon/verify_falcon. Covers the Falcon, Falcon-512, Falcon-1024
        # tokens (one family, three parameter-set spellings).
        "name": "Falcon",
        "family": "Falcon (NIST PQC signature; pqcrypto-falcon — C-backed PQClean, "
        "distinct trust class, not pure-Rust) — covers Falcon / Falcon-512 / Falcon-1024",
        "role": "sig",
        "quantumResistance": "post-quantum",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"Falcon-?\d*"],
    },
    {
        # Second KDF family (with Argon2id): real pbkdf2_hmac::<Sha256> worker
        # (PBKDF2-HMAC-SHA-256 600K iterations, SP 800-132) + kdf dispatch.
        "name": "PBKDF2",
        "family": "PBKDF2 (RFC 8018 / SP 800-132) — PBKDF2-HMAC-SHA-256, 600K "
        "iterations (stdlib password-KDF alongside Argon2id)",
        "role": "kdf",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"PBKDF2"],
    },
    {
        # CNSA-2.0-era hash size: real SHA-384/HMAC-SHA-384/HKDF-SHA-384 sites
        # plus the compliance minimum-hash listing.
        "name": "SHA-384",
        "family": "SHA-384 (FIPS 180-4) — hash / HMAC-SHA-384 / HKDF-SHA-384 "
        "wiring in the stdlib crypto suite",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SHA-?384"],
    },
    {
        # One algorithm, two spellings in the tree: "SHA-512" (stdlib crypto /
        # ECVRF) and "SHA512" (src/vault/totp.rs algorithm id + tests) — one
        # entry covers both (cf. the SHA-256 entry covering SHA256).
        "name": "SHA-512",
        "family": "SHA-512 (FIPS 180-4) — covers the SHA-512 and SHA512 spellings "
        "(stdlib crypto + TOTP/ECVRF uses)",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SHA-?512"],
    },
    {
        # FIPS 202 XOF; distinct function/security level from SHAKE256 -> own
        # entry (the AES-128-GCM vs AES-256-GCM precedent).
        "name": "SHAKE128",
        "family": "SHAKE128 (FIPS 202 XOF) — extendable-output function",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SHAKE128"],
    },
    {
        "name": "SHAKE256",
        "family": "SHAKE256 (FIPS 202 XOF) — extendable-output function",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"SHAKE256"],
    },
    {
        # Third password-KDF option (crypto.hash_password/verify_password),
        # real scrypt::Params::recommended() + PHC-format verification. Both
        # lexical spellings ([Ss]crypt: crate path + type name) are counted.
        "name": "scrypt",
        "family": "scrypt (RFC 7914) — password hashing for crypto.hash_password / "
        "verify_password (alongside Argon2id and PBKDF2)",
        "role": "kdf",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"[Ss]crypt"],
    },
    {
        # RFC 8452 misuse-resistant AEAD with an explicit stdlib surface
        # (crypto.encrypt_gcm_siv / decrypt_gcm_siv). One entry covers all three
        # spellings the scanner finds; NOT a default AEAD — payload protection
        # stays AES-256-GCM / ChaCha20-Poly1305 (registered set unchanged).
        "name": "AES-256-GCM-SIV",
        "family": "AES-256-GCM-SIV (RFC 8452, misuse-resistant AEAD) — covers the "
        "AES-256-GCM-SIV / AES-GCM-SIV / GCM-SIV spellings (explicit stdlib surface, "
        "not a default AEAD)",
        "role": "aead",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [
            r"AES-?256-?GCM-?SIV",
            r"AES-?GCM-?SIV",
            r"(?<![0-9A-Za-z_])GCM-?SIV",
        ],
    },
    {
        # SP 800-38F / RFC 3394 key wrap — a symmetric cipher-suite role of its
        # own ('keywrap', added to the role enum for this pass), not an AEAD:
        # deterministic, no nonce. Real dispatch: crypto.key_wrap (128/192/256
        # KEK) + crypto.aes_key_wrap (AES-256-KW).
        "name": "AES-256-KW",
        "family": "AES-256-KW (SP 800-38F / RFC 3394 key wrap) — key-wrapping "
        "cipher suite (crypto.key_wrap / crypto.aes_key_wrap); not an AEAD",
        "role": "keywrap",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"AES-?256-?KW"],
    },
    # ------------------------------------------------------------------
    # E-3-08 DISCOVERY expansion registration pass (2026-09-13) — clears the
    # blind spot recorded by E-2-01 §3 item 1 / design §D4 step 4 (+ OQ-6:
    # full set): the 13 families below were present in the governed roots but
    # invisible to DISCOVERY (not even counted). Registration (not rejection)
    # rationale: every family has a live site in the roots and is lexical like
    # every other entry. Roles `cipher` (symmetric ciphers / FPE) and
    # `protocol` (Noise) are new enum values for this pass (header comment).
    # HONESTY NOTES (verbatim from the source): BBS registers the token family
    # whose implementation is an EXPERIMENTAL Ed25519 commitment approximation
    # (NOT pairing-based BBS+); FROST likewise (Shamir-split Ed25519, NOT
    # RFC 9591 — no DKG/aggregation); OPAQUE is an EXPERIMENTAL envelope
    # approximation (NOT RFC 9392 — no OPRF). Registering tracks presence, it
    # does not certify the construction — the family text says so.
    # ------------------------------------------------------------------
    {
        # REAL SM2DSA (OSCCA GM/T 0003) via the sm2 crate; default
        # distinguishing identifier per GB/T 32918.5.
        "name": "SM2",
        "family": "SM2 (OSCCA GM/T 0003 SM2DSA) — REAL via the sm2 crate "
        "(stdlib sm2_sign/sm2_verify; Ed25519-era simulation comment superseded)",
        "role": "sig",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])[Ss][Mm]-?2"],
    },
    {
        # REAL via sm3 crate (OSCCA standard).
        "name": "SM3",
        "family": "SM3 (OSCCA GM/T 0004) — REAL via the sm3 crate (stdlib sm3_hash)",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])[Ss][Mm]-?3"],
    },
    {
        # REAL via sm4+cbc crates, CBC mode only — a symmetric block cipher,
        # not an AEAD (role `cipher`, added this pass).
        "name": "SM4",
        "family": "SM4 (OSCCA GB/T 32907, 128-bit block cipher) — REAL via the "
        "sm4+cbc crates in CBC mode (stdlib sm4_encrypt/sm4_decrypt; not an AEAD)",
        "role": "cipher",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])[Ss][Mm]-?4"],
    },
    {
        # REAL via streebog crate (GOST R 34.11-2012, Streebog-256).
        "name": "Streebog",
        "family": "Streebog (GOST R 34.11-2012, 256-bit) — REAL via the streebog "
        "crate (stdlib gost_hash)",
        "role": "hash",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])[Ss]treebog\w*"],
    },
    {
        # REAL via kuznyechik+cbc crates, CBC mode (GOST R 34.12-2015).
        "name": "Kuznyechik",
        "family": "Kuznyechik / Grasshopper (GOST R 34.12-2015, 128-bit block "
        "cipher) — REAL via the kuznyechik+cbc crates in CBC mode (stdlib "
        "gost_encrypt/gost_decrypt; not an AEAD)",
        "role": "cipher",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])[Kk]uznyechik\w*"],
    },
    {
        # REAL bcrypt::hash at DEFAULT_COST (crypto.hash_password 'bcrypt'),
        # a third password-KDF option alongside Argon2id/scrypt/PBKDF2.
        "name": "bcrypt",
        "family": "bcrypt (OpenBSD/Provos-Song password hashing) — REAL via the "
        "bcrypt crate (crypto.hash_password 'bcrypt', DEFAULT_COST)",
        "role": "kdf",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])[Bb]crypt\w*"],
    },
    {
        # REAL BLS12-381 min_pk via the blst crate: bls_sign/bls_verify/
        # bls_aggregate; BLS_SIG_... G2 DST. One family, covers blst spellings.
        "name": "BLS",
        "family": "BLS signatures (BLS12-381, min_pk) — REAL via the blst crate "
        "(bls_sign/bls_verify/bls_aggregate; covers the blst crate/type spellings)",
        "role": "sig",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])BLS\w*", r"(?<![0-9A-Za-z_])blst\w*"],
    },
    {
        # REAL via spake2 crate over Ed25519Group. All-case family pattern: the
        # tree writes SPAKE2 (prose) / Spake2 / spake2_* (code) — all captured.
        "name": "SPAKE2",
        "family": "SPAKE2 PAKE (RFC 9382) — REAL via the spake2 crate over "
        "Ed25519Group (stdlib spake2_exchange/spake2_start)",
        "role": "pake",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])[Ss][Pp][Aa][Kk][Ee]2\w*"],
    },
    {
        # EXPERIMENTAL Argon2id + Ed25519 + BLAKE3 keyed-hash envelope aPAKE —
        # NOT RFC 9392 OPAQUE (no OPRF). Token also appears in tallow-crypto
        # pake/mod.rs ("OPAQUE is deferred to v2").
        "name": "OPAQUE",
        "family": "OPAQUE-style aPAKE — EXPERIMENTAL Argon2id + Ed25519 + BLAKE3 "
        "keyed-hash envelope approximation; NOT RFC 9392 OPAQUE (no OPRF — the "
        "separate OPRF entry is a distinct surface); fails closed per source notes",
        "role": "pake",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])OPAQUE\w*", r"(?<![0-9A-Za-z_])[Oo]paque\w*"],
    },
    {
        # EXPERIMENTAL Ed25519 commitment + signature approximation — NOT the
        # pairing-based BBS+ scheme (no selective disclosure; source notes say
        # so verbatim). Registers the BBS / BBS+ / bbs_* token family.
        "name": "BBS",
        "family": "BBS+ anonymous credentials — EXPERIMENTAL Ed25519 commitment + "
        "signature approximation (NOT pairing-based BBS+; no selective disclosure) "
        "— covers BBS / BBS+ / bbs_* helper spellings",
        "role": "sig",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])BBS\+?", r"(?<![0-9A-Za-z_])bbs_\w+"],
    },
    {
        # EXPERIMENTAL Shamir-split Ed25519 — NOT FROST (RFC 9591); no DKG, no
        # aggregation, threshold property absent (source notes verbatim).
        # Word-boundaried so "FROSTY"-style words never count.
        "name": "FROST",
        "family": "FROST threshold signatures — EXPERIMENTAL Shamir-split Ed25519 "
        "approximation; NOT RFC 9591 FROST (no DKG/aggregation, threshold property "
        "absent per source notes)",
        "role": "sig",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])FROST\b"],
    },
    {
        # REAL HMAC-based OPRF using BLAKE3 keyed hash (oprf_setup/blind/
        # evaluate/finalize). Distinct surface from the OPAQUE entry.
        "name": "OPRF",
        "family": "OPRF — REAL HMAC-based oblivious pseudorandom function using "
        "BLAKE3 keyed hash (stdlib oprf_setup/oprf_blind/oprf_evaluate/oprf_finalize)",
        "role": "mac",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])OPRF\b", r"(?<![0-9A-Za-z_])oprf_\w+"],
    },
    {
        # ECVRF-Ed25519-SHA512-TAI (draft-irtf-cfrg-vrf-15) via ed25519-dalek.
        "name": "VRF",
        "family": "VRF / ECVRF (draft-irtf-cfrg-vrf-15, Ed25519-SHA512-TAI) — "
        "Ed25519-based ECVRF (vrf_generate_keypair/vrf_prove/vrf_verify)",
        "role": "sig",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [
            r"(?<![0-9A-Za-z_])ECVRF\w*",
            r"(?<![0-9A-Za-z_])VRF\b",
            r"(?<![0-9A-Za-z_])vrf_\w+",
        ],
    },
    {
        # FF1-style format-preserving encryption (SP 800-38G family) — Feistel
        # construction with a BLAKE3 PRF in this tree (fpe_tokenize/
        # fpe_detokenize); a cipher mode, not an AEAD (role `cipher`).
        "name": "FF1",
        "family": "FF1-style format-preserving encryption (NIST SP 800-38G "
        "family) — Feistel construction with BLAKE3 PRF (fpe_tokenize/"
        "fpe_detokenize, ff1_encrypt); not an AEAD",
        "role": "cipher",
        "quantumResistance": "symmetric-grover-halved",
        "state": "active",
        "pqTransition": None,
        "patterns": [r"(?<![0-9A-Za-z_])FF1\b", r"(?<![0-9A-Za-z_])ff1_\w+"],
    },
    {
        # REAL via the snow crate: suite Noise_<pattern>_25519_ChaChaPoly_
        # BLAKE2s (noise_handshake/encrypt/decrypt). Role `protocol` (new):
        # the framework is not an AEAD itself and is not covered by an existing
        # enum value; its AEAD component is the registered ChaCha20-Poly1305.
        "name": "Noise",
        "family": "Noise Protocol Framework — REAL via the snow crate (suite "
        "Noise_<pattern>_25519_ChaChaPoly_BLAKE2s; stdlib noise_handshake/"
        "noise_encrypt/noise_decrypt; AEAD component = registered "
        "ChaCha20-Poly1305)",
        "role": "protocol",
        "quantumResistance": "classical-vulnerable",
        "state": "active",
        "pqTransition": dict(IR8547_CLASSICAL),
        "patterns": [r"(?<![0-9A-Za-z_])Noise\w*", r"(?<![0-9A-Za-z_])noise_\w+"],
    },
]

# Per-entry union regexes: each entry matches once per site, no self-double-count.
ENTRY_UNIONS = {
    e["name"]: re.compile("|".join("(?:%s)" % p for p in e["patterns"]))
    for e in REGISTRY
}

# ---------------------------------------------------------------------------
# REJECTED_PRIMITIVES — hard guardrail (P10-R14; matrix #172/#173; report
# phase10-crypto-profiles/10-crypto-target-draft.md §10.6 item 2: "Ed448/X448 —
# no interop demand, larger keys, not in crate"; agent-01 R-12). Rejected
# primitives are never registerable: if a rejected token appears anywhere in
# the scanned roots the gate fails and the only fix is removing/reworking the
# code. Matching is lexical like the registry patterns, so mentions in
# comments/strings count too — keep any necessary policy *discussion* outside
# the scanned crypto roots or reword it. The `(?<![0-9A-Za-z_])` lookbehind
# avoids false hits inside identifiers/hex literals (e.g. `0x448`, `fooX448`).
# ---------------------------------------------------------------------------
REJECTED_PRIMITIVES = [
    {
        "name": "Ed448",
        "reason": "exotic curve: no interop demand, larger keys, not in crate (report §10.6 item 2; agent-01 R-12)",
        "policyRef": "P10-R14 / matrix #172,#173",
        "patterns": [r"(?<![0-9A-Za-z_])Ed448\w*", r"(?<![0-9A-Za-z_])ed448\w*"],
    },
    {
        "name": "X448",
        "reason": "exotic curve: no interop demand, larger keys, not in crate (report §10.6 item 2; agent-01 R-12)",
        "policyRef": "P10-R14 / matrix #172,#173",
        "patterns": [r"(?<![0-9A-Za-z_])X448\b", r"(?<![0-9A-Za-z_])x448\b"],
    },
]

REJECTED_UNIONS = {
    e["name"]: re.compile("|".join("(?:%s)" % p for p in e["patterns"]))
    for e in REJECTED_PRIMITIVES
}

# ---------------------------------------------------------------------------
# Novel-AEAD classifier. Applied to the tokens DISCOVERY captures: a token is
# a "novel AEAD / unregistered cipher-suite" candidate when it is AEAD-shaped
# (an AEAD mode name, a symmetric-suite family prefix, or a modern AEAD family
# name) and does NOT full-match any registered AEAD-role pattern. `covered()`
# (a substring search) is deliberately laxer and would let e.g. "AES-256-OCB"
# pass via the AES-256-GCM entry — this classifier is exact-match based, so new
# modes/families surface even when they share a prefix with a registered entry.
# Scope note: detection is lexical and limited to the spellings captured by
# DISCOVERY; it is an alarm for conscious registration, not proof of
# completeness.
# ---------------------------------------------------------------------------
AEAD_SHAPE = re.compile(
    r"GCM|OCB\d*|CCM|EAX|SIV|AES|ChaCha|AEGIS"
    r"|Ascon\w*|Deoxys\w*|NORX\w*|MORUS\w*|Xoodyak\w*"
    r"|Elephant\w*|ISAP\w*|Ketje\w*|Gimli\w*|Salsa20\w*"
)
# Cover set for the classifier: registered AEAD entries plus consciously
# registered non-AEAD symmetric-suite roles. E-2-01 added 'keywrap' because
# AES-256-KW (SP 800-38F) is AEAD-shaped to AEAD_SHAPE only by its "AES"
# prefix: registering it consciously is precisely what the alarm asks for, so
# the conscious entry must cover. E-3-08 added 'protocol': a full Noise suite
# spelling written as one string (Noise_XX_25519_ChaChaPoly_BLAKE2s) is
# AEAD-shaped via its "ChaChaPoly" substring, and the registered Noise entry is
# the conscious coverage for Noise-suite spellings. Only registered roles
# count — the alarm still fires for any suite spelling with no entry.
CIPHER_SUITE_ROLES = ("aead", "keywrap", "protocol")
AEAD_COVER_PATTERNS = [
    p for e in REGISTRY if e["role"] in CIPHER_SUITE_ROLES for p in e["patterns"]
]


def novel_aead_token(token: str) -> bool:
    """True when a discovered token is AEAD-shaped but not in the registered AEAD set."""
    if not AEAD_SHAPE.search(token):
        return False
    return not any(re.fullmatch(p, token) for p in AEAD_COVER_PATTERNS)


def rejected_token(token: str) -> bool:
    """True when a discovered token matches a REJECTED_PRIMITIVES pattern."""
    return any(rx.search(token) for rx in REJECTED_UNIONS.values())


# ---------------------------------------------------------------------------
# AEGIS outside-root allowance (E-2-01, 2026-09-13; dependency half closed by
# W2-11, 2026-09-13). The stance rule itself is unchanged — AEGIS use sites
# belong inside crates/tallow-crypto/ — but src/stdlib/crypto.rs hosts the two
# explicit stdlib entry points (crypto.encrypt_aegis / crypto.decrypt_aegis),
# both `#[allow(dead_code)]`, reachable only through explicit crypto.* calls,
# never a default path.
#
# W2-11 applied E-2-01 §1(c)/§3's NARROWER of the two recorded options: the
# root-level `aegis` dependency is gated (optional = true, behind the
# non-default `aegis` feature in root Cargo.toml) instead of relocating the
# entry points into crates/tallow-crypto (the root crate still has no
# tallow-crypto dependency — W2-02 §OPEN P-2 — so relocation would first need
# that wiring). With the feature OFF the entry points compile to honest
# "not enabled" errors; no AEGIS code is linked into default builds.
#
# The allowance therefore SURVIVES this wave, and per E-2-01 §3's follow-up it
# now carries an occurrence ceiling (AEGIS_ALLOWANCE_CEILING below): the file is
# allowed, but only up to the recorded number of registered-variant tokens, so
# a future second endpoint/mention cannot pass silently. Single-file allowlist,
# not a blanket rule: any OTHER file still fails the gate.
# ---------------------------------------------------------------------------
AEGIS_OUTSIDE_ALLOWLIST = {
    "src/stdlib/crypto.rs": "explicit crypto.encrypt_aegis / crypto.decrypt_aegis entry "
    "points (#[allow(dead_code)]; feature-gated behind the non-default 'aegis' feature as "
    "of W2-11; reachable only via explicit crypto.* dispatch); the ONLY permitted AEGIS "
    "site outside crates/tallow-crypto/",
}

# E-2-01 §3 follow-up ("consider an occurrence ceiling if the allowance survives
# more than one wave"): measured W2-11 baseline = AEGIS-128L 15 + AEGIS-256 15 =
# 30 registered-variant occurrences in src/stdlib/crypto.rs. Exceeding a ceiling
# fails --check with an explicit message; raising it is a conscious edit of this
# constant (with the reason recorded in the same change) or, better, the
# relocation option above. Ceilings are keyed by allowlisted file.
AEGIS_ALLOWANCE_CEILING = {
    "src/stdlib/crypto.rs": 30,
}

# E-3-08: both registered AEGIS variants are governed by the same family-level
# outside-crate rule and the single annotated allowance above — AEGIS-128L must
# not slip past the "optional at most" policy now that it has its own entry
# (the other half of the granularity item). Keep in sync with the registry names.
AEGIS_VARIANT_ENTRIES = ("AEGIS-128L", "AEGIS-256")


# ---------------------------------------------------------------------------
# POLICY — machine-readable statement of the enforced guardrail (emitted in the
# artifact's "policy" object). "One params source": the REGISTRY above is the
# single source of truth for the primitive set; per-use-site parameters (key
# sizes, nonce lengths, KDF costs, ...) must derive from / be cross-checked
# against the central tallow-crypto definitions and REGISTRY entries, never a
# second algorithm/params table (P10-F6).
# ---------------------------------------------------------------------------
POLICY = {
    "policyRef": [
        "P10-R14 (small primitive set guardrail)",
        "matrix #172",
        "matrix #173",
        "final/06-crypto-architecture.md §6.2 guardrails",
        "phase10-crypto-profiles/10-crypto-target-draft.md §10.6 items 2 & 8",
    ],
    "oneParamsSource": {
        "rule": "REGISTRY (scripts/crypto-inventory.py) is the single source of truth for the "
        "primitive set; algorithm parameters at use sites must derive from / be cross-checked "
        "against the central tallow-crypto definitions, never a second algorithm/params table",
        "paramsSource": "scripts/crypto-inventory.py:REGISTRY (bound by registrySha256 in this artifact)",
        "enforcement": "--check fails on any crypto-shaped token not covered by a REGISTRY entry; "
        "the committed artifact is byte-gated, so registry/parameter changes land atomically with "
        "the artifact update (--write in the same change)",
        "history": "P10-F6 — Argon2id constants were duplicated x4 (crate vs vault plumbing); "
        "fix = one implementation + versioned params in the container header",
    },
    "rejectedPrimitives": [
        {"name": r["name"], "reason": r["reason"], "policyRef": r["policyRef"]}
        for r in REJECTED_PRIMITIVES
    ],
    "novelAeadRule": {
        "rule": "no novel AEADs: an AEAD/cipher-suite token outside the registered AEAD set must "
        "be consciously registered (with rationale) or removed before --check can pass",
        "registeredAeadSet": "REGISTRY entries with role 'aead'",
        "detection": "AEAD-shaped tokens captured by DISCOVERY that do not full-match a registered "
        "aead pattern (novelAeadCandidates must be empty)",
    },
    "aegisStance": {
        "rule": "AEGIS (AEGIS-128L / AEGIS-256) stays feature-gated and optional at most - never "
        "a default AEAD",
        "policyRef": "phase10-crypto-profiles/10-crypto-target-draft.md §10.6 item 8; P10-R14",
        "enforcement": "AEGIS use sites (both registered variants, per E-3-08) must stay inside "
        "crates/tallow-crypto/, with exactly one explicit annotated exception (E-2-01: "
        "AEGIS_OUTSIDE_ALLOWLIST — the stdlib entry points in src/stdlib/crypto.rs); "
        "aegisSitesOutsideTallowCrypto must be empty (it lists only unexcused sites) and "
        "aegisAllowedOutsideTallowCrypto records every conscious exception — a single-file "
        "allowance, never a blanket rule; the allowance is occurrence-ceilinged "
        "(aegisAllowanceCeiling vs aegisAllowanceOccurrences, W2-11) so a second AEGIS "
        "endpoint in the allowed file cannot land silently. The feature gate is asserted on "
        "BOTH sides: the crates/tallow-crypto manifest (optional dep behind 'aegis') and, "
        "since W2-11, the root manifest (aegis dependency optional behind the non-default "
        "'aegis' feature; the stdlib entry points compile to honest 'not enabled' errors "
        "without it) — E-2-01 §1(c)/§3's dependency-gate recommendation, narrower option.",
    },
}


def policy_digest() -> str:
    blob = json.dumps(POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# Broad crypto-shaped token detector used to catch *unregistered* algorithms.
# Deliberately wider than REGISTRY (includes Falcon, PBKDF2, scrypt, Ed448,
# X448, SHA-2, modern AEAD families, secp256k1, P-256/P-384 ...) so a newly
# introduced algorithm surfaces as a candidate and --check fails until it is
# consciously registered or removed. The novel-AEAD alternatives come first so
# e.g. "AES-256-OCB" is captured whole (and classified as an unregistered AEAD)
# instead of silently degrading to the covered prefix "AES-256".
# E-3-08: appended the 13 previously-blind family patterns (block at the end)
# and split the AEGIS alternative per variant — "AEGIS-128L" is captured whole
# and the superseded bare "AEGIS-128" / any unregistered AEGIS-nnn spelling now
# alarms (novel-AEAD shape) instead of silently matching the AEGIS-256 entry.
DISCOVERY = re.compile(
    r"AES-\d+-(?:GCM-SIV|GCMSIV|OCB\d*|CCM\d*|SIV|EAX|XTS|KW|CBC|CTR\d*)"
    r"|(?<![0-9A-Za-z_])(?:AES-)?GCM-?SIV\b"
    r"|(?<![0-9A-Za-z_])OCB\d*\b"
    r"|(?<![0-9A-Za-z_])(?:X)?Salsa20\w*"
    r"|(?<![0-9A-Za-z_])(?:Ascon|Deoxys|NORX|MORUS|Xoodyak|Elephant|ISAP|Ketje|Gimli)[-\w]*"
    r"|XChaCha20Poly1305|ChaCha20Poly1305|XChaCha20|ChaCha20"
    r"|X25519(?:MLKEM768)?|Curve25519|Ed25519|Ed448|X448"
    r"|ML-?KEM-?\d*|MLKEM\d*|MlKem\d*|Kyber\d*"
    r"|ML-?DSA-?\d*|MLDSA\d*|MlDsa\d*|Dilithium\d*|Falcon-?\d*"
    r"|AES-\d+(?:-GCM)?|Aes\d{3}Gcm"
    r"|AEGIS-?128L\b|AEGIS-?\d+|Argon2\w*|HKDF(?:-SHA\d+)?|PBKDF2|scrypt"
    r"|SHA3(?:-?\d+)?|SHA-?\d{3}|SHAKE\d+|BLAKE[23]\w*|HMAC|Poly1305"
    r"|Ristretto\w*|CPace|SPHINCS\+?|SLH-?DSA\w*|SlhDsa\w*"
    r"|secp256k1|P-25[56]"
    # -- E-3-08 DISCOVERY expansion (design §D4 step 4 + OQ-6 "full set") ------
    # The 13 previously-blind families (all live in src/stdlib/crypto.rs) are
    # now tokenized so --check *guards* them instead of only counting them.
    # Pattern notes (lexical scanner, not a parser):
    #   * SM family: [Ss][Mm] two-case form with optional hyphen (SM2/Sm2/sm2);
    #     the lookbehind keeps embedded spellings (SOFTHSM2_MODULE, crypto_sm2_*)
    #     from minting phantom tokens.
    #   * BLS/blst: one family, both spellings — the crate/type writing too
    #     (blst::min_pk, BLS_DST, BLS_SIG_BLS12381G2_XMD_...).
    #   * BBS / bbs_*: family token plus the experimental helper names.
    #   * SPAKE2 uses the all-case form — the tree writes the family in caps in
    #     prose (SPAKE2) and mixed/lowercase in code (Spake2/spake2_*).
    #   * FROST is word-boundaried so "FROSTY"-style words never tokenize;
    #     lowercase "frost_*" identifiers are deliberately NOT captured (none is
    #     an algorithm reference today) — honest non-detection note.
    #   * VRF word-boundaried; ECVRF/vrf_* cover the construct spellings.
    #   * FF1 word-boundaried + ff1_* helpers (hex literals like 0xFF1A never
    #     match thanks to the lookbehind).
    #   * Noise/noise_*: uppercase family + snake-case helper names; a full
    #     suite string (Noise_XX_25519_ChaChaPoly_BLAKE2s) stays covered by the
    #     registered Noise entry ('protocol' in CIPHER_SUITE_ROLES).
    r"|(?<![0-9A-Za-z_])[Ss][Mm]-?[234]"
    r"|(?<![0-9A-Za-z_])[Ss]treebog\w*"
    r"|(?<![0-9A-Za-z_])[Kk]uznyechik\w*"
    r"|(?<![0-9A-Za-z_])[Bb]crypt\w*"
    r"|(?<![0-9A-Za-z_])BLS\w*"
    r"|(?<![0-9A-Za-z_])blst\w*"
    r"|(?<![0-9A-Za-z_])[Ss][Pp][Aa][Kk][Ee]2\w*"
    r"|(?<![0-9A-Za-z_])OPAQUE\w*"
    r"|(?<![0-9A-Za-z_])[Oo]paque\w*"
    r"|(?<![0-9A-Za-z_])BBS\+?"
    r"|(?<![0-9A-Za-z_])bbs_\w+"
    r"|(?<![0-9A-Za-z_])FROST\b"
    r"|(?<![0-9A-Za-z_])OPRF\b"
    r"|(?<![0-9A-Za-z_])oprf_\w+"
    r"|(?<![0-9A-Za-z_])ECVRF\w*"
    r"|(?<![0-9A-Za-z_])VRF\b"
    r"|(?<![0-9A-Za-z_])vrf_\w+"
    r"|(?<![0-9A-Za-z_])FF1\b"
    r"|(?<![0-9A-Za-z_])ff1_\w+"
    r"|(?<![0-9A-Za-z_])Noise\w*"
    r"|(?<![0-9A-Za-z_])noise_\w+"
)


def registry_digest() -> str:
    blob = json.dumps(REGISTRY, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def display_path(p: Path) -> str:
    try:
        return str(p.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def scan(roots) -> dict:
    files = []
    for root in roots:
        base = Path(root)
        base = base if base.is_absolute() else REPO_ROOT / base
        if base.is_dir():
            files.extend(sorted(base.rglob("*.rs")))
        elif base.is_file():
            # E-1-02: file roots are supported so a single large module (e.g.
            # src/stdlib/crypto.rs) can be governed without dragging all of its
            # sibling modules into the CBOM.
            files.append(base)
        else:
            sys.stderr.write("crypto-inventory: scan root not found: %s\n" % base)
            sys.exit(2)
    seen = set()
    ordered = []
    for p in files:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            ordered.append(p)

    site_counts = {e["name"]: {} for e in REGISTRY}
    rejected_counts = {e["name"]: {} for e in REJECTED_PRIMITIVES}
    candidates = set()
    for p in ordered:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            sys.stderr.write("crypto-inventory: cannot read %s: %s\n" % (p, exc))
            sys.exit(2)
        rel = display_path(p)
        for e in REGISTRY:
            n = len(ENTRY_UNIONS[e["name"]].findall(text))
            if n:
                site_counts[e["name"]][rel] = n
        for e in REJECTED_PRIMITIVES:
            n = len(REJECTED_UNIONS[e["name"]].findall(text))
            if n:
                rejected_counts[e["name"]][rel] = n
        candidates.update(m.group(0) for m in DISCOVERY.finditer(text))

    def covered(token: str) -> bool:
        return any(re.search(p, token) for e in REGISTRY for p in e["patterns"])

    # Partition the discovered token set. Rejected primitives take precedence
    # (they are never registerable), then novel AEAD / cipher-suite shapes,
    # then the plain "not covered by any registered entry" candidates.
    unregistered = sorted(
        t
        for t in candidates
        if not covered(t) and not rejected_token(t) and not novel_aead_token(t)
    )
    novel_aeads = sorted(t for t in candidates if novel_aead_token(t) and not rejected_token(t))

    rejected_found = []
    for e in REJECTED_PRIMITIVES:
        sites = sorted(rejected_counts[e["name"]].items())
        if sites:
            rejected_found.append(
                {
                    "name": e["name"],
                    "occurrences": sum(c for _, c in sites),
                    "sites": [{"file": f, "count": c} for f, c in sites],
                }
            )

    algorithms = []
    total = 0
    present = 0
    for e in sorted(REGISTRY, key=lambda x: x["name"]):
        sites = sorted(site_counts[e["name"]].items())
        occ = sum(c for _, c in sites)
        total += occ
        if occ:
            present += 1
        algorithms.append(
            {
                "name": e["name"],
                "family": e["family"],
                "role": e["role"],
                "quantumResistance": e["quantumResistance"],
                "state": e["state"],
                "pqTransition": e["pqTransition"],
                "occurrences": occ,
                "sites": [{"file": f, "count": c} for f, c in sites],
            }
        )
    aegis_variant_sites = {
        f for name in AEGIS_VARIANT_ENTRIES for f in site_counts.get(name, {})
    }
    # E-3-08: family-level outside check over BOTH registered variants (the
    # former single-entry check let an AEGIS-128L-only outside site go silent).
    aegis_outside_all = sorted(
        f for f in aegis_variant_sites if not f.startswith("crates/tallow-crypto/")
    )
    # E-2-01: apply the explicit out-of-crate allowance (AEGIS_OUTSIDE_ALLOWLIST,
    # a single annotated file — never a blanket rule). aegisSitesOutsideTallowCrypto
    # keeps its contract: it lists only *unexcused* sites and MUST stay empty; the
    # conscious exception is recorded separately so the artifact stays auditable.
    aegis_allowed = sorted(f for f in aegis_outside_all if f in AEGIS_OUTSIDE_ALLOWLIST)
    aegis_outside = sorted(f for f in aegis_outside_all if f not in AEGIS_OUTSIDE_ALLOWLIST)
    # W2-11: occurrence census for the allowlisted files (registered variants
    # only) — the surviving allowance is ceilinged per E-2-01 §3's follow-up, so
    # raising the census beyond AEGIS_ALLOWANCE_CEILING fails --check.
    aegis_allowance_occurrences = {
        f: sum(site_counts.get(name, {}).get(f, 0) for name in AEGIS_VARIANT_ENTRIES)
        for f in AEGIS_OUTSIDE_ALLOWLIST
    }
    return {
        "format": "tallow-cbom-seed/1",
        "generator": "scripts/crypto-inventory.py",
        "registrySha256": registry_digest(),
        "scanRoots": [str(Path(r)) for r in roots],
        "registryEntryCount": len(REGISTRY),
        "algorithmCount": present,
        "totalOccurrences": total,
        "unregisteredCandidates": unregistered,
        "policy": {
            "policyRef": POLICY["policyRef"],
            "policySha256": policy_digest(),
            "oneParamsSource": POLICY["oneParamsSource"],
            "rejectedPrimitives": POLICY["rejectedPrimitives"],
            "rejectedPrimitivesFound": rejected_found,
            "novelAeadCandidates": novel_aeads,
            "aegisStance": POLICY["aegisStance"],
            "aegisSitesOutsideTallowCrypto": aegis_outside,
            "aegisAllowedOutsideTallowCrypto": aegis_allowed,
            "aegisAllowanceCeiling": dict(sorted(AEGIS_ALLOWANCE_CEILING.items())),
            "aegisAllowanceOccurrences": dict(sorted(aegis_allowance_occurrences.items())),
        },
        "algorithms": algorithms,
    }


def render(inv: dict) -> str:
    lines = [
        "{",
        '  "format": %s,' % json.dumps(inv["format"]),
        '  "generator": %s,' % json.dumps(inv["generator"]),
        '  "registrySha256": %s,' % json.dumps(inv["registrySha256"]),
        '  "scanRoots": %s,' % json.dumps(inv["scanRoots"]),
        '  "registryEntryCount": %d,' % inv["registryEntryCount"],
        '  "algorithmCount": %d,' % inv["algorithmCount"],
        '  "totalOccurrences": %d,' % inv["totalOccurrences"],
        '  "unregisteredCandidates": %s,' % json.dumps(inv["unregisteredCandidates"]),
        '  "policy": %s,' % json.dumps(inv["policy"], sort_keys=True, separators=(",", ":")),
        '  "algorithms": [',
    ]
    algs = inv["algorithms"]
    for i, a in enumerate(algs):
        comma = "," if i < len(algs) - 1 else ""
        lines.append("    " + json.dumps(a, sort_keys=True, separators=(",", ":")) + comma)
    lines += ["  ]", "}", ""]
    return "\n".join(lines)


def conformance_problems(inv: dict) -> list:
    problems = []
    policy = inv.get("policy", {})

    rejected = policy.get("rejectedPrimitivesFound") or []
    if rejected:
        detail = "; ".join(
            "%s (%d occurrence(s): %s)"
            % (
                r["name"],
                r["occurrences"],
                ", ".join("%s x%d" % (s["file"], s["count"]) for s in r["sites"]),
            )
            for r in rejected
        )
        problems.append(
            "REJECTED primitive(s) present: %s — policy P10-R14 (matrix #172/#173) rejects "
            "Ed448/X448 outright; registering them is not a path — remove or rework the "
            "use site(s)" % detail
        )

    novel = policy.get("novelAeadCandidates") or []
    if novel:
        problems.append(
            "novel AEAD / unregistered cipher-suite token(s): %s — no novel AEAD may land "
            "without conscious registration (P10-R14): register the algorithm in REGISTRY "
            "(with rationale) or remove it" % ", ".join(novel)
        )

    aegis_outside = policy.get("aegisSitesOutsideTallowCrypto") or []
    if aegis_outside:
        problems.append(
            "AEGIS ('optional at most' — AEGIS-128L/AEGIS-256; feature-gated, never a "
            "default AEAD; report §10.6 item 8) is used outside crates/tallow-crypto/: %s"
            % ", ".join(aegis_outside)
        )

    # W2-11 (E-2-01 §3 follow-up): the single annotated file allowance survives,
    # so it is occurrence-ceilinged — a new AEGIS mention/endpoint in an allowed
    # file must be a conscious, recorded decision, not a silent pass.
    ceilings = policy.get("aegisAllowanceCeiling") or {}
    census = policy.get("aegisAllowanceOccurrences") or {}
    over = [
        "%s: %d occurrence(s) > ceiling %d" % (f, census.get(f, 0), limit)
        for f, limit in sorted(ceilings.items())
        if census.get(f, 0) > limit
    ]
    if over:
        problems.append(
            "AEGIS allowance occurrence ceiling exceeded (%s) — the E-2-01 allowance is "
            "file-level; a new AEGIS mention/endpoint must be re-registered consciously: "
            "tighten the site, bump AEGIS_ALLOWANCE_CEILING with a recorded reason, or take "
            "the relocation option (entry points into crates/tallow-crypto)" % "; ".join(over)
        )

    if inv["unregisteredCandidates"]:
        problems.append(
            "unregistered crypto token(s): %s — a new algorithm must be consciously "
            "registered in REGISTRY (scripts/crypto-inventory.py) before the gate can pass"
            % ", ".join(inv["unregisteredCandidates"])
        )
    missing = [
        a["name"] for a in inv["algorithms"] if a["state"] == "active" and a["occurrences"] == 0
    ]
    if missing:
        problems.append(
            "active registered algorithm(s) with no use sites: %s — retire or reclassify "
            "their state in REGISTRY consciously" % ", ".join(missing)
        )
    return problems


# Fixture for --self-test: minimal Rust-ish text carrying every guardrail
# trigger, plus consciously registered cipher suites that must NOT trip it
# (E-2-01: AES-256-GCM-SIV / AES-256-KW cover). Written only into a temp dir
# by self_test() — never the repo.
SELFTEST_FIXTURE = """\
// U-106 guardrail self-test fixture (temp dir only, never committed).
pub const REJECTED_CURVE_1: &str = "Ed448";
pub const REJECTED_CURVE_2: &str = "X448";
pub fn uses_rejected_lowercase() -> &'static str { "x448" }
pub const NOVEL_AEAD_1: &str = "AES-256-OCB";
pub const NOVEL_AEAD_2: &str = "Ascon-AEAD128";
pub const OPTIONAL_ONLY: &str = "AEGIS-256";
pub const REGISTERED_AEAD_SUITE: &str = "AES-256-GCM-SIV";
pub const REGISTERED_KW_SUITE: &str = "AES-256-KW";
"""

# E-3-08: expanded-DISCOVERY fixture — one representative site per newly guarded
# family (all 13) so the extended REGISTRY coverage is pinned by the self-test
# itself. AEGIS-128L is exercised in its own fixture below (its outside-crate
# policy finding must fire, so it cannot sit in a must-stay-silent fixture).
# Non-detection notes (honest, deliberate): bare "AEGIS" family words and
# lowercase "frost_*" identifiers are NOT tokenized (see the DISCOVERY block);
# unregistered variant shapes (e.g. the superseded "AEGIS-128") MUST alarm —
# pinned by the negative check below.
SELFTEST_EXPANDED_FIXTURE = """\
// E-3-08 expanded-DISCOVERY fixture (temp dir only, never committed).
pub const NATIONAL_SIG: &str = "SM2";
pub const NATIONAL_HASH: &str = "SM3";
pub const NATIONAL_CIPHER: &str = "SM4-CBC";
pub const RU_HASH: &str = "Streebog-256";
pub const RU_CIPHER: &str = "Kuznyechik-CBC";
pub const PASSWORD_KDF: &str = "bcrypt";
pub const PAIRING_SIG: &str = "BLS12-381";
pub const PAKE: &str = "SPAKE2";
pub const APake: &str = "OPAQUE";
pub const CREDENTIALS: &str = "BBS+";
pub const THRESHOLD: &str = "FROST";
pub const OPRF_HELPER: &str = "oprf_blind";
pub const VRF_PROOF: &str = "ECVRF";
pub const FPE_HELPER: &str = "ff1_encrypt";
pub const NOISE_SESSION: &str = "NoiseSession";
"""


def self_test() -> int:
    """Guardrail self-test on throwaway temp fixtures (no repo writes).

    Checks (1) the guardrail stays silent on benign code, (2) rejected
    primitives + novel AEADs + stray AEGIS trip conformance exactly as
    designed, (3) the repo's default scan roots are currently green, and
    (4) E-3-08: the expanded DISCOVERY families are covered by the extended
    REGISTRY and the AEGIS variant granularity alarms correctly, and
    (5) W2-11: the AEGIS allowance occurrence ceiling passes at the limit and
    fails above it.
    """
    import tempfile

    failures = []

    def check(cond: bool, label: str) -> None:
        print(("  PASS " if cond else "  FAIL ") + label)
        if not cond:
            failures.append(label)

    with tempfile.TemporaryDirectory(prefix="crypto-inventory-selftest-") as tmp:
        tmp_path = Path(tmp)

        benign_root = tmp_path / "benign"
        benign_root.mkdir()
        (benign_root / "lib.rs").write_text(
            "pub fn add(a: u64, b: u64) -> u64 { a + b }\n", encoding="utf-8"
        )
        inv = scan([str(benign_root)])
        probs = conformance_problems(inv)
        check(inv["unregisteredCandidates"] == [], "benign fixture: no unregistered candidates")
        check(
            not any(
                ("REJECTED" in p) or ("novel AEAD" in p) or ("optional at most" in p) for p in probs
            ),
            "benign fixture: guardrail stays silent",
        )
        check(
            not (
                inv["policy"]["rejectedPrimitivesFound"]
                or inv["policy"]["novelAeadCandidates"]
                or inv["policy"]["aegisSitesOutsideTallowCrypto"]
            ),
            "benign fixture: policy findings empty",
        )

        bad_root = tmp_path / "rejected"
        bad_root.mkdir()
        (bad_root / "curves.rs").write_text(SELFTEST_FIXTURE, encoding="utf-8")
        inv = scan([str(bad_root)])
        probs = conformance_problems(inv)
        names = [r["name"] for r in inv["policy"]["rejectedPrimitivesFound"]]
        check(names == ["Ed448", "X448"], "rejected fixture: Ed448/X448 detected (%s)" % names)
        check(
            not (
                "Ed448" in inv["unregisteredCandidates"]
                or "X448" in inv["unregisteredCandidates"]
            ),
            "rejected fixture: rejected tokens not offered as registerable candidates",
        )
        check(
            "AES-256-OCB" in inv["policy"]["novelAeadCandidates"],
            "novel-AEAD fixture: AES-256-OCB flagged",
        )
        check(
            "Ascon-AEAD128" in inv["policy"]["novelAeadCandidates"],
            "novel-AEAD fixture: Ascon-AEAD128 flagged",
        )
        check(
            "AES-256-GCM-SIV" not in inv["policy"]["novelAeadCandidates"]
            and "AES-256-KW" not in inv["policy"]["novelAeadCandidates"],
            "registered cipher suites: AES-256-GCM-SIV + AES-256-KW covered, not re-flagged",
        )
        check(any("REJECTED" in p for p in probs), "conformance fails on rejected primitives")
        check(any("novel AEAD" in p for p in probs), "conformance fails on novel AEADs")
        check(any("optional at most" in p for p in probs), "conformance fails on stray AEGIS use")

        # -- E-3-08: expanded DISCOVERY (13 families) + AEGIS variant granularity
        expanded_root = tmp_path / "expanded"
        expanded_root.mkdir()
        (expanded_root / "families.rs").write_text(SELFTEST_EXPANDED_FIXTURE, encoding="utf-8")
        inv = scan([str(expanded_root)])
        probs = conformance_problems(inv)
        check(
            inv["unregisteredCandidates"] == [] and inv["policy"]["novelAeadCandidates"] == [],
            "expanded-DISCOVERY fixture: all families covered, none re-flagged (%r)"
            % (inv["unregisteredCandidates"] + inv["policy"]["novelAeadCandidates"]),
        )
        present = {a["name"] for a in inv["algorithms"] if a["occurrences"]}
        wanted = {
            "SM2", "SM3", "SM4", "Streebog", "Kuznyechik", "bcrypt", "BLS", "SPAKE2",
            "OPAQUE", "BBS", "FROST", "OPRF", "VRF", "FF1", "Noise",
        }
        check(
            wanted <= present,
            "expanded-DISCOVERY fixture: all 15 expanded entries have live sites "
            "(missing: %r)" % sorted(wanted - present),
        )
        check(
            not any(("REJECTED" in p) or ("optional at most" in p) for p in probs),
            "expanded-DISCOVERY fixture: no rejected/AEGIS findings",
        )

        aegis128l_root = tmp_path / "aegis-128l"
        aegis128l_root.mkdir()
        (aegis128l_root / "variant.rs").write_text(
            'pub const DEFAULT_VARIANT: &str = "AEGIS-128L";\n', encoding="utf-8"
        )
        inv = scan([str(aegis128l_root)])
        probs = conformance_problems(inv)
        check(
            inv["unregisteredCandidates"] == [] and inv["policy"]["novelAeadCandidates"] == [],
            "AEGIS-128L fixture: variant covered by its own entry (granularity split)",
        )
        check(
            any("optional at most" in p for p in probs),
            "AEGIS-128L fixture: outside-crate use still fails the optional-at-most rule",
        )

        bare_aegis_root = tmp_path / "bare-aegis"
        bare_aegis_root.mkdir()
        (bare_aegis_root / "mention.rs").write_text(
            'pub const FAMILY_WORD: &str = "AEGIS";\n', encoding="utf-8"
        )
        inv = scan([str(bare_aegis_root)])
        check(
            inv["unregisteredCandidates"] == [] and inv["policy"]["novelAeadCandidates"] == [],
            "bare AEGIS family mention: intentionally not tokenized (documented "
            "non-detection — variants, not family words, are the alarm surface)",
        )

        aegis128_root = tmp_path / "aegis-128"
        aegis128_root.mkdir()
        (aegis128_root / "old_variant.rs").write_text(
            'pub const OLD_VARIANT: &str = "AEGIS-128";\n', encoding="utf-8"
        )
        inv = scan([str(aegis128_root)])
        probs = conformance_problems(inv)
        check(
            "AEGIS-128" in inv["policy"]["novelAeadCandidates"],
            "AEGIS-128 (superseded, unregistered variant) now alarms instead of "
            "silently matching the AEGIS-256 entry",
        )
        check(
            any("novel AEAD" in p for p in probs),
            "conformance fails on the superseded AEGIS-128 variant",
        )

        # -- W2-11: allowance occurrence ceiling (E-2-01 §3 follow-up)
        ceiling_file = "src/stdlib/crypto.rs"
        limit = AEGIS_ALLOWANCE_CEILING[ceiling_file]

        def ceiling_fixture(census: int) -> dict:
            return {
                "policy": {
                    "aegisAllowanceCeiling": {ceiling_file: limit},
                    "aegisAllowanceOccurrences": {ceiling_file: census},
                },
                "unregisteredCandidates": [],
                "algorithms": [],
            }

        check(
            not any("occurrence ceiling" in p for p in conformance_problems(ceiling_fixture(limit))),
            "allowance ceiling fixture: census == ceiling stays green",
        )
        check(
            any(
                "occurrence ceiling" in p
                for p in conformance_problems(ceiling_fixture(limit + 1))
            ),
            "allowance ceiling fixture: census > ceiling fails the gate",
        )

    inv = scan(DEFAULT_ROOTS)
    probs = conformance_problems(inv)
    check(probs == [], "repo default scan roots: conformance green (problems: %r)" % probs)

    if failures:
        sys.stderr.write("crypto-inventory: SELF-TEST FAILED (%d check(s))\n" % len(failures))
        return 1
    print("crypto-inventory: guardrail self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate or check the crypto-agility registry CBOM seed (T-206)"
    )
    ap.add_argument("--write", metavar="PATH", help="write the CBOM seed artifact to PATH")
    ap.add_argument(
        "--check",
        metavar="PATH",
        nargs="?",
        const=True,
        help="registry conformance gate; with PATH, also fail if PATH differs "
        "from the regenerated artifact (byte gate)",
    )
    ap.add_argument(
        "--root",
        action="append",
        default=None,
        help="override scan root (repeatable, file or directory); for drift "
        "drills/tests only, defaults to the four governed crypto roots "
        "(tallow-crypto, tallow-net, src/vault, src/stdlib/crypto.rs)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the guardrail self-test on throwaway temp fixtures (no repo writes) "
        "and verify the default scan roots are green",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    roots = args.root if args.root else list(DEFAULT_ROOTS)
    inv = scan(roots)
    text = render(inv)

    if args.write:
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(
            "crypto-inventory: wrote %s (%d registered, %d present, %d occurrences)"
            % (out, inv["registryEntryCount"], inv["algorithmCount"], inv["totalOccurrences"])
        )
        if inv["unregisteredCandidates"]:
            sys.stderr.write(
                "crypto-inventory: note: %d unregistered candidate(s) recorded — "
                "--check will fail until they are registered: %s\n"
                % (len(inv["unregisteredCandidates"]), ", ".join(inv["unregisteredCandidates"]))
            )
        rejected_names = [r["name"] for r in inv["policy"]["rejectedPrimitivesFound"]]
        if rejected_names:
            sys.stderr.write(
                "crypto-inventory: note: REJECTED primitive(s) present — fix the use site(s), "
                "they cannot be registered: %s\n" % ", ".join(rejected_names)
            )
        if inv["policy"]["novelAeadCandidates"]:
            sys.stderr.write(
                "crypto-inventory: note: %d novel AEAD token(s) recorded — --check will fail "
                "until consciously registered or removed: %s\n"
                % (
                    len(inv["policy"]["novelAeadCandidates"]),
                    ", ".join(inv["policy"]["novelAeadCandidates"]),
                )
            )
        if inv["policy"]["aegisSitesOutsideTallowCrypto"]:
            sys.stderr.write(
                "crypto-inventory: note: AEGIS (optional at most) used outside "
                "crates/tallow-crypto/: %s\n"
                % ", ".join(inv["policy"]["aegisSitesOutsideTallowCrypto"])
            )
        return 0

    if args.check is not None:
        drift = False
        for problem in conformance_problems(inv):
            drift = True
            sys.stderr.write("crypto-inventory: REGISTRY DRIFT — %s\n" % problem)
        if isinstance(args.check, str):
            snapshot = Path(args.check)
            if not snapshot.is_file():
                sys.stderr.write("crypto-inventory: artifact %s not found\n" % snapshot)
                return 2
            expected = snapshot.read_text(encoding="utf-8")
            if expected == text:
                print(
                    "crypto-inventory: CBOM drift gate OK — regenerated artifact matches %s"
                    % snapshot
                )
            else:
                drift = True
                sys.stderr.writelines(
                    difflib.unified_diff(
                        expected.splitlines(keepends=True),
                        text.splitlines(keepends=True),
                        fromfile="%s (committed)" % snapshot,
                        tofile="regenerated",
                    )
                )
                sys.stderr.write(
                    "crypto-inventory: CBOM DRIFT — %s does not match the regenerated "
                    "artifact; update it in the same change:\n"
                    "  python3 scripts/crypto-inventory.py --write %s\n" % (snapshot, snapshot)
                )
        if drift:
            return 1
        if not isinstance(args.check, str):
            print(
                "crypto-inventory: registry OK — %d registered, %d present, %d occurrences, "
                "no unregistered tokens; guardrail enforced (no rejected primitives, "
                "no novel AEADs, AEGIS inside tallow-crypto or the single annotated "
                "occurrence-ceilinged allowance)"
                % (inv["registryEntryCount"], inv["algorithmCount"], inv["totalOccurrences"])
            )
        return 0

    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
