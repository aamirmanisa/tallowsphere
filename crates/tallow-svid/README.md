<div align="center">

# tallow-svid

**Workload identity with a short life, a defined issuer, and a revocation list that is checked before use.**

![model](https://img.shields.io/badge/model-SPIFFE--style-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

A long-lived certificate on a server is a permanent password with a nice name. Workload identity replaces it: the workload proves who it is, receives a credential scoped to what it does, and the credential expires — and if the workload is revoked, the list says so before anyone acts on it.

## What it is

| Module | Responsibility |
|---|---|
| `model` | Identity model: trust domain, workload ID, SVID shape |
| `issuer` | Certificate issuance and DER parsing (Ed25519, SAN, basic constraints) |
| `join` | Join flow — how a workload proves it may receive an SVID |
| `verify` | Verification of an SVID against the trust bundle |
| `policy` | Which workload may receive which identity |
| `rotation` | Rotation schedule and overlap |
| `revocation` | Signed revocation entries and lists: 64-byte signatures, 6-hour maximum age, 5-minute clock skew |
| `relay_auth` | Relay authentication using SVID identity |
| `workload` | Runtime side: fetch, hold and present the credential |
| `wire` | Encoding of requests and responses |

The revocation list is the part most systems get wrong. Here it is explicit: an entry may be an X.509 serial or a workload ID, it is signed, it has a validity window, and `check_freshness` refuses a list older than the bound. A stale revocation list is a failure, not a permissive default.

## What it is not

- **Not a full SPIFFE implementation.** SPIFFE-style in shape — trust domain, workload identity document, SVID — not a claim of conformance to the SPIFFE spec.
- **Not a public CA.** The issuer is yours; there is no ACME, no public transparency log.
- **Not a secrets store.** An SVID proves identity; it does not carry application secrets.
- **Not magic.** If the workload cannot keep a private key private, rotation shortens the damage window and nothing more.

## Quick start

```rust
use tallow_svid::revocation::{RevocationEntry, RevocationList, RevocationReason};

// An entry names the workload (or X.509 serial), the reason, and when it takes effect.
let entry = RevocationEntry::unsigned(
    "spiffe://tallow.local/workload/worker-7",
    RevocationReason::KeyCompromise,
    1_700_000_000,
)?;

// The list is sealed and signed by the revocation authority; entries must
// already carry their 64-byte signatures.
let list = RevocationList::sign(&authority_key, seq, issued_at, vec![entry])?;
list.verify(&authority_pubkey)?;

// Staleness is a refusal, not a warning.
list.check_freshness(now_secs, 6 * 3600)?;
assert!(list.is_revoked("spiffe://tallow.local/workload/worker-7"));
```

Constants that define the contract:

| Constant | Value | Meaning |
|---|---|---|
| `SIGNATURE_LEN` | 64 | Ed25519 signature length in an entry |
| `REVOCATION_MAX_AGE_SECS` | 6 h | A list older than this is not usable |
| `MAX_CLOCK_SKEW_SECS` | 300 | Tolerated clock difference when checking validity |
| `LIST_VERSION` | 1 | Revocation list format version |

## Configuration

The crate reads no environment variables and has no configuration file. A trust domain, an issuer key and a revocation authority are constructor arguments, because a workload identity layer that can be redirected by an environment variable is a workload identity layer an attacker can redirect.

Rotation parameters (TTL and overlap) are explicit in `rotation`; overlap exists so a new SVID can be issued before the old one expires without a gap.

## Deploying it

The issuer is the sensitive component. Run it where the keys are, and never where the workloads are:

```ini
# /etc/systemd/system/tallow-svid-issuer.service
[Service]
ExecStart=/usr/local/bin/tallow-svid-issuer --config /etc/tallow/svid.toml
User=tallow-svid
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/tallow-svid
```

Operational rules:

- **Short TTL, real rotation overlap.** A TTL longer than your incident response time is a TTL that outlives the incident.
- **Publish the revocation list on a schedule shorter than its maximum age.** A list that goes stale stops protecting anything, because checks fail closed.
- **Keep issuer keys off workload hosts.** The whole point of a join flow is that a compromised workload cannot mint identities.
- **Pin the trust bundle.** Workloads must not accept an SVID from a different issuer that happens to have a similar name.

## Design notes

**Why revocation is a signed list, not a CRL URL.** Fetching an unsigned or unverifiable list at request time is an availability dependency that fails open in practice. A signed list with a freshness bound fails closed and can be cached.

**Why explicit clock skew.** Distributed hosts disagree about time. A fixed, small tolerance makes the disagreement a documented parameter instead of a mystery intermittently-expired credential.

**Why DER parsing lives here.** Issuance and verification must agree on exactly what was signed; delegating that to two different libraries is how signature checks drift.

## Verification

```console
$ cargo test -p tallow-svid
$ cargo test -p tallow-svid revocation -- --nocapture
$ cargo test -p tallow-svid issuer -- --nocapture
```

150 test functions in the crate source [measured 2026-10-21]: DER encoding and parsing edges, sign/verify and tamper cases, freshness boundaries, skew boundaries, rotation overlap, and relay authentication.

## Limits

| Limit | Detail |
|---|---|
| SPIFFE-style, not SPIFFE-conformant | The model is similar; conformance is not claimed |
| No transparency log | Issuance is not externally auditable beyond your own logs |
| Ed25519 only | No RSA or ECDSA issuers |
| No workload attestation plugins | The join flow is the hook; attestation sources are yours |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
