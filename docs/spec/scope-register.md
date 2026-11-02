# Scope register — outbound authorization gate

There was no existing doc page for this gate (`docs/intel/topology.md`
§"The scope gate" is cited from `docs/intel/handle-registry-design.md`
and does not exist in this tree). This page is that page.

## What it is

`src/scope.rs` is the authorization register for outbound targets.
Deny-by-default: a host that is not listed is refused before a socket
is opened. The shipped artifact is
`configs/tallow/scope/authorized-hosts.toml`.

`tallow scope check|list|verify` is the operator surface.

## Method vocabulary

Closed. An unknown token is a malformed register (every host refused),
not a silent extra grant. The set is `GRANTABLE_METHODS` in
`src/scope.rs`:

```
GET HEAD POST PUT PATCH DELETE OPTIONS TRACE CONNECT
```

Default for an omitted `methods` field: `GET`, `HEAD`. Existing shipped
entries keep that pair. The vocabulary change does not widen them.

## What a `CONNECT` grant means

`CONNECT` is permission to open a raw TCP socket to the listed host —
the verb `Scanner.scan` (`src/stdlib/osint.rs`) presents to the gate
before `TcpStream::connect_timeout`. It is **not** HTTP CONNECT
(RFC 9110 proxy tunneling), and it is not implied by `GET`/`HEAD`.

A `methods = ["CONNECT"]` entry authorizes CONNECT on that host and
nothing else. A GET on the same host is `scope:method-not-allowed`.

## What may carry it

An explicit operator line. Any basis the type system can express may
list it; the parser does not couple basis and method. Guidance:

- `ownership` / `self-hosted`: the natural carriers (the operator's
  machines, or machines they own).
- `written-consent`: only when `evidence` covers scanning, not merely
  fetching a public page.
- `public-read-only`: a category error. A port scan is not public-data
  retrieval. Do not grant it.

This shipped register grants CONNECT to **no** host, including
loopback. A local scan requires the operator to add CONNECT to the
loopback entries. That is a recommendation, not a default.

## Expiry

Every entry is refused once `expires_at` is behind `today`, whatever its
basis: `ScopeRegister::authorize` compares the dates before it consults the
basis, so `public-read-only` and `self-hosted` lapse exactly like
`written-consent`. An entry expiring *today* is still valid for today; it lapses
the day after. `expires_at` is optional in the type, but `tallow scope verify`
counts an entry without one as a defect and exits non-zero, and `scope list`
prints it as `unbounded` — so in practice a shipped grant without an expiry is a
finding, not a default.

## Matching is on the host alone

`ScopeEntry` has no path field. A grant authorises the granted methods on every
path of that host. On an owned or single-purpose host that is the same thing; on
a shared-hosting name (`storage.googleapis.com`, a CDN apex, a multi-tenant
API host) it is not — the grant reaches object prefixes, buckets and tenants
nobody justified. There is no way to express "only
`/chrome-for-testing-public/**`" today. Two rules follow:

- A shared host may be granted only for a read-only plane whose justification
  does not depend on the path, and the entry's `notes` must name the call sites
  the host-wide reach covers.
- `example.com` is granted as two exact hosts, not `*.example.com`, for the same
  reason: the wildcard is opt-in and the apex is not covered by it.

## Fail-closed

A missing, unreadable, or malformed register refuses every host. An
expired grant is not a grant. `WrittenConsent` without `evidence` is
not a grant.
