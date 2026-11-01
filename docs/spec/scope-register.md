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

## Fail-closed

A missing, unreadable, or malformed register refuses every host. An
expired grant is not a grant. `WrittenConsent` without `evidence` is
not a grant.
