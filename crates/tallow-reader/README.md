<div align="center">

# tallow-reader

**One HTTP call, one clean article, behind a token — with a warm browser pool and a per-launch Tor identity.**

![api](https://img.shields.io/badge/api-HTTP%20%C2%B7%20bearer%20token-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

Extracting an article from a modern site means executing JavaScript, waiting for the content to settle, and not being thrown out by the first bot check. Doing it per request means paying that cost every time. This daemon keeps a warm browser pool, hands out one identity per launch, and returns a structured result instead of a HTML blob.

## What it is

| Part | Behaviour |
|---|---|
| **HTTP API** | `POST /extract` with `{"url": …, "anon": bool}`; `GET /health`; `GET /pool`; `POST /shutdown` |
| **Auth** | Bearer token. Generated on first run, written `0600`, never logged |
| **Warm pool** | Direct pool and a Tor pool, each up to `pool_max_size` instances |
| **Identity** | Every browser launch mints fresh `IsolateSOCKSAuth` credentials, so each slot gets its own Tor circuit rather than inheriting its predecessor's |
| **Extraction** | Readability-style article extraction, title, length, member/error flags |
| **Cookies** | Harvested after navigation and returned, so a caller can replay a session server-side |
| **CAPTCHA** | Optional provider backend (DataDome-class pages), off unless a key is configured |

`ExtractRequest` is deliberately small — a URL and an anonymity flag. Everything else is policy the daemon owns.

## What it is not

- **Not a general proxy.** It fetches pages; it does not relay arbitrary traffic.
- **Not anonymous by default.** `anon: true` routes through Tor, and the result reports `exit_ip`. A request without it leaves from the host, and the API says so rather than implying otherwise.
- **Not a scraper framework.** No scheduling, no crawling, no schema. One page in, one article out.
- **Not a CAPTCHA solver.** It can call a configured provider; without a key the tier is simply absent.

## Quick start

```console
$ cargo build -p tallow-reader
$ ./target/debug/tallow-reader --pool-size 4
```

On first run the daemon creates its token and writes the port file into its data directory:

```console
$ TOKEN=$(cat ~/.local/share/tallow-reader/token)
$ PORT=$(cat ~/.local/share/tallow-reader/port)

$ curl -s http://127.0.0.1:$PORT/health
$ curl -s -X POST http://127.0.0.1:$PORT/extract \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"url":"https://example.com/article","anon":true}' | jq '{title, length, exit_ip}'
```

A response carries `url`, `title`, `content`, `length`, `source`, `member`, optional `exit_ip`, optional `error`, and any harvested `cookies`.

## Configuration

| Flag / variable | Meaning | Default |
|---|---|---|
| `--pool-size N` | Browser instances per pool | 4 |
| `pool_tor_instances` | Warm Tor instances | 1 |
| `extract_timeout_secs` | Hard limit per extraction | 60 s |
| Tor SOCKS endpoint | Where the Tor pool points | `127.0.0.1:9050` |
| `TALLOW_CAPTCHA_API_KEY` | CAPTCHA provider key (optional) | unset |
| `TALLOW_2CAPTCHA_API_KEY` | Provider-specific alias | unset |
| `TALLOW_CAPTCHA_BACKEND` | Which backend to use | unset |
| `RUST_LOG` | Log filter | `tallow_reader=info` |

The token is written with `O_EXCL` and mode `0600`. A failed write leaves no partial secret behind — the config path refuses rather than clobbering.

## Deploying it

Run it as a service on the same host as Tor, bound to loopback, and put your own front end in front if it must be reachable:

```ini
# /etc/systemd/system/tallow-reader.service
[Unit]
Description=Tallow reader (extraction daemon)
After=network-online.target tor.service

[Service]
ExecStart=/usr/local/bin/tallow-reader --pool-size 4
User=tallow
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/tallow-reader

[Install]
WantedBy=multi-user.target
```

Operational rules that matter more than the unit file:

- **Each browser is expensive.** Pool size is a memory decision: a Chromium instance is hundreds of megabytes. Four is a workstation number, not a server default to scale blindly.
- **Tor identity isolation depends on credentials.** Sharing one bare `socks5://127.0.0.1:9050` URL across launches means one box-wide circuit; the daemon mints per-launch credentials precisely to avoid that.
- **`anon: false` is not a secret.** The host IP is used. Do not treat a non-anonymous result as private.
- **Rotate the token like a password.** It is the only thing between a local process and your browser pool.

## Design notes

**Why the pool is warm.** Cold-starting a browser per request dominates latency and makes rate limiting look like failure. Warm instances keep the cost where it belongs — at startup, once.

**Why per-launch credentials.** A relaunched slot that inherits its predecessor's circuit silently links two unrelated tasks to the same exit. Minting credentials per launch is the difference between "uses Tor" and "uses a distinct circuit".

**Why the token is on disk, not in the environment.** A service needs to survive restarts; a token regenerated on every boot breaks every client. A `0600` file survives and stays readable only by the service user.

## Verification

```console
$ cargo test -p tallow-reader
```

7 test functions in the crate source [measured 2026-10-21], covering config/token handling, the secret-write refusals, request validation, and extractor behaviour on saved HTML.

The API surface itself is small enough to test by hand in a minute — `health`, `pool`, `extract` — which is why the quickstart above is also the smoke test.

## Limits

| Limit | Detail |
|---|---|
| Requires a browser toolchain | Chromium must be installed; the daemon does not ship one |
| Tor pool is small by default | One warm instance; raise it deliberately |
| Article extraction, not structured data | For schema-first extraction use `tallow extract` with a contract |
| No queue | Concurrent requests beyond the pool wait or fail; there is no backlog service |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
