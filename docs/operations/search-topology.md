# Tallow Search — stack topology & bring-up runbook

> status: prepared 2026-09-16 (R7b, TO-100 campaign) — **nothing installed**; units below are
> templates under `tallow-search/deploy/` awaiting an operator step. Local boot of the API in
> dev mode was executed and verified on this box (evidence:
> `artifacts/to-100-2026-09-16/R7b-evidence/`); production install steps are marked
> **OPERATOR-GATED**.

Source findings: `artifacts/nixe-v1-readiness-audit-2026-09-15/05-services-topology.md` F1/F3/F4/F5/F10,
`04-deploy-release.md`, `fixes/FIX-WAVE.md` (L2/L3), `fixes/search-api.md`.

## 1. Components & desired topology

| Component | Runs as | Listens | Config source | What the routes need |
|---|---|---|---|---|
| `tallow-search-api` (Axum) | `tallow-search-api.service` *(template)* | `127.0.0.1:3001` (`PORT`/`BIND_ADDR`) | env (`/etc/tallow-search/api.env`) | Postgres **mandatory at boot**; Meilisearch optional (degrades explicitly) |
| `tallow-search-web` (Astro SSR, node standalone) | `tallow-search-web.service` *(template; box unit exists but is inactive+disabled and points at a missing dir)* | `127.0.0.1:4323` (`PORT`/`HOST`) | env | API reachable same-origin under `/api/v1` (Caddy) |
| Postgres 17 | `postgresql@17-main.service` | `127.0.0.1:5432` | `/etc/postgresql/17/main/` | `DATABASE_URL` |
| Meilisearch | external / not deployed here | e.g. `127.0.0.1:7700` | `MEILI_*` + `HTC_MEILI_*` | `/search`, `/search/unified` (hybrid/fallback), `/product-search` |
| Caddy | `caddy.service` | `:80`/`:443` | `/etc/caddy/Caddyfile` | **no search-stack upstream today** — operator must add `reverse_proxy` |

Request flow (intended):

```
browser → Caddy :443 (host block)
           ├── /api/v1/*  → reverse_proxy 127.0.0.1:3001   (tallow-search-api)
           └── /*         → reverse_proxy 127.0.0.1:4323   (tallow-search-web, SSR)
tallow-search-api → Postgres 127.0.0.1:5432 (required) + Meilisearch (optional, degrades loudly)
```

### Current box state (2026-09-16 05:2x–05:32 UTC, re-verified)

| Claim | State |
|---|---|
| API unit | **absent** — no `tallow-search-api.service` anywhere under `/etc/systemd/system` |
| API process | not running (no listener :3001) |
| Web unit | `tallow-search-web.service`: **inactive + disabled**; `WorkingDirectory=/opt/tallow-search/web` does not exist (`/opt/tallow-search` absent) |
| Postgres 17 | installed (17.11), cluster `17-main` **failed** since 2026-09-12; **data directory `/var/lib/postgresql/17/main` does not exist** — config leftover only, cluster cannot start as-is (see §5) |
| Meilisearch | not running (:7700 free) |
| Caddy | listening :80/:443/:2019; blocks for vape-island, sendtallow.com, relay — **no search-stack upstream** |

## 2. Env vars & secrets

Set via `/etc/tallow-search/api.env` (template: `deploy/tallow-search-api.env.example`).
Consumed in `tallow-search/api/src/config.rs`.

| Var | Default in code | Notes |
|---|---|---|
| `PORT` | `3001` | api listen port; every script/parity tool assumes 3001 on this box (historical Hetzner prod used 8080) |
| `BIND_ADDR` | `127.0.0.1` | loopback-only by design (T-121). Caddy is on-box; keep loopback |
| `DATABASE_URL` | `postgres://tallow:***@localhost:5432/tallow_search` | **the default password is a literal placeholder — never rely on the default**; set explicitly |
| `SQLITE_PATH` | `data/cache.db` | **relative to CWD** — the unit's `WorkingDirectory` decides where it lands; the API also creates `./data/` unconditionally |
| `CORS_ORIGINS` | `http://localhost:4322,http://localhost:3000` | stale vs the ports in use (web dev 4322, web unit 4323, Astro default 4321). Behind the Caddy same-origin proxy CORS is not exercised; for direct/dev access set `http://localhost:4321,http://localhost:4322,http://localhost:4323`. `*` is refused by design |
| `AUTH_SECRET` | `tallow-dev-secret-change-in-production` | dev default; **must be a real secret** wherever the authed surface is reachable. No startup guard exists — operator's responsibility |
| `MEILI_URL` / `MEILI_KEY` | `http://127.0.0.1:7700` / empty | main Meili client (`/search`, `/search/unified`). Empty `MEILI_KEY` ⇒ requests sent unauthenticated (warn logged) |
| `HTC_MEILI_URL` / `HTC_MEILI_KEY` / `HTC_MEILI_INDEX` | `http://127.0.0.1:7700` / empty / `products` | **second, duplicate family** consumed only by `/product-search` (audit F4; `HTC_` is HackTheCart-era). Set BOTH families or half the stack silently degrades |
| `TALLOW_PROXY` | `socks5://127.0.0.1:9050` (Tor) | used by `proxy.rs` + finance/execute paths. With Tor down those routes fail; set explicitly (empty string = direct) |
| `RUST_LOG` | unset → `info` | |

**Dev-mode truth (doc/behaviour drift):** `tallow-search/api/AGENTS.override.md` claims
`TALLOW_DEV_MODE=1` / `RUST_ENV=dev` "enable local dev defaults". **No such branch exists in the
source** (`rg -n 'TALLOW_DEV_MODE|RUST_ENV' tallow-search/api/src` → 0 hits). The only dev
conveniences are the fallback defaults in the table above (`AUTH_SECRET`, `DATABASE_URL`, `PORT`).
Postgres is required for boot in *all* modes — see §3.

## 3. Database & migrations flow

- Boot order (`src/main.rs:28-29`): `AppState::new` → `PgPool::connect(DATABASE_URL)` (panics
  "Failed to initialize" on failure) → `db::postgres::run_migrations` (panics "Postgres
  migrations failed").
- `run_migrations` (`src/db/postgres.rs`) is **inline DDL** (`CREATE TABLE IF NOT EXISTS …`,
  idempotent): `users`, `jobs`, `scrape_results`, `exports`, `user_proxies`,
  `scheduled_exports`, `price_history`, `page_snapshots`, `change_events`, `user_settings`
  (verified live: `\dt` output in `R7b-evidence/`).
- **The SQL files in `tallow-search/api/migrations/*.sql` are NOT applied at boot.** They are
  consumed only by tests (`tests/migrations_schema_contract.rs`) and the
  `rating_snapshot_once` bin's preflight expectations. An operator expecting "run the migrations"
  to apply those files must do so explicitly (`psql -f`) — today nothing else does.
- Requires `gen_random_uuid()` (built-in since PG13; no `pgcrypto` extension needed on PG17).
- DB bootstrap (once per box):

```bash
su - postgres -c "psql -c \"CREATE ROLE tallow LOGIN PASSWORD '<secret>';\""
su - postgres -c "createdb -O tallow tallow_search"
```

- Migrations are **additive/idempotent**; there is no down-migration tooling. Schema changes ship
  in `src/db/postgres.rs` + a matching `migrations/*.sql` for the contract tests (follow the
  AGENTS.override rule: migrations dir first).

## 4. Dev-mode boot recipe (verified 2026-09-16, this box)

Two paths for Postgres. Path A needs no system changes (used for R7b evidence); Path B repairs the
system cluster (**operator call** — see §5).

```bash
# ---- Path A: throwaway cluster inside the evidence dir (no system state touched) ----
EV=~/Nixe/artifacts/to-100-2026-09-16/R7b-evidence
install -d -o postgres -g postgres -m 700 "$EV/pgdata"
su -s /bin/bash postgres -c "/usr/lib/postgresql/17/bin/initdb -D $EV/pgdata -U postgres -A trust -E UTF8 --no-locale"
#   NOTE: the pg_ctl log must live inside the postgres-owned dir or the start fails with
#   "cannot create …: Permission denied"
su -s /bin/bash postgres -c "/usr/lib/postgresql/17/bin/pg_ctl -D $EV/pgdata -l $EV/pgdata/server.log \
  -o '-p 5432 -c listen_addresses=127.0.0.1 -c unix_socket_directories=/var/run/postgresql' start"
su -s /bin/bash postgres -c "psql -h /var/run/postgresql -p 5432 -v ON_ERROR_STOP=1 \
  -c \"CREATE ROLE tallow LOGIN PASSWORD 'tallow_dev_only'\" -c \"CREATE DATABASE tallow_search OWNER tallow\""

# ---- boot the API (debug binary; cargo build -p tallow-search-api if missing) ----
cd ~/Nixe/artifacts/to-100-2026-09-16/R7b-evidence/run   # CWD ⇒ SQLite/./data land here
env BIND_ADDR=127.0.0.1 PORT=3001 \
  DATABASE_URL='postgres://tallow:tallow_dev_only@127.0.0.1:5432/tallow_search' \
  AUTH_SECRET='tallow-dev-secret-change-in-production' \
  SQLITE_PATH="$PWD/cache.db" MEILI_URL='' \
  HTC_MEILI_URL='http://127.0.0.1:7799' HTC_MEILI_KEY='dev-search-key' HTC_MEILI_INDEX='products' \
  RUST_LOG=info \
  ~/Nixe/tallow-search/target/debug/tallow-search-api > api.log 2>&1 &

curl -s http://127.0.0.1:3001/api/v1/health        # → {"service":"tallow-search","status":"ok"}
curl -s 'http://127.0.0.1:3001/api/v1/product-search?q=milk&limit=5'   # public route, no token

# ---- cleanup ----
pkill -TERM -f 'tallow-search-ap[i]'               # or kill the recorded PID
su -s /bin/bash postgres -c "/usr/lib/postgresql/17/bin/pg_ctl -D $EV/pgdata stop -m fast"
```

Pitfall: killing by `pkill -f '…/tallow-search-api'` **self-matches your own shell command line**
and signals your shell too. Use the bracket trick (`'tallow-search-ap[i]'`) or a PID file.

Verified boot log (full file: `R7b-evidence/02-api.log`):

```
INFO tallow_search_api::state: Meilisearch disabled (config.meili_url not set)
INFO sqlx::postgres::notice: column "level" of relation "scrape_results" already exists, skipping
INFO tallow_search_api::db::postgres: Postgres migrations complete
INFO tallow_search_api::scheduler: Scheduled export runner started (60s interval)
INFO tallow_search_api: Tallow Search API on 127.0.0.1:3001
```

## 5. Postgres operator step (currently broken on this box)

The system cluster `postgresql@17-main` cannot start: `data_directory=/var/lib/postgresql/17/main`
no longer exists (teardown leftover; `pg_lsclusters` still lists it, service state `failed`).
**OPERATOR-GATED** — pick one:

```bash
# Option 1 (repair, matches the config layout the failed unit expects):
pg_dropcluster 17 main          # cluster is stopped; drops the config leftover
pg_createcluster 17 main --start
# then §3 DB bootstrap (role 'tallow' + db 'tallow_search')

# Option 2 (no system changes): the Path-A throwaway recipe in §4, as done for the R7b evidence.
```

R7b started the throwaway instance, ran the boot test, and stopped it again; the system cluster
was left untouched (`failed`, no datadir). Before/after evidence: `R7b-evidence/00-postgres-before.txt`,
`01a-initdb.log`, `01b-pg.log`, `01c-postgres-after.txt`, `09-final-state.txt`.

## 6. Install steps for later (OPERATOR-GATED — nothing below has been executed)

Templates live in `tallow-search/deploy/` (`tallow-search-api.service`,
`tallow-search-web.service`, `tallow-search-api.env.example`). See `deploy/README.md`.

```bash
# 1) service user + layout
useradd --system --home /opt/tallow-search --shell /usr/sbin/nologin tallow-search
install -d -o tallow-search -g tallow-search /opt/tallow-search/api/bin /opt/tallow-search/api/data /opt/tallow-search/web

# 2) API binary (release build) + env + unit
cargo build --release -p tallow-search-api                      # from tallow-search/
install -m 0755 tallow-search/target/release/tallow-search-api /opt/tallow-search/api/bin/
install -d -m 0750 /etc/tallow-search
install -m 0640 -o root -g tallow-search deploy/tallow-search-api.env.example /etc/tallow-search/api.env
#   → edit /etc/tallow-search/api.env: real DATABASE_URL, AUTH_SECRET, MEILI_KEY, HTC_MEILI_KEY
install -m 0644 deploy/tallow-search-api.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tallow-search-api.service
curl -s http://127.0.0.1:3001/api/v1/health

# 3) web (Astro SSR standalone)
cd tallow-search/web && npm ci && npm run build                 # produces dist/server/entry.mjs
rsync -a --delete dist/ package.json package-lock.json /opt/tallow-search/web/
(cd /opt/tallow-search/web && npm ci --omit=dev)                # runtime deps for the node server
install -m 0644 deploy/tallow-search-web.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tallow-search-web.service
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4323/

# 4) Caddy (operator-managed blocks; current file has NO search upstream)
#    add inside the host block that should serve the app — file convention is
#    "# BEGIN <name> - managed by Hermes" … "# END <name> …" blocks:
#      handle /api/v1/* { reverse_proxy 127.0.0.1:3001 }
#      handle         { reverse_proxy 127.0.0.1:4323 }
systemctl reload caddy
```

Notes:
- The existing box unit `/etc/systemd/system/tallow-search-web.service` is left untouched by R7b;
  it is inactive+disabled and points at the not-yet-existing `/opt/tallow-search/web`.
- Web runtime needs `node` ≥ 18 (standalone adapter; `/usr/bin/node` per the box unit).
- Web auth uses same-origin `/api/v1` (`web/src/lib/api.ts` `BASE`), so no CORS config is needed
  once Caddy proxies both behind one host; direct dev access needs §2's `CORS_ORIGINS`.
- `web/astro.config.mjs` dev proxy defaults to a **remote** host (`http://203.0.113.1:3001`);
  for local dev set `API_URL=http://127.0.0.1:3001` (or run `npm run dev` without the proxy).

## 7. `/product-search` degraded envelope (verified live, 2026-09-16)

Response shape (fix L3 / `routes/product_search.rs`): `degraded: bool` + `degraded_reason`.
`degraded:true` means the Meili query did not complete — `results:[]`/`total:0` there is NOT a
genuine zero-hit result. Genuine zero hits return `degraded:false`, `total:0`.

Verified matrix against the locally booted API (`q=milk&limit=5`; evidence
`R7b-evidence/03-*.json`, `03-product-search-matrix.json`):

| Case | Upstream state | `degraded` | `degraded_reason` |
|---|---|---|---|
| A | Meili unreachable (transport) | `true` | `Meilisearch request failed (transport): error sending request for url (http://127.0.0.1:7799/indexes/products/search)` |
| B | Meili HTTP 401 | `true` | `Meilisearch returned HTTP 401 Unauthorized for index 'products'` |
| C | Meili ok, 2 hits | `false` | `null` (results parsed incl. `best_price`, per-store prices, `source:"hackthecart"`) |
| D | Meili ok, 0 hits | `false` | `null` (`total:0` — genuine empty) |
| E | Meili 200, non-JSON body | `true` | `Meilisearch response could not be parsed as JSON: error decoding response body` |

All five returned HTTP 200 with the envelope; the route is **public** (no auth header needed).
Re-run against any instance: `deploy/verify-product-search-degraded.sh [BASE_URL]`.

**No automated test covers this route** (`rg 'product[_-]search|degraded' tallow-search/api/tests`
→ 0 hits) — the live curl matrix is the current acceptance evidence. A contract test asserting the
envelope shape is the obvious follow-up (belongs to the API test surface, not R7b).

## 8. Failure modes & triage

| Symptom | Cause | Triage |
|---|---|---|
| API exits: `Failed to initialize` | Postgres unreachable / bad `DATABASE_URL` (default password is a literal placeholder) | `pg_isready`; check `DATABASE_URL`; §5 |
| API exits: `Postgres migrations failed` | DB reachable but DDL failed (role lacks CREATE on schema, disk full) | `psql "$DATABASE_URL" -c '\dn'`; PG logs |
| API up but `/search` is keyword-only | Meili client init failed/timed out (5 s bound) — logged `falling back to Postgres search` | check `MEILI_URL`/`MEILI_KEY`; response carries `source` |
| `/product-search` `degraded:true` | Meili down/401/parse failure for `HTC_MEILI_*` | reason string names the cause; check the *HTC* family (§2) |
| Web 404 on `/api/v1/*` | Caddy has no upstream for the search stack (§1) | add the `handle` blocks (§6.4) |
| Web SSR 502 after deploy | `/opt/tallow-search/web/dist/server/entry.mjs` missing (unit points there) | rebuild + copy (§6.3) |
| Browser CORS errors (direct access) | `CORS_ORIGINS` defaults to 4322/3000 only; ports in play: 4321/4322/4323 | set `CORS_ORIGINS` explicitly (§2) |
| `data/cache.db` in the wrong place / permission error at boot | `SQLITE_PATH` (default) is relative to CWD; API also creates `./data` | set absolute `SQLITE_PATH` + writable `WorkingDirectory` (unit template does) |
| Port 3001 already in use | stray dev instance | `ss -ltnp \| grep 3001`; kill by PID (bracket trick in §4) |
| Historical: `tallow-search-web.service` points at `/opt/tallow-search` (missing) | unit was written for a layout never shipped on this box | §6 install or remove unit (operator call) |

## 9. What remains operator-gated

1. Postgres system cluster repair (§5) + role/db creation with a real password.
2. Real secrets provisioning: `AUTH_SECRET`, `MEILI_KEY`, `HTC_MEILI_KEY` (and Meili's own key
   config), `TALLOW_PROXY` decision (Tor vs direct).
3. Installing the two unit templates + `/opt/tallow-search` layout + `tallow-search` service user (§6).
4. Caddy upstream blocks + which hostname serves the search stack (§6.4).
5. A Meilisearch instance + index (`products` for `/product-search`, `scrape_results` for the
   main client) — no Meili is deployed on this box.
6. Web artifact build/copy (`web/` build is R7a's lane; production copy fresh from the built `dist/`).

## 10. References

- Audit: `artifacts/nixe-v1-readiness-audit-2026-09-15/05-services-topology.md` (F1/F3/F4/F5/F10),
  `04-deploy-release.md`; fixes: `fixes/FIX-WAVE.md` (L2/L3), `fixes/search-api.md`
  (degraded-envelope diff + "Runtime/live proof" — **closed by R7b evidence**).
- Box-local parity tooling: `tallow-search/scripts/hetzner_parity_check.ps1`,
  `tallow-search/DEPLOYMENT_VERIFICATION_CHECKLIST.md` (historical Hetzner prod: port 8080,
  unit `tallow-search-api.service`).
- Boot evidence: `artifacts/to-100-2026-09-16/R7b-evidence/` (`02-api.log`, `03-*`, `09-final-state.txt`).
