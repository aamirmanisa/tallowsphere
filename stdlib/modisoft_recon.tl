// tallow.modisoft_recon — READ-ONLY Modisoft estate deep-dive recon (module C, wave9).
//
// Estate-recon surface encoding the wave9 a2_autharch playbook
// (artifacts/modisoft/wave9_2026-09-05/agents/a2_autharch/REPORT.md §1):
//   estate_hosts()   curated host manifest (families + roles, incl. dead /
//                    misclassified CT slots so later dives skip them)
//   ct_hosts(dom)    fresh crt.sh subdomain enumeration (deduped/sorted)
//   probe(url, p?)   one-URL HTTP fingerprint
//                    {url,status,content_type,server_header,title,len,
//                     body_head,final_url}
//   routes(url, ps)  batch GET route oracle [{path,status,ct,title_or_hint}]
//                    — the a2 discriminator: 405 = POST-only route exists,
//                    404 = no route, 200-login-HTML = SPA catch-all,
//                    3xx Location = redirect gate
//   flight(url)      Next.js RSC probe (RSC:1 + Accept: text/x-component) —
//                    reads the server-rendered tenant/apiBaseUrl payload
//   wayback_cdx(dom) Wayback CDX snapshot rows (historical page discovery)
//
// ⚠ READ-ONLY POLICY (non-negotiable)
// -----------------------------------
// This module issues GET requests ONLY. Never POSTs, never submits
// credentials, never triggers OTP/email side effects, never touches login /
// signup / recover-account / refresh-token or authenticated routes, never
// writes. The route oracle is a GET oracle ON PURPOSE: a GET against a
// POST-only route returns 405, and that 405 IS the finding — we never send
// the POST itself. Red surfaces (REPORT §4 R1–R11) are annotated in
// estate_hosts() output (roles dead / misclassified / anon-leak / collector)
// so drivers route AROUND them. aiinvoice/ai-theft-detection upload and SAS
// surfaces are fingerprint-only; the module never uploads and never writes.
//
// Conventions
// -----------
// * Every function returns the RAW JSON body as a String; call
//   `let v = raw.parse_json()` in your script to consume it.
// * All network calls are paced through GOV_MODISOFT_RECON (default 2 rps;
//   override env TALLOW_MODISOFT_RECON_RPS, read once at first use).
//   routes() additionally enforces a 400 ms minimum gap between path GETs.
//   ct_hosts/wayback_cdx retry with exponential backoff on 429/5xx
//   (governed_get); probe/routes/flight are single-attempt by design — a 502
//   is itself a fingerprint and must not be masked by retries.
// * probe/routes/flight report HTTP status codes IN-BAND (never as errors);
//   a transport-level failure (DNS/connect/TLS) returns a JSON object with
//   "status":"ERR" (probe also echoes the url). Only argument problems and
//   ct/wayback upstream shape failures are Err results.
// * Error contract — match on these prefixes in .tl:
//     modisoft_recon:http:<status>   non-200 after retries (ct/wayback)
//     modisoft_recon:net:<cause>     persistent transport failure
//     modisoft_recon:shape:<detail>  upstream body shape mismatch
//     modisoft_recon:param:<detail>  bad argument (type/value)
//
// Legal
// -----
// These are PUBLIC, keyless, read-only surfaces (crt.sh, Wayback, and
// estate GETs); @legal annotations on your own network fns still apply, e.g.
// `@legal(basis:.public_data, purpose:.business_research, rate_limit:2.per_second)`.
//
// Plan: wave9 module C; knowledge base = a2_autharch REPORT §1 + wave8
// estate host triage (estate-hosts-credential-surfaces.md). Read-only; rate
// ceiling deliberate politeness.

// Curated manifest of the Modisoft estate host families: JSON array of
// {host, family, role, note?}. Roles drive deep-dive routing — dead /
// misclassified slots are encoded so future dives SKIP them, anon-leak rows
// carry the anonymous admin-exposure warning (GET-only, vendor-notify).
// Pure local data; no network. Returns a JSON array String.
fn estate_hosts() -> String

// Fresh crt.sh subdomain enumeration for a bare domain (no scheme/path):
// GET https://crt.sh/?q=%25.<domain>&output=json, dedupe the name_value
// entries, drop `*.` wildcards, lowercase. Returns a sorted JSON array of
// hostname Strings. Errors: modisoft_recon:param|http|net|shape.
fn ct_hosts(domain: String) -> String

// Fingerprint ONE url (optional path appended): redirect-following governed
// GET with a browser UA. Returns JSON {url, status, content_type,
// server_header, title (null when absent), len (bytes), body_head (first
// 300 chars, control chars stripped), final_url (after redirects)}. HTTP
// statuses 404/405/429/502/… are returned in-band, never as errors; a
// transport failure returns {url, status:"ERR", error}. Param errors are Err.
fn probe(url: String, path: String?) -> String

// Batch GET route oracle (the a2 405/404/200-login/302 discriminator).
// paths is a [String] list (max 25 — more is a param Err, never silently
// truncated); missing/Nil/[] falls back to the 9 standard probes (/, swagger
// v1 + index, /health, /api-docs, /login, /account/login, /Account/LogIn,
// /account/logon). Redirects are NOT followed so 3xx Location headers stay
// visible in title_or_hint. Returns a JSON array of {path, status, ct,
// title_or_hint} rows; per-path transport failures become {path,
// status:"ERR", error} rows and the batch continues. Read the oracle:
//   405 → POST-only route exists (login published)
//   404 → no route / AFD|istio dead end
//   200 login HTML → SPA catch-all (Next.js /account/login behaviour)
//   3xx → redirect gate; title_or_hint carries "Location: …"
fn routes(url: String, paths: [String]) -> String

// Next.js RSC flight probe: GET with headers RSC:1 + Accept:
// text/x-component and a browser UA. Next.js App Router answers with the
// serialized RSC flight payload (server-rendered props — e.g. the per-tenant
// apiBaseUrl baked into the public login HTML); non-Next.js origins answer
// with normal HTML. Returns JSON {status, len (FULL body bytes), body
// (truncated to 20000 chars)}. Transport failure → {status:"ERR", error}.
fn flight(url: String) -> String

// Wayback CDX snapshot rows for a bare domain: GET
// https://web.archive.org/cdx/search/cdx?url=<domain>*&output=json&limit=N
// (governed, retried). limit defaults to 200, clamps 1..=5000. Returns a
// JSON array of {urlkey, timestamp, original, statuscode, mimetype} objects
// — one per snapshot — with the CDX header row skipped.
fn wayback_cdx(domain: String, limit: Int?) -> String
