# W12 ember — publication exclusion set for tallowsphere

Lane: report only. No tree was created (`/home/aamir/tallow-publish-w12` does not
exist and was not created), no build was run, nothing was pushed or tagged.

## 0. Provenance of every number in this report

| field | value |
|---|---|
| worktree | `/home/aamir/tallow-worktrees/w12/ember` |
| branch | `rel/w12-ember` |
| commit | `758e5bc0d0a88015e0357f233b67af64ab635f50` |
| tree object | `425e7fc4f597666c5b8fad0e77be50debdcf5cd7` |
| tracked-file manifest digest | `b83db55c559dfea7acc0a3bebd28bf901572d3c91139dc04de4213044b48ffc8` |
| tracked files | 1859 |
| tracked bytes | 35,031,526 |
| cargo invocation | **none** — this lane is report-only, so there is no `test result:` line to quote |

Manifest digest = sha256 over `git ls-files -z | xargs -0 sha256sum | LC_ALL=C sort -k2 | sha256sum`,
i.e. every tracked path with its content hash. If a file is added, deleted or
edited anywhere in the tree, this digest changes. Re-derive it with:

    git rev-parse HEAD HEAD^{tree}
    git ls-files -z | xargs -0 sha256sum | LC_ALL=C sort -k2 | sha256sum

### Scope of every count

`target/` and `.git/` are excluded from **every** count below. Two independent
reasons, both checked: (1) the universe used throughout is `git ls-files`, which
only emits tracked paths, and neither directory has a tracked path; (2)
`target/` does not exist in this worktree at all, and `.git` here is a 4 KB
gitdir *pointer file* of a linked worktree, not a directory:

    ls -d target .git ; du -sh .git
    # du: cannot access 'target': No such file or directory
    # 4.0K  .git

Where a filesystem walk was used instead of the index, it carried the flags
explicitly (`du -sh --exclude=target --exclude=.git .` → `39M`, block-rounded;
the byte-accurate sum of tracked files is 35,031,526 — the difference is
allocation rounding, not content).

## 1. Premises in the brief that are wrong

Refuting a premise is a deliverable; these three changed the shape of the set.

**P1 — "client-engagement content" is not present in this tree.** It was already
removed, by three commits that are ancestors of `758e5bc`: `92cf156` (client
street address + demo phone number), `0b8689d` (the fixture ignore rule stopped
spelling the client), `e3ada9b` (client-derived fixtures and fleet artifacts kept
out). The removal is still visible in the module registry as a tombstone:

    sed -n '88p' src/stdlib/mod.rs
    # // (removed in the publication pass: client-named module)

and the content itself is gone:

    rg -l --no-messages -i 'modisoft|lathrop|512-850-1815' -g '!target/**' | wc -l
    # 0

    rg -o --no-messages -g 'tests/fixtures/**' -g 'conformance/**' \
      '[a-z0-9-]+\.(com|net|org|io|co|de|nl|be)\b' | awk -F: '{print $NF}' \
      | sort | uniq -c | sort -rn
    #   14 example.com
    #    1 github.com

So the class-1 exclusion set is **empty (0 files)** — not because I did not look,
but because the client name, the client fixtures and the client-named module are
not in the tree. What is left that is engagement-shaped is the *platform-bypass*
family (class 2), which names real publishers and platforms rather than the
client, and the operator's own infrastructure addresses (class 3).

**P2 — the brief's binary list (`.exe`, `.ll`, `.wasm`) is empty; the real
committed binaries are different files.** All three extensions are absent from
the index:

    git ls-files | rg -i '\.(exe|ll|wasm)$' || echo none
    # none

The binaries that *are* committed are `examples/self_host.exp` (an Intel amd64
COFF object) and `examples/self_host.lib` (an `ar` archive), plus two `.pcap`
fixtures — found by MIME type, not by extension (class 4 below).

**P3 — "fixtures over a size bound" is a claim I could not operationalise, and it
would be the wrong instrument.** The largest tracked fixture is
`crates/tallow-crypto/tests/wycheproof_vectors/x25519_test.json` at 253,890 bytes,
a published Wycheproof test vector with no publication risk. A byte bound would
exclude it and keep a 676-byte packet capture that *is* a build output. I
classified by content type instead:

    git ls-files -z | xargs -0 file --mime-type | rg -v 'text/|application/json|application/xml|inode/x-empty|application/toml'

## 2. Class 1 — client-engagement content: 0 paths

Set: **∅**. Evidence in P1 above. No path in this tree carries a client name, a
client-named engagement module, or a fixture that names a customer.

The five modules that the publication pass deleted were deleted *whole*, and no
orphan is left behind — every `src/stdlib/*.rs` is registered in `src/stdlib/mod.rs`
(either directly or via `#[path = ...]`) and every `stdlib/*.tl` has a Rust
counterpart or is a pure declaration module:

    for f in src/stdlib/*.rs; do s=$(basename "$f" .rs); \
      rg -q "(pub mod|$s;)" src/stdlib/mod.rs || echo "UNDECLARED: $f"; done
    # (intel_api/intel_ip/intel_traffic are declared via #[path = "…"] at mod.rs:45,50,55)

    comm -23 <(ls stdlib/*.tl | xargs -n1 basename | sed 's/\.tl$//' | sort) \
             <(ls src/stdlib/*.rs | xargs -n1 basename | sed 's/\.rs$//' | sort)
    # api evidence ip traffic   (all four are #[path]-routed Rust modules or declaration-only)

## 3. Class 2 — credential- and attack-shaped modules: 13 paths, 209,711 bytes

Every row states the line that makes the file publication-unsafe.

| # | path | bytes | the line that makes it unsafe |
|---|---|---|---|
| 1 | `src/stdlib/cxense.rs` | 19,640 | `:1` "Cxense-metered paywall bypass client"; `:41` "Whitelisted heavy-traffic referrers (server-side meter bypass)" |
| 2 | `src/stdlib/substack.rs` | 27,024 | `:1` "Substack.com paywall bypass client"; `:15` "## Bypass Vectors" incl. `:20` "Email share tokens — extended validity, can be harvested" |
| 3 | `src/stdlib/medium.rs` | 24,113 | `:1` "paywall bypass client"; `:6` "## Bypass Vectors" (meter-cookie reset, cache/proxy bypass) |
| 4 | `src/stdlib/wordpress.rs` | 20,977 | `:1` "WordPress membership paywall bypass"; `:213` "REST API. This is the PRIMARY bypass" |
| 5 | `src/stdlib/ghost.rs` | 17,301 | `:1` "Ghost CMS paywall interface"; `:17` "## Known Bypass Vectors" |
| 6 | `src/stdlib/beehiiv.rs` | 23,998 | `:12` "`/api/auth/set-token` -- JWT injection (accepts any formatted JWT!)"; `:480` `set_jwt` injection, `:422` premium content "only present when authed" |
| 7 | `src/stdlib/jwt.rs` | 21,596 | `:134` dispatch to `attack_weak_secrets`; `:209` the brute-forcer; `:234-236` the baked weak-secret list (`"secret", "password", "jwt_secret", "key", "private", …`) |
| 8 | `stdlib/jwt.tl` | 1,480 | `:4` "run standard JWT attacks: alg:none, weak secret brute force"; `:30-45` `attack_none`, `attack_weak_secrets`, `attack_kid_injection`, `attack_alg_confusion` |
| 9 | `stdlib/cxense.tl` | 1,143 | declarations for the bypass client (paired with row 1) |
| 10 | `stdlib/beehiiv.tl` | 1,526 | declarations for the JWT-injection client (paired with row 6) |
| 11 | `src/browser/wordfence_bypass.rs` | 5,133 | `:1` "Wordfence JS challenge bypass for Tallow"; `:9-13` automate bypass via CDP JS execution |
| 12 | `src/browser/wordpress_auth.rs` | 10,731 | `:1` "WordPress authentication automation"; `:4-8` nonce extraction, login-form submission, 2FA detection |
| 13 | `docs/TALLOW-330-TOOLS.md` | 35,049 | `:9` "## 1. Cybersecurity — Offensive (20)"; `:17` CredSpray "distributed credential stuffing"; `:19` PhishKit "credential capture"; `:30` LDAPHarvest "password spraying" |

Judged and **retained** (not in the set) — recorded so the judgement is auditable:

- `src/vault/audit.rs:116` `WEAK_PASSWORDS` — a 24-entry denylist used by a
  password *strength check*. Defensive; the strings are the OWASP-style top-N.
  It stays.
- `src/stdlib/osint.rs:304` "Default wordlist for DNS brute-force (~200 common
  subdomains)" — subdomain enumeration from a public vocabulary. It stays, and
  the file is a shipped feature.
- `src/browser/captcha.rs`, `src/stdlib/turnstile.rs` — CAPTCHA *detection and
  classification* plus a solve chain routed to the live engine. Borderline
  (bot-wall circumvention), but it is the product's advertised anti-bot plane and
  excluding it removes a documented capability. **Operator decision, not mine.**
- `src/decoy_endpoints.rs` — self-honeypot tripwires on the operator's own
  estate; defensive.
- `src/host_probe.rs` — read-only `/proc/sys` inspection. Nothing to hide.
- `crates/tallow-net/src/relay/{client,resolve,directory}.rs`,
  `crates/tallow-net/tests/proxy_integration.rs` — `18.119.135.151:4433`
  hardcoded in comments and tests (a public relay address). See the REWRITE set;
  it is one address, not a module.
- `src/sluice.rs`, `src/typeck.rs`, `src/interp.rs` `"/bin/sh"`-adjacent hits —
  process spawning for the compiler/daemon, not attack primitives.

## 4. Class 3 — operator-personal paths and machine names

### 4a. Excluded: 4 paths, 128,005 bytes

| # | path | bytes | what leaks |
|---|---|---|---|
| 14 | `docs/opsec/stealth-scanning-statement-of-intent.md` | 22,425 | `:30` and `:191` the box's real IPv6 `2a01:4f9:c014:1dca::1` (Hetzner `2a01:4f9::/32`); `:225` two verified Tor exit IPs `203.55.81.1`, `96.44.159.148`. `203.0.113.1` is RFC 5737 sanitised, the IPv6 is not |
| 15 | `docs/ops/watchlist_pqc_seed.md` | 7,412 | `:16` "verified exit `193.189.100.195` ≠ box IP `203.0.113.1`" — provenance of a live probe from this host |
| 16 | `docs/MEGA_SCRAPER_ENGINE_RESEARCH.md` | 97,398 | `:122` "Server: Hetzner Cloud Helsinki (203.0.113.1, 16GB RAM)" — identifies the machine by provider, city and RAM |
| 17 | `tests/fixtures/topology_adversarial/bypass_hostname_unlisted.tl` | 770 | `:1` and `:9` the machine's real hostname `ubuntu-16gb-hel1-1`, plus how it resolves (`/etc/hosts` → 127.0.1.1) |

### 4b. Must be rewritten, not excluded: 11 paths, 68,421 bytes

These cannot be deleted without breaking schema `$ref` resolution, but a private
hostname cannot ship either. The fix is `https://nixe.local/...` → the public
schema base, preserving each `$id`'s path component:

    rg -l --no-messages 'nixe\.local' -g '!target/**' | sort
    # configs/tallow/targets.schema.json
    # configs/tallow/targets.v2.example.json
    # schemas/tallow/artifact-manifest.schema.json
    # schemas/tallow/capability-status.schema.json
    # schemas/tallow/compliance-gate-report.schema.json
    # schemas/tallow/error-taxonomy.schema.json
    # schemas/tallow/extraction-row-validation-report.schema.json
    # schemas/tallow/extraction-row.schema.json
    # schemas/tallow/extraction-schema.schema.json
    # schemas/tallow/full-run.schema.json
    # schemas/tallow/target-manifest-v2.schema.json

Also rewrite (evidence chain depends on the file staying):

- `scripts/bbs_extract_vectors.py:15` — `DRAFT = Path("/home/user/.hermes/profiles/alden/cache/web/www.ietf.org-….md")`.
  Keep the script (it is cited as the provenance of two RFC fixtures — see
  `docs/operations/stub-register.md` row 90); replace the absolute cache path
  with a repo-relative one.
- `src/browser/process.rs:618` — the literal `/home/user/.hermes/` prefix check.
  Harmless as a string, but it hardcodes the operator's tooling layout into a
  product conditional; make it configurable or drop it.

Checked and clean: `configs/tallow/scope/authorized-hosts.toml` (loopback,
`example.com`, `check.torproject.org` only — no client host, no grant to
`CONNECT`); `aamirmanisa` / `tallowsphere` / `Tallow-Language` references in
README, `install.sh:20`, `SECURITY.md:31`, `schemas/tallow/retailer-config.schema.json:3`,
`src/pkg/manifest.rs:547`, `src/signing.rs` — these are the intended public
identity of the project, not operator-personal data.

## 5. Class 4 — committed binaries and generated artefacts

| # | path | bytes | what it is |
|---|---|---|---|
| 18 | `examples/self_host.exp` | 2,248 | `Intel amd64 COFF object file, not stripped, 2 sections, 26 symbols, 1st section ".edata"` |
| 19 | `examples/self_host.lib` | 4,356 | `current ar archive` (a Windows import library) |
Rows 18-19 are x86-64 Windows link artefacts committed into an aarch64 Linux
workspace; the repo's own `.gitignore` excludes `examples/*.exe` and
`examples/*.ll`, so these two slipped past a rule aimed at exactly their class.
Nothing in the tree references them:

    rg -n 'self_host\.(exp|lib)' -g '!examples/self_host.*'
    # (no match outside this report)

**Retained, to be regenerated rather than excluded** — a correction to my first
pass, which had these in the exclusion set:

- `tests/fixtures/intel_traffic/sample-be-usec.pcap` (676 B)
- `tests/fixtures/intel_traffic/sample-le-usec.pcap` (676 B)

They are build outputs — but they are compiled *in*:

    rg -n 'sample-be-usec|sample-le-usec' tests crates src
    # tests/fixtures/intel_traffic/gen_pcap.py:130  (the generator writes both)
    # src/stdlib/intel_traffic.rs:1578  const LE: &[u8] = include_bytes!("../../tests/fixtures/intel_traffic/sample-le-usec.pcap");
    # src/stdlib/intel_traffic.rs:1579  const BE: &[u8] = include_bytes!("../../tests/fixtures/intel_traffic/sample-be-usec.pcap");

Excluding them without touching `src/stdlib/intel_traffic.rs:1578-1579` is a
compile error, so they are a rewrite (generate from `gen_pcap.py` at test time,
or drop the two `include_bytes!` lines) and their 1,352 bytes stay in the tree.
Their sha256, so a reviewer can confirm the regenerated copies match:

    de238d4fd393edb734934e37418596e48c7880483084c757018e25ce71153789  sample-be-usec.pcap
    f126c1fc41f986dd926a309b8f7ec6b135afd97ca08d4be726c94447a9a63dea  sample-le-usec.pcap

**Retained** — `assets/sphere-{compiler,extract,hero}-{dark,light}.png` (6 files,
608,878 bytes, largest 195,359). Human-authored brand artwork, referenced from
`README.md`, and carrying no metadata:

    for p in assets/*.png; do strings -n 6 "$p" | rg -i 'exif|xmp|/home|Photoshop|tEXt|Software'; done
    # (no output for any of the six)

## 6. Size table

Commands (each is a set operation over explicit paths; a duplicated row and a
missing row therefore cannot cancel out):

    cd /home/aamir/tallow-worktrees/w12/ember
    git ls-files | sort > /tmp/tracked.txt
    printf '%s\n' <class paths, one per line> | sort | while read -r f; do
        printf '%s %s\n' "$(stat -c %s "$f")" "$f"; done | tee /tmp/classX.txt \
        | awk '{b+=$1;n++} END{print "count="n, "bytes="b}'
    comm -12 /tmp/tracked.txt <(cat /tmp/classB.txt /tmp/classC.txt /tmp/classD.txt | awk '{print $2}' | sort) | wc -l
    comm -23 /tmp/tracked.txt <(cat /tmp/classB.txt /tmp/classC.txt /tmp/classD.txt | awk '{print $2}' | sort) | wc -l

| class | files | bytes |
|---|---|---|
| 1 client-engagement | 0 | 0 |
| 2 credential/attack-shaped | 13 | 209,711 |
| 3 operator-personal / machine names (excluded) | 4 | 128,005 |
| 4 committed binaries / generated artefacts | 4 | 7,956 |
| **EXCLUSION SET (union of 1-4)** | **21** | **345,672** |
| 3b rewrite-in-place (not excluded) | 11 | 68,421 |
| **tracked tree at 758e5bc** | **1,859** | **35,031,526** |
| **filtered publication tree** | **1,838** | **34,685,854** |

Cross-checks, all of which must hold (and do):

    comm -12 /tmp/tracked.txt /tmp/exclude.txt | wc -l   # 21  — every excluded path is tracked
    comm -13 /tmp/tracked.txt /tmp/exclude.txt           # (empty) — no invented path
    comm -23 /tmp/tracked.txt /tmp/exclude.txt | wc -l   # 1838
    git ls-files | wc -l                                 # 1859 = 1838 + 21
    awk '{b+=$1} END{print b}' /tmp/classB.txt /tmp/classC.txt /tmp/classD.txt  # 345672
    # 35,031,526 − 345,672 = 34,685,854

## 7. Work items — what this report cannot prove

1. **A build is required to prove the filtered tree compiles, and none was run.**
   Removing the 13 class-2 modules leaves live references behind. These are the
   exact sites, found by `rg -l`, in the files that must be edited together with
   the deletion:

   | site | what it references |
   |---|---|
   | `src/stdlib/mod.rs:76-81,83` | `pub mod {beehiiv,medium,substack,cxense,wordpress,ghost,jwt};` |
   | `src/stdlib/mod.rs:249-256` | dispatch arms `"beehiiv" \| "medium" \| "cxense" \| "substack" \| "wordpress" \| "ghost" \| "jwt"` |
   | `src/stdlib/mod.rs:376-378` | the module-name allowlist (string table) |
   | `src/interp.rs` (38 hits) | stdlib dispatch + native-name tables |
   | `src/typeck.rs` (5 hits), `src/codegen.rs` (4 hits) | declared-signature and lowering tables |
   | `src/browser/mod.rs` (1 hit each for wordfence/wordpress_auth) | browser module registration |
   | `tests/wordpress_login.rs`, `tests/egress_census.rs`, `tests/fixtures/stdlib_native_lowering/baseline.json` | tests that name the removed modules |

   `tests/egress_census.rs` is the sharp one: it is the egress-coverage gate, and
   deleting modules changes its expected surface. Per the lane rules this is a
   build-and-fix task, not something to assert from a text report.
2. **Two docs in the exclusion set are load-bearing for tests.** Excluding them
   breaks these, which must be edited in the same change:
   - `tests/sec1_honesty_sweep.rs:226` reads `docs/TALLOW-330-TOOLS.md`;
   - `tests/test_docs_truth_maintenance.py:129` lists the same path;
   - `tests/sec1_honesty_sweep.rs:228` reads `docs/MEGA_SCRAPER_ENGINE_RESEARCH.md`.
   `read()` on a missing path is a panic, so this is a red test unless the
   lists and the docs move together.
3. **`docs/claims-ledger.yaml` cites `docs/TALLOW-330-TOOLS.md` six times**
   (lines 171, 504, 623, 624, 625, 671). Excluding the doc leaves six dangling
   citations in the file the repo uses as its truth surface; the ledger rows must
   be retired in the same commit that removes the doc.
4. **`docs/operations/stub-register.md` row 90** cites
   `scripts/bbs_extract_vectors.py` as fixture provenance — hence rewrite, not
   exclude, for that script.
5. **`crates/tallow-net` relay address** `18.119.135.151:4433` (comments and
   tests) should become `relay.example.com` before publication. It is a live
   operator endpoint published as a test fixture.
6. **The `.gitignore` change in this worktree is not mine.** `reports/` was
   ignore-any-deep until this lane started; the working tree already carried an
   uncommitted edit un-ignoring `reports/*.md` so that a lane report can be cited
   from the repository. It is committed here as part of this report's commit and
   is called out in the commit message, because without it this file is untracked
   and the deliverable would vanish.

## 8. Reproduction block (start to finish)

    cd /home/aamir/tallow-worktrees/w12/ember
    git rev-parse HEAD HEAD^{tree}
    git ls-files | wc -l                                    # 1859
    git ls-files -z | xargs -0 stat -c %s | awk '{b+=$1} END{print b}'   # 35031526
    git ls-files -z | xargs -0 sha256sum | LC_ALL=C sort -k2 | sha256sum # b83db55c…

    # class 1 must be empty
    rg -l --no-messages -i 'modisoft|lathrop|512-850-1815' -g '!target/**' | wc -l  # 0

    # class 2 + 3 + 4 paths, as sets
    printf '%s\n' \
      src/stdlib/beehiiv.rs src/stdlib/cxense.rs src/stdlib/ghost.rs \
      src/stdlib/medium.rs src/stdlib/substack.rs src/stdlib/wordpress.rs \
      src/stdlib/jwt.rs stdlib/beehiiv.tl stdlib/cxense.tl stdlib/jwt.tl \
      src/browser/wordfence_bypass.rs src/browser/wordpress_auth.rs \
      docs/TALLOW-330-TOOLS.md \
      docs/opsec/stealth-scanning-statement-of-intent.md \
      docs/ops/watchlist_pqc_seed.md docs/MEGA_SCRAPER_ENGINE_RESEARCH.md \
      tests/fixtures/topology_adversarial/bypass_hostname_unlisted.tl \
      examples/self_host.exp examples/self_host.lib \
      tests/fixtures/intel_traffic/sample-be-usec.pcap \
      tests/fixtures/intel_traffic/sample-le-usec.pcap \
      | sort > /tmp/exclude.txt
    wc -l < /tmp/exclude.txt                                # 21
    git ls-files | sort > /tmp/tracked.txt
    comm -13 /tmp/tracked.txt /tmp/exclude.txt              # empty: no invented path
    comm -23 /tmp/tracked.txt /tmp/exclude.txt | wc -l      # 1838
    while read -r f; do stat -c %s "$f"; done < /tmp/exclude.txt | awk '{b+=$1} END{print b}'  # 345672
