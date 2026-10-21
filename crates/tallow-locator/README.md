<div align="center">

# tallow-locator

**Find a lawful place to run a workload, score it with a stated model, and refuse when nothing qualifies.**

![policy](https://img.shields.io/badge/policy-fail--close-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

Choosing a provider is usually a spreadsheet and a hunch. This crate turns it into a pipeline with an explicit model: poll official catalogs, normalise offers, score them on four axes, select — and when nothing meets the policy, **refuse and say so** instead of falling back to the cheapest thing that answered.

## What it is

| Stage | Module | Behaviour |
|---|---|---|
| Poll | `watchers` | Hetzner, Vultr, DigitalOcean, OVH. Each has a **fixture** source (deterministic JSON) and an **HTTP** source (official API, own key) |
| Normalise | `model` | `Offer`, `JobClass` — one shape regardless of provider |
| Score | `score` | Cost · latency · jurisdiction · capability, with class-dependent jurisdiction policy and static latency baselines |
| Select | `select` | Fail-close: zero compliant offers ⇒ an explicit `Refusal`, exit `3` |
| Record | `receipts` | `locator.scorecard` and `locator.refusal` receipts on the registry ledger |

Jurisdiction policy is not a tiebreak. The `privacy` class excludes US jurisdictions and treats an unknown country as disqualifying; the model documents its weights (`locator-model/v1`) so a reviewer can argue with them.

## What it is not

- **Not a provisioner.** It decides where a workload *may* run; spending money is a separate, gated step.
- **Not a live latency probe.** v1 uses a static baseline table, marked as such. A baseline is not a measurement of the moment.
- **Not a compliance certification.** It applies a policy you configure; it does not establish that the provider is lawful for your use.
- **Not autonomous.** `--live` is required for any network call. Without it the CLI reads fixtures and touches nothing.

## Quick start

```console
$ cargo build -p tallow-locator

# score a set of fixtures and pick, without touching the network
$ ./target/debug/tallow-locator scan --fixtures ./fixtures --class privacy

# machine-readable
$ ./target/debug/tallow-locator scan --fixtures ./fixtures --class privacy --json

# the built-in self-test
$ ./target/debug/tallow-locator selftest
```

Exit codes: `0` a compliant offer was chosen · `3` refused (fail-close) · `2` usage · `1` error.

A refusal is a **result**, not a failure: it means the policy held and the answer is "none of these". The refusal receipt records how many offers were considered and which exclusion applied.

### Live polling

```console
$ export HCLOUD_TOKEN=…
$ export VULTR_API_KEY=…
$ export DIGITALOCEAN_TOKEN=…
$ export OVH_APP_KEY=…
$ export TALLOW_LOCATOR_PROXY=socks5://127.0.0.1:9053   # optional egress proxy

$ ./target/debug/tallow-locator scan --fixtures ./fixtures --class relay --live --ledger receipts.jsonl
```

Without `--live`, provider keys are never read and no socket is opened.

## Configuration

| Variable | Used for |
|---|---|
| `HCLOUD_TOKEN` | Hetzner API |
| `VULTR_API_KEY` | Vultr API |
| `DIGITALOCEAN_TOKEN` | DigitalOcean API |
| `OVH_APP_KEY` | OVH API |
| `TALLOW_LOCATOR_PROXY` | Proxy for live polling (`socks5://` or `http://`) |

Flags: `--class privacy|relay|general`, `--only-country CC,CC`, `--json`, `--ledger <path>` (appends a signed receipt; DEV key unless a real key is configured).

## Deploying it

The locator is a decision tool, not a service. The production shape is a scheduled scan whose receipt lands in the fleet ledger:

```ini
# /etc/systemd/system/tallow-locator.service
[Service]
Type=oneshot
EnvironmentFile=/etc/tallow/locator.env
ExecStart=/usr/local/bin/tallow-locator scan \
  --fixtures /srv/tallow/fixtures --class privacy --live \
  --ledger /var/lib/tallow/receipts.jsonl
User=tallow
```

Then verify the ledger like any other: a scorecard nobody can check is a preference, not a decision record.

Rules:

- **Provider keys belong in a credential file**, not in a unit's `ExecStart` line.
- **Route `--live` through the proxy** when the scan itself should not reveal the box.
- **Keep fixtures under version control.** They are how the model's behaviour is reviewed without network variance.

## Design notes

**Why fail-close.** A selector with a fallback path will eventually use it at the worst moment, and the fallback will be the cheapest non-compliant offer. Refusal is the only behaviour that cannot silently violate the policy.

**Why the model is versioned.** `locator-model/v1` is part of the receipt. When weights change, old decisions remain interpretable.

**Why fixtures ship with the code.** A scoring model is a policy; policy tests must not depend on what a provider's catalog looks like today.

## Verification

```console
$ cargo test -p tallow-locator
$ cargo test -p tallow-locator score -- --nocapture
$ cargo test -p tallow-locator select -- --nocapture
$ ./target/debug/tallow-locator selftest
```

20 test functions in the crate source [measured 2026-10-21], covering jurisdiction tiers, exclusion ordering, refusal on empty compliant sets, and receipt shape.

## Limits

| Limit | Detail |
|---|---|
| Static latency baselines | Marked as baselines; not a live probe |
| No provisioning | By design — spending is a separate gate |
| Four providers | Hetzner, Vultr, DigitalOcean, OVH |
| No Onionoo/RDAP/Atlas sources | Follow-ups, not shipped |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
