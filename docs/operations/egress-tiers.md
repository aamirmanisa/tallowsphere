# Egress tiers — target-class → egress-class mapping (P1 W1-E3/E4)

Scope: **design + gate stub**. Nothing in this document provisions a bridge or
buys commercial egress; both are operator-gated decisions (see §Operator gate).

## The mapping

| target class | requested egress   | state (R0)                                        |
|--------------|--------------------|---------------------------------------------------|
| `Public`     | `public-tor`       | live — the box default (fail-closed Tor)          |
| `Sensitive`  | `bridge`           | **operator-gated** — not provisioned              |
| `Hostile`    | `commercial`       | **operator-gated** — budget/contract decision     |

Implemented in `src/tor/tiers.rs` (`requested_egress_class`,
`effective_egress_class`). The **effective** class is what a run may use:

- Default `OperatorGate` (both approvals `false`) ⇒ **every** target class
  resolves to `public-tor`;
- a requested `bridge`/`commercial` class without its approval is **downgraded
  to `public-tor` with a visible reason string** — the downgrade is recorded,
  never silent;
- the two gates are independent (`bridges_approved` does not enable commercial
  spend).

## Operator gate (decision, not code)

- **Bridges** (`bridges_approved`): requires the operator to provision an
  obfs4/webtunnel transport (or a private Tor bridge) and record the approval.
  Until then, `Sensitive` targets run on `public-tor`.
- **Commercial egress** (`commercial_budget_approved`): requires a spend/
  contract decision (residential/mobile proxy provider) and a budget envelope.
  Until then, `Hostile` targets run on `public-tor`.

## One task = one exit (W1-E4)

Rule: a bounded task (one target set, one run window) egresses through **one**
exit — no exit reuse across *different* tasks inside the same window, and no
mid-task exit churn that would correlate sessions.

Where it is enforced today (each enforcement is in code, not prose):

- **Per-run SOCKS5 identity.** Every run path binds an `IsolateSOCKSAuth`
  credential pair (RFC 1929 userinfo) so Tor assigns a per-stream circuit:
  `tor::pool::{isolation_credentials, isolated_proxy_url}`,
  `TorPool::{attach_browser, isolate, fresh_circuit}`. The credential pair is
  minted **once per invocation** and reused for the whole session (sticky).
- **Per-domain isolation in the orchestrator.** `browser::antibot` pins each
  domain to its own cached circuit (`isolated_circuits`) and *drops the cache
  entry* when the escalation ladder reaches its rotate-egress rung — so a
  rotation is a fresh circuit, never a silent re-use of the pinned one.
- **Runner duty.** Batch runners re-probe per target block and carry a
  `requests`-counted state file (see the store-sweep driver), so a target set
  is processed under a single circuit epoch per pass. A future runner that
  needs a fresh epoch per target calls the rotate-egress path above.

### Browser CLI caveat (documented precedence, not a silent no-op)

`tallow browser --tor` binds the per-invocation credential URL into
`BrowserConfig.proxy` **and** writes the analytics-blocking PAC. When the PAC
is present it **supersedes** `proxy` in both engines (`browser/process.rs`), and
the PAC format (`SOCKS5 host:port`) cannot carry credentials — under an active
PAC the run egresses on the shared circuit. The credential URL takes effect on
the PAC-absent branch (e.g. PAC write failure). Follow-up options if
browser-CLI circuit binding must be credential-exact: per-run Tor instance
(dedicated port) or a generated PAC with a per-run sidecar SOCKS listener.
Registered as a residual in the P1 wave evidence.

## Not in scope here

- No new external endpoints or targets (P1 constraint).
- No Tor config changes on the live box (relay/daemon paths untouched).
