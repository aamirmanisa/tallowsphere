# Tallow — I/O Plane Tiers

The I/O plane is tiered. **Kernel-bypass is not in the default tier.**

| Tier | Mechanism | When | Requirements |
|---|---|---|---|
| **Default** | `epoll` / `io_uring` (see `src/runtime/io_uring_runtime.rs`) | up to the ≤1 M connection tier | none |
| **Opt-in — large** | `io_uring` with registered buffers / IOPoll / SQPOLL / zero-copy | the >1 M tier | a runtime profile; **SQPOLL pegs a CPU core** |
| **Opt-in — kernel-bypass** | DPDK / SPDK | the >1 M tier **only** | **explicit opt-in, `root`** |

## The boundary

- DPDK / SPDK are **not** default dependencies and are **not** selected by any automatic path. A workload
  that wants kernel-bypass must ask for it explicitly.
- The intended enforcement is static: an `IPPool` of a given tier is a **static obligation** — the tier is
  chosen in source, not discovered at run time.
- Kernel-bypass needs `root`; it is out of scope for the confined default runtime.

## Why the order matters

`io_uring` is promoted to the default plane **in measured order** — async execution first, then batched
submission, registered buffers, IOPoll, SQPOLL, zero-copy. Naive adoption returns only **1.06–1.10×**; the
cumulative benefit is real only when the steps are taken in order. Each step therefore lands with its own
measured delta, and no step is merged without its number.
