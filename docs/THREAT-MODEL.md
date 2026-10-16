# Tallow — Threat Model (measured planes)

**Status:** published statement of what the toolkit defeats and does not defeat. Every claim here is a
*measured plane* — a statement of which adversary sees what — never an absolute. "Undetectable",
"untraceable" and "unbreakable" are not used here and must not be inferred.

## 1. What the egress plane defeats

- **A network observer on the path.** An on-path passive observer sees Tor traffic to an entry guard,
  not plaintext destinations or content. Prove the route with the egress acceptance check before relying
  on it: the plane is a separate repository (`tallow-scrape-sandbox`) and neither half is a working
  anonymous scraper without the other.
- **Destination-site identification.** When the browser lane runs over the Tor-routed proxy, the
  destination sees a Tor exit, not the box IP. **Exits rotate** — a previously observed exit is never
  current, and no pinned exit may be quoted as today's.

## 2. What it only partially defeats

- **An adversary who controls the exit node you drew.** The operator of that exit sees the destination,
  and the plaintext of any traffic that is not end-to-end encrypted. TLS hides content from a passive
  exit; it does not hide the destination. This is **partial by construction** — Tor cannot defend
  against the exit it selected.

## 3. What it does NOT defeat

- **End-to-end timing / volume correlation.** An adversary who observes both ends can correlate timing
  and volume. Tallow does not defeat this.
- **Site-level behavioural linkability.** Behaviour across a session — navigation order, cadence, an
  authenticated identity — can link sessions even behind Tor. Tallow does not defeat this.
- **A compromised endpoint.** Anything running on the box itself is outside a network-plane model.

## 4. The transfer / stealth tier

The transfer and stealth tiers are **"maximised stealth, leaks closed"** — not "undetectable". The
compile-time stealth/opsec passes reject a program that would write a hook or emit a fingerprint signal;
that is a statement about **programs the compiler refuses**, not about an adversary's inability to
observe traffic.

## 5. The rule behind this document

Any public claim about the toolkit's anonymity is stated as a **measured plane** ("the target sees a Tor
exit"), never as an absolute. Where an adversary class is not defeated, it is named here rather than left
to be inferred.
