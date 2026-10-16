# Tallow — Agent Capability → Control Map

**Status:** analysis / mapping (proposed). This maps Tallow's compile-time agent capability flags onto
published agentic-AI threat models. It is **not** a certification or an audit result.

## 1. The capability model (source of truth)

`src/agent_pass.rs` declares five flags on an `@agent` function. A function lacking a capability is
rejected **at compile time** when it uses the corresponding operation (`E0302` and siblings):

| Flag | Default | Gates |
|---|---|---|
| `can_write` | `false` | filesystem write operations |
| `can_store` | `false` | persistent-store writes |
| `can_spawn` | `false` | spawning child agents |
| `can_network` | `true` (per spec) | `fetch` / `connect` |
| `can_execute` | `false` | process execution |

These are enforced at the compiler boundary, not inside tool code — the same discipline the MCP security
guidance asks for at the *server* boundary.

## 2. Mapping to MAESTRO (CSA — 7 layers + cross-layer)

MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) models an agentic system as seven
layers plus a cross-layer dimension. Tallow's flags govern behaviour concentrated at **Layer 3 — Agent
Frameworks** (tool access and autonomy boundaries), reaching into Layer 2 (Data Operations) and Layer 7
(Agent Ecosystem):

| Capability | MAESTRO layer | Threat the flag gates |
|---|---|---|
| `can_write` | 3 — Agent Frameworks | tool-access boundary → **T2 (Tool Misuse)** |
| `can_store` | 2 — Data Operations | data-write boundary |
| `can_spawn` | 3 → 7 | autonomy boundary → **T13 (Rogue Agents)**, **T12 (Agent Communication Poisoning)** |
| `can_network` | 7 — Agent Ecosystem | egress boundary → **T9 (Identity Spoofing)**, **T14 (Human Attacks on MAS)** |
| `can_execute` | 3 → 4 — Deployment & Infrastructure | execution boundary |

**Gaps named:** no capability flag governs **Layer 5 — Evaluation & Observability** (there is a separate
`agent_observability` surface but no flag) or **Layer 6 — Security & Compliance** as a first-class
capability.

## 3. Mapping to CSA AICM v1.1

The AI Controls Matrix (AICM) v1.1 is **247 control objectives across 18 security domains**, including the
AI-specific **Model Security (MDS-01 … MDS-13)** domain. Each capability flag is the enforcement point for
controls in the domains below (domain names per AICM v1.1; the exact control IDs live in the AICM
spreadsheet):

| Capability | AICM v1.1 domain |
|---|---|
| `can_write` | Application & Interface Security |
| `can_store` | Data Security & Privacy Lifecycle Management |
| `can_spawn` | Model Security (MDS) / Identity & Access Management |
| `can_network` | Identity & Access Management / Logging & Monitoring |
| `can_execute` | Threat & Vulnerability Management |

## 4. The gate this document answers

*"A control per capability; a name per gap."* Every capability flag above names the control it is the
enforcement point for; the two gaps (MAESTRO L5 and L6) are named rather than left implicit.
