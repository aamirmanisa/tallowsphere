# Tallow Scraper Systems — 1000x Upgrade Plan

**Date:** 2026-08-04 | **Status:** executing

## Architecture survey
- 100 browser modules, 84,219 LoC
- Distributed scraper: 2,090 LoC (coordinator, discovery, registry, relay, scheduler)
- HackTheCart: 44 retail scraping modules (declared, partially wired)
- 24 TODO/FIXME items across browser/net
- 5 CDP TODOs (fd inheritance, pipes, socket paths)

## Phase D1 — Distributed Scraper (10x multiplier)
Wire the distributed browser pool into the runtime.
- `coordinator.rs` — gossip-based node coordination
- `discovery.rs` — peer discovery
- `registry.rs` — session registry with TTL expiration
- `relay.rs` — CDP relay server
- `scheduler.rs` — work distribution
- Add `tallow scraper cluster` CLI command
- Add integration test with 2-node cluster

## Phase D2 — CDP Gap Closure (2x reliability)
- Close 5 CDP TODOs (fd inheritance, named pipes, platform socket paths)
- Add Unix socket support for local CDP
- Add connection pooling for browser tabs
- Add browser crash recovery

## Phase D3 — HackTheCart Expansion (5x coverage)
- Wire 44 retail scraping modules into dispatch
- ProductMatcher, QualityValidator, PriceTracker, InventoryMonitor
- Add end-to-end retail scraper test

## Phase D4 — Stealth v3 (3x stealth)
- Fingerprint rotation per-request
- Residential proxy pool integration
- TLS fingerprint randomization
- Advanced antibot detection bypass

## Phase D5 — AI/ML Adaptive (10x intelligence)
- ML-based crawl strategy per domain
- Domain difficulty learning
- Auto-adaptive retry intelligence
- Content quality scoring

## Execution
- D1, D2, D3 dispatch as parallel subagents
- D4 + D5 sequential after D1-D3 land
