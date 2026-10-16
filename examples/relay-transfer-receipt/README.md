# relay-transfer-receipt — Stage 3 / Slice 1 flagship demo

One real end-to-end product flow driven by the language:

1. `tallow relay` starts the TallowTransfer relay server (relay-v1).
2. `tallow send --relay … --code …` and `tallow receive --relay … --code …`
   pair live through the relay and transfer a file end-to-end encrypted
   (the crypto core is the shared canonical `tallow_protocol::transfer::relay`
   crate — the same crate the SendTallow product consumes).
3. `verify_receipt.tl` — a pure-Tallow program — independently verifies the
   receipt: BLAKE3 equality, chunk-tree root equality, size equality, and an
   optional caller-supplied expected hash. Exit 0 = verified, 2 = mismatch.

## Run

```bash
./run.sh                 # /tmp/tallow-receipt-demo by default
TALLOW=/path/to/tallow ./run.sh /tmp/my-demo
```

## Files

- `verify_receipt.tl` — the language-driven receipt verifier.
- `run.sh` — end-to-end runner (payload → relay → transfer → verify).

Evidence for the first recorded run lives in
`artifacts/sendtallow-integration-2026-09-15/stage3-slice1/`.
