# public_source_get_batch.tl

Release-quality local fixture example for `http.batch` over public-source-style GET targets.

## Command

Terminal 1:

```bash
python3 examples/fixtures/mock_server.py --port 18080
```

Terminal 2:

```bash
./target/debug/tallow run examples/public_source_get_batch.tl
```

For the card verification check only:

```bash
./target/debug/tallow check examples/public_source_get_batch.tl
```

## Expected output

```text
public_source_get_batch planned=2
public_source_get_batch responses=2
```

The check command should print:

```text
check passed: 2 items, 0 warning(s)
```

## Fixtures

- `examples/fixtures/mock_server.py` binds `127.0.0.1` and serves `/status` and `/api/products`.
- The TL file intentionally targets `http://127.0.0.1:18080/...` only.

## Non-claims

- No public internet access.
- No secrets or vault resolution.
- No browser fallback or browser artifacts.
- No production/live compliance gate claim.
- No benchmark/performance claim.
