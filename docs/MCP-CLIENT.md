# The MCP client: Tallow consuming someone else's tools

Sheet item **U-G03** — *"Add an MCP **client**. Export-only means Tallow is a tool, never the
orchestrator."* Gate: *"Consumes a third-party MCP server in an integration test."*

Tallow had no MCP code and no MCP dependency before this: `rg -i mcp` over the tree found only prose
in docs. This is the client direction — the engine calling out to a third-party tool server — as
opposed to the *export* direction, where Tallow's own tools are the thing being consumed.

**The two halves now exist and they are different halves.** The export direction was already here:
`src/stdlib/agentic.rs` gives `Agent.mcp_tools()`, which exports Tallow's capabilities as MCP tool
*definitions*, and `mcp_pass` (E1801) is a policy pass over that surface. Neither of those can call
anyone. That is precisely the asymmetry the item names: with export only, Tallow is a tool and never
the orchestrator. This client is the missing direction; it does not duplicate the export path.

## The wire format, verified rather than assumed

**Newline-delimited JSON-RPC 2.0 over the child's stdin/stdout.** Not the LSP-style
`Content-Length:` framing. This is the one trap in the whole item, because both framings are
honestly describable as "JSON-RPC over stdio", and picking the wrong one fails as a parse error on
the first byte rather than as a protocol error — it looks like a server bug, not a client bug.

Probed directly against two real servers before a line of Rust was written (2026-10-16):

```
$ printf '{"jsonrpc":"2.0","id":1,"method":"initialize",...}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' | caveman-mcp
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{}},"protocolVersion":"2024-11-05","serverInfo":{"name":"caveman","version":"dev"}}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"caveman_compress", ...}]}}
```

Same shape from the canonical reference server (`npx -y @modelcontextprotocol/server-filesystem`):
one line in, one line out, `serverInfo.name = "secure-filesystem-server"`. One request per line,
one response per line, no headers — confirmed on two independent implementations, one Go and one
Node, so it is the protocol and not one server's quirk.

Sequence: `initialize` → `notifications/initialized` → any method. Responses are correlated by
`id`; notifications (no `id`) and any stray non-JSON logging are skipped rather than treated as
protocol errors, because a server is entitled to log on stdout's sibling and a client that aborts
on the first unexpected line is fragile against servers it did not write.

## The three failure modes it is built to avoid

These are the ones that make an MCP client *look* finished while being useless:

1. **A wedged server must time out, not hang the caller.** stdout is drained on a reader thread
   into a channel and every wait is a `recv_timeout` (30 s default), so a server that never answers
   produces a timeout naming the method — not an infinite block, and not an empty result.
2. **A failed tool must not read as a successful empty result.** `tools/call` returning
   `isError: true` is surfaced as `Err`, because prose describing a failure is exactly what a
   caller will otherwise act on as if it were output.
3. **Success must not be inferable from silence.** The integration test asserts that calling a
   **nonexistent** tool comes back as an error — without that assertion, a client returning an
   empty `String` for every call would pass a naive test suite.

## Use

```sh
# What does this server offer?
tallow mcp tools -- /root/.caveman/bin/caveman-mcp

# Call one of its tools. VALUE is parsed as JSON when it parses, else taken as a string.
tallow mcp call --tool caveman_compress --arg input="$(cat big.log)" \
  -- /root/.caveman/bin/caveman-mcp

# When the value IS JSON text that must stay a string, use --arg-str (--arg would send an object):
tallow mcp call --tool caveman_toon_encode --arg-str 'input=[{"a":1,"b":2}]' \
  -- /root/.caveman/bin/caveman-mcp
# -> {"output":"[1]{a,b}:\n  1,2","encoded":true,"input_bytes":15,"output_bytes":15}

# Any stdio MCP server works, including the canonical reference one:
tallow mcp tools -- npx -y @modelcontextprotocol/server-filesystem /tmp
tallow mcp call --tool list_directory --arg path=/tmp \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

**`--arg` infers the JSON type; `--arg-str` forces a string.** `path=/tmp` → string, `tail=10` →
number, but `input={"a":1}` would be sent as an *object* and a tool expecting JSON *text* rejects it.
That is not hypothetical — it is how this CLI first failed against `caveman_toon_encode`
(`cave_invalid_arguments: missing input`). `--arg-str` is applied after `--arg`, so for a repeated
key the explicit "this is a string" wins over the inference.

The tool list goes to **stdout** so it can be piped; diagnostics (the server banner, the tool count,
errors) go to **stderr**. Exit codes follow the CLI's existing convention:
`5 IO_ERROR` for a server that will not start or answer, `64 USAGE_ERROR` for a malformed `--arg`.

## Scope

Deliberately a client core, not a platform: `initialize` / `tools/list` / `tools/call` only.
Resources, prompts, sampling, roots, and reconnection are **not** implemented. The child's stderr is
inherited rather than captured, so a server that refuses to start explains itself instead of failing
silently. `McpClient::drop` kills the child — a server does not outlive the process that spawned it.
