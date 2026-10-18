# Page events — delivery contract

How `PageEvent`s reach `.tl` code, and what the guarantees are.

## One buffer and one pump per CDP session

Events are recorded by a background task that subscribes to the connection's
CDP event stream and filters on the page's session id. The buffer and the
"pump already started" flag live on the CDP client, keyed by session id — not on
the `Page` value.

Why: a `Page` is cloned freely, and a pooled page is wrapped in a fresh `Page`
on every acquire. With a per-value buffer, each clone/re-acquire spawned another
listener whose events nobody drained, while the handle the caller now holds
started with an empty buffer. Register #112.

Consequences:

- Every `Page` value for one session reads the same buffer.
- A second construction for a session never starts a second pump.
- `Page::from_cdp` discards whatever the previous lease left in the buffer, so a
  re-acquired pooled page never delivers another run's traffic.
- `Page::from_cdp_raw` builds a page **without** a pump, for call sites that
  cannot await. Handlers registered on such a page never fire.

## Capture is opt-in for console and error

The pump enables `Page` and `Network`. It does **not** send `Runtime.enable`:
that command is a strong CDP-attachment signal, and the pump runs for every
page. Without `Runtime.enable` there are no `consoleAPICalled` or
`exceptionThrown` events — network events are unaffected.

Opt in with:

| Call | Effect |
| --- | --- |
| `page.capture_console()` | sends `Runtime.enable`, idempotent per session |
| `page.on_console(f)` / `page.on_error(f)` | enables, then registers |
| `page.expose_function(...)` / `page.expose_binding(...)` | enables, then adds the binding |

A program that only polls (`page.drain_events("console", n)`) must call
`capture_console()` first; otherwise it gets an empty list, because the events
were never delivered to the client.

## Delivery is deferred

The interpreter is single-threaded; a CDP event arrives on the browser runtime,
where a `.tl` function cannot be called. Registered handlers therefore run at
the **start of the next `Page` method call**, in registration order, one call
per buffered event.

- Any `Page` call is a delivery point (including `wait_for_timeout(0)`).
- `page.close()` delivers pending events first, then closes the target — after
  the close the session is gone and nothing can be delivered.
- `browser.close()` does **not** deliver: it destroys the browser, and there is
  no page left to pump. A program that must flush calls `wait_for_timeout(0)`
  (or `page.close()`) before closing the browser.

Handlers live on the `Page` value, not in an interpreter registry, so nothing
outlives the page that registered it. Registering the same `(kind, function)`
pair twice is a no-op.

## Buffer

- Capacity 512 events per session; the oldest are dropped when full.
- Draining removes: a second drain of the same kind returns `[]`.
- Kinds: `console`, `error`, `request`, `response`, `filechooser`, `download`,
  `binding`.

## Native plane

The browser API has no native lowering. `tallow run` on a browser program prints
`native build unavailable (page.goto/navigate …)` and runs it in the
interpreter; `tallow build` reports the same. This is deliberate: the backend
cannot construct `NavigationResult`, and returning a wrong value would be worse
than falling back. The interpreter is the supported execution plane for browser
programs.
