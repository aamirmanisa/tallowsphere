# Native callback ABI (the `on_*` / `expose_*` family)

The callback methods are not blocked on closures. Two facts decide the design:

1. **The API takes a handler *name*, not a function value.** `page.on_console("handler")`
   registers the string `"handler"`; the handler is an ordinary top-level
   `fn` looked up by name.
2. **Delivery already has a thread contract in the interpreter.**
   `pump_page_handlers` runs "before each `Page` method so handler output appears
   in program order, immediately before the call that follows the event". The CDP
   pump thread only *buffers*; the program thread *delivers*.

So the native plane never re-enters compiled code from the CDP thread. Any design
that does is wrong on this runtime, no matter how convenient it looks.

## The ABI

Runtime → compiled code, one call per buffered event:

```c
void (*tallow_event_handler)(const char *kind,
                             const char *method,
                             const char *payload_json);
```

Three C strings rather than a struct: the event's shape (`PageEvent`) is a Tallow
struct, and only generated code can build one. Codegen emits a thin wrapper per
handler name that receives the three strings, constructs `PageEvent`, and calls
the user's function.

## Flow

1. `page.on_console("handle_console")` — codegen emits (once per name) a wrapper
   `@tallow_cb_wrap_<hash>` and registers it:
   `tallow_page_register_handler(page, "console", wrap_ptr)`.
   The runtime stores `(kind, fnptr)` and enables the CDP domain, exactly as the
   interpreter's arm does (`enable_runtime_events`).
2. The CDP pump buffers events into the page's per-kind buffer (it already does;
   `drain_events` is the reader).
3. **Before every `Page` method**, codegen calls `tallow_page_pump(page)`.
   The runtime walks its handler list, drains that kind, and calls each wrapper.
   No events, no call — the pump is cheap and must stay cheap, since it runs at
   the head of every page call.
4. A handler that calls a `Page` method re-enters the pump. It terminates because
   its own kind is already drained, matching the interpreter's note.

## Ordering and limits

- Ordering: FIFO per kind, delivered at the next page call — identical to the
  interpreter, so a parity test can assert byte-identical stdout.
- The pump must not recurse unboundedly: a handler that generates events of its
  own kind each call would loop. The interpreter has the same property (its note
  says "terminates unless the page produced new events"). Keep the behaviour, add
  a depth cap of 8 with a loud error rather than a stack overflow.
- `expose_function` / `expose_binding` ride the same table but are driven by
  `Runtime.bindingCalled`; the binding name travels in the payload, so one drain
  serves all bindings.

## Scope of the first slice

`on_console` end-to-end, verified against the interpreter on a page that logs at
known points, with the other seven still refusing loudly. Then extend one kind at
a time; the wrapper, the registry and the pump are shared.

## Why not "call the handler from the CDP thread"

Generated Tallow code is not re-entrant across threads: it has no locking, and the
runtime's own locks (`handlers`, event buffers) are held during delivery. Calling
compiled code from the pump thread would deadlock on the first handler that
touches the page, and would corrupt the program's own state if it did not.
