# The handle registry — design for the four bucket-B modules

Design only. **No cargo was run, no code was changed**; every claim states its evidence as
`[read]` (a static reading of the file at the stated line) or `[baseline]` (the checked-in
census fixture). Citations are resolved against this worktree at `4a8db9a`; the sibling triage
doc `docs/intel/native-lowering-gaps.md` cites `345f205`, so its line numbers have drifted and
none of them are reused here unverified.

Inputs, as the task names them:

| Artefact | What it contributes |
|---|---|
| `docs/intel/native-lowering-gaps.md` §Bucket B | the four modules, and the four properties a bridge-shaped handle would need |
| `src/runtime/stdlib_bridge_ffi.rs` | the JSON round trip, the prefix discriminators, who owns the returned pointer |
| `src/codegen.rs` | the bridge dispatch gate, `BridgeOpaque` and its single legal consumer, the `Handle` type that does not exist |
| `src/stdlib/{ws,net,relay_room,browser}.rs` | the registries and handle values that exist today |
| `src/scope.rs`, `configs/tallow/scope/authorized-hosts.toml` | the authorization register a mint must consult |

The design answers four questions in order — what a handle carries (§2), where the registry
lives and how a handle crosses the bridge (§3), what frees it (§4), and the smallest honest
version (§5) — and then delivers the failure cases as tests to write (§6) rather than as prose.

---

## 1. What exists today, measured

Four modules, four different handle shapes, and 32 independent registries across
`src/stdlib/*.rs` (`grep -c 'LazyLock<Mutex<HashMap' src/stdlib/*.rs` → 32), 13 of them in
`net.rs` alone. This is the surface the registry has to absorb.

| Module | Registry | Id allocator | Handle value the program holds | Close path | Close semantics |
|---|---|---|---|---|---|
| `ws` | `WS_CONNECTIONS: Mutex<HashMap<u64, WebSocket>>` (`ws.rs:82`) | `NEXT_WS_ID: AtomicU64` from 1 (`ws.rs:81,85`) | `Struct{name:"WebSocket", id:Int, url:String}` (`ws.rs:400-406`) | `ws_close` (`ws.rs:436`) | `remove` → `None` ⇒ `Ok(Nil)` — double close is a no-op *and so is a close of an id that never existed* |
| `net` (TorPool) | `TOR_CONNECTIONS: Mutex<HashMap<u64, TorConnectionState>>` (`net.rs:1033`) | `NET_ID_COUNTER: Mutex<u64>` from 0, shared by **all 13 net registries** (`net.rs:134,136`) | `Struct{name:"TorPool", _tor_id:Int, size, ready, rotation, socks_addr, control_addr}` (`net.rs:1084-1094`) | `tor_close` (`net.rs:1199`) | `remove(&id)` unconditionally, `Ok(Nil)` — same conflation |
| `relay_room` | `ROOMS: Mutex<HashMap<u64, Sender<Cmd>>>` (`relay_room.rs:83`) | `ROOM_ID_COUNTER: Mutex<u64>` from 0 (`relay_room.rs:85,88`) | room id carried in the `RelayRoom` struct | `room_leave` (`relay_room.rs:669`, `remove` at `:671`) | `remove` — but the sender is also removed on **every** operation and re-inserted (`take_sender` `:276`, `put_sender` `:284`), so "absent" already means "in use" as well as "closed" |
| `browser` | none — a thread-local singleton page (`src/runtime/browser.rs:219`) | CDP's own `browserContextId` string | `Struct{name:"BrowserContext", context_id:String, proxy, timezone, locale, isolated, pages_count}` (`src/stdlib/browser.rs:589-599`) | none | the context is never disposed; `disposeOnDetach:false` at mint (`src/stdlib/browser.rs:570`, inside `with_bound_page` at `:569`) |

Three facts fall out of that table and shape everything below.

**1. The id spaces collide.** `ws` handle 1, `TorPool` 1 and relay room 1 are three different
live objects in the same process. What separates them today is a *name check on the value* —
`dispatch_method` matches `if name == "WebSocket"` (`ws.rs:339`) — i.e. a string field inside
the value the program holds, not anything the registry owns.

**2. Non-reuse is an allocator property, not a handle property.** `ids are never reused` is true
only because each counter is monotonic and nothing resets it. Every one of these registries is a
process-global static with no teardown (`gaps` §Bucket B, "registry affinity"), so the property
holds until someone adds per-run reset, slot reuse, or a second table behind the same type name.
At that moment a stale id stops being an error and starts being *a different live object* — the
ABA problem, in the one place where the consequence is "your program now writes to a socket it
never opened".

**3. "Absent" is overloaded three ways.** Closed, never-minted, and (in `relay_room`) currently
checked out all look identical to a `HashMap::get`. `ws_close` (`ws.rs:445-448`) documents the
collapse deliberately — "Closing an already-closed handle is a no-op, not an error" — which is
the right *policy* stated at the wrong *layer*: it cannot distinguish the caller who closed
twice from the caller who forged an id.

---

## 2. What a handle must carry

### 2.1 The record

The registry owns the resource; the program owns a *name* for it. One record per mint:

```
struct HandleRecord {
    slot:       u32,          // index into the kind's table; may be reused after close
    generation: u32,          // incarnation of that slot; bumped on every reuse, never on close
    kind:       HandleKind,   // ws.socket | net.tor_pool | relay_room.session | browser.context
    owner:      OwnerId,      // (epoch: u64, grant: GrantId)
    state:      SlotState,
}

enum SlotState {
    Live(Payload),                              // in the table, callable
    CheckedOut,                                 // leased to a caller mid-method
    Closed { at: Timestamp, reason: CloseReason },  // tombstone; payload already dropped
}
```

Four fields, four jobs, each answering a distinct failure that the current design cannot express:

- **kind** answers *which table*. It is the registry's own discriminator, so a value cannot
  choose its own route: a payload claiming `WebSocket` whose token says `net.tor_pool` is
  refused before a table is touched.
- **slot + generation** answer *which incarnation*. Slot reuse is what makes memory bounded;
  generation is what makes reuse safe. Neither alone is enough: slot alone is ABA, generation
  alone leaves the table unbounded.
- **owner** answers *under whose authority*. Two components, because they fail differently:
  `epoch` catches a handle replayed after the registry was reset inside the same process (the
  multi-program case — `tests/` runs many programs per test binary); `grant` catches a handle
  whose authorization is no longer live (§3.4).

### 2.2 The value the program holds

Exactly one opaque field, a string:

```
Struct { name: "WebSocket",
         _handle: "ws.socket/3/1/7f2a",     // <kind>/<slot>/<generation>/<epoch>
         url:     "wss://feed.example" }    // user-facing fields stay readable
```

A packed string rather than four `Int` fields, for three reasons that are each a test in §6:

1. **It cannot be arithmetic'd into a plausible handle.** `h.id + 1` today yields a value that
   `handle_id` (`ws.rs:356`) happily casts to `u64` and looks up. A token has no successor.
2. **It is printed as one opaque blob**, not as a struct that reads like ordinary data.
3. **It is parsed with a whitelist**, the same discipline `parse_float_tag` already uses for
   non-finite floats (`stdlib_bridge_ffi.rs:135-142`): a token this runtime did not write is
   refused, never interpreted.

The user-facing fields (`url`, `size`, `ready`, `rotation`) stay exactly as they are — `TorPool.ready`
is read by programs and is data, not authority. `_handle` is deliberately **not declared** in
`stdlib/ws.tl` (`stdlib/ws.tl:7-9` declares `struct WebSocket { url: String }`), which closes the
literal-construction path: `typeck` refuses a struct literal with an undeclared field
(`src/typeck.rs:3666`, `"struct `{name}` has no field `{}`"`).

### 2.3 Why an id alone is unsafe — three collapses, each with a line

**Collapse A — same integer, different object, chosen by the program.**
`ws` id 1 and `net` TorPool id 1 coexist (`ws.rs:81` vs `net.rs:134`). Routing is decided by the
struct name in the value (`ws.rs:339`, `src/stdlib/mod.rs:582`, `:590`), and `json_to_value` will build a
`Struct` of *any* name from a payload carrying `__type` (`agent_comm.rs:236-246`) — it never
consults the declaration. So the name is a claim the value makes about itself. With id alone,
the claim *is* the routing decision. With `kind` in the record, the claim is checked against the
registry and a mismatch is a refusal.

**Collapse B — ABA after slot reuse.**
Close handle 3, free slot 3, mint a new socket into slot 3. The old token (kind, slot 3, gen 1)
now names a live object it never minted. Generation 2 is the only thing that can tell the two
apart. Today this cannot happen *only* because nothing reuses slots; the moment a per-run reset
or a compacting allocator lands, it is the default behaviour.

**Collapse C — replay across runs in one process.**
The registries are `LazyLock` statics (`ws.rs:82`), so they survive a second program run in the
same process. A handle value captured from run *n* resolves in run *n+1* if the ids happen to
line up. `epoch` makes that a category, not a coincidence: every mint stamps the current epoch,
every resolve compares.

The one thing an id + generation + epoch does **not** give you is unguessability, and §3.5
states that plainly rather than implying a secret that is not there.

---

## 3. Where the registry lives, and how a handle crosses

### 3.1 One place, in the process, reachable from both call paths

`src/runtime/handles.rs`, exported through the crate that is already compiled twice over:
`Cargo.toml:14` declares `crate-type = ["lib", "staticlib"]`, and `tallow build` links
`libtallow_runtime.a` / `libtallow.a` into the emitted executable (`src/codegen.rs:28855-28872`).
Consequence, and it is the whole answer to "so both planes see it":

- **Interpreted plane**: `interp.rs:14774` calls `stdlib::dispatch_method` (`src/stdlib/mod.rs:475`), which
  calls into the same `Handles` statics.
- **Compiled plane**: emitted IR calls `extern "C"` entry points in `src/runtime/handles.rs`,
  which are in the *same address space* because they are in the same static library.
- **There is no third place.** The registry is never a file, never a socket, never an env var,
  never a side channel between the interpreter and a built binary. A handle that leaves the
  process is not a handle; it is a number, and the epoch check is what makes it inert.

That is stronger than the status quo the triage doc describes as "affinity by accident"
(`gaps` §Bucket B): the statics are shared because `tallow_stdlib_call` happens to run the
interpreter's dispatch in-process. Here it is shared because the ABI is defined to be shared,
and §6 pins it with a test that goes through the compiled binary, not through the interpreter.

**Per-kind tables, one shared allocator.** `Handles` is
`LazyLock<Mutex<Registry>>` where `Registry` holds the epoch, the shared slot allocator, and a
`HashMap<HandleKind, KindTable>`; each `KindTable` has its own lock and its own payload map.
Not one global map, for a reason grounded in the code: `ws` holds its registry lock **across the
blocking read** — the module doc says so explicitly (`ws.rs:78-80`, "the lock is held across the
blocking read/write inside a method call") — so a single global lock would let one `ws.recv(7000)`
stall every `TorPool` and browser-context operation in the process. Per-kind locks keep the
serialization where the module already accepts it.

### 3.2 The lease, not the held lock

Resolve returns a lease; the payload is taken out of the table, the method runs, the payload goes
back. This is `relay_room`'s existing `take_sender`/`put_sender` (`relay_room.rs:276,284`)
generalized — and generalizing it is also what fixes `relay_room`'s ambiguity: with a
`CheckedOut` state in the record, "absent" no longer has to mean "closed".

```
resolve(token, expected_kind, current_epoch) -> Result<Lease, Refuse>
  Lease  // holds the payload; Drop returns it to Live
```

A `RuntimeError` mid-method returns the lease through `Drop`; only an explicit `close` writes a
tombstone. On the compiled plane a mid-method abort kills the process, so there is no unwinding
to get right — stated as a limitation, not hidden (§4.3).

### 3.3 Crossing the bridge: a name, not an authority

The handle crosses as tagged JSON on the existing round trip: `value_to_json` writes
`__type` plus every field (`agent_comm.rs:185-197`), `json_to_value` reads it back
(`:236-246`), both wrapped in `RAW_PREFIX` (`stdlib_bridge_ffi.rs:99`). No new encoding is
needed for the value itself. What is needed is a **new entry point for the receiver**, because
the bridge can only dispatch on a module ident — `emit_method_call` reaches the bridge only when
`!self.variables.contains_key(other)` (`src/codegen.rs:9375`), i.e. never for a value.

The new ABI, mirroring `tallow_stdlib_call` (`stdlib_bridge_ffi.rs:149`) and declared alongside
it at `src/codegen.rs:1920`:

```c
char *tallow_stdlib_call_method(const char *handle_json, const char *method,
                                long argc, const char *const *argv);
```

It decodes the first argument to a `Value::Struct`, calls `stdlib::dispatch_method`
(`src/stdlib/mod.rs:475`) — which already has the arms this design needs: `WebSocket` (`src/stdlib/mod.rs:582`),
`RelayRoom` (`:586`), `TorPool` (`:590`) — and encodes the result through the existing
`encode_result` (`stdlib_bridge_ffi.rs:259`). No second implementation, same as the module
bridge: the compiled plane's semantics are the interpreter's by construction.

Codegen needs one new type and one new arm:

- `LLType::Handle(kind)` — like `BridgeOpaque` in that it is a pointer to marshalled JSON, unlike
  it in having exactly two legal consumers: (a) another `tallow_stdlib_call_method` on the same
  kind, (b) an argument to a bridged call whose declaration accepts that kind. `print`,
  `+`, `==`, `if`, `to_string` and coercion all refuse through the existing
  `refuse_bridge_opaque` hook (`src/codegen.rs:21972`), extended to name the kind.
- `RetKind::Handle(String)` in `src/stdlib/signatures.rs:61-75`, so `WS.connect`'s declared
  `-> WebSocket` (`stdlib/ws.tl:13`) classifies as a handle rather than as `Named`, which today
  keeps a bare pointer the whole backend then treats as ordinary data. This is the difference
  between a census flip and a usable module.

### 3.4 Scope: the registry is the mint chokepoint

`ws.connect` opens a TCP socket to an arbitrary URL today with **no scope consult** — the grep
for `scope|require_authorized` in `ws.rs` and `relay_room.rs` returns nothing. `net`'s pool
creation probes live endpoints (`net.rs:1041-1085`). A handle registry that mints those without
a grant would be the defect this design exists to avoid.

Mint becomes: `scope::require(host, "<kind>")` (`src/scope.rs:686`) → `Decision::Allowed(entry)`
→ the grant id goes into `HandleRecord.owner.grant`. A refusal is the register's own, with the
register's own codes (`scope:not-listed`, `scope:expired`, `scope:register-unreadable`, …,
`src/scope.rs:129-159`), and it happens **before the socket is opened**, which is testable by
counting accepts on a loopback listener (§6, T12) rather than by reading the code.

Two rules that make the grant honest rather than decorative:

- **Reloading the register invalidates every handle minted under it** (epoch bump). Fail-closed:
  a long-lived session cannot outlive the authorization that created it. The alternative —
  re-validate on every method call — costs a register read per `recv` and still leaves the
  window; the cost is stated in §7 as decision D2.
- **The grant is in the record, not the token.** A program cannot move a handle between owners by
  editing the value it holds.

### 3.5 What actually stops this being a capability leak — and what does not

The leak to design against is not "an attacker guesses the number". It is **the token escaping
the authority that minted it**. Four escape routes, four closures:

| Route | Closure |
|---|---|
| E1 **printed** — `print h` writes the marshalled JSON, id and all, to stdout, into a log, into a file | `LLType::Handle` refuses print/coerce/compare via `refuse_bridge_opaque` (`codegen.rs:21972`). Today a struct result keeps a raw pointer (`signatures.rs:68`, `Named`), so this is currently open. |
| E2 **passed sideways** — handed to a module that does not accept that kind | marshal-time kind check against the callee's declaration; refusal is a build/abort naming the kind, not a runtime type confusion |
| E3 **persisted and replayed** — written to a file, read by a later run or another process | a new process has an empty table (`Unknown`); a later run in the same process has a different epoch (`StaleEpoch`); the token grammar is never accepted from a program string, only from a decoded handle value |
| E4 **synthesised** — a program builds `WebSocket{_handle: "ws.socket/1/1/0"}` | literal path closed by typeck (`typeck.rs:3666`) because `_handle` is undeclared; JSON-decode path is open only to values the registry itself encoded, since nothing in the language turns program text into a tagged `Struct` today (that is `json.parse<T>`, bucket A, and §5.4 makes it a constraint on that work) |

**Residual risk, stated rather than papered over:** within one epoch and one owner, a handle is a
*bearer token* — a program that constructs the right token string reaches the socket. There is no
per-handle secret and this design does not add one, because the "attacker" is the same program
holding the same grant; a MAC would be security theatre. The properties actually bought are:
no cross-kind alias, no ABA, no cross-run replay, no accidental printing, and no mint without a
live grant. §6 keeps T2/T4/T5/T7 as the tests that hold that line.

---

## 4. Lifetime: what frees a handle

### 4.1 The four frees

| Free | What it does | Runs when |
|---|---|---|
| **explicit close** — `h.close()` / `h.leave()` | payload dropped, record → `Closed{at, reason}` tombstone; generation **not** bumped | program asks; the only free that releases the socket while the program is still live |
| **`defer h.close()`** | same, at function exit | both planes scope `defer` to the **function frame**, not the block — `codegen.rs:5955` pushes to `defer_stack`, emitted LIFO before every `ret` and at the epilogue; `interp.rs:2577-2588` pushes to `deferred_stack.last_mut()` with the comment "current function frame". So it fires on early returns, and does **not** fire on abort |
| **registry reset** — `Handles::reset()` | every live payload closed, every slot tombstoned, `epoch += 1` | the interpreter's run entry, and a `tallow_handles_reset()` call emitted at the single `main` return in the compiled plane |
| **process exit** | the OS closes the fd | always; not a teardown — no close frame, no flush, no destructor order |

What does **not** free a handle, and is worth stating because the code invites the confusion:
`tallow_free_string` (`src/runtime/mod.rs:119`) frees the *marshalled text*, never the resource.
`emit_stdlib_bridge_call` frees a bridged result's pointer at the end of the binding's block
(`codegen.rs:23057` contract, `bridge_binding_escapes` at `:23130`). Dropping the text must never
close the socket, and §6 (T16) pins that as an invariant rather than a comment.

### 4.2 Double close and use-after-close — two different answers

The design refuses to conflate them, which is exactly what `ws_close` does today
(`ws.rs:445-448`, `remove` → `None` ⇒ `Ok(Nil)`):

- **Double close** — token generation == record generation, state `Closed` ⇒ `Ok(Nil)`, no-op.
  The caller's intent (the socket is gone) already holds. Unchanged behaviour, now enforced in
  the registry instead of re-implemented in each module.
- **Close of a dead incarnation** — token generation < record generation ⇒ **refuse**, `Stale`.
  The id was reused; this token names something that no longer exists, and silently succeeding
  would hide the bug that produced the stale copy.
- **Close of a never-minted token** — slot never allocated, or generation 0 ⇒ **refuse**,
  `Unknown`. Today this is indistinguishable from a double close; that is the hole.
- **Use-after-close** — any method on `Closed` ⇒ refuse, naming the kind, the token, and when it
  closed. Never a silent reconnect: `ws.rs:367-371` already states that policy ("silently opening
  a new socket would make `send` succeed against a connection the program never established") —
  the registry makes it structural instead of per-module.
- **Use while checked out** — second thread resolving a `CheckedOut` record ⇒ `Busy` refusal,
  not a block on the payload lock.

### 4.3 The honest limitation

A compiled program that never closes leaks nothing at exit (the OS reclaims the fd) but holds
the socket for its whole run, and a compiled program that aborts — which is every bridge failure,
`tallow_stdlib_bridge_abort` (`stdlib_bridge_ffi.rs:525`) — never runs `reset`. `defer` does not
save it either: `defer` frames are emitted before `ret`, and `abort` is not a `ret`. So: **the
epilogue `reset` is a courtesy for the normal path; the abort path relies on the OS.** That is
acceptable for fds and wrong for the Tor control port (a `NEWNYM` in flight, a relay worker
thread), which is why §7 D1 asks before `net`/`relay_room` are migrated, not before `ws`.

---

## 5. The smallest version that moves ONE module to `lowers`

### 5.1 The module: `ws`

`ws` is the only one of the four where every prerequisite already exists:

| Requirement | `ws` | the other three |
|---|---|---|
| value-level dispatch already written | `dispatch_method` with `recv`/`recv_all`/`send`/`close` (`ws.rs:338-349`) | `TorPool`: yes (`net.rs` `dispatch_method`), but `tor_pool_create` runs live TCP probes at mint and sits in the hand-written `emit_stdlib_module_call` arm (`codegen.rs:23549`, `"net"` at `:23563`) — two extra layers |
| registry is one table, one payload | `HashMap<u64, WebSocket>` (`ws.rs:82`) | `relay_room`: a worker thread, a channel protocol and a transient take/put map (`relay_room.rs:83,276,284`) |
| close already idempotent and documented | `ws_close` (`ws.rs:436-460`) | `browser`: no close at all; the context needs a table the runtime does not have (`src/stdlib/browser.rs:569`, `src/runtime/browser.rs:219`) |
| no dependency on the product relay/protocol | plain TCP + TLS (`ws.rs:90-120`) | `relay_room` depends on `tallow_protocol::room::code` (`relay_room.rs:703-712`) |

It also has the smallest census-to-reality gap: the baseline records
`build failed: native backend has no lowering for method 'connect' … (unknown method for any
statically-known kind)` [baseline], i.e. `WS.connect` fails at the *alias*, which is a one-line
class of fix — the dangerous kind of flip, because it would make the census say `lowers` while
the handle stayed inert (`gaps` §Bucket B, "the probe would compile and the program still would
not"). `ws` is where the honest version is cheapest to prove.

### 5.2 Three slices, each independently verifiable

**S1 — the registry, no ABI change.** Introduce `src/runtime/handles.rs` (record, token grammar,
epoch, per-kind table, lease, tombstone) and move `WS_CONNECTIONS` + `NEXT_WS_ID` behind it.
`handle_id` (`ws.rs:356`) becomes `resolve`. Behaviour is unchanged except T14 (a close of a
never-minted token becomes a refusal) and T6 (a stale close no longer touches the live holder). Gate: the existing `ws` tests still pass, plus the registry unit tests.
**No flip claimed at S1.**

**S2 — the receiver path.** `tallow_stdlib_call_method` + `LLType::Handle` + `RetKind::Handle` +
the `emit_method_call` arm, and the `WS` alias in `REGISTERED_MODULES` (`src/stdlib/mod.rs:366`;
`dispatch` already accepts `"WS"` at `:311`, and `tests/stdlib_dispatch.rs:527` already runs
`WS.connect` interpreted). This is the slice that earns the flip, and it is earned only with the
parity test in T21 attached: the census probe must go green **and** a compiled program must
`connect → send → recv → close` a loopback server with stdout byte-identical to the interpreter,
in the shape of `tests/structured_data_parity.rs`.

**S3 — the grant.** `scope::require` at mint, grant in `owner`, epoch bump on register reload.
This is the slice with blast radius: a program connecting to a host absent from
`configs/tallow/scope/authorized-hosts.toml` starts refusing. Loopback is granted on a
self-hosted basis (`docs/intel/topology.md` §"The scope gate"), so `tests/stdlib_dispatch.rs:527`
(`ws://127.0.0.1:9/nope`) should still reach its connection error — but that is a `[unverified]`
claim until measured, and it is the first thing to check.

### 5.3 What is explicitly NOT in the smallest version

`net`, `relay_room`, `browser` (they get the registry, not the flip); slot reuse with a free list
(generation exists from S1 so reuse is safe *when* it lands, but nothing reuses yet); the
`main`-epilogue `reset` on abort paths; per-method grant re-validation; any change to
`net.rs`'s other 12 registries; any change to the hand-written browser arm.

### 5.4 One forward constraint this design imposes

`json.parse<T>` — bucket A, and the one module the triage doc excludes from the 14 because it
needs a codegen-side deserialiser (`gaps` §"Decision input") — must not be allowed to construct a
`Struct` whose `__type` is a handle kind. Otherwise the generic deserialiser becomes a handle
forgery primitive and E4 reopens. That is a one-line rule to carry into that work, and §6 T22
pins it.

---

## 6. The failure cases, as tests to write

Named as test paths so they can be created verbatim. `unit` = `src/runtime/handles.rs`
`mod tests`; `integ` = `tests/handle_registry.rs`; `parity` = `tests/ws_handle_parity.rs`;
`compile-fail` = `tests/handle_codegen_refusals.rs` (build the program, assert the diagnostic
and that no binary is produced). Nothing here is claimed as measured.

### Identity and kind

| # | test | arrange | assert | plane |
|---|---|---|---|---|
| T1 | `two_kinds_never_alias_on_the_same_integer` | mint `ws` slot 1 and `net.tor_pool` slot 1 | resolving the ws token as `TorPool` is `KindMismatch`; neither mutates the other | unit |
| T2 | `payload_that_lies_about_its_kind_is_refused_before_lookup` | `Struct{name:"WebSocket", _handle:"net.tor_pool/1/1/0"}` | `KindMismatch`, and the net table is never locked (assert via a lock-attempt counter) | unit |
| T3 | `unknown_kind_token_is_refused_not_defaulted` | `_handle: "ws.socketz/1/1/0"` | `Unknown`, no fallback to the `ws` table | unit |
| T4 | `handle_type_name_is_not_authority` | two structs named `WebSocket`, one holding a relay token | the relay-token one is refused by kind, not routed by name | unit |

### Generation (the ABA cases)

| # | test | arrange | assert | plane |
|---|---|---|---|---|
| T5 | `reused_slot_invalidates_the_old_token` | mint (slot 3, gen 1) → close → force reuse into slot 3 (gen 2) | gen-1 token ⇒ `Stale`; gen-2 token ⇒ `Live` | unit |
| T6 | `stale_close_does_not_close_the_live_holder` | as T5, then `close(gen1_token)` | refusal, and the gen-2 socket still `send`s | unit |
| T7 | `generation_zero_is_never_minted` | hand-built token gen 0 | `Unknown` | unit |
| T8 | `generation_is_not_bumped_by_close` | mint, close, read record | generation unchanged; state `Closed` | unit |

### Owner and epoch

| # | test | arrange | assert | plane |
|---|---|---|---|---|
| T9 | `handle_from_a_previous_epoch_is_stale` | mint, `reset()`, resolve the old token | `StaleEpoch` — the multi-program-in-one-process case | unit |
| T10 | `reset_closes_every_live_payload_exactly_once` | mint 3 with a `Drop`-counting double, `reset()` | 3 payload drops, 3 tombstones, epoch +1 | unit |
| T11 | `register_reload_invalidates_handles_minted_under_it` | mint under grant g1, reload the register, resolve | refusal naming the grant; document the `basis` | integ (S3) |
| T12 | `mint_without_a_grant_is_refused_before_any_socket` | unlisted host, listener counting accepts | refusal with `scope:not-listed`; accepts == 0 | integ (S3) |

### Close, double close, use after close

| # | test | arrange | assert | plane |
|---|---|---|---|---|
| T13 | `double_close_is_a_no_op_not_an_error` | close twice | second `Ok(nil)`, one tombstone, payload dropped once | unit |
| T14 | `close_of_a_never_minted_token_refuses` | token for an unallocated slot | `Unknown` — **today `ws_close` returns `Ok(nil)` (`ws.rs:445-448`); this test is a regression against that conflation** | unit |
| T15 | `use_after_close_names_the_close` | send after close | refusal containing kind, token and close reason; no reconnect attempted (listener accept count unchanged) | integ |
| T16 | `freeing_the_marshalled_text_does_not_close` | encode token → drop the text → resolve again | still `Live`; and a subsequent `close` is the only thing that tombstones | unit |
| T17 | `checked_out_handle_is_busy_not_blocked` | hold a lease on thread A, resolve on B | B gets `Busy` promptly (bounded time), no deadlock on the payload lock | unit |
| T18 | `failed_method_body_returns_the_lease` | method returns `Err` mid-lease | record back to `Live`, not `CheckedOut` | unit |

### Crossing the bridge / codegen

| # | test | arrange | assert | plane |
|---|---|---|---|---|
| T19 | `print_handle_refuses_at_build` | `let h = WS.connect(u); print(h)` | build error naming `WebSocket` handle; no binary emitted | compile-fail |
| T20 | `compare_if_and_coerce_refuse` | `h == h`, `if h`, `let s: String = h`, `h.to_string()` | four refusals, each naming the kind; mirror of `refuse_bridge_opaque` (`codegen.rs:21972`) | compile-fail |
| T21 | `ws_connect_send_recv_close_parity` | loopback ws server, one program run on both planes | compiled stdout byte-identical to interpreter; IR contains `tallow_stdlib_call_method` | parity |
| T22 | `json_deserialiser_cannot_construct_a_handle` | deserialise `{"__type":"WebSocket","_handle":…}` | refused (forward constraint, §5.4) | unit |
| T23 | `handle_passed_to_a_callee_that_does_not_accept_it_is_refused_at_marshal` | pass a `WebSocket` handle to a bridged call declaring `String` | marshal-time refusal naming both kinds; not a runtime abort after a partial call | integ |
| T24 | `census_flip_is_backed_by_a_usable_handle` | the census probe **plus** T21 | the module is `lowers` **and** the handle works; a flip without T21 is a regression, not a fix | parity |

### Lifetime at the edges

| # | test | arrange | assert | plane |
|---|---|---|---|---|
| T25 | `defer_close_runs_on_the_early_return_path` | two exits, both with `defer h.close()` | peer observes close frame on each path, both planes | parity |
| T26 | `main_epilogue_reset_closes_what_the_program_forgot` | compiled program that never closes | peer observes EOF at exit; if S3 defers this, the test is `#[ignore]`d with the §4.3 reason — not silently missing | parity |
| T27 | `abort_path_does_not_run_reset` | force a bridge abort with a live handle | document the leak: no close frame; the OS closes the fd. The assertion is that this is *known*, not that it is clean | parity |

Two tests in that table are the design's own falsifiers, not just coverage: **T14** fails against
today's `ws_close` and must be made to fail before S1 is written, and **T24** fails against any
S2 that adds the alias without the receiver path — the exact dishonest flip `gaps` warns about.

---

## 7. Decisions that need an owner above this lane

| # | decision | default proposed | why it is not mine |
|---|---|---|---|
| D1 | does `net`/`relay_room` migration require a real teardown (worker join, control-port NEWNYM flush) before the abort-path leak of §4.3 is acceptable? | leave them at "not lowerable" until yes | it changes whether a refusal is honest or a resource bug moved behind a green census |
| D2 | re-validate the grant on every method call, or epoch-bump on register reload? | epoch-bump (cheap, fail-closed, invalidates long sessions) | the second is friendlier to long-lived sessions and weaker at the boundary |
| D3 | does S3's scope gate on `ws.connect` land before or after the census re-bless? | before — a `lowers` that opens sockets without a grant is the defect | it changes existing program behaviour; loopback is granted, but that needs measuring first |

Everything else in this document is inside the L2 envelope: a new module under `src/runtime/`,
one new `extern "C"`, one codegen arm, one alias, and tests.

---

## 8. Where the truth lives

| Path | What |
|---|---|
| `src/runtime/handles.rs` | **does not exist yet** — this design's deliverable is the file above it |
| `src/runtime/stdlib_bridge_ffi.rs:149` | `tallow_stdlib_call` — the shape `tallow_stdlib_call_method` mirrors |
| `src/runtime/stdlib_bridge_ffi.rs:99,113` | `RAW_PREFIX` / `FLOAT_PREFIX` — the discriminator discipline the token grammar follows |
| `src/runtime/stdlib_bridge_ffi.rs:259` | `encode_result` — what a bridged value can be |
| `src/agent_comm.rs:166,185,215,236` | `value_to_json` / `__type` / `json_to_value` / the untagged-object fallback |
| `src/codegen.rs:9375` | the gate that makes a variable unusable as a bridge receiver |
| `src/codegen.rs:21972` | `refuse_bridge_opaque` — the hook `LLType::Handle` extends |
| `src/codegen.rs:23057,23130` | result-pointer ownership and `bridge_binding_escapes` |
| `src/codegen.rs:5955` | `defer` is function-frame scoped in the compiled plane |
| `src/interp.rs:2577,14774` | the same `defer` frame rule, and the value-level dispatch call site |
| `src/stdlib/mod.rs:366,475,582-590` | `REGISTERED_MODULES` (no `WS`), `dispatch_method`, and the handle arms that already exist |
| `src/stdlib/ws.rs:81,82,338,356,436` | the counter, the table, the methods, the id reader, the close |
| `src/stdlib/net.rs:134,1033,1199` | one counter for 13 tables, the TorPool table, its close |
| `src/stdlib/relay_room.rs:83,276,284` | the table, and the take/put that becomes the lease |
| `src/scope.rs:129-159,686` | the refusal enum and its codes, and `require` — the mint gate |
| `src/typeck.rs:3666` | struct-literal unknown-field refusal — closes the synthesis path |
| `Cargo.toml:14` · `src/codegen.rs:28855-28872` | `staticlib`, and the link that puts the registry in the binary's address space |
