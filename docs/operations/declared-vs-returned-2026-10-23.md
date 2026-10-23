# Module-level browser helpers: declared types vs what the interpreter returns

Status: FIXED 2026-10-23 — Option 1 adopted (operator: "Go"). The interpreter
now returns the declared structs; see "Resolution" at the end.

## What was measured

While adding native lowering for the module-level `browser.page_*` helpers, six
of them were found returning a PRIMITIVE from the interpreter where
`stdlib/browser.tl` declares a struct:

| helper | declared | interpreter returns | evidence |
| --- | --- | --- | --- |
| `page_throttle_cpu(rate)` | `CpuThrottle` | `Ok(Float)` — the rate | `src/stdlib/browser.rs:486` |
| `page_emulate_media(a,b,c)` | `MediaEmulation` | `Ok(Nil)` | `src/stdlib/browser.rs` (`.map(\|_\| Value::Ok(Box::new(Value::Nil)))`) |
| `page_wait_for_url(p, t)` | `WaitResult` | `Ok(Bool)` — matched | same file, `.map(\|(ok, _ms, _url)\| … Bool(ok))` |
| `page_wait_for_function(js, t)` | `WaitResult` | `Ok(Bool)` | same file |
| `page_add_script_tag(s)` | `ScriptTag` | `Ok(String)` — tag id | same file |
| `page_add_style_tag(s)` | `StyleTag` | `Ok(String)` | same file |
| `page_set_content(html)` | `PageContentResult` | `Ok(Int)` — bytes | same file |

Reproduced end to end, not just by reading:

```
let ct = browser.page_throttle_cpu(2.0) match { Ok(c) -> c, Err(e) -> { bail "{e}" } }
print(ct.applied)
# interpreter: runtime error: type error: unknown method: .applied() on float
```

The *method* forms disagree in the other direction: the native arms for
`Page.throttle_cpu` / `Page.wait_for_url` build the declared structs
(`CpuThrottle`, `WaitResult`), and `Page.set_content` returns a raw status with a
comment calling it a known gap. So today there are three shapes for the same
idea — declaration, interpreter, native method — and none of them agree.

## Why it was not fixed inside the native-lowering change

Native lowering must produce what `tallow run` produces, and `tallow run` prefers
native. Lowering these six to their declared structs would have made compiled
runs return a `CpuThrottle` while `--interpret` returned a float — a new
divergence in the very change meant to remove one. The additional arms were
written, measured against the interpreter, and reverted.

## Options

1. **Fix the interpreter to return the declared structs** (my recommendation).
   The declaration is the published contract and the native method arms already
   build structs; the interpreter is the outlier. Cost: six arms in
   `src/stdlib/browser.rs`, a test per helper, and a note in the changelog that
   these calls now return what the spec says. Programs that printed the old
   primitive see a struct instead — which is what the type declares.
2. **Change the declarations to the primitives.** Cheap, but it makes
   `page.set_content` return an `Int` while `Page.set_content` returns
   `PageContentResult`, and it tells users the helper has less information than
   the CDP call behind it actually produced.

## Resolution (2026-10-23)

Option 1 was taken: the interpreter was aligned to the declarations.

- Six arms in `src/stdlib/browser.rs` now build the declared structs.
- The shared `WaitResult` builder gained the two fields it had never produced
  (`status`, `event`) — a second, quieter defect found while fixing the first.
- Native lowering for the seven helpers was added on top of the current-page
  receiver. Where the backend cannot infer the struct type of a match-arm
  binding, it refuses by name and `tallow run` falls back to the interpreter,
  which is now the correct implementation. That is a missing optimisation, not
  a wrong answer: `--require-native` fails loudly instead of guessing a layout.
- Migration surface measured before changing anything: five of the six helpers
  had zero call sites in the repository; the sixth (`page_set_content`) had two,
  both tests introduced by this work.
