# Stdlib surface audit — 2026-10-22

The Tallow-Language spec publishes four counts: 36 keywords, 51 operator tokens,
176 error codes, 85 stdlib modules / 1,118 functions. This records how each was
verified against the engine, what was broken, and what is still known to be
missing. Every "fixed" line below was proven by running a program.

## What was verified, and how

| claim | method | result |
|---|---|---|
| 36 keywords | each word through `tallow::lexer::tokenize`, kind compared to the spec table | all 36 lex to the documented `TokenKind` |
| 51 operator/punctuation tokens | each spelling through the lexer, one token + EOF expected | all 51 lex correctly |
| 176 error codes | every `"E####"` literal in `src/**/*.rs` compared with the catalogue, both directions | exactly equal, 176 |
| 85 modules | `stdlib/*.tl` file count, plus a dispatcher routing probe per module | 85, all routed |
| 1,118 functions | declaration count (the generator's metric) | 1,118 |

The gate is `tests/language_surface.rs` and it runs in the CI contract job, so a
count that drifts or a code that is published but unemittable fails the build.

## Defects found and fixed

All of these were declared in `stdlib/*.tl` and undefined at runtime.

- **math** — `asin, acos, atan, atan2, cbrt, abs_i, min_i, max_i, clamp_i`.
  `math.asin(0.5)` returned `undefined function: math.asin`. Now: 0.523599,
  cbrt(27)=3, abs_i(-7)=7, min_i(3,9)=3, clamp_i(50,0,10)=10, atan2(1,1)=0.785398.
- **url** — `with_path, domain, is_secure, param`. A `.tl` method body is not
  executed for a native struct, so all four were unreachable
  (`unknown method: .with_path() on URL`). Now `u.with_path("/b")` keeps the
  query and rebuilds `raw`; `u.domain()` = `example.com`.
- **json** — `get, at, as_string, as_number, as_bool, is_null, len`. The module's
  `dispatch_method` was never called from `stdlib/mod.rs`, and `parse_value`
  returns plain runtime values rather than a tagged `JsonValue`, so the accessors
  are answered by value shape. Now `parse_value("123").as_number()`=123,
  `("true").as_bool()`=true, `("null").is_null()`=true.
- **env.require, json.to_json_pretty, rand.shuffle** — same class, now
  implemented (`env.require("HOME")` → `/root`, `rand.shuffle([3,1,2])` →
  a permutation).
- **spec generator** — `rstrip(".")` had reduced the comments `// .` and `// ..`
  to empty spellings, and `_ (as pattern)` was published verbatim. The tables now
  read `.`, `..`, `_`. Counts unchanged; only the spelling column was wrong.

## Known remaining gaps — not fixed, stated

1. **17 browser functions are stubs with no implementation.**
   `stdlib/browser.tl` declares them with empty bodies and a `// Runtime:` or
   `// native:` comment; no Rust handler exists for any of them:
   `page_is_wordfence_challenge`, `page_bypass_wordfence`,
   `page_navigate_bypass_wordfence`, `page_wp_extract_rest_nonce`,
   `page_wp_is_logged_in`, `page_wp_login`, `page_wp_extract_all_nonces`,
   `browser_context_create`, `page_extract_all_text`, `page_extract_all_attrs`,
   `page_block_non_essential`, `page_wait_for_stable`, `page_detect_pagination`,
   `page_handle_cookie_consent`, `page_structured_data`,
   `page_capture_dom_snapshot`, `page_text_redacted`.
   These need CDP scripting (DOM stability observers, WordPress/Wordfence flows),
   not a dispatcher arm. They are a feature build, and until it happens the spec
   counts them among the 1,118 while the engine answers `unknown method`.

2. **`agent.AgentHandle.cancel` / `.is_done`** — same class, need the agent
   runtime to expose handle state.

3. **No native lowering for the new math calls.** `math.asin` compiles on the
   interpreter plane; the native backend prints "no lowering for method 'asin' —
   failing loudly so the interpreter runs it" and falls back. Correct behaviour,
   not native support.

## Classification of the declared surface

Under the audit's own declaration walker (which attributes 879 of the 1,118 —
the rest are generic and multi-line forms it does not classify): 201 have real
Tallow bodies, 657 have a Rust handler, 21 had neither — of which 3 were fixed
in the commit that added this document and 18 remain, listed above.
