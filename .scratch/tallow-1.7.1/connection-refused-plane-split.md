# The connection-refused case is a plane split, and 1.7.0 ships it

Found by **lexicon** while fixing `http_status_as_data_parity` for the v1.7.0 cut
(2026-11-02), and deliberately recorded rather than papered over.

## Measured

Same program, same URL, host refusing the connection:

| plane | result |
|---|---|
| interpreter | `Err("http.get: redirect-transport: refusing <url> — io: Connection refused (os error 111)")` |
| compiled (native) | aborts |

The test now quotes both and marks the case `DISAGREE` instead of asserting a byte
match, because a byte match never held.

## Why it was not fixed in 1.7.0

The 1.7.0 release is the egress-gate cut: the register, the redirect hop, the
typed `http.batch` entry. Making the compiled plane return an inspectable error
value here is a change to failure semantics on both planes, which is the same
decision as **Defect 2** in `docs/egress-gate-open-defects.md` ("should a refused
effect-call abort on both planes, or return an inspectable error on both?"). Doing
it in the release cut would have changed the semantics of every effect call under
a gate everyone had just finished agreeing on.

## What 1.7.1 owes

1. Decide the contract once — abort on both planes, or an inspectable value on
   both — and write it in the spec, not only in a test.
2. Whatever is chosen, `http_status_as_data_parity` stops being `DISAGREE` and
   becomes an assertion of the chosen shape on both planes.
3. If abort wins, the interpreter's `Err` string must not be the only signal the
   caller ever sees; if the value wins, the compiled plane must stop aborting.

## Note on scope

This is a *failure-semantics* split, not an egress-gate hole: the register is
consulted before the socket on both planes, and a refused host is still refused
before a socket is opened.
