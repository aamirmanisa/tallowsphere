# Egress gate — measured state and open defects (2026-10-30)

## Fixed and verified
`net.connect` is gated on BOTH planes. Interpreter and compiled plane both emit:
    net.connect(1.1.1.1:443): scope:not-listed — refused: 1.1.1.1 is not in the authorization register (deny-by-default)
Compiled plane opens **0 sockets** (strace) on that path. Committed in cf41072.

## Defect 1 — unused calls are eliminated (blocks testing)
`let s = net.connect(...)` with `s` never observed emits **no call at all**.
    fn main() { let s = net.connect("1.1.1.1:443"); let n = 5; print(n) }
    -> prints 5, 0 connect() syscalls, exit 0
So a program can "pass" a gate test by never reaching the gate. Any egress test
must consume the result (`print(s)`).

## Defect 2 — a refused result is a value, not a failure
The compiled plane returns the refusal string and continues. Program exits 0
around a refusal unless it inspects the result. Interpreter errors and exits
non-zero. This is a plane split on failure semantics, and it is why the
regression test asserts on exit status and cannot pass.
DECISION NEEDED: should a refused effect-call abort (both planes), or return an
inspectable error value (both planes)? Do not paper over it in the gate.

## Defect 3 — http.* on the compiled plane still renders `(null)`
`print(http.post("https://1.1.1.1/x","body"))` -> `(null)`, 0 connects.
Same class as the net.connect defect fixed in cf41072; httprs never got the
null->last_error treatment.

## Defect 4 — the test fixture's effect row does not parse
`with Net(connect), Budget(bytes: 1048576), Plane(egress)` is a parse error
(`expected ')', found ':'`). Per docs/plans/2026-10-tallow-2.0-feature-backlog.md
only `Net` is enforced; Budget/Plane are unlanded. Correct row here is
`with Net(post)` for http.post.
