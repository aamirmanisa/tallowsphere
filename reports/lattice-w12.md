# lattice — W12: the "unused effect calls are eliminated" premise

Transcribed by the merge owner from the lane's own closing turn in
`/root/.hermes/profiles/lattice/state.db` (the lane hit the iteration cap before
writing files). The measurements below are the lane's, taken with the 1.7.0
binary; the merge owner has NOT re-run them. Treat every number as the lane's
claim until probe's independent re-measure lands.

---

I hit the iteration cap before writing files, so nothing is committed. Here is the state of the work — critically, **the brief's central premise is false**, and I have execution evidence for that.

## MEASURED RESULT (the headline)

The unused call is **not** eliminated. On the current tree the compiler emits the call *and* the fail-closed guard, and the program aborts at the gate.

Probe `p.tl` (brief's program + the headers the checker requires, `with Net(connect)`), compiled with the 1.7.0 binary:

```
$ tallow build p.tl            # /home/aamir/tallowsphere/target/debug/tallow
$ strace -f -e trace=network -o st.txt ./p
runtime error: net.connect(1.1.1.1:443): scope:not-listed — refused: 1.1.1.1 is not in the authorization register (deny-by-default)
exit=1        socket() = 0    connect() = 0    "5" never printed
```

Control `q.tl` (identical but `print(s)`, result consumed): **byte-for-byte same behaviour** — same refusal, exit 1, 0/0 network syscalls. Interpreter on `p.tl`: same refusal, exit 1. So consumption makes no difference; the two planes agree.

The emitted IR for `p.tl` (no `print(s)` anywhere) is decisive:

```
%4 = select i1 %3, ptr @.str.3, ptr @.str.2
%5 = call ptr @tallow_net_connect(ptr %4)
call void @tallow_check_string(ptr %5)
%6 = alloca ptr
store ptr %5, ptr %6          ; stored, never loaded — and still emitted
```

## WHY THE DOC LOOKED RIGHT

`docs/egress-gate-open-defects.md` defect 1 ("unused calls are eliminated") is a **stale measurement of the pre-fix lowering**: the `select`-substitution printed the refusal and exited 0, so "0 connect() syscalls + exit 0 + prints 5" read as "the call never happened". And 0 `connect()` syscalls can never distinguish the two hypotheses — the scope gate refuses *before* `TcpStream::connect` (`src/runtime/net_ffi.rs:33-37`), so a refused connect and an eliminated call both show zero sockets. The instrument was blind to the question it was asked.

## §2 MATERIAL (verified by reading, not grep)

No elimination pass exists. The emit chain, all `src/codegen.rs`:
- `CodeGen::emit_block` :5624 — emits every statement unconditionally (:5652), no liveness test
- `CodeGen::emit_stmt`, `StmtKind::Let|Var` arm :5718/:5720 — evaluates the initialiser unconditionally at **:6405**; there is no use-set anywhere in codegen
- `CodeGen::emit_method_call` :10526 → module arm at :10594 → `emit_stdlib_module_call` :25927, `"net"` dispatch at **:25941**
- `CodeGen::emit_stdlib_net` :30452 — `call ptr @tallow_net_connect` at **:30464-30466**, `call void @tallow_check_string` at **:30486**
- Backend: `clang ... -O2` at :1332 over a `declare ptr @tallow_net_connect(ptr)` (:2487) with **no attributes** — not eliminable, and empirically not eliminated
- The only two AST-mutating passes before codegen are `callnorm::normalize` (`src/callnorm.rs:153`) and `newtypes::lower` (`src/newtypes.rs:40`); neither drops statements

## TWO FINDINGS THAT CHANGE THE §4 ARGUMENT

1. **The tree already pins model (a).** `src/codegen.rs:40898 codegen_stdlib_net_connect` compiles `fn main() { let s = net.connect("localhost") }` — `s` never used — and asserts IR contains `@tallow_net_connect`; `:40913 codegen_stdlib_net_connect_is_fail_closed` asserts `tallow_check_string` on the *same* unused-result program. Model (b) would turn two existing tests red, i.e. it is a new optimisation feature, not a description of current behaviour.
2. **The "elimination" doctrine is a test comment, not an assertion** — `tests/egress_scope_gate.rs:74-78`. It is false and it caused that test to consume the result for a non-reason. Correcting it is part of the implementing lane's work; no code change is needed for the invariant itself.

Also refuted: `git log --all | grep -c cf41072` = **0** — the hash cited in the defect doc is not in this repo. The gate actually landed in **747c88c, 2026-10-30 16:43:58** ("fix(net): the scope gate holds on both planes, and a refusal is visible").

## BINARY STAMP (honest)

`tallow version` → 1.7.0, build 2026-11-01T22:34:59Z, **git 7bdf59fad3**. `git diff --stat 7bdf59f 758e5bc` = `configs/tallow/scope/authorized-hosts.toml` only (8+/3-) — **zero `src/` delta**, so this binary is source-identical to `rel/w12-lattice @ 758e5bc`. I deliberately did **not** use `/usr/local/bin/tallow` (1.5.8, git 6aa9fcfb, 2026-10-26): it predates 747c88c and would have measured the old plane. Compiled artifact `p`: 538,121,712 bytes, sha256 `9345fb9a…`. **Zero cargo invocations used**, so no `test result:` line exists to quote.

## WHAT IS NOT DONE

`docs/spec/EFFECT-CALL-PRESERVATION.md` and `reports/lattice-w12.md` are **not written and not committed** — that is the outstanding deliverable, and all the content above plus the §3 model analysis (cost/risk: (b) either splits the planes or makes the language lazy in effectful statements; (a)'s open risk is an unclosed handle on an ignored success) is ready to be written into them. Section §2 must be phrased as "there is no eliminating pass; here is the chain that proves emission and the one site where elimination could hide", and §4 must recommend (a) as an invariant-plus-gate, not a codegen change.
