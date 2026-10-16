# BBS+ implementation plan — draft-irtf-cfrg-bbs-signatures-08, ciphersuite `BLS12-381-SHA-256`

Stub register row #90, third family (`bbs_issue` / `bbs_prove` / `bbs_verify`). The canonical names
refuse until this is real and vector-checked; the `_experimental` counterpart is an Ed25519
commitment with no pairing-based security and must not be wired to them.

Draft text (complete, 6,664 lines) is cached at
`/home/user/.hermes/profiles/alden/cache/web/www.ietf.org-2a9f2a6f38.md`. All line numbers below refer to
that file. Fetch fresh from `https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.txt`
if it is gone.

## Increment 1 — utility layer (`src/bbs.rs`) — LANDED

- Ciphersuite constants (§7.2.2): `ciphersuite_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"`,
  `octet_scalar_length = 32`, `octet_point_length = 48`, `expand_len = 48`.
- `api_id = ciphersuite_id || "H2G_HM2S_"` (§3.5). Confirmed by the D.2.3 vector's `dst`, which is
  exactly `api_id || "H2S_"`.
- `expand_message_xmd` (RFC 9380 §5.3.1, SHA-256). **`DST_prime = DST || I2OSP(len(DST), 1)`** — the
  length suffix is part of the construction; omitting it silently yields wrong values (it did).
- `hash_to_scalar` (§4.2.2): `OS2IP(expand_message(msg, dst, 48)) mod r`.
- G1 layer over `blst`. **`blst_p1_mult` reads the scalar little-endian**; the module's own encodings
  stay big-endian and the reversal is confined to that one call.
- `create_generators(count)` (§4.1.1) → `(Q_1, H_1, …, H_{count-1})`: for the BBS interface
  `generator_1` is Q_1 (§4.2.3, confirmed by CoreSign's `length(generators) != L + 1` check).
- `ciphersuite_p1()` (§7.2). **Trap:** P1's `generator_seed` is
  `ciphersuite_id || "H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"`, *not* the interface's
  `api_id || "MESSAGE_GENERATOR_SEED"`. P1 is not `create_generators(1)[0]`.

Evidence: P1 reproduces §7.2.2's literal; `hash_to_scalar` reproduces D.2.3; scalar multiplication's
byte order is pinned by `1·P = P` and `2·P = P + P`; compressed points round-trip and a non-curve or
non-subgroup encoding is refused.

## Increment 2 — key generation and the signature — LANDED (`57391ea`)

**Established while writing it.** PK is indeed a 96-byte E2 point and `SkToPk` is `SK · BP2`; the
pairing is `blst_miller_loop` + `blst_fp12_mul` + `blst_final_exp` + `blst_fp12_is_one`, with the
fp12 values initialised from `blst_fp12_one()` because the binding's derive set has no `Default`.
`blst_p2_mult` reads its scalar little-endian exactly as `blst_p1_mult` does, so the reversal is one
shared helper. `KeyGen`'s `derive_input` is `key_material || I2OSP(len(key_info), 2) || key_info`.

**Two findings from the tests, both about the vectors rather than the scheme.** The fixture parser
must split on `=` and trim both sides — `m_10` is the empty message, and trimming the line ate the
`" = "` separator, which failed eight tests with a parser panic before any crypto ran. And the
draft's two Sign fixtures **share one key pair** (the same `SK` and `PK` in §8.4.4.1 and §8.4.4.2),
so the §D.2.1.6 wrong-key case cannot borrow the other fixture's `PK`: a different valid key has to
be constructed. Both are recorded in the test comments.

Validated: `SK`, `PK`, `Q_1` + `H_1..H_10`, all ten message scalars, `domain`, `B`, and both
signature fixtures byte for byte, plus the D.2.1 accept/reject cases and malformed-input refusals.

The .tl surface for increment 4 (read from `stdlib/crypto.tl`): `bbs_issue(attributes, signer_id)`
returns `BbsCredential{credential_signature, signer_public_key, attributes, num_attributes}`;
`bbs_prove(credential_signature, attributes, disclosed_indices)` returns
`BbsProof{proof, disclosed_attributes, num_disclosed, num_total}`; `bbs_verify(proof,
disclosed_attributes, signer_public_key)`. Neither struct has a field for a key or a header, so both
the credential and the proof strings must be self-describing, as the blind family's transcripts are.

| What | Where |
|---|---|
| `KeyGen` / `SkToPk` (§3.4.1, §3.4.2) | 742–845 |
| `Sign` / `Verify` interface (§3.5.1, §3.5.2) | 870–990 |
| `CoreSign` (§3.6.1) | 1181–1264 |
| `CoreVerify` (§3.6.2) | 1265–1349 |
| `serialize` (§4.2.4.1) | 2581–2615 |
| `signature_to_octets` / `octets_to_signature` (§4.2.4.2, §4.2.4.3) | 2617–2730 |
| `calculate_domain` (§4.2.3) | 2469–2520 |
| `messages_to_scalars` (§4.1.2) | 2231–2280 |

Pinned already (verbatim from the draft):

- `serialize(input_array)`: G1 point → `point_to_octets_E1` (48 bytes); scalar →
  `I2OSP(el, 32)`; integer 0..2^64-1 → `I2OSP(el, 8)`. Concatenate in order.
- `CoreSign(SK, PK, generators, header, messages, api_id)`:
  1. `domain = calculate_domain(PK, Q_1, (H_1..H_L), header, api_id)`
  2. `e = hash_to_scalar(serialize((SK, msg_1, …, msg_L, domain)), api_id || "H2S_")`
  3. `B = P1 + Q_1·domain + H_1·msg_1 + … + H_L·msg_L`
  4. `A = B · (1/(SK + e))` — check `SK + e ≠ 0 mod r` and `A ≠ Identity_G1` before returning
  5. `signature_to_octets((A, e))`
- `hash_to_scalar_dst = api_id || "H2S_"` (§4.2.3 and CoreSign's Definitions agree).
- `calculate_domain(PK, Q_1, H_Points, header, api_id)`: `hash_to_scalar(serialize(PK, Q_1, H_1..H_L,
  header), api_id || "H2S_")` — read 2469–2520 to confirm the exact element order before writing it.

Sign vectors: §8.4 (BLS12381-SHA-256), §8.4.x Sign; plus Appendix D.2.1.1–D.2.1.7, which cover the
accept and reject cases (`Modified Message`, `Extra Unsigned Message`, `Missing Message`,
`Reordered Message`, `Wrong Public Key`, `Wrong Header`) — those are the refusal tests, use them.
Appendix D.2.3 shows the `key_dst`/`derive_input` shape for `KeyGen`: `SK = hash_to_scalar(derive_input,
key_dst)` with `key_dst = api_id || "KEYGEN_DST_"` when not supplied (§3.4.1, line ~799).

## Increment 3 — proofs (the NIZK) — SCALAR OPS LANDED (`7b03729`), SUBROUTINES NOT YET WRITTEN

**Landed:** `calculate_random_scalars` (§4.2.1) and `seeded_random_scalars` (§8.1), the latter
reproducing all ten published `random_scalar_i` values — verified against the fixtures, so the mock
`CoreProofGen`'s determinism depends on is in place before the subroutines that consume it.

**Also fixed, in the fixture extractor:** it recognised only the `name = "value"` single-line form, so
`SEED =` with its value on the following line was dropped; and it stopped accumulating at the first
unquoted line, but the SEED's closing quote sits after a page break. Page furniture is now stripped
before scanning and accumulation runs until the quoting closes. The extracted SEED decodes to
`3.141592653589793238462643383279` — pi with the decimal point, not the bare digits the draft's prose
would suggest.

| What | Where |
|---|---|
| `ProofGen` / `ProofVerify` (§3.5.3, §3.5.4) | 990–1133 |
| `CoreProofGen` (§3.6.3) | 1349–1468 |
| `CoreProofVerify` (§3.6.4) | 1469–1556 |
| **`ProofInit` / `ProofFinalize` / `ProofVerifyInit` / `ProofChallengeCalculate` (§3.7.1–3.7.4)** | 1557–2050 |
| `proof_to_octets` / `octets_to_proof` (§4.2.4.4, §4.2.4.5) | 2730–2864 |
| `calculate_random_scalars` (§4.2.1) | 2333–2378 |
| `seeded_random_scalars` (mock, §8.1) | 3647–3735 |
| Proof vectors (SEED, DST, expected proof) | Appendix D.2.2.1 (6191), D.2.2.2 (6266), §8.4.5 |

Pinned from the draft (read, not reconstructed):

- **`CoreProofGen(PK, signature, generators, header, ph, messages, disclosed_indexes, api_id)`.**
  Deserialization: `L = length(messages)`, `R = length(disclosed_indexes)`, `U = L - R`, every index
  in `[0, L-1]`, `undisclosed_indexes` = the complement. Then:
  1. `random_scalars = calculate_random_scalars(5 + U)`
  2. `init_res = ProofInit(PK, signature_result, generators, random_scalars, header, messages,
     undisclosed_indexes, api_id)`
  3. `challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph)`
  4. `proof = ProofFinalize(init_res, challenge, e, random_scalars, undisclosed_messages)`
- **`CoreProofVerify`**: `octets_to_proof` yields the tuple
  `(Abar, Bbar, D, e^, r1^, r3^, commitments, cp)`; then `ProofVerifyInit`, then
  `ProofChallengeCalculate(init_res, disclosed_indexes, messages, ph, api_id)` — note it passes the
  *disclosed* messages under the name `messages`; then two checks: `cp == challenge`, and
  `h(Abar, W) · h(Bbar, −BP2) == Identity_GT`. The pairing here is the same shape as `CoreVerify`'s
  (already implemented as `pairing_check`), with `Abar`/`Bbar` in place of `A`/`B` and no `e·BP2` term.
- **`calculate_random_scalars(count)`**: `r_i = OS2IP(get_random(expand_len)) mod r`, one fresh call
  per scalar. Required for the real path.
- **`seeded_random_scalars(SEED, DST, count)`** — the mock the vectors use, required for the test:
  `out_len = 48 * count`; **one** `expand_message(SEED, DST, out_len)` call, then each 48-byte chunk
  is reduced mod r. Not `count` separate expand calls — that distinction is exactly what a wrong
  implementation would still get "random-looking" values from. Aborts when `count * 48 > 65535`, and
  `expand_message_xmd` caps at `255 * 32 = 8160` bytes, so the BLS12-381-SHA-256 limit is 170 scalars.
- `random_scalars` is `5 + U` long, and `ProofFinalize` consumes it together with the undisclosed
  messages — so the mock must be fed in the same order the finalize step expects.

Remaining to read before writing: §3.7.1–§3.7.4 (the four subroutines, 1557–2050), the proof codecs
(2730–2864), and the D.2.2 vectors' SEED/DST. Budget this as the largest single increment: four
subroutines plus two codecs plus the mock, then a build cycle per mistake — plan for several.

The proof vectors mock the random scalars with a SEED and DST (§8.1) — implement
`seeded_random_scalars` so `CoreProofGen` can be driven deterministically and compared against the
published proofs (Appendix D.2.2.1, D.2.2.2). Proofs are the part that cannot be checked any other
way, so this mock is required, not optional.

## Increment 4 — wiring and the register — LANDED (`56417fa`)

`bbs_issue` / `bbs_prove` / `bbs_verify` are wired and the BBS family's refusal arm is gone; the
dispatch table holds no refusals at all now. The credential and proof strings are self-describing
(`v1:<signature>:<public_key>:<header>` and `v1:<proof>:<header>:<indexes>:<message_count>`) for the
same reason the blind family's transcripts are: neither declared struct has a field for a key, a
header or an index list.

Recorded rather than hidden: `bbs_issue` draws fresh key material per call, because the surface has no
key-material argument and a `signer_id`-derived key would be guessable from a name. The private key is
therefore not retained, so a caller cannot re-issue under the same identity — a real issuer holds its
own key material, which this surface cannot express.

Evidence: `cargo test --lib bbs` → 29 passed / 0 failed (including the canonical-surface test), and
`cargo test --lib stdlib::crypto` → 127 passed / 0 failed (the dispatch table changed, so the coverage
guard `every_declared_crypto_fn_reaches_this_router` was re-run).

---

Rows for the future, in the order they were originally scoped (kept because the reasoning still
applies if the surface is ever extended):

- Route `bbs_issue` / `bbs_prove` / `bbs_verify` in `src/stdlib/crypto.rs` to this module and remove
  the `crypto_fn_needs_spelling` refusal for the BBS family (the last one in that table).
- The declared `.tl` surface is `bbs_issue(messages)` → `BbsSignature`, `bbs_prove(signature,
  revealed)` → `BbsProof`, `bbs_verify(proof, revealed)` → `bool` (read `stdlib/crypto.tl` for the
  exact declarations and field names before wiring; do not guess).
- The `.tl` surface has no place for the public key on `bbs_verify` — same class of constraint as
  FROST and the blind family. Decide and document how it travels (self-describing string), and record
  the deviation in the module header and the register row, as the other two families did.
- Planes: check `grep -c '"bbs_issue"' src/codegen.rs` (expected 0 → interpreter plane only) and say
  so in the row.
