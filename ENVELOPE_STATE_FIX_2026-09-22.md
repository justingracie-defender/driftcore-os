# Physical envelope: five layers, closed and mutation-tested

> **In this repository:** the mutation harness is
> `scripts/mutation_harness_envelope.py`; run it with
> `python3 scripts/mutation_harness_envelope.py .` from the repository root.
> The reproduction scripts and probes named below (`repro_*.py`,
> `v5_cold_probes/`) and the part 2 design live in the review bundles, not in
> this repository.

**23 September 2026, v6.3 (part 1).** Branch from `4b493e0`. Two files:
`driftcore/governance/physical_envelope.py` and `test_physical_envelope.py`.
Delivered as `envelope_state_fix_v6.3.patch` (`patch -p1`), **not as an archive**
— every archive built this session descends from the pre-Apache tree and would
revert the relicense. v6.3 supersedes v1–v6.2.

External review (SINT Labs / Illia Pashkov) reported one fail-open default.
Fixing it properly surfaced more failures in the same lifecycle; Sol's next pass
found the weakness had moved into how the declared set and the active envelope
change; and then **SINT turned the shared requirements into a 25-case runnable
fixture** — whose case list, read before a single case was run, exposed two holes
in the code the first two layers had just closed. Round 4 (Grok and Sol,
reviewing v4) found seven more, two of them serious (§3b). Round 5 — an
independent cold review, the coordinator's own probes, Sol and GLM — found ten
ways v5 could still reach 800N when it should be at 20N; v5 had introduced
three of them itself (§3c).

---

## 1. Layer one: evidence → state → expiry

| # | Finding | Found by | Now |
|---|---|---|---|
| 0 | `verify_proof=None` default: any non-empty string attested; `proof='x'` earned the wider envelope | SINT Labs | **Refuses to construct** |
| 1 | `ttl=inf` accepted under a genuine signature | Sol | Refused at evidence construction |
| 2 | Order dependence: `[TRUE seq1, FALSE seq2]` held the condition open; reversed did not. **A fence opening did not close the envelope** | Sol | Reduced by sequence number; signed FALSE retracts |
| 3 | Same-sequence conflict resolved last-writer-wins to TRUE | Sol | Fails closed — see §3 for the policy's history |
| 4 | Two trusted sources disagreeing resolved to TRUE | Sol | Fails closed |
| 5 | `accept()` + `deadline_of_last_accept()` was a torn read; `accept([])` between them set the expiry to infinity | Sol | One `ConditionSnapshot`; the racy API is a refusal |
| 6 | Verifier outage: the exception escaped before `_active` was touched, so the wide limit stood *because the check for it had broken* | Sol | Demotes, then reports |
| 7 | Restart replay: superseded evidence refused in-instance, accepted by a fresh authority | Sol | Epoch binding + injectable durable replay state |
| 8 | Deadline written only when the envelope *changed*; fresh evidence never extended it | Claude | Written on every selection |
| 9 | Injected `replay_state` is a trust boundary; a corrupt mark denies a sensor forever, failing closed | `finite_guards` | Screened as input |
| 10 | Unbounded `sequence` denies a sensor permanently and overflows `math.isfinite` | Claude | `MAX_SEQUENCE` |

## 2. Layer two: the declared set → the active envelope

| # | Finding | Found by | On `main` | Now |
|---|---|---|---|---|
| 11 | A widening earned by evidence **committed before its audit record**; with the sink down, the caller saw "refused" while 800N was active — under a comment stating the opposite rule | Sol | active = 800N | Journal first; unrecordable → fallback |
| 12 | **Dropping a dimension bypassed the human gate** (`limits.get(d, 0)` read a removed speed limit as zero) | Sol | accepted | Human required |
| 13 | **Fallback frozen at construction**; after a runtime tightening to 20N, ODD widened back to 60N | Sol | active = 60N | Fallback follows the declared set |
| 14 | **Declaration was activation**; a human-declared 800N went active with no evidence and an infinite deadline | Sol | active = 800N | Human declares, evidence activates |
| 15 | **A transient widening made permanent**: while at 800N an agent added an unconditional 700N "tighter than now"; when evidence vanished, ODD never fired again | Claude | active = 700N | Only a new *safest* envelope skips the human |
| 16 | **Clock-domain mismatch**: a wall-clock authority deadline compared on the monotonic clock; the wide envelope never expired | Claude | never expires | Expiry carried as remaining duration |

Root cause: `_active` was assigned in five places, each with its own rules. Fix:
one door, `_commit()`, behind a direction-aware `_transition()` — toward safety
commits first, anything else records first — and `request_change` asks three
separate questions: who may add it, whether it activates now, what the fallback
becomes. `F1-S1`/`F1-S2` parse the class and fail on a sixth door.

## 3. Layer three: from the case list of SINT's shared fixture

Illia's fixture lists its cases: opaque proof, order-dependence both ways,
verifier outage, expiry race, unbounded TTL, restart replay, same-sequence
conflict, source disagreement, M-of-N attestors, selector faults with fallback
and deny, replay-store outage, and digest binding. Reading that list against v3
found two holes before anything ran:

| # | Finding | Provenance | Reproduced on v3 | Now |
|---|---|---|---|---|
| 17 | **Replay-store outage failed open.** A store that raised on read or write let the exception escape with **800N active** — finding 6 again, one injected dependency over | Introduced in v1, when the store became injectable | active = 800N | An outage: abandon the batch, demote, report |
| 18 | **A conflict could be half-replayed.** After signed TRUE@5 and FALSE@5, a lone reading at 5 was re-admitted, so replaying the captured TRUE half **reopened 800N**. The same held across batches: TRUE@5 accepted, FALSE@5 later, then TRUE@5 again | Present since v1; **v2 pinned it as correct** (old F0-D12) | active = 800N | A conflicted sequence is poisoned: only a strictly newer reading moves the condition |
| 19 | **The authorization named nothing.** The record said "conditions attested"; no digest, sequence or source of the evidence relied on. The same gap SINT's fixture found in SINT | On `main` | — | `authorising_evidence` digest, recorded with every transition |
| 20 | **An unanticipated fault inside selection** left whatever envelope was active standing while the exception was in flight | On `main`, as a class | — | Guard: if `select_for` raises, for any reason, the machine is on the fallback |

**The conflict policy, told straight, because it changed twice today.** v1
failed conflicts closed within a batch. Grok then asked whether advancing the
replay mark on a conflict could strand an honest sensor re-sending at the same
sequence. The coordinator answered that the replay check is strictly-less-than,
so a re-send at the conflicted sequence is still admitted — and wrote F0-D12 to
pin that as correct. That answer *was* the hole: admitting a lone reading at the
conflicted sequence admits either half of the conflict. SINT's fixture expects
the opposite — drop the reading until a strictly newer one arrives, without
quarantining the source — and SINT is right. The honest-sensor worry is
answered by the fact that an honest sensor moves its sequence forward.

Mechanically: each replay-store entry is now `(sequence, digest-of-the-reading-
accepted-there)`. After a conflict at N the entry becomes `(N + 1, "")`, so
nothing at or below N is admitted again. The digest is what makes the
**cross-batch** conflict visible. The comparison happens only after
authentication, so no unauthenticated record can poison a sequence
(`screening-never-moves-replay-state` still holds).

**On the guard (finding 20).** `select_for` now commits the fallback before any
exception leaves it. That makes the older per-handler orderings — outage demotes
first, journal-first on widening, fallback on an unrecordable widening —
defense in depth rather than the only defense. Mutating any one of them alone is
now masked by the guard, so the harness runs those three as **compounds** (inner
layer and guard removed together), and the layers that can be observed on their
own have **isolation checks** that call `evaluate()` directly (F2-R3b, F2-R4,
F2-R6). Without those, the guard would have hidden regressions in four handlers.

## 3b. Layer four: round 4 of review (Grok, Sol), 23 September

#21–24 were reproduced against v4 by Sol; #25–27 by the coordinator. Each fix
has a check, and a mutation restoring the v4 behaviour that the check catches —
v5's tests cannot run on v4 unmodified (the store API changed), so the
mutations are the evidence that each check fails on the old behaviour.

| # | Finding | Found by | Observed on v4 | Now | Check / mutation |
|---|---|---|---|---|---|
| 21 | **Two authorities sharing one replay store could move a mark backward** | Sol | FALSE@5 and an older TRUE@4 evaluated concurrently: both read the old mark, TRUE@4's write landed last, and replaying TRUE@4 went 20N → 800N | Store writes are `compare_and_set` against the exact entry screened; a store without it is **refused at construction**; `ReplayStore` wraps an in-process mapping | F3-S1–S3 / M41, M42 |
| 22 | **Any truthy verifier answer authenticated** | Sol | `verify_proof` returning `"VERIFIED? NO"` passed a junk proof: 800N | Only `True` authenticates; a non-bool answer is a verifier **fault** (demote, report) | F3-V* / M40 |
| 23 | **Renewing 800N on new evidence was not journaled** | Sol | audit sink down, newer evidence: 800N extended, no record, no exception | Renewal on changed evidence is journaled first; unrecordable → fallback | F3-R1 / M43 |
| 24 | **A dissent could be erased by omitting the dissenting source** | Sol | A TRUE@6 + B FALSE@6 → 20N; then A TRUE@6 alone → 800N while B's FALSE was still fresh | A fresh signed FALSE counts until it expires or its source says something newer | F3-D1, D2 / M44 |
| 25 | **Conflict at MAX_SEQUENCE: poison unrecordable in a 64-bit store** | Grok (edge), Claude (store width) | v4 poisoned to N+1 = 2⁶³; a signed-64-bit store refused the write, the poison never landed, and the captured TRUE@MAX replayed to 800N | Conflict recorded as `(N, "conflicted")`: every mark stays in [0, MAX_SEQUENCE]. At MAX, the operator is told the source is finished for the epoch and that rotating it recovers | F3-M1–M5 / M33, M35 |
| 26 | **Replay marks survived epoch rotation** | Claude (probing #25) | durable store, new epoch, sensor counter reset to 0: "superseded" — stranded behind the old epoch's marks | Store keys are `(epoch, source, condition)` | F3-E1, E2 / M34 |
| 27 | **Reading digest was `sha256(repr(payload))`** | Grok, Sol | the same reading typed `5` and `5.0` had two digests — a false conflict that poisoned the sequence and dropped to 20N; no non-Python runner could reproduce it | Versioned, length-prefixed binary encoding with a golden vector; times with no exact binary64 value refused | F3-C1–C4 / M36, M47 |
| 28 | **The authorization named only its evidence** | Grok; Sol on the shape | the same reading earning `working` 800N or `careful` 800N gave one digest | New `authorization_digest` binds envelope name + limits + evidence digest; `authorising_evidence` keeps its meaning | F3-A1, A2 / M45, M46 |
| — | Interrupts: guard behaviour **already correct in v4, untested** | Grok, Sol | — | KeyboardInterrupt and SystemExit propagate unwrapped with the fallback active | F3-B* / M37, M38 |
| — | Unauthenticated poison: **already correct in v4, untested at this point** | Grok | — | a junk-proof FALSE@N cannot poison N | F3-P1 / M39 |

**What review claims did not hold, and why that matters.** Grok's "overflow at
MAX_SEQUENCE" is not a Python overflow — Python integers do not overflow, and
v4's read bound already admitted MAX+1. The coordinator dismissed it on that
basis, and was wrong to: the same boundary fails in a store whose sequence
column is signed 64-bit, the width MAX_SEQUENCE was chosen to match (#25).
Grok's suggested clamp, `(MAX_SEQUENCE, "")`, would reopen the half-replay —
it is mutation M27 at the boundary. Grok's "float repr is unstable across
processes" is not so (CPython's repr is deterministic); the fix is right for the
two reasons in #27.

### The digest specification (v1)

```
field(b)   = uint64_be(len(b)) || b
text(s)    = field(utf8(s))
reading    = sha256( text("driftcore-reading-v1") || text(source) || text(condition)
                     || field(0x01 | 0x00) || field(binary64_be(issued_at))
                     || field(binary64_be(ttl_seconds)) || field(uint64_be(sequence))
                     || text(epoch) )
evidence   = sha256( text("driftcore-evidence-v1") || field(uint64_be(n))
                     || for each (condition, source, sequence, reading) sorted:
                        text(condition) || text(source) || field(uint64_be(sequence)) || text(reading) )
authorization = sha256( text("driftcore-authorization-v1") || text(envelope name)
                     || field(uint64_be(n limits)) || for each (dimension, limit) sorted:
                        text(dimension) || field(binary64_be(limit))
                     || text(evidence) )
```

binary64 writes −0.0 as 0.0. Hex digests are lowercase. The proof is not part
of a reading. The deadline is not part of an authorization: it is operational
state, not evidence. **Golden vector** — `sensor-hub`, `fence_closed`, TRUE,
issued_at 1000.25, ttl 60.0, sequence 7, epoch `boot-epoch-A`:
`1ab21fb06139cdfdfb63cec6cb4f92909d37b963d27163b0627883d3deebc833`
(preimage spelled out field by field in `F3-C1`).

## 3c. Layer five: round 5 (cold pass, Sol, GLM, Grok, Meta), 23 September

Every row was reproduced against v5 before it was fixed; the reproductions are
`v5_cold_probes/` (run them on a v5 tree to see each failure, on a v6 tree to
see it closed). "Cold pass" is an independent reviewer: a fresh Claude
instance given only the code, tests, promises and known limits — no
conversation, no earlier reviews. Origins: **main** = on `4b493e0`; **v1–v4** /
**v5** = introduced by this patch series.

| # | Finding (could reach 800N) | Found by | Origin | Now | Check / mutation |
|---|---|---|---|---|---|
| W1 | Envelope limits and `required` were the caller's live objects: editing them after verification moved a live limit (20N→800N, or an agent's 5N "safest" to 5000N) with no human and no record | cold pass; Sol independently | main | Frozen at construction (read-only mapping, plain keys, `frozenset`); pickling rebuilds through the constructor | F4-W1a–e / M48, M49 |
| W2 | The compare-and-set was skipped when a reading equalled the entry it was judged against — the ordinary control-loop case — so a peer's newer FALSE, or a store whose reads lag its writes, was never seen | cold pass | **v5** | Every acceptance is a compare-and-set | F4-W2a–b / M53 |
| W3 | A conflict from the dissenting source erased its dissent; after its conflicting readings expired, its further FALSEs at that sequence were refused and it went silent | cold pass; coordinator | **v5** | A conflict keeps the source's latest-expiring FALSE; a signed FALSE at a conflicted sequence still counts as a dissent (a replayed FALSE can only tighten) | F4-W3a–c / M55, M56 |
| W4 | Evidence subclasses brought their own `is_fresh`/`expires_at` (an expired reading answered "fresh, forever": 800N, no deadline); a `str` subclass told `canonical` "stowed" | cold pass | main (methods); **v5** (`canonical`) | Exact class at admission; strings stored as plain `str`; field types re-checked exactly | F4-W4a–b / M51, M52 |
| W5 | A human declaring an unconditional non-safest envelope widened the machine on the signature alone | cold pass | main | Refused at runtime (construction is §7) | F4-W5 / M60 |
| W6 | Decisions depended on whether anyone had read `.active` after a lapse: a 20N→400N widening was recorded as a tightening and committed before its record | cold pass | main | Expiry processed before any selection or declaration | F4-W6 / M58 |
| W7 | "Safest" compared limits only: an agent replaced a mechanically enforced 20N fallback with 19.99N enforced in software | cold pass | main | `at_least_as_safe_as` = limits AND enforcement rank, everywhere safety is judged | F4-W7 / M61 |
| W8 | Two `ReplayStore` wrappers over one mapping had separate locks; both compare-and-sets won and the mark went 1→5→2 | coordinator | **v5** | One lock per underlying mapping | F4-W8 / M65 |
| W9 | A conflict whose marker lost its compare-and-set was forgotten; the captured TRUE replayed to 800N on the authority that saw the conflict | Grok, Meta, Sol, coordinator | v1–v4 (as an overwrite race) | Re-read and re-judge; a marker that cannot land is an outage | F4-W9, F4-A1 / M54 |
| W10 | `select_for` could return an authorization that expired while it was being judged | cold pass | main-era | Deadline re-checked before return | F4-W10 / M59 |
| N1 | A controller clock reading NaN extended a wide authorization forever (`nan > deadline` is False) | `finite_guards`, when the check moved | main | A non-number ends the authorization | F4-N1 / M66 |
| C1 | An injected authority clock that stepped BACK made an expired reading fresh again: a wall clock stepping back 40 s returned 800N | probing a clock step, from Grok's round-6 list | main | The authority's own time never runs backward; a forward jump fails closed until real time catches up | F4-C1 / M76 |
| C2 | A clock that is not a number — a string, an integer too large for a float — raised instead of judging everything stale, as the C1 claim said (select_for still ended on 20N) | Sol, round 6 | v6.2 | Anything non-numeric is treated as NaN: everything stale | F4-C2 / M78 |
| U1 | At construction, an unconditional envelope wider than the fallback was accepted silently, and was active on no evidence | Grok, round 6 (the construction half of W5) | main | Refused by default; `allow_unconditional_wide=True` opts in and the activation record names it | F4-U1, U2 / M79, M80 |
| X1 | Finite `issued_at` and `ttl_seconds` summed to an infinite expiry: with a deployment ceiling and authority clock to match, 800N was authorised until `inf` | ChatGPT (on v5; still present in v6.0) | main (which accepted `ttl=inf` outright); v1's fix left the sum open | Expiry must be finite, at construction and again at the trust boundary | F4-X1a–b / M74, M75 |

Also fixed: M1 activation through `request_change` inherited its predecessor's
evidence digest (F4-M1 / M62, M63); M2 a verifier crashed by a junk proof is
still an outage, but the record names the record that crashed it (F4-M2 / M64);
M3 a disagreement is recorded as disputed evidence naming the dissenter, its
sequence and digest, and the epoch (F4-M3 / M57); A1 an honest second authority
that loses the race to the identical reading is not flapped to 20N (F4-A1);
S1–S3 string, limit and surrogate gaps in the digest spec (F4-S1–S3 / M47b,
M52, M67); the store refuses to move a mark backward or overwrite a conflict
marker, whatever its caller decided (GLM; F4-G1 / M50).

**Checks that could not fail in v5, and now can** (cold pass, T1–T4): journal-
first ordering is observed at the moment of recording, so it no longer needs the
fallback guard removed to be tested (F4-T1a–b / M17, M68); the one-door check
sees tuple unpacking, `setattr` and `__dict__` writes (F4-T2 / M69, M73, both
behaviour-identical); both locks are tested with deterministic interleavings
(F4-T3a–b / M70, M71); every named number in the module is on a reviewed list
(F4-T4 / M72). And GLM's suggestion, a randomized property: across 750
batches of genuine, replayed, conflicting, junk, other-epoch and stale readings,
800N is never reached without an uncontradicted genuine TRUE, and both outcomes
occur, so the property is not vacuous (F4-H1–H3).

**What review claims did not hold.** GLM rated the Enum-name case "looks
benign"; the digests differed and the robot dropped to 20N, and the related
spoof widened it (W4). GLM's fix for M1 — refuse to activate a tighter
envelope until its own conditions have evidence — would keep the robot at
800N while a human asks for less; tightening stays free and its evidence is
named correctly instead. Meta's durable-dissent option keyed by epoch would let
an epoch rotation (which v5 advises for recovery at MAX_SEQUENCE) silently
clear a dissent; its "CI asserts the hardware interlock exists" cannot fail.

## 4. Verification

| Check | Main (`4b493e0`) | With the patch |
|---|---|---|
| `test_physical_envelope.py` | 65/65 | **249/249** |
| Full suite | 5,182 / 137 files | **5,366 / 137 files, exit 0** |
| `finite_guards` | PASS — current 182, new 0, removed 3 | **PASS — current 180, new 0, removed 5** |
| `robot_surface --check` | 3 pre-existing `mediated_actuation` regressions | **byte-identical output** |
| `untested_modules` | FAIL (pre-existing) | **byte-identical output** |
| `authority_sites` | OK | OK |
| `claims_ledger` untagged | 1558 | **1558, identical** |
| `claims_ledger` tagged / paired | 137 / 125 | **163 / 151, +26, all paired** |
| `claims_ledger` unpaired | 12 | **12, unchanged** |
| Baseline JSONs | — | **all five untouched** |

+184 checks reconciles exactly against the suite delta. Verified by applying the
patch to a pristine copy of `4b493e0`, not from the tree it was built in.

## 5. Mutation test: 85 reverted, 85 caught

v6 adds M47b, M48–M80 and a single-layer M17 (see §3c) and re-anchors thirteen
mutations whose code was deliberately rewritten. M41 is now a compound
(M41+S): the store's own regression guard masks it, and that guard has its own
isolation check (F4-G1 / M50). M69 and M73 are sixth doors whose behaviour is
identical to `_commit`, so only the structural check can see them. In v6.1 the
harness caught the new overflow check masking M47's only case (10**400); F3-C4
now also refuses a finite inexact time (2**53+1), which only the exactness
check can.

## 5a. v5's mutation test (50 of 50)

v5 adds M33–M47 (see the table in §3b) and re-anchors seven v4 mutations whose
code was deliberately rewritten (M3, M9, M12, M14, M25, M27, M28). M27 is now
"conflict recorded as an ordinary mark" — Grok's literal clamp, generalized.
The v4 list follows.

Thirty-two single-layer mutations and three compounds. Each anchor must match
exactly once or the mutation counts as a survivor — under the old
"replace the first match" rule, M5b would have silently mutated the replay-store
handler instead of the verifier, because they now share a line.

```
M1   reduce by list position                    -> F0-D4
M2   drop the FALSE-retraction branch          -> F0-D1
M3   in-batch conflict: last-writer-wins        -> F0-D5
M4   disagreement resolves to TRUE              -> F0-D7
M5   verifier outage propagates                 -> F2-R6 (isolation)
M5b  verifier outage propagates ANY exception   -> F2-R6 (isolation)
M6   accept any epoch                           -> F0-E5
M7   accept any TTL                             -> F0-F1
M8   deadline not moved for the same envelope   -> F0-H5
M9   rejected record burns a sequence           -> F0-D12b
M10  require_proof with no verifier             -> F0-A1
M11  stop validating evidence structure         -> F0-B3
M12  never write the replay store               -> P0-1
M14  do not advance on a conflict               -> F0-D11
M15  accept an empty epoch                      -> F0-A3
M16  accept an infinite freshness ceiling       -> F0-A4
M18a who-may-add compares with CURRENT only     -> F1-B3
M18b the original limits.get(d, 0) heuristic    -> F1-B1
M19a fallback frozen at construction            -> F1-C2
M19b fallback replaced by ANY declaration       -> F1-C4
M20  declaration activates with no evidence     -> F1-D2
M21  authority deadline on the controller clock -> F1-E2
M22  a sixth door, behaviour identical          -> F1-S1 (structural only)
M24  _commit never bounds a non-fallback        -> S-C
M25  replay-store READ outage propagates        -> F2-R4 (isolation)
M26  replay-store WRITE outage propagates       -> F2-R3b (isolation)
M27  conflict poisons TO the sequence, not past -> F0-D12
M28  conflict across batches not detected       -> F0-D13b
M29a the authorization names nothing            -> F2-G2
M29b digest covers ALL held conditions          -> F2-G6
M30  the fallback guard removed                 -> F2-F1
M31  a door for the digest outside _commit      -> F2-S1 (structural only)
M13+G outage reports before demoting, no guard  -> F0-G2
M17+G every move "toward safety", no guard      -> F1-A3
M23+G unrecordable widening stays, no guard     -> F1-A5
```

## 6. The rules this adds up to

Unauthenticated evidence may tighten, warn, or trigger fallback; it may not
activate a more permissive envelope. A human's signature may declare a more
permissive envelope; it may not activate one. **Neither key alone widens the
machine.** A dependency that cannot answer — verifier or replay store — is
UNKNOWN, never PASS and never empty. A conflicted sequence is never trusted
again. An authorization names the evidence it rests on. And if selection fails
for any reason, the machine is on the fallback before anyone hears about it.

Standing checklist item, from Meta: *does the test harness allow the violating
action to be attempted?* Wherever a violation needs a wide starting state, the
check starts from one — and nine primer assertions, one inside the `wide_then`
helper that primes most of Fixture 0's negatives, fail loudly with
`PRIMER FAILED` rather than letting a check pass vacuously. Two Fixture 1 checks
were written without one and fixed before shipping; one of them turned out to be
the only check that catches a mutation (M23+G).

## 7. What is NOT closed, stated rather than implied

- **No M-of-N quorum.** SINT's fixture has M-of-N cases; DriftCore will fail them
  honestly. Deferred until the cases can be read, so the semantics match rather
  than being guessed. Single-source sufficiency and fail-closed disagreement are
  pinned (`F0-D10`, `F0-D7`).
- **The shared fixture itself has not been run.** It could not be retrieved from
  this session. A DriftCore runner is the next step. The digest is now a
  published spec with a golden vector, but it will still differ from SINT's.
- **Part 2 of v6 (design, awaiting Sol's final report and SINT):** a durable
  dissent latch, not scoped to the epoch, cleared only by a newer clean reading
  from the dissenter or by a journaled human clear that activates nothing; key
  revocation; binding proofs to the robot's identity (a captured FALSE replays
  across a fleet that shares sensor names, keys and epochs — per-robot epochs
  stop it today); an asymmetric quorum (one source may tighten, N must agree to
  widen), with N declared and no default.
- **Unconditional wide envelopes at construction: closed in v6.3** by default.
  A deployment may still configure one with `allow_unconditional_wide=True`; it
  is recorded, not prevented. F0-G4 opts in, because its point is that an outage
  demotes such an envelope.
- **Resolved in round 6: rank stays in activation** (Grok). The proposal below
  is withdrawn; see `PART2_DESIGN_v2.md` §G.
- **Enforcement rank can decline a human's numeric tightening** (Grok, round 6).
  A human declaring 300N enforced in software while 800N enforced in hardware is
  active: v6 does not activate it on declaration, because it is not at least as
  safe on rank. That is right if switching envelopes lifts the hardware ceiling,
  and wrong if the hardware ceiling stays in force underneath — DriftCore's model
  cannot say which. Proposed for part 2: numbers decide activation on a human's
  declaration; rank keeps deciding who may skip the human and what may replace
  the fallback. Rank must never decrease without a human (F4-W7).
- **Two honest authorities contending for one store can starve each other.**
  `_settle` retries a lost compare-and-set three times, then refuses the
  reading (or, for a conflict marker, reports an outage). Under sustained
  contention that is a 20N availability failure, not a widening; the rate of
  "kept changing" refusals should be monitored rather than the gate disabled.
- **The authority's time floor is per instance.** A restart forgets it; a wall
  clock that steps back across a restart is covered only if the epoch rotates,
  as the restart rule already requires.
- **A verifier that raises on a junk proof is still treated as an outage.** The
  contract is: return False for a bad proof, raise only when verification is
  unavailable. DriftCore cannot tell the two apart for a verifier that breaks it.
- **`ReplayStore` is atomic only within one process.** A durable store shared by
  several processes must implement `compare_and_set` natively (a transaction,
  a conditional put). DriftCore cannot check that it does.
- **The dissent memory belongs to one authority, not to the store** (ChatGPT,
  round 5, reproduced on v6.1). Two authorities sharing one replay store can
  decide differently from the same fresh history: authority 1 hears sensor B's
  signed FALSE, authority 2 hears only sensor A's TRUE and holds the condition.
  A restart forgets it too. The replay entry cannot reconstruct it, because it
  stores a digest, not a value. Proposed for part 2, for review before it is
  built. **Superseded by `PART2_DESIGN_v2.md`**, after Grok's round-6 attack
  showed that two store keys cannot give two authorities one view. v2 keeps one
  record per (robot, condition), which is judged and written in a single
  compare-and-set. The v1 sketch is kept below for the record:
  - **Where it lives.** A dissent record lives in the shared store beside the
    mark: key `("dissent", source, condition)`, value `(epoch, sequence, digest,
    issued_at, ttl)` of the source's standing FALSE. It is not scoped to the
    epoch, so rotating the epoch does not clear it.
  - **Write order: tighten first.** The dissent is written (compare-and-set)
    before the replay mark advances, and cleared only after a newer clean
    reading's mark has landed. Every crash window leaves an extra dissent,
    which fails closed, never a missing one. This matters because the store has
    no multi-key transactions.
  - **Who reads it.** Every authority on the store consults it before holding a
    condition: one read per trusted source absent from the batch.
  - **What clears it.** Only an accepted newer reading from that source (a
    higher sequence in the same epoch, or a later `issued_at` across epochs), or
    a journaled human clear that activates nothing.
  - **It does not expire with its TTL.** A dissenter that dies holds the
    machine at 20N until a human clears it, and the record names it. That makes
    key revocation mandatory: a stolen key's single FALSE would otherwise latch.
    Whether deployments that need availability may bound the latch by TTL is
    the same question as Illia's position 1.
- **At MAX_SEQUENCE a conflicted source is finished for the epoch.** Recovery
  is rotating the epoch, which the operator is told.
- **Verifier-outage policy is a judgment call SINT has put to us.** DriftCore
  demotes immediately; SINT's fixture expects no new activation while existing
  evidence runs out its TTL. Proposed: make the normative expectation an upper
  bound, so the stricter behaviour passes.
- **The epoch is declared, not verified**; restart replay is closed only if the
  operator varies it or supplies a durable store (`F0-E4` asserts the exposure).
- **The proof binds a reading, not a deployment.**
- **An unconditional envelope is eligible in every state**; one wider than the
  fallback becomes where the machine goes when no conditional envelope holds.
  Declaring one needs a human.
- **A tightening through `request_change` is not sticky**, and no envelope can be
  retired from the declared set.
- **Any failure in `select_for` now ends on the fallback**, including an audit
  failure while narrowing to an envelope tighter than current but looser than
  the fallback. Deliberately conservative.

## 8. API changes a deployment must action

```python
ConditionAuthority(
    trusted_sources=frozenset({"sensor-hub"}),
    epoch=<changes whenever replay state is lost>,   # required
    max_ttl_seconds=<deployment's staleness limit>,  # required
    verify_proof=<bound to the supervisor's key>,    # required with require_proof
    replay_state=<store with get + compare_and_set>, # ReplayStore(mapping) in-process; one per mapping
    clock=<any clock>,  # any time domain; its time never runs backward here
)
```

- `replay_state` must provide `get(key)` and an atomic
  `compare_and_set(key, expected, new)`; a plain mapping is **refused**. Keys are
  `(epoch, source, condition)`; entries `(sequence, reading-digest)`, or
  `(N, "conflicted")` after a conflict at N. Every sequence fits a signed 64-bit
  column. (New in this patch series; main's store is not injectable, so no
  deployed store is affected.)
- `verify_proof` must return a real `bool`; anything else is a verifier fault.
  Contract: return False for a bad or unparseable proof; raise only when
  verification itself is unavailable.
- (v6) A durable store's `compare_and_set` must be linearizable and must refuse
  a write that moves a mark backward or replaces `(N, "conflicted")` with an
  ordinary entry at N; `get` may lag, the compare-and-set may not.
- (v6) `PhysicalEnvelope.limits` is a read-only mapping with plain string keys;
  `OperatingConditions.required` is a `frozenset` of plain strings (a bare string
  is refused). Limits must have an exact binary64 value. Names must be valid
  Unicode (no lone surrogates); str subclasses and Enum members are stored as
  their plain value.
- (v6) `evaluate()` refuses `ConditionEvidence` subclasses.
- (v6.3) `EnvelopeController(..., allow_unconditional_wide=False)`: an
  unconditional envelope that is not at least as safe as the fallback is refused
  at construction unless this is True; when it is, the activation record names it.
- (v6) `request_change` refuses an unconditional envelope that is not the
  safest; "at least as safe" now counts enforcement rank (`at_least_as_safe_as`).
- (v6) `authorization_digest` is empty only on the fallback; an envelope active
  on no evidence still has one.
- (v6) A signed FALSE at a conflicted sequence counts as a dissent.
- (v6) Audit: `ENVELOPE_ODD_FALLBACK` reads "FAIL CLOSED: evidence for [...] is
  disputed" when the cause is disagreement or conflict, and names the causes;
  outage records carry the reasons.
- `ConditionEvidence.digest` is the v1 spec above; `.canonical` gives its
  preimage (a verifier may sign exactly those bytes). Times must have an exact
  binary64 value.
- `EnvelopeController.authorization_digest` — envelope identity + evidence.
- Audit: new `ENVELOPE_RENEWED`, recorded before a lease is extended on new
  evidence.
- `ConditionSnapshot` gains `replay_store_failed` and `support`.
- `EnvelopeController.authorising_evidence` — the digest of exactly the readings
  the active envelope rests on; `""` for the fallback or an unconditional
  envelope.
- Audit: `ENVELOPE_SWITCHED` detail carries `evidence=<digest>`; new
  `ENVELOPE_REPLAY_STORE_OUTAGE`; `ENVELOPE_WIDENED` is now
  `ENVELOPE_DECLARED_BY_HUMAN`.
- `select_for` wraps an unexpected exception in `EnvelopeRefused`, chaining the
  original, after committing the fallback.
- `request_change` returns `(True, "... declared but NOT active ...")` for a
  declaration that awaits evidence.

One construction site for `ConditionAuthority` in the repo (the test fixture);
one external caller of `request_change` (`test_bounded_audit_fields.py`), which
still passes unchanged.

---

*Every row in §1–§3 was reproduced before being fixed — §1 and §2 against
`4b493e0`, §3 against v3 of this patch. The patch applies with `patch -p1` and
was verified from a clean application to a pristine copy of `4b493e0`. Full
suite 5,366/137 exit 0. 85 of 85 mutations caught. §3b findings reproduced against v4 by Sol and the coordinator; §3c against v5 by the independent cold pass, Sol and the coordinator.*
