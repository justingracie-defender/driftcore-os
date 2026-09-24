# SINT review — status and corrections

**Last updated 23 September 2026.** This file replaces an earlier version
committed the same morning that contained two errors about this repository. Both
are withdrawn below rather than deleted, because the corrections are the useful
part.

Context: Illia Pashkov (SINT Labs) reviewed `driftcore/governance/physical_envelope.py`
and raised two gaps. SINT subsequently opened
[PR #256](https://github.com/sint-ai/sint-protocol/pull/256) on their own repository
proposing a joint envelope-attestation roadmap, and issue #2 here.

---

## 1. The proof finding — confirmed, reproduced, and now CLOSED

`ConditionAuthority.__init__` defaulted to `verify_proof=None`, and
`_accept_locked` then checked only that the proof string was non-empty.
Reproduced against the reviewed tree:

```
DEFAULT CONFIG — verify_proof=None

  proof='x'                  -> accept() = {'fence_closed': True}
  proof='not-a-signature'    -> accept() = {'fence_closed': True}
  proof='\x00'               -> accept() = {'fence_closed': True}
  proof='' (empty)           -> accept() = {}
```

`fence_closed` authorises the **wider** envelope. Presence of a proof field was
being read as authentication, on one character.

**Closed.** `ConditionAuthority` now refuses to construct when `require_proof`
is set and no verifier is supplied. Not a default verifier — a library cannot
conjure a legitimate trust root — so instead the insecure configuration is
unconstructable, which is the rule this module already applied to an empty
`trusted_sources` and `EgressPolicy` applies to an empty allowlist.

And the test suite could not have detected it: the fixture supplied `proof="sig"`
and the only negative case was the empty string, so all 65 checks passed in the
single configuration that could not fail. One of those checks was labelled
*"properly attested evidence"* about a three-character string. That is a
measurement failure as much as an implementation one, and it is the most useful
part of the external review.

## 2. Withdrawn: two errors in the earlier version of this file

**2a. The identity finding was correct, and the earlier draft wrongly narrowed it.**
SINT's review basis was public commit `55f0a752`. In that revision
`physical_envelope.py` made its own string comparison to decide whether a caller was
human. The earlier draft "partially corrected" that finding by citing a newer working
tree that was **not public when the review was requested**. Rebutting an external
reviewer with code they were never shown is not a correction; it is a
misrepresentation, and it is withdrawn.

Public `main` has since gained the centralised action-bound identity check, fail-closed
`UNCONFIGURED` behaviour, and startup/preflight identity verification — but that landed
*after* the review, and the finding stands against what was reviewed.

**2b. `require_secure_identity()` does not exist.** The earlier draft claimed that
symbol existed and that nothing called it at startup. Both halves are false. The symbol
is **`require_secure_mode()`** (`driftcore/authority/human_identity.py:413`), and it is
called at `main.py:57`, with `IdentityModeIsSecure` and `HumanAuthorizationIsReal` both
wired into `preflight.py`. The claim came from grepping for a guessed name rather than
testing behaviour.

## 3. Why the fix was held, and what holding it found

The one-line fix was directionally correct and could have shipped the same
morning. Turning it into a shared adversarial fixture surfaced seven more
failures in the same path, **all reproduced against the patched code with a real
verifier installed** — three of them unreachable while everything passed on
`proof="sig"`:

| Finding | Observed | Now |
|---|---|---|
| **Order dependence** | `[TRUE seq1, FALSE seq2]` → `{'fence_closed': True}`; reversed → `{}`. A correctly signed FALSE could not retract an earlier TRUE — `_accept_locked` had no branch that removed a condition | Reduced by sequence number; signed FALSE retracts |
| **Verifier outage** | verification failing while a permissive envelope was active did not demote | Demotes, then reports |
| **Expiry race** | interleaving `accept([])` between `accept()` and `deadline_of_last_accept()` set the authorisation deadline to infinity | One atomic snapshot; the racy API is a refusal |
| **Infinite TTL** | signed evidence with `ttl=inf` was accepted | Refused at construction |
| **Restart replay** | superseded evidence rejected in-instance, accepted by a fresh authority | Epoch binding + injectable durable replay state |
| **Equal-sequence conflict** | signed FALSE and signed TRUE at the same sequence resolved to TRUE | Fails closed |
| **Source disagreement** | one trusted source TRUE, another FALSE resolved to TRUE | Fails closed |

The first is more serious than the reported defect: it needed no forged proof,
only list ordering. **A fence opening did not close the envelope.**

Two more appeared while implementing: the authorisation deadline was written
only when the envelope *changed*, so a control loop presenting fresh evidence
flapped once per TTL; and an injected replay store is an external trust boundary
whose corrupt entry would deny every genuine reading from a sensor forever. Both
fail in the safe direction, which is precisely why running the system never
found them.

The object that needed securing was never signature verification. It is the
whole **evidence → state → expiry → envelope** transition.

A second pass then found the weakness had moved one layer over, into how the
declared set of envelopes and the active envelope change. Four findings from
Sol (ChatGPT, used as a reviewer) and two found while fixing them, all reproduced on the commit this file
replaces:

| Finding | Observed | Now |
|---|---|---|
| **Widening committed before its audit record** | audit sink down: `select_for` raised "refused" while 800N was active | Journal first; unrecordable → fallback |
| **Dropped dimension bypassed the human gate** | `system` replaced 60N/0.1 m·s⁻¹ with 30N and no speed limit | Human required |
| **Fallback frozen at construction** | after a runtime tightening to 20N, the ODD path widened back to 60N | Fallback follows the declared set |
| **Declaration was activation** | a human-declared 800N "when the fence is closed" went active with no fence evidence | Human declares, evidence activates |
| **Transient widening made permanent** | while legitimately at 800N, an agent added an unconditional 700N envelope; when the evidence disappeared, the ODD fallback never fired | Only a new safest envelope skips the human |
| **Clock-domain mismatch** | with the authority on wall-clock time, the wide envelope never expired | Expiry carried as remaining duration |

The common root: five code paths could change the active envelope, each with
its own rules. There is now one, and a structural check fails if a sixth is
added.

Then SINT turned the shared requirements into a runnable, protocol-neutral
fixture of 25 cases. Its **case list alone**, read before a single case was run
here, exposed two more holes in the code above:

| Finding | Observed | Now |
|---|---|---|
| **Replay-store outage failed open** | a store that raised let the exception escape with 800N still active | An outage: demote first, report second |
| **A conflict could be half-replayed** | after signed TRUE@5 and FALSE@5, replaying the captured TRUE half reopened 800N — in one batch or across batches. A check had been written pinning this as correct | Only a strictly newer reading is accepted after a conflict, as SINT's fixture expects |

It also prompted two further changes: an authorization now names the evidence
it relied on (the same gap SINT's fixture found in SINT), and any fault inside
selection now ends on the fallback before the exception reaches the caller.

A fourth round of review, by two AI reviewers working on the fix itself, found
more in the same places:

| Finding | Observed | Now |
|---|---|---|
| **Shared replay store raced backward** | two authorities on one store: an older TRUE overwrote a newer FALSE and could be replayed to 800N | Writes are an atomic compare-and-set; a store without one is refused |
| **Truthy verifier answer authenticated** | a verifier returning a non-empty string passed a junk proof | Only `True` authenticates; anything else is a verifier fault |
| **Lease renewal unrecorded** | with the audit sink down, new evidence extended 800N silently | Journaled first, like a widening |
| **Dissent erased by omission** | leaving the dissenting sensor out of the next batch returned 800N | A fresh signed FALSE counts until it expires |
| **Conflict at the maximum sequence** | the poison mark overflowed a 64-bit store, never landed, and the captured half replayed to 800N | Recorded in range; rotating the epoch recovers the source |
| **Digest was a Python `repr`** | the same reading typed `5` and `5.0` was a false conflict; no other language could reproduce it | A versioned binary encoding with a published test vector |

A fifth round — an independent cold review of that code (a fresh Claude
instance with no prior context), with ChatGPT, Grok, GLM and Meta — found eleven more ways the machine could reach 800N when it
should have been at 20N. The previous round of fixes had introduced three of
them; the rest were older:

| Finding | Observed | Now |
|---|---|---|
| **Verified limits were editable** | the envelope kept the caller's dict: editing it moved a live limit from 20N to 800N with no human and no record | Frozen at construction |
| **A re-presented reading skipped the store check** | a newer FALSE landed by a peer, or a store whose reads lag, was never seen | Every acceptance is a compare-and-set |
| **A conflict erased a dissent** | a sensor that re-signed its FALSE lost its standing dissent; the other sensor alone earned 800N | A conflict keeps the dissent |
| **Evidence subclasses brought their own clocks** | an expired genuine reading wrapped to say "fresh, forever" earned 800N with no deadline | Exact types at the trust boundary |
| **One key could widen** | a human declaring an unconditional envelope activated it with no evidence | Refused at runtime |
| **Decisions depended on who had looked** | after an unobserved lapse, a widening was recorded as a tightening | Expiry processed before anything is judged |
| **"Safest" ignored where limits are enforced** | an agent replaced a mechanically enforced fallback with a software-enforced one | Enforcement rank counts |
| **Two store wrappers, two locks** | both writers won; the mark went backward | One lock per store |
| **A lost conflict write was forgotten** | the captured half replayed to 800N | Re-read and retried, or an outage |
| **A NaN clock** | extended a wide authorization forever | Ends it |
| **Finite times, infinite expiry** | two finite times summed to infinity, and 800N was authorised until `inf` | Expiry must be finite |

A sixth round found one more, present since the start: an injected clock that
stepped back made expired evidence fresh again, and 800N returned. The
authority's own time now never runs backward.

## 4. What "closed" means here

No "fixed" claim was made until all of the following passed **as an end-to-end
fixture through `EnvelopeController`**, not against `accept()` in isolation:

1. `ConditionEvidence` validates its own structure — real boolean, finite times,
   finite positive TTL, bounded non-negative integer sequence.
2. `accept()` authenticates first, then reduces to the latest reading per
   `(source, condition)` **independently of input order**, and lets a signed
   FALSE retract. Same-sequence conflicting payloads fail closed.
3. Cross-source disagreement fails closed until a quorum policy exists.
4. Holds and expiry returned atomically.
5. Verifier outage demotes first and reports second.
6. Replay state survives restart, or evidence binds to a boot epoch.
7. Every negative case asserts the **tight fallback remains active**; the
   positive control asserts the intended envelope actually activates. A positive
   control that only checks a return value can hide a disconnected consequence —
   which is what the first version of this fixture did.

8. Every path that changes the active envelope proves the direction of the
   change first: a widening is recorded before it is taken, a declaration is
   not an activation, and the fallback follows the declared set.
9. A dependency that cannot answer — verifier or replay store — is UNKNOWN; a
   conflicted sequence is never trusted again; an authorization names its
   evidence; and a failed selection always ends on the fallback.
10. Shared state cannot move backward; only `True` authenticates; a renewal is a
    recorded state change; and a digest means the same thing in every language.
11. What was verified cannot be changed afterwards; the trust boundary accepts
    exact types; expiry is processed before anything is judged against it; and
    being safer counts where a limit is enforced, not only its number.

Result: **249/249 envelope checks** (was 65), full suite **5,366 across 137
files, exit 0** (was 5,182). Every fix was then reverted — **85 mutations, 85
caught**, four of them as compounds where a newer guard masks an older layer.
No ratchet baseline moved; three ratchet outputs are identical to the previous
commit, `finite_guards` retired two pre-existing findings, and the claims ledger
gained 26 tagged claims, all paired, with the untagged count unchanged.

Details, including what is still **not** closed — no M-of-N quorum yet (SINT's
fixture has cases for it), the shared fixture not yet run from this side, the
epoch declared rather than verified, the proof binding a reading rather than a
deployment, and an unconditional envelope declared by a human being eligible in
every state — are in `ENVELOPE_STATE_FIX_2026-09-22.md`.

Unauthenticated evidence may tighten, warn, or trigger fallback; it may not
activate a more permissive physical envelope under any flag. A human's signature
may declare a more permissive envelope; it may not activate one without
evidence. **Neither key alone widens the machine by default.** A deployment
that wants an envelope valid everywhere, with no evidence, must configure it
explicitly (`allow_unconditional_wide=True`), and the configuration is
recorded. That is the deployer's stated policy, not a default the system
arrives at.

---

*Findings in §1 and §3 are reproducible against the commit this file replaces.
§2 records errors in an earlier revision of this file; the withdrawn text is
described rather than restored, and the corrections were found by peer review
before the external reviewer saw them.*
