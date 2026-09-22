# SINT review — verification and draft reply — 22 September 2026

Illia Pashkov (SINT Labs) reviewed `physical_envelope.py` and raised two specific
gaps. Both checked against `driftcore_artifact_channel_2026-09-21.zip`
(SHA-256 `4497bd86…196f9a1`). **One is confirmed and is worse than he stated. The
other is narrower than he stated, but its residue is real.**

---

## 1. "Enforcement and condition attestation remain claims" — CONFIRMED

`ConditionAuthority.__init__` defaults to `verify_proof=None`. With no verifier
injected, `_accept_locked` checks only that the proof string is non-empty:

```python
if self._require_proof:
    if not ev.proof:
        continue
    if self._verify_proof is not None and not self._verify_proof(ev):
        continue
```

Runnable demonstration, production default, nothing stubbed:

```
DEFAULT CONFIG — verify_proof=None

  proof='x'                  -> accept() = {'fence_closed': True}
  proof='not-a-signature'    -> accept() = {'fence_closed': True}
  proof='\x00'               -> accept() = {'fence_closed': True}
  proof='' (empty)           -> accept() = {}
```

A single character — including one null byte — is accepted as cryptographic proof
that the fence is closed. `fence_closed` is exactly the operating condition that
authorises the **wider** envelope. In §0b's own worked example that is the
difference between 60N and 800N.

So the accurate statement is stronger than "remains a claim unless a verifier is
injected": **the default configuration authorises the widest envelope on a
one-character assertion, and only the empty string is refused.**

### And the test suite cannot see it

`test_physical_envelope.py` line 27:

```python
def EV(cond, source="sensor-hub", seq=1, ttl=60.0, proof="sig", value=True, ...)
```

The fixture's default proof is the literal string `"sig"`. Line 272 is the only
proof-related case and it tests `proof=""` — the empty one. **The junk case is never
tested, because with `verify_proof=None` nothing exists that could reject it.**

All 65 checks in that file pass in the configuration that cannot fail. The repo
already has a name for this, written in `human_identity.py` a few modules away:

> *"The earlier sweep that cleared action-binding always passed `action=`, which
> proved the binding works and never tested the case where a caller forgets — the
> property was checked in the configuration that could not fail."*

Same pattern, different module, found from outside by someone who had never read
that comment. That is §0h — *a passing check is a claim about the check* — and it is
the most valuable thing in Illia's email.

**Fix:** default `verify_proof` to a real verifier, or make `ConditionAuthority`
refuse to construct without one (the `EgressPolicy` rule — unconfigured is not
permissive). Then add the junk-proof negative control that currently cannot exist.

---

## 2. "String-based human identity" — narrower than stated, but not clean

The blunt version of this is no longer true. `is_human()` behaves as follows:

| Situation | Result |
|---|---|
| Nothing configured | **`False`** — *"'we could not check' reading as 'we checked'"* |
| A verifier is set | a bare string is **never** human |
| `attestation_required=True` | only a verified `HumanAttestation` passes |
| `action` omitted at the call site | **`False`** — the token cannot supply its own action |
| LABEL_ONLY denylist | reachable **only** through an explicit `declare_label_only()`, guarded by `CLAIM label-only-must-be-declared` |

So the denylist is not the default and cannot be reached by accident, and
`mode()` / `status()` report `secure: False` when it is active.

**But the residue of his point is real, and worth conceding.**
`require_secure_identity()` exists — and `grep` finds **no call to it in any
deployment startup path**. Only tests reference the mode functions. So the
protection is available and unwired: a deployer who never calls it gets no
enforcement of the thing the module itself says to assert at startup. That is the
same shape as finding 1 — a correct mechanism whose activation is optional.

---

## 3. The collaboration seam is genuinely clean

Illia's framing — *"DriftCore/LifeCore supplies deployment evidence and SINT binds it
to execution authority"* — is §0b of the harness restated by someone who arrived at
it independently:

> DriftCore says an envelope must EXIST, be INDEPENDENTLY ENFORCED, and not be
> SELF-WIDENABLE. LifeCore says for this body, that envelope is 60N. Hardware makes
> it physically true.

SINT adds: and the capability token binds it to execution authority. Four layers, no
overlap. His own caveat — *"the token still should not be treated as proof that
firmware or a safety PLC independently enforces those limits"* — is the
interlock-vs-backstop distinction, volunteered about his own system. Worth saying
back to him that it's the same line DriftCore draws, because that agreement is the
foundation the profile rests on.

---

## 4. Draft reply

> Illia — thank you, and the first gap is real. I reproduced it: with the default
> `verify_proof=None`, `ConditionAuthority.accept()` returns `{'fence_closed': True}`
> for `proof='x'`, for `'not-a-signature'`, and for a single null byte. Only the empty
> string is refused. Since `fence_closed` is the condition that authorises the wider
> envelope, the default configuration widens the envelope on a one-character
> assertion.
>
> Worse, my own test suite couldn't have caught it. The fixture's default is
> `proof="sig"` and the only proof case tested is the empty one — so all 65 checks in
> that file pass in the configuration that cannot fail. That's a pattern I'd already
> written up in a neighbouring module and still shipped here. Thank you for finding
> it from the outside.
>
> On string-based human identity I'd offer a partial correction, and I'd rather be
> corrected back if I'm wrong. An unconfigured process returns `False` rather than
> falling through to the denylist; with a verifier set a bare string is never human;
> omitting `action=` at a call site fails closed; and the legacy denylist is reachable
> only through an explicit `declare_label_only()`. But your point survives in a
> narrower form that I'll fix: `require_secure_identity()` exists and **nothing calls
> it at startup**, so the protection is opt-in rather than enforced. That's the same
> shape as the proof gap — a correct mechanism whose activation is optional.
>
> Your framing of the seam matches how the project already splits this: DriftCore
> holds no physical values at all. It asks three questions — is an envelope declared,
> is it enforced below the AI, can it be self-widened — and the numbers belong to the
> deployment. SINT binding that to execution authority sits directly on top of it. And
> I'd echo your own caveat back: a signed token is evidence of authorisation, not
> evidence that firmware enforced anything. Keeping those separate is the same
> interlock-versus-backstop line I try to hold.
>
> On the v0.1 milestone — six deliverables is more than I can do well in one pass, so
> here's a smaller first experiment, and it's the one we just found. **One shared
> adversarial fixture: junk-proof rejection.** Both implementations must refuse
> `proof='x'` for a condition that gates a wider envelope, must accept a genuinely
> signed proof for the same condition, and must record the refusal reason. The
> positive control is load-bearing — a system that refuses everything has to fail this
> fixture, not pass it.
>
> That's small enough to finish, it tests the exact seam between our two layers, and
> one side of it already fails today. If it works I'd take the rest of the profile in
> that order: one fixture at a time, each with its positive control.
>
> — Justin

---

## 5. Before sending

- **Fix the proof default first, or say plainly that it's open.** He may re-run it.
  Either is fine; discovering it yourself after claiming a fix is not.
- **Don't quote a test count.** GitHub `main` is currently at 2,667/83 while the
  archives are at 5,182/137. Anything you cite, he can check.
- **`marshmallow/` isn't on GitHub at all.** If the reply points at the repo, the eval
  harness isn't there to find.
- Read `docs/community/driftcore-sint-collaboration-roadmap.md` on PR #256 before
  replying — 335 lines, and this assessment is based on his email plus the screenshots,
  not that document.

---

*Findings reproduced against `4497bd86…196f9a1`. The junk-proof demonstration uses
`time.monotonic()`, which is the authority's own clock — my first attempt used wall
time and silently returned empty, which would have read as "not reproducible."*
