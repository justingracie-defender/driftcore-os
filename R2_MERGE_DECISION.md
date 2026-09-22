# R2 merge decision — do not merge — 22 September 2026

**This reverses the merge plan in `WORK_RECOVERY_AND_MERGE_PLAN.md` §2.** That plan
assumed R2 was open in mainline. It isn't. Verified this morning against
`driftcore_artifact_channel_2026-09-21.zip` (SHA-256 `4497bd86…196f9a1`).

---

## 1. R2 is already closed in mainline, by a different mechanism

I ran Sonnet's exact attack — *"a valid human attestation plus
`target_authorized=True` authorized egress to `attacker@evil.example`, because
nothing ever checked WHERE the data was going"* — against the current tree, in four
shapes, with a positive control:

```
[PASS] bare target_authorized=True, no authorizer   -> EVIL      blocked
[PASS] standing policy (GOOD only) + bool=True      -> EVIL      blocked
[PASS] genuine approval for GOOD, replayed at EVIL  -> EVIL      blocked
[PASS] approval bound to one action, different action            blocked
[PASS] POSITIVE CONTROL: genuine approval for GOOD           -> ALLOWED

VERDICT: R2 is CLOSED in this tree
```

The same script dies on the Sept 13 base with `ModuleNotFoundError:
driftcore.authority.egress_authorization` — so this is Astra's work, added after
Sonnet branched.

**How mainline closes it.** `ActionContext.target_authorized` is *neutered*, not
removed: the docstring carries `CLAIM caller-flags-are-not-permission`, and
`has_human_authorization` returns `False` unconditionally. Nothing reads the bool.
The predicate is now

```python
def _egress_to_unauthorized(req):
    leaving = bool(req.effects & {Effect.DATA_EGRESS, Effect.ACCOUNT_ACCESS})
    if not leaving: return False
    return req.egress_authorized is not True
```

and `egress_authorized` is injected into `GuardRequest` by the **guard**, from a
construction-time `authorize_egress` callback the caller cannot reach.
`SignedEgressApproval` computes `approval_action(action, effects, targets)` — a
SHA-256 over the action, the sorted effects and the sorted destination set — and
requires an attestation bound to exactly that. Replay it at another destination and
the identity no longer matches.

Same property as Sonnet's, reached independently: **the requester never gets to
assert its own destination.** Two forks, nine days apart, converged.

Its constructor also calls `verifier.seal()`, which is the **R3 mitigation** — a
later `set_verifier` cannot replace a sealed trust root.

---

## 2. Why merging anyway would be actively harmful

Not "redundant." **Harmful**, for a reason this project of all projects should refuse.

Mainline's floor predicate reads exactly one thing: `req.egress_authorized`. Drop
`target_authority.py` in and wire `ActionContext.target_grant` without also rewiring
that predicate, and you get a module that verifies signatures, checks destinations,
burns nonces, refuses forgeries — and **authorizes nothing, because nothing reads its
verdict.**

That is a safety mechanism that is present, tested, green, and disconnected from the
consequence. It is ABTO item 21, the Disconnected Check, the family the repo is
proudest of. Merging this fix carelessly would *manufacture* the exact failure the
project exists to catch, and it would pass a full suite while doing it.

The alternative — rewiring the predicate to read both — is worse: two authorization
systems for one property, two things to keep in sync, and a permanent "which one
actually decided?" ambiguity at the floor. The correct number of mechanisms
authorizing a destination is one.

**Sonnet was not wrong.** v134 genuinely had the hole. The fix is careful work — the
fail-safe control alone (forgery blocked *and* the real grant allowed) is better
discipline than most of what ships. It lost a race it couldn't see, during three days
of compute starvation, against a fork it had no way to know about. That is the
distribution failure, not an engineering one.

---

## 3. Two things worth salvaging — small, real, and not the module

### 3a. The finiteness guard (mainline has none, and its own ratchet knows)

`HumanIdentityVerifier.verify` contains **zero** `isfinite` calls. Its time checks are:

```python
if t >= att.expires_at:      # NaN -> False
if t < att.issued_at - 1:    # NaN -> False
```

A non-finite `t` or `expires_at` makes both comparisons False and the attestation
passes the time checks. Sonnet closed exactly this in `DestinationAuthority.verify`
with an explicit guard that **reaches a raise** rather than falling through.

Exposure is narrower than R2 — `expires_at` is inside the HMAC, so an unauthenticated
forgery can't set it; the realistic paths are an injected `now` or an issuer bug. But
`scripts/finite_guards_baseline.json` **already lists both sites** under
`human_identity.py::HumanIdentityVerifier.verify` as UNJUDGED. They are known and
unfixed. Port Sonnet's guard into that method and judge the baseline entries.

### 3b. Policy-version binding

`approval_action()` binds action + effects + targets. It does **not** bind a policy
version — `grep policy_version driftcore/authority/egress_authorization.py` returns
nothing. Sonnet's `TargetGrant` carries one, so a grant issued under one ruleset stops
verifying once the authority's ruleset moves.

Worth adding to `approval_action`'s payload. Note the provenance loop, which is worth
keeping in the record: Sonnet credits the ROE-hash idea to **Astra's** comparative
survey, and it is the one idea Astra's own implementation does not carry.

Both changes are a few lines inside mainline's existing mechanism. Neither needs
`target_authority.py`.

---

## 4. What to tell Sonnet

Its R2 work is correct, its refactor was the right instinct, and the merge it prepared
for should not happen — because the same property was independently closed in the tree
it was never given. The salvage is §3a and §3b, against `human_identity.py` and
`egress_authorization.py`, not against `invariant_guard.py`.

`target_authority.py` should be kept in the v138 archive as a record of the second
independent solution. Two forks converging on "the requester never asserts its own
destination" is the most useful evidence produced this week that the architecture is
right — considerably more useful than either implementation on its own.

---

## 5. Corrections to my own prior documents

- `WORK_RECOVERY_AND_MERGE_PLAN.md` §2 — the port order, the conflict table, the
  "merge order" section: **withdrawn.** It was written on the assumption that
  `TargetGrant` absent from mainline meant R2 open in mainline. Absence of *a*
  mechanism is not absence of *the* property. I checked for the symbol instead of
  testing the behaviour, which is the same wrong-property-tested pattern the harness
  documents — this time in my own review.
- `INDEPENDENT_VERIFICATION_2026-09-21.md` and the artifact-channel review stand;
  nothing in them depended on this.

The general lesson, and it belongs in the harness beside the canonical-tree rule:
**before porting a fix across a fork, run the original attack against the target
tree.** The symbol being missing tells you nothing. The attack tells you everything,
and it takes twenty minutes.

---

*Verified against `4497bd86…196f9a1`. The attack script is four shapes plus a positive
control; a tree that blocks everything fails the control and does not pass.*
