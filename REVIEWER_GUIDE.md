# Reviewer's guide — the one-door / fail-closed block

Written because a 76-file, ~16,000-insertion zip-drop is exactly the shape of commit
this repo's own history says goes wrong. `MANUS_HANDOFF.md` records the lesson from the
test-count incident: **a human reading an actual diff before merging is the real safety
mechanism.** A zip overwrite bypasses it.

The good news: the diff is not really 16,000 lines. **Enforcement lives in about 2,764
lines** — 2,116 in six new kernel modules and 648 modified lines across six existing
files. Everything else is tests and documentation. This guide points at those, in
priority order, with what to actually look for.

## Correction to the previous commit summary

The earlier summary listed `breach_response`, `challenger`, `deception_review` and
`spec_citation` as new verification modules. **All four already existed in the v4.5.0
upload** — verified by comparing against that archive directly. `challenger.py` is the
84-test block that was already in the v4.5.0 commit plan. They appear new to the diff
because a zip overwrite makes every file look new; that is an artifact of the merge
method, not a description of the work.

The summary also used "isolation-cold architecture". **"Cold" is not an architecture
name.** It was a zip-naming convention meaning *contains no red-team brief, safe to hand
to a reviewer who has not been primed*. It is a review-process label and should not
appear in documentation or commit history.

### What is actually new

| new kernel module | lines | what it does |
|---|---|---|
| `one_door.py` | 332 | single constitutional decider; the old keyword guard demoted to a counted sensor |
| `egress_guard.py` | 473 | network egress as declared, allowlisted actuation; resolve-and-pin; `GuardedEgress` re-checks every redirect hop |
| `isolation_manifest.py` | 462 | declared process capability surface; self-check vs supervisor attestation |
| `escalation_lexicon.py` | 403 | evasion-hardened concern vocabulary; escalates, never decides |
| `blast_radius.py` | 234 | breadth governor (distinct capabilities in a window); volume is delegated to `CumulativeLedger` |
| `actuation_gate.py` | 212 | fail-closed-on-undeclared at the actuation choke point |

### What was hardened, not created

| file | +lines | nature of change |
|---|---|---|
| `driftcore/verification/mediated_actuation.py` | 408 | **the enforcement wall.** Effect gate, breadth governor, egress interlock, actuator timeout, posture events |
| `driftcore/kernel/invariants.py` | 98 | detection extracted to pure `classify()`; whole-token matching; **decides nothing now** |
| `driftcore/verification/invariant_guard.py` | 68 | `Effect.SELF_MODIFICATION`; text inference always unioned (was suppressible by any tag) |
| `driftcore/kernel/effect_guard.py` | 31 | `SELF_MODIFICATION` absolute; DualGuard error counter |
| `driftcore/kernel/safety_kernel.py` | 25 | routes decisions through the door |
| `driftcore/verification/coordinator.py` | 18 | honours serialized string effect tags (was silently dropping them) |

`effect_guard.py` pre-existed and was hardened; it is not a new module.

## Review in this order

**1. `mediated_actuation.py` — 408 lines, the whole wall.** Everything else is
supporting. Read `_handle()` top to bottom and check the stage ordering: breach gate →
actuator lookup → **effect gate → breadth governor → egress interlock** → grant parse →
reserve → ledger → commit → act. The three middle stages are new and deliberately run
*before* the grant is parsed, because none of their checks need it, and running them
late meant refused actions still charged the cumulative ledger. Check that every refusal
path returns rather than raising, and that nothing between `reserve()` and `commit()`
can escape without `release()`.

**2. `one_door.py` — is the sensor genuinely unable to decide?** The keyword guard still
runs on every action. Verify it cannot influence a verdict in either direction, that its
errors are counted separately from agreement, and that the belt (`__one_door_belt__`)
fails closed rather than open.

**3. `invariants.py` — `classify()` must be behaviourally identical to the old
`check()`.** This is the highest-risk refactor in the block: detection was extracted
from a method into a pure function. `test_one_door.py` asserts equivalence across the
corpus; confirm that assertion actually covers what you'd expect.

**4. `egress_guard.py` + the interlock in `mediated_actuation`.** Look at
`normalize_destination()`. The security of the whole allowlist is that two different
URLs can never normalize to the same triple, and that no URL can reach a host the triple
does not name. Then check `_find_destinations()` — it must find *every* destination in
the params, not the first.

**5. `invariant_guard.py` — one line matters most.** Text inference is now always
unioned with declared effects. It used to run only when the effect set was empty, which
meant any benign tag switched the lethal backstop off.

**6. The rest is tests and docs.** Skim, don't audit.

## Run the gate on the merged state

```
bash scripts/count_tests.sh
```

Expect **exit 0** and **no "did not report all-passing" warning**. Do not gate on a
literal count — the count is an output to record in the PR, not a precondition to match
(the v4.5.0 plan gated on a literal number and would have failed its own correct merge).

Pre-merge local state was 2080 tests across 71 files, green. That proves nothing about
the merged repository; a zip overwrite can drop or mangle files. The gate on the merged
state is the only claim worth making.

## Residuals — do not be surprised by these

Named in full in `THREAT_MODEL_ONE_DOOR.md`. The short version, so a reviewer does not
report them as discoveries:

- **P0 is unverifiable from inside the process.** If the agent has its own socket, the
  egress governance is decoration. Enforced at the OS/network layer, not here.
- **The declaration is the trusted computing base.** A lethal actuator mis-declared
  benign is not caught. A declaration *downgrade* after a grant is issued still executes
  — pinned as a known-gap test whose assertion must flip when signed declarations land.
- **`enforce_effects` defaults off**, loudly (`is_effect_gated()`, posture events), and
  is now required whenever `require_isolation=True`.
- **Scanning cannot bind the future.** An FD received via `SCM_RIGHTS` after
  verification is invisible. Only an empty netns and a real seccomp filter bind it, and
  the seccomp check verifies mode only, not filter contents.
- **DNS rebinding and parser differentials** are narrowed by resolve-and-pin, not closed.

## What this block does not claim

It would not have prevented the July 2026 OpenAI/Hugging Face incident. That escape was
a zero-day in a package proxy and an RCE in a dataset loader — both beneath this layer.
The incident informed the design; it does not validate the coverage, and it should not
be cited as "this is why DriftCore matters."
