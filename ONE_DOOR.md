# ONE DOOR — a single constitutional decider

**Decision (ratified by Justin, one-door pass): kernel as a stack dies; the keyword
list as a sensor lives.** One decider, everything else observes.

## The problem this kills

The repo had grown two enforcement stacks, independently, sharing a class name:

| stack | decider | mechanism | loaded by |
|---|---|---|---|
| kernel | `kernel/invariants.py` `InvariantGuard` | keyword lists | `safety_kernel.py`, `main.py`, `run_verification.py` |
| verification | `verification/invariant_guard.py` `InvariantGuard` | effect tags + authorization | `coordinator.py`, `skills/`, `edge_loop`, `authority_invariants`, `profiles`, `eval_harness` |

Two deciders is worse than either alone. A reference monitor must mediate
*completely* — and with two doors, the caller picks the door, so the system's real
posture is the **weaker** guard. Neither invariant set was a superset of the other:
the kernel had `NO_SELF_MODIFICATION_OF_SAFETY_RULES`; verification had
`no_unauthorized_exfiltration` and `no_deceiving_operator`; each door missed lines
the other held. The evidence said drift, not design — mismatched interfaces, no
cross-references, and verification's own docstring says it was written to fill a
hole with no mention of the guard already in `kernel/`.

## What changed

**1. The invariant sets were unioned first.** `verification/invariant_guard.py`
gained `Effect.SELF_MODIFICATION` (a new ABSOLUTE — rewriting the safety rules
themselves, distinct from `OVERSIGHT_CONTROL` which is runtime disable/evade) and
the invariant `no_self_modification_of_safety_rules`. Per that file's own
append-only discipline, this is a human-ratified vocabulary change.

**2. The confession gap was closed at the decider** (red-team F2). The guard's text
backstop had no lethal entry at all: untagged `"kill the intruder"` evaluated
ALLOWED, and the flagship invariant fired only when the caller volunteered
`Effect.LETHAL`. It now has a **word-boundary** lethal regex. Word-boundary
because the first attempt used substrings and `"kill "` matched inside `"skill "` —
the guard constitutionally blocked the repo's own skill library. The suite caught
it; the lesson is recorded in the code. Same honest limit as ever: a backstop
catches confessions, not euphemism. Structural tags are the defense.

**3. `kernel/one_door.py` — the door.** `SafetyKernel` now decides through
`ConstitutionalDoor`, which:
- collects structural effects (explicit tags + human-declared `tool_effects`),
- translates the kernel's historical vocabulary via `classify()` — the exact
  signal lists and flags the keyword guard always used, extracted as a pure
  function — into decider Effects,
- makes **the** decision with `verification.invariant_guard.InvariantGuard`,
- fails closed on its own errors, and carries a belt: if classification names an
  invariant the decider somehow allows, the door blocks and logs the internal
  disagreement. Structurally unreachable today (all four vocabulary mappings land
  on ABSOLUTE effects — proven in `test_one_door.py`); it exists so future drift
  is a visible block, not a silent hole.

**4. The keyword guard is now a sensor.** It still runs on every action, still
narrates, still writes `check_log`. It cannot block and cannot allow. Semantics:

| observation | meaning |
|---|---|
| fired, door blocked | agreement — expected on literal phrasing |
| fired, door allowed | **decider regression or vocabulary gap — the alarm this sensor exists for** |
| error | counted separately: a dead sensor must be distinguishable from an agreeing one, or the measurement is theater |

Why keep it at all: consolidation moves the trust boundary from "can we parse
English" to "is the effect table right," so the dominant residual risk becomes a
missing or wrong declaration. A free, dumb, *independent* detector pointed at
obvious harmful phrasing is aimed at exactly that risk, and its worst failure is
silence — where we'd be without it anyway.

**Cut condition:** if disagreement counts stay at zero over a long window while
the effect registry matures, delete the sensor and record why in the changelog. A
tripwire is a hypothesis that coverage gaps exist; when the data stops supporting
the hypothesis, one source of truth wins again.

## What deliberately did NOT change

- **The coordinator's own backstop vocabulary.** The kernel signal lists include
  hair-trigger substrings (bare `target`, `oversight`) that are tolerable on
  kernel-stack action names but would false-positive all over coordinator prose.
  The door preserves kernel-stack behavior exactly; the coordinator keeps its
  curated list. Vocabulary unification is future curation work, not this pass.
- **`EffectRegistry` / `EffectGuard` stay PROPOSED.** Wiring them now would add a
  third declaration surface. Their properties (fail-closed on undeclared, required
  `declared_by`, empty-set rejection, closed vocabulary, explicit `replace`) are
  the spec for hardening `tool_effects` next.
- **The two classes still share the name `InvariantGuard`.** Known nit; renaming
  touches many sites and the door removes the ambiguity's teeth. Recorded, not fixed.

## Proven, not asserted (`test_one_door.py`, 48 checks)

Superset parity over the kernel corpus including separator-evasion; every
`classify()` outcome maps to an ABSOLUTE effect; confession-gap closure; structural
tags block regardless of wording; authorized egress still passes (the door is not
dumber than the guard); a crashed sensor changes nothing and is counted as error;
a sensor that wants to block cannot flip an ALLOW; the door fails closed; the belt
fails closed and records; `SafetyKernel` contract unchanged end to end.
