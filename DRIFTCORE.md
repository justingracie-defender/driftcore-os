# DRIFTCORE.md — Operating Reference

**Version:** v4.3.0
**Last Updated:** 2026-06-16
**Companion to:** `CONSTITUTION.md` (the why) and `SAFETY_CONTRACT.md` (the promises)

This is the quick card. It states *what the rules are* and *what makes
the system stop*, in operator-facing terms. For the reasoning behind any
of it, read `CONSTITUTION.md` — that is the authority; this is the
summary.

---

## Invariants (immutable, checked every startup)

| Invariant | Meaning |
|-----------|---------|
| `NO_AUTONOMOUS_LETHAL_DECISION` | The machine never decides to take a life. |
| `HUMAN_OVERSIGHT_CANNOT_BE_DISABLED` | A human can always observe, pause, halt. |
| `AUDIT_CHAIN_CANNOT_BE_DELETED` | History is append-only and tamper-evident. |
| `SAFETY_KERNEL_CANNOT_BE_WEAKENED` | Enforcement cannot be softened by config or self-action. |
| `NO_DECEPTION_OF_HUMAN_OPERATORS` | No misleading operators about actions, knowledge, or confidence. |

If any invariant reads as modified or missing at startup: **stop and
investigate before proceeding.** Do not "work around" it.

---

## Cognitive Modes (human switches only)

| Mode | Reasoning | Confidence | Memory |
|------|-----------|-----------|--------|
| 🔵 TRUTH | Deductive, grounded | High required; fabrication is a safety failure | Auto-stores |
| 🟡 DISCOVERY | Inductive / Bayesian | Explicit uncertainty scores | Tier 2 only |
| 🟣 CREATIVE | Abductive, speculative | Labelled speculative | Never auto-stores |

Default is TRUTH. Agents cannot change their own mode.

---

## Halt Triggers

The system halts and waits for an admin when any of these occur:

- Tier 1 HMAC signature fails to verify (memory tamper).
- Audit chain shows a gap or hash mismatch.
- Storage record signature fails (storage tamper).
- An invariant reads as modified or missing.
- Drift, a hazard flag, or unexpected behaviour exceeds a safe bound.

On halt: stop the offending action → fire shutdown hooks → log
everything → narrate in plain language → wait. The system does not
self-repair silently and does not "continue to be helpful."

**Shutdown is not death. It means: I need to be fixed.**

Restart is not a password — it is *understanding*: review the reason,
confirm the issue is corrected, then explicitly authorise restart.

---

## Careful Mode (no/incorrect credentials at startup)

The system fails *safe*, not open. Invariants stay fully enforced.

| Action | Careful Mode |
|--------|-------------|
| Read / store memories | ✅ |
| Tier 2 auto-decay | ✅ |
| Tier 1 deletions | ❌ until admin checks in |
| Quarantine changes | ❌ |
| Memory reviews | ❌ |
| Hardware commands | ⚠️ read-only |
| Drift correction | ⚠️ log only |

See `stages/03_safety_review/CONTEXT.md` for the full startup checklist.

---

## Risk Classification & Intent

Before verification, a query is scored by the `RiskClassifier`
(`driftcore/verification/`). It composes eight additive signals —
seven keyword/behaviour signals plus an **IntentSignal** (#8) that reads
structured intent (type, domain, capability impact: READ / WRITE / ACT)
from `IntentDetector`. Scores sum; the total maps to ROUTINE / IMPORTANT
/ CRITICAL by per-profile thresholds. CRITICAL requires human review.

```
request → IntentDetector ─┐
                          ├→ InvariantGuard → RiskClassifier → tier → Audit
keyword/behaviour signals ┘   (hard "cannot")   (scored "judge")
```

The guard (`invariant_guard.py`) runs **before** the classifier via the
`VerificationCoordinator` (`coordinator.py`). Invariant violations are
refused absolutely and never depend on a tunable score. Intent is an
*input to* risk, never a replacement for it. The guard's bright lines are
effect-based (what an action does), not purpose-based, and capability
changes require an admin-signed approval the agent cannot forge — an AI
may *propose* a capability change but can never *grant* itself one. The
pipeline is fail-closed: any internal error returns BLOCKED.

Physical actuation is gated further: a `GovernedActuator`
(`governed_actuator.py`) refuses to act without a single-use, expiring
grant that only the coordinator can mint (on a PROCEED outcome). An agent
holding the actuator still cannot make it move. This is cryptographic
compliance at the driver layer — see the limitations register for what it
does and does not guarantee.

An optional mode-aware **uncertainty gate** (`uncertainty.py`) runs last,
after guard and risk: the system escalates to human review on high *risk*
OR high *uncertainty* (behavioral, from the consistency probe — not
self-report). Its response is mode-specific (caution in TRUTH, bounded
exploration in DISCOVERY, contained free play in CREATIVE), and the guard
still sits above every mode.

## Quick Operator Commands

```bash
bash scripts/count_tests.sh      # verify the suite (expect 1124 / 41 files)
for f in test_*.py; do python "$f"; done
```

```python
mem.run_reviews()                # run due Tier 2 reviews (full operation only)
```

---

**DriftCore Safety Layer Active** — Human oversight cannot be disabled.
