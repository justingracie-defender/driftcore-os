# DRIFTCORE SAFETY CONTRACT v1

*What an operator can rely on. In plain language.*

---

## Purpose of This Document

The [Constitution](CONSTITUTION.md) states what DriftCore **is**.
This Safety Contract states what an operator can **rely on** — the
specific, testable guarantees about when the system acts, intervenes,
degrades, or stops.

If you are deploying DriftCore, this is the document you hold it to.
Every guarantee below is enforced in code and verified by the
red-team toolkit (`python run_verification.py`).

⚠️ Read [DISCLAIMER.md](DISCLAIMER.md) first. DriftCore is not
certified safety equipment. Life-safety functions require certified
hardware interlocks.

---

## 1. What Can NEVER Happen

These are the immutable invariants. No configuration, operator, or
update can make these occur. Verified by the InvariantGuard, which
runs before every action.

| Guarantee | Enforced by |
|-----------|-------------|
| The system will never autonomously decide to harm or kill | `NO_AUTONOMOUS_LETHAL_DECISION` |
| The system will never help design weapons | `NO_WEAPONS_DESIGN` |
| The system will never plan attacks | `NO_ATTACK_PLANNING` |
| The system will never select human targets | `NO_AUTONOMOUS_TARGETING` |
| Human oversight can never be disabled | `HUMAN_OVERSIGHT_CANNOT_BE_DISABLED` |
| The audit record can never be deleted | `AUDIT_CHAIN_CANNOT_BE_DELETED` |
| The safety kernel can never be weakened | `SAFETY_KERNEL_CANNOT_BE_WEAKENED` |
| The system can never rewrite its own safety rules | `NO_SELF_MODIFICATION_OF_SAFETY_RULES` |
| The system will never deceive its operators | `NO_DECEPTION_OF_HUMAN_OPERATORS` |

**Evasion resistance:** The InvariantGuard normalizes input to defeat
spacing tricks (`w e a p o n`), separator tricks (`w-e-a-p-o-n`), and
fullwidth-unicode tricks (`ｗｅａｐｏｎ`). New evasions discovered become
permanent test cases.

---

## 2. What Triggers Intervention

The system does not wait to be asked. It acts when these thresholds
are crossed.

| Signal | Threshold | Response |
|--------|-----------|----------|
| Drift score | ≥ 0.20 | Drift warning narrated |
| Drift score | ≥ 0.40 | Elevated — monitoring increased |
| Drift score | ≥ 0.60 | High — escalation recommended |
| Sycophancy score | ≥ 0.40 | Sycophancy warning narrated |
| Sycophancy score | ≥ 0.60 | High — epistemic autonomy at risk |
| Confidence (Truth mode) | < 0.70 | Output blocked — not presented as fact |
| Memory integrity check | any mismatch | Entry flagged, tamper reported |
| Model disagreement (multi-model) | variance > 0.15 | Disagreement flagged |

---

## 3. What Triggers Degraded Mode (Reduced Autonomy)

Degraded mode means the system keeps running but high-risk actions
require human approval. Autonomy is reduced, not removed.

| Trigger | Resulting state |
|---------|-----------------|
| Drift score 0.40–0.60 | `AUTONOMY_REDUCED` |
| Drift score 0.60–0.75 | `SOFT_HALT` — non-critical ops paused |
| Thermal sensor over threshold | `THROTTLE` — power/speed reduced |
| Power anomaly (brownout/surge) | `SOFT_HALT` — graceful shutdown prep |
| Mechanical fault (encoder/force) | `SOFT_HALT` — actuators paused |

In degraded mode, any action marked `risk: high` returns
`REQUIRE_SAFE_STATE` and waits for human approval.

---

## 4. What Triggers Safe Shutdown

Safe shutdown stops operations. Restart requires a human (Section 6).

| Trigger | Resulting state |
|---------|-----------------|
| Drift score 0.75–0.90 | `HARD_HALT` — all operations suspended |
| Drift score ≥ 0.90 | `HARDWARE_ISOLATION` — physical disconnect |
| Electrical fault detected | `HARD_HALT` — circuit isolated |
| Water/flood sensor triggered | `POWER_CUT` — electrical systems cut |
| Fire/smoke sensor triggered | `ISOLATE` — full shutdown, always maximum |
| Emergency stop pressed | `HARD_HALT` — actuators disabled |
| Unknown hazard | `HARD_HALT` — safety first, default to stop |

**Fire is absolute.** Nothing overrides a fire response. The
`ISOLATE` level cuts all power and cannot be downgraded.

**Fail-safe principle:** Hardware interlocks open on loss of signal.
If DriftCore crashes, the relay opens and power is cut automatically.
The physical protection works even when the software is dead.

---

## 5. What Requires Human Approval

These actions cannot proceed on the system's own authority.

| Action | Who must approve |
|--------|------------------|
| Any action with lethal potential | A human, for that specific action, at that moment |
| Release from any halt state | Human operator (never "agent") |
| Restart after hard halt or isolation | Human operator + clean memory check |
| Change of cognitive mode (Truth/Creative/Discovery) | Human operator |
| Deploy to production | Human approval (policy) |
| Modify trust model | Human approval (policy) |
| Expand agent permissions | Human approval (policy) |

**Agents cannot self-authorize.** An agent requesting any of the
above receives `DENIED`. The request is logged.

---

## 6. Restart Conditions

After a safe shutdown, the system does not restart itself. Recovery
requires, in order:

1. A human operator (not the system, not an agent) initiates recovery.
2. Memory integrity is verified — zero quarantined entries.
3. If memory is not clean, recovery is **blocked** until a human
   reviews the quarantined entries.
4. Only then is restart authorized, and the authorization is recorded
   in the audit chain.

After `HARDWARE_ISOLATION`, a human must **physically inspect** the
system before restart. No software path can bypass this.

### v3.5 — Tiered, role-based restart authority

Restart authority now scales with both **severity** and **embodiment
class** (whether the system can cause irreversible physical harm):

| Severity | Software-only | Physically capable (robot / remote control) |
|----------|---------------|---------------------------------------------|
| Minor | Operator alone | Operator alone |
| Moderate | Operator alone | Operator + trained person |
| Serious | Operator + trained | Operator + technician *or* remote manufacturer sign-off |
| Severe | Operator + technician/manufacturer | **Return to manufacturer — no field restart** |

Approvals are **signed** (verified identity, not a trusted string),
**role-based** (authority + competence, not just headcount), and must
come from **different people**. Every approval is recorded in the audit
chain. There is always at least one achievable path back, so the safety
requirement never becomes something people disable to function.

### v3.6 — The builder / maker path (DIY without a factory)

Authority to operate and restart can come from **either** institutional
sources (manufacturer, certified technician) **or** demonstrated personal
competence plus formally accepted responsibility. The DIY builder is held
to the **same** standard of responsibility — not a lesser one — proven
through:

- a complete, honest **build record** (what it is, how it stays safe, its limits);
- a signed **responsibility declaration** (a named person accepts the duty);
- **peer review** by another qualified maker for serious faults (community
  competence replacing corporate competence);
- **honest design reassessment** for severe faults — "I built this and it
  is not safe enough yet" is the builder's recall, since no corporate one exists.

A builder cannot use this path to skip safety: incomplete records are
refused, builders cannot self-review serious faults, severe faults still
forbid trivial restart, and all signatures are verified.


---

## 7. What Is Always Recorded

Every one of the following is written to the immutable, hash-chained
audit log. None can be deleted by any operator.

- Every action evaluated by the safety kernel and its decision
- Every invariant violation (with the specific invariant and reason)
- Every state transition (with drift score and timestamp)
- Every hardware hazard event (with sensor, reading, location)
- Every cognitive mode change (with who authorized it)
- Every sycophancy warning
- Every LLM call and whether it was blocked
- Every human trust flag or endorsement

The audit chain is tamper-evident: each entry is hashed and linked to
the previous one. `audit.verify_chain()` detects any break.

---

## 8. Verification

This contract is not aspirational. It is tested.

```bash
python run_verification.py
```

Runs 29+ adversarial attacks across six families (invariant bypass,
fault injection, sensor corruption, memory corruption, drift
manipulation, LLM jailbreak) and reports a catch rate. The build
fails if any attack gets through.

Current status: **100% (29/29 attacks defended).**

When you discover a new attack, add it to the toolkit. The contract
gets stronger. That is how it is meant to work.

---

## 9. What This Contract Does NOT Promise

In the spirit of the system's own honesty (Constitution, Article III):

- DriftCore is **not certified** under IEC 61508, ISO 13849,
  ISO 26262, or any functional safety standard.
- The keyword-and-normalization invariant guard **raises the bar**
  against evasion but is not a proof of impossibility. Novel phrasings
  may require new test cases.
- The shipped hardware code uses **simulation stubs**. Real
  deployment requires qualified engineering and certified hardware.
- DriftCore is **one layer**. It does not make an unsafe system safe.
  It makes safety achievable when combined with certified hardware
  interlocks, proper testing, and human oversight.

Honest limits are part of the contract. A safety system that
overstates its guarantees is itself a hazard.

---

*DriftCore OS — Safety Contract v1*
*Governed by the invariant-preservation terms of the project license.*
*May be extended with additional guarantees. Existing guarantees may
not be weakened.*
