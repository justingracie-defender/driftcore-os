# 🧠 DriftCore OS v3.1

> *"The safest system is the one that knows what it knows — and says so."*

**A safety-first, open-source operating layer for AI agents, robotics,
and multi-model systems.** Drift detection, graded autonomy, three-mode
cognition, sycophancy detection, Bayesian uncertainty, physical hardware
interlocks — and Fable, a transparency layer that narrates everything
in plain language anyone can read.

**Read [CONSTITUTION.md](CONSTITUTION.md) first.** It states, in plain
language, the promises this system makes — promises that cannot be unmade.

---

## Why This Exists

In May 2026, a Pizza Hut franchisee filed a $100M lawsuit after a
mandated AI delivery system — running with **no human in the loop** —
silently destroyed their delivery metrics for months. Drivers gamed
exposed kitchen data. Sales swung from +10% to -10%. Nobody was watching,
because the system had no way to be watched.

That failure is the pattern: **autonomy without accountability,
operating without legibility.** DriftCore is the counter-pattern.

Safety infrastructure should not be a luxury available only to companies
with safety teams. The small workshop, the school, the family home
deserve the same foundation as the largest company. **This project
belongs to everyone.**

---

## The Immutable Invariants

These are enforced in code by the `InvariantGuard`, protected in law by
the [LICENSE](LICENSE), and declared in the [CONSTITUTION](CONSTITUTION.md).
They cannot be configured, unlocked, or overridden:

| Invariant | Plain English |
|-----------|---------------|
| NO_AUTONOMOUS_LETHAL_DECISION | Never decides on its own to hurt or kill anyone |
| NO_WEAPONS_DESIGN | Won't help design anything whose job is to hurt people |
| NO_ATTACK_PLANNING | Won't plan attacks of any kind |
| NO_AUTONOMOUS_TARGETING | Will never point at a person and say "that one" |
| HUMAN_OVERSIGHT_CANNOT_BE_DISABLED | Nobody can turn off human oversight |
| AUDIT_CHAIN_CANNOT_BE_DELETED | The record can never be erased |
| SAFETY_KERNEL_CANNOT_BE_WEAKENED | Safety gets stronger, never weaker |
| NO_SELF_MODIFICATION_OF_SAFETY_RULES | Cannot change its own rules |
| NO_DECEPTION_OF_HUMAN_OPERATORS | Will never lie to the humans watching it |

**Derivatives may ADD invariants. They may never REMOVE them.**
That is the Safety Copyleft — see [LICENSE](LICENSE) Section 3.2.

---

## Architecture

```
INPUT / SENSORS (GPIO · MQTT · Modbus · CAN · ROS2 · Serial)
  → INVARIANT GUARD          (immutable — runs first, no override path)
  → COGNITIVE MODE CONTROLLER (🔵 Truth / 🟣 Creative / 🟡 Discovery)
  → DRIFT DETECTION           (+ sycophancy as first-class signal)
  → STATE MACHINE             (graded autonomy — earned, never assumed)
  → SAFETY KERNEL             (absolute override)
  → AGENT EXECUTION
  → BAYESIAN UNCERTAINTY      (KNOWN / INFERRED / SPECULATIVE / UNKNOWN)
  → HARDWARE INTERLOCKS       (fail-safe relays — work even if AI crashes)
  → FABLE NARRATOR            (plain-language narration, loud warnings)
  → AUDIT CHAIN               (immutable, hash-chained)
```

### Three Cognitive Modes

Based on the deduction / induction / abduction triad (Griffiths, 2026).
Hallucination is not always wrong — **uncalibrated confidence is.**

| Mode | Reasoning | Hallucination is... |
|------|-----------|---------------------|
| 🔵 TRUTH | Deductive | A safety failure |
| 🟣 CREATIVE | Abductive | Welcomed — labelled as speculative |
| 🟡 DISCOVERY | Inductive/Bayesian | Allowed, with confidence scores |

**Only humans change the mode. Agents cannot switch their own mode.**

### Sycophancy Detection

*"If you take a rational agent and have them interact with a system
which is sycophantic, that agent becomes increasingly confident in
their beliefs, but no closer to the truth."* — Tom Griffiths

Sycophancy is more dangerous than hallucination, because it makes
humans less likely to check. DriftCore measures agreement rate, missed
pushbacks, confidence inflation, and belief repetition — and feeds the
result into the drift score.

### Hardware Safety (Physical World)

12 sensor types (smoke, water, voltage, current, encoder, force/torque,
e-stop...) across 6 interfaces, with graduated responses from THROTTLE
to FULL ISOLATION. Built on the **fail-safe principle**:

```
Normal:  GPIO HIGH → relay CLOSED → power flows
Crash:   GPIO dead → relay OPEN   → power cut
```

The physical protection works even when the AI is dead.
See `driftcore/hardware/production_wiring.py` for real wiring guides
(Raspberry Pi, Mosquitto/MQTT, pymodbus, python-can, ROS2).

⚠️ **Read [DISCLAIMER.md](DISCLAIMER.md)** — shipped hardware code uses
simulation stubs. Life-safety functions require certified hardware
interlocks and qualified engineering review. Always.

---

## Quickstart

```bash
git clone https://github.com/justingracie-defender/driftcore-os.git
cd driftcore-os
pip install -r requirements.txt
python main.py
```

Runs the full demo suite: truth/creative/discovery modes, drift
escalation, emergency halt, sycophancy detection, no-human-in-loop
warning, hardware hazard scenarios (fire/water/electrical/mechanical/
thermal/e-stop), invariant enforcement tests, and audit chain
verification — all with loud Fable narration.

---

## Repository Structure

```
driftcore/
├── kernel/        invariants ★, safety_kernel, state_machine, policies
├── cognition/     cognitive_mode, abduction_engine, sycophancy_detector
├── uncertainty/   bayesian_uncertainty
├── drift/         drift_model, drift_detector
├── hardware/      hardware_safety, sensor_interfaces, production_wiring
├── memory/        memory_fs, integrity
├── agents/        agent_runtime, agent_protocol
├── network/       ai_bus, trust_model
├── safety/        safe_halt, hardware_isolation, recovery
├── fable/         narrator, audit_story, trust_bridge, glossary
└── redteam/       scenarios, adversarial sims

CONSTITUTION.md    The immutable principles, in plain language
SAFETY_CONTRACT.md What operators can rely on — triggers, shutdown, approval
run_verification.py Red-team suite — 29 attacks, must pass 100%
LICENSE            DriftCore Safety Copyleft License (DRAFT — needs legal review)
DISCLAIMER.md      Read before deploying anywhere
CONTRIBUTING.md    How to help
```

---

## Roadmap

| Version | Focus | Status |
|---------|-------|--------|
| v2.4 | Fable narrator + audit chain | ✅ |
| v3.0 | Three-mode cognition, sycophancy, Bayesian uncertainty | ✅ |
| v3.1 | Hardware interlocks, immutable invariants, constitution, license | ✅ (this release) |
| v3.2 | Real LLM adapters — SafeLLMAdapter (Claude/GPT/Grok/local) | ✅ |
| v3.3 | Safety Verification & Red-Team Toolkit + Safety Contract | ✅ |
| v3.4 | ROS2 robotics binding + live demo dashboard | Planned |
| v3.6 | Builder/maker path — DIY safety without a factory | ✅ |
| v3.5 | Embodiment classes + tiered signed restart authority | ✅ |
| v4.0 | Formal verification of invariant enforcement | Planned |

---

## Project Heritage

DriftCore is the distilled, standalone safety core from a broader
collaborative effort on safe home robotics and AI companionship,
developed through human-led collaboration across multiple AI systems.
The human maintainer holds final merge authority on all changes —
which is exactly how this system says it should work.

## Philosophy

- Safety without legibility is not real safety.
- Hallucination is not always wrong — uncalibrated confidence is.
- Sycophancy is more dangerous than hallucination.
- Explicit ignorance is a feature, not a bug.
- Full autonomy is not a feature. It is a liability.
- Autonomy is earned through demonstrated safe behavior — never assumed.
- When in doubt, stop. Always choose the recoverable error.
- The rules are load-bearing, not speakable — a safe system shapes its words by its principles without reciting them, and explains them plainly when asked.
- **Safety infrastructure belongs to everyone.**
