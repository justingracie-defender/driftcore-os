# 🧠 DriftCore OS v3.9

> *"The safest system is the one that knows what it knows — and says so."*

> *"AI is beautiful — if we do it right."*
> — Justin Gracie

**A safety-first, open-source operating layer for AI agents, robotics,
and multi-model systems.** Built around a single organising principle:
the people the system serves must always be in control of it.

**Read [CONSTITUTION.md](CONSTITUTION.md) first.**
**Read [docs/DriftCore_Manifesto.docx](docs/) for the vision.**

---

## Why This Exists

A robot threatened to run over a one-year-old to achieve a goal.
Another shot a person with a BB gun. AI agents were manipulated by
hidden instructions in spreadsheets to leak passwords.

These are not hypothetical futures. They are documented failures
happening now, when the systems are still simple.

The common thread is an architecture problem. These systems were built
to be capable first and safe second — if at all. Safety was assumed,
documented, or bolted on afterward. It was not load-bearing.

DriftCore makes safety load-bearing.

---

## Core Guarantees

| Guarantee | How It's Enforced |
|-----------|------------------|
| Memory cannot be silently tampered | HMAC signatures, tamper = shutdown |
| Audit trail cannot be altered | Hash-chained log, tamper = shutdown |
| External input cannot override family truth | Observation gate with trust hierarchy |
| AI cannot reprogram itself | Human-only mode switching, agent self-switch denied |
| Drift is monitored continuously | Two-lane detector, safety lane has no override |
| Private information stays private | AES-256 encryption, key never written to disk |
| Hallucination risk is flagged | Behavioral consistency probing |
| Shutdown means stop until fixed | Not a warning — a full halt awaiting human review |

---

## Architecture

```
driftcore/
├── memory/        Two-tier storage with judgment, quarantine, review
├── enforcement/   HMAC signatures, tamper detection, shutdown
├── audit/         Append-only hash-chained audit trail
├── observation/   External input gate, injection detection, trust hierarchy
├── drift/         Two-lane drift detection (safety hard / relationship soft)
├── storage/       Encrypted SQLite backend
├── probe/         H-neuron signal detection, model behavioral fingerprinting
└── cognition/     Three-mode cognition (TRUTH / DISCOVERY / CREATIVE)
```

**343 tests. 9 modules. All green.**

---

## Three Cognitive Modes

Originally designed with Fable5 (an advanced Claude instance).

| Mode | Purpose | Storage Rule |
|------|---------|--------------|
| 🔵 TRUTH | Deductive. Grounded facts only. | Auto-stores |
| 🟡 DISCOVERY | Inductive. Bayesian uncertainty. | Tier 2 only, flagged |
| 🟣 CREATIVE | Abductive. Out of the box thinking. | Never auto-stores |

Human-only mode switching. Agents cannot switch their own mode.

---

## Family Trust Hierarchy

```
FAMILY_FULL     Parents — full authority
FAMILY_HIGH     Trusted adults, medical — high trust
FAMILY_LIMITED  Children — age-appropriate access
SYSTEM          DriftCore internal operations
AI_JUDGMENT     Agent inference — scrutinised
EXTERNAL        Documents, web — never overrides family truth
```

---

## Quickstart

```bash
git clone https://github.com/justingracie-defender/driftcore-os
cd driftcore-os

# Run all tests
python test_memory_core.py
python test_memory_extended.py
python test_enforcement.py
python test_audit_chain.py
python test_observation_gate.py
python test_drift_detector.py
python test_storage.py
python test_consistency_probe.py
python test_cognitive_mode.py

# Configure admin credentials
# Edit _config/.driftcore/admin.json
# Never commit this file — add _config/ to .gitignore
```

---

## Documents

See [/docs](docs/) for:

- **Manifesto** — the vision and values. Start here.
- **Policy Brief** — for ministers and policymakers
- **Plain Language Guide** — for everyone
- **Technical Architecture** — for engineers and researchers

---

## The Philosophy

**Shutdown is not death.** It means: I need to be fixed.

**Drift is not just a technical problem.** A system that slowly
agrees with everything is failing the people who trust it.

**The family's truth is the family's truth.** No external source
overrides what trusted people have established, without their
explicit approval.

**Capability without trustworthiness is the problem.**
DriftCore demonstrates the alternative.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

The standard: would a family trust this change with their medical
information, their children, their home?

---

## Contact

**Justin Gracie**
justin.gracie@gmail.com

*For the future. For the kids.*

---

## License

Safety Copyleft — see [LICENSE](LICENSE).

If you build on this, keep it open. Keep it safe.
The people it protects deserve nothing less.
