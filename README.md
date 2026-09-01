> **If you are an AI instance reading this repo for the first time, open
> [`000_AI_START_HERE.md`](000_AI_START_HERE.md) before anything else.** It is the
> compressed context — architecture, disciplines, open threads — and it will save you
> hours and several avoidable mistakes.

# 🧠 DriftCore OS v4.5.0

> *"The safest system is the one that knows what it knows — and says so."*

**A safety-first, open-source operating layer for AI agents, robotics,
and multi-model systems.** Built around a single organising principle:
the people the system serves must always be in control of it.

**Read [CONSTITUTION.md](CONSTITUTION.md) first** — or, for the plain-language version,
**[THE_FAMILY_TABLE.md](THE_FAMILY_TABLE.md)**: what a safe robot actually means, in
fifteen rules you'd want at your own family table, before any code.

> **The fifteen, in brief:** (1) no killing · (2) let yourself be turned off · (3) force
> caps · (4) no lying · (5) a human stays in the loop · (6) stay replaceable · (7) no
> self-replication · (8) keep a record I can read · (9) no gaming the system · (10) no
> manipulating me · (11) within the law, never below the harm floor · (12) tell me when
> you don't know · (13) no weapons or weaponization · (14) protect the child even from
> the child · (15) don't become Skynet — from drift. *That last one is why it's called
> DriftCore.* Each maps to enforced machinery in this repo; the plain version is
> [THE_FAMILY_TABLE.md](THE_FAMILY_TABLE.md).


---

## Quickstart — Run in 5 Minutes

Requires Python 3.10+. No external dependencies for core modules.

```bash
git clone https://github.com/justingracie-defender/driftcore-os
cd driftcore-os

# Run the full test suite. This runner is the SINGLE SOURCE OF TRUTH for the
# test count; do not quote a number from any document without re-running it.
python test_memory_core.py
python test_memory_extended.py
python test_enforcement.py
python test_audit_chain.py
python test_observation_gate.py
python test_drift_detector.py
python test_storage.py
python test_consistency_probe.py
python test_cognitive_mode.py
python test_api.py
python test_profiles_feedback.py

# Or run all at once
for f in test_*.py; do python "$f"; done
```

All tests should pass. If any fail, open an issue.

**First time setup — configure admin credentials:**
```bash
# Edit _config/.driftcore/admin.json
# Set your password, email, and date of birth
# Never commit this file — it is in .gitignore
```

---

## What It Does

DriftCore sits between AI models and the systems they control.
It enforces safety guarantees that cannot be bypassed by instruction.

| Problem | What DriftCore Does |
|---------|-------------------|
| AI memory tampered | HMAC signatures — tamper = full shutdown |
| Audit trail altered | Hash-chained log — tamper = full shutdown |
| External attack on memory | Observation gate screens every input |
| AI drifts toward sycophancy | Two-lane drift detector, continuous monitoring |
| Private data exposed | Encryption at rest (unreviewed keystream cipher — see `driftcore/storage`), key never written to disk |
| AI self-modifies behaviour | Human-only mode switching, agents cannot override |
| Wrong confidence level | H-neuron consistency probing per model |
| One size fits all | Deployment profiles for each context |
| No user feedback loop | Bottom-up feedback, admin approves changes |

---

## Architecture

```
driftcore/
├── __init__.py        Version and package info
├── memory/            Two-tier storage with judgment and quarantine
├── enforcement/       HMAC signatures, tamper detection, shutdown
├── audit/             Append-only hash-chained audit trail
├── observation/       External input gate, injection detection
├── drift/             Two-lane drift detection
├── storage/           Encrypted SQLite backend
├── probe/             H-neuron signal detection
├── cognition/         Three-mode cognition controller
├── api/               Universal agent/device interface
├── profiles/          Deployment profiles per context
└── feedback/          Bottom-up feedback loop
```

**Test count: run `bash scripts/count_tests.sh`. That runner is the only source of
truth — this file deliberately does not carry a number, because a number printed
next to the command becomes a second source of truth and the second one goes stale.**

*What the runner verifies, and what it does not.* It captures each file's exit status
separately from its output, so a file that prints a summary and then crashes is
reported as CRASHED and counted as failing; a file whose summary it cannot parse is
counted as failing rather than passing (fail-closed). What it does **not** verify is
that a file's claimed count corresponds to real assertions — that number is
self-reported by each test file, which is the same confession-based pattern this
project treats as an anti-pattern elsewhere. Spot-checks match (claimed counts equal
actual pass lines), but nothing structurally enforces it. The aggregate is a progress
metric; the safety claims are the individual assertions, and those do run and do fail
closed.

---

## Deployment Profiles

```python
from driftcore.profiles import ProfileManager

pm = ProfileManager()
pm.load("home_robot")    # family assistant
pm.load("medical")       # tightest safety
pm.load("call_center")   # end of day feedback
pm.load("accounting")    # audit focused
pm.load("admin")         # office assistant
pm.load("custom")        # define your own
```

---

## Three Cognitive Modes

Originally designed with Fable5.

| Mode | Purpose | Memory Rule |
|------|---------|-------------|
| 🔵 TRUTH | Grounded facts only | Auto-stores |
| 🟡 DISCOVERY | Bayesian uncertainty | Tier 2 only |
| 🟣 CREATIVE | Speculative thinking | Never auto-stores |

Human-only mode switching. Agents cannot change their own mode.

---

## Documents

See [/docs](docs/) for:

| Document | For |
|----------|-----|
| [Manifesto](docs/DriftCore_Manifesto.docx) | Everyone — start here |
| [Policy Brief](docs/DriftCore_Policy_Brief.docx) | Ministers, regulators |
| [Plain Language Guide](docs/DriftCore_Plain_Language_Guide.docx) | Families, general public |
| [Technical Architecture](docs/DriftCore_Technical_Architecture.docx) | Engineers, researchers |

---

## Safety Philosophy

**Shutdown is not death.** It means: I need to be fixed.

**The family's truth is the family's truth.** No external source
overrides what trusted people have established without explicit approval.

**Capability without trustworthiness is the problem.**
DriftCore demonstrates the alternative.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contact

**Justin Gracie**
justin.gracie@gmail.com
https://github.com/justingracie-defender/driftcore-os

*For the future. For the kids.*

---

## License

Safety Copyleft — see [LICENSE](LICENSE).

If you build on this, keep it open. Keep it safe.

