# 🧠 DriftCore OS v4.1.1

> *"The safest system is the one that knows what it knows — and says so."*

**A safety-first, open-source operating layer for AI agents, robotics, and multi-model systems.** Built around a single organising principle: the people the system serves must always be in control of it.

**Read [CONSTITUTION.md](CONSTITUTION.md) first.**

---

## Quickstart — Run in 5 Minutes

Requires Python 3.10+. No external dependencies for core modules.

```bash
git clone https://github.com/justingracie-defender/driftcore-os
cd driftcore-os

# Run the full test suite — 427 tests
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

## Architecture Overview

DriftCore OS is built on **load-bearing safety invariants**:

- **HUMAN_OVERSIGHT_CANNOT_BE_DISABLED**: Human review gates all high-stakes decisions.
- **SHUTDOWN_ON_TAMPER**: Any integrity violation → immediate system halt.
- **OBSERVATION_GATE_ON_EVERY_WRITE**: All memory writes audited in real time.
- **TWO_LANE_DRIFT_DETECTION**: Behavioral + statistical anomaly tracking.
- **H_NEURON_CONSISTENCY_PROBING**: Fingerprint-based model coherence verification.

### Core Modules

```
driftcore/
├── memory/              # Multi-tier memory with audit trail
├── enforcement/         # Policy execution & override detection
├── audit/               # Tamper-evident chain
├── observation/         # Write gates & stream logging
├── drift/               # Behavioral + statistical anomaly detection
├── storage/             # Encrypted, integrity-checked storage
├── probe/               # H-neuron consistency (v4.1.1 new)
├── cognition/           # Cognitive modes (reasoning, execution, etc.)
├── api/                 # Universal Memory API (v4.1.1 enhanced)
├── profiles/            # Agent deployment profiles (v4.1.1 new)
└── feedback/            # System feedback loops (v4.1.1 new)
```

### Test Suite (427 tests)

- `test_memory_core.py` — Memory allocation, isolation, queries
- `test_memory_extended.py` — Advanced memory operations
- `test_enforcement.py` — Policy enforcement & override detection
- `test_audit_chain.py` — Tamper detection & audit trail integrity
- `test_observation_gate.py` — Write-gate auditing
- `test_drift_detector.py` — Behavioral anomaly detection
- `test_storage.py` — Encryption & integrity checks
- `test_consistency_probe.py` — H-neuron fingerprinting
- `test_cognitive_mode.py` — Cognitive mode switching
- `test_api.py` — Universal API (v4.1.1 new)
- `test_profiles_feedback.py` — Profiles & feedback (v4.1.1 new)

---

## Deployment Profiles

Choose a profile for your use case:

- **Research**: Full transparency, all logs, no rate limits
- **Production**: Audit-ready, encrypted logs, human approval gates
- **Robotics**: Real-time constraints, memory optimization
- **Multi-Agent**: Isolation + coordination protocols

See `driftcore/profiles/__init__.py` for details.

---

## Cognitive Modes

- **Reasoning**: Deep analysis, audit every step
- **Execution**: Fast, deterministic, pre-approved actions
- **Exploration**: Hypothesis-driven learning with rollback
- **Recovery**: Constrained repair after anomaly detection

See `driftcore/cognition/cognitive_mode.py`.

---

## Documents

See `docs/`:

- **DriftCore_Manifesto.docx** — Philosophy & principles
- **Safety_Contract.md** — Formal safety guarantees
- **API_Reference.docx** — Full API documentation
- **Deployment_Guide.docx** — Production setup

---

## Philosophy

DriftCore OS is built on the conviction that **safety is not a constraint — it's the foundation**. Systems that can be trusted are systems that *cannot hide*. Every decision is logged, every anomaly is visible, and human oversight is never optional.

See [CONSTITUTION.md](CONSTITUTION.md) for the full organizing principles.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Submitting patches (safety review required)
- Writing tests (427+ test suite)
- Maintaining invariants
- Reporting security issues

All contributors must read [CLAUDE.md](CLAUDE.md) for AI collaboration guidelines.

---

## License

Apache 2.0. See LICENSE.

---

## Contact & Support

- **GitHub Issues**: https://github.com/justingracie-defender/driftcore-os/issues
- **Discussions**: https://github.com/justingracie-defender/driftcore-os/discussions

**Version**: v4.1.1 (June 2026)  
**Status**: Stable, production-ready  
**Test Coverage**: 427 tests, all passing
