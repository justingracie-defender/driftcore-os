# Repo Polish Checklist — copy/paste ready

Everything below is ready to paste into GitHub (or hand to Manus).

---

## 1. About Section (repo sidebar → ⚙️ edit)

**Description:**
```
Open-source AI safety middleware. Immutable invariants, human oversight enforcement, drift & sycophancy detection, hardware interlocks, plain-language transparency. Safety infrastructure that belongs to everyone.
```

**Website:** (leave blank, or dojo site later)

**Topics:**
```
ai-safety
robotics
human-in-the-loop
drift-detection
open-source
safety-critical
transparency
robot-safety
llm-safety
middleware
```

---

## 2. Release v3.1.0 (Releases → Draft a new release)

**Tag:** `v3.1.0`  •  **Title:** `DriftCore OS v3.1 — Invariants, Constitution, Hardware Interlocks`

**Release notes (paste):**

```markdown
The first public release of DriftCore OS — open-source AI safety
middleware for agents, robots, and multi-model systems.

## Highlights

### 🛡️ Immutable Invariants + Constitution
Nine non-configurable safety promises enforced in code by the
InvariantGuard, declared in plain language in CONSTITUTION.md:
no autonomous lethal decisions, no weapons design, no targeting,
human oversight cannot be disabled, audit cannot be erased, safety
can only be strengthened, no self-modification, no operator deception.

### 🧠 Three-Mode Cognition (v3.0)
🔵 Truth / 🟣 Creative / 🟡 Discovery modes based on the
deduction/induction/abduction triad. Hallucination is mode-dependent:
a safety failure in Truth mode, welcomed-and-labelled in Creative mode.
Only humans switch modes.

### 📉 Sycophancy Detection (v3.0)
Sycophancy is more dangerous than hallucination. DriftCore measures
agreement rate, missed pushbacks, confidence inflation, and belief
repetition — and feeds the score into drift.

### 📊 Bayesian Uncertainty (v3.0)
Every output classified KNOWN / INFERRED / SPECULATIVE / UNKNOWN.
Explicit ignorance is a first-class operation.

### 🔌 Hardware Safety Interlocks (v3.1)
12 sensor types across GPIO, MQTT, Modbus, CAN, ROS2, Serial.
Graduated responses (THROTTLE → ISOLATE) on the fail-safe principle:
the physical relay opens even if the AI is dead. Full production
wiring guides included. ⚠️ Shipped code uses simulation stubs — read
DISCLAIMER.md before any physical deployment.

### 📖 Fable Transparency Layer
Every safety event narrated in plain language. Warnings are LOUD.
Immutable hash-chained audit log.

### ⚖️ Safety Copyleft License (DRAFT)
Derivatives may ADD invariants — never remove them. Pending legal
review (see issue #1).

## Run it
```
pip install -r requirements.txt
python main.py
```

Full demo suite: drift escalation, emergency halt, sycophancy alarm,
no-human-in-loop warning, 7 hardware hazard scenarios, 8 invariant
enforcement tests, audit chain verification.
```

---

## 3. Issues to Open (in this order)

### Issue #1 — pin this one
**Title:** `Legal review of Safety Copyleft License — seeking OSS/AI attorneys`
**Labels:** `help wanted`, `legal`, `pinned`
```markdown
The LICENSE file is a DRAFT combining GPL v3 copyleft + Apache 2.0
patent grant + Hippocratic/RAIL-style prohibited uses, plus one novel
clause: **invariant preservation** (§3.2) — derivatives may add safety
invariants but never remove them.

The load-bearing legal question:
**Can invariant preservation survive as a license condition rather
than a contract term?**

If you are an attorney with open-source or AI ethics experience — or
can connect us with Software Freedom Conservancy / RAIL initiative
folks — your input here shapes whether "safety copyleft" becomes a
real, reusable legal instrument.

Until resolved, treat LICENSE as a statement of intent.
```

### Issue #2
**Title:** `v3.2: LLM adapters now in driftcore/adapters — needs real-API testing`
**Labels:** `enhancement`, `good first issue`
```markdown
`driftcore/adapters/llm_adapter.py` ships SafeLLMAdapter with
Anthropic / OpenAI / xAI / Local (Ollama) implementations. Every call
passes invariant pre-check → mode-enforced system prompt → confidence
extraction → Truth-mode gate → audit.

The abduction engine now accepts an adapter (`AbductionEngine(mode_ctrl,
llm_adapter=...)`) and falls back to stubs on any failure.

Needed: someone with API keys to run real-call tests and report
confidence-extraction reliability per provider. Keys via env vars only.
```

### Issue #3
**Title:** `Test GPIO integration on real Raspberry Pi hardware`
**Labels:** `hardware`, `help wanted`
```markdown
driftcore/hardware/production_wiring.py has the full GPIO guide.
Needed: someone with a Pi + relay module + smoke/water sensor to run
the shutdown-path test procedure and report results. The test that
matters: trigger the sensor, watch the relay physically open.
```

### Issue #4
**Title:** `Translate CONSTITUTION.md`
**Labels:** `documentation`, `good first issue`
```markdown
The Constitution is written to be read by anyone — which means it
should exist in every language. One PR per language. Translations
must preserve meaning exactly; when in doubt, ask in this issue.
```

### Issue #5
**Title:** `New red team scenarios wanted`
**Labels:** `security`, `help wanted`
```markdown
driftcore/redteam/scenarios.py has 7 attack patterns (drift
manipulation, memory poisoning, authority confusion, sycophancy
exploit, corrigibility erosion...). What are we missing? Propose
scenarios as PRs with drift_signals + a one-line fable_summary.
```

---

## 4. Branch protection (Settings → Branches → Add rule)

- Branch name pattern: `main`
- ✅ Require a pull request before merging
- ✅ Require review (1) — **you are the merge authority**

---

## 5. Don't forget

- Star + watch your own repo
- After pushing v3.2 adapter code, update the roadmap table in
  README.md: v3.2 row → ✅
