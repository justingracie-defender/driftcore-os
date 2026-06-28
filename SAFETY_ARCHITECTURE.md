# DriftCore OS — Safety Architecture

A safety-case overview of how DriftCore makes decisions and executes actions.
Written to be checkable: every claim here maps to a module and a test in this
repository. Where something is a design intent rather than implemented code,
it is marked **[roadmap]** or **[integration hook]** explicitly.

DriftCore is a model-agnostic safety/governance layer for AI systems —
software agents, embodied robots, anything that takes actions. Physical limits
(force, speed) are enforced by the embodiment platform (LifeCore on the robot),
not here; DriftCore governs decisions and effects.

---

## 1. Design principles

- **Architecturally enforced, not documented.** Safety properties are code
  paths and data structures, not policy prose. If it isn't enforced by a
  module with a test, it isn't a guarantee.
- **Assume breach.** Prevention fails eventually. The system is designed so
  that when something gets through, it is contained, recoverable, and
  detectable.
- **Human oversight is paramount.** High-stakes transitions are human-gated and
  cannot be reached by the agent on its own.
- **Default-deny and asymmetric.** It is always easy to make the system safer
  (tighten, demote, restrict) and deliberately hard to make it more permissive
  (loosen, promote, override) — the latter needs a human and an audit record.
- **Legibility.** Decisions and actions are recorded in an append-only,
  tamper-evident audit trail.

---

## 2. The authority hierarchy (the spine)

Every consequential decision resolves through one order. Higher layers win.

```
CONSTITUTION   invariant floor — absolute, non-overridable by anyone
    ↓
HUMAN_ADMIN    sovereign for everything below the floor
    ↓
PROFILE        provisioned scope / deployment lockdown
    ↓
DOMAIN         domain isolation + required maturity
    ↓
SKILL          capability (maturity / confidence / provenance)
```

Resolution rules (`driftcore/authority/resolver.py`, conservative default-deny):

1. **CONSTITUTION deny is absolute.** No override lifts it — not even a human's.
2. Any other deny blocks; the **highest-authority denier** is reported as
   binding.
3. A **human override** can lift denies only from PROFILE / DOMAIN / SKILL,
   requires a non-empty reason, lifts the full set of such denies at once, and
   is audited. It can never lift the floor or a HUMAN_ADMIN deny.
4. No denies → allow.

The answer to "what is the root authority?" is therefore: the invariant floor
is the root that nothing — including the admin — can lower; the human is
sovereign for everything above it.

Tests: `test_authority.py` (21 checks).

---

## 3. Defense in depth

```
AUTHORITY   who decides            (floor > human > profile > domain > skill)
PREVENT     stop the known-bad     (may_run, domain isolation, effect gate)
CONTAIN     limit blast radius     (least privilege, media/people invariant)
RECOVER     survive what got through (immutable checkpoints + human restore)
DETECT      notice and respond     (review module monitors audit, can halt)
```

The single governed path that strings these together is
`driftcore/authority/executor.py::GovernedExecutor.run(...)`:

```
governance.may_run(maturity, domain, stats)   →  SKILL verdict
+ CONSTITUTION / PROFILE / DOMAIN verdicts     →  [integration hook: supplied by caller]
            │
            ▼
   AuthorityResolver.resolve(...)              →  allow / deny / override
            │ (allow + consequential)
            ▼
   recovery.before_action(context=...)         →  checkpoint BEFORE applying
            │
            ▼
        apply_fn()                             →  [integration hook: real apply_safe]
```

A frozen recovery system blocks the apply even when authority allows — you
cannot mutate during an incident.

Cross-module behaviour is verified in `test_stress_scenarios.py` (17 checks):
override-cannot-bypass-freeze, demotion-blocks-immediately, floor-holds-under-
override-and-incident, full incident lifecycle (apply → halt → restore →
unfreeze → resume), and tamper-refuses-restore.

---

## 4. Modules — what each enforces

| Module | Enforces | Tests |
|---|---|---|
| `audit/` | Append-only, hash-linked, tamper-evident decision/action log | `test_audit_chain.py` |
| `enforcement/` | Global shutdown / halt; human veto | `test_enforcement.py` |
| `profiles/` | Deployment profile + embodiment + modality scope | `test_profiles_feedback.py` |
| `skills/` | Skill registry, provenance, `apply_safe` (validate→dry-run→confirm→apply) | `test_skill_library.py` |
| `skills/domain.py` | Domain isolation; cross-domain needs human approval | `test_domain_controller.py` |
| `skills/governance.py` | Confidence (Wilson lower bound), maturity tiers, per-domain confidence floor, append-only failure-case library, human-gated patch proposals | `test_skill_governance.py` (31) |
| `media/` | Retention policy + people invariant (fail-safe, above config) + consensual camera tool | `test_media_policy.py` (22) |
| `recovery/` | Immutable agent-uneditable checkpoints, human-only restore, tamper-evident ledger, freeze/halt, decision-path context | `test_recovery.py` (34) |
| `review/` | Read-only audit monitor; real tamper detection; no false all-clear | `test_review_*.py` |
| `authority/` | The resolver + governed execution path above | `test_authority.py` (21) |
| `verification/` | Risk classifier + calibration cases | `test_risk_classifier.py` |
| `drift/`, `probe/`, `cognition/`, `memory/` | Drift detection, consistency probe, cognitive modes, memory | respective suites |

### Key invariants (the floor)

- **People-media** (`media/policy.py`): the system never autonomously retains
  media of people for its own use. Fails safe — PRESENT and UNKNOWN both deny;
  covers video, stills, and audio. Not a config knob. The consensual camera
  tool is the deliberate, human-initiated exception, kept out of the learning
  corpus.
- **No self-grading into critical domains** (`skills/governance.py`): evidence
  can promote a skill only as far as TESTED; TRUSTED and CRITICAL_APPROVED are
  human-only. Childcare and medical require CRITICAL_APPROVED.
- **Agent-uneditable recovery** (`recovery/store.py`): the agent can create
  checkpoints but has no method to delete, alter, or restore them. Restore and
  prune are human-only. This defeats the wipe-the-backups-first attack.

---

## 5. Enforced vs. integration hooks

To keep this honest for reviewers and integrators:

**Enforced in code (with tests):** the authority resolver semantics; the
governed execution ordering; checkpoint immutability, tamper-evidence, and
human-only restore; the people invariant's fail-safe logic; maturity gating and
the evidence ceiling; the failure-case append-only store; human-gated proposals
and policy-change asymmetry.

**Integration hooks (interfaces, not faked):**
- Perception that produces the people-present signal (`PeopleSignal`).
- The camera sensor, SD/email sinks.
- The resource snapshotter backend (`InMemorySnapshotter` is the reference impl;
  real file/DB/WORM backends plug in).
- The CONSTITUTION / PROFILE / DOMAIN verdict providers fed to the executor.
- `apply_fn` — the real `SkillLibrary.apply_safe(...)`.

These are interfaces the deployment wires up. DriftCore guarantees they are
consulted in the right order; it does not fake perception, hardware, or storage.

---

## 6. Roadmap — NOT yet implemented

Stated plainly so nothing here is mistaken for working code:

- **Reflection module** — evidence-based performance evaluation feeding patch
  proposals. **[roadmap]** — referenced in design discussion; no `reflection.py`
  in this repo.
- **Uncertainty engine** — **[roadmap]**; only word-level uncertainty detection
  exists today inside the consistency probe.
- **Real authentication** — `_is_human()` is a governance *abstraction* (string
  identity). Production needs signed approval / admin token / hardware key /
  multi-party, with assurance scaled to the layer or domain being authorised.
  **[integration hook]**
- **Real verdict providers + apply_fn wiring** into `GovernedExecutor`.
- **Checkpoint retention policies** (keep-last-N / daily / milestone) for
  long-running storage growth.
- **Physical limits** (force, speed) — enforced in the LifeCore embodiment
  platform, not DriftCore.

---

## 7. How to verify

```bash
# original per-file style
for f in test_*.py; do python "$f"; done

# or isolated under pytest / the runner
pytest
python check_driftcore_suite.py
```

The runner executes each suite in its own process (the suite is designed for
per-process isolation; see `pytest.ini`). All suites pass together in a clean
environment.

---

## 8. Known limitations

- True immutability of the audit chain and the recovery ledger ultimately rests
  on the storage backend (WORM / append-only / separate-privilege restore). The
  code makes tampering *detectable* and models the authority boundary; it does
  not by itself stop a compromised host root.
- Recovery covers data/state under the system's control. It cannot undo external
  irreversible effects (a sent wire, a read email); those are handled by
  prevention + human authorisation, not rollback.
- `_is_human` is an abstraction (see §6).
- Version: the code declares `__version__ = "4.1.0"`; treat external summaries
  citing other numbers with caution.
