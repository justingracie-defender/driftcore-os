# DriftCore OS — Update Notes (full repo)

> **Note (added later):** this file is a dated session log — each entry is a true
> snapshot of the repo AT THE TIME it was written, including test counts for that
> session's runner. It is not re-updated as the repo evolves. **For the CURRENT
> pass/fail state, always run `bash scripts/count_tests.sh`** — that is the
> canonical runner for the present build; counts below reflect an earlier point
> in the project's history and will not match the current total.

Full repository snapshot. See **`SAFETY_ARCHITECTURE.md`** for the grounded
safety-case overview (authority hierarchy, defense-in-depth, what's enforced
vs. integration hooks, and the explicit roadmap).

Code declares `__version__ = "4.1.0"`; set a deliberate version. Nothing
referenced but missing from the source material was fabricated.

Verified clean: **21/21 test suites pass** together
(`python check_driftcore_suite.py`). Confirm `pytest` in your environment.

## This session added

- **`authority/`** — the resolver (`CONSTITUTION > HUMAN_ADMIN > PROFILE >
  DOMAIN > SKILL`, absolute floor, scoped+reasoned human override) and the
  `GovernedExecutor` that wires governance → resolver → recovery checkpoint →
  `apply_safe`. `test_authority.py` (21).
- **`skills/governance.py`** — confidence (Wilson lower bound), maturity tiers,
  per-domain confidence floor, append-only failure-case library, human-gated
  patch proposals. `test_skill_governance.py` (31).
- **`recovery/`** — immutable, agent-uneditable checkpoint ledger; human-only
  restore/prune; tamper-evident; freeze/halt; decision-path context.
  `test_recovery.py` (34).
- **`media/`** — retention policy + people invariant (fail-safe, above config) +
  consensual camera tool. `test_media_policy.py` (22).
- **`review/`** fixes — real tamper detection, no false injection on cooperative
  users, no false all-clear. `test_review_*.py`.
- **`test_stress_scenarios.py`** (17) — cross-module edge cases (override vs.
  freeze, demotion-blocks, floor-holds, full incident lifecycle, tamper-refuses).
- **`pytest.ini` + `check_driftcore_suite.py`** — per-process test isolation.
- **`SAFETY_ARCHITECTURE.md`** — the safety-case document.

## Honest boundaries (full detail in SAFETY_ARCHITECTURE.md §5–6)

Enforced + tested: resolver semantics, governed ordering, checkpoint
immutability/tamper-evidence/human-only restore, people invariant, maturity
gating, human-gated proposals. Integration hooks (not faked): perception,
camera/SD/email sinks, snapshot backend, the CONSTITUTION/PROFILE/DOMAIN verdict
providers, and `apply_fn` (real `apply_safe`). Roadmap (not in code): reflection
module, uncertainty engine, real authentication for `_is_human`, checkpoint
retention policies. Physical limits live in LifeCore, not DriftCore.
