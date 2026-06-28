# Integration Notes — Authority / Objective / Gate modules

Merged 2026-06-27 into the 2026-06-22 base. Full suite: 25/25 suites pass
(21 original + 4 new). New modules add 57 internal checks (all passing).

## What was added (all IMPLEMENTED + tested)
- driftcore/verification/invariant_guard.py     — the constitutional floor in code
  (egress / oversight / deception / log-integrity). Fills the previously-empty
  CONSTITUTION slot. Fail-closed.
- driftcore/verification/authority_invariants.py — anti-authority-drift cluster
  (#7–#13: self-granted authority, self-review, definition capture, emergency
  bypass, self-preservation, concealment, manipulation). Absolute; parametrized.
- driftcore/authority/authorization_gate.py     — the "dumb lock": passive,
  external-verifier, fail-closed, degrade-to-safe-rest.
- driftcore/authority/gated_executor.py         — runs the gate before the
  governed path.
- driftcore/authority/scoped_authorization.py   — one-key-per-door, on-demand
  admin keys, one-time burn (atomic), daily budget, facts-only approval,
  revocation.
- driftcore/objectives/{__init__,engine,coverage}.py — objective engine:
  purpose as a ratified hash-linked artifact, coverage kernel, no-goodness-as-
  target invariant, embodiment floor contract.
- SAFETY_MODEL.md, OBJECTIVE_ENGINE.md          — the WHY behind all of it.
- decision_harness.py (repo root)               — wall-vs-fence behaviour table.

## TWO WIRING JOBS STILL OPEN (deliberate human decisions — NOT done here)
These change existing enforced behaviour, so they are left for explicit review
rather than silently applied:

1. FAIL-CLOSE THE GUARD IMPORT.
   driftcore/skills/__init__.py imports InvariantGuard inside a
   `try/except ImportError: pass`. That silently passes if the guard is absent.
   Change it to use invariant_guard.load_guard() so a missing floor HALTS
   instead of waving actions through.

2. ROUTE A REAL AGENT THROUGH THE GUARDS.
   Nothing governs a live agent until something constructs a
   GatedExecutor / ScopedGate with a REAL verifier and sends agent actions
   through it. Until then these guards govern nothing in that agent's path.

## NOT IN SCOPE HERE (deployment / "key-maker" job)
Signed/one-time tokens, secure time, hardware verifier, issuer≠verifier split.
See SAFETY_MODEL.md §11 "VERIFIER_CONTRACT". The logic layer is done; making the
KEY itself un-forgeable is the deployment's obligation and the field red-team's
target.
