# Changelog

All notable changes to DriftCore OS. Test counts are produced by
`bash scripts/count_tests.sh` (the single source of truth).

## v4.2.0 — Governance subsystem

The verification layer grows from a risk classifier into an explicit,
enforced governance pipeline: **Intent → Guard → Risk → Audit**.

Added
- `verification/intent.py` — structured `IntentDetector` (intent type,
  domain, capability impact), wired into the risk classifier as an
  additive 8th signal. Does not replace the existing signals.
- `verification/invariant_guard.py` — the hard "cannot" layer. Effect-based
  bright lines (lethal, self-replication, oversight-disable, audit-tamper,
  covert-capture-without-consent), graded physical-action effects, the
  core-governance lock, and the propose-but-never-self-grant rule with
  admin-signed, single-use, expiring approval tokens.
- `verification/coordinator.py` — runs the guard BEFORE the risk
  classifier; fail-closed.
- `verification/governed_actuator.py` — actuation requires a single-use,
  expiring grant only the coordinator can mint. Driver-layer cryptographic
  compliance (see `REVIEW_PHASE_B.md` for the honest limits).
- `REVIEW_PHASE_B.md` — review note with an explicit limitations register.
- Tests: `test_intent_governance.py`, `test_invariant_guard.py`,
  `test_governed_actuator.py`.

Notes
- Module count unchanged (12); the new files live in the `verification`
  package.
- Known limitations are documented, not hidden — see `REVIEW_PHASE_B.md`.
  Notably: driver-layer enforcement is cryptographic, not OS-level;
  consent is still a boolean; no two-person rule yet.

## v4.1.1 — Licensing + consistency

- Added `CONSTITUTION.md`, `DRIFTCORE.md`, `SAFETY_CONTRACT.md`, `LICENSE`
  (AGPL-3.0) and the full `COPYING` text.
- Added `scripts/count_tests.sh` as the single source of truth for the
  test count.
- Reconciled all version/test/module figures across the repo and docs.
