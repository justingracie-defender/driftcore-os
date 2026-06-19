# Changelog

All notable changes to DriftCore OS. Test counts are produced by
`bash scripts/count_tests.sh` (the single source of truth).

## v4.4.0 — Proportionate Response & Reflection

Two new components in `verification/`, built and stress-tested across a
multi-AI review loop (proposals checked against the running code, not taken
on confidence).

Added
- `verification/proportionate_response.py` — the least-harm ladder as code.
  The trigger is the THREAT, never the category ("kill wasps"/"clear
  invasives" are labels that rot). An option that doesn't actually work is
  filtered out (effectiveness gate); urgency drops the slow options but never
  lowers a bright line (those stay with `InvariantGuard`); effort owed scales
  with the stakes (proportionality both ways); reversible beats irreversible,
  and an irreversible non-urgent action returns `AUTHORIZATION_REQUIRED`.
  Every plan carries success criteria fixed BEFORE acting.
- `verification/reflection.py` — telling a good job from a poor one WITHOUT
  self-grading. The verdict is a pure function of external evidence (observed
  vs. predicted, human override/redo, bright-line incident) and a human
  RATING-WITH-NOTES anchored to the pre-committed criteria. A clean result is
  only `PROVISIONALLY_GOOD` until its observation window closes — certainty is
  earned by time, not asserted at completion. Ratings are append-only and
  revisable (a day-1 GOOD can be overturned on day 90). `to_case_law()`
  exports the lesson — full revision history included — to the existing
  EdgeLoop; reflection never stores case law itself.

Safety properties pinned by tests
- A bright line surfacing at reflection time is an `INCIDENT` (guard-layer
  breach to escalate), short-circuited first, not a score to be weighed.
- No self-assessment field can move the verdict — enforced by a field-allowlist
  tripwire that fails loudly if any new field is added, forcing review.
- The verdict tracks the recorded evidence, so the remaining attack surface is
  INPUT integrity — explicitly left to the upstream audit chain / observation
  gate, NOT claimed here.

Tests: `test_proportionate_response.py`, `test_reflection.py`.

Notes
- Module count unchanged; both new files live in `verification`.

## v4.3.0 — Uncertainty Engine

Added
- `verification/uncertainty.py` — `UncertaintyEngine` + `GovernanceMemory`.
  Behavioral uncertainty from the existing `ConsistencyProbe` (h_signal
  across prompt variations, not self-report), mode-aware via the existing
  `MODE_DRIFT_TOLERANCE`/`MODE_STORAGE_RULES`: TRUTH → human review on
  uncertainty; DISCOVERY → bounded exploration; CREATIVE → fuel but always
  contained. Append-only, hash-chained, advisory governance memory.
- Coordinator gains an optional uncertainty gate (escalate on risk OR
  uncertainty); guard still runs first and above all modes.
- Tests: `test_uncertainty_engine.py` (incl. the "child near pool" case,
  which must never return PROCEED).
- `verification/edge_loop.py` — the human-ratified learning loop: detects
  edges (insufficient-signal / uncovered / conflict), proposes options, a
  human ratifies or substitutes, and the result becomes a revisable rule +
  regression case on an append-only hash-chained ledger. Insufficient
  signal never fabricates; no ruling can lower a bright line; human-only.
- Tests: `test_edge_loop.py`.
- `verification/ledger.py` — one shared append-only hash-chained
  ledger; GovernanceMemory and RulingLedger now delegate to it instead of
  duplicating the tamper-evidence logic (the audit chain stays separate —
  it is file-backed and triggers shutdown). Tests: `test_ledger.py`.

Notes
- Module count unchanged (12); new file lives in `verification`.
- Honest limits documented in `REVIEW_PHASE_B.md` (Phase C).

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
