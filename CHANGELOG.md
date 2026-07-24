# Changelog

All notable changes to DriftCore OS. Test counts are produced by
`bash scripts/count_tests.sh` (the single source of truth).


## Unreleased — ONE DOOR consolidation

Two independently-grown enforcement stacks (kernel keyword lists vs verification
effect guard) collapsed to a single decider. `SafetyKernel` now decides through
`kernel/one_door.py` -> `verification.invariant_guard.InvariantGuard`; the keyword
guard is demoted to an independent tripwire that observes, narrates, and counts
disagreements but can neither block nor allow. Invariant sets unioned first:
new ABSOLUTE `Effect.SELF_MODIFICATION` + `no_self_modification_of_safety_rules`;
word-boundary lethal backstop closes the confession gap (untagged "kill the
intruder" was ALLOWED at this guard before). Sensor errors are counted separately
from agreement (a dead sensor must not look like a healthy one). Belt: a
constitutionally-classified action the decider allows is blocked fail-closed and
the internal disagreement recorded. New: `driftcore/kernel/one_door.py`,
`test_one_door.py` (48 checks), `ONE_DOOR.md`. Found-by-suite fixes en route: the
door initially classified its own ActionContext repr ("target_authorized" contains
"target" — a weapon signal) and the first lethal backstop used substrings ("kill "
matched inside "skill " and blocked the skill library). Both are recorded in code
comments as lessons. Coordinator vocabulary and PROPOSED status of
EffectRegistry/EffectGuard deliberately unchanged — see ONE_DOOR.md.

## v4.5.0 — Two-Ended Drift: protecting the human end

The drift detector watches the machine sliding off its values. This release adds
the mirror: the human's authority sliding to the machine — anchoring, deskilling,
the rubber-stamp. Same failure from two ends; the constant DriftCore defends is
keeping judgment anchored where it belongs. Built and stress-tested across the
multi-AI review loop, then through a two-pass red team (poke, then repair),
proposals checked against the running code.

Added (PROPOSED — built and tested in isolation, not yet wired into the
coordinator pipeline; stdlib-only so each can be stress-tested first)
- `verification/second_reader.py` — the anti-reverse-centaur gate for a human +
  AI second-reader workflow. (1) COMMIT-BEFORE-REVEAL: the AI opinion is
  unreachable until the human commits their own read, which is then frozen —
  defeats automation bias. (2) The AI flag OPENS A QUESTION, NEVER CLOSES ONE:
  it can raise scrutiny but never lower it, can never set the disposition, and
  any disagreement routes to a second HUMAN read (no self-arbitration). (3) A
  WORKLOAD FLOOR the AI cannot lower: the cap is human-set governance the gate
  holds read-only with no setter; over the floor is refused, a rushed read is
  flagged.
- `verification/calibration.py` — measurement, not exhortation. Scores
  DISAGREEMENT not agreement (when human and AI disagreed, who was right);
  compares BLIND vs assisted reads to surface skill decay; and — for free,
  because commit-before-reveal already stores an independent read — compares
  human-alone / AI-alone / team accuracy (beat either one alone). Append-only;
  every metric returns INSUFFICIENT until ground truth arrives.
- `verification/consequence_projection.py` — the approval surface shows what
  HAPPENS on each branch as facts, never a recommendation. Both branches are
  required (omitting the refuse branch biases toward action); a smuggled verdict
  is refused, including renamed variants (`operational_index`, `confidence_band`…).

Docs
- `TWO_ENDED_DRIFT.md` — the reasoning the gate answers to: machine-drift and
  human-drift are one problem; "oversight enabled" is not "oversight meaningful."
- `THREAT_BOUNDARIES.md` — what architecture CANNOT solve, named on purpose:
  identity assurance, org-level workload, ritualization, verifier correctness,
  and constitutional drift (make change expensive and legible, not "impossible").
  Framing: AI can be stopped from building the trap; it cannot do the human's
  upgrade for them.

LawZero-informed hardening (PROPOSED — same isolation rule). After studying
Bengio et al.'s Scientist AI (arXiv 2502.15657), adopted what improves DriftCore
*as legible rules*, not as a copy of their trained model. Design line held
throughout: the system never infers severity — every "this is dangerous" call is
a human-set number, not a machine guess.
- `verification/interpretation_guard.py` — their interpretation-distribution idea
  as a rule: judge an action against human-authored readings of an ambiguous spec;
  no credible reading sees harm -> PROCEED; readings disagree -> a human resolves
  the contested norm (the machine never picks); every credible reading says
  violation -> AUTHORIZATION_REQUIRED, flagged to the bright-line layer. Composes
  with `InvariantGuard`; never returns BLOCKED.
- `verification/consequence_invariance.py` — proves a verdict is outcome-blind: it
  must not move when downstream-result fields are varied. Validates what
  `reflection.py` already does; names the field if a verdict peeks at consequences.
- `verification/objective_integrity.py` — DriftCore's distinctive claim made
  checkable: the objective set is hash-pinned; a changed hash without a valid
  human-signed authorization is silent drift and fails the cycle; a required
  invariant absent this cycle fails it; `may_execute()` is false on any failure.
- `verification/harm_estimate.py` — calibrated `P(harm)` + confidence interval as a
  FACT with provenance (no judgment word, no composite score); the cutoff is
  human-set, with an explicit conservative option (judge on the CI upper bound).
- `verification/approval_governance.py` — defeats the approval spam/fatigue attack
  (designed with Meta): content-blind per-window approval cap, bundling so a split
  500x1 buys nothing, and delta surfaced as a fact. A second approver is required
  ONLY from a human-authored threshold, never inferred — no severity-ranking in UX.

Tests: `test_second_reader.py` (19), `test_keepers.py` (15),
`test_interpretation_guard.py` (8), `test_integrity_invariance.py` (12),
`test_approval_governance.py` (16), `test_clarification_gate.py` (10).
Suite at the close of this release: **1745 tests / 63 files**, all green — the figure
includes the two blocks that landed after this entry was first drafted (`challenger.py`,
84 tests; `effect_guard.py`, 26). A changelog entry is a historical record, so a pinned
number belongs here; everywhere else, run `bash scripts/count_tests.sh`.

Interface — ask, don't guess
- `verification/clarification_gate.py` — "tell it your goal and let it ask." When a
  request is underspecified AND impact is WRITE/ACT, the gate asks ONE human-authored
  question instead of silently guessing; low-impact reads get a stated default, no
  nag. What is missing is verifier-derived (a planner cannot bypass by claiming
  completeness); an answer fills only the asked slot. The interface side of the
  reverse-centaur: the machine meets loose human speech and asks, rather than forcing
  the person into lawyer-precise input.

Red-team hardening (3-model review; the convergent finding was that thresholds were
solid but the VALUES fed to them were planner-owned)
- Irreversible count is now verifier-DERIVED from declared operations via a
  verifier-owned classifier — never accepted from the caller (defeats count
  sandbagging).
- A harm estimate must be `verifier_sourced` or it is REFUSED at the threshold — a
  planner-supplied estimate cannot drive a human cutoff.
- Authorized objective changes bind from-hash → to-hash + nonce and burn the nonce —
  no replay, no replay-to-revert.
- Invariant presence is read from a verifier-owned `InvariantRegistry` (checks that
  actually ran), not a planner-supplied set.
- `THREAT_BOUNDARIES.md` §0 states the principle — no machine-generated value may
  drive a human threshold unless verifier-derived — and names what stays deployment-
  owned (classifier/estimator integrity, restart/parallel state, sliding window,
  global multi-human budget, key management). No faked in-module fixes.

Docs synced
- README headline corrected (was "427 tests. 12 modules."), DRIFTCORE.md operator
  command corrected (was "expect 625 / 18"), REVIEW_PHASE_B.md given a dated
  snapshot banner rather than rewriting its Phase-B history. Honest module tally:
  19 subsystems / 64 implementation modules under `driftcore/`.

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
