# MANUS HANDOFF — v4.5.0 integration block (post-red-team round 1)

**State: 1228 tests passing across 46 test files.** Run `bash scripts/count_tests.sh` to verify before committing.

## Changed files
- `driftcore/verification/coordinator.py` — v4.5.0 stages wired as opt-in (objective-integrity preflight, clarification, interpretation, proportionate-response/mercy ladder, harm estimate), bounded autonomy (max_cycles + re_ratify), authorized-egress policy (ratified targets, per-call derivation, no self-authorization channel), durable/cross-instance state hooks, strict_v45 mode, ctx hygiene (underscore keys stripped from caller input).
- `driftcore/verification/harm_estimate.py` — added provenance-agnostic `would_exceed`; verified/unverified asymmetry.
- `driftcore/profiles/__init__.py` — new `repeating_tasks` profile (coordinator block: objectives, allowed_effects, tool_effects, authorized_targets, owner, reratify_every).
- `driftcore/profiles/coordinator_builder.py` — NEW: profile → configured coordinator bridge, capability-allowlist guard builder.
- `driftcore/verification/authorization_state.py` — NEW: durable, hash-chained, cross-instance store for burned nonces + cycle budget (closes replay-across-restart and the 8-agents/8-budgets hole).
- `driftcore/verification/review_router.py` — NEW: the human-review path; composes ApprovalThrottle (fatigue cap, anti-split) + SecondReaderGate (commit-before-reveal, workload floor).
- `THREAT_BOUNDARIES.md` — new §7 (sequences + cognition frontier: cumulative harm, social manipulation, semantic drift, cognitive integrity, outside-ontology), updated PROPOSED note.

## New test files
- `test_coordinator_v45_integration.py` (53 checks)
- `test_repeating_tasks_profile.py` (18)
- `test_authorization_state.py` (14)
- `test_multi_instance_state.py` (5)
- `test_review_router.py` (14)

## Deliberately NOT changed (do not "fix")
- Version strings still 4.1.x in README / `__init__.py` — parked until Justin's red-team passes, then flip with the status language in one commit.
- `calibration.py`, `consequence_projection.py` remain PROPOSED / unwired.
- No CI config added yet.

## Suggested branch
`assistant/v4.5.0-integration-hardening` per the existing commit plan.
