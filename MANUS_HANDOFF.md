# MANUS HANDOFF — Montreal-readiness pass (safety case, README front door, cleanup, LawZero framing)

**State: 1433 tests passing across 55 test files.** Verify with `bash scripts/count_tests.sh`.

## New/changed in THIS block — ADD these as new files (a zip cannot signal additions)
- `THE_FAMILY_TABLE.md` — NEW. Plain-language front door: the 15 rules for a safe household robot, each mapped to enforced machinery. (Human-facing; strongest thing for a newcomer/reviewer to read first.)
- `SAFETY_CASE.md` — NEW. One-page assurance breakdown: TIER 1 interlock (real guarantees) / TIER 2 backstop (foolable, adopt-don't-build) / TIER 3 open frontier (named, not solved) + explicit "what we do NOT claim."
- `DRIFTCORE_X_LAWZERO.md` — NEW. Pitch framing: DriftCore as the deterministic legible-rules FLOOR beneath LawZero's learned Scientist-AI monitor (complementary, not competing); consequence-invariance convergence as the hook; review-first ask; no overclaiming.
- `eval_harness.py` + `EVAL_HARNESS_README.md` — the existence proof (already delivered; now improved with a CONTROL row proving the guard discriminates rather than rubber-stamps, and dead coordinator code removed).
- Also still-to-add from prior blocks: `TO_WHATEVER_READS_THIS_NEXT.md`, `GOVERNED_LEARNING_LOOP.md`, `WHY_MACHINE_ERA_BANK_SECURITY.md`, `WHY_DRIFTCORE_MATTERS_MORE_WITH_SENSORY_LEARNING.md`, `DRIFTCORE_SESSION_HARNESS.md`.

## CHANGED (Manus overwrites)
- `README.md` — the 15 rules woven into the opening as a front door + pointer to THE_FAMILY_TABLE.md. NOTE: the README still contains an OLD quickstart claiming "1124 tests across 41 files" and listing individual old test files — this should be corrected to "1433 tests / 55 files" and `bash scripts/count_tests.sh` as the canonical runner. (Flagged; not yet rewritten in full.)
- `.gitignore` — extended to cover root-level runtime artifacts.

## RUNTIME-ARTIFACT CLEANUP (do this with git, not a zip re-apply)
These are runtime state that keeps riding into commits. Remove from tracking (keep locally):
  git rm --cached driftcore_daily_budget.json driftcore_spent_tokens.json
  git rm --cached -r logs/  data/   2>/dev/null || true
  git rm --cached logs/*.jsonl 2>/dev/null || true
The updated .gitignore now covers *_spent_tokens.json, *_daily_budget.json, *.jsonl, logs/, data/.

## Suggested branch
assistant/montreal-readiness
