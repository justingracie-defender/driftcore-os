# Commit plan — v4.5.0 (Two-Ended Drift + LawZero-informed + red-team hardened)

Branch: assistant/two-ended-drift-v4.5.0   (all new files + doc sync, one block)
Target: PR to main. Read the diff against this manifest before merge. Merge yourself.

## NEW modules — 9 (land at EXACTLY these paths; no -1/-2 suffixes)
driftcore/verification/second_reader.py            # anti-reverse-centaur gate
driftcore/verification/calibration.py              # disagreement-scoring + blind-case decay
driftcore/verification/consequence_projection.py   # both-branches facts, no recommendation
driftcore/verification/interpretation_guard.py     # legible reading-distribution guard
driftcore/verification/consequence_invariance.py   # prove a verdict is outcome-blind
driftcore/verification/objective_integrity.py      # mission integrity, replay-proof + registry-derived
driftcore/verification/harm_estimate.py            # P(harm)+CI as fact; verifier-sourced only
driftcore/verification/approval_governance.py      # anti-spam; irreversible count verifier-derived
driftcore/verification/clarification_gate.py       # ask one question instead of guessing

## NEW tests — 6
test_second_reader.py            (19)
test_keepers.py                  (15)
test_interpretation_guard.py     (8)
test_integrity_invariance.py     (12)
test_approval_governance.py      (16)
test_clarification_gate.py       (10)

## NEW docs — 2
TWO_ENDED_DRIFT.md
THREAT_BOUNDARIES.md     # includes §0 input-integrity principle + deployment-owned items

## MODIFIED — 3 (overwrite in place; already exist)
README.md            # -> points at scripts/count_tests.sh (no hardcoded count)
DRIFTCORE.md         # operator command: run scripts/count_tests.sh
CHANGELOG.md         # v4.5.0 entry
# (REVIEW_PHASE_B.md dated banner carried from the prior package.)

## DO NOT TOUCH
scripts/count_tests.sh

## Post-merge verification (the only proof that counts)
bash scripts/count_tests.sh
# GATE: exit 0, and NO "WARNING: N file(s) did not report all-passing" line.
# Do NOT gate on a literal count. This plan previously expected "1695 across 62";
# two blocks landed after it was written (challenger.py +84, effect_guard.py +26)
# and a correct merge would have failed its own gate. The count is an OUTPUT to
# record in the PR description, not a precondition to match.
# The count must not DROP: compare against the pre-merge run on the same checkout.

## Notes
- ALL nine modules are PROPOSED: stdlib-only, tested in isolation, NOT wired into
  the coordinator. Do not present them as shipped.
- Design line held throughout: the system never infers severity, and no
  machine-generated value drives a human threshold unless verifier-derived.
- Hardened after a 3-model red team. Real fixes landed in code; deployment-owned
  attacks (key mgmt, restart/parallel state, sliding window, global budget) are
  named in THREAT_BOUNDARIES §0, not faked.
