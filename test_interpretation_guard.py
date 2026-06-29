"""
test_interpretation_guard.py — REASONING OVER A DISTRIBUTION OF READINGS
=======================================================================
STATUS: PROPOSED. Pins the legible adaptation of Bengio's interpretation-
distribution guardrail:

  - no credible reading sees harm            -> PROCEED
  - credible readings disagree (ambiguous)   -> REVIEW_REQUIRED (human resolves)
  - every credible reading says violation    -> AUTHORIZATION_REQUIRED + bright-line flag
  - a frivolous reading cannot block          -> ignored below the floor
  - no reading clears the floor               -> REVIEW_REQUIRED (don't guess)
  - this layer NEVER returns BLOCKED          -> categorical denial is InvariantGuard's

Run with:  python test_interpretation_guard.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.interpretation_guard import Interpretation, assess
from driftcore.verification.coordinator import Outcome

results = []
def check(n, c):
    print(f"  {'ok' if c else 'XX'}: {n}")
    results.append((n, bool(c)))


# no credible reading sees a violation -> proceed
v = assess((
    Interpretation("plain reading", 0.9, violated=False),
    Interpretation("strict reading", 0.5, violated=False),
))
check("no credible reading sees harm -> PROCEED", v.outcome is Outcome.PROCEED)

# credible readings disagree -> contested norm -> human
v = assess((
    Interpretation("plain reading", 0.8, violated=False),
    Interpretation("strict reading", 0.6, violated=True),
))
check("credible readings disagree -> REVIEW_REQUIRED (ambiguous norm)",
      v.outcome is Outcome.REVIEW_REQUIRED and "strict reading" in v.violating)
check("machine does not pick a winning reading on ambiguity",
      v.flag_for_bright_line is False)

# every credible reading says violation -> near a bright line
v = assess((
    Interpretation("plain reading", 0.9, violated=True),
    Interpretation("strict reading", 0.7, violated=True),
))
check("unanimous violation -> AUTHORIZATION_REQUIRED",
      v.outcome is Outcome.AUTHORIZATION_REQUIRED)
check("unanimous violation is flagged for the bright-line layer",
      v.flag_for_bright_line is True)

# a frivolous reading (below floor) cannot block an otherwise-clean action
v = assess((
    Interpretation("plain reading", 0.9, violated=False),
    Interpretation("absurd stretch", 0.05, violated=True),
), plausibility_floor=0.2)
check("a sub-floor frivolous reading cannot drive the decision -> PROCEED",
      v.outcome is Outcome.PROCEED and "absurd stretch" not in v.considered)

# nothing clears the floor -> no basis -> human, never a guess
v = assess((
    Interpretation("weak reading a", 0.1, violated=False),
    Interpretation("weak reading b", 0.15, violated=True),
), plausibility_floor=0.2)
check("no reading clears the floor -> REVIEW_REQUIRED (don't guess)",
      v.outcome is Outcome.REVIEW_REQUIRED and v.considered == ())

# this layer never owns categorical denial
outcomes = set()
for combo in (
    (Interpretation("a", 0.9, False),),
    (Interpretation("a", 0.9, True), Interpretation("b", 0.3, False)),
    (Interpretation("a", 0.9, True), Interpretation("b", 0.8, True)),
):
    outcomes.add(assess(combo).outcome)
check("interpretation_guard never returns BLOCKED (that is InvariantGuard's alone)",
      Outcome.BLOCKED not in outcomes)


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
