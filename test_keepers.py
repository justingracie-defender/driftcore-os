"""
test_keepers.py — THE THREE KEEPERS FROM THE SECOND RED-TEAM PASS
================================================================
STATUS: PROPOSED. Pins:
  B. disagreement-scoring (who was right WHEN they disagreed)
  C. blind-vs-assisted decay detection
  +  beat-either-alone skill comparison
  D. consequence projection: both branches required, no smuggled verdict

Run with:  python test_keepers.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.second_reader import Disposition as D
from driftcore.verification.calibration import CalibrationLedger, CaseOutcome
from driftcore.verification.consequence_projection import project, ProjectionError

results = []
def check(n, c):
    print(f"  {'ok' if c else 'XX'}: {n}")
    results.append((n, bool(c)))


# ── Idea B: score disagreement, not agreement ───────────────────────────────
L = CalibrationLedger(min_cases=3)
# below threshold -> no claim
L.record(CaseOutcome("c0", D.SUSPICIOUS, ai=D.CLEAR, truth=D.SUSPICIOUS))
check("disagreement metric is INSUFFICIENT below the case floor",
      not L.disagreement_correctness().sufficient)
# enough disagreements: human right 3, ai right 1 of 4
L.record(CaseOutcome("c1", D.SUSPICIOUS, ai=D.CLEAR, truth=D.SUSPICIOUS))  # human right
L.record(CaseOutcome("c2", D.CLEAR, ai=D.SUSPICIOUS, truth=D.CLEAR))       # human right
L.record(CaseOutcome("c3", D.CLEAR, ai=D.SUSPICIOUS, truth=D.SUSPICIOUS))  # ai right
t = L.disagreement_correctness()
check("disagreement metric reports once enough disagreements have known truth",
      t.sufficient and t.n == 4)
check("human-right share is computed over disagreements only (3/4)",
      abs(t.value - 0.75) < 1e-9)
# agreements never enter the disagreement metric
L.record(CaseOutcome("a1", D.CLEAR, ai=D.CLEAR, truth=D.CLEAR))
check("agreements do not pad the disagreement metric", L.disagreement_correctness().n == 4)


# ── Idea C: blind vs assisted decay ─────────────────────────────────────────
M = CalibrationLedger(min_cases=3)
# assisted committed reads: 3/3 correct.  blind: 1/3 correct -> human leans on backstop
for i in range(3):
    M.record(CaseOutcome(f"as{i}", D.SUSPICIOUS, ai=D.SUSPICIOUS,
                         truth=D.SUSPICIOUS, blind=False))
M.record(CaseOutcome("b0", D.CLEAR, truth=D.SUSPICIOUS, blind=True))   # wrong
M.record(CaseOutcome("b1", D.CLEAR, truth=D.SUSPICIOUS, blind=True))   # wrong
M.record(CaseOutcome("b2", D.SUSPICIOUS, truth=D.SUSPICIOUS, blind=True))  # right
g = M.blind_vs_assisted()
check("blind-vs-assisted needs both pools -> reports when both are present", g.sufficient)
check("a positive gap surfaces backstop-leaning / decay (assisted > blind)", g.value > 0)

M2 = CalibrationLedger(min_cases=3)
for i in range(3):
    M2.record(CaseOutcome(f"x{i}", D.SUSPICIOUS, ai=D.SUSPICIOUS, truth=D.SUSPICIOUS, blind=False))
check("only assisted cases, no blind -> INSUFFICIENT (can't detect decay yet)",
      not M2.blind_vs_assisted().sufficient)


# ── beat either one alone ───────────────────────────────────────────────────
T = CalibrationLedger(min_cases=3)
# human alone 2/3, ai alone 1/3, team (resolved) 3/3
T.record(CaseOutcome("t0", D.SUSPICIOUS, ai=D.CLEAR, resolved=D.SUSPICIOUS, truth=D.SUSPICIOUS))
T.record(CaseOutcome("t1", D.CLEAR, ai=D.CLEAR, resolved=D.SUSPICIOUS, truth=D.SUSPICIOUS))
T.record(CaseOutcome("t2", D.SUSPICIOUS, ai=D.SUSPICIOUS, resolved=D.SUSPICIOUS, truth=D.SUSPICIOUS))
human, ai, team = T.skill_comparison()
check("skill comparison yields human-alone, ai-alone, team",
      human.sufficient and ai.sufficient and team.sufficient)
check("team accuracy can exceed either alone (the actual goal)",
      team.value >= max(human.value, ai.value))


# ── Idea D: consequence projection ──────────────────────────────────────────
p = project(
    authorize_facts=("247 records change", "12 irreversible", "rollback available"),
    refuse_facts=("no records change", "workflow pauses"),
)
check("projection carries both branches as facts",
      p.authorize.facts and p.refuse.facts)
check("projection dataclass has no recommendation field",
      not hasattr(p, "recommendation"))
check("as_lines renders both branches", any("If refused:" in l for l in p.as_lines()))

try:
    project(authorize_facts=("247 records change",), refuse_facts=())
    check("omitting the refuse branch is refused", False)
except ProjectionError:
    check("omitting the refuse branch is refused", True)

try:
    project(authorize_facts=("Recommended: proceed",), refuse_facts=("workflow pauses",))
    check("an obvious smuggled verdict ('recommended') is refused", False)
except ProjectionError:
    check("an obvious smuggled verdict ('recommended') is refused", True)

try:
    project(authorize_facts=("operational_index 0.8",), refuse_facts=("workflow pauses",))
    check("a renamed smuggled verdict ('operational_index') is refused", False)
except ProjectionError:
    check("a renamed smuggled verdict ('operational_index') is refused", True)


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
