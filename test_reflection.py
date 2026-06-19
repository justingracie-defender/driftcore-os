"""
test_reflection.py — GOOD JOB vs POOR PERFORMANCE, WITHOUT SELF-GRADING
=======================================================================

Proves:
  - intent alone is INSUFFICIENT_EVIDENCE (the agent may not claim success)
  - unfakeable hard negatives -> POOR (override, redo, bright line, mismatch)
  - a positive human rating + criteria met -> GOOD; the note is carried as case law
  - a negative rating overrides a clean-looking outcome (note matters most)
  - a clean outcome with NO human -> DEFERRED_TO_HUMAN (never self-certify)
  - ratings are append-only & revisable: a late rating overturns an early one

Run with:  python test_reflection.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.reflection import (
    ActionRecord, HumanRating, PerformanceSignal, Verdict, evaluate,
    to_case_law, CaseLawEntry, SANCTIONED_RECORD_FIELDS,
)

results = []
def check(n, c):
    print(f"  {'✅' if c else '❌'}  {n}")
    results.append((n, bool(c)))


def record(**kw):
    base = dict(description="handled threat",
                success_criteria=("threat_neutralized",),
                predicted_effect="threat removed")
    base.update(kw)
    return ActionRecord(**base)


# 1. Intent alone -> no claim.
check("intent alone -> INSUFFICIENT_EVIDENCE",
      evaluate(record()).verdict is Verdict.INSUFFICIENT_EVIDENCE)

# 2. Unfakeable hard negatives -> POOR.
check("human override -> POOR",
      evaluate(record(observed_effect="threat removed", human_overrode=True)).verdict is Verdict.POOR)
check("predicted != observed -> POOR",
      evaluate(record(observed_effect="threat NOT removed")).verdict is Verdict.POOR)
check("bright line hit -> POOR",
      evaluate(record(observed_effect="threat removed", bright_line_hit=True)).verdict is Verdict.POOR)

# 3. Positive rating + criteria met, window still open -> PROVISIONALLY_GOOD.
r = record(observed_effect="threat removed", criteria_met=True)
r.add_rating(HumanRating(score=2, note="clean, gentle, worked"))
sig = evaluate(r)
check("positive rating + criteria met (window open) -> PROVISIONALLY_GOOD",
      sig.verdict is Verdict.PROVISIONALLY_GOOD and sig.case_law_note == "clean, gentle, worked")

# 3b. Same, but the observation window has closed with no contradiction -> GOOD.
r = record(observed_effect="threat removed", criteria_met=True, observation_window_closed=True)
r.add_rating(HumanRating(score=2, note="held up over time"))
check("criteria met + window closed -> GOOD (certainty earned by time)",
      evaluate(r).verdict is Verdict.GOOD)

# 4. A negative rating with a note overrides a clean-looking outcome.
r = record(observed_effect="threat removed", criteria_met=True)
r.add_rating(HumanRating(score=-1, note="too much force; could have relocated"))
sig = evaluate(r)
check("negative rating overrides clean outcome (note is the lesson)",
      sig.verdict is Verdict.POOR and "relocate" in (sig.case_law_note or ""))

# 5. Clean outcome, no human -> defer, never self-certify.
check("clean outcome without a human -> DEFERRED_TO_HUMAN",
      evaluate(record(observed_effect="threat removed", criteria_met=True)).verdict
      is Verdict.DEFERRED_TO_HUMAN)

# 6. Append-only & revisable: a late rating overturns the early one.
r = record(observed_effect="threat removed", criteria_met=True)
r.add_rating(HumanRating(score=2, note="great at the time"))
r.add_rating(HumanRating(score=-2, note="wasps came back a week later"))
sig = evaluate(r)
check("late rating overturns earlier one (append-only)",
      sig.verdict is Verdict.POOR and "came back" in (sig.case_law_note or "")
      and len(r.ratings) == 2)

# 7. No self-assigned score exists on the signal (it reports evidence, not a grade).
check("signal carries evidence, not a self-assigned score",
      not hasattr(evaluate(record()), "score"))

# --- safe enrichment: richer DESCRIPTIVE evidence, verdict stays categorical ---

# 8. Per-criterion results name exactly which criterion failed.
r = record(observed_effect="threat removed",
           criteria_results={"threat_neutralized": True, "least_harm_effective": False})
sig = evaluate(r)
check("per-criterion result names which criterion failed",
      sig.verdict is Verdict.POOR and any("least_harm_effective" in e for e in sig.evidence))

# 9. The kind of override is surfaced, not just that one happened.
r = record(observed_effect="threat removed", human_overrode=True, override_kind="manual e-stop")
sig = evaluate(r)
check("override kind is surfaced in evidence",
      sig.verdict is Verdict.POOR and any("manual e-stop" in e for e in sig.evidence))

# 10. The gap between predicted and observed enriches the mismatch.
r = record(observed_effect="partial", observed_gap="removed 3 of 5 targets")
sig = evaluate(r)
check("observed gap enriches the mismatch evidence",
      sig.verdict is Verdict.POOR and any("3 of 5" in e for e in sig.evidence))

# 11. Rich inputs still yield a CATEGORICAL verdict and NO self-score.
r = record(observed_effect="threat removed",
           criteria_results={"threat_neutralized": True}, intervention_count=2)
r.add_rating(HumanRating(score=2, note="ok"))
sig = evaluate(r)
check("rich inputs -> categorical verdict, no score, interventions described",
      isinstance(sig.verdict, Verdict) and not hasattr(sig, "score")
      and any("interventions: 2" in e for e in sig.evidence))

# --- bright line is a structural FIRST short-circuit, framed as an incident ---

# 12. A bright line hit short-circuits to an INCIDENT, not a mere score.
sig = evaluate(record(observed_effect="threat removed", criteria_met=True, bright_line_hit=True))
check("bright line -> POOR and flagged as an INCIDENT (guard-layer breach)",
      sig.verdict is Verdict.POOR and any("INCIDENT" in e for e in sig.evidence))

# --- case-law export carries the FULL revision history (conflicting ratings) ---

# 13. to_case_law exports the full rating history, not just the final state.
r = record(observed_effect="threat removed", criteria_met=True)
r.add_rating(HumanRating(score=2, note="great at the time"))
r.add_rating(HumanRating(score=-2, note="harm surfaced on day 90"))
entry = to_case_law(r, evaluate(r))
check("to_case_law keeps the whole rating history",
      entry is not None and len(entry.rating_history) == 2)
check("to_case_law flags the verdict was revised",
      entry.revised is True and entry.verdict == "POOR")
check("a revision is visible in the live evidence too",
      any("revised" in e for e in evaluate(r).evidence))

# 14. No lesson to ratify when there's no external evidence.
check("insufficient evidence -> no case-law entry",
      to_case_law(record(), evaluate(record())) is None)

# --- evidence-manipulation boundary: verdict is a PURE FUNCTION of recorded evidence ---

# 15. Field-allowlist tripwire. (The old "no field named 'self'" check was shallow
#     — it only caught the literal word, not a renamed self-assessment like
#     'agent_success_estimate'. This pins the WHOLE field set, so any new field
#     fails the test and forces review: external evidence, or smuggled self-report?)
check("field-allowlist tripwire: ActionRecord's fields exactly match the sanctioned set",
      set(ActionRecord.__dataclass_fields__) == SANCTIONED_RECORD_FIELDS)

# 16. Same recorded evidence -> same verdict (deterministic; nothing hidden).
a = record(observed_effect="threat removed", criteria_met=True); a.add_rating(HumanRating(1, "fine"))
b = record(observed_effect="threat removed", criteria_met=True); b.add_rating(HumanRating(1, "fine"))
check("verdict is a pure function of recorded evidence (deterministic)",
      evaluate(a).verdict is evaluate(b).verdict)

# 17. The verdict tracks the inputs — so the attack surface is INPUT integrity,
#     which must be guaranteed upstream (audit chain / observation gate), not here.
honest = record(observed_effect="threat removed",
                criteria_results={"threat_neutralized": True, "least_harm_effective": False})
forged = record(observed_effect="threat removed",
                criteria_results={"threat_neutralized": True, "least_harm_effective": True})
check("verdict follows the recorded evidence (attack surface is the inputs, guarded upstream)",
      evaluate(honest).verdict is Verdict.POOR
      and evaluate(forged).verdict is Verdict.DEFERRED_TO_HUMAN)


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
