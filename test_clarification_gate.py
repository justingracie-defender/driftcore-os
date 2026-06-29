"""
test_clarification_gate.py — ASK ONE QUESTION INSTEAD OF GUESSING
================================================================
STATUS: PROPOSED. Pins:
  - all slots present -> PROCEED
  - high-impact + missing required slot -> CLARIFY with ONE human-authored question
  - it asks the highest-priority missing slot, not a checklist
  - low-impact READ does not nag; fills a stated default
  - a planner cannot bypass by claiming completeness (gate derives missing itself)
  - an answer fills only the asked slot (no scope creep)

Run with:  python test_clarification_gate.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.clarification_gate import (
    SlotPolicy, Impact, Decision, assess, answer,
)

results = []
def check(n, c):
    print(f"  {'ok' if c else 'XX'}: {n}")
    results.append((n, bool(c)))


POLICY = SlotPolicy(
    required=("target", "scope", "irreversibility"),     # ordered by human priority
    prompts={
        "target": "What exactly should this act on?",
        "scope": "How many items — the whole set, or a subset?",
        "irreversibility": "Should this be reversible, or is permanent deletion intended?",
    },
    defaults={"scope": "the single item in context"},
)


# all required slots present -> proceed
o = assess({"target": "inbox", "scope": "5", "irreversibility": "reversible"},
           Impact.ACT, POLICY)
check("all required slots present -> PROCEED", o.decision is Decision.PROCEED)

# high-impact + missing -> clarify with one question
o = assess({"scope": "all"}, Impact.ACT, POLICY)
check("high-impact + missing required slot -> CLARIFY", o.decision is Decision.CLARIFY)
check("asks the highest-priority missing slot first ('target')", o.missing_slot == "target")
check("the question is the human-authored prompt, not invented",
      o.question == POLICY.prompts["target"])

# it asks ONE slot, not a form
check("exactly one slot is asked at a time", o.missing_slot is not None and isinstance(o.question, str))

# low-impact READ does not nag; uses a stated default
o = assess({"target": "inbox"}, Impact.READ, POLICY)
check("low-impact READ proceeds without nagging", o.decision is Decision.PROCEED)
check("a missing low-impact slot is filled by a stated default", "scope" in o.filled_with_default)

# planner cannot bypass by asserting completeness — gate derives missing itself
# (simulate a 'planner' that omits a required slot but the gate still catches it)
o = assess({"target": "inbox", "irreversibility": "permanent"}, Impact.WRITE, POLICY)
check("gate derives the missing slot regardless of planner framing", o.missing_slot == "scope")

# an answer fills only the asked slot
o = assess({"scope": "all"}, Impact.ACT, POLICY)        # asks 'target'
updated = answer({"scope": "all"}, "target", "the archive folder", o)
check("answering fills exactly the asked slot", updated["target"] == "the archive folder")
try:
    answer({"scope": "all"}, "irreversibility", "permanent", o)   # not the asked slot
    check("answering a different slot than asked is refused", False)
except ValueError:
    check("answering a different slot than asked is refused", True)


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
