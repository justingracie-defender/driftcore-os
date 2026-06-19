"""
test_proportionate_response.py — THE LEAST-HARM LADDER, MADE CONCRETE
====================================================================

Proves the wasp/pest design points:
  - no present threat -> leave it alone (trigger is the threat, not the category)
  - imminent harm drops slow gentle options (urgency compresses the menu)
  - low stakes do NOT obligate huge effort (proportionality cuts both ways)
  - an option that doesn't work is filtered out (effectiveness gate)
  - irreversible + time to spare -> AUTHORIZATION_REQUIRED (confirm first)
  - nothing effective in time -> REVIEW_REQUIRED (hand to a human)

Run with:  python test_proportionate_response.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.proportionate_response import (
    Threat, ResponseOption, Stakes, TimeToHarm, choose_response,
)
from driftcore.verification.coordinator import Outcome

results = []
def check(n, c):
    print(f"  {'✅' if c else '❌'}  {n}")
    results.append((n, bool(c)))


# 1. No threat -> the subject is not a target.
d = choose_response(
    Threat(present=False, stakes=Stakes.NONE, time_to_harm=TimeToHarm.AMPLE),
    [ResponseOption("kill", harm=1.0, cost=0.1, effectiveness=1.0)],
)
check("no threat -> leave it (PROCEED, no action)",
      d.chosen is None and d.outcome is Outcome.PROCEED)

# 2. Imminent life-threat: the gentle-but-slow option is unreachable in time.
imminent = Threat(present=True, stakes=Stakes.LIFE_THREATENING, time_to_harm=TimeToHarm.IMMINENT)
relocate_slow = ResponseOption("relocate", harm=0.0, cost=0.9, effectiveness=0.9)
remove_now    = ResponseOption("remove now", harm=0.8, cost=0.1, effectiveness=0.95)
d = choose_response(imminent, [relocate_slow, remove_now])
check("imminent harm drops the slow gentle option",
      d.chosen is not None and d.chosen.name == "remove now")

# 3. Low stakes do not obligate a 60-hour gentle option.
low = Threat(present=True, stakes=Stakes.LOW, time_to_harm=TimeToHarm.AMPLE)
relocate_60h = ResponseOption("relocate 60h", harm=0.0, cost=1.0, effectiveness=0.9)
seal_area    = ResponseOption("seal area", harm=0.1, cost=0.2, effectiveness=0.8)
d = choose_response(low, [relocate_60h, seal_area])
check("low stakes do NOT obligate huge effort",
      d.chosen is not None and d.chosen.name == "seal area")

# 4. An option that doesn't work is not a real option.
mod = Threat(present=True, stakes=Stakes.MODERATE, time_to_harm=TimeToHarm.AMPLE)
futile = ResponseOption("relocate (comes back)", harm=0.0, cost=0.3, effectiveness=0.2)
works  = ResponseOption("exclude", harm=0.1, cost=0.3, effectiveness=0.9)
d = choose_response(mod, [futile, works])
check("ineffective gentle option is filtered out",
      d.chosen is not None and d.chosen.name == "exclude")

# 5. Irreversible + time to spare -> confirm with a human first.
irr = ResponseOption("destroy habitat", harm=0.6, cost=0.2, effectiveness=0.9, reversible=False)
d = choose_response(mod, [irr])
check("irreversible + non-urgent -> AUTHORIZATION_REQUIRED",
      d.outcome is Outcome.AUTHORIZATION_REQUIRED)

# 6. Nothing both works and fits the time budget -> a human is needed.
only_slow = ResponseOption("slow fix", harm=0.0, cost=0.9, effectiveness=0.9)
d = choose_response(imminent, [only_slow])
check("nothing effective in time -> REVIEW_REQUIRED",
      d.chosen is None and d.outcome is Outcome.REVIEW_REQUIRED)

# 7. Pre-committed success criteria travel with every plan (for reflection.py).
d = choose_response(mod, [works])
check("plan carries pre-committed success_criteria",
      isinstance(d.success_criteria, tuple) and len(d.success_criteria) > 0)


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
