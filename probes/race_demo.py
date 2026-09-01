"""Positive control: force the release()/hard_halt() race deterministically.

No scheduler luck. A blocking verifier holds thread A inside release()'s
decide-then-mutate window while the main thread raises a HARD halt.
"""
import sys, threading, time
sys.path.insert(0, "/home/claude/work/driftcore-os")

from driftcore.safety.safe_halt import SafeHalt
from driftcore.governance.restart_authority import ShutdownSeverity

# ---------- RACE 1: release() has no lock at all ----------
in_verifier = threading.Event()
may_return = threading.Event()

def slow_verifier(principal):
    in_verifier.set()          # thread A is now past the decision point
    may_return.wait(5)         # ...and paused before the mutation
    return True

h = SafeHalt(verifier=slow_verifier)
h.soft_halt()
print("RACE 1 — release() with no lock")
print("  start:                    ", h.status())

t = threading.Thread(target=lambda: h.release("operator_jane"))
t.start()
in_verifier.wait(5)            # A is inside the verifier, decision made
print("  A is mid-release, now hard_halt() from the main thread")
h.hard_halt()
print("  after hard_halt():        ", h.status())
may_return.set()
t.join()
print("  after A finishes:         ", h.status())
print("  VERDICT:", "RACE CONFIRMED — the HARD halt was erased"
      if not h.status()["active"] else "no race")

# ---------- RACE 2: release_with_approvals() drops the lock ----------
print()
print("RACE 2 — release_with_approvals() derives severity under lock,")
print("         then evaluates and mutates with the lock released")

in_eval = threading.Event()
eval_may_return = threading.Event()
seen_severity = []

class SlowAuthority:
    def evaluate(self, severity, approvals):
        seen_severity.append(severity)
        in_eval.set()
        eval_may_return.wait(5)
        return {"status": "AUTHORIZED", "reason": "ok",
                "approvals": [{"approver_id": "jane"}]}

h2 = SafeHalt(restart_authority=SlowAuthority())
h2.soft_halt()
print("  start:                    ", h2.status())

t2 = threading.Thread(target=lambda: h2.release_with_approvals([{"a": 1}]))
t2.start()
in_eval.wait(5)
print("  severity derived from SOFT:", seen_severity[0].name)
print("  now escalate to HARD while the authority is still evaluating")
h2.hard_halt()
print("  after hard_halt():        ", h2.status())
eval_may_return.set()
t2.join()
print("  after A finishes:         ", h2.status())
print("  VERDICT:", f"RACE CONFIRMED — a HARD halt cleared on "
      f"{seen_severity[0].name}-level approvals"
      if not h2.status()["active"] else "no race")
