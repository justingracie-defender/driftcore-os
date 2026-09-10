"""Positive control: force the release()/hard_halt() race deterministically.

No scheduler luck. A blocking verifier holds thread A inside release()'s
decide-then-mutate window while the main thread raises a HARD halt.
"""
import os, sys, threading
# (red-team 2026-09-01) This line used to hardcode an absolute path into the author's
# container, so the probe imported DriftCore from a fixed tree no matter which tree it
# was run in — §0f's "probe that scanned the wrong repository", committed inside the
# artifact whose whole job is verification. It failed in the direction that made the
# fix look good: every tree reported "no race", including the unfixed baseline.
# Resolve from THIS FILE's location instead, so the probe always tests the tree it
# ships in.
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(_root, "driftcore")):
    raise SystemExit(
        f"REFUSING TO RUN: no driftcore package at {_root!r}.\n"
        f"This probe resolves the tree from its OWN location, so it must sit in\n"
        f"<repo>/probes/. Run the copy in the repo's probes/ directory, not a\n"
        f"flattened copy elsewhere — a probe that imports the wrong tree reports\n"
        f"'no race' everywhere, which is how this exact bug hid once already.")
sys.path.insert(0, _root)

# (2026-09-09) An unconfigured process now REFUSES identity rather than accepting
# any name not on a six-word denylist. A probe verifies nobody, so it declares
# that — otherwise its own CONTROLS fail and the failure reads as a finding.
import driftcore.authority.human_identity as _identity_boot
_identity_boot.declare_label_only("probe: single process, no verifier installed")


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
