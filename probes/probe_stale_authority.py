"""Probe ChatGPT's question #6: can a security-relevant property change WITHOUT
advancing the generation, leaving the compare-and-swap satisfied but the
authorization stale?

Candidate: `self._restart_authority`. The rule (red-team #7) is that once a
RestartAuthority is installed, a HARD halt may ONLY be released through it. That
check is read at the top of release(). The generation counter tracks (active, level)
only. So if the authority is installed while a release is mid-flight, the gate was
evaluated as absent, the generation never moved, and the CAS passes.
"""
import sys, threading
sys.path.insert(0, "/home/claude/work/session/driftcore-os")
from driftcore.safety.safe_halt import SafeHalt


class Authority:
    """The strong path. Refuses everything, so ANY release through it is denied."""
    def __init__(self):
        self.called = False

    def evaluate(self, severity, approvals):
        self.called = True
        return {"status": "DENIED", "reason": "no approvals supplied"}


entered = threading.Event()
may_return = threading.Event()


def slow_verifier(principal):
    entered.set()
    may_return.wait(5)
    return True


h = SafeHalt(verifier=slow_verifier)          # no RestartAuthority yet
h.hard_halt()
print("start:                       ", {k: v for k, v in h.status().items()
                                        if k in ("active", "level")})
print("restart_authority installed? ", h._restart_authority is not None)

result = []
t = threading.Thread(target=lambda: result.append(h.release("operator_jane")))
t.start()
entered.wait(5)
print("\nthread A is mid-release; the HARD/RestartAuthority gate was evaluated as ABSENT")

auth = Authority()
h._restart_authority = auth                    # deployment wiring completes mid-flight
gen_before = h._generation
print("authority installed, generation unchanged:", gen_before)

may_return.set()
t.join(5)

print("\nresult:      ", result[0][:70])
print("final state: ", {k: v for k, v in h.status().items()
                        if k in ("active", "level")})
print("authority ever consulted?", auth.called)
print()
if not h.status()["active"] and not auth.called:
    print("FINDING CONFIRMED — a HARD halt was released by the weak path while a "
          "RestartAuthority was installed. The generation counter did not move "
          "because (active, level) did not move. red-team #7 reopened through a "
          "timing window.")
else:
    print("no finding — the gate held")
