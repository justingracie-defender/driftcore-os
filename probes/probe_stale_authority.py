"""Probe ChatGPT's question #6: can a security-relevant property change WITHOUT
advancing the generation, leaving the compare-and-swap satisfied but the
authorization stale?

Candidate: `self._restart_authority`. The rule (red-team #7) is that once a
RestartAuthority is installed, a HARD halt may ONLY be released through it. That
check is read at the top of release(). The generation counter tracks (active, level)
only. So if the authority is installed while a release is mid-flight, the gate was
evaluated as absent, the generation never moved, and the CAS passes.
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
# `_generation` is instrumentation added BY the fix, so it does not exist on the
# unfixed baseline. Read it defensively: a probe whose job is to indict the old tree
# must be able to RUN on the old tree. (Found by running it there — it crashed
# before reaching its verdict, which would have read as "no finding".)
gen_before = getattr(h, "_generation", None)
print("authority installed, halt-state generation unchanged:",
      gen_before if gen_before is not None
      else "(no generation counter on this tree — pre-fix)")

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
