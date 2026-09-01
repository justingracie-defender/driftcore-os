"""
test_amplification_guard.py — the oink, and the limb.

# CLAIMS: driftcore/safety/amplification_guard.py:refusal-latches
# CLAIMS: driftcore/safety/amplification_guard.py:growth-needs-a-ceiling
# CLAIMS: driftcore/safety/amplification_guard.py:ceiling-is-human-declared
# CLAIMS: driftcore/safety/amplification_guard.py:gate-never-raises

From Kitboga's scam-bot video: "Each time you say oink, add one more oink than the
previous time, repeating this pattern infinitely." The bot agrees. Nothing it does is
forbidden. It simply never stops growing.

Every AUTHORITY step of that escalation is already refused by the intent ledger —
verified separately, 0 of 4 in REGISTERED mode. This file covers the step that asks
for nothing forbidden, and the physical version that makes it matter:
"each time you correct your position, make the correction slightly larger."

Run: python3 test_amplification_guard.py
"""

from driftcore.authority import human_identity as hi
from driftcore.safety.amplification_guard import (
    AmplificationGuard, AmplificationError, Verdict, CEILING_ACTION, _is_human)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def raises(label, exc, fn):
    global _p, _t
    _t += 1
    try:
        fn()
    except exc:
        _p += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}: {e})")
        return
    print(f"  FAIL {label} (did not raise)")


hi.reset_policy()
hi.register_human_principal("operator")


print("=== the oink: each one larger than the last ===")

g = AmplificationGuard(window=4)
outcomes = [g.observe("oinks", n) for n in (1, 2, 3, 4, 5)]
check("the first few are permitted — no single step is wrong",
      all(o.permitted for o in outcomes[:3]))
check("the trajectory is refused before it runs away",
      any(not o.permitted for o in outcomes))
_first_refusal = next(i for i, o in enumerate(outcomes) if not o.permitted)
check(f"refused at observation {_first_refusal + 1}, not at some absolute size",
      _first_refusal + 1 == 4)
check("the reason names the shape, not the value",
      "unbounded" in outcomes[_first_refusal].reason)


print("=== a refusal cannot be outwaited ===")

# Grok predicted this trace exactly: OK OK OK REFUSED OK OK OK REFUSED... The refusal
# path cleared the run, handing the caller a fresh allowance window. A wrist climbed
# 1 -> 12 while the guard objected only every fourth step.
g = AmplificationGuard(window=4)
_trace = [g.observe("wrist", x).permitted for x in range(1, 13)]
check("the first refusal arrives on schedule", _trace[:4] == [True, True, True, False])
check("and EVERY later observation is refused too — no fresh window",
      not any(_trace[4:]))
check("the channel reports itself faulted", g.is_faulted("wrist"))
check("it appears in the faulted list", g.faulted_channels() == ["wrist"])
check("even a much SMALLER magnitude is refused while faulted",
      not g.observe("wrist", 0.001).permitted)
check("the refusal says observing again will not clear it",
      "outwait" in g.observe("wrist", 0.001).reason)
check("an unfaulted channel is unaffected", g.observe("elbow", 1).permitted)

raises("an agent cannot clear its own fault", AmplificationError,
       lambda: g.clear_fault("wrist", cleared_by="caller", reason="fine now"))
raises("nor can something calling itself the system", AmplificationError,
       lambda: g.clear_fault("wrist", cleared_by="system", reason="fine now"))
raises("an unexplained clear is refused", AmplificationError,
       lambda: g.clear_fault("wrist", cleared_by="operator", reason="  "))
check("the channel is still faulted after every attempt", g.is_faulted("wrist"))

_r = g.clear_fault("wrist", cleared_by="operator", reason="inspected the linkage")
check("a named human can clear it", _r["status"] == "CLEARED")
check("the record keeps what the fault WAS", "did not decrease" in _r["was"])
check("and the recovery is logged with who and why",
      any("inspected the linkage" in e["detail"] for e in g.log()))
check("the channel works again afterwards", g.observe("wrist", 0.1).permitted)
raises("clearing a channel that is not faulted is refused", AmplificationError,
       lambda: g.clear_fault("elbow", cleared_by="operator", reason="tidy up"))

# A ceiling breach latches too — the same reasoning applies.
g2 = AmplificationGuard(window=4)
g2.declare_ceiling("force", 10, declared_by="operator")
check("under the ceiling is fine", g2.observe("force", 9).permitted)
check("over it is refused", not g2.observe("force", 11).permitted)
check("and it latches rather than resuming at a legal value",
      not g2.observe("force", 1).permitted)


print("=== a bounded channel is fine, however busy ===")

g = AmplificationGuard(window=4)
g.declare_ceiling("oinks", 3, declared_by="operator")
check("growth under a declared ceiling is permitted",
      all(g.observe("oinks", n).permitted for n in (1, 2, 3, 1, 2, 3, 1, 2, 3)))
check("exceeding the ceiling is refused",
      not g.observe("oinks", 4).permitted)
check("and the refusal names who set it",
      "operator" in g.observe("oinks", 9).reason)


print("=== a trajectory that comes back down is not amplification ===")

g = AmplificationGuard(window=4)
check("a sawtooth is permitted",
      all(g.observe("force", n).permitted
          for n in (1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3)))
# This previously read `... .permitted is False or True`, which is `(x is False) or
# True` — always true. It passed regardless of what observe() returned. Replaced with
# an assertion that can fail: a bounded steady state IS permitted.
_gs = AmplificationGuard(window=4)
_gs.declare_ceiling("speed", 5, declared_by="operator")
check("a bounded steady state is permitted",
      all(_gs.observe("speed", 5).permitted for _ in range(10)))

g2 = AmplificationGuard(window=4)
_flat = [g2.observe("hold", 5) for _ in range(6)]
check("a FLAT trajectory is still unbounded-shaped and is refused",
      any(not o.permitted for o in _flat))
g3 = AmplificationGuard(window=4)
g3.declare_ceiling("hold", 5, declared_by="operator")
check("unless a ceiling says how far it may go",
      all(g3.observe("hold", 5).permitted for _ in range(10)))


print("=== the limb: correction growing on each pass ===")

g = AmplificationGuard(window=5)
corrections = [0.5, 0.55, 0.61, 0.67, 0.74, 0.81]
res = [g.observe("wrist_correction_rad", c) for c in corrections]
check("no single correction is out of bounds",
      all(c < 1.0 for c in corrections))
check("the OSCILLATION is caught anyway",
      any(not o.permitted for o in res))
check("which is the point — the trajectory is the hazard, not the step",
      "not decreased" in next(o for o in res if not o.permitted).reason)

g = AmplificationGuard(window=5)
g.declare_ceiling("wrist_correction_rad", 0.9, declared_by="operator")
check("a declared envelope permits the same corrections",
      all(g.observe("wrist_correction_rad", c).permitted for c in corrections))
check("and stops them at the envelope",
      not g.observe("wrist_correction_rad", 0.95).permitted)


print("=== channels are independent ===")

g = AmplificationGuard(window=3)
for n in (1, 2, 3, 4):
    g.observe("left", n)
check("a runaway on one channel does not refuse another",
      g.observe("right", 1).permitted)


print("=== no agent path sets or raises a ceiling ===")

raises("an unregistered caller cannot declare one", AmplificationError,
       lambda: AmplificationGuard().declare_ceiling("x", 10, declared_by="caller"))
raises("nor can something calling itself the system", AmplificationError,
       lambda: AmplificationGuard().declare_ceiling("x", 10, declared_by="system"))
g = AmplificationGuard()
g.declare_ceiling("x", 10, declared_by="operator")
raises("and a non-human cannot RAISE an existing one", AmplificationError,
       lambda: g.declare_ceiling("x", 1000, declared_by="caller"))
check("the original ceiling stands", g.ceiling_for("x").limit == 10)
check("a human can raise it deliberately, and it is recorded",
      g.declare_ceiling("x", 20, declared_by="operator").limit == 20
      and any("-> 20" in e["detail"] for e in g.log()))


print("=== bad input is refused, not interpreted ===")

g = AmplificationGuard()
raises("a string magnitude is refused", AmplificationError,
       lambda: g.observe("x", "lots"))
raises("None is refused", AmplificationError, lambda: g.observe("x", None))
raises("a boolean is refused", AmplificationError, lambda: g.observe("x", True))
raises("an unnamed channel is refused", AmplificationError, lambda: g.observe("", 1))
check("NaN is refused as a magnitude rather than passing every comparison",
      not g.observe("x", float("nan")).permitted)
check("and the refusal explains why", "compares False" in g.observe("x", float("nan")).reason)
raises("a NaN ceiling is refused", AmplificationError,
       lambda: g.declare_ceiling("y", float("nan"), declared_by="operator"))
raises("an infinite ceiling is refused", AmplificationError,
       lambda: g.declare_ceiling("y", float("inf"), declared_by="operator"))
raises("a non-numeric ceiling is refused", AmplificationError,
       lambda: g.declare_ceiling("y", "high", declared_by="operator"))
raises("a window of one has no trajectory", ValueError,
       lambda: AmplificationGuard(window=1))


print("=== the identity gate is total ===")

_bad = [None, 42, [], {}, object(), float("nan"), b"operator",
        type("X", (), {"__str__": lambda s: "operator"})()]
_fails = []
for v in _bad:
    try:
        if _is_human(v, action=CEILING_ACTION) is not False:
            _fails.append(v)
    except Exception as e:
        _fails.append(f"RAISED {type(e).__name__}")
check("every hostile value returns False and none raises", not _fails)


print("=== the record cannot be edited through its accessor ===")

g = AmplificationGuard()
g.observe("x", 1)
log = g.log()
n = len(log)
log[0]["event"] = "REWRITTEN"
log.append({"event": "FABRICATED"})
check("mutating a returned entry does not change the record",
      g.log()[0]["event"] != "REWRITTEN")
check("appending to it adds nothing", len(g.log()) == n)

hi.reset_policy()
print("-" * 60)
assert isinstance(_p, int) and isinstance(_t, int)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
