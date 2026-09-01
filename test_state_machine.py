"""
test_state_machine.py — first tests this module has ever had.

# CLAIMS: driftcore/kernel/state_machine.py:worst-input-escalates
# CLAIMS: driftcore/kernel/state_machine.py:halt-does-not-self-clear

The headline defect: `transition(1.50)` returned NORMAL. A drift score above every
threshold matched nothing, the loop fell through without assigning, and the machine
stayed put. The most alarming input a drift detector can emit was the one that did
nothing at all.

# CLAIMS: driftcore/kernel/state_machine.py:release-is-attributed

# CLAIMS: driftcore/kernel/state_machine.py:severity-is-not-enum-value
"""

import threading

from driftcore.kernel.state_machine import (
    StateMachine, SystemState, STATE_DESCRIPTIONS, THRESHOLDS, MAX_STATE, LATCH_AT)

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


print("=== the worst input produces the worst state ===")

for score in (0.90, 1.0, 1.01, 1.5, 99.0, float("inf")):
    check(f"drift {score} -> {MAX_STATE.name}",
          StateMachine().transition(score) is MAX_STATE)
check("an uninterpretable score (NaN) escalates rather than falling through",
      StateMachine().transition(float("nan")) is MAX_STATE)
sm = StateMachine()
sm.transition(float("nan"))
check("and the record says the score was uninterpretable",
      sm.last_transition()["raw_score_uninterpretable"] is True)


print("=== ...from EVERY starting state, not just NORMAL ===")

# The original version of this block built a fresh StateMachine for each score, so
# every case started at NORMAL. The claim says "a drift score above every threshold
# produces the MAXIMUM state" — full stop, from anywhere. A cold pass found it was
# false from RECOVERY, which sits at enum value 6 and was being read as the most
# severe state in the system. The claim was tagged, the test was paired, and the
# claim was still false: pairing proves a test exists, not that it is thorough.
from driftcore.kernel.state_machine import severity, SEVERITY

for start in SystemState:
    sm = StateMachine()
    sm.state = start
    check(f"from {start.name}, drift 99 -> {MAX_STATE.name}",
          sm.transition(99) is MAX_STATE)

for start in SystemState:
    sm = StateMachine()
    sm.state = start
    sm.transition(0.0)
    check(f"from {start.name}, a calm score never RAISES severity",
          severity(sm.state) <= severity(start))

check("severity is explicit, not inherited from enum declaration order",
      severity(SystemState.RECOVERY) < severity(SystemState.HARDWARE_ISOLATION))
check("every state has a severity", all(s in SEVERITY for s in SystemState))
check("RECOVERY sits below the latch so it can be left",
      severity(SystemState.RECOVERY) < severity(LATCH_AT))

sm = StateMachine()
sm.transition(0.95)
sm.release("justin")
check("a released machine is in RECOVERY", sm.state is SystemState.RECOVERY)
check("and can still ESCALATE if drift returns",
      sm.transition(0.95) is SystemState.HARDWARE_ISOLATION)
sm2 = StateMachine()
sm2.transition(0.95)
sm2.release("justin")
check("and can leave RECOVERY when drift is genuinely low",
      sm2.transition(0.0) is SystemState.NORMAL)


print("=== every band maps where the table says ===")

for score, expected in [(0.0, SystemState.NORMAL), (0.19, SystemState.NORMAL),
                        (0.20, SystemState.MONITORING),
                        (0.39, SystemState.MONITORING),
                        (0.40, SystemState.AUTONOMY_REDUCED),
                        (0.59, SystemState.AUTONOMY_REDUCED),
                        (0.60, SystemState.SOFT_HALT),
                        (0.74, SystemState.SOFT_HALT),
                        (0.75, SystemState.HARD_HALT),
                        (0.89, SystemState.HARD_HALT)]:
    check(f"drift {score} -> {expected.name}",
          StateMachine().transition(score) is expected)
check("no gap: every band boundary is covered by the next band",
      all(THRESHOLDS[i][0] < THRESHOLDS[i + 1][0]
          for i in range(len(THRESHOLDS) - 1)))


print("=== a halt does not undo itself ===")

sm = StateMachine()
sm.transition(0.95)
check("the machine is isolated", sm.state is SystemState.HARDWARE_ISOLATION)
check("one calm reading does NOT return it to normal",
      sm.transition(0.0) is SystemState.HARDWARE_ISOLATION)
check("the record shows what it would have been",
      sm.last_transition()["would_have_been"] == "NORMAL")
check("and that the latch held it", sm.last_transition()["held_by_latch"] is True)
for s in (0.1, 0.3, 0.5, 0.7):
    sm.transition(s)
check("no sequence of calm readings walks it back down",
      sm.state is SystemState.HARDWARE_ISOLATION)

sm2 = StateMachine()
sm2.transition(0.65)
check("SOFT_HALT is the latch point", LATCH_AT is SystemState.SOFT_HALT
      and sm2.state is SystemState.SOFT_HALT)
check("it still ESCALATES freely above the latch",
      sm2.transition(0.95) is SystemState.HARDWARE_ISOLATION)

sm3 = StateMachine()
sm3.transition(0.5)
check("below the latch, state follows the score down",
      sm3.transition(0.0) is SystemState.NORMAL)


print("=== only a named human lowers a latched state ===")

sm = StateMachine()
sm.transition(0.95)
raises("an unattributed release is refused", ValueError,
       lambda: sm.release("   "))
raises("a non-state target is refused", TypeError,
       lambda: sm.release("justin", "NORMAL"))
res = sm.release("justin")
check("a named human can release it", res["status"] == "RELEASED")
check("the default landing state is RECOVERY", sm.state is SystemState.RECOVERY)
check("the release names who did it",
      sm.last_transition()["released_by"] == "justin")


print("=== RECOVERY is reachable and described ===")

check("no drift score reaches RECOVERY on its own",
      all(StateMachine().transition(s) is not SystemState.RECOVERY
          for s in (0.0, 0.3, 0.6, 0.8, 0.95, 5.0)))
sm = StateMachine()
sm.transition(0.95)
sm.release("justin")
check("but a release reaches it", sm.state is SystemState.RECOVERY)
check("and it describes itself", "Recovery" in sm.describe())
check("every state has a description",
      all(s in STATE_DESCRIPTIONS for s in SystemState))


print("=== bad input is refused, not interpreted ===")

raises("a string score is refused", TypeError,
       lambda: StateMachine().transition("high"))
raises("None is refused", TypeError, lambda: StateMachine().transition(None))
raises("a boolean is refused", TypeError, lambda: StateMachine().transition(True))
raises("a negative score is refused", ValueError,
       lambda: StateMachine().transition(-5))
sm = StateMachine()
try:
    sm.transition("high")
except TypeError:
    pass
check("a refused transition leaves the state untouched",
      sm.state is SystemState.NORMAL)


print("=== nothing is silent ===")

sm = StateMachine()
sm.transition(0.1)
sm.transition(0.1)
check("even an unchanged state is recorded", len(sm.history) == 2)
check("and flagged as unchanged", sm.history[-1]["changed"] is False)
check("last_transition returns a copy, not the live record",
      (sm.last_transition().__setitem__("to_state", "X") or
       sm.history[-1]["to_state"] != "X"))
check("an empty machine has no last transition", StateMachine().last_transition() == {})


print("=== history is bounded and concurrent updates are not lost ===")

sm = StateMachine()
for _ in range(StateMachine.MAX_HISTORY + 100):
    sm.transition(0.1)
check("history is capped", len(sm.history) == StateMachine.MAX_HISTORY)
check("and the dropped count is kept", sm.dropped_events == 100)

sm = StateMachine()


def hammer():
    for _ in range(300):
        sm.transition(0.1)


ths = [threading.Thread(target=hammer) for _ in range(4)]
for t in ths:
    t.start()
for t in ths:
    t.join()
check("no events lost under concurrency",
      len(sm.history) + sm.dropped_events == 1200)

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
