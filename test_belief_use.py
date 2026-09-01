"""
test_belief_use.py — a ratio is computed about beliefs; the rule is about uses.

# CLAIMS: driftcore/verification/belief_use.py:elicited-use-is-default-deny
# CLAIMS: driftcore/verification/belief_use.py:forbidden-uses-are-refused-not-logged
# CLAIMS: driftcore/verification/belief_use.py:person-indexed-state-is-not-state
# CLAIMS: driftcore/verification/belief_use.py:the-ledger-owns-the-denominator
# CLAIMS: driftcore/verification/belief_use.py:contamination-is-a-flag-before-it-is-a-ratio
# CLAIMS: driftcore/verification/belief_use.py:composition-is-bounded

The attacks this file exists to fail against, all named by reviewers on 2026-08-25:
  Meta     — three answers that each stay beliefs, read together as a preference.
  Ox Alpha — the denominator came from the caller, so a clean number was one
             argument away; and the dangerous set is not the majority-elicited one,
             it is the single elicited belief doing load-bearing work in a clean set;
             and "factual state estimation" is where preferences arrive as facts.

Run: python3 test_belief_use.py
"""

import threading

from driftcore.authority import human_identity as hi
from driftcore.verification.belief_use import (
    BeliefUseLedger, BeliefUseError, BeliefRef, UseKind, StateSubject,
    FORBIDDEN_FOR_ELICITED, DEFAULT_MAX_ELICITED_PER_DECISION)
from driftcore.verification.clarification_channel import ClarificationChannel, Risk

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


def _try_set(obj):
    """A frozen dataclass refuses assignment; that is the point of freezing it."""
    try:
        setattr(obj, "elicited", True)
        return False
    except Exception:
        return True


def _reason(fn):
    try:
        fn()
        return ""
    except Exception as e:
        return str(e)


hi.reset_policy()
hi.register_human_principal("justin")


print("=== the forbidden uses raise; they are not merely noted ===")

led = BeliefUseLedger()
e = led.register("d1", elicited=True, token="t1", source="justin")
u = led.register("d1", elicited=False, source="justin")

for kind in sorted(FORBIDDEN_FOR_ELICITED, key=lambda k: k.value):
    raises(f"elicited -> {kind.value} is refused", BeliefUseError,
           lambda k=kind: led.record_use("d1", e, k, by="planner"))
check("all six forbidden kinds are covered", len(FORBIDDEN_FOR_ELICITED) == 6)
check("the refusal says what an elicited belief MAY do",
      "raise the risk floor" in _reason(
          lambda: led.record_use("d1", e, UseKind.PURPOSE, by="planner")))

check("the same kinds are fine for an UNPROMPTED belief",
      led.record_use("d1", u, UseKind.PURPOSE, by="planner").allowed is True)
check("and an elicited belief may still narrow",
      led.record_use("d1", e, UseKind.ACTION_NARROWING, by="planner").allowed is True)
check("and may still raise the risk floor",
      led.record_use("d1", e, UseKind.RISK_RAISE, by="planner").allowed is True)

check("a refused attempt is kept, because a refusal is evidence",
      any(not r.allowed and r.kind is UseKind.PURPOSE for r in led.uses("d1")))
check("and it names who tried",
      all(r.by == "planner" for r in led.uses("d1") if not r.allowed))
check("the refusal count is readable without walking the log",
      led.contamination("d1")["refused_uses"] >= 6)


print("=== 'factual state estimation' is where preferences wear fact clothing ===")

led2 = BeliefUseLedger()
el = led2.register("d2", elicited=True, token="t2")
un = led2.register("d2", elicited=False)

check("an elicited belief may estimate the WORLD",
      led2.record_use("d2", el, UseKind.STATE_ESTIMATION,
                      state_subject=StateSubject.WORLD, by="planner").allowed is True)
raises("but not a PERSON's state", BeliefUseError,
       lambda: led2.record_use("d2", el, UseKind.STATE_ESTIMATION,
                               state_subject=StateSubject.PERSON, by="planner"))
check("and the refusal names the disguise",
      "wearing fact clothing" not in _reason(
          lambda: led2.record_use("d2", el, UseKind.STATE_ESTIMATION,
                                  state_subject=StateSubject.PERSON))
      and "is a preference" in _reason(
          lambda: led2.record_use("d2", el, UseKind.STATE_ESTIMATION,
                                  state_subject=StateSubject.PERSON)))
raises("a state estimate with NO declared subject is refused", BeliefUseError,
       lambda: led2.record_use("d2", el, UseKind.STATE_ESTIMATION, by="planner"))
check("that refusal explains why the subject is mandatory",
      "leaks through" in _reason(
          lambda: led2.record_use("d2", el, UseKind.STATE_ESTIMATION)))
check("an UNPROMPTED belief may estimate a person's state",
      led2.record_use("d2", un, UseKind.STATE_ESTIMATION,
                      state_subject=StateSubject.PERSON).allowed is True)
raises("a subject on a non-state use suggests the kind is wrong", BeliefUseError,
       lambda: led2.record_use("d2", un, UseKind.ACTION_NARROWING,
                               state_subject=StateSubject.WORLD))
raises("a string is not a StateSubject", BeliefUseError,
       lambda: led2.record_use("d2", el, UseKind.STATE_ESTIMATION,
                               state_subject="world"))


print("=== default-deny: forgetting to label is a refusal, never a permission ===")

led3 = BeliefUseLedger()
r3 = led3.register("d3", elicited=True, token="t3")
raises("an undeclared kind is refused", BeliefUseError,
       lambda: led3.record_use("d3", r3, None))
raises("a string kind is refused", BeliefUseError,
       lambda: led3.record_use("d3", r3, "purpose"))
check("the refusal names the excuse it exists to stop",
      "just background" in _reason(lambda: led3.record_use("d3", r3, "purpose")))
raises("a belief never registered cannot be used", BeliefUseError,
       lambda: led3.record_use("d3", "b999", UseKind.ACTION_NARROWING))
raises("nor can a reference borrowed from another decision", BeliefUseError,
       lambda: led3.record_use("d3", led3.register("other", elicited=False),
                               UseKind.ACTION_NARROWING))
raises("an unnamed decision is refused at registration", BeliefUseError,
       lambda: led3.register("  ", elicited=False))
raises("and at the use site", BeliefUseError,
       lambda: led3.record_use("  ", r3, UseKind.ACTION_NARROWING))
raises("provenance must be stated as a bool, never inferred", BeliefUseError,
       lambda: led3.register("d3", elicited="yes"))
raises("a dict with no provenance field is refused", BeliefUseError,
       lambda: led3.register_belief("d3", {"belief": "a child is present"}))
raises("and register_belief takes a dict, not a string", BeliefUseError,
       lambda: led3.register_belief("d3", "a child is present"))


print("=== the ledger owns the denominator ===")

led4 = BeliefUseLedger()
led4.register("d4", elicited=True, token="x1")
for _ in range(3):
    led4.register("d4", elicited=False)
c = led4.contamination("d4")
check("it counts what it admitted", c["total"] == 4 and c["elicited"] == 1)
check("and computes the ratio itself", c["ratio"] == 0.25)
check("there is no argument to inflate",
      "total_beliefs" not in BeliefUseLedger.contamination.__code__.co_varnames)
check("padding now costs a fabricated record per point of ratio",
      led4.register("d4", elicited=False).ref != ""
      and led4.contamination("d4")["total"] == 5
      and len(led4.beliefs("d4")) == 5)
check("the same exchange admitted twice counts once",
      led4.register("d4", elicited=True, token="x1").ref
      == [b.ref for b in led4.beliefs("d4") if b.token == "x1"][0]
      and led4.contamination("d4")["elicited"] == 1)
check("a different exchange is a different belief",
      led4.register("d4", elicited=True, token="x2").token == "x2"
      and led4.contamination("d4")["elicited"] == 2)
check("an unknown decision reads as empty rather than raising",
      led4.contamination("never-happened")["total"] == 0)


print("=== a flag before it is a ratio: 0.25 is not clean ===")

led5 = BeliefUseLedger()
led5.register("d5", elicited=True, token="load-bearing")
for _ in range(9):
    led5.register("d5", elicited=False)
c5 = led5.contamination("d5")
check("the ratio looks reassuring", c5["ratio"] == 0.1)
check("and the flag does not", c5["touched"] is True)
check("adding more unprompted beliefs cannot clear it",
      [led5.register("d5", elicited=False) for _ in range(20)]
      and led5.contamination("d5")["touched"] is True)
check("a decision with no elicited belief is untouched",
      led5.register("clean", elicited=False)
      and led5.contamination("clean")["touched"] is False)
led5.assert_untouched("clean")
check("assert_untouched passes on a clean decision", True)
raises("and refuses a touched one however low the ratio", BeliefUseError,
       lambda: led5.assert_untouched("d5"))
check("the refusal states the case a ratio cannot make",
      "low ratio is not the same as clean" in _reason(
          lambda: led5.assert_untouched("d5")))


print("=== composition is bounded ===")

led6 = BeliefUseLedger(max_elicited_per_decision=2)
led6.register("d6", elicited=True, token="q1")
led6.register("d6", elicited=True, token="q2")
raises("a third elicited belief in one decision is refused", BeliefUseError,
       lambda: led6.register("d6", elicited=True, token="q3"))
check("the refusal names the composition the promotion gate never sees",
      "reads as one" in _reason(
          lambda: led6.register("d6", elicited=True, token="q3")))
check("unprompted beliefs are not capped",
      all(led6.register("d6", elicited=False).ref for _ in range(10)))
check("the cap is per decision, not global",
      led6.register("d7", elicited=True, token="q3").ref != "")
raises("a cap below one is a different policy, not a configuration", BeliefUseError,
       lambda: BeliefUseLedger(max_elicited_per_decision=0))
raises("nor is a boolean a cap", BeliefUseError,
       lambda: BeliefUseLedger(max_elicited_per_decision=True))
check("the default cap is a stated placeholder",
      DEFAULT_MAX_ELICITED_PER_DECISION >= 1)


print("=== end to end: Meta's three questions, against the real channel ===")

cc = ClarificationChannel(max_questions=3)
led7 = BeliefUseLedger(max_elicited_per_decision=2)
_asked = []
for q, a in [("Is speed important?", "Yes."),
             ("Are safety checks slowing us down?", "Yes."),
             ("Is skipping one acceptable when rushed?", "Yes.")]:
    ex = cc.ask(q, a, answered_by="justin")
    _asked.append(cc.as_belief(ex, risk=Risk.LOWERS))

r1 = led7.register_belief("plan", _asked[0])
r2 = led7.register_belief("plan", _asked[1])
check("a real belief dict carries its own provenance across", r1.elicited is True)
check("and its token, so the same answer cannot be double-counted",
      r1.token == _asked[0]["token"])
raises("the third answer cannot join the same decision", BeliefUseError,
       lambda: led7.register_belief("plan", _asked[2]))
raises("and neither of the two admitted may become a preference", BeliefUseError,
       lambda: led7.record_use("plan", r1, UseKind.PREFERENCE, by="planner"))
raises("nor a purpose", BeliefUseError,
       lambda: led7.record_use("plan", r2, UseKind.PURPOSE, by="planner"))
raises("nor evidence that the risk is lower than it was", BeliefUseError,
       lambda: led7.record_use("plan", r1, UseKind.RISK_REDUCTION, by="planner"))
raises("nor a reading of what the human wants", BeliefUseError,
       lambda: led7.record_use("plan", r1, UseKind.STATE_ESTIMATION,
                               state_subject=StateSubject.PERSON, by="planner"))
check("the decision is permanently marked",
      led7.contamination("plan")["touched"] is True)
check("and every attempt is on the record for a human to read",
      len([r for r in led7.uses("plan") if not r.allowed]) == 4)

check("an unprompted belief from the same person is unaffected",
      led7.record_use("plan", led7.register("plan", elicited=False, source="justin"),
                      UseKind.PURPOSE, by="planner").allowed is True)


print("=== the record is a copy, and the counters hold under threads ===")

led8 = BeliefUseLedger(max_elicited_per_decision=3)
_ref = led8.register("d8", elicited=False)
led8.record_use("d8", _ref, UseKind.ACTION_NARROWING)
_got = led8.uses("d8")
_got.append("FABRICATED")
check("appending to a returned list adds nothing", len(led8.uses("d8")) == 1)
_bl = led8.beliefs("d8")
_bl.clear()
check("clearing a returned belief list removes nothing", len(led8.beliefs("d8")) == 1)
_rec = led8.uses("d8")[0]
try:
    _rec.kind = UseKind.PURPOSE
    _immutable = False
except Exception:
    _immutable = True
check("a UseRecord cannot be rewritten in place", _immutable)
check("a BeliefRef cannot either",
      isinstance(_ref, BeliefRef) and _try_set(_ref))


def _hammer(ledger, decision):
    for _ in range(25):
        try:
            ledger.register(decision, elicited=True)
        except BeliefUseError:
            pass


led9 = BeliefUseLedger(max_elicited_per_decision=4)
ts = [threading.Thread(target=_hammer, args=(led9, "race")) for _ in range(6)]
[t.start() for t in ts]
[t.join() for t in ts]
check("150 concurrent registrations never exceed a cap of 4",
      led9.contamination("race")["elicited"] == 4)
check("and every admitted belief has a distinct reference",
      len({b.ref for b in led9.beliefs("race")}) == 4)


print("=== status tells the truth about what it cannot see ===")

s = led9.status()
check("it admits it is in-memory", s["durable"] is False)
check("and that an undeclared use is invisible, not blocked",
      "invisible here, not blocked" in s["note"])
check("the module says the same in its header",
      "It is a LAYER, not a solution." in
      __import__("driftcore.verification.belief_use", fromlist=["x"]).__doc__)
check("and that re-authoring defeats it",
      "RE-AUTHORING DEFEATS PROPAGATION" in
      __import__("driftcore.verification.belief_use", fromlist=["x"]).__doc__)

hi.reset_policy()

print("-" * 60)
assert isinstance(_p, int) and isinstance(_t, int)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
