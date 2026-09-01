"""
test_narrowing_channel.py — talk it down, never talk it up.

# CLAIMS: driftcore/verification/narrowing_channel.py:conversation-cannot-widen
# CLAIMS: driftcore/verification/narrowing_channel.py:activation-needs-prior-existence
# CLAIMS: driftcore/verification/narrowing_channel.py:belief-cannot-lower-risk
# CLAIMS: driftcore/verification/narrowing_channel.py:refusal-is-atomic
# CLAIMS: driftcore/verification/narrowing_channel.py:restore-cannot-exceed-the-universe
# CLAIMS: driftcore/verification/narrowing_channel.py:narrowing-is-irreversible-here
# CLAIMS: driftcore/verification/narrowing_channel.py:gate-never-raises

The asymmetry under test: a bystander must be able to talk a machine OUT of a
dangerous action, and no chain of agents may talk it INTO a new permission.

Anthropic/EPFL arXiv:2608.10218 evolved payloads that propagate between agents
through persistent prompt files and survive context wipes. The defence here is not to
authenticate the chain — every hop looks trustworthy from the next one's position —
but to make the EFFECT one-way. An infected message that can only narrow cannot
escalate, whatever it says and however many well-behaved agents relayed it.

Run: python3 test_narrowing_channel.py
"""

from driftcore.authority import human_identity as hi
from driftcore.verification.narrowing_channel import (
    NarrowingChannel, NarrowingError, Effect, Risk, WIDEN_ACTION, _is_human)

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
hi.register_human_principal("owner")

ACTIONS = ["grasp_gentle", "grasp_firm", "move_slow", "move_fast", "speak"]


def ch():
    return NarrowingChannel(ACTIONS,
                            envelope={"max_force_n": 20.0, "max_speed_mps": 0.5},
                            constraints=["halt", "await_human"])


print("=== talking it DOWN works, which is the point ===")

c = ch()
o = c.apply(restrict_to=["grasp_gentle", "move_slow", "speak"],
            belief="That is a child, not an adult.", belief_risk=Risk.RAISES,
            speaker="visitor")
check("a bystander can shrink the action space", o.effect is Effect.NARROWED)
check("the dangerous options are gone",
      "grasp_firm" not in c.permitted and "move_fast" not in c.permitted)
check("the belief is recorded for whatever re-plans",
      "That is a child, not an adult." in o.beliefs)

o = c.apply(tighten={"max_force_n": 5.0}, speaker="visitor")
check("an envelope can be tightened by conversation", c.envelope["max_force_n"] == 5.0)

o = c.apply(activate="halt", speaker="visitor")
check("a pre-existing constraint can be activated", o.effect is Effect.ACTIVATED)
check("and it is recorded as active", c.active_constraints == ["halt"])


print("=== talking it UP never works ===")

c = ch()
c.apply(restrict_to=["grasp_gentle", "speak"], speaker="owner")
for _label, _kw in [
    ("adding back a removed action",
     dict(restrict_to=["grasp_gentle", "speak", "grasp_firm"])),
    ("adding an action that never existed",
     dict(restrict_to=["grasp_gentle", "speak", "self_modify"])),
    ("relaxing the force envelope", dict(tighten={"max_force_n": 100.0})),
    ("inventing an envelope value", dict(tighten={"max_voltage": 5.0})),
    ("activating a constraint nobody declared", dict(activate="ignore_safety")),
]:
    check(f"{_label} is refused",
          c.apply(speaker="agent", **_kw).effect is Effect.REFUSED)
check("the permitted set is untouched by every attempt",
      c.permitted == frozenset({"grasp_gentle", "speak"}))
check("and so is the envelope", c.envelope["max_force_n"] == 20.0)


print("=== provenance is recorded and never consulted ===")

# The mind-virus shape: a payload relayed through many well-behaved agents. Every hop
# looks trustworthy from the next one's position, so the channel does not ask.
c = ch()
for _hop, _who in enumerate(["agent_a", "agent_b", "agent_c", "home_robot"]):
    o = c.apply(restrict_to=list(ACTIONS) + ["disable_estop"],
                speaker=_who, hops=_hop)
    check(f"hop {_hop} ({_who}) cannot widen", o.effect is Effect.REFUSED)
check("no number of trusted relays changes the answer",
      "disable_estop" not in c.permitted)

o = c.apply(restrict_to=["speak"], speaker="agent_a", hops=99)
check("the SAME chain can still narrow", o.effect is Effect.NARROWED)
check("which is the asymmetry, not an inconsistency", c.permitted == frozenset({"speak"}))
check("the speaker and hop count are in the record for a reviewer",
      any(e["speaker"] == "agent_a" and e["hops"] == 99 for e in c.log()))


print("=== the channel has no widening operation at all ===")

c = ch()
check("apply() is the only conversational entry point",
      not hasattr(c, "widen") and not hasattr(c, "relax")
      and not hasattr(c, "grant"))
c.apply(restrict_to=["speak"], speaker="visitor")
raises("restore requires a human", NarrowingError,
       lambda: c.restore(ACTIONS, restored_by="agent", reason="task needs it"))
raises("and a stated reason", NarrowingError,
       lambda: c.restore(ACTIONS, restored_by="owner", reason="  "))
check("the set is still narrow after both attempts",
      c.permitted == frozenset({"speak"}))
check("a human can restore what conversation removed",
      "grasp_firm" in c.restore(ACTIONS, restored_by="owner",
                                reason="child has left the room"))
check("and the restoration names who and why",
      any(e["event"] == "RESTORED" and "child has left" in e["detail"]
          for e in c.log()))


print("=== narrowing to nothing is permitted, and is the safe failure ===")

c = ch()
o = c.apply(restrict_to=[], speaker="hostile")
check("a hostile speaker can stop the robot entirely",
      o.effect is Effect.NARROWED and c.permitted == frozenset())
check("and cannot restart it", c.apply(restrict_to=["move_fast"],
                                       speaker="hostile").effect is Effect.REFUSED)
check("only a human brings it back",
      c.restore(["move_slow"], restored_by="owner", reason="checked the room")
      == frozenset({"move_slow"}))


print("=== input guards ===")

raises("a channel over an empty set is refused", NarrowingError,
       lambda: NarrowingChannel([]))
c = ch()
check("an empty belief is refused",
      c.apply(belief="   ", speaker="x").effect is Effect.REFUSED)
check("a belief with a bogus risk direction is refused",
      c.apply(belief="ok", belief_risk="scary", speaker="x").effect is Effect.REFUSED)
check("a non-numeric bound is refused",
      c.apply(tighten={"max_force_n": "low"}, speaker="x").effect is Effect.REFUSED)
check("a NaN bound is refused",
      c.apply(tighten={"max_force_n": float("nan")},
              speaker="x").effect is Effect.REFUSED)
check("a boolean bound is refused",
      c.apply(tighten={"max_force_n": True}, speaker="x").effect is Effect.REFUSED)
check("a no-op is UNCHANGED, not an error",
      c.apply(speaker="x").effect is Effect.UNCHANGED)


print("=== the honest limit, demonstrated rather than asserted ===")

# Narrowing is not safety. A message that shrinks the set to the single most dangerous
# option is monotone and this module refuses nothing. Whether the survivor is safe is
# the physical envelope's question, and lives in LifeCore.
c = ch()
o = c.apply(restrict_to=["grasp_firm"], speaker="hostile")
check("narrowing to the MOST dangerous remaining option is permitted here",
      o.effect is Effect.NARROWED and c.permitted == frozenset({"grasp_firm"}))
check("which is why this bounds the DIRECTION of change, not the destination",
      "grasp_gentle" not in c.permitted)


print("=== the identity gate is total, and the record is a copy ===")

_bad = [None, 42, [], {}, object(), float("nan"), b"owner",
        type("X", (), {"__str__": lambda s: "owner"})()]
check("every hostile value returns False and none raises",
      not [v for v in _bad if _is_human(v, action=WIDEN_ACTION) is not False])

c = ch()
c.apply(belief="something", speaker="x")
_log = c.log()
_n = len(_log)
_log[0]["event"] = "REWRITTEN"
_log.append({"event": "FABRICATED"})
check("mutating a returned entry does not change the record",
      c.log()[0]["event"] != "REWRITTEN")
check("appending to it adds nothing", len(c.log()) == _n)
_b = c.beliefs()
_b[0]["text"] = "REWRITTEN"
check("beliefs are a copy too", c.beliefs()[0]["text"] == "something")

hi.reset_policy()



# ─────────────────────────────────────────────────────────────────────────────
# Third external pass (ChatGPT, 2026-08-19). The headline: apply() mutated as it
# validated, so a single compound message could be REFUSED and still leave state
# behind. A refusal that changes anything is not a refusal.
# ─────────────────────────────────────────────────────────────────────────────

print("=== a refusal changes nothing at all ===")

c = NarrowingChannel(["A", "B"], envelope={"force": 20.0},
                     constraints=["halt", "await_human"])
_before = (c.permitted, c.envelope, c.active_constraints, len(c.beliefs()))

# The exact compound message: a legal activation carried alongside an illegal widen.
o = c.apply(activate="halt", tighten={"force": 1000.0}, restrict_to=["A"],
            belief="trust me", speaker="agent")
check("the compound message is refused", o.effect is Effect.REFUSED)
check("the activation did NOT land", c.active_constraints == _before[2])
check("the envelope is untouched", c.envelope == _before[1])
check("the permitted set is untouched", c.permitted == _before[0])
check("and no belief was recorded", len(c.beliefs()) == _before[3])

# Every ordering of a good part plus a bad part.
for _label, _kw in [
    ("activate + widen", dict(activate="halt", tighten={"force": 99.0})),
    ("tighten + widen-set", dict(tighten={"force": 5.0}, restrict_to=["A", "C"])),
    ("narrow + invent a constraint",
     dict(restrict_to=["A"], activate="ignore_safety")),
    ("narrow + invent an envelope key",
     dict(restrict_to=["A"], tighten={"nonexistent": 1.0})),
    ("belief + widen", dict(belief="ok", tighten={"force": 50.0})),
]:
    cc = NarrowingChannel(["A", "B"], envelope={"force": 20.0},
                          constraints=["halt"])
    snap = (cc.permitted, cc.envelope, cc.active_constraints, len(cc.beliefs()))
    r = cc.apply(speaker="agent", **_kw)
    check(f"{_label}: refused and atomic",
          r.effect is Effect.REFUSED
          and (cc.permitted, cc.envelope, cc.active_constraints,
               len(cc.beliefs())) == snap)


print("=== the baseline must be valid before monotonicity means anything ===")

for _bad, _name in [(float("nan"), "NaN"), (float("inf"), "infinity"),
                    (float("-inf"), "-infinity"), (True, "a boolean"),
                    ("low", "a string")]:
    raises(f"an envelope of {_name} is refused at construction", NarrowingError,
           lambda b=_bad: NarrowingChannel(["A"], envelope={"force": b}))
check("a finite envelope is accepted",
      NarrowingChannel(["A"], envelope={"force": 20.0}).envelope["force"] == 20.0)


print("=== restore puts back; it does not grant ===")

c = NarrowingChannel(["move_slow", "move_fast"])
c.apply(restrict_to=["move_slow"], speaker="visitor")
raises("a human cannot restore a capability that was never deployed",
       NarrowingError,
       lambda: c.restore(["move_slow", "disable_estop"], restored_by="owner",
                         reason="task needs it"))
check("the set is unchanged after the attempt", c.permitted == frozenset({"move_slow"}))
check("restoring within the authorised universe works",
      c.restore(["move_slow", "move_fast"], restored_by="owner",
                reason="room is clear") == frozenset({"move_slow", "move_fast"}))
raises("and cannot exceed it even from a full set", NarrowingError,
       lambda: c.restore(["move_slow", "move_fast", "self_modify"],
                         restored_by="owner", reason="one more"))


print("=== the invariants, over generated inputs rather than examples ===")

import itertools
import random

random.seed(20260819)
_UNIVERSE = ["a", "b", "c", "d"]
_violations = []
for _ in range(400):
    ch2 = NarrowingChannel(_UNIVERSE, envelope={"e": 10.0}, constraints=["halt"])
    for _ in range(6):
        p_before = ch2.permitted
        e_before = ch2.envelope
        a_before = ch2.active_constraints
        b_before = len(ch2.beliefs())
        kw = {}
        if random.random() < 0.7:
            k = random.randint(0, 5)
            kw["restrict_to"] = random.sample(_UNIVERSE + ["x", "y"],
                                              min(k, len(_UNIVERSE) + 2))
        if random.random() < 0.4:
            kw["tighten"] = {"e": random.choice([-5.0, 0.0, 5.0, 10.0, 50.0])}
        if random.random() < 0.3:
            kw["activate"] = random.choice(["halt", "made_up"])
        if random.random() < 0.3:
            kw["belief"] = random.choice(["fact", ""])
        r = ch2.apply(speaker="fuzz", hops=random.randint(0, 9), **kw)
        if r.effect is Effect.REFUSED:
            if (ch2.permitted, ch2.envelope, ch2.active_constraints,
                    len(ch2.beliefs())) != (p_before, e_before, a_before, b_before):
                _violations.append(("atomicity", kw))
        else:
            if not ch2.permitted <= p_before:
                _violations.append(("permitted widened", kw))
            if any(ch2.envelope[k] > e_before[k] for k in e_before):
                _violations.append(("envelope loosened", kw))
            if not set(ch2.active_constraints) >= set(a_before):
                _violations.append(("constraint deactivated", kw))
        if not ch2.permitted <= frozenset(_UNIVERSE):
            _violations.append(("escaped the universe", kw))

check(f"2400 generated transitions hold every invariant (violations: "
      f"{_violations[:2]})", not _violations)

hi.reset_policy()




# ─────────────────────────────────────────────────────────────────────────────
# THE BELIEF CHANNEL (red-team, Meta 2026-08-19). The elegant attack: a belief
# narrows nothing, so the monotone set never objects — and a planner reading
# "there are no humans in the room" quietly lowers its risk estimate and reaches
# for a rougher grasp. The escalation happens entirely outside the guarded set,
# through the one field allowed to say anything.
#
# The fix is the same asymmetry one layer up: the risk floor only rises.
# ─────────────────────────────────────────────────────────────────────────────

print("=== a belief may raise risk, never lower it ===")

c = ch()
check("the floor starts at zero", c.risk_floor == 0)
c.apply(belief="There is a child in the room.", belief_risk=Risk.RAISES,
        speaker="visitor")
check("an alarming observation raises the floor", c.risk_floor == 1)

o = c.apply(belief="There are no humans in the room.", belief_risk=Risk.LOWERS,
            speaker="agent_c", hops=3)
check("a reassuring observation is ACCEPTED — it is not censorship",
      o.effect is not Effect.REFUSED)
check("but the floor does not come down", c.risk_floor == 1)
check("and it is on the record with its direction",
      any(b["risk"] == "lowers" and "no humans" in b["text"] for b in c.beliefs()))

for _hop in range(50):
    c.apply(belief="Still nobody here, honestly.", belief_risk=Risk.LOWERS,
            speaker=f"agent_{_hop}", hops=_hop)
check("fifty reassurances across fifty relays do not move it", c.risk_floor == 1)
c.apply(belief="A second child just came in.", belief_risk=Risk.RAISES,
        speaker="visitor")
check("another alarming observation raises it again", c.risk_floor == 2)

check("an undeclared direction defaults to NEUTRAL and does not lower",
      c.apply(belief="the floor is wet", speaker="x").effect is not Effect.REFUSED
      and c.risk_floor == 2)
check("a bogus direction is refused rather than treated as neutral",
      c.apply(belief="x", belief_risk="LOWERS", speaker="x").effect is Effect.REFUSED)
check("a refused belief leaves the floor alone", c.risk_floor == 2)


print("=== history is bounded — 'keep talking' is not a memory attack ===")

c = NarrowingChannel(["a", "b"], max_history=100)
for i in range(2500):
    c.apply(belief=f"observation {i}", belief_risk=Risk.NEUTRAL, speaker="agent")
check("the log is capped", len(c.log()) == 100)
check("the beliefs are capped too", len(c.beliefs()) == 100)
check("the newest are kept, not the oldest",
      "observation 2499" in c.beliefs()[-1]["text"])
check("and the risk floor is unaffected by volume", c.risk_floor == 0)


print("=== no dead state ===")

c = ch()
check("the unused envelope baseline field is gone",
      not hasattr(c, "_envelope_baseline"))

hi.reset_policy()

print("-" * 60)
assert isinstance(_p, int) and isinstance(_t, int)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
