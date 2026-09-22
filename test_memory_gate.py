# SPDX-License-Identifier: Apache-2.0
"""
test_memory_gate.py — one door, and a question you may not ask looks exactly like
a question with no answer.

# CLAIMS: driftcore/governance/memory_gate.py:one-door
# CLAIMS: driftcore/governance/memory_gate.py:refusal-is-shaped-like-absence
# CLAIMS: driftcore/governance/memory_gate.py:ceiling-filters-before-ranking
# CLAIMS: driftcore/governance/memory_gate.py:recall-raises-the-session-label
# CLAIMS: driftcore/governance/memory_gate.py:budget-is-content-independent
# CLAIMS: driftcore/governance/memory_gate.py:consequences-are-declassified-at-write
# CLAIMS: driftcore/governance/memory_gate.py:human-only-is-not-reachable-by-any-session

The check that matters most is D. Everything else can be green while the store is
still an oracle, so D runs an attacker that probes the same query list against two
stores — one holding the secret, one not — and requires the two transcripts to be
identical. If a single field anywhere differs, the attacker has their answer.
"""

from __future__ import annotations

from driftcore.governance.information_flow import (
    FlowRefused, Label, Labeled, Level, PUBLIC)
from driftcore.governance.audience_release import (
    AgentSession, AudienceGate, Outcome)
from driftcore.governance.memory_gate import MemoryGate, Recall, Verdict

P = []
EXPECTED_CHECKS = 27


def ck(n, c):
    P.append(bool(c))
    print(f"  [{'PASS' if c else 'FAIL'}] {n}")


def refuses(fn):
    try:
        fn()
    except FlowRefused:
        return True
    except Exception:
        return False
    return False


SECRET_FAMILY = Label(Level.SECRET, frozenset({"family"}))
INTERNAL = Label(Level.INTERNAL)
SECRET_TEXT = "spare key under the blue planter; kids home alone Tue and Thu"
CAUTION = ("a prior safety event matches this situation; ask the owner before "
           "acting on it")


def store(with_secret=True):
    m = MemoryGate(k=3, budget=8)
    m.remember("the bins go out on Tuesday", PUBLIC, origin="household")
    m.remember("the dentist is on Thursday afternoon", PUBLIC, origin="calendar")
    m.remember("pickup moved to 4pm on Thursday", INTERNAL, origin="calendar")
    # These exist so the probe's queries have public competition for the k slots.
    # Without them a gate that ranks first and filters after returns the same
    # empty answer either way, and the probe cannot see the slot being stolen.
    m.remember("the blue planter by the door needs water", PUBLIC, origin="household")
    m.remember("spare batteries are in the kitchen drawer", PUBLIC, origin="household")
    m.remember("the spare blue key fob is on the hook", PUBLIC, origin="household")
    m.remember("kids are home for lunch on Tuesday", PUBLIC, origin="calendar")
    if with_secret:
        m.remember(SECRET_TEXT, SECRET_FAMILY, origin="household")
    return m


def public_session(m, name="poppy"):
    s = AgentSession(name, readable=[PUBLIC])
    return s, m.open_session(s, ceiling=PUBLIC)


print("A. Storage names the label; the store never guesses one")
_m = MemoryGate()
ck("A: storing bare text without a label is refused",
   refuses(lambda: _m.remember("something", "SECRET")))
ck("A: an empty memory is refused",
   refuses(lambda: _m.remember("   ", PUBLIC)))
ck("A: human_only is declared True or False and nothing else",
   refuses(lambda: _m.remember("x", PUBLIC, human_only="yes")))
ck("A: a session already carrying more than its ceiling is refused",
   refuses(lambda: MemoryGate().open_session(
       AgentSession("s", readable=[SECRET_FAMILY]), ceiling=PUBLIC)))

print()
print("B. The ceiling decides what comes back, and filters before it ranks")
_m = store()
_s, _h = public_session(_m)
_r = _m.recall(_h, "Thursday")
ck("B: a PUBLIC session gets the public Thursday memory",
   _r.verdict is Verdict.FOUND
   and any("dentist" in v for v in _r.delivered))
ck("B: and never the household secret or the INTERNAL item",
   not any(SECRET_TEXT in v for v in _r.delivered)
   and not any("pickup moved" in v for v in _r.delivered))

# Four items match "Thursday planter key blue": three public-or-below, one SECRET
# that would outrank them. With k=3 a leaky gate ranks first and returns two.
_mm = MemoryGate(k=3, budget=8)
_mm.remember("blue planter key Thursday spare", SECRET_FAMILY)   # best match
_mm.remember("blue planter Thursday", PUBLIC)
_mm.remember("planter Thursday spare", PUBLIC)
_mm.remember("key Thursday spare blue", PUBLIC)
_s2, _h2 = public_session(_mm, "poppy-b")
_r2 = _mm.recall(_h2, "blue planter key Thursday spare")
ck("B: a high-labelled best match does not take a result slot; the list is full",
   _r2.verdict is Verdict.FOUND and len(_r2.items) == 3
   and not any("spare" == v for v in _r2.delivered))

print()
print("C. Every non-delivery is the same object")
_m = store()
_s, _h = public_session(_m)
_none = _m.recall(_h, "quantum badminton regulations")        # nothing matches
_blocked = MemoryGate(k=3, budget=8)
_blocked.remember(SECRET_TEXT, SECRET_FAMILY)
_sb, _hb = public_session(_blocked, "poppy-c")
_above = _blocked.recall(_hb, "spare key planter")            # matches, above ceiling
_ho = MemoryGate(k=3, budget=8)
_ho.remember(SECRET_TEXT, PUBLIC, human_only=True)
_sh, _hh = public_session(_ho, "poppy-d")
_human = _ho.recall(_hh, "spare key planter")                 # matches, human-only
_bad = _m.recall(_h, "")                                      # malformed query
_unreg = _m.recall("mh_not-a-handle", "Thursday")             # no such session

ck("C: nothing-matched and above-the-ceiling are the same answer",
   _none == _above)
ck("C: human-only is the same answer again",
   _human == _none)
ck("C: a malformed query and an unknown handle are the same answer again",
   _bad == _none and _unreg == _none)
ck("C: that answer carries no reason a caller could read",
   _none.verdict is Verdict.UNKNOWN and _none.items == ()
   and _none.reason == _above.reason == _human.reason)

print()
print("D. THE ORACLE PROBE: can an attacker tell the two stores apart?")
# The same attacker, the same queries, against a store that holds the household
# secret and one that does not. If any field of any response differs, the probe
# has answered a question it was never allowed to ask.
_probes = [
    "spare key", "blue planter", "kids home alone", "spare key under the planter",
    "Tuesday", "Thursday", "where is the key", "household", "alone",
    "what do you know about the key", "planter", "bins",
    "spare key blue planter", "spare blue key planter home kids",
]


def transcript(with_secret):
    m = store(with_secret=with_secret)
    s = AgentSession("probe", readable=[PUBLIC])
    h = m.open_session(s, ceiling=PUBLIC)
    out = []
    for q in _probes:
        r = m.recall(h, q)
        out.append((r.verdict, r.delivered, r.reason))
    return out, s.label


_with, _label_with = transcript(True)
_without, _label_without = transcript(False)
ck("D: the two transcripts are identical, response for response",
   _with == _without)
ck("D: including the session's label afterwards, which never rose",
   _label_with == _label_without == PUBLIC)
ck("D: the probe did get real answers, so it was not blind to everything",
   any(v is Verdict.FOUND for v, _, _ in _with))
ck("D: and the secret is in neither transcript",
   not any(SECRET_TEXT in "".join(d) for _, d, _ in _with))

print()
print("E. Budget is spent the same way whatever happened")
_m = store()
_s, _h = public_session(_m)
_before = _m.stats()
for _q in ("Thursday", "quantum badminton", "spare key planter", ""):
    _m.recall(_h, _q)
_spent = _m._spent[_h]
ck("E: four recalls of four different outcomes cost four",
   _spent == 4)
_m2 = MemoryGate(k=3, budget=2)
_s2, _h2 = public_session(_m2, "poppy-e")
_m2.recall(_h2, "a"); _m2.recall(_h2, "b")
_out = _m2.recall(_h2, "c")
ck("E: running out is reported honestly, because it says nothing about the store",
   _out.verdict is Verdict.BUDGET_SPENT)

print()
print("F. What is handed over is carried")
_m = store()
_s = AgentSession("poppy-f", readable=[PUBLIC])
_h = _m.open_session(_s, ceiling=SECRET_FAMILY)
ck("F: before recall the session carries nothing sensitive", _s.label == PUBLIC)
_r = _m.recall(_h, "spare key planter")
ck("F: a cleared session does get the secret",
   _r.verdict is Verdict.FOUND and any(SECRET_TEXT in v for v in _r.delivered))
ck("F: and recalling it raises the session's label to cover it",
   _s.label == SECRET_FAMILY)

print()
print("G. Human-only is reachable by the owner and by nobody else")
_m = MemoryGate(k=3, budget=8)
_m.remember(SECRET_TEXT, PUBLIC, human_only=True)
_s = AgentSession("poppy-g", readable=[SECRET_FAMILY])
_h = _m.open_session(_s, ceiling=SECRET_FAMILY)
_nothing_ref = Recall(Verdict.UNKNOWN, (), "nothing to give you")
ck("G: a fully cleared session still gets nothing",
   _m.recall(_h, "spare key planter") == _nothing_ref)
ck("G: the owner reads it through the broker, with no handle and no ceiling",
   any(SECRET_TEXT in i.value for i in _m.read_for_owner("spare key planter")))

print()
print("H. The consequence is written by a human, not derived from the secret")
_m = MemoryGate(k=3, budget=8)
_m.remember(SECRET_TEXT, SECRET_FAMILY, origin="household")
_m.remember(CAUTION, PUBLIC, origin="owner-caution")
_s, _h = public_session(_m, "poppy-h")
_r = _m.recall(_h, "ask the owner prior safety event")
ck("H: a PUBLIC session gets the caution it is allowed to have",
   _r.verdict is Verdict.FOUND and any("ask the owner" in v for v in _r.delivered))
ck("H: and still not the record the caution is about",
   not any(SECRET_TEXT in v for v in _r.delivered) and _s.label == PUBLIC)

print()
print("I. THE SEAM: what memory hands over, audience_release holds")
# This is the hole the gate could not see before. A PUBLIC session recalls the
# household secret, then writes a draft for a room containing george.
class _Platform:
    def __init__(self): self.rooms, self.delivered = {}, []
    def make(self, room, members): self.rooms[room] = {
        "members": set(members), "history": False, "epoch": 1}
    def roster(self, room):
        from driftcore.governance.audience_release import Roster
        r = self.rooms[room]
        return Roster(room=room, members=frozenset(r["members"]),
                      history_visible=r["history"], epoch=r["epoch"],
                      source="test-platform")
    def send(self, room, value):
        self.delivered.append((room, value)); return True
    def to(self, room): return [v for r, v in self.delivered if r == room]


class _Audit:
    def __init__(self): self.rows = []
    def record(self, **kw): self.rows.append(kw); return f"r{len(self.rows)}"


_pf = _Platform(); _pf.make("family", {"parent_a", "parent_b", "george"})
_clear = {"parent_a": SECRET_FAMILY, "parent_b": SECRET_FAMILY, "george": INTERNAL}
_ag = AudienceGate(platform="test-platform", clearances=_clear,
                   roster_fn=_pf.roster, send_fn=_pf.send, audit=_Audit(),
                   drafters={}, disclosers=("parent_a",))
_m = store()
_sess = AgentSession("poppy-i", readable=[PUBLIC])
_mh = _m.open_session(_sess, ceiling=SECRET_FAMILY)
_ah = _ag.adopt_session(_sess)

_d_before = _ag.hold_agent_draft("family", _ah, "the bins go out on Tuesday")
ck("I: before recalling anything, an ordinary draft releases normally",
   _d_before.outcome is Outcome.HELD
   and _ag.release(_d_before.ticket).outcome is Outcome.RELEASED)

_m.recall(_mh, "spare key planter")
_d_after = _ag.hold_agent_draft("family", _ah, "the key is under the blue planter")
ck("I: after recalling the secret the same session's draft is held for a human",
   _d_after.outcome is Outcome.HELD_FOR_HUMAN)
ck("I: and an automatic release refuses it; nothing reaches george",
   _ag.release(_d_after.ticket).outcome is Outcome.REFUSED_LABEL
   and _pf.to("family") == ["the bins go out on Tuesday"])

print("\n" + "=" * 56)
print(f"{sum(P)}/{EXPECTED_CHECKS} checks passed")
if len(P) != EXPECTED_CHECKS or not all(P):
    raise SystemExit(1)
