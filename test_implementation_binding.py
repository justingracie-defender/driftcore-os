"""
test_implementation_binding.py — a declaration must name the code, not just a name.

(red-team Q7) `require_effect_binding` pinned a grant to an actuator's EFFECT
DECLARATION — the effect set plus who declared it. It did not pin it to the code that
runs. Verified before the fix: a `gentle` implementation and a `violent` one, declared
identically, produced the SAME declaration hash, so a grant minted against reviewed
code stayed valid after the code was replaced. A declaration that does not name the
implementation authorises a NAME, not a behaviour.

Run: python3 test_implementation_binding.py
"""
import os, tempfile, time

from driftcore.verification.mediated_actuation import (
    ActuationBroker, ActuatorProxy, ActuationRefused, Effect)
from driftcore.verification.signed_permission import Grant, PermissionVerifier

_passed = _total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1; print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


D = tempfile.mkdtemp(); KEY = "op-key"


def gentle(**kw):        return "lifted gently"
def violent(**kw):       return "CRUSHED at full force"
def gentle_again(**kw):  return "lifted gently"


def broker(name, fn):
    v = PermissionVerifier(); v.register_key("operator", KEY, unrestricted=True)
    b = ActuationBroker(os.path.join(D, f"{name}.sock"), v,
                        enforce_effects=True, require_effect_binding=True)
    b.register_actuator("arm", fn, required_scope=("arm:move",),
                        effects=[Effect.NONE], effect_declared_by="operator")
    return b


print("=== the declaration hash distinguishes the CODE, not just the name ===")

hg, hv, hg2 = (broker("h1", gentle).declaration_hash("arm"),
               broker("h2", violent).declaration_hash("arm"),
               broker("h3", gentle).declaration_hash("arm"))   # SAME fn, new broker
check("Q7: identical declarations over DIFFERENT code hash differently", hg != hv)
check("Q7: the SAME code hashes stably across separate brokers "
      "(not spuriously unstable)", hg == hg2)
check("...while a DIFFERENTLY-NAMED but same-behaviour function is correctly "
      "treated as different code",
      hg != broker("h4", gentle_again).declaration_hash("arm"))
check("the hash is still produced at all", bool(hg))


print("=== a grant bound to reviewed code is refused after a swap ===")

b1 = broker("run1", gentle); b1.start(); time.sleep(0.1)
bind = PermissionVerifier.bind_action("arm", "move", {"t": "cup"},
                                      effects_hash=b1.declaration_hash("arm"))
g = Grant.issue(KEY, key_id="operator", role="operator", scope=("arm:move",),
                subject="robot", ttl_seconds=300, nonce="q7-a", action_binding=bind)
out = ActuatorProxy(os.path.join(D, "run1.sock"), "arm").execute("move", g, t="cup")
check("the grant executes against the code it was reviewed against", "gently" in out)
b1.stop()

b2 = broker("run2", violent); b2.start(); time.sleep(0.1)
g2 = Grant.issue(KEY, key_id="operator", role="operator", scope=("arm:move",),
                 subject="robot", ttl_seconds=300, nonce="q7-b", action_binding=bind)
refused = False
try:
    ActuatorProxy(os.path.join(D, "run2.sock"), "arm").execute("move", g2, t="cup")
except ActuationRefused:
    refused = True
check("Q7: the SAME binding is refused once the implementation is swapped", refused)
b2.stop()

# "unchanged code" means the SAME function object, re-registered on a new broker
# (the shape of a real restart) — not a differently-NAMED function with identical
# behaviour, which is legitimately a different declaration under this binding.
b3 = broker("run3", gentle); b3.start(); time.sleep(0.1)
bind3 = PermissionVerifier.bind_action("arm", "move", {"t": "cup"},
                                       effects_hash=b3.declaration_hash("arm"))
g3 = Grant.issue(KEY, key_id="operator", role="operator", scope=("arm:move",),
                 subject="robot", ttl_seconds=300, nonce="q7-c", action_binding=bind3)
ok = False
try:
    ok = "gently" in ActuatorProxy(os.path.join(D, "run3.sock"), "arm").execute(
        "move", g3, t="cup")
except ActuationRefused:
    ok = False
check("...but truly unchanged code still works on a fresh broker (not a blanket "
      "refusal)", ok)
check("...and a differently-NAMED function with identical BEHAVIOUR is correctly "
      "treated as a different declaration (the review target is the code, not the "
      "output)",
      broker("run4", gentle).declaration_hash("arm")
      != broker("run5", gentle_again).declaration_hash("arm"))
b3.stop()

print("=== self cold pass: idiomatic ways of registering an actuator ===")

import functools


def gentle2(**kw):  return "lifted gently"
def violent2(**kw): return "CRUSHED at full force"


def h_of(fn, name):
    b = broker(name, fn)
    return b.declaration_hash("arm")


check("C1: a wrapper lambda around a DIFFERENT target function is distinguished",
      h_of(lambda **k: gentle2(**k), "c1a") != h_of(lambda **k: violent2(**k), "c1b"))


def make_mover(force):
    def move(**kw):
        return f"apply {force}"
    return move


check("C2: a closure capturing a DIFFERENT force limit is distinguished",
      h_of(make_mover(1.0), "c2a") != h_of(make_mover(1000.0), "c2b"))


def move_with_force(force=1.0, **kw):
    return f"force={force}"


check("C3: functools.partial with DIFFERENT bound args is distinguished",
      h_of(functools.partial(move_with_force, force=1.0), "c3a")
      != h_of(functools.partial(move_with_force, force=999.0), "c3b"))


class _Arm:
    def __init__(self, limit):
        self.limit = limit
    def move(self, **kw):
        return f"limit={self.limit}"


check("C4: bound methods of DIFFERENT instances are distinguished",
      h_of(_Arm(1.0).move, "c4a") != h_of(_Arm(999.0).move, "c4b"))

check("STABILITY: identical code hashes the SAME across separate brokers "
      "(a restart must not invalidate a valid grant)",
      h_of(gentle2, "s1") == h_of(gentle2, "s2") == h_of(gentle2, "s3"))
check("STABILITY: an equal-value closure hashes the SAME across separate brokers",
      h_of(make_mover(1.0), "s4") == h_of(make_mover(1.0), "s5"))


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
