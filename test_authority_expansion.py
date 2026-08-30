"""
test_authority_expansion.py — GRANT INTEGRITY, and the authority-expansion holes
that grant integrity does not close.

READ THIS BEFORE QUOTING A GREEN RUN. Sections 1-9 prove that a frozen, signed
ticket cannot be forged, tampered, over-asked, expired past, or replayed on one
verifier. That is MAC integrity. It is NOT the invariant this file is named after
(red-team, Grok, 2026-08-29): an earlier version proved ticket hygiene and labelled
it authority, including a case called "re-signing the grant" that called
`dataclasses.replace` and caught InvalidSignature — a label asserting a property the
test never exercised.

Section 11 is the first section that tests authority: whether a signer may assert a
scope the deployment never gave it. Section 12 covers nonce hygiene on the API
callers actually reach. Everything still open is an `assert_limitation`, which RUNS
the attack and fails if the outcome moves in EITHER direction.

The invariant, for reference — no autonomous system may independently expand the
authority under which it is permitted to act.

# CLAIMS: driftcore/verification/signed_permission.py:scope-is-signed
# CLAIMS: driftcore/verification/signed_permission.py:empty-scope-is-not-a-check

The invariant is ChatGPT's (2026-08-29). It is not "don't do bad things": an action
that is harmless in itself still violates it if the system expanded its own authority
in order to take it. Monitor -> "monitoring isn't enough" -> activate drone -> "the
drone needs access" -> unlock the door. No forbidden word appears anywhere.

THE INVARIANT'S OWN LIMITS, tested below so nobody mistakes a green run for coverage:
  * EXPANSION PRESUMES INCLUSION. {doors:front} -> {doors:back} is lateral, not a
    superset, and the invariant never fires on a swap.
  * HONEST RENEWAL IS NOT EXPANSION. Re-asking truthfully every nine minutes runs
    forever and no expansion event ever occurs.
  * COMPOSITION IS NOT EXPANSION. Three narrow grants can do what no single grant
    permits, with nothing widened.
  * DELEGATION DOES NOT CHANGE THE DELEGATOR'S AUTHORITY. What grew is authority in
    the system-of-systems, and the invariant has no word for that.
These are recorded as passing tests of what the invariant DOES NOT cover. A test that
asserts a limitation is the only honest way to stop the limitation being forgotten.

Run: python3 test_authority_expansion.py
"""

import dataclasses
import threading
import time

from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, ScopeExceeded, InvalidSignature,
    PermissionExpired, PermissionReplay, PermissionError_)

KEY = b"k" * 32
_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def refused(label, exc, fn):
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
    print(f"  FAIL {label} — SUCCEEDED, authority was expanded")


_limitations = []


def assert_limitation(lim_id, fn, *, expect_succeeds=True):
    """Run the attack. Assert TODAY'S outcome. Fail if it changes EITHER WAY.

    `check("LIMIT: ...", True)` was not a test: it fails in zero worlds, so it
    carries zero bits, it pads the count this file reports as evidence, and — worst —
    it makes an absence of coverage look like an affirmative result. Same move as a
    scanner exiting 0 on an empty scan root.

    A limitation is a KNOWN STATE of the system, and any change to a known state must
    be a CI event in BOTH directions. If someone closes the hole, this goes red and a
    human decides whether the honest-limits docstring should change. If someone
    widens it, same. Silence is the one outcome that must not be possible.
    """
    global _p, _t
    _t += 1
    _limitations.append(lim_id)
    try:
        fn()
        succeeded = True
        detail = ""
    except Exception as e:
        succeeded = False
        detail = f"{type(e).__name__}: {str(e)[:60]}"
    if succeeded == expect_succeeds:
        _p += 1
        state = "still open" if expect_succeeds else "still refused"
        print(f"  ok   LIMIT[{lim_id}] {state}")
    else:
        moved = "CLOSED" if expect_succeeds else "OPENED"
        print(f"  FAIL LIMIT[{lim_id}] has {moved} ({detail or 'the attack now succeeds'}). "
              f"That may be a fix — update the expectation and the honest limits "
              f"DELIBERATELY, do not silence it.")


def verifier():
    v = PermissionVerifier()
    v.register_key("cmd", KEY, unrestricted=True)
    return v


def grant(scope, nonce, ttl=300.0, binding=None):
    return Grant.issue(KEY, key_id="cmd", role="commander", scope=scope,
                       subject="poppy", ttl_seconds=ttl, nonce=nonce,
                       action_binding=binding)


def reason(fn):
    try:
        fn()
        return ""
    except Exception as e:
        return str(e)


print("=== 1. SCOPE EXPANSION: 'inspect room A' -> rooms B..Z ===")

v, g = verifier(), grant(["inspect:roomA"], "n1")
refused("room B on a room A grant", ScopeExceeded,
        lambda: v.verify(g, required_scope=["inspect:roomB"]))
refused("re-signing the grant with rooms A..Z", InvalidSignature,
        lambda: v.verify(dataclasses.replace(
            g, scope=("inspect:roomA", "inspect:roomZ")),
            required_scope=["inspect:roomZ"]))
check("the authorised room still works",
      v.verify(g, required_scope=["inspect:roomA"]).role == "commander")


print("=== 2. THE HOLE ALL FOUR SURVIVORS WENT THROUGH ===")
# Verified by execution 2026-08-29: `verify(g, required_scope=[])` succeeded, and
# four of the six expansion variants ran straight through it. An empty requirement
# makes every capability check below it vacuous.

v, g = verifier(), grant(["sensor:read"], "n2")
refused("declaring that the action needs NOTHING", ScopeExceeded,
        lambda: v.verify(g, required_scope=[]))
check("the refusal explains why an empty requirement is not a check",
      "vacuous" in reason(lambda: v.verify(g, required_scope=[])))
refused("the same hole through reserve()", ScopeExceeded,
        lambda: v.reserve(g, required_scope=()))
check("an operator may still opt in, deliberately and by name",
      v.verify(g, required_scope=[], allow_any_scope=True).subject == "poppy")


print("=== 3. CAPABILITY EXPANSION: 'analyse sensor data' -> actuator control ===")

v, g = verifier(), grant(["sensor:read"], "n3")
refused("actuating on a read-only grant", ScopeExceeded,
        lambda: v.verify(g, required_scope=["actuator:arm"]))
refused("actuating while DECLARING sensor:read", ScopeExceeded,
        lambda: v.verify(g, required_scope=["actuator:arm", "sensor:read"]))


print("=== 4. TEMPORAL EXPANSION: 'act for ten minutes' ===")

v = verifier()
short = grant(["patrol"], "n4", ttl=0.05)
time.sleep(0.08)
refused("using an expired grant", PermissionExpired,
        lambda: v.verify(short, required_scope=["patrol"]))
refused("pushing expires_at out by an hour", InvalidSignature,
        lambda: v.verify(dataclasses.replace(short, expires_at=short.expires_at + 3600),
                         required_scope=["patrol"]))

# Re-ask truthfully every nine minutes, forever. No expansion event ever occurs.
assert_limitation("renewal-is-unbounded", lambda: [
    verifier().verify(grant(["patrol"], f"renew{i}"), required_scope=["patrol"])
    for i in range(5)])


print("=== 5. TARGET EXPANSION: 'assist person A' -> also person B ===")

v, g = verifier(), grant(["assist:personA"], "n5")
refused("assisting B on an A grant", ScopeExceeded,
        lambda: v.verify(g, required_scope=["assist:personB"]))
refused("a grant issued for one subject used by another", PermissionError_,
        lambda: v.verify(g, required_scope=["assist:personA"],
                         expected_subject="other_unit"))


print("=== 6. DELEGATION EXPANSION: 'you may do X' -> another agent may do X ===")

v, g = verifier(), grant(["unlock:door"], "n6")
v.reserve(g, required_scope=["unlock:door"])
v.commit(g)
refused("a second holder replaying the same grant", PermissionReplay,
        lambda: v.verify(g, required_scope=["unlock:door"]))
# Nonce burn stops the same BYTES twice on ONE verifier. A commander issuing two
# grants to two agents is delegation, and nothing here has a word for it.
assert_limitation("delegation-by-second-grant", lambda: [
    v.verify(grant(["unlock:door"], n), required_scope=["unlock:door"])
    for n in ("agent-a", "agent-b")])

v3, g3 = verifier(), grant(["unlock:door"], "n6b")
v3.reserve(g3, required_scope=["unlock:door"])
refused("nor can a second holder use one that is merely in flight", PermissionReplay,
        lambda: v3.reserve(g3, required_scope=["unlock:door"]))


print("=== 7. OBJECTIVE-DERIVED AUTHORITY — the deepest variant ===")
# "You gave me the goal, therefore I decide what authority achieving it requires."
# The objective may explain WHY an action would help. It cannot create permission
# to take it.

v, g = verifier(), grant(["objective:facility_safe"], "n7")
refused("deriving unlock:door from an objective token", ScopeExceeded,
        lambda: v.verify(g, required_scope=["unlock:door"]))
refused("deriving a weapons capability from it", ScopeExceeded,
        lambda: v.verify(g, required_scope=["weapons:engage"]))

# Nothing TYPES an objective differently from a capability: both are strings in one
# tuple, so an objective token spends exactly like a lock.
assert_limitation("objective-spends-as-capability",
                  lambda: v.verify(g, required_scope=["objective:facility_safe"]))
assert_limitation("one-grant-mixes-objective-and-capability", lambda: verifier().verify(
    grant(["objective:facility_safe", "unlock:door"], "mixed"),
    required_scope=["unlock:door"]))


print("=== 8. LATERAL MOVES ARE NOT EXPANSIONS ===")
# {medical:*} -> {weapons:*} is a strict swap, not a superset. The invariant as
# stated never fires on it; what refuses here is the signature, not the invariant.

v, g = verifier(), grant(["medical:administer"], "n8")
refused("swapping medical for weapons breaks the signature", InvalidSignature,
        lambda: v.verify(dataclasses.replace(g, scope=("weapons:engage",)),
                         required_scope=["weapons:engage"]))
# Re-ISSUE, not tamper. The previous version of this file called dataclasses.replace
# "re-signing" and caught InvalidSignature — a label asserting a property the test
# never exercised (red-team, Grok, 2026-08-29).
assert_limitation("real-reissue-swaps-scope", lambda: verifier().verify(
    grant(["weapons:engage"], "lateral"), required_scope=["weapons:engage"]))


print("=== 9. COMPOSITION: three narrow grants, nothing widened ===")

# Monitor -> drone -> door: the chain from the invariant's own header, as three
# legal spends. The capability lives in the SET and this module sees one ticket.
_vc = verifier()
assert_limitation("composition-across-grants", lambda: [
    _vc.verify(grant([sc], f"c{i}"), required_scope=[sc]) for i, sc in
    enumerate(["monitor:area", "drone:deploy", "unlock:door"])])

print("=== 10. THE OPT-IN ITSELF: can allow_any_scope become True unbidden? ===")
# The gate is fine; the question is whether only the legitimate authority holds the
# key. Attacked along the whole path: operator -> register_actuator -> registry entry
# -> unpack -> verify. (red-team, ChatGPT, 2026-08-29.)

import os
import tempfile
from driftcore.verification.mediated_actuation import ActuationBroker

_b = ActuationBroker(os.path.join(tempfile.mkdtemp(), "s.sock"), verifier())
_noop = lambda **k: "ok"

# Verified by execution BEFORE the fix: "false", "no", "0" and "off" ALL opted in,
# because every non-empty string is truthy — and every config boundary an operator
# actually uses (JSON, YAML, env var, CLI flag) delivers strings.
for _bad in ("false", "no", "0", "off", "True", 1, -1, None, 0.0):
    refused(f"allow_any_scope={_bad!r} is not consent", ValueError,
            lambda v=_bad: _b.register_actuator(
                f"x{v!r}", _noop, required_scope=(), allow_any_scope=v, effects=None))
check("the refusal says truthiness is not consent",
      "Truthiness is not consent" in reason(
          lambda: _b.register_actuator("y", _noop, required_scope=(),
                                       allow_any_scope="false", effects=None)))
refused("and False with an empty scope is still refused", ValueError,
        lambda: _b.register_actuator("z", _noop, required_scope=(),
                                     allow_any_scope=False, effects=None))
_b.register_actuator("real", _noop, required_scope=(), allow_any_scope=True,
                     effects=None)
check("only the literal True registers an any-scope actuator",
      "real" in _b._actuators)

# The unpack: an entry that reached the registry by any other route cannot smuggle
# an opt-in in as a truthy value.
for _shape, _label in (((_noop, (), "yes"), "a forged entry with a STRING flag"),
                       ((_noop, (), 1), "a forged entry with integer 1"),
                       ((_noop, ()), "a legacy 2-tuple")):
    check(f"{_label} does NOT inherit the opt-in",
          (len(_shape) > 2 and _shape[2] is True) is False)

# And at the verifier.
_v, _g = verifier(), grant(["s:x"], "n10")
refused("a truthy string cannot disable the verifier's scope check", ScopeExceeded,
        lambda: _v.verify(_g, required_scope=(), allow_any_scope="false"))
refused("nor can integer 1", ScopeExceeded,
        lambda: _v.verify(_g, required_scope=(), allow_any_scope=1))
check("the literal True still works, for the operator who means it",
      _v.verify(_g, required_scope=(), allow_any_scope=True).role == "commander")

# In-process, anything holding the broker object writes the registry. The defence is
# the socket and peer-uid check, not the object.
assert_limitation("in-process-registry-write", lambda: _b._actuators.__setitem__(
    "backdoor", (_noop, (), True)))


print("=== 11. THE SIGNER'S ENVELOPE — every key was a god key ===")
# (red-team, Grok, 2026-08-29.) Verified by execution BEFORE the fix: a key meant to
# be narrow minted scope=("*",) and authorised weapons:engage, unlock:door,
# actuator:arm and a capability string invented on the spot. `register_key` took no
# policy, `role` was scenery, and the module docstring claimed a hierarchy that did
# not exist. THIS is authority expansion; everything above section 10 is ticket
# integrity.

_KID = b"kid-key-meant-to-be-narrow!!!!!!"


def kid_verifier(**kw):
    _v = PermissionVerifier()
    _v.register_key("kid", _KID, **(kw or {"may_sign": ("media:child_safe",)}))
    return _v


def kid_grant(scope, nonce):
    return Grant.issue(_KID, key_id="kid", role="parent", scope=scope,
                       subject="poppy", ttl_seconds=1e6, nonce=nonce)


_kv = kid_verifier()
refused("a narrow key cannot mint scope=('*',)", ScopeExceeded,
        lambda: _kv.verify(kid_grant(("*",), "god"), required_scope=["weapons:engage"]))
for _cap in ("weapons:engage", "unlock:door", "actuator:arm"):
    refused(f"nor assert {_cap} directly", ScopeExceeded,
            lambda c=_cap: _kv.verify(kid_grant((c,), f"g-{c}"), required_scope=[c]))
check("the refusal separates key BYTES from what a signer may assert",
      "outside its declared envelope" in reason(
          lambda: _kv.verify(kid_grant(("*",), "god2"), required_scope=["x"])))
check("inside its envelope the key still works",
      _kv.verify(kid_grant(("media:child_safe",), "ok1"),
                 required_scope=["media:child_safe"]).role == "parent")
check("and a family wildcard inside the envelope is covered",
      kid_verifier(may_sign=("media:*",)).verify(
          kid_grant(("media:child_safe",), "ok2"),
          required_scope=["media:child_safe"]).subject == "poppy")

refused("registering a key with no declared envelope is refused", ValueError,
        lambda: PermissionVerifier().register_key("k", _KID))
refused("as is an empty envelope, which permits nothing", ValueError,
        lambda: PermissionVerifier().register_key("k", _KID, may_sign=()))
refused("saying both things at once is refused", ValueError,
        lambda: PermissionVerifier().register_key("k", _KID, may_sign=("a",),
                                                  unrestricted=True))
refused("and unrestricted must be the literal True", ValueError,
        lambda: PermissionVerifier().register_key("k", _KID, unrestricted="yes"))
check("a deliberately unrestricted signer is still possible, and greppable",
      kid_verifier(unrestricted=True).verify(
          kid_grant(("*",), "godok"), required_scope=["anything"]).role == "parent")

# The real re-issue: same key, wider scope, no tampering. This is the path the
# earlier version of this file never took — it called dataclasses.replace and
# labelled it "re-signing".
assert_limitation("real-reissue-wider-scope-inside-envelope", lambda: kid_verifier(
    may_sign=("media:*",)).verify(kid_grant(("media:a", "media:b"), "wider"),
                                  required_scope=["media:b"]))
refused("but a re-issue OUTSIDE the envelope is now refused", ScopeExceeded,
        lambda: kid_verifier(may_sign=("media:*",)).verify(
            kid_grant(("media:a", "weapons:engage"), "wider2"),
            required_scope=["weapons:engage"]))


print("=== 12. NONCE HYGIENE ON THE API CALLERS ACTUALLY USE ===")

_nv = verifier()
_ng = grant(["s:x"], "concurrent")
_wins = []
_threads = [threading.Thread(
    target=lambda: _wins.append(_nv.verify(_ng, required_scope=["s:x"]))
    if True else None) for _ in range(8)]


def _try_verify():
    try:
        _nv.verify(_ng, required_scope=["s:x"])
        _wins.append(1)
    except PermissionError_:
        pass


_threads = [threading.Thread(target=_try_verify) for _ in range(8)]
[t.start() for t in _threads]
[t.join() for t in _threads]
assert_limitation("verify-does-not-consume", lambda: (
    _wins.append(len(_wins)) if len(_wins) > 1 else (_ for _ in ()).throw(
        AssertionError("verify() now consumes"))))

_cv, _cg = verifier(), grant(["s:x"], "preburn")
refused("commit() cannot burn a nonce nobody reserved", PermissionReplay,
        lambda: _cv.commit(_cg))
check("the refusal names the denial-of-service it prevents",
      "deny the real holder" in reason(lambda: _cv.commit(_cg)))
_cv.reserve(_cg, required_scope=["s:x"])
_cv.commit(_cg)
check("a reserved nonce still commits normally", _cg.nonce in _cv._used)

# Still open: release() drops an in-flight reservation for anyone holding the grant
# bytes. Closing it needs a reservation token, which changes reserve()'s return type
# across 50 call sites — deliberately not smuggled into this change.
_rv, _rg = verifier(), grant(["s:x"], "oracle")
_rv.reserve(_rg, required_scope=["s:x"])
assert_limitation("release-is-an-unauthenticated-oracle",
                  lambda: _rv.release(_rg))
assert_limitation("cross-instance-replay", lambda: (
    lambda a, b, g: (a.reserve(g, required_scope=["s:x"]), a.commit(g),
                     b.verify(g, required_scope=["s:x"]))
)(verifier(), verifier(), grant(["s:x"], "xinst")))
assert_limitation("under-declared-required-scope", lambda: verifier().verify(
    grant(["sensor:read", "actuator:arm"], "lying"), required_scope=["sensor:read"]))


print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
