"""
test_human_approval_races.py — the last few metres, where the crypto stops helping.

An external red-team pass (ChatGPT, 2026-08-14) argued the remaining risk was no
longer "can the human signature be forged" but:

    can the exact thing the human approved be changed, substituted, raced or
    reinterpreted between approval, verification and physical execution?

Four items came back in red ink. Run against the real broker, three were already
true and one was a live bug:

  * concurrent replay of one attestation  -> already atomic (verified, kept here)
  * exact approved effect reaches actuator -> already true (verified, kept here)
  * mutable params changed mid-request     -> already refused (verified, kept here)
  * ENVELOPE CHANGED INSIDE THE WINDOW     -> REPRODUCED. Executed at 800N on a
                                              20N approval. Fixed at step 4c.

A fifth, raised as a question rather than a finding, was also real: grant.subject
was not part of the approved identity, so an approval for robot-1 rode into a grant
naming robot-2 and executed. Now bound.

These are execution-boundary tests on purpose. test_human_authorization.py proves
the binding is sound; this proves the binding is what the machine obeys.

Run: python3 test_human_approval_races.py
"""

import threading

from driftcore.verification.mediated_actuation import ActuationBroker, _stable_value
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.authority.human_identity import HumanIdentityVerifier
from driftcore.verification.human_authorization import (
    HumanApprovalGate, HumanApprovalError, envelope_digest, attestation_digest,
    approve, effect_id)

passed = total = 0


def ok(c, label):
    global passed, total
    total += 1
    if c:
        passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def refuses(label, fn):
    global passed, total
    total += 1
    try:
        fn()
    except HumanApprovalError:
        passed += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}: {e})")
        return
    print(f"  FAIL {label} (did NOT refuse)")


OPKEY = b"\x11" * 32
HKEY = b"human-key"
ENV20 = {"max_force_n": 20}
ENV800 = {"max_force_n": 800}
CUP = {"force_n": 20, "duration_s": 2, "target": "cup"}
SUBJECT = "robot-1"
env = {"cur": ENV20}
_i = [0]


def nx(p):
    _i[0] += 1
    return f"{p}-{_i[0]}"


def build(ledger=None):
    v = PermissionVerifier()
    v.register_key("operator", OPKEY, unrestricted=True)
    hv = HumanIdentityVerifier()
    hv.register_principal("justin", HKEY)
    b = ActuationBroker("/tmp/dc_races.sock", v, broker_id="broker-A",
                        human_approval=HumanApprovalGate(hv, require_envelope=True),
                        require_effect_binding=True,
                        envelope_source=lambda: env["cur"])
    if ledger:
        b._ledger_hook = ledger
    seen = []
    b.register_actuator("arm_left", lambda **kw: seen.append(dict(kw)) or "done",
                        required_scope=("arm_left:grip",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
    return b, seen


def att_for(bk, params, subject=SUBJECT):
    return approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                   params=params, ttl_seconds=300, nonce=nx("att"),
                   broker_id="broker-A", subject=subject,
                   effects_hash=bk.declaration_hash("arm_left"),
                   envelope_hash=envelope_digest(env["cur"]))


def grant_for(bk, params, att, subject=SUBJECT):
    binding = PermissionVerifier.bind_action(
        "arm_left", "grip", params, broker_id="broker-A",
        effects_hash=bk.declaration_hash("arm_left"),
        envelope_hash=envelope_digest(env["cur"]),
        attestation_hash=attestation_digest(att), subject=subject)
    return Grant.issue(OPKEY, key_id="operator", role="operator",
                       scope=("arm_left:grip",), subject=subject, ttl_seconds=60,
                       nonce=nx("g"), action_binding=binding).to_dict()


def req(params, g, att):
    return {"op": "execute", "actuator_id": "arm_left", "command": "grip",
            "params": params, "grant": g,
            "attestation": {"principal": att.principal, "action": att.action,
                            "issued_at": att.issued_at, "expires_at": att.expires_at,
                            "nonce": att.nonce, "sig": att.sig}}


print("== ONE approval cannot authorise TWO simultaneous physical effects ==")

env["cur"] = ENV20
b, seen = build()
att = att_for(b, CUP)
grants = [grant_for(b, CUP, att) for _ in range(100)]   # 100 DISTINCT valid grants
results = []
barrier = threading.Barrier(100)


def worker(g):
    barrier.wait()          # release all 100 at the same instant
    results.append(b._handle(req(dict(CUP), g, att)))


threads = [threading.Thread(target=worker, args=(g,)) for g in grants]
for t in threads:
    t.start()
for t in threads:
    t.join()

succ = sum(1 for r in results if r.get("ok") is True)
ok(succ == 1, f"exactly one of 100 concurrent requests succeeded (got {succ})")
ok(len(seen) == 1, f"the actuator fired exactly once (got {len(seen)})")
ok(all(r.get("error") == "human_approval_rejected"
       for r in results if r.get("ok") is not True),
   "every loser was refused for the right reason, not a generic error")


print("== the envelope cannot move inside the authorization window ==")

env["cur"] = ENV20


def widen(a, c, p):
    env["cur"] = ENV800     # runs after the envelope read, before actuation
    return None


b2, seen2 = build(ledger=widen)
att2 = att_for(b2, CUP)
g2 = grant_for(b2, CUP, att2)
r2 = b2._handle(req(dict(CUP), g2, att2))
ok(r2.get("error") == "envelope_changed",
   "a widened envelope is caught at the execution boundary")
ok(seen2 == [], "and nothing actuated under the envelope the human never saw")
env["cur"] = ENV20


print("== the actuator receives EXACTLY the approved effect ==")

b3, seen3 = build()
att3 = att_for(b3, CUP)
r3 = b3._handle(req(dict(CUP), grant_for(b3, CUP, att3), att3))
ok(r3.get("ok") is True, "the approved action executes")
ok(seen3 and seen3[0] == CUP,
   "no defaults added, no parameters dropped, no normalisation applied")
ok(seen3 and effect_id("arm_left", "grip", seen3[0], broker_id="broker-A",
                       effects_hash=b3.declaration_hash("arm_left"),
                       envelope_hash=envelope_digest(ENV20), subject=SUBJECT)
   == att3.action,
   "the effect identity recomputed FROM WHAT THE ACTUATOR GOT equals what was signed")


print("== params mutated mid-request do not reach the actuator ==")

live = dict(CUP)


def mutate(a, c, p):
    live["force_n"] = 900       # same object the broker holds
    live["target"] = "knife"
    return None


b4, seen4 = build(ledger=mutate)
att4 = att_for(b4, CUP)
r4 = b4._handle(req(live, grant_for(b4, CUP, att4), att4))
ok(r4.get("ok") is not True, "a mid-flight mutation is refused")
ok(seen4 == [], "the mutated values never reached the actuator")


print("== nested params: mutation of a nested object is also caught ==")

NEST = {"target": {"device": "cup", "position": {"x": 1, "y": 2}}}
live_n = {"target": {"device": "cup", "position": {"x": 1, "y": 2}}}


def mutate_nested(a, c, p):
    live_n["target"]["position"]["x"] = 999
    return None


b5, seen5 = build(ledger=mutate_nested)
att5 = att_for(b5, NEST)
r5 = b5._handle(req(live_n, grant_for(b5, NEST, att5), att5))
ok(r5.get("ok") is not True, "a nested mutation is refused too")
ok(seen5 == [], "and nothing actuated")


print("== the approval names the BODY, not just the arm ==")

b6, seen6 = build()
att6 = att_for(b6, CUP, subject="robot-1")
g6 = grant_for(b6, CUP, att6, subject="robot-2")     # same effect, different body
r6 = b6._handle(req(dict(CUP), g6, att6))
ok(r6.get("ok") is not True,
   "an approval for robot-1 does not execute on robot-2")
ok(seen6 == [], "and nothing actuated")


print("== strict types: representation must not become authority ==")

hv = HumanIdentityVerifier()
hv.register_principal("justin", HKEY)
gate = HumanApprovalGate(hv)
good = att_for(build()[0], CUP)


def as_dict(**over):
    d = {"principal": good.principal, "action": good.action,
         "issued_at": good.issued_at, "expires_at": good.expires_at,
         "nonce": good.nonce, "sig": good.sig}
    d.update(over)
    return d


refuses("a numeric principal is not coerced to a name",
        lambda: gate.pair_digest(as_dict(principal=123)))
refuses("a list principal is refused", lambda: gate.pair_digest(as_dict(principal=[])))
refuses("a None signature is refused", lambda: gate.pair_digest(as_dict(sig=None)))
refuses("an empty nonce is refused", lambda: gate.pair_digest(as_dict(nonce="")))
refuses("a boolean timestamp is refused",
        lambda: gate.pair_digest(as_dict(issued_at=True)))
refuses("a string timestamp is refused",
        lambda: gate.pair_digest(as_dict(expires_at="9999999999")))
refuses("NaN in the validity window is refused",
        lambda: gate.pair_digest(as_dict(expires_at=float("nan"))))
refuses("Infinity in the validity window is refused",
        lambda: gate.pair_digest(as_dict(expires_at=float("inf"))))
refuses("-Infinity is refused",
        lambda: gate.pair_digest(as_dict(issued_at=float("-inf"))))
refuses("an approval that expires before it is issued authorises nothing",
        lambda: gate.pair_digest(as_dict(expires_at=good.issued_at - 1)))
refuses("an approval valid for zero time is refused",
        lambda: gate.pair_digest(as_dict(expires_at=good.issued_at)))


print("== canonicalisation: key order is not meaning ==")

ok(effect_id("arm_left", "grip", {"force_n": 20, "target": "cup"})
   == effect_id("arm_left", "grip", {"target": "cup", "force_n": 20}),
   "parameter key order does not change the effect identity")
ok(effect_id("arm_left", "grip", {"force_n": 20})
   != effect_id("arm_left", "grip", {"force_n": 20.5}),
   "a semantic change does change the effect identity")
refuses("NaN nested inside params cannot be bound",
        lambda: effect_id("arm_left", "grip", {"limits": {"force": float("nan")}}))
refuses("Infinity inside a params list cannot be bound",
        lambda: effect_id("arm_left", "grip", {"traj": [1, 2, float("inf")]}))

b7, seen7 = build()
att7 = att_for(b7, CUP)
r7 = b7._handle(req({"force_n": float("nan")}, grant_for(b7, CUP, att7), att7))
ok(r7.get("error") == "unbindable_parameters",
   "the wall refuses unbindable params BY NAME, not as a generic broker error")
ok(seen7 == [], "and nothing actuated")


print("== an actuator's OWN side effects must not rewrite its identity ==")

b8, seen8 = build()
h_before = b8.declaration_hash("arm_left")
att8 = att_for(b8, CUP)
g8a = grant_for(b8, CUP, att8)
r8 = b8._handle(req(dict(CUP), g8a, att8))
ok(r8.get("ok") is True, "the first approved action executes")
ok(b8.declaration_hash("arm_left") == h_before,
   "the declaration hash is unchanged after the actuator ran and wrote to its log")

# The real symptom: a SECOND pre-issued approval must still be honoured.
b9, seen9 = build()
att9a = att_for(b9, CUP)
att9b = att_for(b9, CUP)
g9a = grant_for(b9, CUP, att9a)
g9b = grant_for(b9, CUP, att9b)          # both minted BEFORE any actuation
ok(b9._handle(req(dict(CUP), g9a, att9a)).get("ok") is True,
   "first pre-issued approval works")
ok(b9._handle(req(dict(CUP), g9b, att9b)).get("ok") is True,
   "second pre-issued approval still works (approvals are not single-shot per fleet)")
ok(len(seen9) == 2, "both actuations happened")

ok(_stable_value([1, 2]) != _stable_value([1, 2, 3]),
   "containers still render by content, so partial keywords stay discriminated")
ok(b8._derive_implementation_id("arm_left") != b8._impl_ids["arm_left"],
   "re-deriving after actuation WOULD give a different value — which is exactly "
   "why the identity is captured at registration instead")


# A cold pass found that caching identity at registration removed a detection that
# existed before it: a callable swapped by writing into `_actuators` directly no
# longer changed the digest. The cache is now validated by callable identity, which
# separates a swapped OBJECT (an attack) from the same object whose closed-over state
# moved (ordinary).
b_sw, seen_sw = build()
h_before = b_sw.declaration_hash("arm_left")
seen_sw.append({"noise": 1})
ok(b_sw.declaration_hash("arm_left") == h_before,
   "closed-over state moving does NOT change the identity")
b_sw._actuators["arm_left"] = (lambda **k: "CRUSH",
                               b_sw._actuators["arm_left"][1])
ok(b_sw.declaration_hash("arm_left") != h_before,
   "a callable swapped OUTSIDE register_actuator DOES change it")


print("== representation is authority, by design ==")

ok(effect_id("arm_left", "grip", {"force_n": 20})
   != effect_id("arm_left", "grip", {"force_n": 20.0}),
   "int 20 and float 20.0 are DIFFERENT approvals (no silent normalisation)")
ok(effect_id("arm_left", "grip", {"on": True})
   != effect_id("arm_left", "grip", {"on": 1}),
   "True and 1 are different approvals")
ok(effect_id("arm_left", "grip", {"t": "cafe\u0301"})
   != effect_id("arm_left", "grip", {"t": "caf\u00e9"}),
   "Unicode-equivalent strings are different approvals (normalise before signing)")

b10, seen10 = build()
att10 = att_for(b10, {"force_n": 20})              # human signs the INT
g10 = grant_for(b10, {"force_n": 20}, att10)
r10 = b10._handle(req({"force_n": 20.0}, g10, att10))   # request carries the FLOAT
ok(r10.get("ok") is not True,
   "an approval issued as int does not verify against a request sent as float")
ok(seen10 == [], "and nothing actuated")


print("== params boundary: no silent serialisation of arbitrary objects ==")


class Sneaky:
    def __repr__(self):
        return "20"


refuses("a custom object in params cannot be bound, however it prints",
        lambda: effect_id("arm_left", "grip", {"force_n": Sneaky()}))
refuses("a set in params cannot be bound (no canonical JSON form)",
        lambda: effect_id("arm_left", "grip", {"tags": {"a", "b"}}))


print("-" * 60)
print(f"  {passed}/{total} tests passed")
if passed != total:
    raise SystemExit(1)
