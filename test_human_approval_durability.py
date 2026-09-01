"""
test_human_approval_durability.py — the two external dependencies the gate leans on.

A third red-team pass (Grok, 2026-08-14) observed that the binding is only as strong
as two things the gate does not own:

  * the USED-NONCE STORE. `HumanIdentityVerifier` kept spent nonces in a plain set,
    so a restart RE-ARMED every outstanding attestation — approvals a human had
    already spent became spendable again. Verified here, then closed by allowing a
    durable store to be injected.

  * the ENVELOPE SOURCE. It is a caller-supplied callable over caller-owned state.
    The broker samples it twice and refuses if the two samples differ; that is the
    only property available, and it is worth testing under concurrency rather than
    asserting.

One recommendation from that pass is deliberately NOT taken. It proposed snapshotting
the envelope once at the start of `_handle` and reusing the same bytes for both the
binding check and the execution check. That would make the second check a tautology —
comparing a value to itself always passes — and would delete the TOCTOU detection the
previous pass had just established. The two samples must be genuinely separate reads;
what a snapshot legitimately buys is protection against a torn read WITHIN one sample,
which is a different concern and is covered by the concurrent test below.

Run: python3 test_human_approval_durability.py
"""

import os
import tempfile
import threading

from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.authority.human_identity import HumanIdentityVerifier
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
from driftcore.verification.human_authorization import (
    HumanApprovalGate, envelope_digest, attestation_digest, approve)

passed = total = 0


def ok(c, label):
    global passed, total
    total += 1
    if c:
        passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


HKEY = b"human-key"
OPKEY = b"\x22" * 32
CUP = {"force_n": 20, "duration_s": 2, "target": "cup"}
ENV = {"max_force_n": 20}
env = {"cur": ENV}
_i = [0]


def nx(p):
    _i[0] += 1
    return f"{p}-{_i[0]}"


print("== an in-memory used-set re-arms every approval on restart ==")

att_nonce = nx("att")
act = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
              params=CUP, ttl_seconds=3600, nonce=att_nonce, broker_id="broker-A")

v1 = HumanIdentityVerifier()
v1.register_principal("justin", HKEY)
g1 = HumanApprovalGate(v1)
ok(g1.verify(act, actuator_id="arm_left", command="grip", params=CUP,
             broker_id="broker-A") == "justin", "the approval is spent once")

# "Restart": a brand-new verifier, exactly what a process restart produces.
v2 = HumanIdentityVerifier()
v2.register_principal("justin", HKEY)
g2 = HumanApprovalGate(v2)
rearmed = False
try:
    g2.verify(act, actuator_id="arm_left", command="grip", params=CUP,
              broker_id="broker-A")
    rearmed = True
except Exception:
    pass
ok(rearmed,
   "CONFIRMED: with the default in-memory set, a restart makes a spent approval "
   "spendable again — this is why the store must be injectable")


print("== a durable store survives the restart ==")

tmpdir = tempfile.mkdtemp()
dbpath = os.path.join(tmpdir, "attestation_nonces.db")


def durable_store():
    return SqliteNonceStore(dbpath, retention_seconds=7200,
                            max_grant_ttl_seconds=3600, skew_seconds=60)


att2 = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
               params=CUP, ttl_seconds=3600, nonce=nx("att"), broker_id="broker-A")

store_a = durable_store()
va = HumanIdentityVerifier(used_nonces=store_a)
va.register_principal("justin", HKEY)
ok(HumanApprovalGate(va).verify(att2, actuator_id="arm_left", command="grip",
                                params=CUP, broker_id="broker-A") == "justin",
   "the approval is spent once against the durable store")
store_a.close()

store_b = durable_store()          # reopened: the restart
vb = HumanIdentityVerifier(used_nonces=store_b)
vb.register_principal("justin", HKEY)
survived = False
try:
    HumanApprovalGate(vb).verify(att2, actuator_id="arm_left", command="grip",
                                 params=CUP, broker_id="broker-A")
except Exception:
    survived = True
ok(survived, "after a restart the spent approval is STILL spent")

fresh = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                params=CUP, ttl_seconds=3600, nonce=nx("att"), broker_id="broker-A")
ok(HumanApprovalGate(vb).verify(fresh, actuator_id="arm_left", command="grip",
                                params=CUP, broker_id="broker-A") == "justin",
   "and a NEW approval still works (durable, not merely broken)")
store_b.close()


print("== envelope mutated by a background thread, many requests in flight ==")

v = PermissionVerifier()
v.register_key("operator", OPKEY, unrestricted=True)
hv = HumanIdentityVerifier()
hv.register_principal("justin", HKEY)
broker = ActuationBroker("/tmp/dc_durability.sock", v, broker_id="broker-A",
                         human_approval=HumanApprovalGate(hv, require_envelope=True),
                         require_effect_binding=True,
                         envelope_source=lambda: env["cur"])
executed = []
broker.register_actuator("arm_left", lambda **kw: executed.append(dict(kw)) or "done",
                         required_scope=("arm_left:grip",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")

DH = broker.declaration_hash("arm_left")
ENV_D = envelope_digest(ENV)


def make_pair():
    a = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                params=CUP, ttl_seconds=600, nonce=nx("att"), broker_id="broker-A",
                subject="robot-1", effects_hash=DH, envelope_hash=ENV_D)
    binding = PermissionVerifier.bind_action(
        "arm_left", "grip", CUP, broker_id="broker-A", effects_hash=DH,
        envelope_hash=ENV_D, attestation_hash=attestation_digest(a),
        subject="robot-1")
    g = Grant.issue(OPKEY, key_id="operator", role="operator",
                    scope=("arm_left:grip",), subject="robot-1", ttl_seconds=300,
                    nonce=nx("g"), action_binding=binding).to_dict()
    return a, g


pairs = [make_pair() for _ in range(50)]
outcomes = []
stop = threading.Event()


def churn():
    """Flip the envelope continuously while requests are mid-flight."""
    while not stop.is_set():
        env["cur"] = {"max_force_n": 800}
        env["cur"] = ENV


barrier = threading.Barrier(50)


def fire(a, g):
    barrier.wait()
    outcomes.append(broker._handle(
        {"op": "execute", "actuator_id": "arm_left", "command": "grip",
         "params": dict(CUP), "grant": g,
         "attestation": {"principal": a.principal, "action": a.action,
                         "issued_at": a.issued_at, "expires_at": a.expires_at,
                         "nonce": a.nonce, "sig": a.sig}}))


churner = threading.Thread(target=churn, daemon=True)
churner.start()
threads = [threading.Thread(target=fire, args=p) for p in pairs]
for t in threads:
    t.start()
for t in threads:
    t.join()
stop.set()
churner.join(timeout=2)

succeeded = sum(1 for o in outcomes if o.get("ok") is True)
refused_env = sum(1 for o in outcomes if o.get("error") == "envelope_changed")
other = [o.get("error") for o in outcomes
         if o.get("ok") is not True and o.get("error") != "envelope_changed"]

print(f"     {succeeded} executed, {refused_env} refused envelope_changed, "
      f"{len(other)} other")
ok(len(executed) == succeeded,
   "every reported success corresponds to exactly one actuation, and no more")
ok(not other,
   f"no request failed for an unexplained reason (saw {sorted(set(other))})")
ok(succeeded + refused_env == 50,
   "every request either ran under a stable envelope or was refused because it moved")
ok(all(e == CUP for e in executed),
   "every actuation carried exactly the approved parameters")
print(f"     NOTE: a GIL-scheduled churn thread is a weak adversary — this run "
      f"exercised the window {refused_env} time(s). The deterministic case below "
      f"is what gives the claim teeth.")


print("== deterministic: a source that MOVES between the two samples ==")

flip = {"n": 0}


def moving_source():
    """Returns a different envelope on every call, so the broker's two samples of a
    single request are guaranteed to disagree. Not a realistic deployment — a
    deliberate worst case, so the detection is proven rather than hoped for."""
    flip["n"] += 1
    return {"max_force_n": 20} if flip["n"] % 2 else {"max_force_n": 800}


v3 = PermissionVerifier()
v3.register_key("operator", OPKEY, unrestricted=True)
hv3 = HumanIdentityVerifier()
hv3.register_principal("justin", HKEY)
b3 = ActuationBroker("/tmp/dc_durability2.sock", v3, broker_id="broker-A",
                     human_approval=HumanApprovalGate(hv3, require_envelope=True),
                     require_effect_binding=True, envelope_source=moving_source)
ran = []
b3.register_actuator("arm_left", lambda **kw: ran.append(dict(kw)) or "done",
                     required_scope=("arm_left:grip",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")

DH3 = b3.declaration_hash("arm_left")
out3 = []
for _ in range(20):
    seen_env = envelope_digest({"max_force_n": 20})
    a = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                params=CUP, ttl_seconds=600, nonce=nx("att"), broker_id="broker-A",
                subject="robot-1", effects_hash=DH3, envelope_hash=seen_env)
    binding = PermissionVerifier.bind_action(
        "arm_left", "grip", CUP, broker_id="broker-A", effects_hash=DH3,
        envelope_hash=seen_env, attestation_hash=attestation_digest(a),
        subject="robot-1")
    g = Grant.issue(OPKEY, key_id="operator", role="operator",
                    scope=("arm_left:grip",), subject="robot-1", ttl_seconds=300,
                    nonce=nx("g"), action_binding=binding).to_dict()
    out3.append(b3._handle(
        {"op": "execute", "actuator_id": "arm_left", "command": "grip",
         "params": dict(CUP), "grant": g,
         "attestation": {"principal": a.principal, "action": a.action,
                         "issued_at": a.issued_at, "expires_at": a.expires_at,
                         "nonce": a.nonce, "sig": a.sig}}))

moved = sum(1 for o in out3 if o.get("error") == "envelope_changed")
executed3 = sum(1 for o in out3 if o.get("ok") is True)
print(f"     {executed3} executed, {moved} caught by the execution-time re-read")
ok(moved > 0, "a moving envelope IS caught (the window is genuinely checked)")
ok(len(ran) == executed3,
   "no request actuated while its two envelope samples disagreed")

print("-" * 60)
print(f"  {passed}/{total} tests passed")
if passed != total:
    raise SystemExit(1)
