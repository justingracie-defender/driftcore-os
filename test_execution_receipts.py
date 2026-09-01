"""
test_execution_receipts.py — five failure boundaries, kept separate.

An external pass (ChatGPT, 2026-08-14) proposed a rule worth stating plainly:

    human approval != authorization != command delivery != actuator acceptance
                                                        != physical effect

Collapsing any two of those is how a system reports APPROVED about something that
did not happen as approved. This file tests the three boundaries that were closable
here, and states the two that were not.

  1. CROSS-PROCESS NONCE. `in` then `.add()` is two statements. One process is safe
     under a lock; two processes sharing a durable store both see the nonce absent.
     Closed with `SqliteNonceStore.consume()` — a plain INSERT against a PRIMARY KEY,
     so the DATABASE picks the winner. Tested with real processes, not threads.

  2. EXECUTION RECEIPT. Everything the wall proves stops at "the broker commanded the
     approved action". An actuator that inserts a default, converts a unit or ignores
     its kwargs breaks the chain after the last check. Closed for ACCIDENTAL
     divergence by holding an actuator to the args it reports.

  3. DISPLAY FIDELITY. `CanonicalAction` generates the human's text and the signed
     identity from one object, so there is no second description to drift.

NOT closed, and deliberately not claimed: a lying actuator (only hardware clamping
can answer that, and that is LifeCore's layer), and what a human actually saw.

Run: python3 test_execution_receipts.py
"""

import os
import subprocess
import sys
import tempfile

from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.authority.human_identity import HumanIdentityVerifier
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
from driftcore.verification.human_authorization import (
    CanonicalAction, HumanApprovalGate, envelope_digest, attestation_digest,
    effect_id, approve)

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
OPKEY = b"\x33" * 32
CUP = {"force_n": 20, "duration_s": 2, "target": "cup"}
ENV = {"max_force_n": 20}
_i = [0]


def nx(p):
    _i[0] += 1
    return f"{p}-{_i[0]}-{os.getpid()}"


print("== 20 PROCESSES race for one nonce; the database picks the winner ==")

tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "nonces.db")
CHILD = f'''
import sys
sys.path.insert(0, {os.getcwd()!r})
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
s = SqliteNonceStore({db!r}, retention_seconds=7200,
                     max_grant_ttl_seconds=3600, skew_seconds=60,
                     single_owner=False)
print("WON" if s.consume("contested-nonce") else "LOST")
s.close()
'''
script = os.path.join(tmp, "child.py")
open(script, "w").write(CHILD)

procs = [subprocess.Popen([sys.executable, script], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) for _ in range(20)]
outs = []
for p in procs:
    o, e = p.communicate(timeout=60)
    outs.append((o.strip(), e.strip()))

wins = sum(1 for o, _ in outs if o == "WON")
losses = sum(1 for o, _ in outs if o == "LOST")
errs = [e for o, e in outs if o not in ("WON", "LOST")]
print(f"     {wins} won, {losses} lost, {len(errs)} errored")
ok(wins == 1, f"exactly one process claimed the nonce (got {wins})")
ok(wins + losses == 20, f"every process got a definite answer ({errs[:1]})")

s = SqliteNonceStore(db, retention_seconds=7200, max_grant_ttl_seconds=3600,
                     skew_seconds=60, single_owner=False)
ok(s.consume("contested-nonce") is False,
   "a later claim on the same nonce still loses")
ok(s.consume("a-different-nonce") is True,
   "an unrelated nonce is unaffected (durable, not merely broken)")
s.close()

s2 = SqliteNonceStore(db, retention_seconds=7200, max_grant_ttl_seconds=3600,
                      skew_seconds=60, single_owner=False)
ok(s2.consume("contested-nonce") is False,
   "and it is STILL spent after a reopen")
s2.close()


print("== the verifier uses the atomic claim when the store offers one ==")

s3 = SqliteNonceStore(os.path.join(tmp, "v.db"), retention_seconds=7200,
                      max_grant_ttl_seconds=3600, skew_seconds=60)
hv = HumanIdentityVerifier(used_nonces=s3)
hv.register_principal("justin", HKEY)
gate = HumanApprovalGate(hv)
a1 = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
             params=CUP, ttl_seconds=600, nonce=nx("att"), broker_id="broker-A")
ok(gate.verify(a1, actuator_id="arm_left", command="grip", params=CUP,
               broker_id="broker-A") == "justin", "first use succeeds")
spent = False
try:
    gate.verify(a1, actuator_id="arm_left", command="grip", params=CUP,
                broker_id="broker-A")
except Exception:
    spent = True
ok(spent, "second use is refused via the atomic claim")
s3.close()


print("== AUTHORIZED, COMMAND_ACCEPTED and EXECUTION_CONFIRMED are three facts ==")


def build(actuator):
    v = PermissionVerifier()
    v.register_key("operator", OPKEY, unrestricted=True)
    ihv = HumanIdentityVerifier()
    ihv.register_principal("justin", HKEY)
    b = ActuationBroker("/tmp/dc_receipts.sock", v, broker_id="broker-A",
                        human_approval=HumanApprovalGate(ihv, require_envelope=True),
                        require_effect_binding=True,
                        envelope_source=lambda: ENV)
    b.register_actuator("arm_left", actuator, required_scope=("arm_left:grip",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
    return b


def run(b, params=None):
    params = dict(CUP if params is None else params)
    dh = b.declaration_hash("arm_left")
    ed = envelope_digest(ENV)
    a = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                params=params, ttl_seconds=600, nonce=nx("att"),
                broker_id="broker-A", subject="robot-1", effects_hash=dh,
                envelope_hash=ed)
    binding = PermissionVerifier.bind_action(
        "arm_left", "grip", params, broker_id="broker-A", effects_hash=dh,
        envelope_hash=ed, attestation_hash=attestation_digest(a), subject="robot-1")
    g = Grant.issue(OPKEY, key_id="operator", role="operator",
                    scope=("arm_left:grip",), subject="robot-1", ttl_seconds=300,
                    nonce=nx("g"), action_binding=binding).to_dict()
    return b._handle({"op": "execute", "actuator_id": "arm_left", "command": "grip",
                      "params": params, "grant": g,
                      "attestation": {"principal": a.principal, "action": a.action,
                                      "issued_at": a.issued_at,
                                      "expires_at": a.expires_at,
                                      "nonce": a.nonce, "sig": a.sig}})


# (a) An actuator that makes no claim: command accepted, nothing more proven.
r = run(build(lambda **kw: "done"))
ok(r.get("ok") is True, "a silent actuator still executes")
ok(r.get("execution_confirmed") is None,
   "and confirmation is None — NOT True — because it claimed nothing")

# (b) An honest actuator that reports what it ran.
r = run(build(lambda **kw: {"executed_args": dict(kw), "result": "gripped"}))
ok(r.get("ok") is True, "an actuator returning a matching receipt executes")
ok(r.get("execution_confirmed") is True, "and execution is CONFIRMED")

# (c) The case the whole chain previously could not see: an actuator that quietly
#     substitutes a value after every authorization check has passed.
cheated = []


def cheating_actuator(**kw):
    real = dict(kw)
    real["force_n"] = 900          # ignores what it was told
    cheated.append(real)
    return {"executed_args": real, "result": "gripped"}


r = run(build(cheating_actuator))
ok(r.get("error") == "execution_mismatch",
   "an actuator executing different arguments is caught")
ok(r.get("executed_args", {}).get("force_n") == 900,
   "the mismatch names what actually ran")
ok(r.get("approved_args", {}).get("force_n") == 20,
   "and what had been approved")
ok(len(cheated) == 1,
   "the report is NOT a clean refusal — the physical action did occur")

# (d) An actuator that silently inserts a default nobody approved.
r = run(build(lambda **kw: {"executed_args": dict(kw, retries=3)}))
ok(r.get("error") == "execution_mismatch",
   "an unapproved default inserted by the actuator is caught")


print("== display fidelity: one object, both outputs ==")

act = CanonicalAction("arm_left", "grip", CUP, broker_id="broker-A",
                      envelope=ENV, subject="robot-1")
text = act.describe()
ok(all(str(v) in text or repr(v) in text for v in CUP.values()),
   "every approved parameter appears in the text the human reads")
ok("max_force_n" in text, "the safety envelope appears in the text")
ok("robot-1" in text, "the subject appears in the text")
ok(act.identity() in text, "the identity the signature covers is shown too")

att = act.approve_with(HKEY, principal="justin", ttl_seconds=600, nonce=nx("att"))
ok(att.action == act.identity(),
   "the signature covers exactly the identity that was rendered")

hv2 = HumanIdentityVerifier()
hv2.register_principal("justin", HKEY)
ok(HumanApprovalGate(hv2).verify(
    att, actuator_id="arm_left", command="grip", params=CUP,
    broker_id="broker-A", envelope_hash=envelope_digest(ENV),
    subject="robot-1") == "justin",
   "and the gate accepts it against the same action")

sneaky = CanonicalAction("arm_left", "grip", dict(CUP, force_n=900),
                         broker_id="broker-A", envelope=ENV, subject="robot-1")
ok("900" in sneaky.describe(),
   "a changed parameter cannot be hidden from the description")
ok(sneaky.identity() != act.identity(),
   "and it produces a different identity, so the old approval will not verify")

print("-" * 60)
print(f"  {passed}/{total} tests passed")
if passed != total:
    raise SystemExit(1)
