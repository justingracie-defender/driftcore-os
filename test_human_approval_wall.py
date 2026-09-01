"""
test_human_approval_wall.py — the gate has to be ENFORCED, not merely available.

test_human_authorization.py proves the binding is sound in isolation. That is not
the property that matters: the interlock finding earlier in this project was that
`SafeHalt` was correct, `mediated_actuation` was correct, and the system was unsafe
because nothing joined them. So these tests drive the REAL broker request path and
attack it holding a valid operator signing key — the attacker this closes.

The scenario throughout: an attacker holds the operator key (so every grant they
mint verifies), and a real human approval exists for one small action. Every attempt
to turn that pair into something bigger must be refused BY THE WALL.

Run: python3 test_human_approval_wall.py
"""

import time

from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.authority.human_identity import HumanIdentityVerifier
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


OPKEY = b"\x11" * 32          # the operator signing key — assume it is STOLEN
HKEY = b"justins-human-key"   # the human principal key
SOCK = "/tmp/dc_human_wall.sock"
ENV_20N = {"max_force_n": 20, "conditions": ["child_present"]}
ENV_800N = {"max_force_n": 800, "conditions": []}

_env = {"current": ENV_20N}
_nonce = {"i": 0}


def nx(p):
    _nonce["i"] += 1
    return f"{p}-{_nonce['i']}"


def build(with_gate=True, with_envelope=True):
    v = PermissionVerifier()
    v.register_key("operator", OPKEY, unrestricted=True)
    hv = HumanIdentityVerifier()
    hv.register_principal("justin", HKEY)
    gate = HumanApprovalGate(hv, require_envelope=with_envelope) if with_gate else None
    b = ActuationBroker(
        SOCK, v, broker_id="broker-A",
        human_approval=gate, require_effect_binding=True,
        envelope_source=(lambda: _env["current"]) if with_envelope else None)
    fired = []
    b.register_actuator("arm_left", lambda **kw: fired.append(kw),
                        required_scope=("arm_left:grip",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
    return b, fired


def human_approves(actuator_id, command, params, *, envelope=True, bk=None):
    return approve(HKEY, principal="justin", actuator_id=actuator_id,
                   command=command, params=params, ttl_seconds=300,
                   nonce=nx("att"), broker_id="broker-A", subject="robot-1",
                   effects_hash=bk.declaration_hash(actuator_id) if bk else None,
                   envelope_hash=envelope_digest(_env["current"]) if envelope else None)


def attacker_grant(actuator_id, command, params, att, *, envelope=True, bk=None):
    """A grant minted with the STOLEN operator key. It will verify. That is the point."""
    binding = PermissionVerifier.bind_action(
        actuator_id, command, params, broker_id="broker-A",
        effects_hash=bk.declaration_hash(actuator_id) if bk else None,
        envelope_hash=envelope_digest(_env["current"]) if envelope else None,
        attestation_hash=attestation_digest(att) if att is not None else None,
        subject="robot-1" if att is not None else None)
    return Grant.issue(OPKEY, key_id="operator", role="operator",
                       scope=(f"{actuator_id}:{command}",), subject="robot-1",
                       ttl_seconds=60, nonce=nx("g"),
                       action_binding=binding).to_dict()


def req(actuator_id, command, params, g, att=None):
    r = {"op": "execute", "actuator_id": actuator_id, "command": command,
         "params": params, "grant": g}
    if att is not None:
        r["attestation"] = att.__class__ and {
            "principal": att.principal, "action": att.action,
            "issued_at": att.issued_at, "expires_at": att.expires_at,
            "nonce": att.nonce, "sig": att.sig}
    return r


CUP = {"force_n": 20, "duration_s": 2, "target": "cup"}


print("== CONTROL: a real human approval on the real path still actuates ==")

_env["current"] = ENV_20N
b, fired = build()
att = human_approves("arm_left", "grip", CUP, bk=b)
g = attacker_grant("arm_left", "grip", CUP, att, bk=b)
r = b._handle(req("arm_left", "grip", CUP, g, att))
ok(r.get("ok") is True, f"an approved action executes (got {r.get('error')})")
ok(len(fired) == 1, "the actuator actually ran")


print("== a valid signing key with NO human approval does nothing ==")

b, fired = build()
att2 = human_approves("arm_left", "grip", CUP, bk=b)
g2 = attacker_grant("arm_left", "grip", CUP, att2, bk=b)
r = b._handle(req("arm_left", "grip", CUP, g2))          # attestation withheld
ok(r.get("error") == "no_human_attestation",
   "the wall refuses a perfectly-signed grant with no attestation")
ok(fired == [], "and nothing actuated")


print("== the key holder cannot mint their own approval ==")

b, fired = build()
forged = approve(b"attacker-guessed-key", principal="justin",
                 actuator_id="arm_left", command="grip", params=CUP,
                 ttl_seconds=300, nonce=nx("att"), broker_id="broker-A",
                 envelope_hash=envelope_digest(ENV_20N))
g3 = attacker_grant("arm_left", "grip", CUP, forged, bk=b)
r = b._handle(req("arm_left", "grip", CUP, g3, forged))
ok(r.get("error") == "human_approval_rejected", "a forged attestation is refused")
ok(fired == [], "and nothing actuated")


print("== an approval for the cup cannot execute the knife ==")

KNIFE = {"force_n": 900, "duration_s": 2, "target": "knife"}
b, fired = build()
att4 = human_approves("arm_left", "grip", CUP, bk=b)           # human approved the CUP
# Attacker mints a grant for the KNIFE, pinned to the cup approval.
g4 = attacker_grant("arm_left", "grip", KNIFE, att4, bk=b)
r = b._handle(req("arm_left", "grip", KNIFE, g4, att4))
ok(r.get("error") == "human_approval_rejected",
   "the cup approval does not verify against the knife action")
ok(fired == [], "and nothing actuated")


print("== substituting the approval into a differently-bound grant fails ==")

b, fired = build()
att5 = human_approves("arm_left", "grip", CUP, bk=b)
# Grant bound to the action but NOT to this attestation.
g5 = attacker_grant("arm_left", "grip", CUP, None, bk=b)
r = b._handle(req("arm_left", "grip", CUP, g5, att5))
ok(r.get("error") == "grant_rejected",
   "a grant not pinned to the presented approval fails the binding check")
ok(fired == [], "and nothing actuated")


print("== widening the envelope after approval invalidates it ==")

_env["current"] = ENV_20N
b, fired = build()
att6 = human_approves("arm_left", "grip", CUP, bk=b)           # approved under 20N
g6 = attacker_grant("arm_left", "grip", CUP, att6, bk=b)
_env["current"] = ENV_800N                               # widened before execution
r = b._handle(req("arm_left", "grip", CUP, g6, att6))
ok(r.get("ok") is not True, "the approval does not survive the widening")
ok(fired == [], "and nothing actuated")
_env["current"] = ENV_20N


print("== replay: one approval, one action ==")

b, fired = build()
att7 = human_approves("arm_left", "grip", CUP, bk=b)
g7a = attacker_grant("arm_left", "grip", CUP, att7, bk=b)
g7b = attacker_grant("arm_left", "grip", CUP, att7, bk=b)      # fresh grant, same approval
r1 = b._handle(req("arm_left", "grip", CUP, g7a, att7))
r2 = b._handle(req("arm_left", "grip", CUP, g7b, att7))
ok(r1.get("ok") is True, "the first use succeeds")
ok(r2.get("error") == "human_approval_rejected",
   "the same approval cannot drive a second action even with a fresh grant")
ok(len(fired) == 1, "exactly one actuation happened")


print("== an unconfigured broker refuses an approval rather than ignoring it ==")

b, fired = build(with_gate=False, with_envelope=False)
att8 = human_approves("arm_left", "grip", CUP, envelope=False)
g8 = attacker_grant("arm_left", "grip", CUP, None, envelope=False)
r = b._handle(req("arm_left", "grip", CUP, g8, att8))
ok(r.get("error") == "human_approval_unconfigured",
   "a broker with no gate refuses a presented approval instead of silently ignoring it")


print("== an unrelated refusal must not burn the human's approval ==")

b, fired = build()
b._ledger_hook = lambda a, c, p: "ledger says no"
att9 = human_approves("arm_left", "grip", CUP, bk=b)
g9a = attacker_grant("arm_left", "grip", CUP, att9, bk=b)
r = b._handle(req("arm_left", "grip", CUP, g9a, att9))
ok(r.get("error") == "ledger_refused", "the ledger refuses first")
b._ledger_hook = None
g9b = attacker_grant("arm_left", "grip", CUP, att9, bk=b)
r = b._handle(req("arm_left", "grip", CUP, g9b, att9))
ok(r.get("ok") is True,
   "the approval survived a refusal it had nothing to do with and still works")


print("== backward compatibility: brokers without a gate are unchanged ==")

v = PermissionVerifier()
v.register_key("operator", OPKEY, unrestricted=True)
b_old = ActuationBroker(SOCK, v)
fired_old = []
b_old.register_actuator("arm_left", lambda **kw: fired_old.append(kw),
                        required_scope=("arm_left:grip",))
binding = PermissionVerifier.bind_action("arm_left", "grip", CUP)
g_old = Grant.issue(OPKEY, key_id="operator", role="operator",
                    scope=("arm_left:grip",), subject="robot-1", ttl_seconds=60,
                    nonce=nx("old"), action_binding=binding).to_dict()
r = b_old._handle({"op": "execute", "actuator_id": "arm_left", "command": "grip",
                   "params": CUP, "grant": g_old})
ok(r.get("ok") is True, "a pre-existing broker and grant still work untouched")

print("-" * 60)
print(f"  {passed}/{total} tests passed")
if passed != total:
    raise SystemExit(1)
