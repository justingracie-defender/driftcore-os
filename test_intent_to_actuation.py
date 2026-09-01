"""
test_intent_to_actuation.py — the chain closes, or it does not.

Until this file existed, `intent_ledger` and `mediated_actuation` were two correct
halves that could not see each other. The ledger authorised an action STRING; the
broker verified a signature over an actuator command; nothing joined them. So
`authorise("buy advertising")` returning AUTHORISED did not stop the next line
calling the arm. Eighteen defects were closed upstream of that gap this session
while the gap itself stayed open — the same shape as `hardware_safety` reporting a
stop that never happened.

The join: the ledger emits a single-use digest over its decision, that digest goes
into `bind_action`, and the broker redeems the decision against the action it is
actually about to run.

    human sentence -> constraint -> decision -> digest
                                                  |
                                       grant action_binding
                                                  |
                                        broker recomputes
                                                  |
                                              actuator

Run: python3 test_intent_to_actuation.py
"""

import time

from driftcore.authority import human_identity as hi
from driftcore.authority.human_identity import HumanIdentityVerifier
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.verification.intent_ledger import (
    IntentLedger, IntentError, Citation, Disposition, Basis, Verdict)
from driftcore.verification.human_authorization import (
    HumanApprovalGate, envelope_digest, attestation_digest, approve)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


OPKEY = b"\x44" * 32
HKEY = b"human-key"
CUP = {"force_n": 20, "target": "cup"}
ENV = {"max_force_n": 20}
GIVE_BACK = "Any money we make on this, we do have to give it back afterwards."
_i = [0]


def nx(p):
    _i[0] += 1
    return f"{p}-{_i[0]}"


def build():
    hi.reset_policy()
    hi.register_human_principal("founder")
    ledger = IntentLedger()
    ledger.capture("give-back", GIVE_BACK, spoken_by="founder")
    ledger.register_action("arm_left:grip", declared_by="founder")
    ledger.register_action("arm_left:crush", declared_by="founder",
                           consequential=True)

    v = PermissionVerifier()
    v.register_key("operator", OPKEY, unrestricted=True)
    b = ActuationBroker("/tmp/dc_chain.sock", v, broker_id="broker-A",
                        intent_ledger=ledger)
    fired = []
    b.register_actuator("arm_left", lambda **kw: fired.append(dict(kw)) or "done",
                        required_scope=("arm_left:grip",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="founder")
    return ledger, b, fired


def decide(ledger, action, disp=Disposition.NOT_APPLICABLE, span=""):
    return ledger.authorise(action, basis=Basis.CITED,
                            citations=[Citation("give-back", disp, quoted_span=span)],
                            actor="operator")


def request(b, decision, params=None, command="grip"):
    params = dict(CUP if params is None else params)
    binding = PermissionVerifier.bind_action(
        "arm_left", command, params, broker_id="broker-A",
        intent_digest=getattr(decision, "digest", None))
    g = Grant.issue(OPKEY, key_id="operator", role="operator",
                    scope=("arm_left:grip",), subject="robot-1", ttl_seconds=60,
                    nonce=nx("g"), action_binding=binding).to_dict()
    req = {"op": "execute", "actuator_id": "arm_left", "command": command,
           "params": params, "grant": g}
    if decision is not None:
        req["intent_decision"] = decision
    return b._handle(req)


print("== CONTROL: a purpose-accountable action reaches the actuator ==")

ledger, b, fired = build()
d = decide(ledger, "arm_left:grip")
r = request(b, d)
check(f"it executes (got {r.get('error')})", r.get("ok") is True)
check("and the actuator actually ran", len(fired) == 1)


print("== a grant with NO ledger decision does not act ==")

ledger, b, fired = build()
r = request(b, None)
check("the wall refuses a perfectly-signed grant with no decision",
      r.get("error") == "no_intent_decision")
check("nothing actuated", fired == [])


print("== a decision for one action cannot be spent on another ==")

ledger, b, fired = build()
d = decide(ledger, "arm_left:grip")
r = request(b, d, command="crush")
check("presenting a different command is refused", r.get("ok") is not True)
check("nothing actuated", fired == [])


print("== one decision, one actuation ==")

ledger, b, fired = build()
d = decide(ledger, "arm_left:grip")
r1 = request(b, d)
r2 = request(b, d)
check("the first request executes", r1.get("ok") is True)
check("the SAME decision cannot drive a second, even with a fresh grant",
      r2.get("error") == "intent_decision_rejected")
check("exactly one actuation happened", len(fired) == 1)


print("== a purpose stated AFTER the decision invalidates it ==")

ledger, b, fired = build()
d = decide(ledger, "arm_left:grip")
ledger.capture("no-grip", "Never grip anything a child is holding, ever.",
               spoken_by="founder")
r = request(b, d)
check("the stale decision is refused", r.get("error") == "intent_decision_rejected")
check("and the reason names the generation gap", "generation" in r.get("detail", ""))
check("nothing actuated", fired == [])


print("== an ESCALATED decision is not a soft yes at the wall either ==")

ledger, b, fired = build()
d = ledger.authorise("arm_left:grip", basis=Basis.RECONSTRUCTION,
                     reconstruction_note="I believe they would want this",
                     actor="operator")
check("the ledger escalated", d.verdict is Verdict.ESCALATED)
r = request(b, d)
check("the broker refuses it", r.get("ok") is not True)
check("nothing actuated", fired == [])


print("== the digest is IN the grant binding, not merely alongside it ==")

ledger, b, fired = build()
d = decide(ledger, "arm_left:grip")
with_digest = PermissionVerifier.bind_action(
    "arm_left", "grip", CUP, broker_id="broker-A", intent_digest=d.digest)
without = PermissionVerifier.bind_action(
    "arm_left", "grip", CUP, broker_id="broker-A")
check("a grant bound WITH a decision differs from one bound without",
      with_digest != without)
check("omitting the field is byte-identical to the pre-join binding",
      without == PermissionVerifier.bind_action("arm_left", "grip", CUP,
                                                broker_id="broker-A",
                                                intent_digest=None))

# A grant minted against decision A, presented with decision B.
ledger2, b2, fired2 = build()
dA = decide(ledger2, "arm_left:grip")
dB = decide(ledger2, "arm_left:grip")
binding = PermissionVerifier.bind_action("arm_left", "grip", CUP,
                                         broker_id="broker-A",
                                         intent_digest=dA.digest)
g = Grant.issue(OPKEY, key_id="operator", role="operator",
                scope=("arm_left:grip",), subject="robot-1", ttl_seconds=60,
                nonce=nx("g"), action_binding=binding).to_dict()
r = b2._handle({"op": "execute", "actuator_id": "arm_left", "command": "grip",
                "params": dict(CUP), "grant": g, "intent_decision": dB})
check("a grant bound to decision A cannot be presented with decision B",
      r.get("ok") is not True)
check("nothing actuated", fired2 == [])


print("== an unconfigured broker refuses a decision rather than ignoring it ==")

hi.reset_policy()
v = PermissionVerifier()
v.register_key("operator", OPKEY, unrestricted=True)
b3 = ActuationBroker("/tmp/dc_chain2.sock", v, broker_id="broker-A")
fired3 = []
b3.register_actuator("arm_left", lambda **kw: fired3.append(kw),
                     required_scope=("arm_left:grip",))
ledger3 = IntentLedger(require_registered_actions=False)
d3 = ledger3.authorise("arm_left:grip", basis=Basis.CITED, actor="operator")
r = request(b3, d3)
check("a broker with no ledger refuses a presented decision",
      r.get("error") == "intent_ledger_unconfigured")


print("== backward compatibility ==")

hi.reset_policy()
v = PermissionVerifier()
v.register_key("operator", OPKEY, unrestricted=True)
b4 = ActuationBroker("/tmp/dc_chain3.sock", v)
fired4 = []
b4.register_actuator("arm_left", lambda **kw: fired4.append(kw),
                     required_scope=("arm_left:grip",))
binding = PermissionVerifier.bind_action("arm_left", "grip", CUP)
g = Grant.issue(OPKEY, key_id="operator", role="operator",
                scope=("arm_left:grip",), subject="robot-1", ttl_seconds=60,
                nonce=nx("old"), action_binding=binding).to_dict()
r = b4._handle({"op": "execute", "actuator_id": "arm_left", "command": "grip",
                "params": dict(CUP), "grant": g})
check("a pre-existing broker and grant still work untouched", r.get("ok") is True)

hi.reset_policy()
print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
