"""
test_human_authorization.py — "a key will do anything and still look approved".

The gap this closes: `mediated_actuation` verified a Grant signed with an OPERATOR
KEY and called the result authorised. A stolen key, an automation, or an agent that
reached the key store produces a grant that verifies perfectly. The wall proved WHAT
would execute and said nothing about WHO agreed.

These tests attack the join from the direction a key holder would: hold a valid
signing key, hold a valid human approval for something small, and try to turn that
pair into a bigger action. Every one of these must be refused.

Run: python3 test_human_authorization.py
"""

import time

from driftcore.authority.human_identity import (
    HumanAttestation, HumanIdentityVerifier)
from driftcore.verification.signed_permission import PermissionVerifier
from driftcore.verification.human_authorization import (
    HumanApprovalGate, HumanApprovalError, effect_id, envelope_digest,
    attestation_digest, approve)

_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def refuses(label, fn):
    """The gate must RAISE. A falsy return that a caller could read as success is
    itself the bug — so a non-raising call fails the check even if it returned None."""
    global _passed, _total
    _total += 1
    try:
        fn()
    except HumanApprovalError:
        _passed += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}, not HumanApprovalError: {e})")
        return
    print(f"  FAIL {label} (did NOT refuse)")


HKEY = b"human-principal-key-justin"
ENV_20N = {"max_force_n": 20, "max_speed_mps": 0.1, "conditions": ["child_present"]}
ENV_800N = {"max_force_n": 800, "max_speed_mps": 2.0, "conditions": []}


def gate(require_envelope=False):
    v = HumanIdentityVerifier()
    v.register_principal("justin", HKEY)
    return HumanApprovalGate(v, require_envelope=require_envelope)


def n():
    """A fresh nonce per attestation — they are single-use by design."""
    n.i += 1
    return f"att-{n.i}-{time.time()}"


n.i = 0


print("=== the gate cannot be built out of nothing ===")

refuses("a duck-typed 'verifier' that would say yes is refused",
        lambda: HumanApprovalGate(type("Fake", (), {"verify": lambda *a, **k: "justin"})()))
refuses("a verifier with NO registered principals is a misconfiguration, not a gate",
        lambda: HumanApprovalGate(HumanIdentityVerifier()))


print("=== a bare label is never a human ===")

g = gate()
refuses("a string principal is refused", lambda: g.pair_digest("justin"))
refuses("a dict missing the signature is refused",
        lambda: g.pair_digest({"principal": "justin", "action": "x",
                               "issued_at": 0, "expires_at": 1, "nonce": "z"}))
refuses("None is refused", lambda: g.pair_digest(None))


print("=== the happy path actually works (a discriminating gate, not a refusal) ===")

g = gate()
env = envelope_digest(ENV_20N)
att = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
              params={"force_n": 20, "duration_s": 2, "target": "cup"},
              ttl_seconds=300, nonce=n(), broker_id="broker-A", envelope_hash=env)
principal = g.verify(att, actuator_id="arm_left", command="grip",
                     params={"force_n": 20, "duration_s": 2, "target": "cup"},
                     broker_id="broker-A", envelope_hash=env)
check("a matching approval verifies and names the human", principal == "justin")


print("=== the approval does not stretch to a different action ===")

def approved_for_cup():
    return approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                   params={"force_n": 20, "duration_s": 2, "target": "cup"},
                   ttl_seconds=300, nonce=n(), broker_id="broker-A",
                   envelope_hash=envelope_digest(ENV_20N))


BASE = dict(actuator_id="arm_left", command="grip",
            params={"force_n": 20, "duration_s": 2, "target": "cup"},
            broker_id="broker-A", envelope_hash=envelope_digest(ENV_20N))


def attempt(**over):
    d = dict(BASE)
    if "params" in over:
        d["params"] = {**BASE["params"], **over.pop("params")}
    d.update(over)
    a = approved_for_cup()
    return lambda: gate().verify(a, **d)


refuses("EFFECT substituted: approved grip, executing crush",
        attempt(command="crush"))
refuses("TARGET substituted: approved the cup, executing on the knife",
        attempt(params={"target": "knife"}))
refuses("PARAMETER broadened: approved 20N, executing 900N",
        attempt(params={"force_n": 900}))
refuses("DURATION broadened: approved 2s, executing 600s",
        attempt(params={"duration_s": 600}))
refuses("DEVICE substituted: approved the left arm, executing on the right",
        attempt(actuator_id="arm_right"))
refuses("BROKER substituted: approved for broker-A, presented to broker-B",
        attempt(broker_id="broker-B"))
refuses("PARAMETER ADDED that the approver never saw",
        attempt(params={"repeat": 50}))
refuses("ENVELOPE WIDENED after approval: 20N approval under an 800N envelope",
        attempt(envelope_hash=envelope_digest(ENV_800N)))
refuses("ENVELOPE REMOVED after approval",
        attempt(envelope_hash=None))
refuses("EFFECT DECLARATION changed after approval",
        attempt(effects_hash="declaration-downgraded-to-NONE"))


print("=== forgery and replay ===")

wrong_key = HumanAttestation.issue(
    b"not-justins-key", principal="justin",
    action=effect_id("arm_left", "grip", BASE["params"], broker_id="broker-A",
                     envelope_hash=BASE["envelope_hash"]),
    ttl_seconds=300, nonce=n())
refuses("an attestation signed with the wrong key is refused",
        lambda: gate().verify(wrong_key, **BASE))

unknown = HumanAttestation.issue(
    HKEY, principal="mallory",
    action=effect_id("arm_left", "grip", BASE["params"], broker_id="broker-A",
                     envelope_hash=BASE["envelope_hash"]),
    ttl_seconds=300, nonce=n())
refuses("an unregistered principal is refused", lambda: gate().verify(unknown, **BASE))

expired = approve(HKEY, principal="justin", ttl_seconds=1, nonce=n(),
                  now=time.time() - 3600, **BASE)
refuses("an expired approval is refused", lambda: gate().verify(expired, **BASE))

g_replay = gate()
once = approved_for_cup()
check("first use of an approval succeeds",
      g_replay.verify(once, **BASE) == "justin")
refuses("the SAME approval cannot be used twice",
        lambda: g_replay.verify(once, **BASE))

tampered = HumanAttestation(
    principal=once.principal, action=once.action, issued_at=once.issued_at,
    expires_at=once.expires_at + 86400, nonce=once.nonce, sig=once.sig)
refuses("extending the expiry breaks the signature",
        lambda: gate().verify(tampered, **BASE))


print("=== the grant is pinned to ONE approval ===")

a1 = approved_for_cup()
a2 = approved_for_cup()
check("two approvals for the SAME action have different digests (instance pin)",
      attestation_digest(a1) != attestation_digest(a2))
b1 = PermissionVerifier.bind_action("arm_left", "grip", BASE["params"],
                                    broker_id="broker-A",
                                    envelope_hash=BASE["envelope_hash"],
                                    attestation_hash=attestation_digest(a1))
b2 = PermissionVerifier.bind_action("arm_left", "grip", BASE["params"],
                                    broker_id="broker-A",
                                    envelope_hash=BASE["envelope_hash"],
                                    attestation_hash=attestation_digest(a2))
check("a grant bound to approval #1 does not match approval #2", b1 != b2)
check("a grant bound to approval #1 matches approval #1",
      b1 == PermissionVerifier.bind_action(
          "arm_left", "grip", BASE["params"], broker_id="broker-A",
          envelope_hash=BASE["envelope_hash"], attestation_hash=attestation_digest(a1)))


print("=== require_envelope: unconfigured is not permissive ===")

strict = gate(require_envelope=True)
no_env = approve(HKEY, principal="justin", actuator_id="arm_left", command="grip",
                 params=BASE["params"], ttl_seconds=300, nonce=n(),
                 broker_id="broker-A")
refuses("a strict gate refuses when no envelope is bound",
        lambda: strict.verify(no_env, actuator_id="arm_left", command="grip",
                              params=BASE["params"], broker_id="broker-A"))


print("=== envelope digest hygiene ===")

check("None in, None out (no silent pin to an empty dict)",
      envelope_digest(None) is None)
check("the same declaration hashes stably regardless of key order",
      envelope_digest({"a": 1, "b": 2}) == envelope_digest({"b": 2, "a": 1}))
check("a different declaration hashes differently",
      envelope_digest(ENV_20N) != envelope_digest(ENV_800N))
refuses("a bare string is not an envelope declaration",
        lambda: envelope_digest("60N"))
refuses("an envelope containing NaN cannot be bound to",
        lambda: envelope_digest({"max_force_n": float("nan")}))


print("=== backward compatibility: omitted fields change nothing ===")

old = PermissionVerifier.bind_action("arm_left", "grip", {"force_n": 20})
new = PermissionVerifier.bind_action("arm_left", "grip", {"force_n": 20},
                                     envelope_hash=None, attestation_hash=None)
check("omitting both new fields is byte-identical to the old binding", old == new)
check("supplying an envelope changes the binding",
      PermissionVerifier.bind_action("arm_left", "grip", {"force_n": 20},
                                     envelope_hash="e") != old)
check("supplying an attestation changes the binding",
      PermissionVerifier.bind_action("arm_left", "grip", {"force_n": 20},
                                     attestation_hash="a") != old)


print("=== effect_id is the SAME canonicalisation the wall uses ===")

check("effect_id delegates to bind_action rather than reimplementing it",
      effect_id("arm_left", "grip", {"force_n": 20}, broker_id="b")
      == PermissionVerifier.bind_action("arm_left", "grip", {"force_n": 20},
                                        broker_id="b"))
check("effect_id deliberately excludes the attestation (no circular binding)",
      effect_id("arm_left", "grip", {"force_n": 20})
      == PermissionVerifier.bind_action("arm_left", "grip", {"force_n": 20}))
refuses("an empty actuator_id cannot be bound", lambda: effect_id("", "grip"))
refuses("an empty command cannot be bound", lambda: effect_id("arm_left", ""))


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
