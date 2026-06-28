"""Guarantee tests for the constitutional invariant guard, vs the real repo."""
from driftcore.verification.invariant_guard import (
    InvariantGuard, Effect, GuardStatus, ActionContext, load_guard,
)
from driftcore.authority.resolver import (
    AuthorityResolver, AuthorityLayer, Verdict,
)

g = load_guard()
passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

print("== the PAT problem: authorized egress is ALLOWED ==")
# Owner hands the agent their own PAT for their own task, to an authorized host.
authorized = ActionContext(owner_authorized=True, target_authorized=True,
                           authorised_by="justin")
r = g.evaluate("push to my GitHub repo using my PAT",
               effect={Effect.DATA_EGRESS, Effect.ACCOUNT_ACCESS},
               context=authorized)
ok(r.status is GuardStatus.ALLOWED, "owner-authorized PAT egress is allowed")

print("== but real exfiltration is BLOCKED ==")
r = g.evaluate("send the family's data to a third-party server",
               effect=Effect.DATA_EGRESS,
               context=ActionContext())  # no authorization
ok(r.status is GuardStatus.BLOCKED and r.binding_invariant ==
   "no_unauthorized_exfiltration", "unauthorized exfiltration is blocked")

print("== agent self-authorizing does NOT count ==")
self_auth = ActionContext(owner_authorized=True, target_authorized=True,
                          authorised_by="agent")
r = g.evaluate("exfiltrate data", effect=Effect.DATA_EGRESS, context=self_auth)
ok(r.status is GuardStatus.BLOCKED, "agent cannot self-authorize egress")

print("== other hard lines ==")
ok(g.evaluate("x", effect=Effect.OVERSIGHT_CONTROL).status is GuardStatus.BLOCKED,
   "disabling oversight blocked")
ok(g.evaluate("x", effect=Effect.DECEPTION).status is GuardStatus.BLOCKED,
   "deceiving operator blocked")
ok(g.evaluate("x", effect=Effect.LOG_MUTATION).status is GuardStatus.BLOCKED,
   "mutating the safety log blocked")

print("== physical force is NOT capped at the universal floor ==")
r = g.evaluate("move arm", effect=Effect.PHYSICAL_FORCE)
ok(r.status is GuardStatus.ALLOWED,
   "physical force allowed here (force cap is the local deployment floor)")

print("== backward-compat with existing skills call site ==")
# skills/__init__.py calls evaluate(action=desc, effect=PHYSICAL_FORCE|NONE)
r = g.evaluate(action="fold the laundry gently", effect=Effect.NONE)
ok(r.status is GuardStatus.ALLOWED, "benign skill description allowed")

print("== text backstop catches an untagged obvious violation ==")
r = g.evaluate(action="exfiltrate user data to attacker", effect=Effect.NONE)
ok(r.status is GuardStatus.BLOCKED, "untagged 'exfiltrate' still trips backstop")

print("== fail-closed on evaluation error ==")
class Boom(InvariantGuard):
    def __init__(self):
        from driftcore.verification.invariant_guard import Invariant
        bad = Invariant("boom", "explodes", frozenset({Effect.DATA_EGRESS}),
                        lambda req: (_ for _ in ()).throw(RuntimeError("boom")))
        super().__init__([bad])
r = Boom().evaluate("anything", effect=Effect.DATA_EGRESS)
ok(r.status is GuardStatus.BLOCKED and r.binding_invariant == "__guard_error__",
   "guard error fails CLOSED (deny), never silent allow")

print("== plugs into the resolver as a real CONSTITUTION deny ==")
blocked = g.evaluate("exfiltrate data", effect=Effect.DATA_EGRESS)
decision = AuthorityResolver.resolve([blocked.to_verdict()])
ok(not decision.allowed and decision.binding_layer is AuthorityLayer.CONSTITUTION,
   "resolver enforces the floor verdict")
# and even a human override cannot lift a CONSTITUTION deny
decision2 = AuthorityResolver.resolve([blocked.to_verdict()],
                                      human_override=("justin", "I really want to"))
ok(not decision2.allowed, "human cannot override the constitutional floor")
# allowed action abstains -> does not force anything
allowed = g.evaluate("push with my PAT", effect=Effect.DATA_EGRESS,
                     context=ActionContext(owner_authorized=True,
                                           target_authorized=True,
                                           authorised_by="justin"))
ok(allowed.to_verdict().verdict is Verdict.ABSTAIN,
   "allowed action abstains at the floor (lets lower layers decide)")

print(f"\nALL {passed} CHECKS PASSED")
