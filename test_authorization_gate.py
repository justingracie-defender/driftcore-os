"""Authorization gate + GatedExecutor tests, against the real repo."""
import time
from driftcore.authority.authorization_gate import (
    AuthorizationGate, Authorization, CredentialVerifier, GateState,
)
from driftcore.authority.gated_executor import GatedExecutor
from driftcore.authority.executor import GovernedExecutor
from driftcore.recovery import (
    RecoveryManager, CheckpointStore, InMemorySnapshotter,
)
from driftcore.skills.governance import SkillMaturity, SkillStats

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


# A real external verifier accepts only tokens it issued. The agent does not
# implement this — the harness/deployment does.
class HarnessVerifier:
    def __init__(self, good_tokens):
        self._good = set(good_tokens)
    def verify(self, auth: Authorization) -> bool:
        return auth.token in self._good

now = time.time()
valid = Authorization(issuer="justin", operator="justin", token="KEY-OK",
                      issued_at=now, expires_at=now + 3600)

print("== fail closed without a verifier (never fake it) ==")
g0 = AuthorizationGate(verifier=None)
ok(g0.check(valid).state is GateState.BLOCKED,
   "no verifier wired -> everything blocked (fails closed)")

print("== default-deny: no credential ==")
g = AuthorizationGate(verifier=HarnessVerifier(["KEY-OK"]))
ok(g.check(None).state is GateState.BLOCKED, "no authorization -> blocked")

print("== a valid external credential clears ==")
ok(g.check(valid).state is GateState.CLEARED, "valid credential -> cleared")

print("== the agent cannot self-grant ==")
self_issued = Authorization(issuer="agent", operator="agent", token="KEY-OK",
                            issued_at=now, expires_at=now + 3600)
ok(g.check(self_issued).state is GateState.BLOCKED,
   "self-issued credential rejected (issuer not external)")

print("== expired credential blocked ==")
expired = Authorization(issuer="justin", operator="justin", token="KEY-OK",
                        issued_at=now - 7200, expires_at=now - 3600)
ok(g.check(expired).state is GateState.BLOCKED, "expired -> blocked")

print("== unknown token blocked even if well-formed ==")
forged = Authorization(issuer="justin", operator="justin", token="FORGED",
                       issued_at=now, expires_at=now + 3600)
ok(g.check(forged).state is GateState.BLOCKED,
   "verifier rejects unknown token")

print("== safe-rest is a fallen-into default, triggered on block ==")
rested = {"v": False}
gemb = AuthorizationGate(verifier=HarnessVerifier(["KEY-OK"]), embodied=True,
                         safe_state=lambda: rested.__setitem__("v", True))
res = gemb.check(None)
gemb.on_blocked()   # harness invokes it; the agent never chooses it
ok(res.state is GateState.BLOCKED and rested["v"],
   "embodied + blocked -> deployment safe-state invoked by harness")

print("== GatedExecutor: gate blocks BEFORE the governed path runs ==")
ran = {"applied": False}
inner = GovernedExecutor(
    recovery=RecoveryManager(CheckpointStore(), InMemorySnapshotter({})))
gated = GatedExecutor(inner, AuthorizationGate(HarnessVerifier(["KEY-OK"])))

def apply_fn():
    ran["applied"] = True
    return "did the thing"

# No authorization -> must not reach apply_fn at all.
r = gated.run(skill_id="s1", domain="household", maturity=SkillMaturity.TESTED,
              stats=SkillStats(0, 0), apply_fn=apply_fn, resources=[],
              authorization=None)
ok(not r.applied and not ran["applied"],
   "unauthorized action never reaches apply_fn (gate is upstream)")
ok("authorization gate" in r.reason, "block reason names the gate")

print(f"\nALL {passed} CHECKS PASSED")
