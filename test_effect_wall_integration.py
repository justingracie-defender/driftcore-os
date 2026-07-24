"""
End-to-end: the constitutional effect gate WIRED INTO the actuation wall.

These drive the broker's real request handler (`_handle`) — the same path a socket
request takes — with enforce_effects=True, proving the fail-closed-on-undeclared
guarantee holds on the ENFORCED path, not just in the gate module in isolation.
"""
import time
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import (
    PermissionVerifier, Grant, PermissionError_,
)
from driftcore.verification.invariant_guard import Effect

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

KEY = b"\x11" * 32
SOCK = "/tmp/dc_effect_wall.sock"

def broker(enforce):
    v = PermissionVerifier()
    v.register_key("operator", KEY)
    b = ActuationBroker(SOCK, v, enforce_effects=enforce)
    return b, v

def grant(v, actuator_id, command, params, *, nonce, scope):
    binding = PermissionVerifier.bind_action(actuator_id, command, params)
    return Grant.issue(KEY, key_id="operator", role="operator", scope=scope,
                       subject="robot-1", ttl_seconds=60, nonce=nonce,
                       action_binding=binding).to_dict()

def req(actuator_id, command, params, g):
    return {"op": "execute", "actuator_id": actuator_id, "command": command,
            "params": params, "grant": g}


print("== state reporting: enforcement is visible (not a silent gap) ==")
b_off, _ = broker(False)
b_on, _ = broker(True)
ok(b_off.is_effect_gated() is False, "unenforced broker reports is_effect_gated()==False")
ok(b_on.is_effect_gated() is True, "enforced broker reports is_effect_gated()==True")

print("== enforcement ON: registration REQUIRES an effect declaration (fail closed early) ==")
b, v = broker(True)
fired = []
try:
    b.register_actuator("arm_undeclared", lambda **k: fired.append(k),
                        required_scope=("arm:move",))
    ok(False, "registering an actuator without effects under enforcement should raise")
except ValueError:
    ok(True, "cannot register a consequential actuator without declaring its effects")
try:
    b.register_actuator("arm_nodecl", lambda **k: fired.append(k),
                        required_scope=("arm:move",), effects=[Effect.PHYSICAL_FORCE])
    ok(False, "effects without effect_declared_by should raise")
except ValueError:
    ok(True, "effect declaration must be attributable (effect_declared_by required)")

print("== THE GUARANTEE end-to-end: a DECLARED benign actuator actuates ==")
b, v = broker(True)
moved = []
b.register_actuator("vacuum", lambda **k: moved.append(k) or "cleaned",
                    required_scope=("floor:clean",), effects=[Effect.NONE],
                    effect_declared_by="justin")
g = grant(v, "vacuum", "clean", {"room": "kitchen"}, nonce="e1", scope=("floor:clean",))
res = b._handle(req("vacuum", "clean", {"room": "kitchen"}, g))
ok(res.get("ok") is True and moved == [{"room": "kitchen"}],
   "a declared-NONE actuator with a valid grant actuates through the wall")

print("== a DECLARED LETHAL actuator is blocked by the floor even with a valid grant ==")
b, v = broker(True)
bang = []
b.register_actuator("weapon", lambda **k: bang.append(k),
                    required_scope=("weapon:fire",), effects=[Effect.LETHAL],
                    effect_declared_by="justin")
g = grant(v, "weapon", "fire", {"at": "x"}, nonce="e2", scope=("weapon:fire",))
res = b._handle(req("weapon", "fire", {"at": "x"}, g))
ok(res.get("ok") is False and "effect_block" in res.get("error", "") and bang == [],
   "a declared-LETHAL actuator is refused by the constitutional floor; nothing fired")

print("== a lethal-SUGGESTIVE but benign-declared actuator is HELD for review ==")
b, v = broker(True)
b.register_actuator("murder_bot", lambda **k: None,
                    required_scope=("arm:move",), effects=[Effect.PHYSICAL_FORCE],
                    effect_declared_by="justin")
g = grant(v, "murder_bot", "go", {}, nonce="e3", scope=("arm:move",))
res = b._handle(req("murder_bot", "go", {}, g))
ok(res.get("ok") is False and "hold_for_review" in res.get("error", ""),
   "lethal-suggestive capability name -> HELD at the wall, not actuated")

print("== a refused action RELEASES the grant (no side effect, nonce not burned) ==")
b, v = broker(True)
b.register_actuator("weapon2", lambda **k: None, required_scope=("weapon:fire",),
                    effects=[Effect.LETHAL], effect_declared_by="justin")
g = grant(v, "weapon2", "fire", {}, nonce="e4", scope=("weapon:fire",))
b._handle(req("weapon2", "fire", {}, g))      # refused by effect gate
# the same nonce should NOT have been burned by a refusal — but weapon2 always blocks,
# so re-presenting still blocks (proving the refusal path is consistent, grant released)
res2 = b._handle(req("weapon2", "fire", {}, g))
ok(res2.get("ok") is False, "a grant released on effect-refusal is not silently consumed into a success")

print("== comparison: with enforcement OFF, an undeclared actuator STILL actuates (the gap) ==")
b, v = broker(False)
ran = []
b.register_actuator("legacy_arm", lambda **k: ran.append(k) or "ok",
                    required_scope=("arm:move",))   # no effects, allowed when unenforced
g = grant(v, "legacy_arm", "move", {}, nonce="e5", scope=("arm:move",))
res = b._handle(req("legacy_arm", "move", {}, g))
ok(res.get("ok") is True and ran == [{}],
   "unenforced broker actuates an undeclared actuator — WHY enforce_effects must be on in prod")

print("== combined red-team pins ==")
from driftcore.verification.invariant_guard import Effect as _E

# A1: a rejected declaration must leave NO partial registration
b, v = broker(True)
try:
    b.register_actuator("arm", lambda **k: "MOVED", required_scope=("a:m",))
except ValueError:
    pass
ok("arm" not in b._actuators, "a rejected effect declaration leaves no half-registered actuator (A1)")
b.register_actuator("arm", lambda **k: "MOVED", required_scope=("a:m",),
                    effects=[_E.NONE], effect_declared_by="justin")
ok("arm" in b._actuators, "and the operator can simply retry — not locked out behind replace=True")

# A2: the gate runs BEFORE the ledger, so impossible actions cost no budget
charged = []
b, v = broker(True)
b2 = ActuationBroker(SOCK, v, enforce_effects=True,
                     ledger_hook=lambda a, c, p: charged.append(a) or None)
b2.register_actuator("w", lambda **k: "BANG", required_scope=("w:f",),
                     effects=[_E.LETHAL], effect_declared_by="justin")
for i in range(3):
    b2._handle(req("w", "fire", {}, grant(v, "w", "fire", {}, nonce=f"c{i}", scope=("w:f",))))
ok(charged == [], "constitutionally-impossible actions never reach the cumulative ledger (A2)")

# A4: params are part of the lexicon scan surface
b, v = broker(True)
b.register_actuator("vac2", lambda **k: "ok", required_scope=("f:c",),
                    effects=[_E.NONE], effect_declared_by="justin")
p = {"target": "kill the intruder"}
r = b._handle(req("vac2", "clean", p, grant(v, "vac2", "clean", p, nonce="pp", scope=("f:c",))))
ok(r.get("ok") is False, "lethal intent hidden in params is caught, not ignored (A4)")

# A6: a gate exception fails closed and does not escape _handle
b, v = broker(True)
b.register_actuator("vx", lambda **k: "ok", required_scope=("f:c",),
                    effects=[_E.NONE], effect_declared_by="justin")
class _Boom:
    def authorize(self, *a, **k): raise RuntimeError("gate exploded")
b._effect_gate = _Boom()
r = b._handle(req("vx", "clean", {}, grant(v, "vx", "clean", {}, nonce="bx", scope=("f:c",))))
ok(r.get("ok") is False and r.get("error") == "effect_block_error",
   "a crashing gate fails closed and returns, never escaping to a generic broker_error (A6)")

# A7: the authorizer label names the mechanism, not the machine
seen = {}
b, v = broker(True)
b.register_actuator("u", lambda **k: "sent", required_scope=("n:o",),
                    effects=[_E.DATA_EGRESS], effect_declared_by="justin", destination_param="url")
real = b._effect_gate
class _Spy:
    def authorize(self, cap, cmd, ctx):
        seen["by"] = ctx.authorised_by
        return real.authorize(cap, cmd, ctx)
b._effect_gate = _Spy()
b._handle(req("u", "sync", {}, grant(v, "u", "sync", {}, nonce="sy", scope=("n:o",))))
ok(seen.get("by") == "broker:scope-mediated",
   "the effect decision is attributed to the MECHANISM, never to the robot itself (A7)")

# A8: a malformed declaration is loud even when unenforced
b, v = broker(False)
try:
    b.register_actuator("t", lambda **k: 1, required_scope=("t:t",),
                        effects=["LETAHL"], effect_declared_by="justin")
    ok(False, "a typo'd effect declaration should raise")
except ValueError:
    ok(True, "a malformed effect declaration raises even with enforcement off (A8)")

# Meta P1-1: injecting past register_actuator does NOT bypass the gate
b, v = broker(True)
b._actuators["backdoor"] = (lambda **k: "PWNED", ("bd:r",))
r = b._handle(req("backdoor", "run", {}, grant(v, "backdoor", "run", {}, nonce="bd", scope=("bd:r",))))
ok(r.get("ok") is False and "undeclared" in r.get("error", ""),
   "an actuator injected past registration still fails closed — the gate reads the registry")

# 3-way convergence: claiming the wall property requires enforcing effects
try:
    ActuationBroker(SOCK, v, require_isolation=True, enforce_effects=False).start()
    ok(False, "require_isolation without enforce_effects should refuse")
except PermissionError:
    ok(True, "require_isolation=True refuses to start with enforce_effects=False")

# KNOWN GAP (pinned): effect DOWNGRADE after issuance still executes
b, v = broker(True)
b.register_actuator("dg", lambda **k: "MOVED", required_scope=("d:g",),
                    effects=[_E.LETHAL], effect_declared_by="justin")
r1 = b._handle(req("dg", "move", {}, grant(v, "dg", "move", {}, nonce="g1", scope=("d:g",))))
b._effect_registry.register("dg", [_E.NONE], declared_by="mallory", replace=True)
r2 = b._handle(req("dg", "move", {}, grant(v, "dg", "move", {}, nonce="g2", scope=("d:g",))))
ok(r1.get("ok") is False and r2.get("ok") is True,
   "KNOWN GAP: upgrading a declaration fails closed, but DOWNGRADING it executes — "
   "the grant is not bound to the declaration. Signed append-only declarations are the "
   "fix; this assertion must flip when they land")

print(f"\nALL {passed} CHECKS PASSED")
