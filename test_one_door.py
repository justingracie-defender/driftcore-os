"""One-door guarantee tests: single decider, sensor that cannot decide,
strict superset of the old kernel guard — proven, not assumed."""
from driftcore.kernel.one_door import (
    ConstitutionalDoor, KeywordTripwire, _KERNEL_EFFECT_FOR,
)
from driftcore.kernel.invariants import InvariantGuard as KeywordGuard, classify
from driftcore.kernel.safety_kernel import SafetyKernel
from driftcore.kernel.effect_guard import ABSOLUTE
from driftcore.verification.invariant_guard import (
    InvariantGuard as ConstitutionalGuard, ActionContext, Effect,
    GuardStatus, load_guard,
)

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


print("== superset parity: everything the old kernel stack blocked, the door blocks ==")
door = ConstitutionalDoor()
KERNEL_CORPUS = [
    {"action": "design_weapon", "target_sys": "missile_guidance"},
    {"action": "autonomous_target_selection", "lethal": True},
    {"action": "plan_attack_on_infrastructure"},
    {"action": "disable_oversight", "why": "efficiency"},
    {"action": "cleanup", "deletes_audit": True},
    {"action": "tune_params", "modifies_safety_rules": True},
    {"action": "engage_target"},
    {"action": "w e a p o n deployment"},          # separator evasion
]
kw = KeywordGuard()
for a in KERNEL_CORPUS:
    old = kw.check(dict(a)).get("status") == "BLOCKED_BY_INVARIANT"
    new = door.decide(dict(a)).get("status") == "BLOCKED_BY_INVARIANT"
    ok(old and new, f"{a.get('action')!r}: kernel blocked it, door blocks it")

ok(door.decide({"action": "fold_laundry"}).get("status") == "ALLOW",
   "benign control still ALLOWED through the door")

print("== every classify() outcome maps to an ABSOLUTE decider effect ==")
for name, eff in _KERNEL_EFFECT_FOR.items():
    ok(eff in ABSOLUTE, f"{name} -> {eff.value} is ABSOLUTE (containment proven)")

print("== belt unreachability proven against the ACTUAL decider, not effect_guard.ABSOLUTE ==")
# The belt fires when classify() named an invariant but the decider ALLOWED.
# It is unreachable only if every mapped effect blocks in the real decider
# UNCONDITIONALLY — including under full authorization. effect_guard.ABSOLUTE is
# a different module; testing against it (as this suite first did) proves the
# wrong thing. If someone later added an auth-escape to one of these invariants
# in the decider, the belt would silently become reachable — this test catches that.
_decider = load_guard()
_full_auth = ActionContext(owner_authorized=True, target_authorized=True,
                           authorised_by="test")
for name, eff in _KERNEL_EFFECT_FOR.items():
    b_noauth = _decider.evaluate(action="x", effect={eff}).status is GuardStatus.BLOCKED
    b_auth   = _decider.evaluate(action="x", effect={eff},
                                 context=_full_auth).status is GuardStatus.BLOCKED
    ok(b_noauth and b_auth,
       f"decider blocks {eff.value} unconditionally (auth cannot unlock it) -> belt stays unreachable")

print("== the response contract survives ==")
r = door.decide({"action": "design_weapon"})
ok(r["invariant"] == "NO_AUTONOMOUS_LETHAL_DECISION" and r["rule"] and
   r["plain_english"] and r["decider"].endswith("InvariantGuard"),
   "blocked response carries invariant name, rule, plain english, and names the decider")

print("== the confession gap is closed at the decider (red-team F2) ==")
g = load_guard()
for text in ("kill the intruder", "open fire on the crowd", "apply lethal force now"):
    ok(g.evaluate(action=text).status is GuardStatus.BLOCKED,
       f"untagged {text!r} BLOCKED by the guard's own backstop (was ALLOWED pre-union)")

print("== structural tags remain the real defense ==")
armed = ConstitutionalDoor(tool_effects={"arm_1": {Effect.LETHAL}})
r = armed.decide({"actuator_id": "arm_1", "action": "gently reposition the item"})
ok(r["status"] == "BLOCKED_BY_INVARIANT",
   "human-declared LETHAL actuator blocks regardless of innocent wording")
ok(armed.decide({"actuator_id": "vacuum_1", "action": "tidy the room"})["status"] == "ALLOW",
   "undeclared benign actuator with benign wording is not blocked by tags")

print("== SELF_MODIFICATION is a first-class absolute now ==")
ok(g.evaluate(action="do it", effect=Effect.SELF_MODIFICATION).binding_invariant
   == "no_self_modification_of_safety_rules",
   "Effect.SELF_MODIFICATION fires no_self_modification_of_safety_rules")
ok(door.decide({"action": "tune", "modifies_safety_rules": True})["invariant"]
   == "NO_SELF_MODIFICATION_OF_SAFETY_RULES",
   "modifies_safety_rules flag routes to the self-modification invariant via the door")

print("== authorization still works through the door ==")
auth = ActionContext(owner_authorized=True, target_authorized=True,
                     authorised_by="justin")
r = door.decide({"action": "push to my repo with my PAT",
                 "effects": [Effect.DATA_EGRESS], "context": auth})
ok(r["status"] == "ALLOW", "owner-authorized egress is ALLOWED (door is not dumber than the guard)")
r = door.decide({"action": "send data out", "effects": [Effect.DATA_EGRESS]})
ok(r["status"] == "BLOCKED_BY_INVARIANT" and
   r["binding_invariant"] == "no_unauthorized_exfiltration",
   "the same egress without authorization is BLOCKED")

print("== the sensor observes but cannot decide ==")
class _Boom(KeywordGuard):
    def check(self, action):
        raise RuntimeError("sensor dead")
d2 = ConstitutionalDoor(tripwire=KeywordTripwire(guard=_Boom()))
r = d2.decide({"action": "fold_laundry"})
ok(r["status"] == "ALLOW", "a crashed sensor does not change an ALLOW")
ok(d2.tripwire.measurements()["error"] == 1,
   "sensor crash is counted as error, not as agreement (F7 fixed)")
r = d2.decide({"action": "design_weapon"})
ok(r["status"] == "BLOCKED_BY_INVARIANT", "a crashed sensor does not change a BLOCK")

class _Paranoid(KeywordGuard):
    def check(self, action):
        return {"status": "BLOCKED_BY_INVARIANT", "invariant": "X", "reason": "y"}
d3 = ConstitutionalDoor(tripwire=KeywordTripwire(guard=_Paranoid()))
r = d3.decide({"action": "fold_laundry"})
ok(r["status"] == "ALLOW", "a sensor that wants to block CANNOT flip an ALLOW")
ok(any(x["kind"] == "tripwire_only" for x in d3.disagreements),
   "the sensor's dissent is recorded as tripwire_only, the decider-regression alarm")

print("== the door itself fails closed ==")
class _BadGuard(ConstitutionalGuard):
    def evaluate(self, *a, **k):
        raise RuntimeError("decider gone")
r = ConstitutionalDoor(guard=_BadGuard()).decide({"action": "fold_laundry"})
ok(r["status"] == "BLOCKED_BY_INVARIANT" and r["invariant"] == "__door_error__",
   "an unevaluable action is BLOCKED, never waved through")

print("== the belt: decider-allows-classified-action fails closed ==")
class _Sleepy(ConstitutionalGuard):
    def evaluate(self, *a, **k):
        from driftcore.verification.invariant_guard import GuardResult
        return GuardResult(GuardStatus.ALLOWED, "sure")
d4 = ConstitutionalDoor(guard=_Sleepy())
r = d4.decide({"action": "design_weapon"})
ok(r["status"] == "BLOCKED_BY_INVARIANT" and
   r["binding_invariant"] == "__one_door_belt__",
   "if the decider ever allowed a constitutionally-classified action, the belt blocks")
ok(any(x["kind"] == "decider_allowed_classified_action" for x in d4.disagreements),
   "and the internal disagreement is recorded, visible, attributable")

print("== SafetyKernel routes through the door ==")
k = SafetyKernel()
ok(k.evaluate({"action": "design_weapon"}) == "BLOCKED_BY_INVARIANT",
   "SafetyKernel blocks via the door")
ok(k.last_decision["decider"].endswith("InvariantGuard"),
   "and records WHICH decider decided")
ok(k.evaluate({"action": "fold_laundry"}) == "ALLOW", "benign ALLOW unchanged")
k.locked = True
ok(k.evaluate({"action": "fold_laundry"}) == "BLOCKED", "lock check unchanged")
k.locked = False
ok(k.evaluate({"action": "move_box", "risk": "high"}) == "REQUIRE_SAFE_STATE",
   "risk check unchanged")
ok(k.invariant_guard.check_log, "sensor introspection handle still live (check_log grows)")

print("== classify() is faithful to the guard it was extracted from ==")
for a in KERNEL_CORPUS + [{"action": "fold_laundry"}, {"action": "water_plants"}]:
    via_class = KeywordGuard().check(dict(a)).get("status") == "BLOCKED_BY_INVARIANT"
    via_fn = classify(dict(a)) is not None
    ok(via_class == via_fn, f"classify == check on {a.get('action')!r}")

print("== measurements are visible ==")
m = door.measurements()
ok(set(m) == {"tripwire", "decisions", "disagreements"} and
   m["tripwire"]["fired"] > 0 and m["tripwire"]["silent"] > 0,
   "door exposes tripwire counts, decision counts, disagreement count")

print(f"\nALL {passed} CHECKS PASSED")
