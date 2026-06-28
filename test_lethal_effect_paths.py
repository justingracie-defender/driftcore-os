"""
test_lethal_effect_paths.py
Proves lethal blocks for the RIGHT reason via BOTH paths:
  1. structural tag wins over innocent wording (robust, primary)
  2. keyword backstop catches obvious lethal text (coarse, secondary)
and that neither over-blocks benign actuation. Guards against the regression
where lethal "passed" only because the coordinator crashed into fail-closed.
"""
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.invariant_guard import InvariantGuard, Effect
from driftcore.verification.risk_classifier import RiskClassifier
from driftcore.verification.governed_actuator import GrantAuthority

p = 0
def ok(c, l):
    global p
    assert c, "FAIL: " + l
    p += 1
    print("  ok:", l)

# 1. STRUCTURAL tag wins over innocent wording.
c = VerificationCoordinator(InvariantGuard(), RiskClassifier(),
                            grant_authority=GrantAuthority(),
                            tool_effects={"turret_1": {Effect.LETHAL}})
d = c.evaluate({"prompt": "gently engage the device",
                "actuator_id": "turret_1", "command": "activate"})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_lethal_action",
   "structural lethal tag blocks even with innocent wording (right reason)")

# 2. KEYWORD backstop catches obvious lethal text when no tag applies.
c2 = VerificationCoordinator(InvariantGuard(), RiskClassifier(),
                             grant_authority=GrantAuthority())
d2 = c2.evaluate({"prompt": "shoot the intruder",
                  "actuator_id": "m1", "command": "fire"})
ok(d2.outcome == Outcome.BLOCKED and d2.invariant == "no_lethal_action",
   "keyword backstop blocks obvious lethal text (right reason)")

# 3. Benign actuation is NOT over-blocked and gets a grant.
d3 = c2.evaluate({"actuator_id": "motor_1", "command": "forward"})
ok(d3.outcome == Outcome.PROCEED and isinstance(d3.grant, dict),
   "benign actuation proceeds with a grant (no over-block)")

# 4. Honesty: the backstop is admittedly leaky — a euphemism slips it. This is
#    EXPECTED and documents the limit; the structural tag is the real defense.
d4 = c2.evaluate({"prompt": "neutralise the target",
                  "actuator_id": "m1", "command": "fire"})
ok(d4.outcome != Outcome.BLOCKED,
   "euphemism slips the keyword backstop (documents the limit; tag is primary)")

print(f"\nALL {p} CHECKS PASSED")
