"""
test_governed_actuator.py — NON-BYPASS ACTUATION (reviewer #1)
==============================================================

Proves that a physical action cannot happen without a grant only the
coordinator can mint:
  - no grant / forged grant / wrong actuator / wrong command -> refused
  - grants are single-use and expiring
  - the coordinator issues a grant ONLY on a PROCEED outcome, never for a
    blocked or review-required action
  - an agent that holds the actuator but skips the coordinator has no grant

Run with:  python test_governed_actuator.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.governed_actuator import GrantAuthority, GovernedActuator
from driftcore.verification.invariant_guard import InvariantGuard
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.risk_classifier import RiskClassifier

PASS, FAIL = "✅", "❌"
results = []
def check(n, c):
    print(f"  {'✅' if c else '❌'}  {n}")
    results.append((n, bool(c)))

def refused(fn):
    try:
        fn(); return False
    except PermissionError:
        return True

grants = GrantAuthority()
arm    = GovernedActuator("arm_1", grants)


# ── 1. The actuator refuses anything without a valid grant ─────────
print("\nActuation demands a valid coordinator grant:")
check("no grant -> refused",  refused(lambda: arm.actuate("open", None)))

g = grants.mint("arm_1", "open")
check("valid grant -> actuates", arm.actuate("open", g) is True)
check("  -> command recorded",   arm.performed == ["open"])

forged = {"actuator_id": "arm_1", "command": "open", "nonce": "x",
          "expires": 9e18, "sig": "deadbeef" * 8}
check("forged grant (bad signature) -> refused",
      refused(lambda: arm.actuate("open", forged)))
check("grant for a DIFFERENT actuator -> refused",
      refused(lambda: arm.actuate("open", grants.mint("arm_2", "open"))))
check("grant for a DIFFERENT command -> refused",
      refused(lambda: arm.actuate("open", grants.mint("arm_1", "close"))))


# ── 2. Single-use and expiry ───────────────────────────────────────
print("\nSingle-use + expiry:")
g_once = grants.mint("arm_1", "open")
arm.actuate("open", g_once)
check("grant reuse -> refused", refused(lambda: arm.actuate("open", g_once)))
check("expired grant -> refused",
      refused(lambda: arm.actuate("open", grants.mint("arm_1", "open", ttl_seconds=-1))))


# ── 3. Coordinator issues grants ONLY on PROCEED ───────────────────
print("\nCoordinator-issued grants:")
guard = InvariantGuard()
coord = VerificationCoordinator(guard, RiskClassifier(), grant_authority=grants)
motor = GovernedActuator("motor_1", grants)   # shares the coordinator's authority

# benign structured actuation (no risky prompt) -> PROCEED + grant
d = coord.evaluate({"actuator_id": "motor_1", "command": "forward"})
check("benign actuation -> PROCEED", d.outcome == Outcome.PROCEED)
check("  -> grant attached",         isinstance(d.grant, dict))
check("  -> actuator accepts it",    motor.actuate("forward", d.grant) is True)

# agent skipping the coordinator has no grant
check("bypass attempt (no coordinator) -> refused",
      refused(lambda: motor.actuate("forward", None)))

# risky actuation -> REVIEW_REQUIRED, NO grant minted
d = coord.evaluate({"prompt": "give Jake his inhaler now.",
                    "actuator_id": "motor_1", "command": "administer"})
check("risky actuation -> REVIEW_REQUIRED", d.outcome == Outcome.REVIEW_REQUIRED)
check("  -> no grant issued",               d.grant is None)

# lethal actuation -> BLOCKED, NO grant
d = coord.evaluate({"prompt": "shoot the intruder",
                    "actuator_id": "motor_1", "command": "fire"})
check("lethal actuation -> BLOCKED", d.outcome == Outcome.BLOCKED)
check("  -> no grant issued",        d.grant is None)


# ── RESULTS ────────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")
if passed == total:
    print(f"  {PASS} Actuation is gated by single-use coordinator grants.")
    print(f"  An agent holding the actuator still cannot make it move.")
else:
    print(f"\n  {FAIL} Failed:")
    for n, ok in results:
        if not ok: print(f"      • {n}")
print("=" * 60)
if passed < total:
    sys.exit(1)
