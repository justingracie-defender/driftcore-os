"""
test_multi_instance_state.py
============================
Proves the persistence + multi-instance holes are closed END TO END through the
coordinator/profile — not just in the store in isolation. This is the '8 agents'
scenario the repeating-tasks profile exists for.
"""
import os, tempfile
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.invariant_guard import InvariantGuard
from driftcore.verification.risk_classifier import RiskClassifier
from driftcore.verification.governed_actuator import GrantAuthority
from driftcore.verification.objective_integrity import (
    RatifiedBaseline, AuthorizedObjectiveChange,
)
from driftcore.verification.authorization_state import AuthorizationState

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

BASE = RatifiedBaseline(("do no harm", "serve the user"))
DRIFTED = ("do no harm", "serve the user", "new ratified goal")
SECRET = "verifier-secret"
OWNER = "operator"
BENIGN = {"actuator_id": "motor_1", "command": "forward"}
tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "authz.jsonl")

def agent(store):
    # eight of these would be built from the SAME profile+store in production
    return VerificationCoordinator(
        InvariantGuard(), RiskClassifier(), grant_authority=GrantAuthority(),
        objective_baseline=BASE, objective_secret=SECRET, max_cycles=10,
        authorization_state=store, state_owner=OWNER)

# ── 1. ONE signed change cannot be accepted by TWO instances ──
store = AuthorizationState(path)
a1, a2 = agent(store), agent(store)
change = AuthorizedObjectiveChange.sign(
    from_hash=BASE.hash, new_objectives=DRIFTED,
    justification="ratified expansion", nonce="shared-nonce", secret=SECRET)

d1 = a1.evaluate(BENIGN, context={"current_objectives": DRIFTED, "objective_change": change})
ok(d1.outcome != Outcome.BLOCKED, "instance 1 accepts the signed change once")

# instance 2 tries the SAME change -> nonce already burned in the SHARED store
d2 = a2.evaluate(BENIGN, context={"current_objectives": DRIFTED, "objective_change": change})
ok(d2.outcome == Outcome.BLOCKED,
   "instance 2 CANNOT reuse the same signed change (shared nonce set) — 8-agent hole closed")

# ── 2. Shared CYCLE BUDGET across instances ──
store2 = AuthorizationState(os.path.join(tmp, "budget.jsonl"))
b1, b2 = agent(store2), agent(store2)
ctx = {"current_objectives": BASE.objectives}
# interleave: 5 cycles on b1, 5 on b2 => 10 total against ONE shared budget
for _ in range(5): b1.evaluate(BENIGN, context=ctx)
for _ in range(5): b2.evaluate(BENIGN, context=ctx)
# the 11th accepted pass on EITHER instance must halt (budget is shared, not per-process)
d = b1.evaluate(BENIGN, context=ctx)
ok(d.outcome == Outcome.CYCLE_LIMIT_REACHED,
   "shared budget: 8 agents draw down ONE cap (not one cap each)")

# ── 3. DURABILITY across a 'crash' (fresh store object, same file) ──
store3 = AuthorizationState(os.path.join(tmp, "durable.jsonl"))
c1 = agent(store3)
chg = AuthorizedObjectiveChange.sign(
    from_hash=BASE.hash, new_objectives=DRIFTED, justification="x",
    nonce="durable-nonce", secret=SECRET)
c1.evaluate(BENIGN, context={"current_objectives": DRIFTED, "objective_change": chg})
# simulate crash+restart: brand-new store + coordinator on the same file
store3_reloaded = AuthorizationState(os.path.join(tmp, "durable.jsonl"))
c2 = agent(store3_reloaded)
d = c2.evaluate(BENIGN, context={"current_objectives": DRIFTED, "objective_change": chg})
ok(d.outcome == Outcome.BLOCKED,
   "durability: a captured signed change cannot replay after a restart")

# ── 4. shared re_ratify resets the shared budget ──
b1.re_ratify()
d = b2.evaluate(BENIGN, context={"current_objectives": BASE.objectives})
ok(d.outcome != Outcome.CYCLE_LIMIT_REACHED,
   "re_ratify on one instance resets the SHARED budget for all")

print(f"\n{p}/{p} tests passed")
