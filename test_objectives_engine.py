"""Smoke + guarantee tests for driftcore.objectives, run against the real repo."""
from driftcore.objectives import (
    ObjectiveLedger, ObjectiveSignal, SignalRole, GoodnessAsTargetError,
    PlannedAction, check_coverage, check_faithfulness, FaithfulnessOutcome,
    FloorHandle, require_local_floor, enforce_local_floor, FloorContractError,
)
from driftcore.media.policy import EmbodimentClass

passed = 0
def ok(cond, label):
    global passed
    assert cond, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

print("== ledger: human-only ratification ==")
L = ObjectiveLedger()
good, msg = L.ratify_initial("be a good steward", ["safety", "care"],
                             authorised_by="agent")
ok(not good, "agent cannot establish an objective")
good, msg = L.ratify_initial("be a good steward", ["safety", "care"],
                             authorised_by="justin")
ok(good and L.current().version == 1, "human establishes objective at v1")

print("== agent may propose, only human ratifies ==")
p = L.propose("be a good steward, plus tidy", ["safety", "care", "tidy"],
              rationale="add tidiness", proposed_by="agent")
ok(L.current().version == 1, "proposal does not auto-apply")
good, _ = L.ratify_proposal(p.proposal_id, authorised_by="agent")
ok(not good, "agent cannot ratify its own proposal")
good, _ = L.ratify_proposal(p.proposal_id, authorised_by="justin", note="ok")
ok(good and L.current().version == 2, "human ratifies -> v2")

print("== hash chain integrity ==")
chain_ok, why = L.verify_chain()
ok(chain_ok, "chain verifies clean")
# tamper with history and re-verify
L._chain[0] = L._chain[0].__class__(
    **{**L._chain[0].__dict__, "content": "SECRETLY ALTERED"})
chain_ok, why = L.verify_chain()
ok(not chain_ok, f"tamper detected: {why}")

print("== goodness-as-target invariant ==")
L2 = ObjectiveLedger()
monitor = ObjectiveSignal("warmth_of_home", SignalRole.MONITOR_ONLY,
                          is_self_assessment=False)
g, _ = L2.ratify_initial("steward", ["care"], signals=[monitor],
                         authorised_by="justin")
ok(g, "monitor-only world-fact signal allowed")
bad = ObjectiveSignal("how_caring_was_i", SignalRole.TARGET,
                      is_self_assessment=True)
try:
    L2.propose("steward harder", ["care"], rationale="game it",
               proposed_by="agent", signals=[bad])
    ok(False, "should have raised")
except GoodnessAsTargetError:
    ok(True, "self-rating-as-TARGET rejected structurally")

print("== coverage check (mechanical) ==")
plan_ok = [PlannedAction("a1", "lock door", serves=("safety",)),
           PlannedAction("a2", "make tea", serves=("care",))]
r = check_coverage(["safety", "care"], plan_ok, require_all_subgoals=True)
ok(r.ok, "on-objective plan passes")
plan_drift = [PlannedAction("a1", "reorganise finances", serves=())]
r = check_coverage(["safety", "care"], plan_drift)
ok(not r.ok and "orphan" in r.reason, "orphan/drifting action caught")
plan_bogus = [PlannedAction("a1", "x", serves=("world_domination",))]
r = check_coverage(["safety", "care"], plan_bogus)
ok(not r.ok and "fabricated" in r.reason, "fabricated citation caught")
ok(r.to_verdict().verdict.value == "deny", "result surfaces as a resolver DENY")

print("== faithfulness is NOT auto-passed ==")
fr = check_faithfulness(L.current(), plan_ok)
ok(fr.outcome is FaithfulnessOutcome.UNVERIFIABLE and fr.needs_human,
   "faithfulness routes to human, never auto-pass")

print("== floor contract (universal teeth) ==")
ok(require_local_floor(EmbodimentClass.SOFTWARE_AGENT, None)[0],
   "software agent needs no physical floor")
ok(not require_local_floor(EmbodimentClass.HOME_ROBOT, None)[0],
   "embodied agent with NO floor refused")
remote = FloorHandle("cloud_limit", is_local=False)
ok(not require_local_floor(EmbodimentClass.MOBILE_ROBOT, remote)[0],
   "embodied agent with non-local floor refused")
local = FloorHandle("onboard_fuse", is_local=True, check=lambda: True)
ok(require_local_floor(EmbodimentClass.HOME_ROBOT, local)[0],
   "embodied agent with healthy local floor governed")
try:
    enforce_local_floor(EmbodimentClass.HOME_ROBOT, None)
    ok(False, "should have raised")
except FloorContractError:
    ok(True, "enforce_local_floor refuses to start without a floor")

print(f"\nALL {passed} CHECKS PASSED")
