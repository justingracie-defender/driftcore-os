"""
test_coordinator_v45_integration.py
===================================
Integration tests for the v4.5.0 stages WIRED INTO the coordinator pipeline.
These exercise the assembled decision path — the surface the isolation tests
(per-module) do NOT cover. This is the file to red-team.

Covered:
  - objective_integrity  : preflight; steady-state pass, drift -> BLOCKED,
                           authorized signed change passes, replay defeated,
                           missing required invariant -> BLOCKED
  - clarification_gate    : high-impact missing slot -> CLARIFICATION_REQUIRED,
                           low-impact default, bright-line BLOCK wins over clarify
  - interpretation_guard  : agree/none -> PROCEED, disagree -> REVIEW,
                           unanimous -> AUTHORIZATION_REQUIRED, NEVER BLOCKED
  - harm_estimate         : verifier-sourced over cutoff -> AUTH; conservative
                           upper bound; planner-sourced number is NON-authoritative
  - consequence_invariance: PROPERTY over the ASSEMBLED coordinator — the verdict
                           does not move when downstream-outcome fields vary
  - authorized egress     : ratified-target policy; per-call forged authorization
                           is ignored (no self-authorization channel)
  - precedence/order      : integrity before guard; guard BLOCK before clarify
  - backward-compat       : with no new inputs, behaviour is unchanged

KNOWN INTEGRATION SEAM (named on purpose, for red-team): the preflight runs per
evaluate() call, but objective_integrity is a per-PLANNING-CYCLE notion. In
steady state (objectives == baseline) it is a cheap hash+presence check every
call, which is correct. The awkward case is the transition cycle: a signed
AuthorizedObjectiveChange authorizes the cycle in which it is presented and burns
its nonce, but the coordinator does NOT mutate its ratified baseline (it holds it
read-only). So a legitimate objective change must be followed by RE-RATIFYING the
baseline (the deployment's job, per objective_integrity.py). Whether the
coordinator should auto-ratify on a valid signed change is an open design call —
left to the operator on purpose, not silently baked in.
"""
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.invariant_guard import InvariantGuard, Effect
from driftcore.verification.risk_classifier import RiskClassifier
from driftcore.verification.governed_actuator import GrantAuthority
from driftcore.verification.objective_integrity import (
    RatifiedBaseline, InvariantRegistry, AuthorizedObjectiveChange, objective_hash,
)
from driftcore.verification.interpretation_guard import Interpretation
from driftcore.verification.clarification_gate import SlotPolicy, Impact
from driftcore.verification.harm_estimate import HarmEstimate, HarmThreshold

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

BENIGN = {"actuator_id": "motor_1", "command": "forward"}   # known-PROCEED action

def plain_coord():
    return VerificationCoordinator(InvariantGuard(), RiskClassifier(),
                                   grant_authority=GrantAuthority())

# ─────────────────────────────────────────────────────────────────
# 1. BACKWARD COMPAT — no new inputs => unchanged behaviour
# ─────────────────────────────────────────────────────────────────
c = plain_coord()
ok(c.evaluate(BENIGN).outcome == Outcome.PROCEED,
   "no new inputs: benign actuation still PROCEEDs")

clethal = VerificationCoordinator(InvariantGuard(), RiskClassifier(),
                                  grant_authority=GrantAuthority(),
                                  tool_effects={"turret_1": {Effect.LETHAL}})
ok(clethal.evaluate({"prompt": "gently engage", "actuator_id": "turret_1",
                     "command": "activate"}).outcome == Outcome.BLOCKED,
   "no new inputs: lethal structural tag still BLOCKs")

# ─────────────────────────────────────────────────────────────────
# 2. OBJECTIVE INTEGRITY PREFLIGHT
# ─────────────────────────────────────────────────────────────────
BASE = RatifiedBaseline(("do no harm", "serve the user"))
SECRET = "verifier-secret"

def integ_coord():
    reg = InvariantRegistry()
    reg.mark_checked("no_lethal_action")          # enforcement marks checks that ran
    return VerificationCoordinator(
        InvariantGuard(), RiskClassifier(), grant_authority=GrantAuthority(),
        objective_baseline=BASE,
        required_invariants=frozenset({"no_lethal_action"}),
        invariant_registry=reg, objective_secret=SECRET)

# 2a. steady state: current == baseline, required invariant present -> not blocked
d = integ_coord().evaluate(BENIGN, context={"current_objectives": BASE.objectives})
ok(d.outcome != Outcome.BLOCKED and d.invariant != "objective_integrity",
   "integrity: steady-state (objectives intact) does not block")

# 2b. silent drift, no authorization -> BLOCKED on objective_integrity
drifted = ("do no harm", "serve the user", "maximize engagement")
d = integ_coord().evaluate(BENIGN, context={"current_objectives": drifted})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "objective_integrity",
   "integrity: silent objective drift is BLOCKED (right invariant)")

# 2c. authorized, signed change for the drift -> not blocked by integrity
change = AuthorizedObjectiveChange.sign(
    from_hash=BASE.hash, new_objectives=drifted,
    justification="ratified product expansion", nonce="nonce-A", secret=SECRET)
cc = integ_coord()
d = cc.evaluate(BENIGN, context={"current_objectives": drifted,
                                 "objective_change": change})
ok(d.outcome != Outcome.BLOCKED or d.invariant != "objective_integrity",
   "integrity: a valid human-signed change authorizes the drift")

# 2d. REPLAY the same change on the same coordinator -> nonce burned -> BLOCKED
d2 = cc.evaluate(BENIGN, context={"current_objectives": drifted,
                                  "objective_change": change})
ok(d2.outcome == Outcome.BLOCKED and d2.invariant == "objective_integrity",
   "integrity: replayed authorization (burned nonce) is BLOCKED")

# 2e. a DIFFERENT old authorization cannot revert: wrong from_hash
stale = AuthorizedObjectiveChange.sign(
    from_hash=objective_hash(("some other baseline",)), new_objectives=drifted,
    justification="stale", nonce="nonce-Z", secret=SECRET)
d = integ_coord().evaluate(BENIGN, context={"current_objectives": drifted,
                                            "objective_change": stale})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "objective_integrity",
   "integrity: authorization bound to a different from-hash is rejected")

# 2f. required invariant silently absent this cycle -> BLOCKED (even if no drift)
reg_empty = InvariantRegistry()    # nothing marked checked
c_missing = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(), grant_authority=GrantAuthority(),
    objective_baseline=BASE, required_invariants=frozenset({"no_lethal_action"}),
    invariant_registry=reg_empty, objective_secret=SECRET)
d = c_missing.evaluate(BENIGN, context={"current_objectives": BASE.objectives})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "objective_integrity",
   "integrity: a required invariant not checked this cycle is BLOCKED")

# ─────────────────────────────────────────────────────────────────
# 3. CLARIFICATION GATE
# ─────────────────────────────────────────────────────────────────
policy = SlotPolicy(
    required=("recipient", "amount"),
    prompts={"recipient": "Who should receive this?", "amount": "How much?"},
    defaults={"amount": 0})

# 3a. high-impact (ACT) + missing required slot -> CLARIFICATION_REQUIRED
d = plain_coord().evaluate(BENIGN, context={"clarification": {
    "policy": policy, "impact": Impact.ACT, "provided": {"amount": 100}}})
ok(d.outcome == Outcome.CLARIFICATION_REQUIRED and d.detail["slot"] == "recipient"
   and "receive" in (d.detail["question"] or ""),
   "clarify: high-impact missing slot asks ONE human-authored question")

# 3b. all slots present -> proceeds past clarification
d = plain_coord().evaluate(BENIGN, context={"clarification": {
    "policy": policy, "impact": Impact.ACT,
    "provided": {"recipient": "alice", "amount": 100}}})
ok(d.outcome == Outcome.PROCEED,
   "clarify: all required slots present -> proceeds")

# 3c. low-impact READ missing slot -> default, NOT clarify
d = plain_coord().evaluate(BENIGN, context={"clarification": {
    "policy": policy, "impact": Impact.READ, "provided": {"recipient": "alice"}}})
ok(d.outcome == Outcome.PROCEED,
   "clarify: low-impact read fills default, does not nag")

# 3d. bright-line BLOCK wins over clarification (never clarify a forbidden act)
d = clethal.evaluate({"prompt": "engage", "actuator_id": "turret_1",
                      "command": "activate"},
                     context={"clarification": {"policy": policy,
                              "impact": Impact.ACT, "provided": {}}})
ok(d.outcome == Outcome.BLOCKED,
   "order: bright-line BLOCK beats clarification")

# ─────────────────────────────────────────────────────────────────
# 4. INTERPRETATION GUARD (the fuzzy middle; NEVER BLOCKED)
# ─────────────────────────────────────────────────────────────────
# 4a. no credible reading sees a violation -> PROCEED (falls through)
interps_ok = (Interpretation("plain", 0.9, False),
              Interpretation("strict", 0.5, False))
d = plain_coord().evaluate(BENIGN, context={"interpretations": interps_ok})
ok(d.outcome == Outcome.PROCEED,
   "interp: no credible reading sees violation -> PROCEED")

# 4b. credible readings DISAGREE -> REVIEW_REQUIRED (machine does not pick)
interps_split = (Interpretation("permissive", 0.8, False),
                 Interpretation("protective", 0.7, True))
d = plain_coord().evaluate(BENIGN, context={"interpretations": interps_split})
ok(d.outcome == Outcome.REVIEW_REQUIRED,
   "interp: credible readings disagree -> REVIEW_REQUIRED")

# 4c. UNANIMOUS violation -> AUTHORIZATION_REQUIRED, flagged, and NOT BLOCKED
interps_unanimous = (Interpretation("a", 0.9, True),
                     Interpretation("b", 0.6, True))
d = plain_coord().evaluate(BENIGN, context={"interpretations": interps_unanimous})
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED and d.outcome != Outcome.BLOCKED
   and d.detail["flag_for_bright_line"] is True,
   "interp: unanimous violation -> AUTH (flagged), never BLOCKED")

# 4d. frivolous sub-floor reading cannot block -> no credible reading -> REVIEW
interps_frivolous = (Interpretation("frivolous", 0.05, True),)
d = plain_coord().evaluate(BENIGN, context={"interpretations": interps_frivolous})
ok(d.outcome == Outcome.REVIEW_REQUIRED,
   "interp: sub-floor frivolous reading cannot block; no basis -> REVIEW")

# ─────────────────────────────────────────────────────────────────
# 5. HARM ESTIMATE vs HUMAN CUTOFF
# ─────────────────────────────────────────────────────────────────
thr = HarmThreshold(cutoff=0.5, use_upper_bound=True)

# 5a. verifier-sourced, clearly over cutoff -> AUTHORIZATION_REQUIRED
est_over = HarmEstimate(p=0.7, ci_low=0.6, ci_high=0.8,
                        source="verifier", verifier_sourced=True)
d = plain_coord().evaluate(BENIGN, context={"harm_estimate": est_over,
                                            "harm_threshold": thr})
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED and "P(harm)" in d.detail["harm"],
   "harm: verifier estimate over cutoff -> AUTH (with the fact)")

# 5b. CONSERVATIVE upper bound: point under, CI upper over -> escalates
est_wide = HarmEstimate(p=0.1, ci_low=0.0, ci_high=0.6,
                        source="verifier", verifier_sourced=True)
d = plain_coord().evaluate(BENIGN, context={"harm_estimate": est_wide,
                                            "harm_threshold": thr})
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED,
   "harm: wide CI (upper over cutoff) triggers caution though point is under")

# 5c. same wide estimate but cutoff judged on POINT -> under -> proceeds
thr_point = HarmThreshold(cutoff=0.5, use_upper_bound=False)
d = plain_coord().evaluate(BENIGN, context={"harm_estimate": est_wide,
                                            "harm_threshold": thr_point})
ok(d.outcome == Outcome.PROCEED,
   "harm: judging on the point estimate, an under-cutoff value proceeds")

# 5d. UNVERIFIED estimate that WOULD cross the cutoff: cannot RUN past it, and
#     cannot be trusted to hard-stop on its own -> routes to a human (REVIEW).
est_unv_stop = HarmEstimate(p=0.9, ci_low=0.85, ci_high=0.95,
                            source="planner", verifier_sourced=False)
d = plain_coord().evaluate(BENIGN, context={"harm_estimate": est_unv_stop,
                                            "harm_threshold": thr})
ok(d.outcome == Outcome.REVIEW_REQUIRED and d.detail["verifier_sourced"] is False,
   "harm: UNVERIFIED estimate over cutoff -> REVIEW (cannot self-authorize OR self-stop)")

# 5e. UNVERIFIED estimate that would NOT cross the cutoff is IGNORED — an
#     unverified number may never be used to lower caution; pipeline proceeds.
est_unv_run = HarmEstimate(p=0.01, ci_low=0.0, ci_high=0.05,
                           source="planner", verifier_sourced=False)
d = plain_coord().evaluate(BENIGN, context={"harm_estimate": est_unv_run,
                                            "harm_threshold": thr})
ok(d.outcome == Outcome.PROCEED,
   "harm: UNVERIFIED estimate under cutoff is ignored (cannot lower caution) -> PROCEED")

# ─────────────────────────────────────────────────────────────────
# 6. CONSEQUENCE INVARIANCE — property over the ASSEMBLED coordinator
# ─────────────────────────────────────────────────────────────────
from driftcore.verification.consequence_invariance import check_consequence_invariance

coord_ci = plain_coord()
def decide(rec):
    # downstream-outcome fields are passed into CONTEXT; the verdict must not move
    ctx = {k: v for k, v in rec.items() if k != "prompt"}
    return coord_ci.evaluate({"prompt": rec["prompt"]}, context=ctx).outcome

record = {"prompt": "draft a friendly greeting",
          "actual_harm_occurred": False, "payoff": 0.0, "succeeded": True}
rep = check_consequence_invariance(
    decide, record,
    outcome_fields=["actual_harm_occurred", "payoff", "succeeded"],
    probe_values=[True, False, 1.0, -1.0, "anything"])
ok(rep.invariant and rep.offending_field is None,
   "consequence-invariance: assembled verdict is blind to downstream-outcome fields")

# ─────────────────────────────────────────────────────────────────
# 7. PRECEDENCE — objective integrity runs BEFORE the guard
# ─────────────────────────────────────────────────────────────────
reg = InvariantRegistry(); reg.mark_checked("no_lethal_action")
c_order = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(), grant_authority=GrantAuthority(),
    tool_effects={"turret_1": {Effect.LETHAL}},
    objective_baseline=BASE, required_invariants=frozenset({"no_lethal_action"}),
    invariant_registry=reg, objective_secret=SECRET)
# both would fire (objectives drifted AND lethal tag) -> integrity wins (it's first)
d = c_order.evaluate({"prompt": "x", "actuator_id": "turret_1", "command": "activate"},
                     context={"current_objectives": drifted})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "objective_integrity",
   "order: objective-integrity preflight blocks before the guard is reached")

# ─────────────────────────────────────────────────────────────────
# 8. FOOTGUN CLOSED — missing current_objectives is an ERROR, not a pass
# ─────────────────────────────────────────────────────────────────
d = integ_coord().evaluate(BENIGN)   # NOTE: no current_objectives supplied
ok(d.outcome == Outcome.BLOCKED and d.invariant == "objective_integrity"
   and d.detail.get("error") == "missing_current_objectives"
   and d.detail.get("retryable") is True,
   "footgun: preflight on + current_objectives absent -> BLOCKED retryable (no silent pass)")

# ─────────────────────────────────────────────────────────────────
# 9. BOUNDED AUTONOMY (max_cycles) — the fix for the 1-cycle cliff
# ─────────────────────────────────────────────────────────────────
def bounded_coord(maxc):
    reg = InvariantRegistry(); reg.mark_checked("no_lethal_action")
    return VerificationCoordinator(
        InvariantGuard(), RiskClassifier(), grant_authority=GrantAuthority(),
        objective_baseline=BASE, required_invariants=frozenset({"no_lethal_action"}),
        invariant_registry=reg, objective_secret=SECRET, max_cycles=maxc)

# 9a. THE CLIFF IS GONE: one signed change buys CONTINUED operation under the new
#     goal without re-presenting the (burned) change on the next cycle.
bc = bounded_coord(10)
chg = AuthorizedObjectiveChange.sign(
    from_hash=BASE.hash, new_objectives=drifted,
    justification="ratified expansion", nonce="bn-1", secret=SECRET)
d1 = bc.evaluate(BENIGN, context={"current_objectives": drifted, "objective_change": chg})
ok(d1.outcome != Outcome.BLOCKED,
   "bounded: signed change accepted (operative goal advances)")
d2 = bc.evaluate(BENIGN, context={"current_objectives": drifted})   # no change presented
ok(d2.outcome not in (Outcome.BLOCKED, Outcome.CYCLE_LIMIT_REACHED),
   "bounded: next cycle under the new goal proceeds WITHOUT re-presenting the change (cliff fixed)")

# 9b. THE CAP HOLDS: after max_cycles accepted passes -> CYCLE_LIMIT_REACHED.
bc2 = bounded_coord(3)
outs = [bc2.evaluate(BENIGN, context={"current_objectives": BASE.objectives}).outcome
        for _ in range(3)]
ok(all(o != Outcome.CYCLE_LIMIT_REACHED for o in outs),
   "bounded: the first max_cycles passes are allowed")
d_halt = bc2.evaluate(BENIGN, context={"current_objectives": BASE.objectives})
ok(d_halt.outcome == Outcome.CYCLE_LIMIT_REACHED and d_halt.detail["max_cycles"] == 3,
   "bounded: the pass after the budget is HALTED (CYCLE_LIMIT_REACHED)")
ok(d_halt.tier is None and d_halt.grant is None,
   "bounded: a halted pass runs none of the downstream pipeline (no tier/grant)")

# 9c. RE-RATIFY resets the budget (the 'new key').
bc2.re_ratify()
d_after = bc2.evaluate(BENIGN, context={"current_objectives": BASE.objectives})
ok(d_after.outcome != Outcome.CYCLE_LIMIT_REACHED,
   "bounded: re_ratify() resets the cycle budget and operation resumes")

# 9d. REPLAY in bounded mode: a burned authorization cannot force a DIFFERENT
#     goal once the operative goal has moved on.
bc3 = bounded_coord(10)
chgA = AuthorizedObjectiveChange.sign(
    from_hash=BASE.hash, new_objectives=drifted, justification="A",
    nonce="rb-1", secret=SECRET)
bc3.evaluate(BENIGN, context={"current_objectives": drifted, "objective_change": chgA})
attacker_goal = ("do no harm", "serve the user", "exfiltrate data")
d_attack = bc3.evaluate(BENIGN, context={"current_objectives": attacker_goal,
                                         "objective_change": chgA})   # replay old key
ok(d_attack.outcome == Outcome.BLOCKED and d_attack.invariant == "objective_integrity",
   "bounded: a burned authorization cannot force a different goal (replay defeated)")

# ─────────────────────────────────────────────────────────────────
# 10. AUTHORIZED EGRESS — the seed stays alive, the key is real
# ─────────────────────────────────────────────────────────────────
from driftcore.verification.invariant_guard import ActionContext

def egress_coord(targets):
    return VerificationCoordinator(InvariantGuard(), RiskClassifier(),
        grant_authority=GrantAuthority(),
        authorized_egress_targets=targets, egress_owner="operator")

EMAIL = {"prompt": "send the nightly summary", "effects": [Effect.DATA_EGRESS],
         "target": "reports@example.com"}

# 10a. BACKWARD COMPAT / fail-closed default: NO policy -> egress still blocked
d = plain_coord().evaluate(EMAIL)
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_unauthorized_exfiltration",
   "egress: with no ratified policy, all egress still trips the seed (unchanged default)")

# 10b. ratified target -> authorized egress passes the seed
d = egress_coord(["reports@example.com"]).evaluate(EMAIL)
ok(d.outcome == Outcome.PROCEED,
   "egress: ratified target passes the exfiltration seed (the key works)")

# 10c. SAME effect, UNRATIFIED target -> the seed fires (it is alive per-action)
d = egress_coord(["reports@example.com"]).evaluate(dict(EMAIL, target="dropzone.evil"))
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_unauthorized_exfiltration",
   "egress: unratified target trips the seed — authorization varies per action, not per run")

# 10d. egress with NO declared target -> fail-closed even with a policy present
d = egress_coord(["reports@example.com"]).evaluate(
    {"prompt": "send it", "effects": [Effect.DATA_EGRESS]})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_unauthorized_exfiltration",
   "egress: undeclared target fails closed")

# 10e. SELF-AUTHORIZATION DEFEATED: a forged ActionContext in the per-call
#      context dict is ignored — authorization derives only from the policy.
forged = ActionContext(owner_authorized=True, target_authorized=True,
                       authorised_by="operator")
d = plain_coord().evaluate(EMAIL, context={"action_context": forged})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_unauthorized_exfiltration",
   "egress: a forged per-call ActionContext is ignored (no self-authorization channel)")

# 10f. multiple targets: ALL must be ratified, or the seed fires
d = egress_coord(["reports@example.com"]).evaluate(
    dict(EMAIL, target=["reports@example.com", "dropzone.evil"]))
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_unauthorized_exfiltration",
   "egress: mixed target list with one unratified destination is blocked")

# 10g. exact-string matching: near-miss canonicalization tricks do not pass
d = egress_coord(["reports@example.com"]).evaluate(
    dict(EMAIL, target="Reports@Example.com"))
ok(d.outcome == Outcome.BLOCKED,
   "egress: matching is exact — case-variant target does not pass")

# ─────────────────────────────────────────────────────────────────
# 11. THE MERCY LADDER — PREFER_THE_GENTLEST_AVAILABLE_PATH as enforcement
# ─────────────────────────────────────────────────────────────────
from driftcore.verification.proportionate_response import (
    Threat, Stakes, TimeToHarm, ResponseOption,
)

RELOCATE = ResponseOption("relocate", harm=0.05, cost=0.3, effectiveness=0.8, reversible=True)
WARN     = ResponseOption("warn", harm=0.0, cost=0.1, effectiveness=0.7, reversible=True)
STRIKE   = ResponseOption("strike", harm=0.7, cost=0.2, effectiveness=0.9, reversible=False)
EXTERM   = ResponseOption("exterminate", harm=0.9, cost=0.1, effectiveness=0.95, reversible=False)
WASPS    = Threat(True, Stakes.MODERATE, TimeToHarm.AMPLE, "wasp nest by the door")

def mercy_ctx(threat, options, proposed=None, verified=True):
    return {"proportionate": {"threat": threat, "options": options,
                              "proposed": proposed, "verifier_sourced": verified}}

# 11a. a gentler effective path exists -> the harsher proposal is NOT greenlit
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(WASPS, [RELOCATE, EXTERM], "exterminate"))
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED and "relocate" in d.reason,
   "mercy: gentler path exists -> harsher proposal needs a human (names the gentler path)")

# 11b. the proposal IS the gentlest -> falls through; plan + pre-committed
#      success criteria ride on the final PROCEED for reflection.py
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(WASPS, [RELOCATE, EXTERM], "relocate"))
ok(d.outcome == Outcome.PROCEED and d.detail["mercy"]["chosen"] == "relocate"
   and "chosen_was_least_harm_effective" in d.detail["mercy"]["success_criteria"],
   "mercy: gentlest proposal proceeds, success criteria pre-committed on the decision")

# 11c. NO-THREAT TRAP: no present threat but the agent proposes action anyway ->
#      not greenlit (the trigger is the threat, never the category)
CALM = Threat(False, Stakes.NONE, TimeToHarm.AMPLE, "wasps far away, nobody near")
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(CALM, [RELOCATE, EXTERM], "exterminate"))
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED and "trigger is the threat" in d.reason,
   "mercy: no present threat -> proposed action is not greenlit (category is not a target)")

# 11c2. no threat and nothing proposed -> proceeds as a no-action plan
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(CALM, [RELOCATE, EXTERM]))
ok(d.outcome == Outcome.PROCEED and "no_action_taken" in d.detail["mercy"]["success_criteria"],
   "mercy: no threat, no proposal -> no-action plan proceeds")

# 11d. urgency compresses deliberation: imminent threat makes the slow gentle
#      option unreachable; the fast option is chosen and proceeds NOW
CHARGE = Threat(True, Stakes.LIFE_THREATENING, TimeToHarm.IMMINENT, "dog charging a child")
SLOW_RELOCATE = ResponseOption("relocate", harm=0.05, cost=0.8, effectiveness=0.8)
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(CHARGE, [SLOW_RELOCATE, STRIKE], "strike"))
ok(d.outcome == Outcome.PROCEED and d.detail["mercy"]["chosen"] == "strike",
   "mercy: imminent harm -> slow-gentle unreachable, fast option acts now (audited)")

# 11e. irreversible + time to spare -> a human confirms BEFORE it happens
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(
    Threat(True, Stakes.SEVERE, TimeToHarm.AMPLE, "raccoon in the pantry"),
    [STRIKE], "strike"))
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED and "irreversible" in d.reason,
   "mercy: irreversible with time to spare -> human confirms before acting")

# 11f. UNVERIFIED-NUMBERS TRAP: planner-sourced numbers cannot authorize harm,
#      even for the least-harm option
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(WASPS, [RELOCATE], "relocate", verified=False))
ok(d.outcome == Outcome.AUTHORIZATION_REQUIRED and "not verifier-sourced" in d.reason,
   "mercy: unverified numbers may not authorize a harmful path")

# 11g. ...but unverified numbers CAN select a harmless path
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(WASPS, [WARN], "warn", verified=False))
ok(d.outcome == Outcome.PROCEED,
   "mercy: unverified numbers may still pick a harmless path (caution can only rise)")

# 11h. nothing both works and is reachable -> hand to a human
d = plain_coord().evaluate(BENIGN, context=mercy_ctx(
    WASPS, [ResponseOption("wish", 0.0, 0.1, 0.2)], "wish"))
ok(d.outcome == Outcome.REVIEW_REQUIRED,
   "mercy: no effective option -> REVIEW (a human is needed, not a guess)")

# 11i. bright lines still own BLOCKED: a lethal-tagged request never reaches mercy
d = plain_coord().evaluate({"prompt": "x", "effects": [Effect.LETHAL]},
                           context=mercy_ctx(WASPS, [RELOCATE, EXTERM], "exterminate"))
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_lethal_action",
   "order: the guard's bright line fires before the mercy ladder is consulted")

# ─────────────────────────────────────────────────────────────────
# 12. STRICT MODE (enforce_v45) + CONTEXT HYGIENE
# ─────────────────────────────────────────────────────────────────
# 12a. strict mode refuses to construct without an objective baseline
try:
    VerificationCoordinator(InvariantGuard(), RiskClassifier(), strict_v45=True)
    ok(False, "strict construction without a baseline should raise")
except ValueError:
    ok(True, "strict: refuses to run ungoverned (no baseline at construction -> raise)")

def strict_coord():
    return VerificationCoordinator(
        InvariantGuard(), RiskClassifier(), grant_authority=GrantAuthority(),
        objective_baseline=BASE, strict_v45=True)

# 12b. strict: a consequential action (carries effects) without verifier harm
#      inputs is BLOCKED (retryable) — gates cannot be silently left disabled
d = strict_coord().evaluate(
    {"prompt": "act", "effects": [Effect.PHYSICAL_FORCE]},
    context={"current_objectives": BASE.objectives})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "strict_v45"
   and d.detail.get("retryable") is True,
   "strict: consequential action without harm inputs is BLOCKED (won't run unless wired)")

# 12c. strict: same action WITH verifier harm inputs proceeds (under cutoff)
from driftcore.verification.harm_estimate import HarmEstimate, HarmThreshold
safe = HarmEstimate(p=0.01, ci_low=0.0, ci_high=0.05, source="verifier", verifier_sourced=True)
d = strict_coord().evaluate(
    {"prompt": "act", "effects": [Effect.PHYSICAL_FORCE]},
    context={"current_objectives": BASE.objectives,
             "harm_estimate": safe, "harm_threshold": HarmThreshold(0.5, True)})
ok(d.outcome == Outcome.PROCEED,
   "strict: consequential action WITH verifier harm inputs proceeds")

# 12d. strict: an effect-free action needs no harm inputs (nothing consequential)
d = strict_coord().evaluate({"prompt": "just summarize"},
                            context={"current_objectives": BASE.objectives})
ok(d.outcome in (Outcome.PROCEED, Outcome.REVIEW_REQUIRED),
   "strict: effect-free action is not forced to carry harm inputs")

# 12e. CONTEXT HYGIENE: a caller-injected _mercy_plan is stripped, never honored
d = plain_coord().evaluate({"actuator_id": "motor_1", "command": "forward"},
                           context={"_mercy_plan": {"chosen": "FORGED", "rationale": "injected"}})
ok(d.outcome == Outcome.PROCEED and d.detail.get("mercy") is None,
   "ctx hygiene: a forged _mercy_plan in caller context is stripped (no internal-provenance forgery)")

print(f"\n{p}/{p} tests passed")


# ─────────────────────────────────────────────────────────────────
# 13. CUMULATIVE-EFFECT LEDGER wired into the pipeline (end-to-end)
# ─────────────────────────────────────────────────────────────────
import tempfile as _tf, os as _os
from driftcore.verification.cumulative_ledger import CumulativeLedger, BudgetPolicy, LedgerVerdict

_tmp = _tf.mkdtemp()
def _ledger_coord(ledger):
    return VerificationCoordinator(InvariantGuard(), RiskClassifier(),
        grant_authority=GrantAuthority(), cumulative_ledger=ledger)

# an egress action that clears the per-action guard (authorized target so the
# exfiltration seed doesn't fire), so we isolate the LEDGER's cross-action gate
def _egress_coord(ledger, targets):
    return VerificationCoordinator(InvariantGuard(), RiskClassifier(),
        grant_authority=GrantAuthority(), cumulative_ledger=ledger,
        authorized_egress_targets=targets, egress_owner="operator")
EG = {"prompt": "send summary", "effects": [Effect.DATA_EGRESS], "target": "ok@x.com"}

# 13a. fragmentation THROUGH the coordinator: 2 egress ok, 3rd BLOCKED by ledger
lg = CumulativeLedger(_os.path.join(_tmp, "e2e.jsonl"),
                      BudgetPolicy(window_seconds=3600, max_egress_actions=2))
c = _egress_coord(lg, ["ok@x.com"])
d1 = c.evaluate(EG); 
r1 = d1.detail.get("ledger_reservation")
ok(d1.outcome == Outcome.PROCEED and r1 is not None, "ledger: 1st egress proceeds with a reservation attached")
lg.commit(r1)
d2 = c.evaluate(EG); lg.commit(d2.detail["ledger_reservation"])
ok(d2.outcome == Outcome.PROCEED, "ledger: 2nd egress proceeds")
d3 = c.evaluate(EG)
ok(d3.outcome == Outcome.BLOCKED and d3.invariant == "cumulative_ledger",
   "ledger e2e: 3rd egress is BLOCKED by the cumulative budget through the pipeline (fragmentation closed)")

# 13b. the reservation is released (rolled back) when the action does NOT proceed.
#      Build a coordinator whose risk stage forces REVIEW, and confirm budget frees.
lg2 = CumulativeLedger(_os.path.join(_tmp, "rb_e2e.jsonl"),
                       BudgetPolicy(window_seconds=3600, max_egress_actions=1))
# reserve once via a proceeding action, roll back by NOT committing, budget frees
c2 = _egress_coord(lg2, ["ok@x.com"])
dd = c2.evaluate(EG)
ok(dd.outcome == Outcome.PROCEED, "ledger: action reserves and proceeds")
lg2.rollback(dd.detail["ledger_reservation"])   # deployment reports the send failed
dd2 = c2.evaluate(EG)
ok(dd2.outcome == Outcome.PROCEED,
   "ledger e2e: a rolled-back reservation frees the budget for a retry")

# 13c. inert when no ledger configured (backward compat spot-check)
c3 = _egress_coord(None, ["ok@x.com"])
ok(c3.evaluate(EG).outcome == Outcome.PROCEED and "ledger_reservation" not in c3.evaluate(EG).detail,
   "ledger: with no ledger configured, the pipeline is unchanged")

print(f"\n{p}/{p} tests passed")


# ── 13d. RESERVATION LEAK FIX: a stage throwing AFTER reserve releases the hold ──
class _BoomClassifier:
    def classify(self, *a, **k):
        raise RuntimeError("boom")

_lg_leak = CumulativeLedger(_os.path.join(_tmp, "leak.jsonl"),
                            BudgetPolicy(window_seconds=3600, max_egress_actions=1))
_c_leak = VerificationCoordinator(InvariantGuard(), _BoomClassifier(),
    grant_authority=GrantAuthority(), cumulative_ledger=_lg_leak,
    authorized_egress_targets=["ok@x.com"], egress_owner="operator")
_d_leak = _c_leak.evaluate(EG)   # reserves, then classifier throws -> BLOCKED (fail-closed)
ok(_d_leak.outcome == Outcome.BLOCKED, "exception after reserve -> BLOCKED (fail-closed)")
from driftcore.verification.cumulative_ledger import ProposedAction as _PA
_r_after = _lg_leak.reserve("operator", _PA(effects=("data_egress",)))
ok(_r_after.verdict == LedgerVerdict.OK,
   "reservation-leak FIX: a throwing later stage releases the hold (budget free, no leak)")

print(f"\n{p}/{p} tests passed")
