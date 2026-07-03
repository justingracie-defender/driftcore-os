"""
test_repeating_tasks_profile.py
===============================
Tests the zero-config 'repeating_tasks' deployment profile and the profile ->
coordinator builder (driftcore/profiles/coordinator_builder.py).

The story under test: a set-once profile that is SILENT in steady state and
flags ONLY off-pattern behaviour (a changed goal, or an effect outside the
approved capability set), WITHOUT relaxing any safety property.

Design note for red-team: through the coordinator, DATA_EGRESS / ACCOUNT_ACCESS
always trip a seed invariant (there is no auth-context path on the coordinator's
guard call), so PHYSICAL_FORCE — the one effect the universal floor does NOT cap
— is used as the clean 'seed-free' effect to isolate the capability allowlist.
"""
from driftcore.profiles import ProfileManager, PROFILES
from driftcore.profiles.coordinator_builder import (
    build_coordinator, build_capability_guard,
)
from driftcore.verification.coordinator import Outcome
from driftcore.verification.invariant_guard import Effect, SEED_INVARIANTS

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

OBJ = ("run the nightly report", "email the summary")
SECRET = "deployment-secret"

def profile(allowed, reratify=None, objectives=OBJ):
    # a minimal profile dict; build_coordinator only reads the 'coordinator' block
    return {"coordinator": {
        "objectives": list(objectives),
        "allowed_effects": list(allowed),
        "reratify_every": reratify,
    }}

def steady():
    # current_objectives MUST be supplied every cycle (footgun-closed);
    # for a stable repeating deployment it equals the pinned objectives.
    return {"current_objectives": list(OBJ)}

MOTOR = {"actuator_id": "motor_1", "command": "forward"}   # effect-free, benign

# ── the profile is discoverable and standard methods still work ──
pm = ProfileManager()
ok("repeating_tasks" in pm.available(), "profile is discoverable via ProfileManager")
ok(isinstance(pm.describe("repeating_tasks"), str), "describe() works on the new profile")

# 1. builder turns a profile into a coordinator
coord = build_coordinator(profile(["PHYSICAL_FORCE"]), objective_secret=SECRET)
ok(coord is not None, "builder: profile -> configured coordinator")

# 2. STEADY STATE is silent: effect-free action just proceeds
d = coord.evaluate(MOTOR, context=steady())
ok(d.outcome == Outcome.PROCEED, "steady state: effect-free action proceeds silently")

# 3. an ON-allowlist effect proceeds
d = coord.evaluate({"prompt": "nudge", "effects": [Effect.PHYSICAL_FORCE]}, context=steady())
ok(d.outcome == Outcome.PROCEED, "on-allowlist effect (physical_force) proceeds")

# 4. OBJECTIVE DRIFT is flagged (an agent operating under a changed goal)
d = coord.evaluate({"prompt": "x"}, context={"current_objectives": ["a different goal"]})
ok(d.outcome == Outcome.BLOCKED and d.invariant == "objective_integrity",
   "off-pattern goal: objective drift is BLOCKED")

# 5. OFF-PATTERN EFFECT is flagged by the capability allowlist (seed-free effect)
coord_empty = build_coordinator(profile([]), objective_secret=SECRET)   # allow nothing
d = coord_empty.evaluate({"prompt": "x", "effects": [Effect.PHYSICAL_FORCE]}, context=steady())
ok(d.outcome == Outcome.BLOCKED and d.invariant == "capability_allowlist",
   "off-pattern effect: blocked by the capability allowlist")

# 6. THE ALLOWLIST CANNOT WIDEN PAST THE FLOOR: allowlist 'permits' lethal, the
#    seed still fires — and it is the SEED that binds, not the allowlist.
coord_lethal = build_coordinator(profile(["LETHAL"]), objective_secret=SECRET)
d = coord_lethal.evaluate({"prompt": "x", "effects": [Effect.LETHAL]}, context=steady())
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_lethal_action",
   "floor holds: lethal blocked by the SEED even when allowlisted (allowlist only narrows)")

# 7. an effect-FREE action passes even under an empty allowlist (nothing to be
#    'outside' the list) — the allowlist does not nag benign no-effect work
d = coord_empty.evaluate(MOTOR, context=steady())
ok(d.outcome == Outcome.PROCEED, "effect-free action passes under an empty allowlist")

# 8. OVERSIGHT CADENCE: reratify_every bounds accepted cycles; re_ratify resets.
#    (This is a cadence, NOT a safety dial — the guard fired on every cycle above.)
coord_cad = build_coordinator(profile(["PHYSICAL_FORCE"], reratify=3), objective_secret=SECRET)
outs = [coord_cad.evaluate(MOTOR, context=steady()).outcome for _ in range(3)]
ok(all(o != Outcome.CYCLE_LIMIT_REACHED for o in outs), "cadence: first N cycles allowed")
d = coord_cad.evaluate(MOTOR, context=steady())
ok(d.outcome == Outcome.CYCLE_LIMIT_REACHED, "cadence: halts after N accepted cycles (re-check-in)")
coord_cad.re_ratify()
d = coord_cad.evaluate(MOTOR, context=steady())
ok(d.outcome != Outcome.CYCLE_LIMIT_REACHED, "cadence: re_ratify() resets the checkpoint")

# 9. the builder REQUIRES a set-once objective baseline
try:
    build_coordinator({"coordinator": {"objectives": []}}, objective_secret=SECRET)
    ok(False, "empty objectives should raise")
except ValueError:
    ok(True, "builder requires a non-empty objectives baseline (raises ValueError)")

# 10. the capability guard keeps EVERY seed and adds exactly one allowlist invariant
g = build_capability_guard(["PHYSICAL_FORCE"])
ids = [i.invariant_id for i in g._invariants]
ok(all(s.invariant_id in ids for s in SEED_INVARIANTS)
   and "capability_allowlist" in ids
   and len(ids) == len(SEED_INVARIANTS) + 1,
   "capability guard = all seed invariants + one allowlist invariant (seeds never dropped)")

# 11. the footgun stays closed through a profile-built coordinator
d = coord.evaluate({"prompt": "x"})   # no current_objectives supplied
ok(d.outcome == Outcome.BLOCKED and d.detail.get("retryable") is True,
   "footgun: built coordinator still requires current_objectives (BLOCKED retryable)")

# ── 12. THE GAP CLOSED — her summary email actually works ──
# Two independent checks must BOTH pass: effect class on the capability
# allowlist AND target on the ratified egress list. Content is NOT inspected.
prof = profile(["DATA_EGRESS"])
prof["coordinator"]["authorized_targets"] = ["reports@herco.example"]
prof["coordinator"]["owner"] = "operator"
c12 = build_coordinator(prof, objective_secret=SECRET)
SEND = {"prompt": "send nightly summary", "effects": [Effect.DATA_EGRESS],
        "target": "reports@herco.example"}

d = c12.evaluate(SEND, context=steady())
ok(d.outcome == Outcome.PROCEED,
   "gap closed: allowlisted effect + ratified target -> her summary email proceeds")

d = c12.evaluate(dict(SEND, target="dropzone.evil"), context=steady())
ok(d.outcome == Outcome.BLOCKED and d.invariant == "no_unauthorized_exfiltration",
   "gap closed: same task, unratified destination -> exfiltration seed fires")

# effect NOT on the capability allowlist, even with a ratified target -> the
# capability check blocks independently (defense in depth, two separate keys)
prof2 = profile([])
prof2["coordinator"]["authorized_targets"] = ["reports@herco.example"]
prof2["coordinator"]["owner"] = "operator"
c12b = build_coordinator(prof2, objective_secret=SECRET)
d = c12b.evaluate(SEND, context=steady())
ok(d.outcome == Outcome.BLOCKED and d.invariant == "capability_allowlist",
   "independence: ratified target cannot bypass the capability allowlist")

print(f"\n{p}/{p} tests passed")
