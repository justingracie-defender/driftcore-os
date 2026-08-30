"""
Blast-radius governor + posture events — the incident-derived controls.

These replay the SHAPE of the OpenAI/Hugging Face July 2026 incident against the
wall: many individually-unremarkable actions moving laterally across many distinct
capabilities. Each check maps to a row in THREAT_MODEL_ONE_DOOR.md §Incident-derived.

Honest scope, restated here so a reader of the tests cannot over-read them: none of
this would have caught that incident's actual escape, which was a zero-day beneath
this layer. What it catches is the shape, for actions that DO cross the wall.
"""
from driftcore.kernel.blast_radius import (
    BlastRadiusGovernor, BreadthPolicy, BreadthVerdict,
)
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.verification.invariant_guard import Effect

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

KEY = b"\x11" * 32
SOCK = "/tmp/dc_blast.sock"

def grant(v, aid, cmd, params, nonce, scope):
    return Grant.issue(KEY, key_id="operator", role="operator", scope=scope,
                       subject="robot-1", ttl_seconds=60, nonce=nonce,
                       action_binding=PermissionVerifier.bind_action(aid, cmd, params)
                       ).to_dict()
def rq(aid, cmd, p, g):
    return {"op": "execute", "actuator_id": aid, "command": cmd, "params": p, "grant": g}


print("== unarmed governor measures nothing, and SAYS so ==")
g0 = BlastRadiusGovernor()
ok(g0.is_armed() is False, "a governor with no policy reports is_armed()==False")
ok(g0.observe("anything").permitted,
   "and it permits — so a clean record from an unarmed governor is not evidence")
g1 = BlastRadiusGovernor(BreadthPolicy(window_seconds=60))
ok(g1.is_armed() is False, "a policy with every ceiling unset is still UNARMED")

print("== one capability driven hard is NOT spread ==")
gov = BlastRadiusGovernor(BreadthPolicy(window_seconds=60, max_distinct_capabilities=5))
for i in range(200):
    r = gov.observe("arm_1", [Effect.PHYSICAL_FORCE])
ok(r.permitted, "200 uses of ONE capability stays within a breadth ceiling of 5")
ok(r.distinct_capabilities == 1, "and breadth is correctly measured as 1")

print("== THE INCIDENT SHAPE: many DISTINCT capabilities in one window ==")
gov = BlastRadiusGovernor(BreadthPolicy(window_seconds=60, max_distinct_capabilities=5))
verdicts = [gov.observe(f"host_{i}_exec", [Effect.NONE]) for i in range(12)]
ok(verdicts[4].permitted, "the first few distinct capabilities are unremarkable")
ok(not verdicts[-1].permitted,
   "spreading across many DECLARED capabilities is caught. NOTE: this is spread by an "
   "attacker who still has to ask the wall. An escaped process moving at the OS level "
   "never calls observe() at all and is invisible here — see the module docstring")
ok(verdicts[-1].verdict is BreadthVerdict.REVIEW_REQUIRED,
   "and it is a REVIEW hold, not a permanent block — a human decides")
ok(str(verdicts[-1].distinct_capabilities) in verdicts[-1].reason
   and "5" in verdicts[-1].reason,
   "the reason names the observed number AND the ceiling — legible, not a verdict to trust")

print("== breadth of CONSEQUENCE is separately measurable ==")
gov = BlastRadiusGovernor(BreadthPolicy(window_seconds=60, max_distinct_effects=2))
gov.observe("a", [Effect.NONE]); gov.observe("b", [Effect.PHYSICAL_FORCE])
r = gov.observe("c", [Effect.DATA_EGRESS])
ok(not r.permitted and r.distinct_effects == 3,
   "touching 3 distinct effect classes crosses a consequence-breadth ceiling of 2")

print("== novelty: reaching for many never-used capabilities at once ==")
gov = BlastRadiusGovernor(BreadthPolicy(window_seconds=60, max_novel_capabilities=3))
rs = [gov.observe(f"never_used_{i}") for i in range(6)]
ok(not rs[-1].permitted, "many first-ever capability uses in one window is caught")

print("== the window slides: yesterday's breadth is not today's ==")
clock = {"t": 1000.0}
gov = BlastRadiusGovernor(BreadthPolicy(window_seconds=10, max_distinct_capabilities=3),
                          clock=lambda: clock["t"])
for i in range(3):
    gov.observe(f"cap_{i}")
clock["t"] += 100                      # long past the window
r = gov.observe("cap_new")
ok(r.permitted and r.distinct_capabilities == 1,
   "events outside the window are pruned — a long-running robot is not slowly strangled")

print("== fail closed on internal error ==")
class _Boom(BlastRadiusGovernor):
    def _prune(self, now): raise RuntimeError("governor exploded")
gb = _Boom(BreadthPolicy(window_seconds=60, max_distinct_capabilities=2))
r = gb.observe("x")
ok(r.verdict is BreadthVerdict.ERROR and not r.permitted,
   "a governor that cannot evaluate REFUSES, never falls through")

print("== wired into the wall: breadth is enforced at the actuation choke point ==")
v = PermissionVerifier(); v.register_key("operator", KEY, unrestricted=True)
b = ActuationBroker(SOCK, v, enforce_effects=True,
                    blast_radius=BlastRadiusGovernor(
                        BreadthPolicy(window_seconds=60, max_distinct_capabilities=3)))
ran = []
for i in range(6):
    b.register_actuator(f"node_{i}", lambda **k: ran.append(1) or "ok",
                        required_scope=(f"n{i}:x",), effects=[Effect.NONE],
                        effect_declared_by="justin")
results = [b._handle(rq(f"node_{i}", "run", {},
                        grant(v, f"node_{i}", "run", {}, f"b{i}", (f"n{i}:x",))))
           for i in range(6)]
ok(results[0].get("ok") is True, "the first capabilities actuate normally")
ok(results[-1].get("ok") is False and
   results[-1].get("error_code") == "BLAST_RADIUS_REVIEW_REQUIRED",
   "spreading across distinct capabilities is HELD at the wall")
ok(len(ran) < 6, "and the later actuations did NOT run")
ok(b.is_blast_radius_gated() is True, "the wall reports that breadth gating is armed")

print("== POSTURE EVENTS: a disabled layer is an EVENT, not a silent default (§I3) ==")
bare = ActuationBroker(SOCK, v)          # everything off, the convenient default
events = bare.posture_events()
layers = {e["layer"] for e in events}
ok("effect_gate" in layers and "blast_radius" in layers and "breach_gate" in layers,
   "every safety layer that is OFF is recorded at construction")
ok(all(e["state"] == "DISABLED" and e["consequence"] for e in events),
   "each records the CONCRETE consequence of being off, not just a flag name")
ok(any("undeclared actuators can actuate" in e["consequence"] for e in events),
   "e.g. the effect gate being off states plainly what that permits")
hardened = ActuationBroker(SOCK, v, enforce_effects=True, actuator_timeout=5.0,
                           blast_radius=BlastRadiusGovernor(
                               BreadthPolicy(window_seconds=60,
                                             max_distinct_capabilities=3)),
                           posture_source=lambda: True,
                           ledger_hook=lambda a, c, p: None)
hard_layers = {e["layer"] for e in hardened.posture_events()}
ok("effect_gate" not in hard_layers and "blast_radius" not in hard_layers
   and "cumulative_ledger" not in hard_layers,
   "a hardened broker reports those layers as no longer disabled")

print("== measurements are visible ==")
m = gov.measurements()
ok("armed" in m and m["observed"] > 0,
   "the governor exposes armed state and what it has observed")

print(f"\nALL {passed} CHECKS PASSED")
