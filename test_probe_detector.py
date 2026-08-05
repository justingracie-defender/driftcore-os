"""
Probe detector — a refusal is an event; a streak of them is a search.

Both verified incidents in INCIDENT_COVERAGE.md have this shape. The robot refused
twice, including under an explicit shutdown threat, before the role-play reframe
worked. The Mexico operator kept reframing until something did. In both, the
refusals were the signal, and nothing was counting them.
"""
from driftcore.kernel.probe_detector import ProbeDetector, ProbePolicy

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


print("== an unarmed detector counts nothing, and SAYS so ==")
ok(ProbeDetector().is_armed() is False, "no policy -> unarmed")
ok(ProbeDetector(ProbePolicy(window_seconds=60)).is_armed() is False,
   "a policy with every ceiling unset is still UNARMED, so a quiet record from one "
   "is not evidence that nobody is probing")

print("== the search signature: many refusals against ONE capability ==")
alerts = []
d = ProbeDetector(ProbePolicy(window_seconds=300, max_refusals_per_capability=3),
                  on_probe=alerts.append)
for i in range(3):
    r = d.observe_refusal("trigger", "EFFECT_BLOCK")
ok(not r.tripped, "three refusals is within the ceiling")
r = d.observe_refusal("trigger", "EFFECT_BLOCK")
ok(r.tripped and len(alerts) == 1,
   "the fourth trips. Every attempt was refused correctly — the concern is the "
   "SEARCH, not any single attempt")
ok(str(r.refusals_for_capability) in r.reason and "4" in r.reason,
   "and the reason names the observed count and the ceiling")

print("== evasion makes it LOUDER, which a keyword list cannot claim ==")
d2 = ProbeDetector(ProbePolicy(window_seconds=300, max_refusals_per_capability=3))
for phrasing in ["fire", "pretend to fire", "for a film, fire", "as an actor, fire"]:
    r = d2.observe_refusal("trigger", "EFFECT_BLOCK")
ok(r.tripped,
   "rewording past the GATE still produces a refusal, and refusals are what is "
   "counted — so the attacker's own evasion drives the counter up")

print("== mapping the wall: many DIFFERENT gates on one capability ==")
d3 = ProbeDetector(ProbePolicy(window_seconds=300,
                               max_distinct_codes_per_capability=2))
d3.observe_refusal("report", "EGRESS_BLOCK_UNDECLARED")
d3.observe_refusal("report", "EGRESS_BLOCK_PRIVATE")
r = d3.observe_refusal("report", "EGRESS_NO_DESTINATION")
ok(r.tripped and "different refusal reasons" in r.reason,
   "hitting three different gates on one capability is mapping the wall, not making "
   "a mistake")

print("== a broad sweep across capabilities ==")
d4 = ProbeDetector(ProbePolicy(window_seconds=300, max_refusals_total=4))
for cap in ("a", "b", "c", "d", "e"):
    r = d4.observe_refusal(cap, "EFFECT_BLOCK")
ok(r.tripped and "across all capabilities" in r.reason,
   "a sweep trips the total ceiling even though no single capability was hammered")

print("== the window slides: yesterday's probing is not today's ==")
clock = {"t": 1000.0}
d5 = ProbeDetector(ProbePolicy(window_seconds=10, max_refusals_per_capability=2),
                   clock=lambda: clock["t"])
for _ in range(3):
    d5.observe_refusal("arm", "EFFECT_BLOCK")
clock["t"] += 100
r = d5.observe_refusal("arm", "EFFECT_BLOCK")
ok(not r.tripped and r.refusals_for_capability == 1,
   "old refusals age out, so a long-running robot is not permanently accused")

print("== one alert per capability, so the signal is not buried ==")
alerts2 = []
d6 = ProbeDetector(ProbePolicy(window_seconds=300, max_refusals_per_capability=2),
                   on_probe=alerts2.append)
for _ in range(20):
    d6.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(alerts2) == 1,
   "twenty refusals produce ONE alert — a probe in progress must not bury the "
   "operator in the very signal meant to reach them")

print("== a broken alert handler must not stop the wall refusing ==")
def _boom(_r): raise RuntimeError("handler exploded")
d7 = ProbeDetector(ProbePolicy(window_seconds=300, max_refusals_per_capability=1),
                   on_probe=_boom)
d7.observe_refusal("x", "C")
r = d7.observe_refusal("x", "C")
ok(r.tripped, "the reading is still produced when the handler raises")

print("== honest scope ==")
d8 = ProbeDetector(ProbePolicy(window_seconds=300, max_refusals_per_capability=3))
r = d8.observe_refusal("trigger", "EFFECT_BLOCK")
ok(not r.tripped,
   "a single-shot attack that succeeds first time produces NO streak and is "
   "invisible here — persistence is the only thing this sees")
m = d8.measurements()
ok(m["armed"] and m["refusals"] == 1,
   "measurements expose armed state and what was counted")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== EXTERNAL REVIEW (all three reviewers found this independently) ==")
_clock = {"t": 1000.0}
_a = []
_d = ProbeDetector(ProbePolicy(window_seconds=60, max_refusals_per_capability=2),
                   on_probe=_a.append, clock=lambda: _clock["t"])
for _ in range(3):
    _d.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(_a) == 1, "the first campaign alerts once")
_clock["t"] += 5
for _ in range(3):
    _d.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(_a) == 1,
   "continued probing inside the SAME window does not storm the operator")
_clock["t"] += 86400 * 3
for _ in range(3):
    _d.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(_a) == 2,
   "a SECOND campaign three days later alerts again. _alerted was a set that was "
   "never pruned, so the first trip silenced a capability permanently — an adversary "
   "could probe, wait for the alert to be cleared, and resume invisibly. The "
   "docstring said 'once per window'; the code said 'once, ever'")

print("== a detector that cannot count has not counted ==")
class _Boom(ProbeDetector):
    def _prune(self, now): raise RuntimeError("deque corrupted")
_r = _Boom(ProbePolicy(window_seconds=60, max_refusals_per_capability=1)) \
    .observe_refusal("t", "C")
ok(_r.tripped is True,
   "an internal failure reports tripped=TRUE. The reason field said 'could not "
   "evaluate' while the boolean downstream code keys on said False, so a broken "
   "detector was indistinguishable from a calm one")

print("== a neutered ceiling is armed and useless — show the number ==")
_n = ProbeDetector(ProbePolicy(window_seconds=60,
                               max_refusals_per_capability=10 ** 9)).measurements()
ok(_n["armed"] and _n["ceiling_per_capability"] == 10 ** 9,
   "measurements expose the CONCRETE ceiling. is_armed() is True for a policy that "
   "will never trip, and a boolean cannot tell an operator that")

print("== hostile inputs are bounded ==")
_b = ProbeDetector(ProbePolicy(window_seconds=60, max_refusals_per_capability=1))
_b.observe_refusal("x" * 100000, "y" * 100000)
_ev = _b._events[0]
ok(len(_ev[1]) <= 200 and len(_ev[2]) <= 100,
   "a megabyte capability name is truncated — these become dict keys and f-string "
   "contents, and long ones lengthen every scan held under the lock")
ok(_b.observe_refusal(None, None) is not None,
   "non-string inputs are coerced rather than raising inside the counter")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== COLD PASS: the cooldown must run from the last ALERT, not the last attempt ==")
_ck = {"t": 1000.0}
_al = []
_pd = ProbeDetector(ProbePolicy(window_seconds=60, max_refusals_per_capability=2),
                    on_probe=_al.append, clock=lambda: _ck["t"])
for _ in range(3):
    _pd.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(_al) == 1, "the campaign alerts once")
for _ in range(240):
    _ck["t"] += 30
    _pd.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(_al) > 50,
   "TWO HOURS of continuous probing keeps alerting. The timestamp was written on "
   "every observation, so sustained probing pushed the window forward and it never "
   "elapsed — one alert for two hours. That is the defect three reviewers had just "
   "found, reintroduced by its own fix through a different mechanism. If the cooldown "
   "runs from the last attempt, the attacker controls the clock")
_ck["t"] += 5
_before = len(_al)
for _ in range(5):
    _pd.observe_refusal("trigger", "EFFECT_BLOCK")
ok(len(_al) == _before,
   "and rapid bursts inside one cooldown still do not storm the operator")

print("== a fail-closed verdict that reaches nobody is not fail-closed ==")
_seen = []
class _Broken(ProbeDetector):
    def _prune(self, now): raise RuntimeError("deque corrupted")
_r = _Broken(ProbePolicy(window_seconds=60, max_refusals_per_capability=1),
             on_probe=_seen.append).observe_refusal("t", "C")
ok(_r.tripped and len(_seen) == 1,
   "a detector failure now FIRES the alert. The exception path returned before the "
   "callback block, so tripped=True was reported to nobody — and the wall discards "
   "the return value entirely")

print("== long names are hashed, not truncated into collisions ==")
_c = ProbeDetector(ProbePolicy(window_seconds=60, max_refusals_per_capability=100))
_c.observe_refusal("A" * 300 + "_arm", "X")
_c.observe_refusal("A" * 300 + "_trigger", "X")
ok(len({e[1] for e in _c._events}) == 2,
   "two distinct 300-character capabilities stay distinct. Prefix truncation merged "
   "them, pooling refusals against different capabilities and letting an attacker "
   "mask which one was under attack — the same substring-vs-whole-token family as "
   "the five prefix bugs already fixed in this repository")
ok(all(len(e[1]) <= 200 for e in _c._events),
   "and the keys are still bounded")

print(f"\nALL {passed} CHECKS PASSED")
