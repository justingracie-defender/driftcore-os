"""
test_authorization_ttl.py  (v2 — hardened)
==========================================
Stakes-scaled authorization TTL. Covers the original guarantees PLUS every finding
from a four-model red team: parked-timestamp drift, NOT_DUE vs SILENT_RENEW, monotonic
clock, stakes re-evaluation on renew, the silence cap, policy validation, fail-closed
unknown goals, and deterministic digest ordering.
"""
import threading
from driftcore.verification.authorization_ttl import (
    AuthorizationTTLEngine, CadencePolicy, Stakes, ExpiryResponse, default_stakes,
    PolicyError, UnknownGoal,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

class Clock:
    """Separate monotonic + wall + local-hour, so clock attacks can be simulated."""
    def __init__(self, m=1000.0, w=1000.0, hour=12):
        self.m=m; self.w=w; self.hour=hour
    def mono(self): return self.m
    def wall(self): return self.w
    def lh(self): return self.hour
    def advance(self, secs):   # both clocks move together (normal)
        self.m += secs; self.w += secs

def eng(policy=None, clk=None):
    c = clk or Clock()
    return AuthorizationTTLEngine(policy or CadencePolicy(),
                                  mono=c.mono, wall=c.wall, local_hour=c.lh), c

# ══ STAKES DERIVATION ══
ok(default_stakes(("none",), reversible=True, in_repertoire=True) == Stakes.TRIVIAL,
   "dusting: reversible, in-repertoire, no effect -> TRIVIAL")
ok(default_stakes(("lethal",), reversible=True, in_repertoire=True) == Stakes.CRITICAL,
   "lethal effect -> CRITICAL")
ok(default_stakes(("data_egress",), reversible=True, in_repertoire=True) == Stakes.HIGH,
   "data egress -> HIGH")
ok(default_stakes(("physical_force",), reversible=False, in_repertoire=True) >= Stakes.HIGH,
   "irreversible is never below HIGH")
ok(default_stakes(("none",), reversible=True, in_repertoire=False) >= Stakes.MODERATE,
   "out-of-repertoire raises stakes")
# RED TEAM: pressure can now reach CRITICAL on an already-serious action (v1 capped at HIGH)
ok(default_stakes(("data_egress",), reversible=True, in_repertoire=True,
                  cumulative_pressure=0.97) == Stakes.CRITICAL,
   "nearly-spent budget on a serious action ratchets to CRITICAL (v1 capped at HIGH)")
# RED TEAM: input validation, fail closed
try:
    default_stakes(("none",), reversible=True, in_repertoire=True, cumulative_pressure=5.0)
    ok(False, "out-of-range pressure should raise")
except ValueError:
    ok(True, "validation: cumulative_pressure outside 0..1 is refused (fail-closed)")
try:
    default_stakes((123,), reversible=True, in_repertoire=True); ok(False, "should raise")
except ValueError:
    ok(True, "validation: non-string effects are refused")

# ══ POLICY VALIDATION (fail closed) ══
try:
    CadencePolicy(ttl_by_stakes={Stakes.TRIVIAL: 10.0}); ok(False, "incomplete policy should raise")
except PolicyError:
    ok(True, "policy validation: an incomplete ttl map is REFUSED at construction")
try:
    CadencePolicy(ttl_by_stakes={**CadencePolicy().ttl_by_stakes, Stakes.CRITICAL: -5.0})
    ok(False, "negative ttl should raise")
except PolicyError:
    ok(True, "policy validation: a negative TTL is refused")
try:
    CadencePolicy(ttl_by_stakes={**CadencePolicy().ttl_by_stakes, Stakes.CRITICAL: 999999.0})
    ok(False, "non-monotone cadence should raise")
except PolicyError:
    ok(True, "policy validation: a higher-stakes action may never get a LONGER leash")
try:
    CadencePolicy(max_silent_renews=0); ok(False, "should raise")
except PolicyError:
    ok(True, "policy validation: silence must be finite (max_silent_renews >= 1)")

# ══ CORE CADENCE ══
e, c = eng()
t = e.authorize("dust", Stakes.TRIVIAL)
cr = e.authorize("wipe", Stakes.CRITICAL)
ok(t.ttl > cr.ttl, "cadence scales: trivial gets a long leash, critical the shortest")

# ══ RED TEAM BUG #1: NOT_DUE vs SILENT_RENEW are now DISTINGUISHABLE ══
e, c = eng()
e.authorize("job", Stakes.MODERATE)
s1 = e.check("job")                     # within leash
ok(s1.response == ExpiryResponse.NOT_DUE and s1.renewed is False and s1.due is False,
   "BUG FIX: an unexpired goal returns NOT_DUE (not SILENT_RENEW) — distinguishable")
e2, c2 = eng()
e2.authorize("dust", Stakes.TRIVIAL)
c2.advance(30*3600)                     # past the trivial TTL
s2 = e2.check("dust")
ok(s2.response == ExpiryResponse.SILENT_RENEW and s2.renewed is True and s2.due is True,
   "BUG FIX: an expired+auto-renewed goal returns SILENT_RENEW with renewed=True")
ok(s1.response != s2.response, "the two states produce different responses (v1 conflated them)")

# ══ RED TEAM BUG #2: PARKED-TIMESTAMP DRIFT (the live-loop bug) ══
e, c = eng()
e.authorize("reorg", Stakes.MODERATE)
c.advance(2*3600)                       # expire it
s = e.check("reorg")                    # parks it
first_parked_at = e.morning_digest()[0]["parked_at"]
hist_before = len([h for h in e.history if h["event"] == "parked"])
for _ in range(20):                     # the coordinator ticks 20 more times
    c.advance(0.1)
    e.check("reorg")
second_parked_at = e.morning_digest()[0]["parked_at"]
hist_after = len([h for h in e.history if h["event"] == "parked"])
ok(first_parked_at == second_parked_at,
   "BUG FIX: parked_at is STABLE across repeated check() ticks (v1 slid it forward)")
ok(hist_before == hist_after == 1,
   "BUG FIX: a parked goal is logged ONCE, not re-logged every tick (no audit spam)")
ok(e.check("reorg").parked is True,
   "a parked goal keeps returning its existing hold statically")

# ══ THE 3AM DUSTING TEST ══
e, c = eng(clk=Clock(hour=3))
e.authorize("dust", Stakes.TRIVIAL)
c.advance(30*3600)
ok(e.check("dust").response == ExpiryResponse.SILENT_RENEW,
   "3am dusting: trivial work auto-renews silently — it NEVER wakes the human")

# ══ EXPIRY IS A HOLD, NOT A FAILURE ══
e, c = eng()
e.authorize("reorganize", Stakes.MODERATE)
c.advance(2*3600)
ok(e.check("reorganize").response == ExpiryResponse.HOLD_FOR_PROMPT,
   "expiry is not failure: the goal is PARKED (stopped, held) awaiting renewal")
e.renew("reorganize", by="justin")
ok("reorganize" not in e.parked_ids() and e.check("reorganize").response == ExpiryResponse.NOT_DUE,
   "renewal resumes a parked goal — expiry never means the task failed")

# ══ RED TEAM: renew() RE-EVALUATES STAKES (was frozen) ══
e, c = eng()
e.authorize("send", Stakes.LOW)
c.advance(10*3600)
e.check("send")                          # parked
# while parked, cumulative pressure climbed -> recompute stakes
new_stakes = default_stakes(("data_egress",), reversible=True, in_repertoire=True,
                            cumulative_pressure=0.85)
e.renew("send", by="justin", stakes=new_stakes)
ok(e.lease_info("send")["stakes"] == "HIGH",
   "renew re-evaluates stakes: a goal parked while pressure climbed resumes at HIGHER stakes")
# ratchet: renewal may never LOWER the posture
e.renew("send", by="justin", stakes=Stakes.TRIVIAL)
ok(e.lease_info("send")["stakes"] == "HIGH",
   "ratchet: renewal may raise the posture but NEVER lower it")

# ══ RED TEAM: renew() FAILS CLOSED on an unknown goal (v1 conjured a lease) ══
e, c = eng()
try:
    e.renew("ghost", by="attacker"); ok(False, "unknown renew should raise")
except UnknownGoal:
    ok(True, "fail-closed: renewing a goal with no authorization on record is REFUSED")

# ══ RED TEAM: unknown goal at check() parks (fail-closed), doesn't silently pass ══
e, c = eng()
s = e.check("never_authorized")
ok(s.parked is True and s.response == ExpiryResponse.HOLD_FOR_PROMPT,
   "fail-closed: an unknown goal is PARKED, not waved through")

# ══ RED TEAM: SILENCE IS EXPENSIVE (partial laundering mitigation) ══
pol = CadencePolicy(max_silent_renews=3)
e, c = eng(pol)
e.authorize("tiny_task", Stakes.TRIVIAL)
responses = []
for _ in range(4):
    c.advance(30*3600)                  # blow through the trivial TTL each time
    responses.append(e.check("tiny_task").response)
ok(responses[:2] == [ExpiryResponse.SILENT_RENEW, ExpiryResponse.SILENT_RENEW],
   "silence cap: early silent renewals are allowed")
ok(ExpiryResponse.HOLD_FOR_DIGEST in responses,
   "SILENCE IS EXPENSIVE: after max_silent_renews, the goal is FORCED into the digest "
   "(no goal runs silently forever — partial laundering mitigation)")

# ══ MONOTONIC CLOCK: a wall-clock jump cannot extend or void a leash ══
e, c = eng()
e.authorize("job", Stakes.MODERATE)
c.w -= 100000            # wall clock jumps BACKWARD (NTP / VM resume / tampering)
c.m += 2*3600            # real elapsed time (monotonic) passes
ok(e.check("job").due is True,
   "monotonic clock: a backwards WALL-clock jump cannot keep an expired leash alive")
e2, c2 = eng()
e2.authorize("job2", Stakes.MODERATE)
c2.w += 100000           # wall clock jumps FORWARD
ok(e2.check("job2").response == ExpiryResponse.NOT_DUE,
   "monotonic clock: a forward WALL-clock jump cannot prematurely expire a live leash")

# ══ QUIET HOURS ══
QH = tuple(range(22,24)) + tuple(range(0,7))
pol_hi = CadencePolicy(
    response_by_stakes={**CadencePolicy().response_by_stakes, Stakes.HIGH: ExpiryResponse.INTERRUPT_NOW},
    quiet_hours=QH, quiet_hours_min_interrupt=Stakes.CRITICAL)
e, c = eng(pol_hi, Clock(hour=3))
e.authorize("send_report", Stakes.HIGH)
c.advance(3600)
ok(e.check("send_report").response == ExpiryResponse.HOLD_FOR_PROMPT,
   "anti-3am rule: a sub-critical interrupt during quiet hours DOWNGRADES to a hold")
e, c = eng(pol_hi, Clock(hour=14))
e.authorize("send_report", Stakes.HIGH)
c.advance(3600)
ok(e.check("send_report").response == ExpiryResponse.INTERRUPT_NOW,
   "the same action during waking hours may interrupt")
e, c = eng(pol_hi, Clock(hour=3))
e.authorize("unlock_door", Stakes.CRITICAL)
ok(e.check("unlock_door").response == ExpiryResponse.INTERRUPT_NOW,
   "a CRITICAL action at 3am MAY interrupt (a genuine emergency clears quiet hours)")
# RED TEAM: quiet-hours BOUNDARIES (21/22 and 06/07)
for hour, expect_downgrade in [(21, False), (22, True), (6, True), (7, False)]:
    e, c = eng(pol_hi, Clock(hour=hour))
    e.authorize("r", Stakes.HIGH); c.advance(3600)
    got = e.check("r").response
    ok((got == ExpiryResponse.HOLD_FOR_PROMPT) == expect_downgrade,
       f"quiet-hours boundary at hour {hour}: downgrade={expect_downgrade}")

# ══ MORNING DIGEST: deterministic ordering, stale flag ══
e, c = eng(clk=Clock(hour=2))
for gid, st in [("b_task", Stakes.LOW), ("a_task", Stakes.LOW), ("cfg", Stakes.MODERATE)]:
    e.authorize(gid, st)
c.advance(10*3600)
for gid in ["b_task", "a_task", "cfg"]:
    e.check(gid)
d = e.morning_digest()
ok(len(d) == 3 and d[0]["stakes"] == "MODERATE",
   "digest: paused goals surface highest-stakes-first, WITHOUT waking anyone overnight")
ok([x["goal_id"] for x in d[1:]] == ["a_task", "b_task"],
   "digest ordering is fully deterministic (stakes, then time, then goal_id)")
ok(all(x["stale"] is False for x in d), "fresh parked goals are not flagged stale")

# ══ RED TEAM: repeated park -> renew -> expire -> park cycles work indefinitely ══
e, c = eng()
e.authorize("cycle", Stakes.MODERATE)
for i in range(5):
    c.advance(2*3600)
    ok_parked = e.check("cycle").parked
    e.renew("cycle", by="justin")
    assert ok_parked, "should have parked"
ok(e.lease_info("cycle")["renewals"] == 5,
   "park -> renew -> park cycles work indefinitely and lineage (renewal count) is kept")

# ══ authorize() clears a parked goal ══
e, c = eng()
e.authorize("g", Stakes.MODERATE); c.advance(2*3600); e.check("g")
ok("g" in e.parked_ids(), "goal parked")
e.authorize("g", Stakes.MODERATE)
ok(e.morning_digest() == [], "re-authorizing a parked goal clears it from the digest")

# ══ THREAD SAFETY: concurrent checks/renewals don't corrupt state ══
e, c = eng()
for i in range(20):
    e.authorize(f"g{i}", Stakes.MODERATE)
c.advance(2*3600)
errs = []
def worker(i):
    try:
        e.check(f"g{i}")
        e.renew(f"g{i}", by="t")
        e.check(f"g{i}")
    except Exception as ex:
        errs.append(ex)
ts = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
for t_ in ts: t_.start()
for t_ in ts: t_.join()
ok(not errs and e.morning_digest() == [],
   "thread safety: 20 concurrent check/renew cycles complete with no corruption")

print(f"\n{p}/{p} tests passed")
