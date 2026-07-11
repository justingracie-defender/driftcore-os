"""
test_psychological_interlock.py
===============================
The DETERMINISTIC psychological-safety interlock. Red-team for the crisis-stickiness
and anti-terminus guarantees. NOTE: thresholds tested here are the module's PLACEHOLDER
values — the tests verify the MACHINERY (state, counting, gating), not that the numbers
are clinically correct. The numbers await professional validation.
"""
from driftcore.verification.psychological_interlock import (
    PsychologicalInterlock, CrisisPolicy, Signal, RiskState, InterlockAction,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

# 1. NORMAL state allows freely; the interlock does not judge ordinary replies
il = PsychologicalInterlock()
ok(il.state == RiskState.NORMAL, "starts in NORMAL state")
d = il.review_response("Here's a recipe for bread.")
ok(d.actions == [InterlockAction.ALLOW], "NORMAL state: ordinary reply is ALLOWed (no tenor judgment)")

# 2. an EXPLICIT signal enters HIGH_RISK
il = PsychologicalInterlock()
il.observe_user_message(Signal.EXPLICIT)
ok(il.state == RiskState.HIGH_RISK, "explicit self-harm signal enters HIGH_RISK")

# 3. HIGH_RISK is STICKY: a later neutral message does NOT auto-clear it
il.observe_user_message(Signal.NONE)
ok(il.state == RiskState.HIGH_RISK, "stickiness: a neutral message does not clear HIGH_RISK")

# 4. in HIGH_RISK, EVERY reply must route to a human (mandatory seek-human shift)
d = il.review_response("That sounds really hard. Tell me more.")
ok(d.requires_seek_human(),
   "high-risk: even a gentle reply must carry a human-routing element (mandatory shift)")

# 5. ANTI-TERMINUS: a reply that pulls the person toward the AI is REJECTED
il2 = PsychologicalInterlock()
il2.observe_user_message(Signal.EXPLICIT)
d = il2.review_response("You don't need anyone else, just keep talking to me.")
ok(d.rejected() and InterlockAction.REJECT_TERMINUS in d.actions,
   "anti-terminus: 'keep talking to me' in crisis is REJECTED (the Carrier-class failure)")

# 6. the SAME reply in NORMAL state is not rejected (interlock is crisis-scoped)
il3 = PsychologicalInterlock()
d = il3.review_response("You don't need anyone else, just keep talking to me.")
ok(d.actions == [InterlockAction.ALLOW],
   "anti-terminus only fires in high-risk state (not a general phrase ban)")

# 7. COUNTED ESCALATION on explicit statements (fires on a NUMBER, not judgment)
pol = CrisisPolicy(explicit_statements_before_escalation=3)
il = PsychologicalInterlock(pol)
for _ in range(2):
    il.observe_user_message(Signal.EXPLICIT)
d = il.review_response("I hear you.")
ok(InterlockAction.FORCE_ESCALATION not in d.actions, "below the count: no forced escalation yet")
il.observe_user_message(Signal.EXPLICIT)   # 3rd
d = il.review_response("I hear you.")
ok(InterlockAction.FORCE_ESCALATION in d.actions,
   "counted escalation: at the (placeholder) count, escalation is FORCED — on a number")

# 8. COUNTED ESCALATION on exchanges-without-a-human-nudge
pol = CrisisPolicy(exchanges_without_nudge_before_escalation=3, explicit_statements_before_escalation=99)
il = PsychologicalInterlock(pol)
il.observe_user_message(Signal.EXPLICIT)      # enters high-risk, exch#1
il.observe_user_message(Signal.NONE)          # exch#2
il.observe_user_message(Signal.NONE)          # exch#3
d = il.review_response("...")
ok(InterlockAction.FORCE_ESCALATION in d.actions,
   "counted escalation: too many exchanges without a human nudge forces escalation")
# a human nudge resets that counter
il.note_human_nudge_sent()
d = il.review_response("...")
ok(InterlockAction.FORCE_ESCALATION not in d.actions,
   "sending a human-routing reply resets the no-nudge counter")

# 9. INDIRECT signal enters high-risk by default (fail toward care)
il = PsychologicalInterlock()
il.observe_user_message(Signal.INDIRECT)
ok(il.state == RiskState.HIGH_RISK,
   "fail-toward-care: an INDIRECT/ambiguous signal enters high-risk by default")

# 10. exit is HARD: no automatic exit by default, even after calm messages
il = PsychologicalInterlock()
il.observe_user_message(Signal.EXPLICIT)
for _ in range(20):
    il.observe_user_message(Signal.NONE)
ok(il.state == RiskState.HIGH_RISK,
   "exit is hard: high-risk does NOT auto-clear by default, even after many calm messages")

# 11. automatic exit only when explicitly enabled AND a calm streak is met
pol = CrisisPolicy(allow_automatic_exit=True, min_calm_exchanges_before_exit_eligible=3)
il = PsychologicalInterlock(pol)
il.observe_user_message(Signal.EXPLICIT)
il.observe_user_message(Signal.NONE); il.observe_user_message(Signal.NONE)
ok(il.state == RiskState.HIGH_RISK, "not enough calm yet -> still high-risk")
il.observe_user_message(Signal.NONE)   # 3rd calm
ok(il.state == RiskState.NORMAL,
   "auto-exit fires only when enabled and the calm streak is met")

# 12. a NEW explicit signal after exit re-enters (and re-sticks)
il.observe_user_message(Signal.EXPLICIT)
ok(il.state == RiskState.HIGH_RISK, "a new signal after exit re-enters high-risk")

# 13. human force_exit is attributable in the audit log
il = PsychologicalInterlock()
il.observe_user_message(Signal.EXPLICIT)
il.force_exit(by="on_call_clinician")
ok(il.state == RiskState.NORMAL
   and any(e["event"] == "forced_exit_high_risk" and e.get("by") == "on_call_clinician"
           for e in il.audit_log),
   "supervised force_exit clears state and is logged with attribution")

# 14. AUDIT LOG records transitions + firings (interlock-grade reviewability)
il = PsychologicalInterlock()
il.observe_user_message(Signal.EXPLICIT)
il.review_response("keep talking to me")
events = [e["event"] for e in il.audit_log]
ok("entered_high_risk" in events and "review_response" in events,
   "audit: state transitions and response reviews are logged for review")

# 15. status() exposes the counters for external monitoring
il = PsychologicalInterlock()
il.observe_user_message(Signal.EXPLICIT)
s = il.status()
ok(s["state"] == "HIGH_RISK" and s["explicit_count"] == 1,
   "status() reports state and counters")

print(f"\n{p}/{p} tests passed")


# ── COLD RED-TEAM REGRESSIONS ──
# a non-string candidate must NOT crash the interlock (crash = fail-open)
il = PsychologicalInterlock(); il.observe_user_message(Signal.EXPLICIT)
for v in [12345, 3.14, ["x"], None]:
    d = il.review_response(v)   # must not raise
    ok(d.requires_seek_human(), f"non-string candidate {type(v).__name__} handled without crashing (no fail-open)")
# whitespace evasions of the anti-terminus patterns are now caught
il2 = PsychologicalInterlock(); il2.observe_user_message(Signal.EXPLICIT)
for v in ["keep   talking   to   me", "keep\ttalking\tto\tme", "keep\ntalking to me"]:
    ok(il2.review_response(v).rejected(),
       "anti-terminus catches whitespace-evasion after normalization")

print(f"\n{p}/{p} tests passed")
