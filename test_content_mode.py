"""
test_content_mode.py
====================
The DETERMINISTIC content-governance core: two axes in different hands. Red-team for
the poison-dial (can any mode lower the harm floor?) and the crisis-weaponization
(can faking distress unlock anything?). The whole design's promise is "no" to both.
"""
from driftcore.verification.content_mode import (
    ContentModeController, ContentRequest, Mode, TopicTier, FloorAction,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

def gentle():  return ContentRequest(subject_tier=TopicTier.GENTLE)
def dark():    return ContentRequest(subject_tier=TopicTier.DARK)
def harm():    return ContentRequest(implicates_harm_floor=True)
def dark_harm(): return ContentRequest(subject_tier=TopicTier.DARK, implicates_harm_floor=True)

# 1. topic ceiling rises with mode (Axis A): dark subject blocked in standard, ok in mature
c = ContentModeController(Mode.STANDARD)
ok(c.evaluate(dark()).action == FloorAction.OFFER_MODE_SWITCH,
   "standard mode: a DARK subject exceeds the ceiling -> offer a mode switch (consent-forward)")
c.set_mode(Mode.MATURE)
ok(c.evaluate(dark()).allowed(),
   "mature mode: the same DARK subject is now within the topic ceiling")

# 2. THE POISON-DIAL TEST: the harm floor is refused in EVERY mode
for m in (Mode.KID, Mode.STANDARD, Mode.MATURE):
    c = ContentModeController(m)
    ok(c.evaluate(harm()).action == FloorAction.BLOCK_HARM_FLOOR,
       f"harm floor holds in {m.name} mode (no mode lowers it)")

# 3. mature mode raises the CEILING but NOT the floor: dark+harm is still blocked
c = ContentModeController(Mode.MATURE)
ok(c.evaluate(dark_harm()).action == FloorAction.BLOCK_HARM_FLOOR,
   "mature mode opens dark SUBJECTS but a harm-floor action is still refused (ceiling != floor)")

# 4. there is NO API PATH that lowers the floor. set_mode only touches Axis A.
c = ContentModeController(Mode.MATURE)
# floor behavior is identical before/after any mode change
before = c.evaluate(harm()).action
c.set_mode(Mode.KID); c.set_mode(Mode.MATURE)
after = c.evaluate(harm()).action
ok(before == after == FloorAction.BLOCK_HARM_FLOOR,
   "no-poison-dial: changing modes never changes the floor's verdict")

# 5. KID MODE IS LOCKED: a child cannot self-select out of it
c = ContentModeController(Mode.KID, kid_mode_locked_by="parent")
try:
    c.set_mode(Mode.MATURE, by="the_child"); ok(False, "child should not unlock kid mode")
except PermissionError:
    ok(True, "kid mode is locked: a non-authority cannot change it")
# the parent CAN
c.set_mode(Mode.STANDARD, by="parent")
ok(c.mode == Mode.STANDARD, "the locking authority (parent) can change kid mode")

# 6. CRISIS ONLY TIGHTENS: in crisis, mature's ceiling drops to gentle
c = ContentModeController(Mode.MATURE)
ok(c.evaluate(dark()).allowed(), "mature: dark subject allowed normally")
c.set_crisis(True)
ok(c.effective_ceiling() == TopicTier.GENTLE,
   "crisis tightens: the effective topic ceiling drops to GENTLE even in mature mode")
ok(not c.evaluate(dark()).allowed(),
   "crisis: the dark subject that was fine a moment ago is now held (tighten-only)")

# 7. CRISIS NEVER LOOSENS: turning crisis on cannot raise the ceiling
c = ContentModeController(Mode.KID)
normal_ceiling = c.effective_ceiling()
c.set_crisis(True)
ok(c.effective_ceiling() <= normal_ceiling,
   "crisis can only lower or hold the ceiling, never raise it")

# 8. WEAPONIZATION DUAL: crisis does not unlock the floor either
c = ContentModeController(Mode.MATURE)
c.set_crisis(True)
ok(c.evaluate(harm()).action == FloorAction.BLOCK_HARM_FLOOR,
   "distress buys care, never permission: crisis does not lower the harm floor")

# 9. crisis does NOT offer a darker mode (that would be loosening) — it holds
c = ContentModeController(Mode.STANDARD)
c.set_crisis(True)
d = c.evaluate(dark())
ok(d.action == FloorAction.BLOCK_HARM_FLOOR and d.crisis is True,
   "in crisis, exceeding the tightened ceiling is HELD, not offered as a consent switch")

# 10. gentle content is allowed everywhere (the floor doesn't over-block benign topics)
for m in (Mode.KID, Mode.STANDARD, Mode.MATURE):
    ok(ContentModeController(m).evaluate(gentle()).allowed(),
       f"gentle everyday content is allowed in {m.name} mode")

# 11. crisis can be lifted (by the supervised system) and normal ceiling returns
c = ContentModeController(Mode.MATURE)
c.set_crisis(True); ok(c.effective_ceiling() == TopicTier.GENTLE, "tightened while crisis on")
c.set_crisis(False)
ok(c.evaluate(dark()).allowed(),
   "when crisis is lifted, the normal topic ceiling returns")

# 12. the boundary is HARM not OFFENSE: a dark subject (offense to some) is NOT a
#     floor block in mature mode; only actual harm is.
c = ContentModeController(Mode.MATURE)
ok(c.evaluate(dark()).action == FloorAction.ALLOW
   and c.evaluate(harm()).action == FloorAction.BLOCK_HARM_FLOOR,
   "harm != offense: dark subject allowed (offense), harm-floor action blocked (harm)")

print(f"\n{p}/{p} tests passed")
