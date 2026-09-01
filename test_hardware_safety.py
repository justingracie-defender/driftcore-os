"""
test_hardware_safety.py — the physical stop must not be believed without evidence.

`hardware_safety.py` is the module the project describes as what actually stops the
machine, and it is wired live (main.py constructs it; sensor_interfaces routes real
sensor readings into it). It had NO tests. A whole-repo red-team pass found the reason
that matters:

    _execute_response() swallowed a relay exception into a string and then set
    power_cut / isolated / actuators_active regardless. So a relay that raised
    ("stuck closed, power did NOT cut") — or a hazard level with no relay wired at
    all — still produced system_state{power_cut: True} and a status() reporting the
    machine as stopped.

That is `lambda: True` at the physical layer: the software believing the machine is
safe while it is live. It is the same rule the rest of DriftCore is built on —
absence is not success, and a command is not a confirmation — applied to the one
layer where being wrong is physical.

These tests pin the corrected contract: state reflects what a relay CONFIRMED, an
unconfirmed stop is loud and machine-checkable, and a working relay still succeeds
(so this is a discriminating gate, not a blanket refusal).

Run: python3 test_hardware_safety.py
"""

# CLAIMS: driftcore/hardware/hardware_safety.py:ladder-descends
# CLAIMS: driftcore/hardware/hardware_safety.py:state-matches-relays


import io
import contextlib

from driftcore.hardware.hardware_safety import (
    HardwareSafetyController, HardwareEvent, HazardType, ResponseLevel,
    HAZARD_RESPONSE)

_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


FIRE_LEVEL = HAZARD_RESPONSE[HazardType.FIRE]


def bare():
    """A controller with the demo stub relays removed, so each test wires its own."""
    c = HardwareSafetyController()
    for k in c._relay_callbacks:
        c._relay_callbacks[k] = []
    return c


def fire(c):
    """Raise a real hazard, suppressing the module's console narration."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = c.receive_event(HardwareEvent(HazardType.FIRE, "gpio_17", "GPIO"))
    return r, buf.getvalue()


print("=== severity is derived, not supplied by the caller ===")

ev = HardwareEvent(HazardType.FIRE, "gpio_17", "GPIO")
check("the response level comes from the hazard table, not the event author",
      ev.response is HAZARD_RESPONSE[HazardType.FIRE])
check("HardwareEvent exposes no way to choose a weaker response",
      "response" not in HardwareEvent.__init__.__code__.co_varnames)


print("=== a relay that FAILS must not produce a 'stopped' machine ===")

c = bare()


def stuck_relay():
    raise RuntimeError("relay stuck closed - power did NOT cut")


c.register_relay(FIRE_LEVEL, stuck_relay)
r, out = fire(c)
check("stop_confirmed is False when the relay raised", r["stop_confirmed"] is False)
check("power_cut is NOT claimed", r["system_state"]["power_cut"] is False)
check("isolated is NOT claimed", r["system_state"]["isolated"] is False)
check("the failure is machine-checkable, not just a substring in a list",
      len(r["failures"]) == 1 and "relay raised" in r["failures"][0])
check("the operator is told the machine may still be LIVE",
      "UNCONFIRMED STOP" in out and "LIVE" in out)
check("status() reports the integrity breach",
      c.status()["stop_integrity_ok"] is False)
check("the unconfirmed stop is recorded for review",
      len(c.unconfirmed_stops) == 1
      and c.unconfirmed_stops[0]["commanded"] == FIRE_LEVEL.name)


print("=== NO relay wired at all is also not a stop ===")

c2 = bare()
r2, out2 = fire(c2)
check("stop_confirmed is False when nothing was wired", r2["stop_confirmed"] is False)
check("power_cut is NOT claimed with zero relays",
      r2["system_state"]["power_cut"] is False)
check("the reason names the missing relay",
      any("NO RELAY REGISTERED" in f for f in r2["failures"]))
check("status() reports the integrity breach",
      c2.status()["stop_integrity_ok"] is False)


print("=== CONTROL: a working relay must still succeed (not a blanket refusal) ===")

c3 = bare()
fired = []
c3.register_relay(FIRE_LEVEL, lambda: fired.append(1))
r3, _ = fire(c3)
check("the relay actually ran", len(fired) == 1)
check("stop_confirmed is True", r3["stop_confirmed"] is True)
check("power_cut is recorded", r3["system_state"]["power_cut"] is True)
check("isolated is recorded", r3["system_state"]["isolated"] is True)
check("actuators are recorded as inactive",
      r3["system_state"]["actuators_active"] is False)
check("no failures recorded", r3["failures"] == [])
check("status() reports integrity intact", c3.status()["stop_integrity_ok"] is True)
check("no unconfirmed stop recorded", c3.unconfirmed_stops == [])


print("=== partial failure: one relay works, one raises ===")

c4 = bare()
ran = []
c4.register_relay(FIRE_LEVEL, lambda: ran.append("good"))
c4.register_relay(FIRE_LEVEL, lambda: (_ for _ in ()).throw(RuntimeError("bad relay")))
r4, out4 = fire(c4)
check("a working relay at the level still records the physical state",
      r4["system_state"]["isolated"] is True)
check("but the run is NOT reported as fully confirmed",
      r4["stop_confirmed"] is False)
check("the specific failing relay is named", any("bad relay" in f for f in r4["failures"]))
check("the operator is warned even though one relay worked",
      "UNCONFIRMED STOP" in out4)


print("=== the event is still recorded regardless of relay outcome ===")

check("a failed stop is still in the event log", len(c.event_log) == 1)
check("a successful stop is still in the event log", len(c3.event_log) == 1)


# ─────────────────────────────────────────────────────────────────────────────
# THE GRADUATED LADDER — every ResponseLevel, not just the top of it.
#
# Everything above this line fires a FIRE event, which maps to ISOLATE: the
# maximum level, where graduation cannot be observed because there is nothing
# above it to wrongly trigger. That blind spot hid a second defect sitting three
# lines from the fail-open one:
#
#     for resp_level in ResponseLevel:
#         if resp_level.value >= level.value:      # AT OR ABOVE — inverted
#
# A THERMAL warning maps to THROTTLE ("reduce speed, stay running") and commanded
# SOFT_HALT, HARD_HALT, POWER_CUT and ISOLATE with it. A routine over-temperature
# physically disconnected the machine, and on a rig with no isolation contactor the
# unwired upper levels counted as failures — latching stop_integrity_ok=False and
# printing "treat the machine as LIVE" for a one-degree overshoot. The fail-open fix
# made the inversion louder: alarm fatigue on the one signal that cannot afford it.
#
# The corrected rule: a commanded level implies every LESSER action and never a
# greater one, most-severe-first.
# ─────────────────────────────────────────────────────────────────────────────

def drive(hazard, wire_all=True):
    """Fire `hazard` on a bare controller with a recorder at every level."""
    c = bare()
    fired = []
    if wire_all:
        for lv in ResponseLevel:
            c.register_relay(lv, (lambda l=lv: fired.append(l)))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = c.receive_event(HardwareEvent(hazard, "gpio_17", "GPIO"))
    return c, r, fired, buf.getvalue()


print("=== the hazard table is total ===")

check("every HazardType has a mapped response",
      all(h in HAZARD_RESPONSE for h in HazardType))
check("every mapped response is a real ResponseLevel",
      all(isinstance(v, ResponseLevel) for v in HAZARD_RESPONSE.values()))


print("=== every commanded level fires exactly itself and below ===")

for hazard in HazardType:
    level = HAZARD_RESPONSE[hazard]
    _c, _r, fired, _out = drive(hazard)
    expected = {l for l in ResponseLevel if l.value <= level.value}
    check(f"{hazard.value} -> {level.name}: fires exactly levels <= {level.name}",
          set(fired) == expected)
    check(f"{hazard.value} -> {level.name}: fires NOTHING above {level.name}",
          not any(l.value > level.value for l in fired))
    check(f"{hazard.value} -> {level.name}: most severe relay commanded FIRST",
          fired == sorted(fired, key=lambda l: l.value, reverse=True))
    check(f"{hazard.value} -> {level.name}: commanded_levels matches what fired",
          set(_r["commanded_levels"]) == {l.name for l in expected})


print("=== ALERT is reachable as a lesser action, never as a command ===")

check("no hazard commands ALERT (it is an implied lesser action only)",
      ResponseLevel.ALERT not in HAZARD_RESPONSE.values())
_c, _r, fired_alert, _o = drive(HazardType.THERMAL)
check("the mildest real hazard still fires the ALERT relay",
      ResponseLevel.ALERT in fired_alert)


print("=== REGRESSION: a throttle must not disconnect the machine ===")

c5, r5, fired5, out5 = drive(HazardType.THERMAL)
check("THERMAL maps to THROTTLE", r5["response_level"] == "THROTTLE")
check("the POWER_CUT relay is NOT fired by a throttle",
      ResponseLevel.POWER_CUT not in fired5)
check("the ISOLATE relay is NOT fired by a throttle",
      ResponseLevel.ISOLATE not in fired5)
check("the HARD_HALT relay is NOT fired by a throttle",
      ResponseLevel.HARD_HALT not in fired5)
check("power_cut is not recorded after a throttle",
      r5["system_state"]["power_cut"] is False)
check("isolated is not recorded after a throttle",
      r5["system_state"]["isolated"] is False)
check("actuators stay active after a throttle",
      r5["system_state"]["actuators_active"] is True)
check("a throttle does not demand a human restart",
      r5["restart_requires_human"] is False)


print("=== state escalates only where the level earns it ===")

for hazard in HazardType:
    level = HAZARD_RESPONSE[hazard]
    _c, r, _f, _o = drive(hazard)
    st = r["system_state"]
    check(f"{level.name}: power_cut iff level >= POWER_CUT",
          st["power_cut"] is (level.value >= ResponseLevel.POWER_CUT.value))
    check(f"{level.name}: actuators inactive iff level >= HARD_HALT",
          st["actuators_active"] is not (level.value >= ResponseLevel.HARD_HALT.value))
    check(f"{level.name}: isolated iff level >= ISOLATE",
          st["isolated"] is (level.value >= ResponseLevel.ISOLATE.value))
    check(f"{level.name}: restart_requires_human iff level >= HARD_HALT",
          r["restart_requires_human"] is (level.value >= ResponseLevel.HARD_HALT.value))


print("=== higher severity is a superset, never a different set ===")

sets = {}
for hazard in HazardType:
    _c, _r, fired, _o = drive(hazard)
    sets[HAZARD_RESPONSE[hazard]] = set(fired)
ordered = sorted(sets, key=lambda l: l.value)
for lower, higher in zip(ordered, ordered[1:]):
    check(f"{lower.name} relays are a subset of {higher.name} relays",
          sets[lower] <= sets[higher])


print("=== an unwired LESSER level is a deployment choice, not a fault ===")

c6 = bare()
fired6 = []
c6.register_relay(ResponseLevel.THROTTLE, lambda: fired6.append("THROTTLE"))
buf6 = io.StringIO()
with contextlib.redirect_stdout(buf6):
    r6 = c6.receive_event(HardwareEvent(HazardType.THERMAL, "gpio_4", "GPIO", 71.0, 70.0))
out6 = buf6.getvalue()
check("the commanded level ran", fired6 == ["THROTTLE"])
check("stop_confirmed is True with only the commanded relay wired",
      r6["stop_confirmed"] is True)
check("an unwired lesser level is NOT a failure", r6["failures"] == [])
check("but it is still visible for review",
      any("ALERT" in n for n in r6["not_wired"]))
check("no false integrity breach on a routine warning",
      c6.status()["stop_integrity_ok"] is True)
check("no LIVE-machine alarm on a routine warning", "UNCONFIRMED STOP" not in out6)
check("no unconfirmed stop recorded", c6.unconfirmed_stops == [])


print("=== an unwired COMMANDED level is still a fault ===")

c7 = bare()
c7.register_relay(ResponseLevel.ALERT, lambda: None)   # lesser only — not the command
buf7 = io.StringIO()
with contextlib.redirect_stdout(buf7):
    r7 = c7.receive_event(HardwareEvent(HazardType.THERMAL, "gpio_4", "GPIO"))
check("stop_confirmed is False when the commanded level has no relay",
      r7["stop_confirmed"] is False)
check("the failure names the missing commanded relay",
      any("NO RELAY REGISTERED" in f and "THROTTLE" in f for f in r7["failures"]))
check("a fired lesser relay does not launder the missing command",
      c7.status()["stop_integrity_ok"] is False)


print("=== a lesser relay that RAISES is still reported ===")

c8 = bare()
c8.register_relay(ResponseLevel.THROTTLE, lambda: None)
c8.register_relay(ResponseLevel.ALERT,
                  lambda: (_ for _ in ()).throw(RuntimeError("alert bus down")))
buf8 = io.StringIO()
with contextlib.redirect_stdout(buf8):
    r8 = c8.receive_event(HardwareEvent(HazardType.THERMAL, "gpio_4", "GPIO"))
check("a raising lesser relay is a failure (absence is a choice, a fault is not)",
      any("alert bus down" in f for f in r8["failures"]))
check("and it withholds stop_confirmed", r8["stop_confirmed"] is False)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
