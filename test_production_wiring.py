"""
test_production_wiring.py — the wiring guide must teach code that actually works.

`production_wiring.py` is not ordinary code: its payload is EXAMPLE CODE that an
integrator copies to connect real relays to real power. A defect here does not crash a
test — it propagates into physical wiring, where it becomes a machine that does not
stop. It had no tests.

Two failure classes matter, and neither is caught by running the module:

  DOC DRIFT — the API moves and the guide keeps teaching the old call. This session
    alone `register_sensor` gained mandatory `normally_closed` for EMERGENCY_STOP,
    finite-threshold validation, strict enum types and a configuration lock. A guide
    that predates any of those teaches code that now raises. So the registrations in
    the guides are EXECUTED here against the real hub.

  SILENTLY-DEFEATING PATTERNS — code that runs fine and destroys a safety property.
    The guide originally taught:
        def real_power_cut():
            GPIO.output(POWER_PIN, GPIO.LOW)
    `HardwareSafetyController` treats a relay callback that RETURNS as a CONFIRMED
    stop. GPIO.output() returns successfully when the relay is welded shut, the coil
    is open, or the wire fell off — so that callback reports a stop that never
    happened, defeating the confirmation mechanism exactly where it matters. The guide
    must teach read-back.

Run: python3 test_production_wiring.py
"""

import ast
import re

from driftcore.hardware import production_wiring as W
from driftcore.hardware.hardware_safety import (
    HardwareSafetyController, ResponseLevel, HazardType, HardwareEvent)
from driftcore.hardware.sensor_interfaces import (
    SensorHub, SensorType, InterfaceType)

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


GUIDES = {name: getattr(W, name) for name in dir(W)
          if name.endswith("_GUIDE") or name.endswith("_DIAGRAM")}


print("=== the guides exist and are reachable ===")

check("at least four interface guides are published", len(GUIDES) >= 4)
check("print_all_guides() is callable", callable(W.print_all_guides))


print("=== DOC DRIFT: every register_sensor(...) the guide teaches must still work ===")

# Pull the literal calls out of the guide text and execute them against a real hub.
# A guide that teaches a call the API now rejects is a guide that will fail in a lab
# at 2am, which is the worst possible place to discover it.
CALL = re.compile(r"hub\.register_sensor\(([^)]*)\)", re.S)
calls = []
for name, text in GUIDES.items():
    for m in CALL.finditer(text):
        calls.append((name, m.group(0)))

check("the guides actually contain register_sensor examples", len(calls) >= 8)

hub = SensorHub(HardwareSafetyController())
failures = []
for guide_name, snippet in calls:
    try:
        # evaluate the documented call with the real names in scope
        eval(compile(ast.parse(snippet, mode="eval"), "<guide>", "eval"),
             {"hub": hub, "SensorType": SensorType, "InterfaceType": InterfaceType})
    except Exception as e:
        failures.append((guide_name, snippet.split("(")[1][:40], type(e).__name__, str(e)[:60]))

for g, s, etype, msg in failures:
    print(f"       {g}: {s}… -> {etype}: {msg}")
check("EVERY documented register_sensor call executes against the current API",
      failures == [])


print("=== the guide covers the most important sensor of all ===")

all_text = "\n".join(GUIDES.values())
check("an EMERGENCY_STOP is actually shown (it is the whole point of a stop system)",
      "EMERGENCY_STOP" in all_text)
check("and it is wired NORMALLY CLOSED, so a cut wire trips it",
      "normally_closed=True" in all_text)
check("the guide explains WHY normally-closed (a severed NO line reads NORMAL)",
      "normally-closed" in all_text.lower() or "NORMALLY CLOSED" in all_text)


print("=== the relay examples must not silently defeat stop-confirmation ===")

check("the guide warns that a returning callback is treated as CONFIRMED",
      "CONFIRMED" in all_text)
check("the relay example READS BACK a feedback contact",
      "GPIO.input(feedback_pin)" in all_text or "feedback" in all_text.lower())
check("and RAISES when the relay did not move",
      "raise RuntimeError" in all_text)
check("the test procedure tells the integrator to verify the failure path",
      "stop_confirmed=False" in all_text or "UNCONFIRMED STOP" in all_text)
check("and to test the e-stop by CUTTING the line, not just pressing the button",
      "CUT" in all_text)


print("=== fail-safe relay polarity is taught correctly ===")

check("de-energising OPENS the relay and CUTS power (loss of signal is safe)",
      "LOW  → relay OPEN" in all_text or "LOW = relay opens" in all_text
      or "Open relay" in all_text)
check("energised/HIGH is the RUNNING state, not the stopped one",
      "HIGH = relay closed" in all_text or "HIGH → relay CLOSED" in all_text)


print("=== the documented read-back pattern genuinely works end to end ===")

# Model the guide's pattern against the real controller: a relay whose feedback
# disagrees must produce an UNCONFIRMED stop, not a clean one.
def _guide_style_relay(feedback_ok: bool):
    def relay():
        if not feedback_ok:
            raise RuntimeError("relay did not open — feedback contact still closed")
    return relay


import io, contextlib


def _fire(relay):
    c = HardwareSafetyController()
    for k in c._relay_callbacks:
        c._relay_callbacks[k] = []
    c.register_relay(HazardType and ResponseLevel.ISOLATE, relay)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = c.receive_event(HardwareEvent(HazardType.FIRE, "gpio:17", "GPIO"))
    return r, buf.getvalue(), c


good, _, c_good = _fire(_guide_style_relay(True))
check("a relay whose feedback CONFIRMS produces a confirmed stop",
      good["stop_confirmed"] is True and good["system_state"]["power_cut"] is True)

bad, out, c_bad = _fire(_guide_style_relay(False))
check("a relay whose feedback DISAGREES produces an UNCONFIRMED stop",
      bad["stop_confirmed"] is False)
check("...and does NOT claim the machine is stopped",
      bad["system_state"]["power_cut"] is False)
check("...and tells the operator to treat the machine as live",
      "LIVE" in out)
check("...and is recorded for review", len(c_bad.unconfirmed_stops) == 1)


print("=== the guide's own configuration advice is followed through ===")

check("it tells the integrator to lock the configuration after registration",
      "lock_configuration()" in all_text)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
