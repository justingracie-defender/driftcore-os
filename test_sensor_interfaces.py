"""
test_sensor_interfaces.py — the input path to the physical safety controller.

`sensor_interfaces.py` is what turns a physical reading into a HardwareEvent and hands
it to `HardwareSafetyController`. It is live (main.py wires it) and it had NO tests. A
safety controller is only as good as the events that reach it, so the failures worth
hunting here are the ones where a real hazard produces NO event, or produces a "normal"
one.

What the red-team pass found, all reproduced before being fixed:

  A1  an UNREGISTERED source was dropped. A real smoke reading arriving on a key that
      was never registered (typo, sensor added to the rig but not the map, drifted
      source string) reached zero controllers — and the returned dict was TRUTHY, so a
      caller writing `if result:` saw success.
  A2  the code claimed to treat "NaN or impossible value" as triggered, but handled
      only NaN. `None` and `"HIGH"` RAISED TypeError from inside receive() — in a
      polling loop that kills the loop, so every later sensor goes unread too — and
      -inf passed through as a NORMAL reading.
  A6  re-registering a source overwrote it SILENTLY. Raising the threshold on a live
      smoke detector made real smoke read NORMAL, with nothing in the output to show
      the sensor had been desensitised.
  A7  only `value >= threshold` existed, so a NORMALLY-CLOSED emergency stop — the
      standard wiring, chosen precisely so a cut wire trips the machine — read a
      severed line as NORMAL. The exact failure the wiring exists to prevent.

Run: python3 test_sensor_interfaces.py
"""

import contextlib
import io

from driftcore.hardware.hardware_safety import HardwareSafetyController
from driftcore.hardware.sensor_interfaces import (
    SensorHub, SensorType, InterfaceType, SensorReading)

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


def hub():
    return SensorHub(HardwareSafetyController())


def quiet(fn, *a, **kw):
    """Run without the module's console narration."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **kw)
    return r, buf.getvalue()


def tripped(result) -> bool:
    """A reading tripped iff it produced a controller response."""
    return isinstance(result, dict) and "response_level" in result


print("=== the normal path still works (this must not become a blanket alarm) ===")

h = hub()
h.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0,
                  location="kitchen")
r, _ = quiet(h.receive, "gpio:17", 0.0)
check("a quiet sensor reads NORMAL", r["status"] == "NORMAL")
check("no event reached the controller", len(h.controller.event_log) == 0)

r, _ = quiet(h.receive, "gpio:17", 1.0)
check("a reading at the threshold TRIPS", tripped(r))
check("the controller received the event", len(h.controller.event_log) == 1)


print("=== A1: an unregistered source is a config fault, not a shrug ===")

h2 = hub()
h2.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
r, out = quiet(h2.receive, "gpio:18", 1.0)     # real smoke, wrong key
check("A1: reported under the same 'status' key every other path uses",
      r.get("status") == "UNROUTED")
check("A1: the dropped reading is recorded for review", len(h2.unrouted) == 1)
check("A1: it names the source and value",
      h2.unrouted[0]["source"] == "gpio:18" and h2.unrouted[0]["value"] == 1.0)
check("A1: an operator is told, loudly", "UNROUTED SENSOR READING" in out)
check("A1: and it is honest that no controller saw it",
      "reached no safety controller" in r["reason"])


print("=== A2: an unreadable sensor TRIPS, and never crashes the loop ===")

h3 = hub()
h3.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
for bad, label in ((None, "None (disconnected)"),
                   ("HIGH", "a string from a driver"),
                   (float("nan"), "NaN"),
                   (float("-inf"), "-inf"),
                   (float("inf"), "+inf")):
    raised = False
    try:
        r, _ = quiet(h3.receive, "gpio:17", bad)
    except Exception:
        raised = True
        r = None
    check(f"A2: {label} does not raise", not raised)
    check(f"A2: {label} TRIPS rather than reading normal", bool(r) and tripped(r))

r, _ = quiet(h3.receive, "gpio:17", 0.0)
check("A2: a genuinely quiet sensor is still NORMAL (not everything trips)",
      r["status"] == "NORMAL")


print("=== A6: a live sensor cannot be desensitised silently ===")

h4 = hub()
h4.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
raised = False
try:
    h4.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=999.0)
except ValueError:
    raised = True
check("A6: re-registering with different settings is REFUSED", raised)
r, _ = quiet(h4.receive, "gpio:17", 1.0)
check("A6: the original threshold still holds after the refusal", tripped(r))

# an identical re-registration is harmless and must not be an error
ok = True
try:
    h4.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
except ValueError:
    ok = False
check("A6: an IDENTICAL re-registration is allowed (idempotent)", ok)

h4.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=999.0,
                   replace=True)
r, _ = quiet(h4.receive, "gpio:17", 1.0)
check("A6: a deliberate replace=True does take effect", r["status"] == "NORMAL")


print("=== A7: emergency-stop wiring must be declared, then honoured ===")

h5 = hub()
raised = False
try:
    h5.register_sensor("gpio:99", SensorType.EMERGENCY_STOP, InterfaceType.GPIO,
                       threshold=1.0)
except ValueError:
    raised = True
check("A7: an e-stop with UNDECLARED wiring is refused", raised)

# normally-closed: the line is held high; losing it must trip
h6 = hub()
h6.register_sensor("gpio:99", SensorType.EMERGENCY_STOP, InterfaceType.GPIO,
                   threshold=1.0, normally_closed=True, location="panel")
r, _ = quiet(h6.receive, "gpio:99", 1.0)
check("A7 NC: a healthy held line reads NORMAL (no permanent trip)",
      r["status"] == "NORMAL")
r, _ = quiet(h6.receive, "gpio:99", 0.0)
check("A7 NC: a CUT WIRE trips the stop", tripped(r))
r, _ = quiet(h6.receive, "gpio:99", 0.5)
check("A7 NC: a degraded line trips the stop", tripped(r))

# normally-open: the button closes the circuit
h7 = hub()
h7.register_sensor("gpio:98", SensorType.EMERGENCY_STOP, InterfaceType.GPIO,
                   threshold=1.0, normally_closed=False)
r, _ = quiet(h7.receive, "gpio:98", 0.0)
check("A7 NO: an idle button reads NORMAL", r["status"] == "NORMAL")
r, _ = quiet(h7.receive, "gpio:98", 1.0)
check("A7 NO: a pressed button trips the stop", tripped(r))


print("=== the reading carries the wiring it was judged under ===")

nc = SensorReading(SensorType.EMERGENCY_STOP, InterfaceType.GPIO, "gpio:99",
                   value=0.0, threshold=1.0, normally_closed=True)
no = SensorReading(SensorType.EMERGENCY_STOP, InterfaceType.GPIO, "gpio:98",
                   value=0.0, threshold=1.0, normally_closed=False)
check("the same 0.0 trips under NC and not under NO",
      nc.triggered is True and no.triggered is False)
check("a corrupt reading is flagged as corrupt, not merely triggered",
      SensorReading(SensorType.SMOKE, InterfaceType.GPIO, "x", value=None,
                    threshold=1.0).corrupted is True)


print("=== a tripped reading becomes a well-formed hardware event ===")

h8 = hub()
h8.register_sensor("gpio:17", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0,
                   location="kitchen")
quiet(h8.receive, "gpio:17", 1.0)
ev = h8.controller.event_log[-1]
check("the event names the hazard", ev["hazard"] == "FIRE")
check("the event carries the source", ev["source"] == "gpio:17")
check("the event carries the location", ev["location"] == "kitchen")
check("the event carries the reading and threshold",
      ev["reading"] == 1.0 and ev["threshold"] == 1.0)


print("=== A8: a corrupt DECISION BOUNDARY is refused (mirror of A2) ===")

for bad, label in ((float("nan"), "NaN (never compares true in EITHER direction)"),
                   (float("inf"), "+inf (never trips)"),
                   (float("-inf"), "-inf (always trips)"),
                   ("999", "a string"),
                   (None, "None"),
                   (True, "a bool masquerading as a number")):
    h = hub()
    raised = False
    try:
        h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=bad)
    except ValueError:
        raised = True
    check(f"A8: threshold {label} is refused", raised)

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
r, _ = quiet(h.receive, "g", 5.0)
check("A8: a finite threshold still works normally", tripped(r))


print("=== configuration types cannot be coerced into a wrong meaning ===")

h = hub()
raised = False
try:
    h.register_sensor("e", SensorType.EMERGENCY_STOP, InterfaceType.GPIO,
                      threshold=1.0, normally_closed="false")
except ValueError:
    raised = True
check("the STRING 'false' is refused (bool('false') is True — silent inversion)",
      raised)

for st, it, label in (("SMOKE", InterfaceType.GPIO, "sensor_type as a string"),
                      (SensorType.SMOKE, "GPIO", "interface as a string")):
    h = hub()
    raised = False
    try:
        h.register_sensor("x", st, it, threshold=1.0)
    except ValueError:
        raised = True
    check(f"{label} is refused at registration", raised)


print("=== safety state is bounded: no memory or log exhaustion ===")

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
_, out = quiet(lambda: [h.receive("g", 0.0) for _ in range(8000)])
check("the readings buffer is bounded", len(h.readings) <= 5000)
_, out = quiet(lambda: [h.receive("flood", 0.0) for _ in range(8000)])
check("the unrouted buffer is bounded", len(h.unrouted) <= 5000)
check("the UNROUTED warning is rate-limited, not one line per message",
      out.count("UNROUTED SENSOR READING") < 200)
check("but the flood is still announced at least once",
      out.count("UNROUTED SENSOR READING") > 0)


print("=== silence is not safety: a dead sensor is visible ===")

h = hub()
h.register_sensor("alive", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0,
                  location="kitchen")
h.register_sensor("never", SensorType.HEAT, InterfaceType.GPIO, threshold=1.0,
                  location="attic")
quiet(h.receive, "alive", 0.0)
stale = {s["source"]: s["state"] for s in h.stale_sensors(max_age_seconds=0.0)}
check("a source that has gone quiet is reported STALE", stale.get("alive") == "STALE")
check("a source never heard from at all is reported NEVER_REPORTED",
      stale.get("never") == "NEVER_REPORTED")
check("a freshly-reporting sensor is NOT stale under a generous window",
      h.stale_sensors(max_age_seconds=3600) and
      all(s["source"] != "alive" for s in h.stale_sensors(max_age_seconds=3600)))


print("=== configuration is a start-up privilege, not a runtime capability ===")

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
h.lock_configuration()
raised = False
try:
    h.register_sensor("new", SensorType.HEAT, InterfaceType.GPIO, threshold=1.0)
except PermissionError:
    raised = True
check("registering a new sensor while locked is refused", raised)
raised = False
try:
    h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=999.0,
                      replace=True)
except PermissionError:
    raised = True
check("replace=True cannot desensitise a live sensor while locked", raised)
r, _ = quiet(h.receive, "g", 1.0)
check("the original threshold survived the attempt", tripped(r))
h.unlock_configuration(h.UNLOCK_TOKEN)   # A13: unlocking is deliberate
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=999.0,
                  replace=True)
check("a deliberate unlock still allows a real change",
      h.sensor_map["g"]["threshold"] == 999.0)


print("=== a trip and a sensor failure must not look identical ===")

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
quiet(h.receive, "g", 5.0)
quiet(h.receive, "g", None)
qualities = [e["quality"] for e in h.controller.event_log]
check("a real measurement is marked VALID", "VALID" in qualities)
check("an untrustworthy reading is marked CORRUPT", "CORRUPT" in qualities)
check("quality is its OWN field — `source` stays clean provenance",
      all(e["source"] == "g" for e in h.controller.event_log))
check("both still reached the controller (both are unsafe)",
      len(h.controller.event_log) == 2)


print("=== A9: rate-limit bookkeeping is bounded too ===")

h = hub()
quiet(lambda: [h.receive(f"typo-topic-{i}", 1.0) for i in range(3000)])
check("A9: the unrouted deque is bounded", len(h.unrouted) <= 5000)
check("A9: and so is the rate-limit dict (a flood of UNIQUE sources)",
      len(h._unrouted_warned) <= 1000)


print("=== A10: a failing controller must not take the intake offline ===")


class _ExplodingController(HardwareSafetyController):
    def receive_event(self, event):
        raise RuntimeError("downstream failure")


h = SensorHub(_ExplodingController())
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
raised = False
try:
    r, out = quiet(h.receive, "g", 5.0)
except Exception:
    raised = True
    r, out = None, ""
check("A10: a controller exception does NOT escape receive()", not raised)
check("A10: the trip is still reported, not swallowed",
      r and r["status"] == "TRIP_UNDELIVERED" and r["triggered"] is True)
check("A10: the undelivered hazard is recorded", len(h.undelivered) == 1)
check("A10: an operator is told the hazard was NOT processed",
      "CONTROLLER FAILED" in out)
later, _ = quiet(h.receive, "g", 0.0)
check("A10: a LATER sensor still gets processed (the loop survived)",
      later["status"] == "NORMAL")


print("=== A11: concurrent callers do not corrupt shared safety state ===")

import threading

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=99.0)
errors = []


def _hammer():
    try:
        for _ in range(400):
            h.receive("g", 0.0)
            h.stale_sensors(60)
    except Exception as e:      # pragma: no cover - a race would land here
        errors.append(e)


threads = [threading.Thread(target=_hammer) for _ in range(8)]
quiet(lambda: ([t.start() for t in threads], [t.join() for t in threads]))
check("A11: 8 concurrent readers/writers raise nothing", errors == [])
check("A11: the hub exposes a real lock, not just a flag",
      hasattr(h, "_lock") and hasattr(h._lock, "acquire"))


print("=== A12: silence can be escalated into a real event ===")

h = hub()
h.register_sensor("dead", SensorType.TEMPERATURE, InterfaceType.MQTT, threshold=85.0,
                  location="cpu")
raised_events, _ = quiet(h.raise_stale_as_hazard, 0.0)
check("A12: a never-reporting continuous sensor produces an event",
      len(raised_events) == 1)
check("A12: the controller actually received it", len(h.controller.event_log) == 1)
check("A12: it is marked CORRUPT, not a real measurement",
      h.controller.event_log[-1]["quality"] == "CORRUPT")

# a freshly-reporting sensor must NOT be escalated
h2 = hub()
h2.register_sensor("alive", SensorType.TEMPERATURE, InterfaceType.MQTT, threshold=85.0)
quiet(h2.receive, "alive", 20.0)
out, _ = quiet(h2.raise_stale_as_hazard, 3600.0)
check("A12: a healthy reporting sensor is NOT escalated", out == [])


print("=== A13: unlocking is deliberate, not a stray call ===")

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
h.lock_configuration()
raised = False
try:
    h.unlock_configuration()
except PermissionError:
    raised = True
check("A13: a bare unlock_configuration() is refused", raised)
h.unlock_configuration(h.UNLOCK_TOKEN)
check("A13: the explicit token unlocks it", h._config_locked is False)


print("=== A14: timestamps are timezone-aware throughout ===")

h = hub()
h.register_sensor("g", SensorType.SMOKE, InterfaceType.GPIO, threshold=1.0)
quiet(h.receive, "g", 0.0)
check("A14: the reading timestamp is aware UTC (not naive utcnow)",
      h.readings[-1].timestamp.endswith("+00:00"))
check("A14: last_seen is aware UTC", h.last_seen["g"].tzinfo is not None)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
