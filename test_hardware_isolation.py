"""
test_hardware_isolation.py — first tests this module has ever had.

Every defect asserted below was reproduced against the ORIGINAL code first. The
headline one: `full_isolation()` returned FULLY_ISOLATED on a bare process with no
relay, no callback and no mechanism of any kind for reaching hardware. This is the
third module in this repo to carry that same fail-open shape, and the one where it
mattered most — it is the isolation claim itself.

Run: python3 test_hardware_isolation.py
"""

# CLAIMS: driftcore/safety/hardware_isolation.py:no-relay-no-claim
# CLAIMS: driftcore/safety/hardware_isolation.py:log-not-editable


import re
import threading

from driftcore.safety.hardware_isolation import IsolationController

_passed = _total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def raises(label, exc, fn):
    global _passed, _total
    _total += 1
    try:
        fn()
    except exc:
        _passed += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}: {e})")
        return
    print(f"  FAIL {label} (did not raise)")


print("=== a controller with no relay claims NOTHING ===")

c = IsolationController()
r = c.full_isolation()
check("full_isolation does not report FULLY_ISOLATED",
      r["status"] == "ISOLATION_UNCONFIRMED")
check("confirmed is False", r["confirmed"] is False)
check("both channels are named as unconfirmed",
      r["energy"] == "ENERGY_ISOLATION_UNCONFIRMED"
      and r["actuators"] == "ACTUATOR_CUTOFF_UNCONFIRMED")
check("the failures say nothing physical was commanded",
      len(r["failures"]) == 2
      and all("NO RELAY REGISTERED" in f for f in r["failures"]))
check("and the note tells the operator to treat the machine as live",
      "LIVE" in r["note"])


print("=== with working relays, isolation is confirmed ===")

fired = []
c = IsolationController()
c.register_relay("energy", lambda: fired.append("energy"))
c.register_relay("actuators", lambda: fired.append("actuators"))
r = c.full_isolation()
check("both relays fired", fired == ["energy", "actuators"])
check("status is FULLY_ISOLATED", r["status"] == "FULLY_ISOLATED")
check("confirmed is True", r["confirmed"] is True)
check("no failures", r["failures"] == [])
check("and the note demands human inspection", "inspection" in r["note"])


print("=== a relay that FAILS must not produce an isolated machine ===")


def boom():
    raise RuntimeError("contactor welded shut")


c = IsolationController()
c.register_relay("energy", boom)
c.register_relay("actuators", lambda: None)
r = c.full_isolation()
check("status is NOT FULLY_ISOLATED", r["status"] != "FULLY_ISOLATED")
check("the failing channel is named",
      any("contactor welded shut" in f for f in r["failures"]))
check("the working channel still reports its own success",
      r["actuators"] == "ACTUATORS_DISABLED")
check("but the whole is unconfirmed", r["confirmed"] is False)


print("=== a failure on one channel does not skip the other ===")

ran = []
c = IsolationController()
c.register_relay("energy", boom)
c.register_relay("actuators", lambda: ran.append("actuators"))
c.full_isolation()
check("the actuator cutoff still ran after the energy relay raised",
      ran == ["actuators"])


print("=== a partly-working channel is still a fault ===")

c = IsolationController()
c.register_relay("energy", lambda: None)
c.register_relay("energy", boom)          # two relays, one broken
c.register_relay("actuators", lambda: None)
r = c.full_isolation()
check("one good relay does not launder a broken one on the same channel",
      r["confirmed"] is False)


print("=== the audit log cannot be edited through its accessor ===")

c = IsolationController()
c.register_relay("energy", lambda: None)
c.isolate_energy_system()
log = c.get_isolation_log()
original = log[0]["action"]
log[0]["action"] = "NOTHING_HAPPENED"
log.append({"action": "FABRICATED"})
check("mutating the returned entry does not change the record",
      c.get_isolation_log()[0]["action"] == original)
check("appending to the returned list does not add a record",
      not any(e["action"] == "FABRICATED" for e in c.get_isolation_log()))


print("=== every entry is timestamped, timezone-aware, and honest ===")

c = IsolationController()
c.full_isolation()
entries = c.get_isolation_log()
check("entries were written even though nothing was confirmed", len(entries) >= 2)
check("every entry carries a UTC offset",
      all(re.search(r"(\+00:00|Z)$", e["timestamp"]) for e in entries))
check("and every entry says whether it was confirmed",
      all(isinstance(e["confirmed"], bool) for e in entries))
check("an unconfirmed run is recorded as unconfirmed",
      all(e["confirmed"] is False for e in entries))


print("=== registration is guarded ===")

c = IsolationController()
raises("an unknown channel is refused", ValueError,
       lambda: c.register_relay("cooling", lambda: None))
raises("a non-callable relay is refused", TypeError,
       lambda: c.register_relay("energy", "open the contactor"))


print("=== the log is bounded and says what it dropped ===")

c = IsolationController(max_log_entries=50)
c.register_relay("energy", lambda: None)
for _ in range(200):
    c.isolate_energy_system()
check("the log is capped", len(c.get_isolation_log()) == 50)
check("and the dropped count is kept", c.dropped_entries == 150)


print("=== controllers are independent (no shared module global) ===")

a = IsolationController()
b = IsolationController()
a.register_relay("energy", lambda: None)
a.isolate_energy_system()
check("one controller's log does not appear in another's",
      len(b.get_isolation_log()) == 0)


print("=== concurrent isolation calls all get recorded ===")

c = IsolationController()
c.register_relay("energy", lambda: None)
c.register_relay("actuators", lambda: None)


def hammer():
    for _ in range(100):
        c.full_isolation()


threads = [threading.Thread(target=hammer) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
# 3 entries per full_isolation (energy, actuators, summary) x 400 calls.
check("no entries were lost under concurrency",
      len(c.get_isolation_log()) + c.dropped_entries == 1200)

print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
