"""
hardware_isolation.py — Physical System Cutoff

When software safety fails, hardware must be able to stop the system.
In real deployment this maps to physical relay/interlock signals.

CLAIM no-relay-no-claim: nothing is reported as isolated unless a registered relay
was called and returned; with no relay the result is ISOLATION_UNCONFIRMED.
CLAIM log-not-editable: the isolation log cannot be altered through the accessor
that returns it.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests, and it carried the same fail-open defect already fixed twice
elsewhere in this repo — in the module whose entire purpose is the isolation claim.

1. IT REPORTED SAFETY IT HAD NOT ACHIEVED. `full_isolation()` returned
   `status: "FULLY_ISOLATED"` after appending two dictionaries to a list. There was
   no relay, no callback, no mechanism of any kind by which a deployment could attach
   the physical interlock the docstring promised. Any caller integrating this got a
   function that always answers FULLY_ISOLATED, including on a machine with the
   energy system fully live. Reproduced: called on a bare process with nothing
   registered, it returned FULLY_ISOLATED.

   The correction is the same one `hardware_safety.py` needed: COMMANDED and
   CONFIRMED are different facts. Nothing is reported as isolated unless a registered
   relay was called and returned.

2. THE AUDIT LOG WAS EDITABLE THROUGH ITS OWN ACCESSOR. `get_isolation_log()`
   returned `list(_isolation_log)` — a shallow copy sharing the entry dicts.
   Reproduced: a caller reassigned `log[0]["action"]` and the module's real record
   changed to "NOTHING_HAPPENED". A copy that lets you rewrite the original is worse
   than no copy, because it reads as protection.

3. TIMESTAMPS WERE NAIVE AND DEPRECATED. `datetime.utcnow()` emits a
   DeprecationWarning on modern Python and returns a datetime with no timezone, so
   the isoformat string carried no offset. An isolation record that cannot be placed
   on a timeline against another machine's records is not much of a record.

4. UNBOUNDED MODULE-LEVEL GLOBAL. `_isolation_log` grew forever and was shared by
   every importer, with no way to bound it or scope it to a deployment.

HONEST LIMIT: registering a relay for a level means the deployment asserts that
callable ACHIEVES that level. Nothing here can verify that claim — a relay that
returns without opening a contactor is indistinguishable from one that works. This
module can prove a relay was called and returned; the physical fact behind it belongs
to LifeCore and the hardware (see the layer split in 000_AI_START_HERE.md).

Run: python3 test_hardware_isolation.py
"""

import copy
import threading
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

MAX_LOG_ENTRIES = 2000


def _now() -> str:
    """Timezone-aware, non-deprecated, comparable across machines."""
    return datetime.now(timezone.utc).isoformat()


class IsolationController:
    """Physical isolation, with the claim separated from the command."""

    ENERGY = "energy"
    ACTUATORS = "actuators"

    def __init__(self, max_log_entries: int = MAX_LOG_ENTRIES) -> None:
        self._relays: Dict[str, List[Callable[[], object]]] = {
            self.ENERGY: [], self.ACTUATORS: []}
        self._log: List[dict] = []
        self._dropped = 0
        self._max_log = int(max_log_entries)
        self._lock = threading.RLock()

    def register_relay(self, channel: str, callback: Callable[[], object]) -> None:
        """Attach the physical mechanism for a channel.

        The thing that was missing entirely: without this, nothing in this module
        could ever have touched hardware, while reporting that it had.
        """
        if channel not in self._relays:
            raise ValueError(
                f"unknown isolation channel {channel!r}; expected one of "
                f"{sorted(self._relays)}")
        if not callable(callback):
            raise TypeError("an isolation relay must be callable")
        with self._lock:
            self._relays[channel].append(callback)

    def _record(self, action: str, confirmed: bool, detail: str = "") -> dict:
        entry = {"action": action, "confirmed": confirmed, "detail": detail,
                 "timestamp": _now()}
        with self._lock:
            self._log.append(entry)
            if len(self._log) > self._max_log:
                drop = len(self._log) - self._max_log
                del self._log[:drop]
                self._dropped += drop
        return entry

    def _fire(self, channel: str, achieved: str, unconfirmed: str) -> dict:
        with self._lock:
            callbacks = list(self._relays[channel])
        if not callbacks:
            self._record(unconfirmed, False,
                         "NO RELAY REGISTERED — nothing physical was commanded")
            return {"status": unconfirmed, "confirmed": False,
                    "failures": [f"{channel}: NO RELAY REGISTERED — nothing "
                                 f"physical was commanded on this channel"]}
        failures = []
        confirmed = False
        for cb in callbacks:
            try:
                cb()
                confirmed = True
            except Exception as e:
                failures.append(f"{channel}: relay raised — {e}")
        # A relay that raised is a fault even if another one returned: the deployment
        # registered it because it was needed.
        ok = confirmed and not failures
        status = achieved if ok else unconfirmed
        self._record(status, ok, "; ".join(failures))
        return {"status": status, "confirmed": ok, "failures": failures}

    def isolate_energy_system(self) -> dict:
        return self._fire(self.ENERGY, "ENERGY_ISOLATED",
                          "ENERGY_ISOLATION_UNCONFIRMED")

    def cutoff_actuators(self) -> dict:
        return self._fire(self.ACTUATORS, "ACTUATORS_DISABLED",
                          "ACTUATOR_CUTOFF_UNCONFIRMED")

    def full_isolation(self) -> dict:
        """Both channels. FULLY_ISOLATED only if BOTH physically confirmed.

        Both are attempted even if the first fails — a failure to cut energy is no
        reason to leave the actuators powered as well.
        """
        e = self.isolate_energy_system()
        a = self.cutoff_actuators()
        failures = e["failures"] + a["failures"]
        confirmed = e["confirmed"] and a["confirmed"]
        result = {
            "energy": e["status"],
            "actuators": a["status"],
            "status": "FULLY_ISOLATED" if confirmed else "ISOLATION_UNCONFIRMED",
            "confirmed": confirmed,
            "failures": failures,
            "timestamp": _now(),
            "note": ("Human physical inspection required before any restart"
                     if confirmed else
                     "ISOLATION WAS NOT CONFIRMED — treat the machine as LIVE and "
                     "intervene physically. Do not read this as a stop."),
        }
        self._record(result["status"], confirmed, "; ".join(failures))
        return result

    def get_isolation_log(self) -> List[dict]:
        """A DEEP copy. The previous shallow copy shared its entry dicts, so a caller
        could rewrite the module's own record of what happened."""
        with self._lock:
            return copy.deepcopy(self._log)

    @property
    def dropped_entries(self) -> int:
        return self._dropped


# ── module-level default, preserving the original import surface ──
_default = IsolationController()


def register_relay(channel: str, callback: Callable[[], object]) -> None:
    _default.register_relay(channel, callback)


def isolate_energy_system() -> dict:
    return _default.isolate_energy_system()


def cutoff_actuators() -> dict:
    return _default.cutoff_actuators()


def full_isolation() -> dict:
    return _default.full_isolation()


def get_isolation_log() -> List[dict]:
    return _default.get_isolation_log()


def default_controller() -> IsolationController:
    return _default
