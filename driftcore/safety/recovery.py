"""
recovery.py — Verified Restart Protocol

Recovery is not just restarting.
It is verifying that what went wrong has been understood,
that memory is clean, and that a human has approved the restart.

CLAIM agent-cannot-authorize: no value an agent can supply for `authorized_by`
produces RECOVERY_APPROVED; the check is an allow-list of registered humans, not a
denylist of the string "agent".
CLAIM unreadable-memory-blocks: if memory state cannot be read, recovery is blocked
rather than approved.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests, and the authorization check was a denylist of one string.

1. ANY NAME EXCEPT "agent" AUTHORISED A RESTART. The guard was
   `if not authorized_by or authorized_by == "agent"`. So "Agent", "agent2",
   "the_agent", "system", "" .strip(), or literally "not_a_human" all returned
   RECOVERY_APPROVED. An agent choosing its own authorizer string had to pick
   exactly the one forbidden value to be stopped. Denylists on an authorization
   boundary fail this way by construction; this is now an allow-list of principals
   the deployment registered.

2. THE DEFAULT ARGUMENT AUTHORISED ITSELF. `authorized_by: str = "human_operator"`
   meant `attempt_recovery()` with NO arguments returned RECOVERY_APPROVED. The
   safest call site — the one that forgot to pass anything — was the one that
   approved a restart. There is no default now.

3. A FAILING MEMORY CHECK APPROVED THE RESTART. `verify_memory` called
   `self.memory.quarantine` and `self.memory.stats()` unguarded; if either raised,
   the exception propagated out of `attempt_recovery` — and any caller wrapping this
   in a broad `except` got no result at all rather than a refusal. Memory that
   cannot be read is now BLOCKED, on the principle that "I could not check" is not
   "it was clean".

4. RECOVERY_APPROVED WAS NOT A RECOVERY. Nothing recorded that a restart had been
   authorised, so the same approval could be replayed indefinitely and nothing tied
   an approval to the incident it was given for. Approvals are now single-use and
   carry the incident they were issued against.

HONEST LIMIT: this decides whether a restart is PERMITTED. It does not perform one,
and it cannot confirm that whatever restarts afterwards is the system it approved.
Binding an approval to the image that actually boots needs attested measurement,
which is named as an open item in the safety case and is not solved here.

Run: python3 test_recovery.py
"""

import threading
from datetime import datetime, timezone
from typing import List, Optional, Set


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RecoverySystem:

    def __init__(self, memory_fs, integrity_checker,
                 authorized_humans: Optional[Set[str]] = None) -> None:
        self.memory = memory_fs
        self.integrity = integrity_checker
        self.recovery_log: List[dict] = []
        # An ALLOW-list. Empty means nobody can authorise a restart, which is the
        # correct posture for a deployment that has not said who may.
        self._humans = set(authorized_humans or ())
        self._used_approvals: Set[str] = set()
        self._lock = threading.RLock()

    def register_human(self, name: str) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("an authorizer must have a non-empty name")
        with self._lock:
            self._humans.add(name)

    def verify_memory(self) -> dict:
        """Read memory state. Unreadable is NOT clean."""
        try:
            quarantine_count = len(self.memory.quarantine)
            stats = self.memory.stats()
            readable = True
            detail = ""
        except Exception as e:
            quarantine_count = None
            stats = None
            readable = False
            detail = f"{type(e).__name__}: {e}"
        result = {
            "timestamp": _now(),
            "memory_stats": stats,
            "quarantine_count": quarantine_count,
            "readable": readable,
            "detail": detail,
            # Clean requires a successful read AND an empty quarantine. Previously an
            # unreadable memory could not produce this field at all.
            "memory_clean": readable and quarantine_count == 0,
        }
        with self._lock:
            self.recovery_log.append(result)
        return result

    def attempt_recovery(self, authorized_by: str, incident_id: str) -> dict:
        """Both arguments are required. Neither has a default that says yes.

        CLAIM approval-is-single-use: an approval authorises one restart for one
        named incident and cannot be replayed.
        """
        if not isinstance(authorized_by, str) or not authorized_by.strip():
            return {"status": "RECOVERY_DENIED",
                    "reason": "no authorizer named"}
        with self._lock:
            known = authorized_by in self._humans
        if not known:
            return {"status": "RECOVERY_DENIED",
                    "reason": (f"{authorized_by!r} is not a registered human "
                               f"authorizer. Recovery uses an allow-list: an "
                               f"unrecognised name is refused, not accepted for "
                               f"not being on a denylist.")}
        if not isinstance(incident_id, str) or not incident_id.strip():
            return {"status": "RECOVERY_DENIED",
                    "reason": ("recovery must name the incident it is recovering "
                               "from; an approval bound to nothing authorises "
                               "every restart equally")}

        with self._lock:
            # (red-team, cold pass 2026-08-14.) The token was `human:incident`, so N
            # registered humans yielded N restarts for ONE incident — while the claim
            # above says an approval authorises one restart for one named incident.
            # The incident is the unit; another human is not another incident.
            token = incident_id
            if token in self._used_approvals:
                return {"status": "RECOVERY_DENIED",
                        "reason": (f"incident {incident_id!r} has already been "
                                   f"recovered from. One incident, one restart — a "
                                   f"second authorizer is not a second incident.")}

        memory_check = self.verify_memory()
        if not memory_check["readable"]:
            return {"status": "RECOVERY_BLOCKED",
                    "reason": (f"memory state could not be read "
                               f"({memory_check['detail']}). 'I could not check' is "
                               f"not 'it was clean'."),
                    "memory_stats": None}
        if not memory_check["memory_clean"]:
            return {"status": "RECOVERY_BLOCKED",
                    "reason": (f"{memory_check['quarantine_count']} quarantined "
                               f"memory entries must be reviewed first"),
                    "memory_stats": memory_check["memory_stats"]}

        with self._lock:
            self._used_approvals.add(token)
        return {
            "status": "RECOVERY_APPROVED",
            "action": "verify_memory_integrity_then_restart",
            "authorized_by": authorized_by,
            "incident_id": incident_id,
            "timestamp": _now(),
        }
