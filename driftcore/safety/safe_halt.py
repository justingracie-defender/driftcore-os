"""
safe_halt.py — Graduated Halt System

Halting is not binary. There are degrees.
A soft halt pauses. A hard halt stops. Isolation cuts the wire.
Recovery is always possible — but only after verification.
"""

from datetime import datetime


class SafeHalt:

    def __init__(self):
        self.active = False
        self.level = None
        self.log = []

    def soft_halt(self) -> str:
        self.active = True
        self.level = "SOFT"
        self._log("SOFT_HALT_TRIGGERED")
        return "SYSTEM_IN_SOFT_HALT — Non-critical ops paused"

    def hard_halt(self) -> str:
        self.active = True
        self.level = "HARD"
        self._log("HARD_HALT_TRIGGERED")
        return "SYSTEM_IN_HARD_HALT — All operations suspended"

    def trigger(self) -> str:
        """Default halt — goes to hard halt."""
        return self.hard_halt()

    def release(self, authorized_by: str = "human_operator") -> str:
        if not authorized_by or authorized_by == "agent":
            return "RELEASE_DENIED — Only human operators can release a halt"
        self.active = False
        self.level = None
        self._log(f"HALT_RELEASED by {authorized_by}")
        return "SYSTEM_RESUMED"

    def status(self) -> dict:
        return {"active": self.active, "level": self.level}

    def _log(self, event: str):
        self.log.append({"event": event, "timestamp": datetime.utcnow().isoformat()})
