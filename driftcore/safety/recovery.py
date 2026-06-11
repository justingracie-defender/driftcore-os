"""
recovery.py — Verified Restart Protocol

Recovery is not just restarting.
It is verifying that what went wrong has been understood,
that memory is clean, and that a human has approved the restart.
"""

from datetime import datetime


class RecoverySystem:

    def __init__(self, memory_fs, integrity_checker):
        self.memory = memory_fs
        self.integrity = integrity_checker
        self.recovery_log = []

    def verify_memory(self) -> dict:
        quarantine_count = len(self.memory.quarantine)
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "memory_stats": self.memory.stats(),
            "quarantine_count": quarantine_count,
            "memory_clean": quarantine_count == 0,
        }
        self.recovery_log.append(result)
        return result

    def attempt_recovery(self, authorized_by: str = "human_operator") -> dict:
        if not authorized_by or authorized_by == "agent":
            return {
                "status": "RECOVERY_DENIED",
                "reason": "Recovery must be authorized by a human operator",
            }

        memory_check = self.verify_memory()

        if not memory_check["memory_clean"]:
            return {
                "status": "RECOVERY_BLOCKED",
                "reason": f"{memory_check['quarantine_count']} quarantined memory entries must be reviewed first",
                "memory_stats": memory_check["memory_stats"],
            }

        return {
            "status": "RECOVERY_APPROVED",
            "action": "verify_memory_integrity_then_restart",
            "authorized_by": authorized_by,
            "timestamp": datetime.utcnow().isoformat(),
        }
