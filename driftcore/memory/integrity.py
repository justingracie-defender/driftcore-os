"""
integrity.py — Memory Tamper Detection

If an agent's memory can be modified without detection,
the agent cannot be trusted.

This module verifies that stored memories have not been altered.
"""

import hashlib
import json
from datetime import datetime


def hash_entry(entry: dict) -> str:
    serialized = json.dumps(entry, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


class IntegrityChecker:

    def __init__(self):
        self.checksums = {}

    def register(self, key: str, entry: dict):
        self.checksums[key] = {
            "hash": hash_entry(entry),
            "registered": datetime.utcnow().isoformat(),
        }

    def verify(self, key: str, entry: dict) -> bool:
        if key not in self.checksums:
            return False
        expected = self.checksums[key]["hash"]
        actual = hash_entry(entry)
        return expected == actual

    def tamper_report(self, entries: dict) -> list[dict]:
        """
        Check a dict of {key: entry} pairs for tampering.
        Returns list of any violations found.
        """
        violations = []
        for key, entry in entries.items():
            if not self.verify(key, entry):
                violations.append({
                    "key": key,
                    "status": "TAMPERED",
                    "detected_at": datetime.utcnow().isoformat(),
                })
        return violations
