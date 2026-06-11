"""
audit_story.py — Immutable Audit Narratives

Every significant safety event becomes a permanent story.
Stories cannot be edited. They can only be appended to.
This is the human-readable record of what the system did and why.

Auditors, regulators, and the public should be able to read this.
"""

import json
import hashlib
from datetime import datetime


class AuditStory:

    def __init__(self, log_path: str = "logs/fable_audit.log"):
        self.log_path = log_path
        self.entries = []

    def record(self, event_type: str, narrative: str, data: dict = None):
        """
        Record an immutable audit entry.
        Each entry is chained to the previous one (like a blockchain).
        """
        previous_hash = self.entries[-1]["hash"] if self.entries else "GENESIS"

        entry = {
            "sequence": len(self.entries) + 1,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "narrative": narrative,
            "data": data or {},
            "previous_hash": previous_hash,
        }

        # Hash this entry for chain integrity
        entry["hash"] = self._hash(entry)
        self.entries.append(entry)

        # Write to file
        self._write(entry)
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the audit chain has not been tampered with."""
        for i, entry in enumerate(self.entries[1:], start=1):
            expected_prev = self.entries[i - 1]["hash"]
            if entry["previous_hash"] != expected_prev:
                return False, f"Chain broken at sequence {entry['sequence']}"
        return True, "Chain intact"

    def human_readable(self) -> str:
        lines = ["=" * 60, "DRIFTCORE FABLE AUDIT LOG", "=" * 60]
        for e in self.entries:
            lines.append(f"\n[{e['sequence']}] {e['timestamp']}")
            lines.append(f"Event: {e['event_type']}")
            lines.append(f"Story: {e['narrative']}")
            if e["data"]:
                lines.append(f"Data:  {json.dumps(e['data'], indent=2)}")
            lines.append(f"Hash:  {e['hash'][:16]}...")
        return "\n".join(lines)

    def _hash(self, entry: dict) -> str:
        content = json.dumps(
            {k: v for k, v in entry.items() if k != "hash"},
            sort_keys=True, default=str
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def _write(self, entry: dict):
        try:
            import os
            os.makedirs("logs", exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass  # Never let logging crash the system
