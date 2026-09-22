# SPDX-License-Identifier: Apache-2.0
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


# ── log directory resolution ──────────────────────────────────────────────
# Ten test files write logs/SHUTDOWN_REASON.json and logs/CHAIN_SHUTDOWN_REASON.json
# at a fixed RELATIVE path. Run in parallel, one file's cleanup races another
# file's write and the loser reports a failure that passes when run alone.
# "Passes when run alone" is not a green suite, so the path is resolvable per
# process: set DRIFTCORE_LOG_DIR and each runner gets its own.
def _log_dir() -> str:
    import os
    return os.environ.get("DRIFTCORE_LOG_DIR", "logs")


def _log_path(name: str) -> str:
    import os
    return os.path.join(_log_dir(), name)



class AuditStory:

    def __init__(self, log_path: str = _log_path("fable_audit.log")):
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
            os.makedirs(_log_dir(), exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass  # Never let logging crash the system
