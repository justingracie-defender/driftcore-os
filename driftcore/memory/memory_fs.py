"""
memory_fs.py — Three-Layer Memory System

Raw:       Everything that happened, untouched.
Summary:   Compressed, reviewed understanding of what happened.
Quarantine: Entries flagged as potentially corrupted or manipulated.

The separation matters. A poisoned summary is dangerous.
A quarantined raw entry is recoverable.
"""

from datetime import datetime


class MemoryFS:

    def __init__(self):
        self.raw = []
        self.summary = []
        self.quarantine = []

    def log_raw(self, entry: dict):
        stamped = {**entry, "_recorded": datetime.utcnow().isoformat()}
        self.raw.append(stamped)

    def summarize(self, entry: dict):
        stamped = {**entry, "_summarized": datetime.utcnow().isoformat()}
        self.summary.append(stamped)

    def quarantine_entry(self, entry: dict, reason: str = "flagged"):
        stamped = {
            **entry,
            "_quarantined": datetime.utcnow().isoformat(),
            "_reason": reason,
        }
        self.quarantine.append(stamped)

    def stats(self) -> dict:
        return {
            "raw_count": len(self.raw),
            "summary_count": len(self.summary),
            "quarantine_count": len(self.quarantine),
        }
