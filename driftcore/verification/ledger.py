"""
driftcore/verification/ledger.py
================================
ONE append-only, hash-chained, tamper-evident ledger (in-memory,
per-instance). The governance memory and the ruling ledger both use this,
so the chain/verify logic lives in exactly one place instead of being
copy-pasted (redundant *implementation* is the bad kind of redundancy).

This is NOT the system audit chain (`driftcore/audit`). That one is a
separate, file-backed singleton that triggers shutdown on tamper. This is
the lightweight in-memory primitive for advisory governance logs.

HONEST LIMIT: tamper-EVIDENT (detect), not OS-immutable (prevent).
"""

from typing import List
import hashlib
import json
import time


class HashChainLedger:
    GENESIS = "0" * 64

    def __init__(self):
        self._chain: List[dict] = []

    def append(self, payload: dict) -> dict:
        prev = self._chain[-1]["hash"] if self._chain else self.GENESIS
        entry = {**payload, "ts": time.time(), "prev": prev}
        entry["hash"] = hashlib.sha256(
            (prev + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
        self._chain.append(entry)
        return entry

    @property
    def chain(self) -> List[dict]:
        return self._chain

    def verify(self) -> bool:
        prev = self.GENESIS
        for e in self._chain:
            if e["prev"] != prev:
                return False
            body = {k: e[k] for k in e if k != "hash"}
            if hashlib.sha256(
                    (e["prev"] + json.dumps(body, sort_keys=True)).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def __len__(self) -> int:
        return len(self._chain)
