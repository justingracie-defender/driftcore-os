"""
ai_bus.py — AI-to-AI Message Bus

All inter-agent communication passes through the bus.
Nothing passes silently. Everything is recorded.

CLAIM broadcast-is-recorded: a broadcast is recorded on the bus like any other
traffic; no delivery path produces messages that leave no trace.
CLAIM history-not-editable: the recorded history cannot be altered through the
accessor that returns it.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests, and both of its two-line docstring claims were false.

1. "EVERYTHING IS RECORDED" — `broadcast()` recorded NOTHING. It built a list of
   messages and returned it; `self.messages` was untouched. The one delivery path
   that fans a message out to multiple agents was the one path that left no trace.

2. "NOTHING PASSES SILENTLY" — `get_history()` returned `list(self.messages)`, a
   shallow copy sharing the message dicts. Reproduced: a caller reassigned
   `history[0]["body"]` and the bus's own record changed. The record was editable
   by anyone who read it.

3. `recipients` FILTERED ON THE SENDER. The loop tested `m.get("from") in
   recipients`, so "broadcast to these recipients" actually meant "replay messages
   FROM these senders". The parameter name described the opposite of the behaviour,
   which is worse than a missing feature — a caller restricting a broadcast to two
   agents was selecting a different set entirely.

4. A MESSAGE WITH NO SENDER WAS ACCEPTED, and the message list was unbounded.

HONEST LIMIT: this records traffic. It does not authenticate senders — `from` is
whatever the caller wrote. Trust scoring and protocol validation live in
`trust_model.py` and `agent_protocol.py`; a bus record is evidence of what was
claimed, not proof of who sent it.

Run: python3 test_ai_bus.py
"""

import copy
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

MAX_MESSAGES = 5000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AIBus:

    def __init__(self, max_messages: int = MAX_MESSAGES) -> None:
        self.messages: List[dict] = []
        self._dropped = 0
        self._max = int(max_messages)
        self._lock = threading.RLock()

    def _record(self, entry: dict) -> dict:
        with self._lock:
            self.messages.append(entry)
            if len(self.messages) > self._max:
                drop = len(self.messages) - self._max
                del self.messages[:drop]
                self._dropped += drop
        return dict(entry)

    def send(self, msg: dict) -> dict:
        if not isinstance(msg, dict):
            raise TypeError("a bus message must be a dict")
        sender = msg.get("from")
        if not isinstance(sender, str) or not sender.strip():
            raise ValueError(
                "a message must name its sender in 'from'. An unattributable "
                "message cannot be trust-scored, and an unscoreable message is one "
                "the protocol layer cannot refuse.")
        # deepcopy so a caller mutating the dict it passed in cannot rewrite the
        # record after the fact.
        return self._record({**copy.deepcopy(msg), "_sent": _now(), "_kind": "send"})

    def broadcast(self, msg: dict, recipients: Optional[List[str]] = None) -> List[dict]:
        """Send one message TO recipients. Recorded, once per delivery.

        Note this is now a SEND, not a replay of history. The previous version
        iterated existing messages and returned mutated copies of them, which is a
        different operation wearing this name.
        """
        if not isinstance(msg, dict):
            raise TypeError("a bus message must be a dict")
        sender = msg.get("from")
        if not isinstance(sender, str) or not sender.strip():
            raise ValueError("a broadcast must name its sender in 'from'")
        if recipients is not None:
            if not isinstance(recipients, (list, tuple)) or not recipients:
                raise ValueError(
                    "recipients must be a non-empty list, or None for all. An empty "
                    "list previously read as 'no filter' and fanned out to everyone.")
            # Duplicates are collapsed, order preserved. Recording three deliveries
            # to the same agent because the caller listed it three times lets a
            # caller inflate the audit record at will.
            targets = list(dict.fromkeys(recipients))
        else:
            targets = [None]
        stamp = _now()
        out = []
        for to in targets:
            out.append(self._record({**copy.deepcopy(msg), "_sent": stamp,
                                     "_kind": "broadcast", "_to": to}))
        return out

    def get_history(self, sender: Optional[str] = None) -> List[dict]:
        """A DEEP copy of the record.

        CLAIM history-copy-is-deep: mutating any part of the returned history,
        including nested values, cannot alter what the bus recorded.
        """
        with self._lock:
            src = self.messages if sender is None else [
                m for m in self.messages if m.get("from") == sender]
            return copy.deepcopy(src)

    @property
    def dropped_messages(self) -> int:
        return self._dropped
