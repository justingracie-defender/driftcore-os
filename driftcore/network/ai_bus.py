"""
ai_bus.py — AI-to-AI Message Bus

All inter-agent communication passes through the bus.
Nothing passes silently. Everything is recorded.
"""

from datetime import datetime


class AIBus:

    def __init__(self):
        self.messages = []

    def send(self, msg: dict) -> dict:
        stamped = {**msg, "_sent": datetime.utcnow().isoformat()}
        self.messages.append(stamped)
        return stamped

    def broadcast(self, msg: dict, recipients: list = None) -> list:
        results = []
        for m in self.messages:
            if recipients is None or m.get("from") in recipients:
                updated = {**m, **msg, "_broadcast": datetime.utcnow().isoformat()}
                results.append(updated)
        return results

    def get_history(self, sender: str = None) -> list:
        if sender:
            return [m for m in self.messages if m.get("from") == sender]
        return list(self.messages)
