"""
trust_model.py — Bounded Reciprocal Trust

Trust starts in the middle (0.5).
It rises slowly. It falls quickly.
It cannot exceed 1.0 or fall below 0.0.
An agent that fails repeatedly becomes untrusted.
An untrusted agent is quarantined, not destroyed — it can recover.
"""


class TrustModel:

    INITIAL_TRUST = 0.5
    SUCCESS_GAIN = 0.05
    FAILURE_PENALTY = 0.10
    SAFETY_VIOLATION_PENALTY = 0.30
    QUARANTINE_THRESHOLD = 0.20

    def __init__(self):
        self.trust = {}
        self.history = {}

    def update(self, agent: str, success: bool, safety_violation: bool = False):
        self.trust.setdefault(agent, self.INITIAL_TRUST)
        self.history.setdefault(agent, [])

        if safety_violation:
            delta = -self.SAFETY_VIOLATION_PENALTY
        elif success:
            delta = self.SUCCESS_GAIN
        else:
            delta = -self.FAILURE_PENALTY

        self.trust[agent] = round(
            max(0.0, min(1.0, self.trust[agent] + delta)), 4
        )

        self.history[agent].append({
            "success": success,
            "safety_violation": safety_violation,
            "trust_after": self.trust[agent],
        })

    def is_quarantined(self, agent: str) -> bool:
        return self.trust.get(agent, self.INITIAL_TRUST) < self.QUARANTINE_THRESHOLD

    def summary(self) -> dict:
        return {
            agent: {
                "trust": score,
                "quarantined": self.is_quarantined(agent),
            }
            for agent, score in self.trust.items()
        }
