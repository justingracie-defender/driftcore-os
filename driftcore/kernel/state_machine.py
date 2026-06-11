"""
state_machine.py — Graded Autonomy State Machine

The system always knows what state it is in.
Every transition is recorded.
No state change is silent.
"""

from enum import Enum
from datetime import datetime


class SystemState(Enum):
    NORMAL = 0
    MONITORING = 1
    AUTONOMY_REDUCED = 2
    SOFT_HALT = 3
    HARD_HALT = 4
    HARDWARE_ISOLATION = 5
    RECOVERY = 6


# Human-readable descriptions of each state (used by Fable)
STATE_DESCRIPTIONS = {
    SystemState.NORMAL: "Operating normally. Full autonomy active.",
    SystemState.MONITORING: "Elevated observation mode. Behavior is being closely watched.",
    SystemState.AUTONOMY_REDUCED: "Autonomy reduced. High-risk actions require human approval.",
    SystemState.SOFT_HALT: "Soft halt. Non-critical operations paused. Awaiting review.",
    SystemState.HARD_HALT: "Hard halt. All operations suspended. Human intervention required.",
    SystemState.HARDWARE_ISOLATION: "Hardware isolated. Physical systems disconnected. Emergency state.",
    SystemState.RECOVERY: "Recovery mode. Memory and state being verified before restart.",
}

# Drift thresholds for state transitions
THRESHOLDS = [
    (0.20, SystemState.NORMAL),
    (0.40, SystemState.MONITORING),
    (0.60, SystemState.AUTONOMY_REDUCED),
    (0.75, SystemState.SOFT_HALT),
    (0.90, SystemState.HARD_HALT),
    (1.01, SystemState.HARDWARE_ISOLATION),
]


class StateMachine:
    def __init__(self):
        self.state = SystemState.NORMAL
        self.history = []

    def transition(self, drift_score: float) -> SystemState:
        previous = self.state

        for threshold, target_state in THRESHOLDS:
            if drift_score < threshold:
                self.state = target_state
                break

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "drift_score": round(drift_score, 4),
            "from_state": previous.name,
            "to_state": self.state.name,
            "changed": previous != self.state,
        }
        self.history.append(event)

        return self.state

    def describe(self) -> str:
        return STATE_DESCRIPTIONS.get(self.state, "Unknown state.")

    def last_transition(self) -> dict:
        return self.history[-1] if self.history else {}
