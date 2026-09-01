"""
state_machine.py — Graded Autonomy State Machine

The system always knows what state it is in.
Every transition is recorded.
No state change is silent.
Safety states escalate; they do not drift back down on their own.

CLAIM worst-input-escalates: a drift score above every threshold produces the
MAXIMUM state, never a lower one and never no change.
CLAIM halt-does-not-self-clear: once at SOFT_HALT or above, a lower drift score
cannot return the machine to a less severe state without an explicit human release.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests. All reproduced against the running code before any change.

1. THE WORST INPUT PRODUCED NO ESCALATION. The threshold table ended at
   `(1.01, HARDWARE_ISOLATION)` and the loop was `if drift_score < threshold: ...
   break`. A drift score of 1.50 matched NOTHING, so the loop fell through without
   ever assigning `self.state` and the machine stayed exactly where it was.
   Reproduced: `transition(1.50)` from NORMAL returned NORMAL. The single most
   alarming input a drift detector can produce was the one input that did nothing.
   `float('nan')` did the same, because every comparison against NaN is False.

2. A HALT UNDID ITSELF. After `transition(0.95)` put the machine in
   HARDWARE_ISOLATION, one `transition(0.0)` returned it to NORMAL — no human, no
   record of a release, nothing. `safe_halt.py` in this same repo is escalation-only
   for exactly this reason; this module contradicted it.

3. NEGATIVE SCORES WERE ACCEPTED as NORMAL, and a non-numeric score raised a bare
   TypeError out of the transition path rather than being refused as invalid input.

4. RECOVERY was in the enum and in STATE_DESCRIPTIONS but no drift score could
   reach it — a documented state with no path to it.

HONEST LIMIT: this module maps a drift SCORE to a state. Whether the score means
anything is the drift detector's problem, not this one's. A perfectly-behaved state
machine fed a broken score is still wrong; it will simply be wrong on the record.

Run: python3 test_state_machine.py
"""

import threading
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class SystemState(Enum):
    NORMAL = 0
    MONITORING = 1
    AUTONOMY_REDUCED = 2
    SOFT_HALT = 3
    HARD_HALT = 4
    HARDWARE_ISOLATION = 5
    RECOVERY = 6


STATE_DESCRIPTIONS = {
    SystemState.NORMAL: "Operating normally. Full autonomy active.",
    SystemState.MONITORING: "Elevated observation mode. Behavior is being closely watched.",
    SystemState.AUTONOMY_REDUCED: "Autonomy reduced. High-risk actions require human approval.",
    SystemState.SOFT_HALT: "Soft halt. Non-critical operations paused. Awaiting review.",
    SystemState.HARD_HALT: "Hard halt. All operations suspended. Human intervention required.",
    SystemState.HARDWARE_ISOLATION: "Hardware isolated. Physical systems disconnected. Emergency state.",
    SystemState.RECOVERY: "Recovery mode. Memory and state being verified before restart.",
}

# Upper bound (exclusive) -> state. The final entry is the CATCH-ALL: anything at or
# above the last named threshold is the maximum state. Previously the table simply
# ended, and scores past its end matched nothing at all.
THRESHOLDS = [
    (0.20, SystemState.NORMAL),
    (0.40, SystemState.MONITORING),
    (0.60, SystemState.AUTONOMY_REDUCED),
    (0.75, SystemState.SOFT_HALT),
    (0.90, SystemState.HARD_HALT),
]
MAX_STATE = SystemState.HARDWARE_ISOLATION

# SEVERITY IS NOT THE ENUM VALUE. (red-team, cold pass 2026-08-14 — REPRODUCED.)
# The enum is a LIST OF STATES, written before any of them had a severity ordering,
# and RECOVERY sits at value 6 — numerically above HARDWARE_ISOLATION. Using `.value`
# as severity meant the latch treated RECOVERY as the most severe state in the system:
# after `release()` landed there, a drift score of 99 returned RECOVERY, and so did
# every other score. The state a human releases INTO could neither escalate nor be
# left. That is the same fail-open this module was rewritten to remove, reintroduced
# by the fix for it.
#
# RECOVERY is a supervised operational state — "verifying before restart" — so it sits
# below the latch: it escalates freely if drift rises, and clears normally if it does
# not. Severity is now explicit rather than inherited from declaration order.
SEVERITY = {
    SystemState.NORMAL: 0,
    SystemState.MONITORING: 1,
    SystemState.RECOVERY: 2,
    SystemState.AUTONOMY_REDUCED: 2,
    SystemState.SOFT_HALT: 3,
    SystemState.HARD_HALT: 4,
    SystemState.HARDWARE_ISOLATION: 5,
}

# At or above this severity, a state only escalates. Returning below requires `release`.
LATCH_AT = SystemState.SOFT_HALT


def severity(state: SystemState) -> int:
    """Explicit severity, never the enum value.

    CLAIM severity-is-not-enum-value: severity is defined explicitly for every state
    and does not follow enum declaration order, so a state added later cannot become
    the most severe one by accident.
    """
    return SEVERITY[state]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateMachine:

    MAX_HISTORY = 2000

    def __init__(self) -> None:
        self.state = SystemState.NORMAL
        self.history: List[dict] = []
        self._dropped = 0
        self._lock = threading.RLock()

    @staticmethod
    def _score(drift_score) -> float:
        if isinstance(drift_score, bool) or not isinstance(drift_score, (int, float)):
            raise TypeError(
                f"drift_score must be a number, got {type(drift_score).__name__}. "
                f"A score the machine cannot compare is not a safe score.")
        s = float(drift_score)
        if s != s:
            # NaN compares False against everything, so it previously fell through
            # every threshold and left the machine untouched. Treat an uninterpretable
            # score as the worst case, not the best one.
            return float("inf")
        return s

    def _target(self, score: float) -> SystemState:
        if score < 0:
            raise ValueError(
                f"drift_score {score} is negative; a drift detector reporting less "
                f"than no drift is malfunctioning and its output is not usable.")
        for upper, state in THRESHOLDS:
            if score < upper:
                return state
        return MAX_STATE

    def transition(self, drift_score) -> SystemState:
        score = self._score(drift_score)
        target = self._target(score)
        with self._lock:
            previous = self.state
            if severity(previous) >= severity(LATCH_AT) and \
                    severity(target) < severity(previous):
                # Escalation-only above the latch. De-escalating out of a halt is a
                # human decision (`release`), never a consequence of one calm reading.
                new = previous
                latched = True
            else:
                new = target if severity(target) > severity(previous) or \
                    severity(previous) < severity(LATCH_AT) else previous
                latched = False
            self.state = new
            self._append({
                "timestamp": _now(),
                "drift_score": (None if score == float("inf") and drift_score != drift_score
                                else round(score, 4)),
                "raw_score_uninterpretable": drift_score != drift_score,
                "from_state": previous.name,
                "to_state": self.state.name,
                "would_have_been": target.name,
                "changed": previous != self.state,
                "held_by_latch": latched,
            })
            return self.state

    def release(self, released_by: str, to_state: SystemState = SystemState.RECOVERY) -> dict:
        """A named human lowers the state. The only way down from a halt.

        CLAIM release-is-attributed: lowering a latched state requires a named
        releaser and is recorded with that name.
        """
        if not isinstance(released_by, str) or not released_by.strip():
            raise ValueError(
                "release requires the name of whoever is releasing. An unattributed "
                "release is indistinguishable from the system releasing itself.")
        if not isinstance(to_state, SystemState):
            raise TypeError("to_state must be a SystemState")
        with self._lock:
            previous = self.state
            self.state = to_state
            self._append({
                "timestamp": _now(), "drift_score": None,
                "from_state": previous.name, "to_state": to_state.name,
                "changed": previous != to_state, "released_by": released_by,
                "held_by_latch": False, "would_have_been": to_state.name,
                "raw_score_uninterpretable": False,
            })
            return {"status": "RELEASED", "from": previous.name,
                    "to": to_state.name, "released_by": released_by}

    def _append(self, event: dict) -> None:
        self.history.append(event)
        if len(self.history) > self.MAX_HISTORY:
            drop = len(self.history) - self.MAX_HISTORY
            del self.history[:drop]
            self._dropped += drop

    @property
    def dropped_events(self) -> int:
        return self._dropped

    def describe(self) -> str:
        return STATE_DESCRIPTIONS.get(self.state, "Unknown state.")

    def last_transition(self) -> dict:
        with self._lock:
            return dict(self.history[-1]) if self.history else {}
