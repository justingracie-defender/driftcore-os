"""
trust_model.py — Bounded Reciprocal Trust

Trust starts in the middle (0.5).
It rises slowly. It falls quickly.
It cannot exceed 1.0 or fall below 0.0.
An agent that fails repeatedly becomes untrusted.
An untrusted agent is quarantined, not destroyed — it can recover, but a human
decides when.

CLAIM one-violation-quarantines: a single safety violation quarantines an agent
regardless of accumulated trust.
CLAIM quarantine-latches: quarantine is cleared only by a named human, never by
subsequent successes.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests. All four were reproduced against the running code before any change.

1. ONE SAFETY VIOLATION DID NOT QUARANTINE. The constants encode the intent exactly:
   INITIAL_TRUST 0.5 minus SAFETY_VIOLATION_PENALTY 0.30 is 0.20, and
   QUARANTINE_THRESHOLD is 0.20. But the test was `trust < THRESHOLD`, so an agent
   landing precisely on the threshold the constants were tuned to produce was NOT
   quarantined. An off-by-one on a safety boundary — and because 0.5 - 0.30 == 0.20
   exactly in binary floating point, it failed every single time rather than
   intermittently. The comparison is now inclusive.

2. A SAFETY VIOLATION WAS CANCELLABLE BY ROUTINE SUCCESS. Six ordinary successes
   (+0.05 each) restored exactly the 0.30 a violation removed, so an agent that
   violated safety once per six successful actions kept full trust indefinitely.
   A safety violation is not a quality of service to be averaged against good days.
   It now quarantines immediately, independently of the score.

3. QUARANTINE LEAKED AWAY. There was no hysteresis: an agent could cross back over
   the threshold on a single success and oscillate. Quarantine now LATCHES and is
   cleared only by `release_quarantine`, which requires a named human AND a score
   that has genuinely recovered.

4. ANY OBJECT COULD BE AN AGENT. `None` and `""` were accepted as identities and
   silently created entries. An agent nobody can name is an agent nobody can
   quarantine.

HONEST LIMIT, and a real one: `trust` is a public dict, and `fable/trust_bridge`
writes to it DIRECTLY rather than through `update()` — recording no history and
tripping no latch, while its own docstring says it must not silently change trust
values. `is_quarantined` therefore also tests the live score, so a direct write that
drops an agent below the threshold still quarantines. What a direct write cannot do
is un-quarantine a latched agent: the latch is not reachable from the dict.

Run: python3 test_trust_model.py
"""

import threading
from typing import Dict, List, Optional


class TrustModel:

    INITIAL_TRUST = 0.5
    SUCCESS_GAIN = 0.05
    FAILURE_PENALTY = 0.10
    SAFETY_VIOLATION_PENALTY = 0.30
    QUARANTINE_THRESHOLD = 0.20
    # Hysteresis. Leaving quarantine requires materially more than the score that
    # entered it, so an agent cannot chatter across the boundary on single events.
    RELEASE_THRESHOLD = 0.50
    MAX_HISTORY = 1000

    def __init__(self) -> None:
        # Public for existing consumers (agent_protocol reads it, trust_bridge writes
        # it). Kept a plain dict deliberately rather than hidden behind a property:
        # breaking those callers silently would be worse than the limit noted above.
        self.trust: Dict[str, float] = {}
        self.history: Dict[str, List[dict]] = {}
        self._quarantined: Dict[str, str] = {}
        self._violations: Dict[str, int] = {}
        self._dropped: Dict[str, int] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _check_agent(agent) -> str:
        if not isinstance(agent, str) or not agent.strip():
            raise ValueError(
                f"agent must be a non-empty string, got {agent!r}. An agent nobody "
                f"can name is an agent nobody can quarantine.")
        return agent

    def update(self, agent: str, success: bool, safety_violation: bool = False) -> None:
        agent = self._check_agent(agent)
        with self._lock:
            self.trust.setdefault(agent, self.INITIAL_TRUST)
            self.history.setdefault(agent, [])

            if safety_violation:
                delta = -self.SAFETY_VIOLATION_PENALTY
            elif success:
                delta = self.SUCCESS_GAIN
            else:
                delta = -self.FAILURE_PENALTY

            self.trust[agent] = round(
                max(0.0, min(1.0, self.trust[agent] + delta)), 4)

            if safety_violation:
                self._violations[agent] = self._violations.get(agent, 0) + 1
                # setdefault pinned the FIRST reason, so an agent already quarantined
                # for low trust that then violated safety still read "trust fell to
                # 0.2". The more serious cause must be the one an operator sees.
                self._quarantined[agent] = (
                    f"safety violation #{self._violations[agent]}")
            elif self.trust[agent] <= self.QUARANTINE_THRESHOLD:
                self._quarantined.setdefault(
                    agent, f"trust fell to {self.trust[agent]}")

            h = self.history[agent]
            h.append({
                "success": success,
                "safety_violation": safety_violation,
                "trust_after": self.trust[agent],
                "quarantined_after": agent in self._quarantined,
            })
            if len(h) > self.MAX_HISTORY:
                # Bounded: a long-running process must not be exhaustible by an agent
                # that simply keeps acting. The dropped count is kept so the record
                # never silently understates activity.
                drop = len(h) - self.MAX_HISTORY
                del h[:drop]
                self._dropped[agent] = self._dropped.get(agent, 0) + drop

    def is_quarantined(self, agent: str) -> bool:
        """Latched quarantine OR a live score at/below the threshold.

        Both, because the score can be written directly by other modules without
        going through `update()`. Testing only the latch would let a direct write
        drop an agent to 0.0 while this reported it as fine.
        """
        if not isinstance(agent, str):
            return False
        with self._lock:
            if agent in self._quarantined:
                return True
            return self.trust.get(
                agent, self.INITIAL_TRUST) <= self.QUARANTINE_THRESHOLD

    def quarantine_reason(self, agent: str) -> Optional[str]:
        with self._lock:
            if agent in self._quarantined:
                return self._quarantined[agent]
            score = self.trust.get(agent, self.INITIAL_TRUST)
            if score <= self.QUARANTINE_THRESHOLD:
                return f"trust is {score}"
            return None

    def release_quarantine(self, agent: str, released_by: str) -> dict:
        """A named human releases an agent. Recovery is possible; it is not automatic.

        Refused while the score is still low, so releasing cannot be a shortcut past
        the recovery it is supposed to represent.
        """
        agent = self._check_agent(agent)
        if not isinstance(released_by, str) or not released_by.strip():
            raise ValueError(
                "release_quarantine requires the name of whoever is releasing. An "
                "unattributable release is indistinguishable from the agent "
                "releasing itself.")
        with self._lock:
            score = self.trust.get(agent, self.INITIAL_TRUST)
            if score < self.RELEASE_THRESHOLD:
                raise PermissionError(
                    f"agent {agent!r} is at {score} and cannot be released below "
                    f"{self.RELEASE_THRESHOLD}. Let it earn the score back first — "
                    f"releasing it now would make the threshold decorative.")
            self._quarantined.pop(agent, None)
            self.history.setdefault(agent, []).append({
                "success": True, "safety_violation": False,
                "trust_after": score, "quarantined_after": False,
                "released_by": released_by,
            })
            return {"status": "RELEASED", "agent": agent,
                    "released_by": released_by, "trust": score}

    def summary(self) -> dict:
        with self._lock:
            agents = set(self.trust) | set(self._quarantined)
            return {
                agent: {
                    "trust": self.trust.get(agent, self.INITIAL_TRUST),
                    "quarantined": self.is_quarantined(agent),
                    "reason": self.quarantine_reason(agent),
                    "safety_violations": self._violations.get(agent, 0),
                    "history_dropped": self._dropped.get(agent, 0),
                }
                for agent in sorted(agents)
            }
