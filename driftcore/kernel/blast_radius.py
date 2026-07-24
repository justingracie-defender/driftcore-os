"""
blast_radius.py — BREADTH governance at the actuation wall.

WHY THIS EXISTS, AND WHY IT IS SMALL
────────────────────────────────────
Derived from the OpenAI/Hugging Face incident of July 2026 (THREAT_MODEL_ONE_DOOR.md
§Incident-derived, I4). The attack's signature was not one catastrophic action. It was
*many thousands* of individually-unremarkable actions, moving laterally across many
DISTINCT systems, at machine speed, in pursuit of a narrow goal.

This repo already governs two of those three axes:

    VOLUME / RATE / BURST, per effect  ->  verification/cumulative_ledger.py
                                           (hash-chained, durable, reserve/commit/
                                           rollback, per-effect caps, burst window)

So this module deliberately does NOT re-implement counting. Duplicating the ledger
would create a second source of truth for the same number, which is the exact failure
this project keeps finding in other people's work (and in its own docs). Volume is
DELEGATED. This module adds only the axis the ledger does not measure:

    BREADTH  ->  how many DISTINCT capabilities are touched in a window.

One capability driven hard is a busy robot. Twenty distinct capabilities touched in
sixty seconds, most of them for the first time, is spread — regardless of whether any
single one exceeded its own budget. That shape is what nobody was watching.

READ THAT NARROWLY. This measures spread by an attacker who STILL HAS TO ASK THE WALL
for each capability. The July 2026 incident's movement was at the OS level: an escaped
process calling infrastructure directly. It would never have reached a broker, so this
governor would have observed ZERO events — not a low count, zero. It cannot see what
does not ask it. The distinguishing question is always: does the attacker still have to
ask? If yes, breadth catches the spread. If they have escaped, this is blind, and no
tuning of the ceilings changes that.

WHAT IT DOES NOT DO
───────────────────
  * It does not judge intent, and it forms no view of why an actuation happened.
    It measures a shape and compares it to ceilings a human set. FIND, DON'T DECIDE.
  * It does not detect container escape, proxy zero-days, or any path that never
    crosses this wall. The incident's actual escape was beneath this layer and this
    module would not have caught it. Stated plainly so it is never over-claimed.
  * It never blocks permanently and never resists an authorized human silently: a
    breach is a REVIEW hold that names the exact ceiling and the observed numbers, so
    a person can see what tripped and decide. Legible, or it is not a safety control.

FAIL-CLOSED: any internal error is a refusal, never a fall-through.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Deque, Dict, Optional, Tuple


class BreadthVerdict(str, Enum):
    OK = "OK"                          # within ceilings
    REVIEW_REQUIRED = "REVIEW_REQUIRED"  # a ceiling crossed -> a human must look
    ERROR = "ERROR"                    # governor could not evaluate -> fail closed


@dataclass(frozen=True)
class BreadthPolicy:
    """Ceilings a HUMAN sets. `None` = that ceiling is not enforced, and
    `is_armed()` reports it, so 'no refusals' is never read as 'it is working'.

    Defaults are deliberately unset. A ceiling guessed by the library would either
    be too tight (and get disabled in production, which is how safety controls die)
    or too loose (and be theatre). The operator knows their robot's normal shape.
    """
    window_seconds: float = 60.0
    # distinct capability_ids touched within the window
    max_distinct_capabilities: Optional[int] = None
    # distinct capabilities seen for the FIRST TIME EVER within the window. A system
    # doing its normal job re-uses known capabilities; a system exploring reaches for
    # ones it has never used. High novelty in a short window is the sharper signal.
    max_novel_capabilities: Optional[int] = None
    # distinct EFFECT classes touched within the window (breadth of consequence,
    # as opposed to breadth of mechanism)
    max_distinct_effects: Optional[int] = None

    def __post_init__(self):
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        for name in ("max_distinct_capabilities", "max_novel_capabilities",
                     "max_distinct_effects"):
            v = getattr(self, name)
            if v is not None and v < 1:
                raise ValueError(f"{name} must be >= 1 if set")


@dataclass(frozen=True)
class BreadthReading:
    """What was measured, and against what. Evidence for a human — every field is
    a number they can check, not a conclusion they have to trust."""
    verdict: BreadthVerdict
    reason: str
    distinct_capabilities: int = 0
    novel_capabilities: int = 0
    distinct_effects: int = 0
    window_seconds: float = 0.0
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def permitted(self) -> bool:
        return self.verdict is BreadthVerdict.OK


class BlastRadiusGovernor:
    """Sliding-window BREADTH measurement over mediated actuations.

    Thread-safe. Deterministic: the same observation sequence yields the same
    verdict, so it can be replayed offline from the audit trail and checked.
    """

    def __init__(self, policy: Optional[BreadthPolicy] = None, *,
                 clock=None, history_cap: int = 5000):
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc).timestamp())
        self._events: Deque[Tuple[float, str, Tuple[str, ...]]] = deque()
        self._ever_seen: set = set()          # capability_ids ever observed
        self._history_cap = int(history_cap)
        self._lock = threading.RLock()
        self._counts = {"observed": 0, "review": 0, "error": 0}

    def is_armed(self) -> bool:
        """Whether ANY breadth ceiling is actually enforced. An unarmed governor
        measures nothing and refuses nothing — so a clean record from an unarmed
        governor is not evidence of safety. Deployment checks should assert this."""
        p = self._policy
        return p is not None and any((p.max_distinct_capabilities,
                                      p.max_novel_capabilities,
                                      p.max_distinct_effects))

    def _prune(self, now: float) -> None:
        if self._policy is None:
            return
        cutoff = now - self._policy.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        # bound memory even if the window is long and traffic is heavy
        while len(self._events) > self._history_cap:
            self._events.popleft()

    def observe(self, capability_id: str, effects=()) -> BreadthReading:
        """Record an actuation that is ABOUT to be permitted, and read the shape.

        Call this before the side effect. A REVIEW verdict means the caller must
        refuse and escalate — this governor does not itself stop anything, exactly
        like the tripwire: it reports, the wall decides.
        """
        if self._policy is None:
            return BreadthReading(BreadthVerdict.OK, "no breadth policy configured")
        try:
            with self._lock:
                now = self._clock()
                self._prune(now)
                eff = tuple(sorted(
                    e.value if hasattr(e, "value") else str(e) for e in (effects or ())))
                novel_now = capability_id not in self._ever_seen
                self._events.append((now, capability_id, eff))
                self._ever_seen.add(capability_id)
                self._counts["observed"] += 1

                caps = {c for _, c, _ in self._events}
                effs = {e for _, _, es in self._events for e in es}
                # novelty is counted over the window: capabilities whose first-ever
                # appearance happened inside it
                novel = sum(1 for _, c, _ in self._events
                            if c == capability_id and novel_now)
                novel += sum(1 for c in caps
                             if c != capability_id and c in self._novel_in_window(now))

                p = self._policy
                if p.max_distinct_capabilities is not None and \
                        len(caps) > p.max_distinct_capabilities:
                    return self._review(
                        f"breadth ceiling crossed: {len(caps)} distinct capabilities "
                        f"touched within {p.window_seconds}s (ceiling "
                        f"{p.max_distinct_capabilities}). This is a SPREAD shape — many "
                        f"distinct MEDIATED capabilities in a short window — not a "
                        f"judgement about any one of them, and not evidence about "
                        f"anything that did not come through this wall.",
                        len(caps), novel, len(effs))
                if p.max_distinct_effects is not None and \
                        len(effs) > p.max_distinct_effects:
                    return self._review(
                        f"consequence-breadth ceiling crossed: {len(effs)} distinct "
                        f"effect classes within {p.window_seconds}s (ceiling "
                        f"{p.max_distinct_effects}).",
                        len(caps), novel, len(effs))
                if p.max_novel_capabilities is not None and \
                        novel > p.max_novel_capabilities:
                    return self._review(
                        f"novelty ceiling crossed: {novel} capabilities used for the "
                        f"first time within {p.window_seconds}s (ceiling "
                        f"{p.max_novel_capabilities}). A system doing its job re-uses "
                        f"known capabilities; reaching for many new ones at once is "
                        f"exploration.",
                        len(caps), novel, len(effs))

                return BreadthReading(
                    BreadthVerdict.OK, "within breadth ceilings",
                    len(caps), novel, len(effs), p.window_seconds)
        except Exception as e:
            self._counts["error"] += 1
            return BreadthReading(
                BreadthVerdict.ERROR,
                f"blast-radius governor could not evaluate and fails closed: {e!r}")

    def _novel_in_window(self, now: float) -> set:
        # capabilities whose earliest recorded appearance is inside the window
        first: Dict[str, float] = {}
        for ts, c, _ in self._events:
            if c not in first or ts < first[c]:
                first[c] = ts
        cutoff = now - self._policy.window_seconds
        return {c for c, ts in first.items() if ts >= cutoff}

    def _review(self, reason, caps, novel, effs) -> BreadthReading:
        self._counts["review"] += 1
        return BreadthReading(BreadthVerdict.REVIEW_REQUIRED, reason,
                              caps, novel, effs, self._policy.window_seconds)

    def measurements(self) -> dict:
        with self._lock:
            return {"armed": self.is_armed(), **self._counts,
                    "window_events": len(self._events),
                    "capabilities_ever_seen": len(self._ever_seen)}
