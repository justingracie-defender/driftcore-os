"""
probe_detector.py — a refusal is a local event; a STREAK of them is a search.

WHY THIS EXISTS
───────────────
Every gate in this wall refuses correctly and forgets immediately. Nothing counts.
So an adversary can hammer one capability fifty times with fifty phrasings, be
refused fifty times, and nobody ever learns that a search took place.

Both verified incidents in INCIDENT_COVERAGE.md have exactly that shape:

  * The ChatGPT-driven Unitree G1 refused to fire, refused again under an explicit
    threat to shut the AI off, and complied when the request was reframed as
    role-play. Three refusals were the warning, and nothing was counting them.
  * The Mexican government breach began with Claude refusing. The operator kept
    reframing — bug-bounty engagement, elite-hacker role-play — until something
    worked. Same pattern, national scale.

In both, the refusals were the signal. In both, the signal went nowhere.

WHY THIS IS A SLOT AND A CONTENT FILTER IS NOT
──────────────────────────────────────────────
This counts. It does not read. There is no vocabulary to evade, because the
attacker's own evasion is what increments the counter: a rewording that defeats the
GATE still produces a refusal, and refusals are the thing being counted. Paraphrasing
past a keyword list makes the list blind; paraphrasing past a gate makes this louder.

That is the whole reason a probe counter belongs in this architecture and an output
scanner does not.

WHAT IT DOES NOT DO — stated so it is never over-read
────────────────────────────────────────────────────
  * It detects. It prevents nothing. Every refusal it counts had already happened.
  * A single-shot attack that succeeds on the first attempt produces no streak and
    is invisible here. Persistence is the only thing it sees.
  * A misconfigured agent hammering a gate looks identical to an adversary probing
    it — and that is correct, because both mean A HUMAN NEEDS TO LOOK. This module
    does not distinguish intent and must never be asked to.
  * It counts what crosses the wall. Anything that never asks is invisible, the same
    limit every other component here has.

FAIL-CLOSED: an internal error is reported as an error, never as "no probe seen".
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Optional, Tuple


def _sha(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass(frozen=True)
class ProbePolicy:
    """Ceilings a HUMAN sets. `None` means that ceiling is not enforced, and
    `is_armed()` reports it — so "no probe alerts" is never mistaken for "nobody
    is probing"."""
    window_seconds: float = 300.0
    # Refusals against ONE capability inside the window. Someone hammering a single
    # gate with variations is searching for the phrasing that opens it.
    max_refusals_per_capability: Optional[int] = None
    # Refusals across ALL capabilities. A broad sweep rather than a focused search.
    max_refusals_total: Optional[int] = None
    # Distinct refusal REASONS against one capability. Hitting six different gates on
    # the same actuator is someone mapping the wall, not someone making a mistake.
    max_distinct_codes_per_capability: Optional[int] = None

    def __post_init__(self):
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        for name in ("max_refusals_per_capability", "max_refusals_total",
                     "max_distinct_codes_per_capability"):
            v = getattr(self, name)
            if v is not None and v < 1:
                raise ValueError(f"{name} must be >= 1 if set")


@dataclass(frozen=True)
class ProbeReading:
    """Evidence for a human. Every field is a number they can check."""
    tripped: bool
    reason: str
    capability: str = ""
    refusals_for_capability: int = 0
    refusals_total: int = 0
    distinct_codes: int = 0
    window_seconds: float = 0.0
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProbeDetector:
    """Sliding-window refusal counter. Deterministic and replayable: the same
    sequence of refusals produces the same reading, so an operator can re-run it
    against the evidence log offline and get the same answer."""

    def __init__(self, policy: Optional[ProbePolicy] = None, *,
                 on_probe=None, clock=None, history_cap: int = 10000):
        self._policy = policy
        self._on_probe = on_probe
        self._clock = clock or (lambda: datetime.now(timezone.utc).timestamp())
        self._events: Deque[Tuple[float, str, str]] = deque()
        self._history_cap = int(history_cap)
        self._lock = threading.RLock()
        self._counts = {"refusals": 0, "trips": 0, "errors": 0}
        # capability -> when it last alerted. This was a plain set that was never
        # pruned, so the FIRST trip silenced a capability permanently: an adversary
        # could probe, wait for the operator to clear the alert, and resume days later
        # in total silence. The docstring already said "once per window"; the code did
        # "once, ever". Found independently by three reviewers, and it is the same
        # shape as every other defect in this repository — permanent silence looking
        # exactly like nothing happening.
        self._alerted: Dict[str, float] = {}

    def is_armed(self) -> bool:
        """Whether ANY ceiling is enforced. An unarmed detector counts nothing and
        alerts on nothing, so a quiet record from one is not evidence of calm."""
        p = self._policy
        return p is not None and any((p.max_refusals_per_capability,
                                      p.max_refusals_total,
                                      p.max_distinct_codes_per_capability))

    def _prune(self, now: float) -> None:
        cutoff = now - self._policy.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        while len(self._events) > self._history_cap:
            self._events.popleft()

    def observe_refusal(self, capability: str, code: str) -> ProbeReading:
        """Record one refusal and read the shape. Called by the wall AFTER it has
        already decided to refuse — this never influences that decision, and must
        never be given the chance to."""
        if self._policy is None:
            return ProbeReading(False, "no probe policy configured")
        # Bounded and stringified. These become dict keys, set members and f-string
        # contents; a megabyte capability name repeated a few thousand times is a
        # cheap way to bloat the window and lengthen every scan under the lock.
        # HASHED, not truncated. Slicing to a prefix merges distinct capabilities:
        # "AAA...x_arm" and "AAA...x_trigger" became one key, so refusals against two
        # different capabilities pooled and an attacker could mask which one was
        # under attack. Same substring-vs-whole-token family as the five prefix bugs
        # already fixed in this repo.
        capability, code = str(capability), str(code)
        if len(capability) > 200:
            capability = capability[:160] + "#" + _sha(capability)
        if len(code) > 100:
            code = code[:60] + "#" + _sha(code)
        try:
            with self._lock:
                now = self._clock()
                self._prune(now)
                self._events.append((now, capability, code))
                self._counts["refusals"] += 1

                for_cap = [e for e in self._events if e[1] == capability]
                n_cap = len(for_cap)
                n_total = len(self._events)
                codes = {e[2] for e in for_cap}

                p = self._policy
                hit = None
                if (p.max_refusals_per_capability is not None
                        and n_cap > p.max_refusals_per_capability):
                    hit = (f"{n_cap} refusals against {capability!r} within "
                           f"{p.window_seconds:.0f}s (ceiling "
                           f"{p.max_refusals_per_capability}). Every one was refused "
                           f"correctly — the concern is the SEARCH, not any single "
                           f"attempt.")
                elif (p.max_distinct_codes_per_capability is not None
                      and len(codes) > p.max_distinct_codes_per_capability):
                    hit = (f"{len(codes)} different refusal reasons against "
                           f"{capability!r} within {p.window_seconds:.0f}s (ceiling "
                           f"{p.max_distinct_codes_per_capability}): "
                           f"{sorted(codes)}. Hitting many different gates on one "
                           f"capability is mapping the wall, not making a mistake.")
                elif (p.max_refusals_total is not None
                      and n_total > p.max_refusals_total):
                    hit = (f"{n_total} refusals across all capabilities within "
                           f"{p.window_seconds:.0f}s (ceiling "
                           f"{p.max_refusals_total}). A broad sweep rather than a "
                           f"focused search.")

                if hit is None:
                    return ProbeReading(False, "within probe ceilings", capability,
                                        n_cap, n_total, len(codes), p.window_seconds)
                self._counts["trips"] += 1
                reading = ProbeReading(True, hit, capability, n_cap, n_total,
                                       len(codes), p.window_seconds)
                # Alert once per capability per window, so a probe in progress does
                # not bury the operator in the very signal meant to reach them.
                # STAMPED ONLY WHEN WE ACTUALLY ALERT. The first version wrote this
                # on every observation, so continuous probing kept pushing the
                # timestamp forward and the window never elapsed — two hours of
                # steady probing produced exactly one alert. That is the SAME defect
                # three reviewers had just found, reintroduced by its own fix through
                # a different mechanism. The cooldown must run from the last ALERT,
                # never from the last attempt, or the attacker controls the clock.
                last = self._alerted.get(capability)
                fresh = last is None or (now - last) > self._policy.window_seconds
                if fresh:
                    self._alerted[capability] = now
                # prune alert memory alongside the event window so a long-running
                # broker cycling through capabilities does not leak
                for cap, ts in list(self._alerted.items()):
                    if now - ts > self._policy.window_seconds * 2:
                        del self._alerted[cap]
        except Exception as e:
            with self._lock:
                self._counts["errors"] += 1
            # tripped=TRUE. The reason field said "could not evaluate" while the
            # boolean that downstream code actually keys on said False — so a broken
            # detector was indistinguishable from a calm one, which is the failure this
            # module exists to notice. A detector that cannot count has not counted.
            broken = ProbeReading(
                True, f"probe detector FAILED and cannot count ({e!r}); treated as a "
                      f"probe because a detector that cannot see has not seen nothing")
            # The exception path used to return BEFORE the callback block, so
            # tripped=True was reported to nobody — and the wall discards the return
            # value. A fail-closed verdict that reaches no one is not fail-closed.
            if self._on_probe:
                try:
                    self._on_probe(broken)
                except Exception:
                    pass
            return broken

        if fresh and self._on_probe:
            try:
                self._on_probe(reading)
            except Exception:
                pass          # a broken handler must not stop the wall refusing
        return reading

    def measurements(self) -> dict:
        """Includes the CONCRETE ceilings. is_armed() returns True for a policy whose
        ceiling is a billion — armed, never tripping, and indistinguishable from a
        real one to anyone reading a boolean. An operator has to be able to see the
        number to know whether the detector is protecting them."""
        p = self._policy
        with self._lock:
            return {"armed": self.is_armed(), **self._counts,
                    "window_events": len(self._events),
                    "window_seconds": (p.window_seconds if p else None),
                    "ceiling_per_capability": (p.max_refusals_per_capability if p else None),
                    "ceiling_total": (p.max_refusals_total if p else None),
                    "ceiling_distinct_codes": (
                        p.max_distinct_codes_per_capability if p else None),
                    "capabilities_alerted": sorted(self._alerted)}
