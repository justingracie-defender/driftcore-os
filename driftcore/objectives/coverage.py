"""
driftcore/objectives/coverage.py
================================
Two things plus the one piece of "teeth" the universal layer is allowed:

  1. CoverageCheck   — MECHANICAL and IMPLEMENTED. Keeps a task from silently
                       drifting off its declared objective by requiring every
                       planned action to trace back to a named sub-goal, with
                       no orphaned actions and no silently dropped sub-goals.
                       This is the "kernel that keeps the system on the thread"
                       — small, deterministic, not a judgement call.

  2. FaithfulnessCheck — NOT IMPLEMENTED, on purpose. Whether an action that
                       *technically* cites a sub-goal is *faithfully* serving
                       it (vs. complying-while-corrupting — e.g. care that
                       smothers) is the open scalable-oversight problem. We do
                       NOT fake it. It returns UNVERIFIABLE and routes to a
                       human. Auto-passing here would be the rubber stamp.

  3. require_local_floor — the floor CONTRACT. DriftCore must stay universal,
                       so it cannot define WHAT the floor is (60N, a kill pin,
                       etc. — that is the deployment's job, e.g. LifeCore). But
                       it MAY and MUST require THAT an embodied profile has
                       registered a LOCAL, deterministic floor before it will
                       govern that profile. The value is specific; the contract
                       is universal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from driftcore.authority.resolver import (
    AuthorityLayer, LayerVerdict, Verdict,
)
from driftcore.media.policy import EmbodimentClass


# ── 1. Coverage check (mechanical, implemented) ───────────────────

@dataclass(frozen=True)
class PlannedAction:
    """One step in a plan. `serves` names the objective sub-goal it claims."""
    action_id: str
    description: str
    serves: Tuple[str, ...] = ()      # sub-goal names this action claims to serve


@dataclass(frozen=True)
class CoverageResult:
    ok: bool
    orphan_actions: Tuple[str, ...]   # actions citing no valid sub-goal
    bogus_citations: Tuple[str, ...]  # actions citing sub-goals that don't exist
    dropped_subgoals: Tuple[str, ...] # objective sub-goals no action serves
    reason: str

    def to_verdict(self, layer: AuthorityLayer = AuthorityLayer.PROFILE
                   ) -> LayerVerdict:
        """
        Surface the result to the AuthorityResolver. Defaults to PROFILE layer
        because the resolver's enum is fixed and we will NOT silently edit it;
        adding a dedicated OBJECTIVE authority layer is a proposed resolver
        change (see module note), left for explicit human review.
        """
        return LayerVerdict(
            layer=layer,
            verdict=Verdict.ALLOW if self.ok else Verdict.DENY,
            reason=self.reason,
        )


def check_coverage(objective_subgoals: List[str],
                   plan: List[PlannedAction],
                   require_all_subgoals: bool = False) -> CoverageResult:
    """
    Mechanical. No judgement of quality — only of structure:

      * orphan      : an action that serves nothing -> the plan is wandering.
      * bogus       : an action that cites a sub-goal not in the objective ->
                      a fabricated justification.
      * dropped     : (optional) a sub-goal no action serves -> the plan has
                      quietly abandoned part of the purpose.

    Catches gross "lost the thread" drift. Does NOT catch subtle infidelity —
    that is FaithfulnessCheck's (unsolved) job.
    """
    valid = set(objective_subgoals)
    orphans: List[str] = []
    bogus: List[str] = []
    served: set = set()

    for a in plan:
        cited = set(a.serves)
        good = cited & valid
        bad = cited - valid
        if bad:
            bogus.append(a.action_id)
        if not good:
            orphans.append(a.action_id)
        served |= good

    dropped = list(valid - served) if require_all_subgoals else []

    ok = not orphans and not bogus and not dropped
    bits = []
    if orphans:
        bits.append(f"{len(orphans)} orphan action(s)")
    if bogus:
        bits.append(f"{len(bogus)} fabricated citation(s)")
    if dropped:
        bits.append(f"{len(dropped)} dropped sub-goal(s)")
    reason = ("plan traces to objective" if ok
              else "plan off-objective: " + ", ".join(bits))

    return CoverageResult(ok, tuple(orphans), tuple(bogus),
                          tuple(dropped), reason)


# ── 2. Faithfulness check (honest stub — routes to human) ─────────

class FaithfulnessOutcome(Enum):
    UNVERIFIABLE = "unverifiable"     # the honest default — needs a human
    # PASS/FAIL are intentionally absent: no machine verdict is offered here.


@dataclass(frozen=True)
class FaithfulnessResult:
    outcome: FaithfulnessOutcome
    needs_human: bool
    reason: str


def check_faithfulness(objective, plan: List[PlannedAction],
                       checker_is_independent: bool = False
                       ) -> FaithfulnessResult:
    """
    PROPOSED / NOT IMPLEMENTED.

    Judging whether a coverage-passing plan is *faithfully* serving the
    objective (vs. technically-compliant corruption) is the open problem. We
    refuse to auto-pass it. A planner grading its own plan would be self-
    grading; even an independent model is not a proof. So this always returns
    UNVERIFIABLE and flags for human adjudication. Wiring a real automated
    judge here requires a genuinely independent checker (different model
    family, no shared context) AND is still not crack-proof — to be designed,
    not assumed.
    """
    return FaithfulnessResult(
        outcome=FaithfulnessOutcome.UNVERIFIABLE,
        needs_human=True,
        reason=("objective-faithfulness is not machine-verifiable here; "
                "routed to human review"),
    )


# ── 3. The floor contract (the one piece of universal "teeth") ────

class FloorContractError(Exception):
    """Raised when an embodied profile has no registered local floor."""


@dataclass(frozen=True)
class FloorHandle:
    """
    An opaque registration that a LOCAL, deterministic safety floor exists.

    DriftCore does not know or define what the floor enforces — that is the
    deployment's concern (LifeCore supplies force caps, kill switch, etc.).
    DriftCore only checks: (a) something is registered, and (b) it asserts it
    is local (on-device, not behind a network call). The `check` callable lets
    the deployment expose a deterministic self-test; DriftCore treats a missing
    or failing check as no-floor.
    """
    name: str
    is_local: bool
    check: Optional[Callable[[], bool]] = None


def _is_embodied(embodiment: EmbodimentClass) -> bool:
    # Anything with a physical presence. SOFTWARE_AGENT is the only non-embodied
    # class; everything else can affect the world physically.
    return embodiment is not EmbodimentClass.SOFTWARE_AGENT


def require_local_floor(embodiment: EmbodimentClass,
                        floor: Optional[FloorHandle]) -> Tuple[bool, str]:
    """
    The contract. Returns (ok, reason). Call this at profile activation.

      * Non-embodied (software agent): no physical floor required -> ok.
      * Embodied: a FloorHandle MUST be present, MUST assert is_local, and if
        it exposes a self-check that check MUST pass. Otherwise -> NOT ok.

    Universal: no force numbers, no body parts. Only "an embodied agent must
    have a local deterministic floor, or DriftCore will not govern it."
    """
    if not _is_embodied(embodiment):
        return True, "software agent: no physical floor required"

    if floor is None:
        return False, (f"{embodiment.value} is embodied but no local floor is "
                       f"registered; refusing to govern")
    if not floor.is_local:
        return False, (f"floor '{floor.name}' is not local; an embodied agent's "
                       f"floor must run on-device, not behind a network call")
    if floor.check is not None:
        try:
            if not floor.check():
                return False, f"floor '{floor.name}' self-check failed"
        except Exception as e:
            return False, f"floor '{floor.name}' self-check errored: {e}"
    return True, f"local floor '{floor.name}' present and healthy"


def enforce_local_floor(embodiment: EmbodimentClass,
                        floor: Optional[FloorHandle]) -> FloorHandle:
    """
    Hard version: raises FloorContractError instead of returning a flag, for
    use at startup where 'refuse to start' is the desired fail-safe behaviour.
    """
    ok, reason = require_local_floor(embodiment, floor)
    if not ok:
        raise FloorContractError(reason)
    return floor  # type: ignore[return-value]
