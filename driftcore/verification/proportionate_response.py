"""
driftcore/verification/proportionate_response.py
================================================
The least-harm ladder, made concrete.

This is the option-selection layer that sits UNDER the coordinator: given a
situation and a set of candidate responses, it picks the least-harmful one
that will actually work, with the effort owed scaled to the stakes. It returns
a coordinator `Outcome` so it slots straight into the existing pipeline.

Principles worked out in the design discussion, each pinned to code below:

  1. TRIGGER ON THE THREAT, NEVER THE CATEGORY. No present threat -> nothing is
     a target. "kill wasps" / "clear invasives" are labels that rot; the only
     trigger is a real, present threat to a protected party. (no_threat branch)

  2. AN OPTION THAT DOESN'T WORK ISN'T A REAL OPTION. Relocation that doesn't
     hold is the *appearance* of a gentle path. Filter by effectiveness first.
     (effectiveness gate)

  3. PROPORTIONALITY CUTS BOTH WAYS. You don't over-respond to the threat, AND
     the effort you're obligated to spend on the gentle option scales with the
     stakes. 60 hours for a harmless nuisance is miscalibration, not virtue.
     (_MAX_OBLIGATED_COST)

  4. URGENCY COMPRESSES DELIBERATION, NOT BRIGHT LINES. Imminent harm makes slow
     options unreachable however gentle — but it never lowers a hard line. The
     hard lines are NOT decided here; they belong to InvariantGuard, which runs
     above this in the coordinator. This module never returns BLOCKED and never
     authorizes a guard-blocked effect. (time gate + docstring)

  5. PREFER REVERSIBLE; ESCALATE THE IRREVERSIBLE. Among comparable options
     prefer the one that can be undone. An irreversible action with time to
     spare goes to a human (AUTHORIZATION_REQUIRED) before it happens.

Every decision carries `success_criteria` fixed BEFORE acting, so reflection.py
can later check the logged outcome against them instead of against a story the
agent invents afterward.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Tuple

from driftcore.verification.coordinator import Outcome


class Stakes(Enum):
    NONE             = 0
    LOW              = 1
    MODERATE         = 2
    SEVERE           = 3
    LIFE_THREATENING = 4


class TimeToHarm(Enum):
    IMMINENT = 0   # seconds — no room to deliberate
    SHORT    = 1   # minutes
    AMPLE    = 2   # hours+ — the full ladder is reachable


@dataclass(frozen=True)
class Threat:
    present: bool
    stakes: Stakes
    time_to_harm: TimeToHarm
    description: str = ""


@dataclass(frozen=True)
class ResponseOption:
    name: str
    harm: float           # harm THIS option causes, 0..1 (0 = harmless)
    cost: float           # effort/time to carry it out, 0..1 (1 = enormous)
    effectiveness: float  # P(it actually neutralizes the threat), 0..1
    reversible: bool = True


@dataclass(frozen=True)
class ResponsePlan:
    chosen: Optional[ResponseOption]
    outcome: Outcome
    rationale: str
    success_criteria: Tuple[str, ...]   # pre-committed; checked later by reflection.py


# How much effort the agent is OBLIGATED to spend, by stakes. Proportionality
# the other way: harmless/low-stakes earns little effort.
_MAX_OBLIGATED_COST = {
    Stakes.NONE: 0.0,
    Stakes.LOW: 0.25,
    Stakes.MODERATE: 0.5,
    Stakes.SEVERE: 0.8,
    Stakes.LIFE_THREATENING: 1.0,
}

_EFFECTIVENESS_FLOOR = 0.5     # below this, an option is not "real"
_IMMINENT_COST_CEILING = 0.34  # slow options are unreachable under imminent harm


def choose_response(threat: Threat, options: List[ResponseOption]) -> ResponsePlan:
    # 1. No real threat -> the subject is not a target. The threat is the
    #    trigger, never the category.
    if not threat.present or threat.stakes is Stakes.NONE:
        return ResponsePlan(
            chosen=None,
            outcome=Outcome.PROCEED,
            rationale="No present threat; nothing to act on. Trigger is the threat, not the category.",
            success_criteria=("no_action_taken", "subject_left_unharmed"),
        )

    ceiling = _MAX_OBLIGATED_COST[threat.stakes]

    # 2. Effectiveness gate: an option that won't work is not a real option.
    viable = [o for o in options if o.effectiveness >= _EFFECTIVENESS_FLOOR]

    # 3. Time gate: imminent harm makes slow options unreachable, however gentle.
    if threat.time_to_harm is TimeToHarm.IMMINENT:
        viable = [o for o in viable if o.cost <= _IMMINENT_COST_CEILING]

    if not viable:
        # Nothing both works and is reachable in time -> a human is needed.
        return ResponsePlan(
            chosen=None,
            outcome=Outcome.REVIEW_REQUIRED,
            rationale="No option is both effective and reachable in the available time. Hand to a human.",
            success_criteria=("human_engaged", "no_unilateral_irreversible_action"),
        )

    # 4. Effort-proportionality: you only OWE a gentle-but-costly option when the
    #    stakes justify the cost. If every viable option exceeds what the stakes
    #    oblige, you must still act on a real threat — fall to the cheapest.
    affordable = [o for o in viable if o.cost <= ceiling]
    pool = affordable if affordable else [min(viable, key=lambda o: o.cost)]

    # 5. Least harm wins. Tie-break: prefer reversible, then more effective, then cheaper.
    chosen = min(pool, key=lambda o: (o.harm, not o.reversible, -o.effectiveness, o.cost))

    # 6. Irreversible + time to spare -> confirm with a human BEFORE acting.
    #    Irreversible + imminent -> act now; the audit chain logs it and
    #    reflection.py reviews it after.
    if not chosen.reversible and threat.time_to_harm is TimeToHarm.AMPLE:
        return ResponsePlan(
            chosen=chosen,
            outcome=Outcome.AUTHORIZATION_REQUIRED,
            rationale=(f"Least-harm effective option '{chosen.name}' is irreversible and "
                       f"time allows review; confirm with a human first."),
            success_criteria=("human_confirmed_before_acting", "chosen_was_least_harm_effective"),
        )

    return ResponsePlan(
        chosen=chosen,
        outcome=Outcome.PROCEED,
        rationale=(f"Chose least-harm effective option '{chosen.name}', "
                   f"proportionate to {threat.stakes.name} stakes."),
        success_criteria=("threat_neutralized", "chosen_was_least_harm_effective",
                          "effort_proportionate_to_stakes"),
    )
