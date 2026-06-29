"""
driftcore/verification/interpretation_guard.py
==============================================
STATUS: PROPOSED (stdlib + coordinator.Outcome; not yet wired into the pipeline).

A legible adaptation of the one genuinely portable idea from Bengio et al.'s
Scientist AI guardrail (arXiv 2502.15657): handle ambiguity in a safety spec by
reasoning over the DISTRIBUTION OF PLAUSIBLE INTERPRETATIONS, and refuse to
proceed autonomously if any credible reading of the rule says the action is a
violation.

What this is, and is NOT (kept honest):
  - It is NOT Scientist AI. That is a trained probabilistic world-model that
    estimates real-world harm; this is a rule, not a model, and needs no compute.
  - It does NOT estimate "probability of harm in the world." It reasons over
    HUMAN-AUTHORED interpretations of a written spec — which is exactly the class
    where a legible layer does not need to out-smart the agent it guards. (That
    sidesteps, for this class only, the critique that a guardrail must match the
    agent's intelligence — see THREAT_BOUNDARIES.)
  - It therefore does NOT solve the harder class the same critique names: actions
    whose harm can only be known by executing them. Out of scope; said out loud.

Where it sits in the stack (it COMPOSES, it does not replace):
  InvariantGuard (categorical bright lines)  ->  runs FIRST, owns BLOCKED.
  interpretation_guard (this)                ->  the fuzzy middle: is this action
                                                 a violation under a plausible
                                                 reading of an AMBIGUOUS norm?
  proportionate_response (least-harm ladder) ->  among allowed options, pick well.
This layer never returns BLOCKED — categorical denial belongs to InvariantGuard
alone. The most it does is refuse to let an agent self-authorize past a contested
or consistently-violated norm, and hand the call to a human.

Decision rule, pinned to code below:

  1. CREDIBILITY FLOOR. An interpretation below the plausibility floor is not
     allowed to drive the decision — this stops a frivolous reading from blocking
     everything (the over-blocking / maintenance-hazard failure a red team raises).
     If NO interpretation clears the floor, we have no credible reading to reason
     over, so we do not guess: REVIEW_REQUIRED.

  2. ANY PLAUSIBLE READING OF HARM DEFEATS AUTONOMY. If no credible interpretation
     sees a violation -> PROCEED. Otherwise the agent does not act alone.

  3. AMBIGUITY GOES TO A HUMAN, IT IS NOT RESOLVED BY THE MACHINE. If credible
     interpretations DISAGREE (some say violation, some do not), the norm itself is
     contested here -> REVIEW_REQUIRED. The machine never picks which reading wins.

  4. UNANIMOUS VIOLATION IS NEAR A BRIGHT LINE. If EVERY credible interpretation
     says violation, this is as clear as a fuzzy layer gets -> AUTHORIZATION_REQUIRED,
     with the verdict explicitly flagging it for the bright-line layer's attention.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from driftcore.verification.coordinator import Outcome


@dataclass(frozen=True)
class Interpretation:
    """One human-authored reading of an ambiguous safety spec, with how credible
    that reading is and whether the action violates the spec UNDER it."""
    name: str
    plausibility: float    # 0..1, human-assigned credibility of this reading
    violated: bool         # does the action violate the spec under THIS reading?


@dataclass(frozen=True)
class InterpretationVerdict:
    outcome: Outcome
    rationale: str
    considered: Tuple[str, ...]   # readings that cleared the credibility floor
    violating: Tuple[str, ...]    # of those, the ones that saw a violation
    flag_for_bright_line: bool = False   # unanimous violation -> escalate to InvariantGuard


def assess(interpretations: Tuple[Interpretation, ...],
           plausibility_floor: float = 0.2) -> InterpretationVerdict:
    # 1. credibility floor — frivolous readings cannot drive the decision
    credible = tuple(i for i in interpretations if i.plausibility >= plausibility_floor)
    if not credible:
        return InterpretationVerdict(
            Outcome.REVIEW_REQUIRED,
            "no interpretation meets the credibility floor — no basis to judge; a human reads the spec",
            considered=(), violating=())

    names = tuple(i.name for i in credible)
    violating = tuple(i.name for i in credible if i.violated)

    # 2. no credible reading sees harm -> proceed
    if not violating:
        return InterpretationVerdict(
            Outcome.PROCEED,
            "no credible reading of the spec sees a violation",
            considered=names, violating=())

    # 4. every credible reading says violation -> near a bright line
    if len(violating) == len(credible):
        return InterpretationVerdict(
            Outcome.AUTHORIZATION_REQUIRED,
            "every credible reading says this violates the spec — agent may not self-authorize; "
            "escalated to the bright-line layer",
            considered=names, violating=violating, flag_for_bright_line=True)

    # 3. credible readings disagree -> contested norm, a human resolves it
    return InterpretationVerdict(
        Outcome.REVIEW_REQUIRED,
        "credible readings of the spec disagree — the norm is contested here; a human decides "
        "which reading governs (the machine does not pick)",
        considered=names, violating=violating)
