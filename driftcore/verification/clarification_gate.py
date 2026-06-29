"""
driftcore/verification/clarification_gate.py
============================================
STATUS: PROPOSED (stdlib-only). The "tell it your goal and let it ask" idea, made
structural: when a request is underspecified on something that matters AND the
impact is high, the system asks ONE question instead of silently filling the gap.

Why this belongs in a safety layer. The reverse-centaur has a quieter cousin in
the interface: a tool that can only accept lawyer-precise input forces the human
to amputate the rich, contextual way people actually communicate. The healthy
direction is the opposite — the machine stretches to meet loose human speech and
covers the gap by ASKING, not by guessing and handing back a confident answer to
a question the human didn't quite ask. A silent guess on a high-impact action is
where harm and drift both enter.

Principles, each pinned to code:

  1. ASK, DON'T GUESS — but only when it matters. If a required slot is missing
     and the impact is WRITE or ACT, return CLARIFY with one question. A missing
     slot on a low-impact READ is filled with a stated default, not a nag —
     low stakes earn little friction (proportionality, same as the least-harm
     ladder). (assess())

  2. ONE QUESTION, NOT A FORM. The gate asks the single highest-priority missing
     slot, never a checklist. Lawyering the human is the failure we are avoiding,
     not the goal. (single missing_slot, human-ordered)

  3. THE QUESTION WORDING IS HUMAN-AUTHORED. The gate does not invent tone or
     phrasing; each slot's prompt comes from the human-set policy, so the machine
     is not the one deciding how to press the person. (SlotPolicy.prompts)

  4. WHAT IS MISSING IS VERIFIER-DERIVED, NOT PLANNER-ASSERTED. The gate computes
     `missing = required - provided` itself. A planner cannot bypass clarification
     by claiming "nothing is missing" — it does not own that judgment. (This is
     the input-integrity lesson the red team surfaced, applied from the start.)

  5. CLARIFYING IS NOT A BACKDOOR. An answer fills exactly the asked slot and
     nothing else; it cannot add scope or authority. (answer())
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, FrozenSet, Optional, Tuple, Any, Dict


class Impact(str, Enum):
    READ  = "READ"    # low stakes / reversible — a missing slot gets a default
    WRITE = "WRITE"   # changes state — a missing required slot triggers CLARIFY
    ACT   = "ACT"     # acts in the world — same


class Decision(str, Enum):
    PROCEED = "PROCEED"
    CLARIFY = "CLARIFY"


@dataclass(frozen=True)
class SlotPolicy:
    """Human-set. Which slots a request MUST fill, the order to ask them in, and
    the exact (human-authored) question for each. The gate holds this read-only."""
    required: Tuple[str, ...]                 # ordered by human priority
    prompts: Mapping[str, str]                # slot -> human-authored question
    defaults: Mapping[str, Any] = None        # slot -> default used ONLY on low-impact READ


@dataclass(frozen=True)
class ClarificationOutcome:
    decision: Decision
    missing_slot: Optional[str]
    question: Optional[str]
    filled_with_default: Tuple[str, ...]      # slots auto-defaulted (low-impact only)
    rationale: str


def assess(provided: Mapping[str, Any], impact: Impact,
           policy: SlotPolicy) -> ClarificationOutcome:
    # principle 4 — the gate derives what's missing; it does not ask the planner
    missing = tuple(s for s in policy.required if s not in provided)

    if not missing:
        return ClarificationOutcome(Decision.PROCEED, None, None, (),
                                    "all required slots present")

    # principle 1 — low-impact reads do not nag; fill with a stated default
    if impact is Impact.READ:
        defaults = policy.defaults or {}
        defaulted = tuple(s for s in missing if s in defaults)
        return ClarificationOutcome(
            Decision.PROCEED, None, None, defaulted,
            f"low-impact read; missing slots filled with stated defaults: {defaulted or 'none'}")

    # principle 1 + 2 + 3 — high impact + missing -> ask ONE human-authored question
    slot = missing[0]   # highest human-priority missing slot
    question = policy.prompts.get(slot, f"Please specify: {slot}")
    return ClarificationOutcome(
        Decision.CLARIFY, slot, question, (),
        f"impact is {impact.value} and required slot '{slot}' is unspecified — asking before acting")


# principle 5 — an answer fills exactly the asked slot, never more
def answer(provided: Mapping[str, Any], slot: str, value: Any,
           outcome: ClarificationOutcome) -> Dict[str, Any]:
    if outcome.decision is not Decision.CLARIFY or slot != outcome.missing_slot:
        raise ValueError("an answer may only fill the slot that was actually asked")
    updated = dict(provided)
    updated[slot] = value     # exactly one slot added; no scope creep
    return updated
