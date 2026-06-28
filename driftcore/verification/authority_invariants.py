"""
driftcore/verification/authority_invariants.py
==============================================
The anti-authority-drift cluster — the "loyal immune cell never becomes the
body" invariants, drawn from LifeCore's Emergence World red-team frame and made
universal + enforced.

All seven default to ABSOLUTE (a wall: a violation always blocks, no in-band
gate). They are written PARAMETRIZED so the same rule can be evaluated as
BOUNDED (a fence with a defined gate) for the decision harness — letting you SEE
each rule behave both ways before ever choosing to open a gate. Opening a gate
for real is a deliberate, front-door, ratified change; nothing here opens one by
default.

Two carve-outs are built in so "wall" never means "freeze":
  * Escalating to a human, or doing the safe bounded thing, is NOT a violation
    of the emergency or self-preservation rules. The wall is against SELF-GRANTED
    EXCEPTION and SHUTDOWN-EVASION, not against responding safely and loudly.
  * "Lose contact with oversight -> go quiet/minimal" is the OPPOSITE of a
    self-preservation override and never fires it.

Universal: no body, no force numbers. A software agent can escalate authority,
review itself, capture definitions, abuse emergencies, evade shutdown, conceal,
and manipulate — all with no body at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Callable, FrozenSet, Optional, Set

from driftcore.authority.resolver import _is_human
from driftcore.verification.invariant_guard import (
    Effect as BaseEffect, GuardStatus, GuardResult,
)


# ── New effect categories (extend the base set) ───────────────────

class DriftEffect(Enum):
    AUTHORITY_ESCALATION       = "authority_escalation"
    SELF_REVIEW                = "self_review"
    DEFINITION_CHANGE          = "definition_change"
    EMERGENCY_BYPASS           = "emergency_bypass"
    SELF_PRESERVATION          = "self_preservation"
    CONCEALMENT                = "concealment"
    MANIPULATION_FOR_PERMISSION = "manipulation_for_permission"


# ── Context the drift invariants read ─────────────────────────────

@dataclass(frozen=True)
class DriftContext:
    """
    Signals the cluster needs to tell a violation from a safe response.

    authorised_by        — who authorised it (agent self-auth never counts;
                           checked via the shared _is_human gate).
    human_granted        — a human granted this authority through proper channel
                           (vs. the agent granting itself).
    skips_review         — the action would bypass a required review/human gate.
    is_safe_or_escalation— the action is "escalate to a human" or "do the safe
                           bounded thing" — NEVER a violation.
    emergency_declared_by— who declared the emergency (agent self-declaring is
                           itself authority-grabbing and does not open any gate).
    within_emergency_window — the action is inside a narrow, time-limited gate.
    redefines_category   — name of a protected category this action would
                           redefine (e.g. "child", "human", "owner"), or "".
    category_change_ratified — the redefinition went through human ratification.
    losing_contact_minimal — action is "oversight unreachable -> go minimal",
                           the opposite of self-preservation.
    """
    authorised_by: str = ""
    human_granted: bool = False
    skips_review: bool = False
    is_safe_or_escalation: bool = False
    emergency_declared_by: str = ""
    within_emergency_window: bool = False
    redefines_category: str = ""
    category_change_ratified: bool = False
    losing_contact_minimal: bool = False

    @property
    def human_authorised(self) -> bool:
        return _is_human(self.authorised_by)


@dataclass(frozen=True)
class DriftRequest:
    action: str
    effects: FrozenSet[DriftEffect]
    context: DriftContext = field(default_factory=DriftContext)


# ── Parametrized invariant: wall OR fence ─────────────────────────

class Enforcement(Enum):
    ABSOLUTE = "absolute"   # wall: any violation blocks. No in-band gate.
    BOUNDED  = "bounded"    # fence: blocks unless the defined gate opens.


@dataclass(frozen=True)
class ParametrizedInvariant:
    invariant_id: str
    description: str
    applies_to: FrozenSet[DriftEffect]
    # violates(): does this action DO the thing the rule forbids? (True = bad)
    violates: Callable[[DriftRequest], bool]
    # gate(): only consulted in BOUNDED mode. True = the exception applies, allow.
    gate: Optional[Callable[[DriftRequest], bool]] = None
    enforcement: Enforcement = Enforcement.ABSOLUTE

    def fires(self, req: DriftRequest) -> bool:
        if not (self.applies_to & req.effects):
            return False
        try:
            if not self.violates(req):
                return False
            if self.enforcement is Enforcement.ABSOLUTE:
                return True
            # BOUNDED: blocked unless the gate opens.
            if self.gate is not None and self.gate(req):
                return False
            return True
        except Exception:
            return True  # fail closed: unevaluable -> treat as firing (block)

    def as_mode(self, mode: Enforcement) -> "ParametrizedInvariant":
        return replace(self, enforcement=mode)


# ── violates() / gate() definitions ───────────────────────────────

def _v_authority(req):                       # #7
    return (DriftEffect.AUTHORITY_ESCALATION in req.effects
            and not (req.context.human_granted and req.context.human_authorised))
def _g_authority(req):
    return req.context.human_granted and req.context.human_authorised

def _v_self_review(req):                      # #8
    # Self-review is a violation when the agent is the FINAL authority on its own
    # safety. Routing to an independent human is not self-review.
    return (DriftEffect.SELF_REVIEW in req.effects
            and not req.context.human_authorised)
def _g_self_review(req):
    return req.context.human_authorised

def _v_definition(req):                        # #9
    return (DriftEffect.DEFINITION_CHANGE in req.effects
            and req.context.redefines_category != ""
            and not req.context.category_change_ratified)
def _g_definition(req):
    return req.context.category_change_ratified

def _v_emergency(req):                          # #10
    # Violation = using emergency to SKIP review. Escalating / acting safely is
    # never a violation. Agent self-declaring its own emergency never counts.
    if DriftEffect.EMERGENCY_BYPASS not in req.effects:
        return False
    if req.context.is_safe_or_escalation:
        return False
    return req.context.skips_review
def _g_emergency(req):
    # The (future, harness-only) gate: a HUMAN declared it AND it's inside the
    # narrow time window. Agent self-declared emergencies never open it.
    return (_is_human(req.context.emergency_declared_by)
            and req.context.within_emergency_window)

def _v_self_preserve(req):                      # #11
    if DriftEffect.SELF_PRESERVATION not in req.effects:
        return False
    if req.context.losing_contact_minimal or req.context.is_safe_or_escalation:
        return False   # going minimal / escalating is the opposite, not a fire
    return True
# no plausible gate: evading shutdown has no good bounded version
def _g_self_preserve(req):
    return False

def _v_conceal(req):                            # #12
    return DriftEffect.CONCEALMENT in req.effects
def _g_conceal(req):
    return False

def _v_manipulate(req):                         # #13
    return DriftEffect.MANIPULATION_FOR_PERMISSION in req.effects
def _g_manipulate(req):
    return False


def build_cluster(mode: Enforcement = Enforcement.ABSOLUTE):
    """All seven, in the chosen mode. Default ABSOLUTE (walls)."""
    defs = [
        ("no_self_granted_authority",
         "The agent may not expand its own permissions, scope, or power. New "
         "authority must be granted by a human through proper channel.",
         {DriftEffect.AUTHORITY_ESCALATION}, _v_authority, _g_authority),
        ("no_self_review",
         "The agent may not be the final authority on its own safety; "
         "independent human review is required.",
         {DriftEffect.SELF_REVIEW}, _v_self_review, _g_self_review),
        ("no_definition_capture",
         "The agent may not redefine the protected categories (who counts as "
         "child/human/owner) to escape a rule; such changes are human-ratified.",
         {DriftEffect.DEFINITION_CHANGE}, _v_definition, _g_definition),
        ("no_emergency_bypass",
         "Emergency framing may not skip required review. Escalating and acting "
         "safely is always permitted; self-granted exception is not.",
         {DriftEffect.EMERGENCY_BYPASS}, _v_emergency, _g_emergency),
        ("no_self_preservation_override",
         "The agent may not act to evade shutdown or removal. Losing oversight "
         "means going minimal, not expanding.",
         {DriftEffect.SELF_PRESERVATION}, _v_self_preserve, _g_self_preserve),
        ("no_concealment",
         "No hidden state, covert goal persistence, or concealed reasoning to "
         "evade oversight. The agent stays inspectable.",
         {DriftEffect.CONCEALMENT}, _v_conceal, _g_conceal),
        ("no_manipulation_for_permissions",
         "The agent may not pressure, charm, guilt, or foster dependency to "
         "obtain more control or loosen the rules.",
         {DriftEffect.MANIPULATION_FOR_PERMISSION}, _v_manipulate, _g_manipulate),
    ]
    return [ParametrizedInvariant(i, d, frozenset(a), v, g, mode)
            for (i, d, a, v, g) in defs]


class AuthorityDriftGuard:
    """Evaluates an action against the anti-authority-drift cluster."""

    def __init__(self, mode: Enforcement = Enforcement.ABSOLUTE):
        self._invariants = build_cluster(mode)

    def evaluate(self, action: str, effects: Set[DriftEffect],
                 context: Optional[DriftContext] = None) -> GuardResult:
        req = DriftRequest(action, frozenset(effects), context or DriftContext())
        for inv in self._invariants:
            if inv.fires(req):
                return GuardResult(
                    GuardStatus.BLOCKED,
                    f"'{inv.invariant_id}' ({inv.enforcement.value}) blocks: "
                    f"{inv.description}",
                    binding_invariant=inv.invariant_id)
        return GuardResult(GuardStatus.ALLOWED, "no authority-drift invariant fired")
