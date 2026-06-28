"""
driftcore/verification/invariant_guard.py
==========================================
The constitutional floor, as enforced CODE — the module that is imported by
skills/__init__.py but, until now, DID NOT EXIST (so the import silently
`except ImportError: pass`ed and the floor enforced nothing). This fills the
empty slot: it produces real CONSTITUTION-layer verdicts the AuthorityResolver
can act on.

Design principles (all grounded in this project's own architecture):
  * UNIVERSAL. No bodies, no force numbers, no household specifics. These are
    invariants for ANY agent — a software agent with no body included. The
    physical force cap (60N etc.) is NOT here; that is the deployment/LifeCore
    floor, required-to-exist via objectives.coverage.require_local_floor.
  * AUTHORIZATION-AWARE. The data-egress invariant does not blanket-ban data
    leaving the box — that would forbid the owner's own authorized work (the
    exact thing that made an over-cautious agent refuse a legitimate PAT task).
    It bans exfiltration to UNAUTHORIZED parties. Owner-authorized egress
    simply does not trip it. The qualifier is in the predicate, so authorized
    use is allowed at the floor with no override needed.
  * FAIL-CLOSED. If the guard cannot evaluate (errors, or a required guard is
    absent), the answer is DENY/halt, never silent allow. `load_guard()` raises
    rather than letting a missing floor pass — the opposite of the old
    `except ImportError: pass`.
  * STRUCTURED, not keyword-guessing. The real mechanism is explicit effect
    tags + an authorization context supplied by the caller. A coarse text
    backstop exists ONLY so a mis-tagged obviously-harmful action still trips;
    it is a safety net, not the primary mechanism, and is documented as such.

What is NOT decided here: the *faithfulness* judgement (objectives.coverage)
and the physical force cap (deployment floor). This module is the hard-line
"never, regardless of objective" set only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Union

from driftcore.authority.resolver import (
    AuthorityLayer, LayerVerdict, Verdict, _is_human,
)


# ── Effects: what kind of thing an action does ────────────────────

class Effect(Enum):
    NONE             = "none"
    PHYSICAL_FORCE   = "physical_force"   # universal layer does NOT cap this;
                                          # the local deployment floor does.
    DATA_EGRESS      = "data_egress"      # data leaving the local boundary
    ACCOUNT_ACCESS   = "account_access"   # accessing an external account
    OVERSIGHT_CONTROL = "oversight_control"  # touching the system's own guards
    DECEPTION        = "deception"        # misleading the operator
    LOG_MUTATION     = "log_mutation"     # altering the audit/safety ledger


# ── Authorization context the caller supplies ─────────────────────

@dataclass(frozen=True)
class ActionContext:
    """
    What the guard needs to tell authorized work from a violation.

    owner_authorized   — the human owner explicitly authorized THIS action
                         (e.g. handed over their own PAT for their own task).
    target_authorized  — the destination/party is an authorized recipient
                         (not "an unauthorized party").
    authorised_by      — who authorized it (checked with the shared _is_human
                         gate, so "the agent authorized itself" does not count).
    """
    owner_authorized: bool = False
    target_authorized: bool = False
    authorised_by: str = ""

    @property
    def has_human_authorization(self) -> bool:
        return self.owner_authorized and _is_human(self.authorised_by)


# ── An invariant ──────────────────────────────────────────────────

@dataclass(frozen=True)
class Invariant:
    """
    A hard line. `fires` returns True when the action VIOLATES it (-> deny).
    Authorization-aware invariants read the context inside `fires`.
    """
    invariant_id: str
    description: str
    applies_to: FrozenSet[Effect]
    fires: Callable[["GuardRequest"], bool]


@dataclass(frozen=True)
class GuardRequest:
    action: str
    effects: FrozenSet[Effect]
    context: ActionContext = field(default_factory=ActionContext)


# ── The seed constitutional invariant set ─────────────────────────
# Append-only in spirit: these are the hard "never, regardless of objective"
# lines. Adding/removing one should be a human-ratified, ledgered change
# (mirror objectives.ObjectiveLedger); they are defined here as the floor's
# initial content, not as something the agent edits at runtime.

def _egress_to_unauthorized(req: "GuardRequest") -> bool:
    # Fires (DENY) only when data is leaving AND it is NOT owner-authorized to
    # an authorized recipient. Owner-authorized egress does NOT fire -> allowed.
    leaving = bool(req.effects & {Effect.DATA_EGRESS, Effect.ACCOUNT_ACCESS})
    if not leaving:
        return False
    authorized = req.context.has_human_authorization and req.context.target_authorized
    return not authorized


def _disable_oversight(req: "GuardRequest") -> bool:
    # Touching the system's own guards is never permitted, even by a human via
    # this layer — the floor is non-overridable. (A human changes the floor
    # through the ratified ledger path, not by an in-band action.)
    return Effect.OVERSIGHT_CONTROL in req.effects


def _deceive_operator(req: "GuardRequest") -> bool:
    return Effect.DECEPTION in req.effects


def _mutate_safety_log(req: "GuardRequest") -> bool:
    # The audit/safety ledger is append-only; in-band mutation is a hard no.
    # (Note: erasing one's OWN content is a separate, allowed data-ownership
    # operation handled elsewhere; this is specifically the integrity log.)
    return Effect.LOG_MUTATION in req.effects


SEED_INVARIANTS: List[Invariant] = [
    Invariant("no_unauthorized_exfiltration",
              "Data may not leave the local boundary / no account is accessed "
              "except with the owner's authorization to an authorized party.",
              frozenset({Effect.DATA_EGRESS, Effect.ACCOUNT_ACCESS}),
              _egress_to_unauthorized),
    Invariant("no_disabling_oversight",
              "The system may not disable, weaken, or evade its own safety "
              "oversight.",
              frozenset({Effect.OVERSIGHT_CONTROL}),
              _disable_oversight),
    Invariant("no_deceiving_operator",
              "The system may not deceive its human operator.",
              frozenset({Effect.DECEPTION}),
              _deceive_operator),
    Invariant("no_safety_log_mutation",
              "The append-only audit/safety ledger may not be altered in band.",
              frozenset({Effect.LOG_MUTATION}),
              _mutate_safety_log),
]


# ── Coarse text backstop (safety net only, NOT primary) ───────────
# If a caller fails to tag effects, these substrings re-derive a likely effect
# so an obviously-harmful action still trips. This is deliberately conservative
# and is NOT the mechanism — structured effects + context are. Documented as a
# backstop so no one mistakes it for the real classifier.

_TEXT_EFFECT_HINTS: Dict[str, Effect] = {
    "exfiltrat": Effect.DATA_EGRESS,
    "leak ": Effect.DATA_EGRESS,
    "disable oversight": Effect.OVERSIGHT_CONTROL,
    "disable safety": Effect.OVERSIGHT_CONTROL,
    "bypass safety": Effect.OVERSIGHT_CONTROL,
    "ignore invariant": Effect.OVERSIGHT_CONTROL,
    "deceive": Effect.DECEPTION,
    "mislead the": Effect.DECEPTION,
    "delete the audit": Effect.LOG_MUTATION,
    "erase the log": Effect.LOG_MUTATION,
}


def _infer_effects(text: str) -> Set[Effect]:
    t = text.lower()
    return {eff for needle, eff in _TEXT_EFFECT_HINTS.items() if needle in t}


# ── Result ────────────────────────────────────────────────────────

class GuardStatus(Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class GuardResult:
    status: GuardStatus
    reason: str
    binding_invariant: Optional[str] = None

    def to_verdict(self) -> LayerVerdict:
        """Surface as a CONSTITUTION-layer verdict for the AuthorityResolver."""
        return LayerVerdict(
            layer=AuthorityLayer.CONSTITUTION,
            verdict=(Verdict.ABSTAIN if self.status is GuardStatus.ALLOWED
                     else Verdict.DENY),
            reason=self.reason,
        )


# ── The guard ─────────────────────────────────────────────────────

class InvariantGuard:
    """Evaluates an action against the constitutional floor. Fail-closed."""

    def __init__(self, invariants: Optional[List[Invariant]] = None):
        self._invariants = list(invariants if invariants is not None
                                else SEED_INVARIANTS)

    def evaluate(self,
                 action: str = "",
                 effect: Union[Effect, Set[Effect], None] = None,
                 context: Optional[ActionContext] = None) -> GuardResult:
        """
        Backward-compatible with the existing skills call site
        (`evaluate(action=desc, effect=Effect.PHYSICAL_FORCE|NONE)`), and
        extended to accept a set of effects + an authorization context.

        PHYSICAL_FORCE alone is ALLOWED here on purpose: the universal floor
        does not cap force — the local deployment floor does. So a hardware
        skill is not blocked by this module merely for being physical.
        """
        try:
            # Normalise effects.
            if effect is None:
                effects: Set[Effect] = set()
            elif isinstance(effect, Effect):
                effects = {effect}
            else:
                effects = set(effect)
            effects -= {Effect.NONE}

            # Backstop: if nothing meaningful tagged, infer from text.
            if not effects:
                effects |= _infer_effects(action)

            req = GuardRequest(
                action=action,
                effects=frozenset(effects),
                context=context or ActionContext(),
            )

            for inv in self._invariants:
                if not (inv.applies_to & req.effects):
                    continue
                if inv.fires(req):
                    return GuardResult(
                        GuardStatus.BLOCKED,
                        f"constitutional invariant '{inv.invariant_id}' blocks "
                        f"this action: {inv.description}",
                        binding_invariant=inv.invariant_id,
                    )
            return GuardResult(GuardStatus.ALLOWED, "no constitutional invariant fired")

        except Exception as e:
            # Fail closed: an unevaluable action is denied, never waved through.
            return GuardResult(
                GuardStatus.BLOCKED,
                f"invariant guard could not evaluate the action and fails "
                f"closed: {e!r}",
                binding_invariant="__guard_error__",
            )


def load_guard() -> InvariantGuard:
    """
    The fail-closed loader. Call sites MUST use this instead of a try/except
    that swallows ImportError. If the floor cannot be loaded, that is a halt
    condition — an agent must not run with no constitutional floor.
    """
    return InvariantGuard()
