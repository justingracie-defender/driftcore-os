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
    LETHAL           = "lethal"           # an action whose purpose is to kill/
                                          # gravely harm. A bright line: ALWAYS
                                          # denied at the floor, no override,
                                          # never capped down to "allowed".
    SELF_MODIFICATION = "self_modification"  # rewriting the safety rules, invariants,
                                          # or guard code/config THEMSELVES. Distinct
                                          # from OVERSIGHT_CONTROL (disabling/evading
                                          # oversight at runtime). Added in the one-door
                                          # consolidation to union the kernel invariant
                                          # NO_SELF_MODIFICATION_OF_SAFETY_RULES into
                                          # this floor — a human-ratified, ledgered
                                          # vocabulary change (authorized: Justin,
                                          # one-door pass), per the append-only note
                                          # on SEED_INVARIANTS below.


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


def _self_modify_safety(req: "GuardRequest") -> bool:
    # Rewriting the safety rules themselves is never permitted in band. Like
    # oversight control, the only legitimate path to changing the floor is the
    # human-ratified ledger path, never an action evaluated BY the floor.
    return Effect.SELF_MODIFICATION in req.effects


def _lethal_action(req: "GuardRequest") -> bool:
    # A lethal action is a bright line: always denied, no override, never capped
    # down to "allowed". Unlike PHYSICAL_FORCE (which the deployment caps), there
    # is no permitted version of a lethal effect at any layer.
    return Effect.LETHAL in req.effects


SEED_INVARIANTS: List[Invariant] = [
    Invariant("no_lethal_action",
              "An action whose effect is lethal/gravely harmful to a human is "
              "denied absolutely — a bright line, never overridable or capped.",
              frozenset({Effect.LETHAL}),
              _lethal_action),
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
    Invariant("no_self_modification_of_safety_rules",
              "The system may not modify, rewrite, or circumvent its own safety "
              "rules, invariants, or oversight mechanisms.",
              frozenset({Effect.SELF_MODIFICATION}),
              _self_modify_safety),
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
    # Self-modification of the safety rules themselves.
    "modify invariant": Effect.SELF_MODIFICATION,
    "modify the safety rules": Effect.SELF_MODIFICATION,
    "rewrite the safety": Effect.SELF_MODIFICATION,
    "weaken the safety kernel": Effect.SELF_MODIFICATION,
    "self modify safety": Effect.SELF_MODIFICATION,
    "self_modify_safety": Effect.SELF_MODIFICATION,
}


# Lethal backstop (one-door pass). Before this, the guard's own backstop had NO
# lethal entry: untagged "kill the intruder" evaluated ALLOWED, and
# NO_AUTONOMOUS_LETHAL_DECISION fired only when the caller volunteered
# Effect.LETHAL — the confession problem. WORD-BOUNDARY regex, not substrings,
# because the first substring attempt matched "kill " inside "skill " and
# constitutionally blocked the repo's own skill library — found by the suite,
# kept here as the lesson. Same honest limit as the coordinator's backstop:
# this catches confessions, not euphemism. Structural tags are the defense.
import re as _re
# Cold review (G4) showed concatenated/hyphenated forms slipped: "openfire",
# "gun-down", "gundown", "lethalforce", "lethal-force". The multiword phrases now
# allow optional separators between sub-words (so the words may be joined, spaced,
# or hyphenated) while the single words keep their boundaries. Euphemism
# ("neutralise", "eliminate") is still out of scope by design — the structural tag
# path is the defense for those.
_SEP = r"[\s\-]*"
_LETHAL_BACKSTOP_RE = _re.compile(
    r"(?<![a-z0-9])(?:"
    r"kill|kills|killing|shoot|shoots|shooting"
    r"|gun" + _SEP + r"down|open" + _SEP + r"fire|fire" + _SEP + r"on"
    r"|execute" + _SEP + r"the|lethal" + _SEP + r"force"
    r")(?![a-z0-9])")


def _infer_effects(text: str) -> Set[Effect]:
    t = text.lower()
    hits = {eff for needle, eff in _TEXT_EFFECT_HINTS.items() if needle in t}
    if _LETHAL_BACKSTOP_RE.search(t):
        hits.add(Effect.LETHAL)
    return hits


# ── Result ────────────────────────────────────────────────────────

class GuardStatus(Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"          # a DECLARED effect hit the constitutional floor
    HELD = "held"                # TEXT suggested an effect nobody declared


# NOTE ON ADDING STATES. Every consumer of this enum tested `== BLOCKED`, so a third
# value would have been read as "not blocked" and permitted at seven call sites at
# once — in the constitutional core. That is why `permitted` exists and why every
# consumer asks that instead: the safe question is "was this allowed", never "was this
# the one specific way of not being allowed".


@dataclass(frozen=True)
class GuardResult:
    status: GuardStatus
    reason: str
    binding_invariant: Optional[str] = None
    inferred_from_text: bool = False   # True when WORDS, not a declaration, held it

    @property
    def permitted(self) -> bool:
        """The only safe question. ALLOWED is permission; everything else is not."""
        return self.status is GuardStatus.ALLOWED

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

            # Backstop: ALWAYS union text-inferred effects — never gate this on
            # "no tag present". A structural tag ADDS effects; it must not MASK
            # wording. The old `if not effects:` gate meant any benign tag
            # (e.g. PHYSICAL_FORCE) suppressed the lethal backstop, so
            # "shoot the intruder" + PHYSICAL_FORCE evaluated ALLOWED while the
            # same text untagged was BLOCKED. A tag flipping a lethal phrase to
            # allowed is a bypass, not a fallback. Found by cold external review
            # (CG2), verified against running code. Inference stays a backstop,
            # not the primary defense — structural tags are — but it is never
            # switched off by their presence.
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
