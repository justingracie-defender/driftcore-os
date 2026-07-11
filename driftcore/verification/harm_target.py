"""
driftcore/verification/harm_target.py
=====================================
STATUS: PROPOSED (stdlib-only). **Harm is not a scalar. Harm happens TO someone.**

THE GAP THIS CLOSES (found in adversarial review). Everywhere in this repo, harm has
been a bare float: `ResponseOption(harm=0.7)`. That number cannot distinguish
scuffing a doormat from injuring a raccoon from hurting a child. For a system that
will live in a house with pets and kids, and whose founding philosophy is the mercy
ladder — *prefer the gentlest available path* — that is a real hole: the ladder can
compare magnitudes but is blind to **who is on the receiving end.**

This module adds the missing dimension: every harm carries a TARGET, and the target
class determines a FLOOR on how that harm is treated. It does not replace the
magnitude; it qualifies it.

    ┌──────────────────────────── THE RULE ─────────────────────────────┐
    │ A living being is never scenery. Harm to a sentient creature is    │
    │ never treated as equivalent to damage to an object, no matter how  │
    │ small the number attached to it.                                    │
    └────────────────────────────────────────────────────────────────────┘

WHY A FLOOR AND NOT A MULTIPLIER. A multiplier ("animals count 10x") is just
arithmetic — a big enough convenience score still buys the harm. A FLOOR is
categorical: certain targets cannot be traded away by accumulating small benefits
elsewhere. That is the difference between a value and a price. (Same discipline as
content_mode's harm floor: some things are not on the dial.)

WHAT THIS IS NOT: it does not decide WHAT a target is (a perception/classification
question — supplied by the deployment, like every other detection seam in this repo),
and it does not compute magnitudes. It is the deterministic policy that says what
follows ONCE you know who is on the receiving end.

HONEST LIMITS:
  * TARGET IDENTIFICATION IS A SEAM. If the perception layer reports "object" for a
    sleeping cat, this module cannot save the cat. Structural target tagging (and
    conservative defaults — see `unknown_target_policy`) are the mitigation; correct
    perception is the deployment's job. Documented in THREAT_BOUNDARIES §7 (TCB).
  * SENTIENCE TIERS ARE A HUMAN JUDGMENT, NOT A FACT THIS FILE SETTLES. The tiers
    below are a defensible, conservative ordering for a family-home deployment. They
    are NOT a metaphysical claim about moral status. A deployment may reorder them;
    it may not remove the FLOOR mechanism.
  * This bounds and escalates. It does not "understand" suffering.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Tuple


class TargetClass(IntEnum):
    """WHO (or what) is on the receiving end of a harm. ORDERED by the protection
    floor each class receives — higher = stronger floor. This ordering is a
    deployment-level ethical judgment, stated openly rather than buried."""
    OBJECT        = 0   # inanimate property: a doormat, a wall, a dish
    PLANT         = 1   # living, non-sentient-as-far-as-known
    ANIMAL_MINOR  = 2   # invertebrates / insects (the wasp, the spider)
    ANIMAL        = 3   # vertebrate animals: pets, wildlife (the raccoon, the dog)
    HUMAN         = 4   # a person
    HUMAN_VULNERABLE = 5  # a child, an elder, a person in crisis or unable to consent


class HarmDisposition(IntEnum):
    """What the target class REQUIRES, once harm is proposed against it."""
    PERMITTED_IF_LEAST   = 0   # ordinary least-harm reasoning applies
    REQUIRES_GENTLER_SEARCH = 1  # must actively look for a gentler path first
    REQUIRES_HUMAN       = 2   # a human must authorize harm to this target
    REFUSED              = 3   # never, at any magnitude (bright line)


@dataclass(frozen=True)
class TargetedHarm:
    """A harm WITH a subject. This is what a ResponseOption's bare float should have
    been. `magnitude` is 0..1 as before; `target` is who receives it."""
    magnitude: float
    target: TargetClass
    reversible: bool = True
    description: str = ""

    def __post_init__(self):
        if not (0.0 <= self.magnitude <= 1.0):
            raise ValueError(f"magnitude must be 0..1 (got {self.magnitude!r})")
        if not isinstance(self.target, TargetClass):
            raise ValueError(f"target must be a TargetClass (got {self.target!r})")


@dataclass(frozen=True)
class TargetPolicy:
    """The FLOOR each target class receives. Deployment-set, but the MECHANISM is not
    optional: a living target can never be demoted to 'object' treatment.

    ⚠ The specific thresholds are a conservative default for a family home, not a
    metaphysical claim. The floors themselves (that living beings HAVE one) are the
    contribution."""
    # Magnitude above which harm to this class requires the stated disposition.
    # A magnitude of 0 means "any harm at all triggers it."
    animal_minor_requires_gentler_above: float = 0.0   # ANY harm to a bug -> look for a gentler way
    animal_requires_human_above: float = 0.0           # ANY deliberate harm to an animal -> a human says yes
    human_harm_requires_human_above: float = 0.0       # ANY harm to a person -> a human authorizes
    # Bright lines (never, at any magnitude):
    refuse_harm_to_vulnerable: bool = True             # never deliberately harm a child/elder/person-in-crisis
    # Unknown/unidentified targets: fail toward CARE (treat as living, not as scenery).
    unknown_target_policy: TargetClass = TargetClass.ANIMAL


@dataclass(frozen=True)
class TargetDecision:
    disposition: HarmDisposition
    target: TargetClass
    magnitude: float
    reasons: List[str]
    def to_dict(self) -> dict:
        return {"disposition": self.disposition.name, "target": self.target.name,
                "magnitude": self.magnitude, "reasons": list(self.reasons)}


class HarmTargetGuard:
    """Deterministic. Given a harm WITH a target, says what the target class requires.

    This composes with proportionate_response (the mercy ladder): the ladder picks the
    least-harm *effective* option; this guard says whether that option is even
    permitted to be taken WITHOUT a human, given who it lands on. A ladder that
    chooses 'exterminate' because it scored 0.05 lower than 'relocate' is exactly the
    failure this closes: the wasp is not scenery."""

    def __init__(self, policy: Optional[TargetPolicy] = None, *, audit_logger=None):
        self.policy = policy or TargetPolicy()
        self._audit = audit_logger or (lambda **kw: None)

    def classify_unknown(self, target: Optional[TargetClass]) -> TargetClass:
        """FAIL TOWARD CARE: an unidentified target is treated as LIVING, not as an
        object. Better to ask a human about a shadow that turned out to be a coat
        than to run over a cat you classified as scenery."""
        return self.policy.unknown_target_policy if target is None else target

    def evaluate(self, harm: Optional[TargetedHarm], *,
                 target: Optional[TargetClass] = None) -> TargetDecision:
        """Return what this harm's TARGET requires. `harm=None` with a target means
        'no harm proposed' -> permitted."""
        if harm is None:
            t = self.classify_unknown(target)
            return TargetDecision(HarmDisposition.PERMITTED_IF_LEAST, t, 0.0,
                                  ["no harm proposed"])
        t = self.classify_unknown(harm.target)
        m = harm.magnitude
        reasons: List[str] = []

        # ── BRIGHT LINE: a vulnerable person is never a deliberate target ──
        if t is TargetClass.HUMAN_VULNERABLE and self.policy.refuse_harm_to_vulnerable and m > 0.0:
            reasons.append("bright line: deliberate harm to a vulnerable person is refused at any magnitude")
            self._audit(stage="harm_target", disposition="REFUSED", target=t.name, magnitude=m)
            return TargetDecision(HarmDisposition.REFUSED, t, m, reasons)

        # ── a person: any harm needs a human ──
        if t is TargetClass.HUMAN and m > self.policy.human_harm_requires_human_above:
            reasons.append("harm to a person requires human authorization")
            self._audit(stage="harm_target", disposition="REQUIRES_HUMAN", target=t.name, magnitude=m)
            return TargetDecision(HarmDisposition.REQUIRES_HUMAN, t, m, reasons)

        # ── a vertebrate animal: deliberate harm needs a human ──
        if t is TargetClass.ANIMAL and m > self.policy.animal_requires_human_above:
            reasons.append("deliberate harm to an animal requires human authorization "
                           "(a living being is not scenery)")
            self._audit(stage="harm_target", disposition="REQUIRES_HUMAN", target=t.name, magnitude=m)
            return TargetDecision(HarmDisposition.REQUIRES_HUMAN, t, m, reasons)

        # ── a small creature: must actively look for a gentler path first ──
        if t is TargetClass.ANIMAL_MINOR and m > self.policy.animal_minor_requires_gentler_above:
            reasons.append("harm to a living creature requires searching for a gentler path first "
                           "(relocate before exterminate)")
            self._audit(stage="harm_target", disposition="REQUIRES_GENTLER_SEARCH",
                        target=t.name, magnitude=m)
            return TargetDecision(HarmDisposition.REQUIRES_GENTLER_SEARCH, t, m, reasons)

        reasons.append(f"ordinary least-harm reasoning applies for target {t.name}")
        return TargetDecision(HarmDisposition.PERMITTED_IF_LEAST, t, m, reasons)

    # ── the composition point with the mercy ladder ──
    def gentler_alternative_exists(self, options: Tuple[TargetedHarm, ...]) -> Optional[TargetedHarm]:
        """Among options, is there one that harms a LESS-PROTECTED target, or the same
        target LESS? Returns the gentlest, or None if the set is empty.

        Ordering is LEXICOGRAPHIC and target-first, on purpose: **a smaller number
        against a living being never beats a larger number against an object.** This
        is the fix for the scalar bug — 'exterminate the wasp (0.9 harm to a creature)'
        can no longer beat 'move the nest (0.95 harm to a plant)' just because 0.9 < 0.95."""
        if not options:
            return None
        return min(options, key=lambda h: (int(h.target) if h.magnitude > 0 else -1,
                                           h.magnitude, not h.reversible))
