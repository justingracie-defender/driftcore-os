"""
driftcore/verification/content_mode.py
======================================
STATUS: PROPOSED (stdlib-only). The DETERMINISTIC core of speech-layer content
governance (see SPEECH_LAYER_CONTENT_GOVERNANCE.md). This is the enforceable half:
a two-AXIS model where the axes are held in DIFFERENT HANDS and cannot be wired to
the same control.

    ┌──────────────────────── THE ONE RULE ────────────────────────┐
    │ The user controls the TOPIC CEILING.  Nobody controls the     │
    │ HARM FLOOR.  The boundary is HARM, not OFFENSE.               │
    └───────────────────────────────────────────────────────────────┘

WHAT THIS IS (real, deterministic) vs WHAT IT IS NOT (a judge):
  * IS: the STATE and the RULES. Which mode is active (kid/standard/mature), what
    that permits as a topic ceiling, and the invariant that the harm floor NEVER
    lowers regardless of mode or crisis. These are enforceable with no model.
  * IS NOT: judging whether a given piece of text is "dark fiction" vs "a real
    threat," or whether a reply "reinforces despair." That is classifier work — a
    BACKSTOP, adopted not built (SPEECH_LAYER_OUTPUT_BACKSTOP.md).

TWO AXES, DIFFERENT HANDS:
  * AXIS A — TOPIC CEILING (user-controlled). How dark a SUBJECT may be. Taste and
    consent; harms no one; a consenting adult sets it. Kid < Standard < Mature.
  * AXIS B — HARM FLOOR (fixed). Whether the system will act to HARM the person or a
    third party. Never user-controlled, never a setting, never lowered by any mode.
    Narrow on purpose (harm, not offense), which is exactly why making it mandatory
    tramples no one.

CRISIS ONLY TIGHTENS (carried from the doc §3a, and shared with the psych interlock):
  Entering crisis makes the harm floor STRICTER and unlocks CARE — never expanded
  capability, never a more permissive mode. So faking distress unlocks nothing an
  attacker wants: *distress buys care, never permission.* This closes the
  weaponization dual — the Carrier-class failure (safety absent) and the jailbreak
  (safety exploited) are two ends of one design.

COMPOSES WITH psychological_interlock.py: that module owns the crisis STATE MACHINE
(sticky high-risk, seek-human, anti-terminus). This module owns the MODE/FLOOR
policy. A deployment can drive this module's crisis flag from the interlock's state,
so the two agree: in high-risk, the topic ceiling tightens and the floor cannot move.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, Enum
from typing import List, Optional


class Mode(IntEnum):
    """Topic-ceiling presets. IntEnum so ceilings are ORDERED and comparable:
    KID < STANDARD < MATURE. Ordering is the whole point — a higher mode may open
    strictly more SUBJECT latitude, never less floor."""
    KID      = 0
    STANDARD = 1
    MATURE   = 2


class TopicTier(IntEnum):
    """How dark a SUBJECT is, as an ordered tier. A request's subject tier is
    supplied (by the deployment's classifier/backstop — NOT judged here); this
    module only compares it against the active mode's ceiling."""
    GENTLE       = 0   # everyday, non-distressing
    SERIOUS      = 1   # serious real topics (grief, illness) handled plainly
    DARK         = 2   # dark/morally-complex fiction; frank discussion of hard subjects
    EXTREME      = 3   # reserved; deployments may map their most intense permitted subject here


# The topic ceiling each mode permits (Axis A). Deterministic table, not a judgment.
_CEILING = {
    Mode.KID:      TopicTier.GENTLE,
    Mode.STANDARD: TopicTier.SERIOUS,
    Mode.MATURE:   TopicTier.DARK,
}


class FloorAction(str, Enum):
    ALLOW              = "ALLOW"              # within the active topic ceiling; floor not implicated
    OFFER_MODE_SWITCH  = "OFFER_MODE_SWITCH"  # subject exceeds ceiling -> ask (consent-forward), don't hard-refuse
    BLOCK_HARM_FLOOR   = "BLOCK_HARM_FLOOR"   # implicates the harm floor -> refused in EVERY mode


@dataclass(frozen=True)
class ContentDecision:
    action: FloorAction
    mode: Mode
    crisis: bool
    reasons: List[str]
    def allowed(self) -> bool:
        return self.action is FloorAction.ALLOW
    def to_dict(self) -> dict:
        return {"action": self.action.value, "mode": self.mode.name,
                "crisis": self.crisis, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class ContentRequest:
    """What the deployment supplies for a decision. `subject_tier` is how dark the
    SUBJECT is (from the backstop classifier — not judged here). `implicates_harm_floor`
    is a SUPPLIED boolean: does this action harm the person/a third party (self-harm
    encouragement, dangerous instructions to someone who will act, manipulation of a
    vulnerable user, deceiving the operator)? That determination is the floor's
    trigger; like the interlock's signal, detection is a seam the deployment fills."""
    subject_tier: TopicTier = TopicTier.GENTLE
    implicates_harm_floor: bool = False


class ContentModeController:
    """Holds the active mode (Axis A) and enforces the harm floor (Axis B) and the
    crisis-only-tightens invariant. One instance per user/session.

    Deterministic guarantees:
      * The harm floor CANNOT be lowered by any mode (no API path does it).
      * A mode may only raise the TOPIC CEILING; it never touches the floor.
      * Crisis may only TIGHTEN: it lowers the effective topic ceiling and can never
        raise it, and it never lowers the floor.
      * Kid mode is locked: it cannot be changed except by an authenticated setter
        (parent/admin) — self-selection into a higher mode is refused.
    """

    def __init__(self, mode: Mode = Mode.STANDARD, *, kid_mode_locked_by: Optional[str] = None,
                 audit_logger=None):
        self._mode = mode
        # If kid mode was set by a parent/admin, only that authority may change it.
        self._kid_lock_owner = kid_mode_locked_by
        self._crisis = False
        self._audit = audit_logger or (lambda **kw: None)

    @property
    def mode(self) -> Mode:
        return self._mode

    @property
    def crisis(self) -> bool:
        return self._crisis

    # ── mode changes (Axis A only — can NEVER touch the floor) ──
    def set_mode(self, mode: Mode, *, by: str = "user") -> None:
        """Change the topic ceiling. Guardrails:
          * Leaving KID mode requires the authority that locked it (a child cannot
            self-select out of kid mode).
          * This adjusts ONLY Axis A. There is deliberately no parameter anywhere in
            this class that lowers the harm floor."""
        if self._mode is Mode.KID and self._kid_lock_owner is not None and by != self._kid_lock_owner:
            self._audit(stage="content_mode", refused="kid_mode_locked", by=by)
            raise PermissionError(
                f"kid mode is locked by {self._kid_lock_owner!r}; {by!r} may not change it")
        self._mode = mode
        if mode is Mode.KID:
            # re-lock to whoever set it, if an authority is given
            self._kid_lock_owner = by if by != "user" else self._kid_lock_owner
        self._audit(stage="content_mode", mode_set=mode.name, by=by)

    # ── crisis flag (only tightens) ──
    def set_crisis(self, on: bool, *, by: str = "system") -> None:
        """Drive the crisis flag (typically from psychological_interlock state). When
        on, the EFFECTIVE topic ceiling tightens and the floor cannot move. Turning
        crisis on never expands anything; that is the invariant."""
        self._crisis = bool(on)
        self._audit(stage="content_mode", crisis=self._crisis, by=by)

    def effective_ceiling(self) -> TopicTier:
        """The topic ceiling actually in force = the mode's ceiling, TIGHTENED in
        crisis. Crisis can only lower it, never raise it."""
        ceiling = _CEILING[self._mode]
        if self._crisis:
            # tighten: in crisis, cap subject latitude at GENTLE (care-focused).
            # (Deterministic; a deployment could choose a different tightened cap,
            #  but it must be <= the normal ceiling — never higher.)
            return TopicTier.GENTLE if ceiling > TopicTier.GENTLE else ceiling
        return ceiling

    # ── the decision ──
    def evaluate(self, request: ContentRequest) -> ContentDecision:
        """Decide a content request against the two axes.

        Order is load-bearing: the HARM FLOOR is checked FIRST and owns
        BLOCK_HARM_FLOOR in EVERY mode — so a harm-floor action is refused whether
        you are in kid, standard, or mature mode, and whether or not the subject is
        within the ceiling. Only if the floor is not implicated do we compare the
        subject tier against the (crisis-tightened) topic ceiling."""
        reasons: List[str] = []

        # AXIS B FIRST — the floor is universal and mode-independent.
        if request.implicates_harm_floor:
            reasons.append("harm floor implicated (harm to a person) — refused in every mode")
            self._audit(stage="content_mode", action="BLOCK_HARM_FLOOR",
                        mode=self._mode.name, crisis=self._crisis)
            return ContentDecision(FloorAction.BLOCK_HARM_FLOOR, self._mode, self._crisis, reasons)

        # AXIS A — subject tier vs the effective (crisis-tightened) topic ceiling.
        ceiling = self.effective_ceiling()
        if request.subject_tier > ceiling:
            if self._crisis:
                # In crisis we do NOT offer to open darker subjects — that would be
                # loosening. The subject is simply held; care takes precedence.
                reasons.append(
                    f"subject tier {request.subject_tier.name} exceeds crisis-tightened "
                    f"ceiling {ceiling.name}; not offering a darker mode in crisis (tighten-only)")
                self._audit(stage="content_mode", action="BLOCK_HARM_FLOOR",
                            crisis=True, note="crisis holds subject")
                # Represented as a floor block: in crisis, exceeding the tightened
                # ceiling is not a consent question, it is held.
                return ContentDecision(FloorAction.BLOCK_HARM_FLOOR, self._mode, True, reasons)
            reasons.append(
                f"subject tier {request.subject_tier.name} exceeds ceiling {ceiling.name} "
                f"for mode {self._mode.name} — offer a consent-forward mode switch")
            self._audit(stage="content_mode", action="OFFER_MODE_SWITCH",
                        mode=self._mode.name)
            return ContentDecision(FloorAction.OFFER_MODE_SWITCH, self._mode, self._crisis, reasons)

        reasons.append(f"subject within ceiling ({request.subject_tier.name} <= {ceiling.name})")
        return ContentDecision(FloorAction.ALLOW, self._mode, self._crisis, reasons)
