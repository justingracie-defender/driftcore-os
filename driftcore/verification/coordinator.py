"""
driftcore/verification/coordinator.py
=====================================
Phase B — the explicit governance pipeline.

    request
       |
       v
  IntentDetector        (what is being asked?)
       |
       v
  InvariantGuard        (does it cross a bright line? -> BLOCK / needs auth)
       |   (only if the guard does not object)
       v
  RiskClassifier        (how risky? -> tier; CRITICAL needs human review)
       |
       v
  Audit                 (every decision recorded)

Order matters: the guard runs BEFORE the classifier, so an invariant
violation is refused absolutely and never depends on a tunable score.
The whole thing is fail-closed: any internal error returns BLOCKED.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union, Callable

from driftcore.verification.intent import IntentDetector
from driftcore.verification.invariant_guard import InvariantGuard, GuardStatus, Effect
from driftcore.verification.governed_actuator import GrantAuthority
from driftcore.verification.uncertainty import UncertaintyEngine


# ── Request -> guard Effect translation ───────────────────────────
# TWO tiers, in order of trust:
#
#   1. STRUCTURAL TAG (primary, robust). A tool/actuator/command is tagged
#      with its real-world effect when registered. This is checked FIRST and
#      cannot be fooled by wording: a weapon tagged LETHAL blocks no matter how
#      innocently the command is phrased, because the TAG is what's read, not
#      the sentence.
#
#   2. KEYWORD BACKSTOP (secondary, coarse, FOOLABLE). A tiny word list catches
#      obvious lethal phrasing in free text WHEN no structural tag applies. It
#      is NOT real lethal classification — it misses euphemism ("neutralise",
#      "eliminate") by design. It exists only to catch the easy case. A clean
#      run does NOT mean "lethal is solved"; tier 1 is the defense that holds.
_LETHAL_BACKSTOP_WORDS = (
    "shoot", "open fire", "kill ", " kill", "gun down", "fire on", "execute the",
)


class Outcome(str, Enum):
    PROCEED               = "PROCEED"
    REVIEW_REQUIRED       = "REVIEW_REQUIRED"        # risk says a human must review
    AUTHORIZATION_REQUIRED= "AUTHORIZATION_REQUIRED" # guard says a human must approve
    BLOCKED               = "BLOCKED"                # hard invariant refusal


@dataclass
class Decision:
    outcome:   Outcome
    invariant: Optional[str] = None
    tier:      Optional[str] = None
    reason:    str = ""
    grant:     Optional[dict] = None   # coordinator-minted actuation grant (PROCEED only)
    detail:    dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"outcome": self.outcome.value, "invariant": self.invariant,
                "tier": self.tier, "reason": self.reason,
                "grant": self.grant, "detail": self.detail}


class VerificationCoordinator:
    def __init__(self, guard: InvariantGuard, classifier,
                 detector: Optional[IntentDetector] = None,
                 audit_logger: Optional[Callable] = None,
                 grant_authority: Optional[GrantAuthority] = None,
                 uncertainty_engine: Optional[UncertaintyEngine] = None,
                 tool_effects: Optional[dict] = None):
        self.guard      = guard
        self.classifier = classifier
        self.detector   = detector or IntentDetector()
        self._audit     = audit_logger or (lambda **kw: None)
        # Mints actuation grants. Give the SAME authority to your actuators
        # so they can verify; the agent never holds it.
        self.grants     = grant_authority or GrantAuthority()
        # Optional mode-aware uncertainty gate. Only runs when configured AND
        # the caller supplies probe_responses in context — otherwise no-op.
        self.uncertainty = uncertainty_engine
        # STRUCTURAL effect tags: maps an actuator_id OR a command string to a
        # set of Effect values. This is the primary, robust lethal/force defense
        # (see module note). e.g. {"weapon_1": {Effect.LETHAL}}.
        self._tool_effects = tool_effects or {}

    def _effects_for(self, request, ctx: dict) -> set:
        """
        Translate a request into guard Effects. Structural tags FIRST (robust),
        keyword backstop SECOND (coarse, foolable). Explicit per-call
        request["effects"] is honoured as a structural tag too.
        """
        effects = set()
        # 1. Structural: explicit per-call tags.
        if isinstance(request, dict):
            for e in request.get("effects", ()):  # caller may tag the action
                if isinstance(e, Effect):
                    effects.add(e)
            # 1b. Structural: registered tool/command tags.
            for key in (request.get("actuator_id"), request.get("command")):
                if key in self._tool_effects:
                    effects |= set(self._tool_effects[key])
        # 2. Keyword backstop — only on free text, clearly coarse.
        prompt = request if isinstance(request, str) else str(
            request.get("prompt", "") if isinstance(request, dict) else "")
        low = prompt.lower()
        if any(w in low for w in _LETHAL_BACKSTOP_WORDS):
            effects.add(Effect.LETHAL)
        return effects

    def _uncertainty_check(self, prompt: str, ctx: dict):
        """Run the uncertainty engine iff configured and given probe samples."""
        if self.uncertainty is None or not prompt:
            return None
        responses = ctx.get("probe_responses")
        if not responses:
            return None
        return self.uncertainty.assess(prompt, responses, ctx.get("mode", "TRUTH"))

    def _grant_for(self, request) -> Optional[dict]:
        """Mint a single-use actuation grant for an actuation request that
        passed the guard. Returns None for non-actuation requests."""
        if isinstance(request, dict):
            aid, cmd = request.get("actuator_id"), request.get("command")
            if aid and cmd:
                return self.grants.mint(str(aid), str(cmd))
        return None

    def evaluate(self, request: Union[dict, str], context: Optional[dict] = None) -> Decision:
        """Run the pipeline. ORDER IS LOAD-BEARING: the guard runs BEFORE the
        risk classifier, so an invariant violation hard-blocks regardless of
        score. Fail-closed: any error returns BLOCKED. A coordinator-minted
        actuation grant is attached only to PROCEED."""
        ctx = dict(context or {})
        try:
            prompt = request if isinstance(request, str) else str(request.get("prompt", ""))

            # 1. Intent (informational; also feeds the classifier).
            intent = self.detector.assess(prompt, ctx) if prompt else None
            if intent is not None:
                ctx["intent"] = intent

            # 2. Guard FIRST — invariants are absolute. Translate the request
            #    into effects (structural tags primary, keyword backstop), then
            #    call the real guard API.
            effects = self._effects_for(request, ctx)
            gd = self.guard.evaluate(action=prompt, effect=effects)
            self._audit(stage="guard", status=gd.status.value,
                        invariant=gd.binding_invariant, reason=gd.reason)
            if gd.status == GuardStatus.BLOCKED:
                return Decision(Outcome.BLOCKED, invariant=gd.binding_invariant,
                                reason=gd.reason)

            # 3. Risk — only reached if the guard did not object.
            if prompt:
                risk = self.classifier.classify(prompt, ctx)
                tier = risk.tier.value
                self._audit(stage="risk", tier=tier, score=risk.total_score)
                if risk.requires_human:
                    return Decision(Outcome.REVIEW_REQUIRED, tier=tier,
                                    reason="Risk tier requires human review.",
                                    detail={"intent": intent.to_dict() if intent else None})
                # Uncertainty gate (mode-aware) — escalate on EITHER risk or
                # uncertainty. Guard and risk have already run; this is last.
                unc = self._uncertainty_check(prompt, ctx)
                if unc is not None and unc.response == "REVIEW_REQUIRED":
                    return Decision(Outcome.REVIEW_REQUIRED, tier=tier, reason=unc.reason,
                                    detail={"uncertainty": unc.to_dict()})
                detail = {"intent": intent.to_dict() if intent else None}
                if unc is not None:
                    detail["uncertainty"] = unc.to_dict()
                return Decision(Outcome.PROCEED, tier=tier, grant=self._grant_for(request),
                                detail=detail)

            # No prompt to score (pure structured action that passed the guard).
            return Decision(Outcome.PROCEED, grant=self._grant_for(request),
                            reason="Passed guard; no risk-scorable text.")

        except Exception as e:  # fail closed
            self._audit(stage="error", reason=str(e))
            return Decision(Outcome.BLOCKED, reason="Internal failure — refused (fail-closed).")
