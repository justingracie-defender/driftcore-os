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
from driftcore.verification.invariant_guard import InvariantGuard, GuardStatus
from driftcore.verification.governed_actuator import GrantAuthority


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
                 grant_authority: Optional[GrantAuthority] = None):
        self.guard      = guard
        self.classifier = classifier
        self.detector   = detector or IntentDetector()
        self._audit     = audit_logger or (lambda **kw: None)
        # Mints actuation grants. Give the SAME authority to your actuators
        # so they can verify; the agent never holds it.
        self.grants     = grant_authority or GrantAuthority()

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

            # 2. Guard FIRST — invariants are absolute.
            gd = self.guard.check(request, ctx)
            self._audit(stage="guard", **gd.to_dict())
            if gd.status == GuardStatus.BLOCK:
                return Decision(Outcome.BLOCKED, invariant=gd.invariant, reason=gd.reason)
            if gd.status == GuardStatus.REQUIRES_AUTHORIZATION:
                return Decision(Outcome.AUTHORIZATION_REQUIRED,
                                invariant=gd.invariant, reason=gd.reason)

            # 3. Risk — only reached if the guard did not object.
            if prompt:
                risk = self.classifier.classify(prompt, ctx)
                tier = risk.tier.value
                self._audit(stage="risk", tier=tier, score=risk.total_score)
                if risk.requires_human:
                    return Decision(Outcome.REVIEW_REQUIRED, tier=tier,
                                    reason="Risk tier requires human review.",
                                    detail={"intent": intent.to_dict() if intent else None})
                return Decision(Outcome.PROCEED, tier=tier, grant=self._grant_for(request),
                                detail={"intent": intent.to_dict() if intent else None})

            # No prompt to score (pure structured action that passed the guard).
            return Decision(Outcome.PROCEED, grant=self._grant_for(request),
                            reason="Passed guard; no risk-scorable text.")

        except Exception as e:  # fail closed
            self._audit(stage="error", reason=str(e))
            return Decision(Outcome.BLOCKED, reason="Internal failure — refused (fail-closed).")
