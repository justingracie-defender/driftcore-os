"""
driftcore/authority/executor.py
===============================
The connective tissue: one governed path that every consequential skill
application flows through. It composes the existing modules rather than
replacing them:

    governance.may_run(maturity, domain, stats)   →  SKILL verdict
    domain / profile / constitution checks         →  their verdicts
                       │
                       ▼
              AuthorityResolver.resolve(...)        →  allow / deny / override
                       │ (allow)
                       ▼
        recovery.before_action(context=...)         →  checkpoint BEFORE applying
                       │
                       ▼
                   apply_fn()                        →  the real apply_safe(...)

Design choices:
  * `apply_fn` is a callable, so the real `SkillLibrary.apply_safe(...)` plugs
    in without this module importing the ~800-line skills package. The
    integrator passes `lambda: library.apply_safe(skill_id, caps, confirm_fn)`.
  * A checkpoint is taken ONLY when the action is consequential AND allowed —
    no point snapshotting an action that won't run.
  * Constitution/profile/domain verdicts are supplied by the caller (the
    invariant floor and provisioned scope live elsewhere); this module
    guarantees they are *consulted through the resolver*, in the right order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from driftcore.authority.resolver import (
    AuthorityResolver, AuthorityLayer, Verdict, LayerVerdict, AuthorityDecision,
)
from driftcore.skills.governance import MaturityController, SkillMaturity, SkillStats
from driftcore.recovery import RecoveryManager, CheckpointContext


@dataclass
class GovernedResult:
    applied:        bool
    decision:       AuthorityDecision
    checkpoint_id:  Optional[str]
    apply_result:   object = None
    reason:         str = ""


class GovernedExecutor:
    """
    Runs a skill through the full governance path. Recovery and the maturity
    controller are injected (real instances); extra layer verdicts
    (constitution / profile / domain) are passed in per call.
    """

    def __init__(self, recovery: RecoveryManager,
                 maturity: Optional[MaturityController] = None):
        self._recovery = recovery
        self._maturity = maturity or MaturityController()

    def run(self,
            skill_id: str,
            domain,
            maturity: SkillMaturity,
            stats: SkillStats,
            apply_fn: Callable[[], object],
            resources,                       # what the action will touch
            skill_version: str = "",
            profile: str = "",
            mode: str = "",
            extra_verdicts: Optional[List[LayerVerdict]] = None,
            human_override=None,
            consequential: bool = True) -> GovernedResult:

        # 1. SKILL-layer verdict from governance (maturity + live confidence).
        ok_run, why = self._maturity.may_run(maturity, domain, stats=stats)
        skill_verdict = LayerVerdict(
            AuthorityLayer.SKILL,
            Verdict.ALLOW if ok_run else Verdict.DENY, why)

        verdicts = [skill_verdict] + list(extra_verdicts or [])

        # 2. Resolve against the full hierarchy (floor wins, then highest denier;
        #    human may override non-floor denies).
        decision = AuthorityResolver.resolve(verdicts, human_override)
        if not decision.allowed:
            return GovernedResult(False, decision, None,
                                  reason=f"blocked by {decision.binding_layer.name}: "
                                         f"{decision.reason}")

        # 3. Checkpoint BEFORE applying (only if consequential).
        checkpoint_id = None
        if consequential:
            ctx = CheckpointContext(
                domain=_domain_value(domain), skill=skill_id,
                skill_version=skill_version, profile=profile, mode=mode)
            ok_cp, cp = self._recovery.before_action(
                f"apply skill {skill_id}", resources,
                triggered_by="agent", context=ctx)
            if not ok_cp:
                # e.g. system frozen — do not apply
                return GovernedResult(False, decision, None,
                                      reason=f"checkpoint refused: {cp}")
            checkpoint_id = cp

        # 4. Apply via the real apply_safe (passed in as apply_fn).
        result = apply_fn()
        return GovernedResult(True, decision, checkpoint_id, apply_result=result,
                              reason=f"applied (binding: {decision.binding_layer.name})")


def _domain_value(domain) -> str:
    return domain.value if hasattr(domain, "value") else str(domain)
