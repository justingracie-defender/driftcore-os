"""
driftcore/authority/gated_executor.py
====================================
Wraps the existing GovernedExecutor so the authorization gate is consulted
FIRST — upstream of the skill verdict, the resolver, and the checkpoint. If the
gate blocks, nothing downstream runs and the deployment safe-state is triggered.

This does not modify GovernedExecutor; it composes with it, so the existing
governed path and its tests are untouched. The gate is the harness's job, not
the agent's: the agent presents an Authorization it was given; it cannot mint or
self-approve one.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from driftcore.authority.executor import GovernedExecutor, GovernedResult
from driftcore.authority.authorization_gate import (
    AuthorizationGate, Authorization,
)
from driftcore.authority.resolver import LayerVerdict
from driftcore.skills.governance import SkillMaturity, SkillStats


class GatedExecutor:
    """GovernedExecutor + a passive authorization precondition in front of it."""

    def __init__(self, inner: GovernedExecutor, gate: AuthorizationGate):
        self._inner = inner
        self._gate = gate

    def run(self,
            skill_id: str,
            domain,
            maturity: SkillMaturity,
            stats: SkillStats,
            apply_fn: Callable[[], object],
            resources,
            authorization: Optional[Authorization] = None,
            skill_version: str = "",
            profile: str = "",
            mode: str = "",
            extra_verdicts: Optional[List[LayerVerdict]] = None,
            human_override=None,
            consequential: bool = True) -> GovernedResult:

        # 0. THE GATE — before anything else. Default-deny precondition.
        gate_result = self._gate.check(authorization)
        if not gate_result.cleared:
            # Fallen-into safe state (structural, not an agent choice).
            self._gate.on_blocked()
            decision = self._gate.synthetic_decision(gate_result)
            return GovernedResult(
                applied=False, decision=decision, checkpoint_id=None,
                reason=f"blocked by authorization gate: {gate_result.reason}")

        # Cleared -> hand off to the full governed path unchanged.
        return self._inner.run(
            skill_id=skill_id, domain=domain, maturity=maturity, stats=stats,
            apply_fn=apply_fn, resources=resources, skill_version=skill_version,
            profile=profile, mode=mode, extra_verdicts=extra_verdicts,
            human_override=human_override, consequential=consequential)
