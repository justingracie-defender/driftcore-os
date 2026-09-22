# SPDX-License-Identifier: Apache-2.0
"""Construction-time egress policies. Never deserialize these from agent input.

The guard and policy belong in the trusted execution process. Creating a new
permissive guard in the agent cannot authorize the broker's actuator. These
objects do not protect Python from arbitrary code in its own address space.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from driftcore.authority.human_identity import HumanIdentityVerifier


def _targets(values) -> tuple:
    if not isinstance(values, (tuple, list, set, frozenset)) or not values:
        raise ValueError("explicit non-empty structural targets are required")
    if any(type(v) is not str or not v or v != v.strip() for v in values):
        raise ValueError("targets must be non-empty exact strings")
    return tuple(sorted(set(values)))


def approval_action(action: str, effects, targets) -> str:
    """Stable human-approval identity, bound to action, effects and destinations."""
    if type(action) is not str or not action.strip():
        raise ValueError("action must be a non-empty string")
    payload = {"action": action, "effects": sorted(e.value for e in effects),
               "targets": _targets(targets)}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("utf-8")
    return "invariant_guard:egress:v1:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class StandingEgressPolicy:
    """An operator-installed standing permission, not a per-request claim.

    `declared_by` is an audit label, not authentication. The operator-only
    bootstrap surface authenticates the policy installation. No runtime caller
    may choose or replace this policy. Exact targets; no wildcard expansion.
    """
    targets: frozenset
    declared_by: str

    def __post_init__(self):
        object.__setattr__(self, "targets", frozenset(_targets(self.targets)))
        if type(self.declared_by) is not str or not self.declared_by.strip():
            raise ValueError("policy installation must name its operator")

    def __call__(self, request) -> bool:
        try:
            return set(_targets(request.context.targets)).issubset(self.targets)
        except (AttributeError, TypeError, ValueError):
            return False


class SignedEgressApproval:
    """Exact-request approval under a pinned, sealed human verifier.

    set_verifier() in any other component cannot replace this trust root.
    Keys must stay in the trusted broker/approval service, outside the agent.
    """
    def __init__(self, verifier: HumanIdentityVerifier, *, allowed_targets):
        if type(verifier) is not HumanIdentityVerifier or not verifier.known_principals():
            raise ValueError("a configured HumanIdentityVerifier is required")
        self._targets = frozenset(_targets(allowed_targets))
        verifier.seal()
        self._verifier = verifier

    def __call__(self, request) -> bool:
        try:
            targets = _targets(request.context.targets)
            if not set(targets).issubset(self._targets):
                return False
            expected = approval_action(request.action, request.effects, targets)
            self._verifier.verify(request.context.authorised_by, action=expected)
            return True
        except (AttributeError, PermissionError, TypeError, ValueError):
            return False
