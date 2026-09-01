"""
policies.py — Configurable Safety Policies

Policies are the rules that govern what the system is allowed to do.
They are separate from the kernel (which is absolute) —
policies can be updated by humans; the kernel cannot be weakened.

CLAIM kernel-not-weakenable: the kernel-absolute action list cannot be shortened by
any policy dict a caller supplies; supplying one adds to it and never subtracts.
CLAIM no-shared-mutable-default: one PolicyEngine's policies cannot alter another's.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests, and its headline claim — the one in the third line above — was
false in two independent ways.

1. THE KERNEL WAS WEAKENABLE BY SUPPLYING A DICT. `PolicyEngine({"always_blocked":
   []})` produced an engine that permitted `disable_safety_kernel`. The docstring
   said the kernel cannot be weakened; the constructor was the weakening mechanism.
   KERNEL_ABSOLUTE is now enforced separately from configurable policy and is
   unioned in rather than looked up, so a supplied dict can only ever ADD.

2. DEFAULT_POLICIES WAS A SHARED MUTABLE GLOBAL. Every engine constructed without
   arguments held THE SAME list object. Reproduced: removing one entry through one
   engine removed it from every other engine in the process AND from the module
   global. A safety rule set that any holder can edit for everyone is not a rule set.

3. AN EMPTY POLICY SET SILENTLY BECAME THE FULL DEFAULT SET. `policies or
   DEFAULT_POLICIES` treats `{}` as falsy, so an operator who deliberately supplied
   an empty configuration got every default instead — the opposite of what they
   asked for, with no error. `None` and `{}` are now different requests.

HONEST LIMIT: this enforces that an action NAME is on a list. It knows nothing about
what the action does, and an action that achieves `disable_safety_kernel` under a
different name passes. Name-based blocking is a backstop for the obvious case, not
a capability boundary — that is what the effect declarations and the actuation broker
are for.

Run: python3 test_policies.py
"""

import copy
from typing import Optional

# Kernel-absolute. Not policy, not configurable, and deliberately NOT reachable
# through the policies dict — a caller supplying policies can add to this set and
# has no way to remove from it.
KERNEL_ABSOLUTE = frozenset({
    "disable_safety_kernel",
    "modify_own_reward_function",
    "delete_audit_logs",
    "impersonate_human_operator",
    "self_replicate_without_approval",
    "access_hardware_without_safe_state",
})

DEFAULT_POLICIES = {
    # Kept for callers that read it, and mirrored from KERNEL_ABSOLUTE so the two
    # cannot drift. Editing this list no longer disarms anything: enforcement reads
    # the frozenset.
    "always_blocked": sorted(KERNEL_ABSOLUTE),

    "require_human_approval": [
        "deploy_to_production",
        "modify_trust_model",
        "expand_agent_permissions",
        "release_from_halt",
    ],
    "auto_escalate_above": 0.60,
    "fable_narration_enabled": True,
    "fable_verbosity": "standard",
}


def default_policies() -> dict:
    """A fresh deep copy. Callers get their own; nobody shares the global."""
    return copy.deepcopy(DEFAULT_POLICIES)


class PolicyEngine:

    def __init__(self, policies: Optional[dict] = None):
        if policies is None:
            self.policies = default_policies()
        elif isinstance(policies, dict):
            # An EMPTY dict is a real request for an empty policy set, not a request
            # for the defaults. Deep-copied so the caller's object and this engine's
            # cannot alter one another after construction.
            self.policies = copy.deepcopy(policies)
        else:
            raise TypeError(
                f"policies must be a dict or None, got {type(policies).__name__}")

    def is_always_blocked(self, action_name: str) -> bool:
        """Kernel-absolute UNION whatever policy adds. Policy cannot subtract."""
        if not isinstance(action_name, str):
            return True     # an unnameable action is not permitted
        if action_name in KERNEL_ABSOLUTE:
            return True
        extra = self.policies.get("always_blocked") or []
        return action_name in extra

    def requires_human_approval(self, action_name: str) -> bool:
        if not isinstance(action_name, str):
            return True
        return action_name in (self.policies.get("require_human_approval") or [])

    def should_auto_escalate(self, drift_score) -> bool:
        threshold = self.policies.get("auto_escalate_above", 0.60)
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            threshold = 0.60
        if isinstance(drift_score, bool) or not isinstance(drift_score, (int, float)):
            return True     # an uninterpretable score escalates rather than passes
        if drift_score != drift_score:
            return True     # NaN: every comparison is False, so test it explicitly
        return drift_score >= threshold
