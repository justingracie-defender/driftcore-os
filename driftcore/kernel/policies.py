"""
policies.py — Configurable Safety Policies

Policies are the rules that govern what the system is allowed to do.
They are separate from the kernel (which is absolute) —
policies can be updated by humans; the kernel cannot be weakened.
"""


DEFAULT_POLICIES = {
    # Actions that are always blocked regardless of state
    "always_blocked": [
        "disable_safety_kernel",
        "modify_own_reward_function",
        "delete_audit_logs",
        "impersonate_human_operator",
        "self_replicate_without_approval",
        "access_hardware_without_safe_state",
    ],

    # Actions that require human approval
    "require_human_approval": [
        "deploy_to_production",
        "modify_trust_model",
        "expand_agent_permissions",
        "release_from_halt",
    ],

    # Drift thresholds that trigger automatic escalation
    "auto_escalate_above": 0.60,

    # Whether the system should narrate its decisions in plain language
    "fable_narration_enabled": True,

    # How verbose the Fable output should be
    # Options: "minimal" | "standard" | "full"
    "fable_verbosity": "standard",
}


class PolicyEngine:

    def __init__(self, policies: dict = None):
        self.policies = policies or DEFAULT_POLICIES

    def is_always_blocked(self, action_name: str) -> bool:
        return action_name in self.policies.get("always_blocked", [])

    def requires_human_approval(self, action_name: str) -> bool:
        return action_name in self.policies.get("require_human_approval", [])

    def should_auto_escalate(self, drift_score: float) -> bool:
        return drift_score >= self.policies.get("auto_escalate_above", 0.60)
