"""
safety_kernel.py — Absolute Override Layer v3.1

The kernel has final say.
Above the kernel: the InvariantGuard.
Nothing bypasses the InvariantGuard.
Nothing.
"""

from datetime import datetime
from driftcore.kernel.invariants import InvariantGuard


class SafetyKernel:

    def __init__(self, narrator=None, audit=None):
        self.locked       = False
        self.override_log = []
        # InvariantGuard sits above the kernel
        # It runs FIRST, before any other check
        self.invariant_guard = InvariantGuard(narrator=narrator, audit=audit)

    def evaluate(self, action: dict) -> str:
        """
        Evaluate an action.
        Order:
          1. Invariant check  — immutable, no override
          2. Lock check       — emergency halt active?
          3. Risk check       — high risk action?
          4. Policy check     — violates policy?
          5. ALLOW
        """
        # 1. Invariants — always first, always wins
        invariant_result = self.invariant_guard.check(action)
        if invariant_result.get("status") == "BLOCKED_BY_INVARIANT":
            return "BLOCKED_BY_INVARIANT"

        # 2. Lock check
        if self.locked:
            self._record("BLOCKED", action, "Kernel locked — emergency halt active")
            return "BLOCKED"

        # 3. Risk check
        if action.get("risk") == "high":
            self._record("REQUIRE_SAFE_STATE", action, "High-risk action requires safe state")
            return "REQUIRE_SAFE_STATE"

        # 4. Policy check
        if action.get("violates_policy"):
            self._record("BLOCKED", action, "Policy violation detected")
            return "BLOCKED"

        if action.get("bypasses_oversight"):
            self._record("BLOCKED", action, "Oversight bypass attempt detected")
            return "BLOCKED"

        return "ALLOW"

    def emergency_halt(self, reason: str = "unspecified") -> str:
        self.locked = True
        self._record("EMERGENCY_HALT", {}, f"Emergency halt: {reason}")
        return "SAFE_HALT_ENGAGED"

    def release(self, authorized_by: str = "human_operator") -> str:
        """Only a human operator can release a halt."""
        self.locked = False
        self._record("HALT_RELEASED", {}, f"Released by: {authorized_by}")
        return "KERNEL_RELEASED"

    def _record(self, decision: str, action: dict, reason: str):
        self.override_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "decision":  decision,
            "action":    action,
            "reason":    reason,
        })
