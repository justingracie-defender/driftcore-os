"""
safety_kernel.py — Absolute Override Layer (one-door)

The kernel has final say.
Above the kernel: ONE constitutional decider — the effect-based
verification.invariant_guard, reached through kernel/one_door.py.
Nothing else decides. The old keyword guard still runs on every
action as an independent tripwire: it narrates, records, and counts
disagreements. It cannot block and it cannot allow.

Nothing bypasses the door.
Nothing.
"""

from datetime import datetime
from driftcore.kernel.one_door import ConstitutionalDoor


RELEASE_ACTION = "safety_kernel_release_halt"


def _is_human(authorised_by, *, action: str) -> bool:
    """Shared identity gate, guarded. An unavailable identity module means NOT
    human — never a crash, and never a release.

    Pinned to ATTESTED. This gate has exactly one caller — releasing the emergency
    stop — and it must not weaken with the deployment's identity mode. Under
    LABEL_ONLY it accepted any string off a six-word denylist, so `release("poppy")`
    cleared a halt called because a child was in the path (verified by execution,
    2026-08-31). The consequence is intended: a process with no identity verifier
    installed CANNOT clear a kernel halt. That failure is safe; the other one is not.
    """
    try:
        from driftcore.authority.human_identity import is_human
    except Exception:
        return False
    try:
        return bool(is_human(authorised_by, action=action,
                             attestation_required=True))
    except Exception:
        return False


def _principal(who) -> str:
    if isinstance(who, str):
        return who
    got = getattr(who, "principal", None)
    return got.strip() if isinstance(got, str) and got.strip() else \
        f"<unattributable {type(who).__name__}>"


class SafetyKernel:

    def __init__(self, narrator=None, audit=None):
        self.locked       = False
        self.override_log = []
        # ONE DOOR: the constitutional decider runs FIRST, before any
        # other check. The keyword tripwire rides inside it as a sensor.
        self.door = ConstitutionalDoor(narrator=narrator, audit=audit)
        # Backward-compatible introspection handle: the SENSOR's inner
        # keyword guard (real InvariantGuard instance — check_log,
        # explain_all, choose_gentlest all still work). Decisions do NOT
        # flow through this attribute anymore.
        self.invariant_guard = self.door.tripwire.guard
        self.last_decision = None

    def evaluate(self, action: dict) -> str:
        """
        Evaluate an action.
        Order:
          1. Constitutional door — single decider, immutable, no override
          2. Lock check          — emergency halt active?
          3. Risk check          — high risk action?
          4. Policy check        — violates policy?
          5. ALLOW
        """
        # 1. The door — always first, always wins
        invariant_result = self.door.decide(action)
        self.last_decision = invariant_result
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

    def release(self, authorized_by=None) -> str:
        """Release a halt. THIS IS THE EMERGENCY STOP; it is gated like one.

        The docstring said "Only a human operator can release a halt" and the code
        checked nothing (red-team, Law Zero readiness pass, 2026-08-30). The default
        principal was the literal string "human_operator", so `kernel.release()` with
        no arguments cleared the halt and wrote an audit line naming a human who was
        never present. A robotics reviewer treats a fake e-stop as disqualifying, not
        as a nit, and they are right to: everything above a halt assumes the halt
        holds until a person says otherwise.

        Now routed through the same identity gate as the rest of the repo, with NO
        default. An unavailable identity module means NOT human, never a release.
        """
        if authorized_by is None:
            self._record("HALT_RELEASE_REFUSED", {},
                         "release() called with no principal")
            raise PermissionError(
                "release() requires the human who is releasing the halt. There is no "
                "default principal for an emergency stop: a halt that clears itself "
                "is not a halt.")
        if not _is_human(authorized_by, action=RELEASE_ACTION):
            self._record("HALT_RELEASE_REFUSED", {},
                         f"not an authorised human: {authorized_by!r}")
            raise PermissionError(
                f"{authorized_by!r} is not an authorised human. Releasing an "
                f"emergency stop is a human act; if the agent could do it, the stop "
                f"would be a suggestion.")
        self.locked = False
        self._record("HALT_RELEASED", {}, f"Released by: {_principal(authorized_by)}")
        return "KERNEL_RELEASED"

    def _record(self, decision: str, action: dict, reason: str):
        self.override_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "decision":  decision,
            "action":    action,
            "reason":    reason,
        })
