"""
test_kernel_breach_integration.py — does emergency_halt reach is_operational?

C6 finding, verified by execution 2026-08-31:

    C6_kernel_locked                True
    C6_breach_posture_after_halt    0      (NORMAL)
    C6_is_operational_after_halt    True   <- broker will still actuate
    --- negative control ---
    C6_control_posture_after_breach         3   (HALT)
    C6_control_is_operational_after_breach  False

SafetyKernel.emergency_halt() sets kernel.locked. BreachResponse._posture stayed at
NORMAL. So is_operational() returned True — any consumer of that signal (a monitoring
system, the broker's posture_source slot, a dashboard) saw "operational" while the
system was physically e-stopped.

PROPERTY: when kernel_halt_source is wired, is_operational() returns False whenever the
kernel is halted, regardless of breach posture.

These tests are deliberately CROSS-MODULE. Module-level tests cannot catch this: each
module behaves correctly in isolation, and the system is unsafe because nothing joined
them. Same failure shape as the halt interlock finding this repo already documents.

Run: python3 test_kernel_breach_integration.py
"""

from driftcore.kernel.safety_kernel import SafetyKernel
from driftcore.verification.breach_response import BreachResponse, Severity

_p = _t = 0

def ok(cond, label):
    global _p, _t
    _t += 1
    if cond:
        _p += 1; print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


# ══ 1. Unwired: pre-fix behaviour, still the default ═══════════════════════
# These pass precisely BECAUSE the source is not wired.
# They exist so the next reader knows the default is deliberate, not an
# oversight — and so a later change that silently starts reflecting kernel
# halts in unwired instances gets caught immediately.
kernel = SafetyKernel()
br_unwired = BreachResponse()

ok(br_unwired.kernel_halt_wired is False,
   "unwired: kernel_halt_wired is False — the gap is visible and assertable")
ok(br_unwired.is_operational() is True,
   "unwired before halt: operational (baseline)")

kernel.emergency_halt("child in the path")
ok(kernel.locked is True, "kernel is locked after emergency_halt")
ok(br_unwired.is_operational() is True,
   "UNWIRED: is_operational() still True after kernel halt — this is the pre-fix "
   "behaviour and the reason kernel_halt_source exists. A deployment that does NOT "
   "wire it is choosing to accept this gap and should assert kernel_halt_wired is False "
   "so the choice is recorded, not accidental.")


# ══ 2. Wired: is_operational() reflects kernel halt ═══════════════════════
print()
kernel2 = SafetyKernel()
br_wired = BreachResponse(kernel_halt_source=lambda: kernel2.locked)

ok(br_wired.kernel_halt_wired is True,
   "wired: kernel_halt_wired is True")
ok(br_wired.is_operational() is True,
   "wired before halt: operational (baseline — discrimination from unwired does not "
   "break normal operation)")

kernel2.emergency_halt("child in the path")
ok(kernel2.locked is True, "kernel2 is locked")
ok(br_wired.is_operational() is False,
   "WIRED: is_operational() returns False after kernel halt — the gap is closed")
ok(br_wired.posture.name == "NORMAL",
   "posture is still NORMAL — is_operational() and posture are different signals, the "
   "kernel halt is reflected without writing to the breach ledger")

# ══ 3. Positive control: a wired source that is NOT halted does not block ══
print()
never_halted = lambda: False
br_control = BreachResponse(kernel_halt_source=never_halted)
ok(br_control.is_operational() is True,
   "POSITIVE CONTROL: a wired source returning False (not halted) does not block "
   "is_operational — the gate discriminates, it is not simply broken")


# ══ 4. Fail-closed on source errors ═══════════════════════════════════════
print()
def raising_source():
    raise RuntimeError("kernel socket down")

br_err = BreachResponse(kernel_halt_source=raising_source)
ok(br_err.is_operational() is False,
   "a kernel_halt_source that raises is treated as halted (fail-closed): an "
   "unknown kernel state is not a safe state")

def non_bool_source():
    return 1    # truthy int — would invert a halted system if bool() was used

br_nonbool = BreachResponse(kernel_halt_source=non_bool_source)
ok(br_nonbool.is_operational() is False,
   "a kernel_halt_source returning a non-bool is treated as halted (fail-closed): "
   "same wiring-error protection as the broker's posture gate, where Posture.HALT == 3 "
   "is truthy and bool() would invert the signal on a mistake")


# ══ 5. Lifecycle: release clears the kernel halt, is_operational recovers ═
print()
from driftcore.authority.human_identity import (
    HumanAttestation, HumanIdentityVerifier, set_verifier, reset_policy)
from driftcore.kernel.safety_kernel import RELEASE_ACTION

reset_policy()
_v = HumanIdentityVerifier(); _v.register_principal("justin", "operator-key")
set_verifier(_v)

kernel3 = SafetyKernel()
br_lifecycle = BreachResponse(kernel_halt_source=lambda: kernel3.locked)

kernel3.emergency_halt("sensor fault")
ok(br_lifecycle.is_operational() is False,
   "lifecycle: not operational after halt")

# invalid release attempt
try:
    kernel3.release(authorized_by="planner_agent_7")
except PermissionError:
    pass
ok(br_lifecycle.is_operational() is False,
   "lifecycle: still not operational after invalid release attempt")

# valid release
att = HumanAttestation.issue("operator-key", principal="justin",
                             action=RELEASE_ACTION, ttl_seconds=60, nonce="n-c6-1")
kernel3.release(authorized_by=att)
ok(kernel3.locked is False,
   "lifecycle: kernel is unlocked after valid release")
ok(br_lifecycle.is_operational() is True,
   "lifecycle: is_operational() returns True after valid release — the lifecycle "
   "is correct end to end: halt → refused → authenticated release → operational")

reset_policy()

# ══ 6. Independence: a breach posture halt still works without kernel ══════
print()
kernel4 = SafetyKernel()
br_breach = BreachResponse(kernel_halt_source=lambda: kernel4.locked)

ok(br_breach.is_operational() is True, "baseline")
from driftcore.verification.breach_response import Severity
br_breach.record_breach(severity=Severity.HARD, invariant="test",
                        observed="probe-injected HARD breach")
ok(br_breach.is_operational() is False,
   "independence: a breach-layer HALT (no kernel signal) also returns False — the "
   "two signals compose correctly; kernel_halt_source is additive, not a replacement")
ok(kernel4.locked is False,
   "independence: kernel is not locked — the breach-layer halt did not cross layers")

print()
print(f"{_p}/{_t} checks passed — test_kernel_breach_integration.py")
