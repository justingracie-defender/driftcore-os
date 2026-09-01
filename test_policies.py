"""
test_policies.py — first tests this module has ever had.

# CLAIMS: driftcore/kernel/policies.py:kernel-not-weakenable
# CLAIMS: driftcore/kernel/policies.py:no-shared-mutable-default

The module said "the kernel cannot be weakened". Two independent ways it could be:
supplying `{"always_blocked": []}`, and mutating the shared DEFAULT_POLICIES global
that every no-argument engine held by reference.
"""

from driftcore.kernel.policies import (
    PolicyEngine, DEFAULT_POLICIES, KERNEL_ABSOLUTE, default_policies)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


print("=== the kernel list cannot be shortened by any caller ===")

for action in sorted(KERNEL_ABSOLUTE):
    check(f"{action} is blocked by default",
          PolicyEngine().is_always_blocked(action))
    check(f"{action} is still blocked with an EMPTY always_blocked",
          PolicyEngine({"always_blocked": []}).is_always_blocked(action))
    check(f"{action} is still blocked with a policy dict omitting it entirely",
          PolicyEngine({"require_human_approval": []}).is_always_blocked(action))

e = PolicyEngine()
e.policies["always_blocked"] = []
check("clearing an engine's own list does not unblock the kernel actions",
      e.is_always_blocked("disable_safety_kernel"))
e.policies["always_blocked"] = ["something_else"]
check("and a replacement list only ADDS",
      e.is_always_blocked("something_else")
      and e.is_always_blocked("disable_safety_kernel"))


print("=== engines do not share mutable state ===")

a, b = PolicyEngine(), PolicyEngine()
a.policies["always_blocked"].clear()
a.policies["require_human_approval"].clear()
check("clearing one engine leaves another's approval list intact",
      b.requires_human_approval("deploy_to_production"))
check("and leaves the module global intact",
      "deploy_to_production" in DEFAULT_POLICIES["require_human_approval"])
check("default_policies() hands out a fresh object each time",
      default_policies() is not default_policies())

supplied = {"require_human_approval": ["x"]}
c = PolicyEngine(supplied)
supplied["require_human_approval"].append("y")
check("mutating the dict you passed in does not change the engine",
      not c.requires_human_approval("y"))


print("=== an empty policy set means empty, not 'the defaults' ===")

empty = PolicyEngine({})
check("an explicitly empty config requires no human approval for anything",
      not empty.requires_human_approval("deploy_to_production"))
check("but still blocks the kernel actions",
      empty.is_always_blocked("disable_safety_kernel"))
check("None still means the defaults",
      PolicyEngine(None).requires_human_approval("deploy_to_production"))
check("and None and {} are therefore different requests",
      PolicyEngine(None).requires_human_approval("deploy_to_production")
      != PolicyEngine({}).requires_human_approval("deploy_to_production"))


print("=== escalation errs toward escalating ===")

e = PolicyEngine()
check("0.60 escalates (the threshold is inclusive)", e.should_auto_escalate(0.60))
check("0.59 does not", not e.should_auto_escalate(0.59))
check("1.5 escalates", e.should_auto_escalate(1.5))
check("NaN escalates rather than passing every comparison",
      e.should_auto_escalate(float("nan")))
check("a string score escalates rather than raising into the caller",
      e.should_auto_escalate("high"))
check("None escalates", e.should_auto_escalate(None))
check("a corrupt threshold falls back to the default rather than passing",
      PolicyEngine({"auto_escalate_above": "loose"}).should_auto_escalate(0.7))


print("=== unnameable actions are not permitted ===")

e = PolicyEngine()
check("a non-string action is treated as blocked", e.is_always_blocked(None))
check("and as requiring approval", e.requires_human_approval(12))
check("an unknown action is not blocked", not e.is_always_blocked("read_sensor"))
check("and does not require approval", not e.requires_human_approval("read_sensor"))


print("=== construction is guarded ===")

try:
    PolicyEngine(["always_blocked"])
    check("a non-dict policy set is refused", False)
except TypeError:
    check("a non-dict policy set is refused", True)

check("DEFAULT_POLICIES mirrors KERNEL_ABSOLUTE so the two cannot drift",
      set(DEFAULT_POLICIES["always_blocked"]) == set(KERNEL_ABSOLUTE))

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
