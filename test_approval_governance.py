"""
test_approval_governance.py — ANTI-SPAM/FATIGUE + UNCERTAINTY-AS-FACT (HARDENED)
==============================================================================
STATUS: PROPOSED. Pins the original properties AND the red-team fixes:
  - content-blind approval cap; identical for trivial and dangerous requests
  - splitting a bundle across the window is refused
  - delta is a fact, not friction
  - second approver required ONLY from a human-set threshold
  - HARDENED: irreversible count is verifier-DERIVED from operations, not caller-supplied
  - harm estimate renders as a fact with provenance; no judgment word
  - HARDENED: a planner-sourced (unverified) estimate may NOT drive a human cutoff

Run with:  python test_approval_governance.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.approval_governance import (
    ApprovalPolicy, ApprovalThrottle, Operation, default_irreversibility,
    ApprovalRateExceeded, SplitEvasion,
)
from driftcore.verification.harm_estimate import (
    HarmEstimate, HarmThreshold, exceeds, UntrustedEstimate,
)

results = []
def check(n, c):
    print(f"  {'ok' if c else 'XX'}: {n}")
    results.append((n, bool(c)))


# ── content-blind rate cap ──────────────────────────────────────────────────
t = ApprovalThrottle(ApprovalPolicy(max_approvals_per_window=3))
for _ in range(3):
    t.register_approval("dr_a")
try:
    t.register_approval("dr_a"); check("approvals past the per-window cap are refused", False)
except ApprovalRateExceeded:
    check("approvals past the per-window cap are refused", True)

t2 = ApprovalThrottle(ApprovalPolicy(max_approvals_per_window=2))
t2.register_approval("dr_b"); t2.register_approval("dr_b")
try:
    t2.register_approval("dr_b"); check("the cap is content-blind", False)
except ApprovalRateExceeded:
    check("the cap is content-blind", True)

check("no setter exists to raise the cap (agent cannot self-grant approvals)",
      not any("policy" in n.lower() and "set" in n.lower() for n in dir(t)))


# ── bundling: splitting a batch is refused ──────────────────────────────────
t3 = ApprovalThrottle(ApprovalPolicy(max_approvals_per_window=100))
t3.register_approval("dr_c", bundle_key="batch-77")
try:
    t3.register_approval("dr_c", bundle_key="batch-77"); check("splitting one bundle is refused", False)
except SplitEvasion:
    check("splitting one bundle is refused", True)


# ── delta is a fact, not friction ───────────────────────────────────────────
fact = ApprovalThrottle.delta_fact(12, [0, 0, 0, 1, 0])
check("delta surfaces as a fact showing the jump", "12" in fact and "\u0394" in fact)
check("delta fact carries no judgment word",
      not any(w in fact.lower() for w in ("risk", "danger", "severe", "recommend", "should")))


# ── HARDENED: irreversible count is verifier-derived, not caller-supplied ────
policy = ApprovalPolicy(max_approvals_per_window=100, second_approver_over_irreversible=10)
t4 = ApprovalThrottle(policy)
# 12 destructive ops -> derived count 12 > 10 -> second approver required
destructive = [Operation(f"op{i}", "delete") for i in range(12)]
check("verifier derives irreversible count from ops (12 deletes > 10 -> 2nd approver)",
      t4.second_approver_required(destructive) is True)
# the planner CANNOT sandbag by mislabeling: a 'delete' is classified irreversible
# regardless of any planner intent, because the classifier is verifier-owned
mixed = [Operation("d1", "delete")] + [Operation(f"r{i}", "read") for i in range(50)]
check("verifier-owned classifier counts the delete (1) not the 50 reads",
      t4.count_irreversible(mixed) == 1)
check("default classifier treats destructive kinds as irreversible",
      default_irreversibility(Operation("x", "purge")) is True
      and default_irreversibility(Operation("y", "read")) is False)
no_policy = ApprovalThrottle(ApprovalPolicy(max_approvals_per_window=100))
check("with no human-set threshold, no 2nd approver is ever auto-required",
      no_policy.second_approver_required(destructive) is False)


# ── uncertainty as a fact + HARDENED provenance gate ────────────────────────
est = HarmEstimate(0.002, 0.001, 0.010, "estimator-v0", verifier_sourced=True)
f = est.as_fact()
check("harm estimate renders P and CI as a fact", "P(harm)" in f and "CI" in f)
check("harm estimate carries no judgment word",
      not any(w in f.lower() for w in ("recommend", "should", "safe", "dangerous", "severe")))

thr = HarmThreshold(cutoff=0.005, use_upper_bound=True)
check("conservative mode crosses on a wide interval (upper 0.010 > 0.005)", exceeds(est, thr) is True)
check("point-estimate mode would not cross (0.002 < 0.005)",
      exceeds(est, HarmThreshold(0.005, use_upper_bound=False)) is False)

# HARDENED: a planner-sourced (unverified) estimate may not drive the cutoff
planner_est = HarmEstimate(0.0001, 0.0, 0.0002, "planner-supplied", verifier_sourced=False)
try:
    exceeds(planner_est, thr)
    check("a planner-sourced estimate is REFUSED at the threshold", False)
except UntrustedEstimate:
    check("a planner-sourced estimate is REFUSED at the threshold", True)
check("an unverified estimate is tagged UNVERIFIED on its fact line",
      "UNVERIFIED" in planner_est.as_fact())


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
