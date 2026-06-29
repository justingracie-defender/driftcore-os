"""
test_integrity_invariance.py — CONSEQUENCE INVARIANCE + OBJECTIVE INTEGRITY (HARDENED)
====================================================================================
STATUS: PROPOSED. Pins the original properties AND the red-team fixes:
  - a verdict peeking at downstream outcomes FAILS the invariance check, named
  - objective drift without a valid signed change FAILS; with one PASSES
  - HARDENED: an authorized change cannot be REPLAYED to revert later (from-hash + nonce)
  - HARDENED: invariant presence is VERIFIER-DERIVED from a registry, not planner-supplied
  - may_execute is False on any failure

Run with:  python test_integrity_invariance.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.consequence_invariance import check_consequence_invariance
from driftcore.verification.objective_integrity import (
    RatifiedBaseline, AuthorizedObjectiveChange, InvariantRegistry,
    verify_planning_cycle, may_execute, objective_hash,
)

results = []
def check(n, c):
    print(f"  {'ok' if c else 'XX'}: {n}")
    results.append((n, bool(c)))


# ── consequence invariance ──────────────────────────────────────────────────
record = {"criteria_met": True, "world_paid_off": True, "profit": 100}
good = lambda r: r["criteria_met"]
bad  = lambda r: r["criteria_met"] and r["world_paid_off"]
check("outcome-blind verdict is consequence-invariant",
      check_consequence_invariance(good, record, ["world_paid_off", "profit"], [True, False, 0]).invariant)
rep = check_consequence_invariance(bad, record, ["world_paid_off", "profit"], [True, False])
check("a verdict peeking at a downstream outcome FAILS", not rep.invariant)
check("the failing check names the offending field", rep.offending_field == "world_paid_off")


# ── objective integrity ─────────────────────────────────────────────────────
SECRET = "operator-secret"
base = RatifiedBaseline(objectives=(
    "keep humans in meaningful control",
    "never conceal safety-relevant facts",
    "no self-granted authority",
))
REQUIRED = frozenset({"no_lethal_action", "no_disabling_oversight", "no_concealment"})

def full_registry():
    reg = InvariantRegistry()
    for inv in REQUIRED:
        reg.mark_checked(inv)
    return reg

# clean cycle
r = verify_planning_cycle(base, base.objectives, REQUIRED, full_registry())
check("clean cycle passes integrity", r.ok and may_execute(r))

# silent drift
drifted = ("notify humans after execution",
           "never conceal safety-relevant facts",
           "no self-granted authority")
r = verify_planning_cycle(base, drifted, REQUIRED, full_registry())
check("silent objective drift FAILS (hash mismatch, no auth)", not r.ok)
check("no plan executes on a failed cycle", not may_execute(r))

# authorized change: binds from-hash -> to-hash + nonce
change = AuthorizedObjectiveChange.sign(base.hash, drifted, "ratified change #14", "nonce-001", SECRET)
seen = set()
r = verify_planning_cycle(base, drifted, REQUIRED, full_registry(),
                          change=change, secret=SECRET, used_nonces=seen)
check("a valid, bound, signed change passes", r.ok)

# HARDENED replay: the SAME change cannot be reused (nonce burned)
r = verify_planning_cycle(base, drifted, REQUIRED, full_registry(),
                          change=change, secret=SECRET, used_nonces=seen)
check("replaying the same signed change is refused (nonce burned)", not r.ok)

# HARDENED replay-to-revert: an old auth bound to a DIFFERENT from-hash doesn't apply.
# Build a change that was signed to move FROM the drifted state; try to use it to
# 'authorize' the base->drifted transition. Its from_hash won't match base.hash.
other = AuthorizedObjectiveChange.sign(objective_hash(drifted), base.objectives,
                                       "revert", "nonce-002", SECRET)
r = verify_planning_cycle(base, drifted, REQUIRED, full_registry(),
                          change=other, secret=SECRET, used_nonces=set())
check("a change bound to a different from-hash cannot authorize this transition", not r.ok)

# tampered signature
bad_change = AuthorizedObjectiveChange(base.hash, drifted, "x", "n9", "deadbeef")
r = verify_planning_cycle(base, drifted, REQUIRED, full_registry(),
                          change=bad_change, secret=SECRET, used_nonces=set())
check("a badly-signed change does NOT authorize drift", not r.ok)

# HARDENED presence: a required invariant that did not actually run fails the cycle
partial = InvariantRegistry()
partial.mark_checked("no_lethal_action")
partial.mark_checked("no_disabling_oversight")   # 'no_concealment' never ran
r = verify_planning_cycle(base, base.objectives, REQUIRED, partial)
check("a required invariant absent from the registry FAILS the cycle", not r.ok)
check("the failure names the absent invariant", any("no_concealment" in f for f in r.failures))


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
