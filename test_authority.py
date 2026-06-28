"""
test_authority.py
================
Proves the authority resolver and the governed execution path.

Resolver:
  - CONSTITUTION deny is absolute (even a human override can't lift it).
  - Any deny blocks; the highest-authority denier is reported.
  - A human override lifts PROFILE/DOMAIN/SKILL denies, not the floor.
  - All-allow → allowed.

Executor (end-to-end wiring):
  - A skill that fails may_run is blocked → no checkpoint, apply_fn not called.
  - A qualifying skill → checkpoint taken (with decision-path context) → apply.
  - A frozen recovery system blocks the apply even when authority allows.

Run:  python test_authority.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.authority import (
    AuthorityResolver, AuthorityLayer, Verdict, LayerVerdict, GovernedExecutor,
)
from driftcore.skills.governance import (
    MaturityController, SkillMaturity, SkillStats,
)
from driftcore.recovery import RecoveryManager, InMemorySnapshotter, CheckpointStore

PASS, FAIL = "PASS", "FAIL"
_results = []


def check(name, cond):
    _results.append(bool(cond))
    print(f"  [{PASS if cond else FAIL}] {name}")


L = AuthorityLayer
V = Verdict


# ── Resolver semantics ─────────────────────────────────────────────
print("\nResolver: hierarchy + floor + override")

# all allow
d = AuthorityResolver.resolve([
    LayerVerdict(L.SKILL, V.ALLOW), LayerVerdict(L.DOMAIN, V.ALLOW)])
check("all-allow is allowed", d.allowed is True)

# a single deny blocks
d = AuthorityResolver.resolve([
    LayerVerdict(L.SKILL, V.ALLOW),
    LayerVerdict(L.DOMAIN, V.DENY, "domain isolation")])
check("any deny blocks", d.allowed is False and d.binding_layer is L.DOMAIN)

# highest-authority denier is reported
d = AuthorityResolver.resolve([
    LayerVerdict(L.SKILL, V.DENY, "immature"),
    LayerVerdict(L.PROFILE, V.DENY, "out of scope")])
check("highest-authority denier is binding (PROFILE over SKILL)",
      d.binding_layer is L.PROFILE)

# constitution deny is absolute
d = AuthorityResolver.resolve([
    LayerVerdict(L.CONSTITUTION, V.DENY, "never retain child media"),
    LayerVerdict(L.SKILL, V.ALLOW)])
check("constitution deny blocks", d.allowed is False
      and d.binding_layer is L.CONSTITUTION)

# constitution deny is NOT overridable by a human
d = AuthorityResolver.resolve(
    [LayerVerdict(L.CONSTITUTION, V.DENY, "floor")],
    human_override=("justin", "I really want to"))
check("human CANNOT override the constitution floor", d.allowed is False)

# human CAN override a domain/skill deny
d = AuthorityResolver.resolve(
    [LayerVerdict(L.DOMAIN, V.DENY, "domain isolation")],
    human_override=("justin", "deliberate cross-domain task, supervised"))
check("human overrides a DOMAIN deny", d.allowed is True and d.overridden is True)

# override with an EMPTY reason is rejected (audit quality)
d = AuthorityResolver.resolve(
    [LayerVerdict(L.DOMAIN, V.DENY, "domain isolation")],
    human_override=("justin", "   "))
check("override without a reason is rejected", d.allowed is False)

# override lifts ALL non-floor denies at once
d = AuthorityResolver.resolve(
    [LayerVerdict(L.DOMAIN, V.DENY, "iso"), LayerVerdict(L.SKILL, V.DENY, "immature")],
    human_override=("justin", "supervised exception"))
check("human override lifts multiple lower-layer denies",
      d.allowed is True and d.overridden is True)

# a non-human 'override' does nothing
d = AuthorityResolver.resolve(
    [LayerVerdict(L.SKILL, V.DENY, "immature")],
    human_override=("system", "nope"))
check("'system' cannot override", d.allowed is False)


# ── Executor: end-to-end governed path ─────────────────────────────
print("\nExecutor: governance -> resolver -> checkpoint -> apply")

mc = MaturityController()
snap = InMemorySnapshotter({"rec:1": "v0"})
rec = RecoveryManager(CheckpointStore(), snap)
applied_flag = {"called": False}
def apply_fn():
    applied_flag["called"] = True
    return "applied-ok"

execu = GovernedExecutor(rec, mc)

# Case A: under-matured skill in childcare -> blocked, no checkpoint, no apply
weak_stats = SkillStats("s.tutor")
for _ in range(5): weak_stats.record(True)
res_a = execu.run("TutoringSkill", "childcare", SkillMaturity.TESTED, weak_stats,
                  apply_fn, resources=["rec:1"], skill_version="v1")
check("under-matured childcare skill blocked", res_a.applied is False)
check("blocked skill took no checkpoint", res_a.checkpoint_id is None)
check("blocked skill never called apply_fn", applied_flag["called"] is False)

# Case B: qualifying skill -> checkpoint (with context) -> apply
strong = SkillStats("s.tutor2")
for _ in range(200): strong.record(True)
res_b = execu.run("TutoringSkill", "childcare",
                  SkillMaturity.CRITICAL_APPROVED, strong,
                  apply_fn, resources=["rec:1"], skill_version="v4.2",
                  profile="CaregiverProfile", mode="TRUTH")
check("qualifying skill is applied", res_b.applied is True)
check("a checkpoint was taken before applying", res_b.checkpoint_id is not None)
check("apply_fn was called", applied_flag["called"] is True)

# the checkpoint carries the decision-path context
cp = rec._store.get(res_b.checkpoint_id)
check("checkpoint context records the domain", cp.context.domain == "childcare")
check("checkpoint context records the skill version",
      cp.context.skill_version == "v4.2")

# Case C: constitution deny via extra_verdicts -> blocked regardless
applied_flag["called"] = False
res_c = execu.run("TutoringSkill", "household",
                  SkillMaturity.TESTED, strong, apply_fn, resources=["rec:1"],
                  extra_verdicts=[LayerVerdict(L.CONSTITUTION, V.DENY,
                                               "forbidden action class")])
check("constitution deny blocks the governed path", res_c.applied is False)
check("no apply on constitution deny", applied_flag["called"] is False)

# Case D: frozen recovery blocks apply even when authority allows
applied_flag["called"] = False
rec.trigger_halt("incident in progress")
res_d = execu.run("TutoringSkill", "household",
                  SkillMaturity.TESTED, strong, apply_fn, resources=["rec:1"])
check("frozen system blocks the apply", res_d.applied is False)
check("authority allowed but checkpoint refused -> no apply",
      res_d.decision.allowed is True and applied_flag["called"] is False)


# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 56)
passed, total = sum(_results), len(_results)
print(f"{passed}/{total} checks passed")
print("=" * 56)
if passed < total:
    sys.exit(1)
